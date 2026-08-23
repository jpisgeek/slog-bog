/**
 * Netdata standalone agent state, across a set of nodes.
 *
 * Deliberately NOT a metrics collector. Netdata already stores high-resolution
 * telemetry on each node and runs its own health engine; duplicating either in
 * swamp would be worse and slower. What this model records is *state truth*:
 * which nodes answer, what they are, which alarms are firing, and how much
 * capacity is left — the things you correlate against inventory and act on.
 *
 * Chart names are platform-specific (macOS has no `system.cpu` and does have
 * `macos.gpu_*`; Linux differs again), so mount discovery reads the agent's
 * own chart list rather than assuming names. Alarm thresholds are Netdata's,
 * not ours.
 *
 * A node that does not answer is data, not an error: `reachable: false` is
 * written and the sweep continues. A homelab always has something powered off.
 * A node that *did* answer before but only partially answers this round
 * (alarms or chart data timed out, say) keeps its last known detail instead
 * of being zeroed out or pruned — see the discover() comments below.
 */
import { z } from "npm:zod@4";

const NodeSchema = z.object({
  name: z.string().describe("Logical node name; match the SSH fleet name"),
  url: z
    .string()
    .refine(
      (v) => {
        try {
          const u = new URL(v);
          // http/https only: Deno fetch will honour a file: URL, and the
          // remote curl honours the file:, ftp:, dict: (etc.) schemes — an
          // unrestricted scheme is an SSRF / local-read footgun. No userinfo
          // (persisted verbatim; would leak if present). No
          // single quote: over the ssh transport the URL is interpolated into
          // a single-quoted remote command and a quote would break out of it.
          return (u.protocol === "http:" || u.protocol === "https:") &&
            u.username === "" && u.password === "" && !v.includes("'");
        } catch {
          return false;
        }
      },
      {
        message:
          "url must be a valid http(s) URL, must not embed credentials " +
          "(user:pass@host) -- discover persists node.url verbatim as " +
          "non-sensitive data -- and must not contain a single quote. Use " +
          "the ssh transport for agents that require authentication.",
      },
    )
    .describe(
      "Agent base URL, e.g. http://netdata.example.com:19999",
    ),
  ssh: z
    .object({
      // host/user become the positional `user@host` argument to ssh; a value
      // starting with "-" would be parsed as an ssh option (-oProxyCommand=…).
      host: z.string().min(1).refine((v) => !v.startsWith("-"), {
        message: "ssh.host must not start with '-'",
      }),
      user: z.string().min(1).refine((v) => !v.startsWith("-"), {
        message: "ssh.user must not start with '-'",
      }),
      port: z.number().int().positive().default(22),
    })
    .optional()
    .describe(
      "Reach this agent by running curl over SSH instead of connecting " +
        "directly. For roaming machines: the agent stays bound to loopback " +
        "with the host firewall on, so it never exposes a port on an " +
        "untrusted network, and swamp still reaches it using the same key " +
        "auth as the SSH fleet.",
    ),
});

const GlobalArgsSchema = z.object({
  nodes: z.array(NodeSchema).min(1),
  timeoutSec: z.number().int().positive().default(15),
  diskWarnPercent: z
    .number()
    .min(1)
    .max(100)
    .default(85)
    .describe("Mounts at or above this used% are flagged"),
  maxConcurrency: z
    .number()
    .int()
    .positive()
    .default(8)
    .describe(
      "Maximum number of nodes polled at once. A large nodes list can " +
        "otherwise exhaust local sockets or spawn an unbounded number of " +
        "ssh processes at the same time.",
    ),
});

const DiscoverArgsSchema = z.object({
  node: z
    .string()
    .optional()
    .describe("Limit the sweep to one node by name"),
});

const NodeStateSchema = z.object({
  name: z.string(),
  url: z.string(),
  reachable: z.boolean(),
  error: z.string(),
  /** "http" or "ssh" -- how swamp reached this agent. */
  transport: z.string(),
  /**
   * Identity fields are nullable, not empty-string, because "we have never
   * successfully reached this node" is a real, distinct state from "this
   * node reports an empty version string." null means the former.
   */
  version: z.string().nullable(),
  hostname: z.string().nullable(),
  osName: z.string().nullable(),
  osVersion: z.string().nullable(),
  cores: z.number(),
  collectors: z.number(),
  charts: z.number(),
  alarmsActive: z.number(),
  alarmsCritical: z.number(),
  alarmsWarning: z.number(),
  claimedToCloud: z.boolean(),
  mountsOverThreshold: z.number(),
});

const AlarmSchema = z.object({
  node: z.string(),
  name: z.string(),
  chart: z.string(),
  status: z.string(),
  value: z.number(),
  units: z.string(),
  info: z.string(),
});

const MountSchema = z.object({
  node: z.string(),
  mount: z.string(),
  availGiB: z.number(),
  usedGiB: z.number(),
  totalGiB: z.number(),
  usedPercent: z.number(),
  overThreshold: z.boolean(),
});

const SummarySchema = z.object({
  nodes: z.number(),
  nodesReachable: z.number(),
  nodesUnreachable: z.number(),
  /** Reachable nodes whose alarm or chart sub-fetch failed this sweep, so
   * their alarm/mount counts are carried-forward, not fresh. When > 0, treat
   * the alarm/mount roll-ups as a floor, not a current total. */
  nodesDegraded: z.number(),
  alarmsActive: z.number(),
  alarmsCritical: z.number(),
  mountsOverThreshold: z.number(),
  syncedAt: z.string(),
});

/**
 * Deterministic, non-cryptographic 32-bit FNV-1a hash, hex-encoded. Used
 * only to make instance names collision-safe -- never for anything
 * security sensitive.
 */
function shortHash(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

function slug(v: string): string {
  return v.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") ||
    "unnamed";
}

/**
 * Build a collision-safe, filesystem-safe instance name. `slug()` alone is
 * not injective (`db 1` and `db-1` both slug to `db-1`), so every name here
 * also carries a short hash of the *raw*, pre-slug identity fields -- node
 * name uniqueness is enforced at the top of discover(), but the
 * alarm/mount name and chart name that get appended
 * per node are not, and are exactly the kind of operator-chosen strings
 * that can collide after slugging.
 */
function instanceName(prefix: string, ...identity: string[]): string {
  // Unit Separator, written as an escape rather than a raw control byte.
  // The join separator must be a character that cannot occur inside an
  // identifier, or ["a","b c"] and ["a b","c"] hash identically. truenas
  // previously used a RAW NUL here, which achieved that but made the file
  // read as binary to grep and to any tool doing exact-text matching.
  const raw = identity.join("\u001f");
  // Build the readable label from EVERY non-empty identity field, not just the
  // first. Taking only the first made the visible part non-discriminating
  // wherever the caller passes a shared scope first: netdata's alarms pass the
  // node name ahead of the alarm name, so every alarm on one node rendered as
  // `alarm-<node>-<hash>` and differed only in an opaque hash. Names were
  // unique, but `swamp data list` became unreadable -- which is the entire
  // reason for having a readable part at all.
  // Capped so an unusually long identity cannot produce an unbounded name; the
  // hash still covers the full raw identity, so uniqueness never depends on
  // what survives truncation.
  const parts = identity.filter((s) => s !== "").map(slug).filter((s) =>
    s !== ""
  );
  const label = parts.length ? parts.join("-").slice(0, 48) : "unnamed";
  return `${prefix}-${label}-${shortHash(raw)}`;
}

/**
 * A node-level failure message safe to PERSIST in the `error` resource field.
 * The full detail (ssh `user@host`, ssh stderr — which can echo local key
 * paths — and any HTTP response body) belongs in the log line, never in stored
 * data. This collapses a raw failure to a class with no transport target or
 * remote output. Keep the raw message for `logger.warning`; store this.
 */
function sanitizeNodeError(raw: string): string {
  const ssh = raw.match(/^ssh to \S+ failed: ([\s\S]*)$/);
  if (ssh) {
    const d = ssh[1];
    if (/host key|known_hosts|verification failed/i.test(d)) {
      return "ssh transport: host key verification failed";
    }
    if (/permission denied|load key|auth|publickey|password/i.test(d)) {
      return "ssh transport: authentication failed";
    }
    const code = d.match(/exit (\d+)/i);
    return code
      ? `ssh transport failed (exit ${code[1]})`
      : "ssh transport failed";
  }
  // "HTTP 500 (transient) on /path: <body>" -> drop the body.
  const http = raw.match(/^(HTTP \d+ \([^)]*\) on [^:\s]+)/);
  if (http) return http[1];
  if (/no HTTP response|connection failure/i.test(raw)) {
    return "connection failed";
  }
  if (/timed out|timeout/i.test(raw)) return "timed out";
  // Fallback: strip anything that looks like an ssh target, then truncate.
  return raw.replace(/\S+@\S+/g, "<host>").slice(0, 120);
}

/** Netdata's alarm status strings; anything else counts as neither. */
function isCritical(status: string): boolean {
  return status.toUpperCase() === "CRITICAL";
}
function isWarning(status: string): boolean {
  return status.toUpperCase() === "WARNING";
}

interface NodeResult {
  name: string;
  url: string;
  reachable: boolean;
  error: string;
  info: Record<string, unknown>;
  alarms: Array<Record<string, unknown>>;
  mounts: Array<{
    mount: string;
    avail: number;
    used: number;
  }>;
  chartCount: number;
  /** False when the /alarms fetch itself failed (node still reachable). */
  alarmsOk: boolean;
  /** False when the /charts fetch itself failed (node still reachable). */
  chartsOk: boolean;
  /** Chart names whose /data query failed individually, chartsOk otherwise true. */
  failedMounts: string[];
}

type PollLogger = {
  warning: (msg: string, props?: Record<string, unknown>) => void;
};

/** Bounded-concurrency map: never runs more than `limit` `fn` calls at once. */
async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  }
  const workers = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    () => worker(),
  );
  await Promise.all(workers);
  return results;
}

/** HTTP errors in the 429/5xx range are worth distinguishing from a hard
 * client error like 403/404 -- the former might clear up on the next sweep,
 * the latter almost certainly won't without operator action. */
function classifyStatus(status: number): "transient" | "permanent" {
  return status === 429 || status >= 500 ? "transient" : "permanent";
}

async function pollNode(
  node: {
    name: string;
    url: string;
    ssh?: { host: string; user: string; port?: number };
  },
  timeoutSec: number,
  signal: AbortSignal,
  logger: PollLogger,
): Promise<NodeResult> {
  const base = node.url.replace(/\/+$/, "");
  const result: NodeResult = {
    name: node.name,
    url: base,
    reachable: false,
    error: "",
    info: {},
    alarms: [],
    mounts: [],
    chartCount: 0,
    alarmsOk: false,
    chartsOk: false,
    failedMounts: [],
  };

  const STATUS_MARKER = "__SWAMP_HTTP_STATUS__";

  /** Fetch over SSH: run curl on the node against its own loopback. A
   * trailing write-out marker carries the HTTP status back regardless of
   * curl's own exit code, so HTTP errors are detected the same way as the
   * direct-fetch path -- curl's --fail flag alone reports failure but
   * varies in whether it also surfaces the response body across versions. */
  const getViaSsh = async (path: string): Promise<unknown> => {
    const ssh = node.ssh!;
    // Single remote command string so the remote shell keeps the query
    // string intact; never assembled through a local shell.
    // No newline before the marker: curl's -w output is appended straight
    // after the body with no separator, and the marker string is
    // distinctive enough that a plain concatenation is unambiguous to
    // locate and strip below.
    const remote =
      `curl -s --max-time ${timeoutSec} -w '${STATUS_MARKER}:%{http_code}' '${base}${
        path.replace(/'/g, "")
      }'`;
    const out = await new Deno.Command("ssh", {
      args: [
        "-o",
        "BatchMode=yes",
        "-o",
        `ConnectTimeout=${Math.min(timeoutSec, 10)}`,
        "-p",
        String(ssh.port ?? 22),
        `${ssh.user}@${ssh.host}`,
        remote,
      ],
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
      signal: AbortSignal.any([
        signal,
        AbortSignal.timeout((timeoutSec + 10) * 1000),
      ]),
    }).output();

    if (!out.success) {
      const err = new TextDecoder().decode(out.stderr).trim();
      throw new Error(
        `ssh to ${ssh.user}@${ssh.host} failed: ${
          err.slice(0, 160) || `exit ${out.code}`
        }`,
      );
    }
    const raw = new TextDecoder().decode(out.stdout);
    const markerIdx = raw.lastIndexOf(`${STATUS_MARKER}:`);
    if (markerIdx === -1) {
      throw new Error(`no HTTP status marker in ssh response for ${path}`);
    }
    const body = raw.slice(0, markerIdx).trim();
    const status = Number(
      raw.slice(markerIdx + STATUS_MARKER.length + 1).trim(),
    );
    if (!Number.isFinite(status) || status === 0) {
      throw new Error(`no HTTP response (connection failure) for ${path}`);
    }
    if (status >= 400) {
      throw new Error(
        `HTTP ${status} (${classifyStatus(status)}) on ${path}${
          body ? `: ${body.slice(0, 200)}` : ""
        }`,
      );
    }
    if (!body) throw new Error(`empty response over ssh for ${path}`);
    return JSON.parse(body);
  };

  const getDirect = async (path: string): Promise<unknown> => {
    const res = await fetch(`${base}${path}`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.any([signal, AbortSignal.timeout(timeoutSec * 1000)]),
    });
    if (!res.ok) {
      const bodyText = await res.text().catch(() => "");
      throw new Error(
        `HTTP ${res.status} (${classifyStatus(res.status)}) on ${path}${
          bodyText ? `: ${bodyText.slice(0, 200)}` : ""
        }`,
      );
    }
    return await res.json();
  };

  const getJson = node.ssh ? getViaSsh : getDirect;

  try {
    const info = await getJson("/api/v1/info") as Record<string, unknown>;
    result.reachable = true;
    result.info = info;

    // Alarms and charts are best-effort: a node that answers /info but not
    // these is still a reachable node, just with less detail. Failures are
    // logged (not just swallowed) so a degraded node is diagnosable without
    // reading stored data.
    try {
      const al = await getJson("/api/v1/alarms?active=true") as Record<
        string,
        unknown
      >;
      // /api/v1/info carries no hostname; the alarms payload does.
      if (!info.hostname && typeof al.hostname === "string") {
        result.info = { ...info, hostname: al.hostname };
      }
      const alarms = (al.alarms ?? {}) as Record<string, unknown>;
      result.alarms = Object.entries(alarms).map(([name, raw]) => {
        const a = (raw ?? {}) as Record<string, unknown>;
        return { name, ...a };
      });
      result.alarmsOk = true;
    } catch (e) {
      logger.warning(
        "netdata {node} /api/v1/alarms failed: {error}",
        {
          node: node.name,
          endpoint: "/api/v1/alarms",
          error: (e as Error).message,
        },
      );
    }

    try {
      const ch = await getJson("/api/v1/charts") as Record<string, unknown>;
      const charts = (ch.charts ?? {}) as Record<string, unknown>;
      result.chartCount = Object.keys(charts).length;
      result.chartsOk = true;

      // Discover filesystem charts instead of assuming names.
      const spaceCharts = Object.keys(charts).filter((k) =>
        k.startsWith("disk_space.")
      );
      for (const chart of spaceCharts) {
        const mount = chart.slice("disk_space.".length);
        try {
          const data = await getJson(
            `/api/v1/data?chart=${encodeURIComponent(chart)}` +
              `&after=-60&points=1&format=json`,
          ) as { labels?: string[]; data?: number[][] };
          const labels = data.labels ?? [];
          const row = (data.data ?? [])[0];
          if (!row) {
            result.failedMounts.push(mount);
            continue;
          }
          // Resolve dimensions by label and REFUSE to guess. indexOf() returns
          // -1 for a missing label, and row[-1] is undefined -- a previous
          // `?? 0` fallback turned that into used:0/avail:0, i.e. a failed
          // read reported as a healthy, empty filesystem on every mount of
          // every node. A mount whose dimensions can't be resolved is a
          // failed mount, same as a failed /data call.
          const availIdx = labels.indexOf("avail");
          const usedIdx = labels.indexOf("used");
          const avail = availIdx === -1 ? NaN : Number(row[availIdx]);
          const used = usedIdx === -1 ? NaN : Number(row[usedIdx]);
          if (!Number.isFinite(avail) || !Number.isFinite(used)) {
            result.failedMounts.push(mount);
            logger.warning(
              "netdata {node} mount {mount}: avail/used dimensions not " +
                "found in chart data (labels: {labels}) -- keeping last known",
              { node: node.name, mount, labels: labels.join(",") },
            );
            continue;
          }
          result.mounts.push({ mount, avail, used });
        } catch (e) {
          result.failedMounts.push(mount);
          logger.warning(
            "netdata {node} mount {mount} data query failed: {error}",
            {
              node: node.name,
              mount,
              endpoint: chart,
              error: (e as Error).message,
            },
          );
        }
      }
    } catch (e) {
      logger.warning(
        "netdata {node} /api/v1/charts failed: {error}",
        {
          node: node.name,
          endpoint: "/api/v1/charts",
          error: (e as Error).message,
        },
      );
    }
  } catch (e) {
    // Caller cancellation (workflow abort) is not an observation about the
    // node -- it is the run being pulled out from under us. Rethrow so
    // discover() aborts before it writes a fleet of false "unreachable"
    // records and runs the prune. `signal` is the caller's raw signal, so
    // this fires only on cancellation, never on this poll's own timeout.
    if (signal.aborted) throw e;
    // Unreachable is a normal homelab state, recorded rather than thrown --
    // but still worth a structured warning so a degraded fleet is visible
    // in logs, not just in stored data someone has to go query. The FULL
    // detail (ssh user@host, ssh stderr, HTTP body) goes to the log; the
    // stored `error` gets only a sanitized class -- see sanitizeNodeError.
    const rawMsg = (e as Error).message;
    result.error = sanitizeNodeError(rawMsg);
    logger.warning(
      "netdata {node} unreachable: {error}",
      { node: node.name, url: base, error: rawMsg.slice(0, 300) },
    );
  }

  return result;
}

async function discover(
  args: z.infer<typeof DiscoverArgsSchema>,
  ctx: {
    signal: AbortSignal;
    globalArgs: Record<string, unknown>;
    modelType: string;
    modelId: string;
    logger: {
      info: (msg: string, props?: Record<string, unknown>) => void;
      warning: (msg: string, props?: Record<string, unknown>) => void;
    };
    readResource: (name: string) => Promise<Record<string, unknown> | null>;
    // deno-lint-ignore no-explicit-any
    writeResource: (...a: any[]) => Promise<any>;
    dataRepository: {
      findAllForModel: (
        t: string,
        id: string,
      ) => Promise<Array<{ name: string }>>;
      delete: (t: string, id: string, name: string) => Promise<void>;
    };
  },
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  // Validated here, not as an object-level refinement on the schema: swamp
  // calls .partial() on globalArguments, and zod 4 refuses that on an object
  // that carries refinements -- an object-level superRefine made every
  // discover() fail before it started.
  const seenNames = new Set<string>();
  const duplicates = new Set<string>();
  for (const n of g.nodes) {
    if (seenNames.has(n.name)) duplicates.add(n.name);
    seenNames.add(n.name);
  }
  if (duplicates.size > 0) {
    throw new Error(
      `Duplicate node name(s): ${[...duplicates].join(", ")} -- node names ` +
        "must be unique; they become part of every resource instance name " +
        "this model writes.",
    );
  }
  const targets = args.node
    ? g.nodes.filter((n) => n.name === args.node)
    : g.nodes;

  if (targets.length === 0) {
    throw new Error(
      `No node named '${args.node}'. Known: ${
        g.nodes.map((n) => n.name).join(", ")
      }`,
    );
  }

  ctx.logger.info("polling {n} netdata node(s)", { n: targets.length });

  // Bounded concurrency: an unbounded Promise.all over a large nodes list
  // can exhaust local sockets or spawn an unbounded number of ssh processes
  // at once. Each poll still carries its own abort timeout.
  const results = await mapWithConcurrency(
    targets,
    g.maxConcurrency,
    (n) => pollNode(n, g.timeoutSec, ctx.signal, ctx.logger),
  );

  const handles = [];
  const live = new Set<string>();
  // Prefixes of existing resource names that must survive this round's
  // prune even though nothing new was written under them -- the node
  // answered before but a sub-fetch failed this round (or the node is
  // unreachable), so we genuinely don't know the current alarm/mount list
  // and must not treat "no fresh data" as "nothing exists any more."
  const protectedPrefixes: string[] = [];
  // The summary rolls up the values ACTUALLY WRITTEN per node (which include
  // carried-forward counts when a sub-fetch failed), not just this round's
  // fresh data -- otherwise a node whose /alarms fetch failed contributes 0
  // and the summary reads "alarmsActive: 0" (healthy) while the per-node
  // records say otherwise. `nodesDegraded` counts nodes that answered /info
  // but not every sub-fetch, so a consumer can tell "0 alarms" from "unknown".
  let reachable = 0, nodesDegraded = 0;
  let alarmsActive = 0, alarmsCritical = 0, overThreshold = 0;

  for (const r of results) {
    const info = r.info;
    const nodeAlarmsCritical = r.alarms.filter((a) =>
      isCritical(String(a.status ?? ""))
    ).length;
    const nodeAlarmsWarning =
      r.alarms.filter((a) => isWarning(String(a.status ?? ""))).length;

    // ---- alarms ---------------------------------------------------------
    if (!r.alarmsOk) {
      // Alarm fetch failed (or node unreachable, which never gets this far
      // truthfully -- alarmsOk starts false). Preserve whatever this node's
      // existing alarm-* records already say instead of pruning them.
      protectedPrefixes.push(`alarm-${slug(r.name)}-`);
    }
    for (const a of r.alarms) {
      const an = instanceName(
        "alarm",
        r.name,
        String(a.name ?? ""),
        String(a.chart ?? ""),
      );
      live.add(an);
      handles.push(
        await ctx.writeResource("alarm", an, {
          node: r.name,
          name: String(a.name ?? ""),
          chart: String(a.chart ?? ""),
          status: String(a.status ?? ""),
          value: Number(a.value ?? 0),
          units: String(a.units ?? ""),
          info: String(a.info ?? ""),
        }, {
          tags: { node: r.name, status: String(a.status ?? "") },
        }),
      );
    }
    // (summary accumulation happens once, from the written per-node values,
    // after the node record is built below)

    // ---- mounts ---------------------------------------------------------
    if (!r.chartsOk) {
      protectedPrefixes.push(`mount-${slug(r.name)}-`);
    }
    let nodeOver = 0;
    for (const m of r.mounts) {
      const total = m.avail + m.used;
      const pct = total > 0 ? Math.round((m.used / total) * 1000) / 10 : 0;
      const over = pct >= g.diskWarnPercent;
      if (over) nodeOver++;
      const mn = instanceName("mount", r.name, m.mount);
      live.add(mn);
      handles.push(
        await ctx.writeResource("mount", mn, {
          node: r.name,
          mount: m.mount,
          availGiB: Math.round(m.avail * 10) / 10,
          usedGiB: Math.round(m.used * 10) / 10,
          totalGiB: Math.round(total * 10) / 10,
          usedPercent: pct,
          overThreshold: over,
        }, {
          tags: { node: r.name, overThreshold: String(over) },
        }),
      );
    }
    // A mount whose data query failed individually (chart list was fine,
    // this one chart's /data call wasn't) keeps its own last-known record
    // rather than being dropped from this round's write set.
    for (const failedMount of r.failedMounts) {
      live.add(instanceName("mount", r.name, failedMount));
    }

    // ---- node -------------------------------------------------------------
    if (r.reachable) reachable++;
    const nn = `node-${slug(r.name)}`;
    live.add(nn);

    // Identity and detail fields depend on this poll actually reaching
    // /api/v1/info (and, for charts/alarms counts, the relevant sub-fetch).
    // When that didn't happen this round, carry forward the last stored
    // values instead of writing blank/zeroed placeholders that would read
    // as "this host has no version" or "zero alarms" -- neither of which is
    // true; the node simply didn't answer (or answer fully) this time.
    const prevNode = (!r.reachable || !r.alarmsOk || !r.chartsOk)
      ? await ctx.readResource(nn)
      : null;

    const identity = r.reachable
      ? {
        version: typeof info.version === "string" ? info.version : null,
        hostname: typeof info.hostname === "string" ? info.hostname : null,
        osName: typeof info.os_name === "string" ? info.os_name : null,
        osVersion: typeof info.os_version === "string" ? info.os_version : null,
        cores: Number(info.cores_total ?? 0),
        collectors: Array.isArray(info.collectors) ? info.collectors.length : 0,
        // Whether this agent streams to Netdata Cloud. Recorded because it
        // is a data-egress fact worth being able to audit per node.
        claimedToCloud: Boolean(info.cloud_enabled ?? info["cloud-enabled"]) &&
          String(info.agent_claimed ?? info["agent-claimed"] ?? "") !==
            "false",
      }
      : {
        version: (prevNode?.version as string | null | undefined) ?? null,
        hostname: (prevNode?.hostname as string | null | undefined) ?? null,
        osName: (prevNode?.osName as string | null | undefined) ?? null,
        osVersion: (prevNode?.osVersion as string | null | undefined) ?? null,
        cores: Number(prevNode?.cores ?? 0),
        collectors: Number(prevNode?.collectors ?? 0),
        claimedToCloud: Boolean(prevNode?.claimedToCloud ?? false),
      };

    const chartsVal = r.chartsOk ? r.chartCount : Number(prevNode?.charts ?? 0);
    const mountsOverVal = r.chartsOk
      ? nodeOver
      : Number(prevNode?.mountsOverThreshold ?? 0);
    const alarmsActiveVal = r.alarmsOk
      ? r.alarms.length
      : Number(prevNode?.alarmsActive ?? 0);
    const alarmsCriticalVal = r.alarmsOk
      ? nodeAlarmsCritical
      : Number(prevNode?.alarmsCritical ?? 0);
    const alarmsWarningVal = r.alarmsOk
      ? nodeAlarmsWarning
      : Number(prevNode?.alarmsWarning ?? 0);

    // Roll up the values actually written for this node (carried-forward
    // included), so the summary can never read "0 alarms" for a node whose
    // alarm fetch failed. A reachable node missing a sub-fetch is "degraded".
    alarmsActive += alarmsActiveVal;
    alarmsCritical += alarmsCriticalVal;
    overThreshold += mountsOverVal;
    if (r.reachable && (!r.alarmsOk || !r.chartsOk)) nodesDegraded++;

    handles.push(
      await ctx.writeResource("node", nn, {
        name: r.name,
        url: r.url,
        reachable: r.reachable,
        error: r.error,
        transport: targets.find((t) => t.name === r.name)?.ssh ? "ssh" : "http",
        ...identity,
        charts: chartsVal,
        alarmsActive: alarmsActiveVal,
        alarmsCritical: alarmsCriticalVal,
        alarmsWarning: alarmsWarningVal,
        mountsOverThreshold: mountsOverVal,
      }, {
        tags: {
          reachable: String(r.reachable),
          os: identity.osName ?? "unknown",
          alarmsCritical: String(alarmsCriticalVal),
        },
      }),
    );
  }

  handles.push(
    await ctx.writeResource("summary", "summary", {
      nodes: results.length,
      nodesReachable: reachable,
      nodesUnreachable: results.length - reachable,
      nodesDegraded,
      alarmsActive,
      alarmsCritical,
      mountsOverThreshold: overThreshold,
      syncedAt: new Date().toISOString(),
    }, {
      tags: {
        alarmsCritical: String(alarmsCritical),
        nodesDegraded: String(nodesDegraded),
      },
    }),
  );
  live.add("summary");

  // Prune only on a full sweep — a single-node run legitimately sees a
  // subset. Skip anything explicitly protected this round (see above) even
  // though it isn't in `live`, and skip anything already in `live`.
  if (!args.node) {
    const existing = await ctx.dataRepository.findAllForModel(
      ctx.modelType,
      ctx.modelId,
    );
    for (const rec of existing) {
      if (live.has(rec.name)) continue;
      if (protectedPrefixes.some((p) => rec.name.startsWith(p))) continue;
      await ctx.dataRepository.delete(ctx.modelType, ctx.modelId, rec.name);
      ctx.logger.info("pruned {name}", { name: rec.name });
    }
  }

  ctx.logger.info(
    "{reachable}/{total} node(s) reachable, {alarms} active alarm(s), " +
      "{over} mount(s) over {pct}%",
    {
      reachable,
      total: results.length,
      alarms: alarmsActive,
      over: overThreshold,
      pct: g.diskWarnPercent,
    },
  );

  return { dataHandles: handles };
}

/**
 * The `@jpisgeek/netdata` model definition: a single `discover` method that
 * polls every configured node concurrently and records reachability,
 * alarms, and filesystem capacity as separate resources. See the module
 * header above for why this deliberately stops short of being a metrics
 * collector or a second health engine.
 */
export const model = {
  type: "@jpisgeek/netdata",
  version: "2026.08.23.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    node: {
      description:
        "One record per Netdata node: identity, version, reachability, " +
        "alarm counts, and whether it streams to Netdata Cloud. An " +
        "unreachable node is recorded with reachable:false, not skipped. " +
        "Identity and count fields carry forward the last known values " +
        "when a poll can't refresh them; consumers should treat `reachable` " +
        "and the per-node record's freshness (not a zeroed field) as the " +
        "signal that something changed.",
      schema: NodeStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    alarm: {
      description:
        "One record per active Netdata alarm. Thresholds are Netdata's own " +
        "health engine — swamp records the verdict, it does not re-derive it.",
      schema: AlarmSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    mount: {
      description:
        "One record per filesystem, discovered from the agent's chart list " +
        "rather than assumed chart names, since these differ per platform.",
      schema: MountSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    summary: {
      description: "Single roll-up of the most recent sweep.",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  methods: {
    discover: {
      description:
        "Poll every configured Netdata node concurrently (bounded by " +
        "maxConcurrency) and record node state, active alarms, and " +
        "filesystem capacity. Unreachable nodes are recorded rather than " +
        "raised. A full sweep prunes departed records; a single-node run " +
        "does not. A node that answers only partially this round (an " +
        "alarms/charts sub-fetch failed) keeps its last known detail " +
        "instead of being zeroed or pruned.",
      arguments: DiscoverArgsSchema,
      execute: discover,
    },
  },
};
