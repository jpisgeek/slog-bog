/**
 * Homelab dashboard renderer.
 *
 * Reads the resources already written by the collector models and emits one
 * self-contained HTML file. It collects nothing itself and reaches no network
 * — if a source model has not run, the dashboard says so rather than inventing
 * a value.
 *
 * The page is exceptions-first: what needs a human goes at the top, everything
 * healthy collapses to one line. A dashboard that lists 38 healthy devices
 * trains you to stop reading it.
 *
 * Delivery is deliberately not this model's job. It writes a file to disk;
 * shipping it to the web server is `@swamp/ssh copy` in the workflow, because
 * that already exists and does it properly.
 */
import { z } from "npm:zod@4";

const SourceSchema = z.object({
  name: z.string().describe(
    "Source alias the render rules key off of — not free-text display. " +
      "Must be exactly one of telemetry, nas, homelab, firewalla; render's " +
      "exception rules match on these literal names.",
  ),
  type: z.string().describe("Model type, e.g. @jpisgeek/firewalla"),
  id: z.string().describe("Model id from `swamp model get <name> --json`"),
});

const SuppressionSchema = z.object({
  id: z.string().describe(
    "Exception id to suppress, e.g. unreachable:host.example.net",
  ),
  reason: z.string().describe("Why this is expected — shown on the page"),
});

const GlobalArgsSchema = z.object({
  title: z.string().default("Homelab"),
  sources: z.array(SourceSchema).min(1),
  outputPath: z
    .string()
    .default("./dashboard/index.html")
    .describe("Where the rendered HTML is written"),
  diskWarnPercent: z.number().min(1).max(100).default(85),
  certWarnDays: z.number().int().positive().default(30),
  suppress: z
    .array(SuppressionSchema)
    .default([])
    .describe(
      "Known-and-accepted states that must not nag. They still appear, " +
        "listed separately as 'expected', so suppression stays visible " +
        "rather than becoming a silent blind spot.",
    ),
});

const RenderArgsSchema = z.object({});

const ExceptionSchema = z.object({
  id: z.string(),
  severity: z.string(),
  subject: z.string(),
  headline: z.string(),
  detail: z.string(),
  source: z.string(),
  suppressed: z.boolean(),
  suppressReason: z.string(),
  /**
   * True when `headline` or `detail` was cut to its display cap (160 and 140
   * characters respectively). Without this, a truncated string is
   * indistinguishable from a naturally short one — the record itself must
   * disclose the loss, not just the render.
   */
  truncated: z.boolean(),
});

const RenderSchema = z.object({
  outputPath: z.string(),
  bytes: z.number(),
  exceptions: z.number(),
  suppressed: z.number(),
  critical: z.number(),
  warning: z.number(),
  sourcesRead: z.number(),
  sourcesStale: z.array(z.string()),
  renderedAt: z.string(),
});

interface Exc {
  id: string;
  severity: "critical" | "warning" | "info";
  subject: string;
  headline: string;
  detail: string;
  source: string;
  suppressed: boolean;
  suppressReason: string;
  truncated: boolean;
}

const SEV_RANK: Record<string, number> = { critical: 0, warning: 1, info: 2 };

/**
 * getContent has returned the resource body directly in some paths and a
 * record wrapping it in others. Accept a JSON string, a {content:...} or
 * {attributes:...} wrapper, or the body itself, rather than guessing once and
 * silently producing undefined fields.
 */
function normalizeContent(raw: unknown): Record<string, unknown> | null {
  if (raw == null) return null;
  // getContent returns the stored bytes, not a parsed object. Decode first --
  // spreading a Uint8Array yields {0:..,1:..} and every field reads undefined.
  if (raw instanceof Uint8Array) {
    return normalizeContent(new TextDecoder().decode(raw));
  }
  if (raw instanceof ArrayBuffer) {
    return normalizeContent(new TextDecoder().decode(new Uint8Array(raw)));
  }
  if (Array.isArray(raw) && raw.every((b) => typeof b === "number")) {
    return normalizeContent(new TextDecoder().decode(Uint8Array.from(raw)));
  }
  if (typeof raw === "string") {
    try {
      return normalizeContent(JSON.parse(raw));
    } catch {
      return null;
    }
  }
  if (typeof raw !== "object") return null;
  const rec = raw as Record<string, unknown>;
  for (const key of ["content", "attributes", "data"]) {
    const inner = rec[key];
    if (inner && typeof inner === "object" && !Array.isArray(inner)) {
      return inner as Record<string, unknown>;
    }
    if (typeof inner === "string") {
      try {
        const parsed = JSON.parse(inner);
        if (parsed && typeof parsed === "object") {
          return parsed as Record<string, unknown>;
        }
      } catch { /* fall through */ }
    }
  }
  return rec;
}

function esc(s: unknown): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Deterministic 32-bit FNV-1a hash, rendered as 8 lowercase hex characters.
 * Used to make instance names collision-safe: two different raw ids that
 * normalize to the same slug (e.g. "alarm:a/b" and "alarm:a-b" both becoming
 * "alarm-a-b") still get different resource names, because the hash is taken
 * over the un-normalized input. Same input always yields the same hash, so a
 * re-render of the same exception still overwrites its own prior resource
 * rather than creating a duplicate.
 */
function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

/** Collision-safe resource name for an exception, keyed on its full raw id. */
function exceptionResourceName(id: string): string {
  const slug = id.replace(/[^a-zA-Z0-9]+/g, "-").toLowerCase().replace(
    /^-+|-+$/g,
    "",
  );
  return `exception-${slug || "id"}-${fnv1a(id)}`;
}

function ago(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "unknown";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 172800) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

/**
 * The `@jpisgeek/dashboard` model definition: a single `render` method that
 * reads every configured source model's latest resources, evaluates the
 * exception rules in `render.execute` below, and writes a self-contained
 * HTML page. See the module header above for why rendering never touches
 * the network and why delivering the file is deliberately out of scope.
 */
export const model = {
  type: "@jpisgeek/dashboard",
  version: "2026.08.22.2",
  globalArguments: GlobalArgsSchema,

  checks: {
    "known-source-aliases": {
      description:
        "render's exception rules key off the literal source aliases " +
        "telemetry, nas, homelab, and firewalla. A `sources` list missing " +
        "one of these produces a dashboard that looks complete but " +
        "silently drops an entire category of exceptions. Skippable for " +
        "deployments that intentionally omit a collector.",
      labels: ["policy"],
      appliesTo: ["render"],
      // deno-lint-ignore no-explicit-any
      execute: (ctx: any) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const required = ["telemetry", "nas", "homelab", "firewalla"];
        const present = new Set(g.sources.map((s: { name: string }) => s.name));
        const missing = required.filter((r) => !present.has(r));
        if (missing.length > 0) {
          return Promise.resolve({
            pass: false,
            errors: [
              `sources is missing required alias(es): ${
                missing.join(", ")
              }. render's rules match on these exact names; without them ` +
              "that source's exceptions never evaluate, even though the " +
              "config otherwise looks valid.",
            ],
          });
        }
        return Promise.resolve({ pass: true });
      },
    },
  },

  resources: {
    exception: {
      description:
        "One record per detected exception, including suppressed ones. " +
        "Queryable independently of the HTML so alerting can be built on " +
        "the same evaluation rather than a second copy of the logic.",
      schema: ExceptionSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    render: {
      description: "Outcome of the most recent render: counts and staleness.",
      schema: RenderSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  methods: {
    render: {
      description:
        "Read every source model's latest resources, evaluate exception " +
        "rules, and write a self-contained HTML page. Reads only stored " +
        "data — never the network.",
      arguments: RenderArgsSchema,
      // deno-lint-ignore no-explicit-any
      execute: async (_args: unknown, ctx: any) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);

        ctx.logger.info(
          "rendering {title} from {n} configured source(s)",
          { title: g.title, n: g.sources.length },
        );

        // ---- load every source's latest resources ------------------------
        // Cross-model reads: `readResource` is scoped to this model's own
        // instance and cannot reach another model's stored data, so reading
        // what telemetry/nas/homelab/firewalla wrote has no choice but to go
        // through the lower-level `dataRepository` (findAllForModel + getContent).
        const bySource: Record<string, Record<string, unknown>[]> = {};
        const stale: string[] = [];
        let sourcesRead = 0;

        for (const src of g.sources) {
          const rows: Record<string, unknown>[] = [];
          let errored = false;
          try {
            const names = await ctx.dataRepository.findAllForModel(
              src.type,
              src.id,
            );
            for (const rec of names) {
              const raw = await ctx.dataRepository.getContent(
                src.type,
                src.id,
                rec.name,
              );
              const content = normalizeContent(raw);
              if (content) rows.push({ __name: rec.name, ...content });
            }
            sourcesRead++;
          } catch (e) {
            errored = true;
            // A read failure here is a live problem (repo error, transient
            // fault) — not the benign "this source has just never run yet"
            // case below. It gets its own log line at warning, with the
            // real error, rather than being silently folded into "stale".
            ctx.logger.warning(
              "source {name} ({type}/{id}) unreadable: {err}",
              {
                name: src.name,
                type: src.type,
                id: src.id,
                err: (e as Error).message,
              },
            );
          }
          if (rows.length === 0) {
            stale.push(src.name);
            if (!errored) {
              ctx.logger.info(
                "source {name} has no usable records yet (never collected, " +
                  "or nothing parsed)",
                { name: src.name },
              );
            }
          }
          bySource[src.name] = rows;
        }

        const pick = (source: string, spec: string) =>
          (bySource[source] ?? []).filter((r) =>
            String(r.__name ?? "").startsWith(spec)
          );

        const exceptions: Exc[] = [];
        const add = (e: Exc) => exceptions.push(e);

        // ---- telemetry: nodes, alarms, mounts ----------------------------
        const nodes = pick("telemetry", "node-");
        for (const n of nodes) {
          if (!n.reachable) {
            add({
              id: `unreachable:${n.name}`,
              severity: "critical",
              subject: String(n.name),
              headline: "Netdata agent unreachable",
              detail: String(n.error || "no response"),
              source: "telemetry",
              suppressed: false,
              suppressReason: "",
              truncated: false,
            });
          }
        }
        for (const a of pick("telemetry", "alarm-")) {
          const crit = String(a.status).toUpperCase() === "CRITICAL";
          add({
            id: `alarm:${a.node}:${a.name}`,
            severity: crit ? "critical" : "warning",
            subject: String(a.node),
            headline: String(a.info || a.name),
            detail: `${a.name} — ${a.value}${a.units}`,
            source: "netdata",
            suppressed: false,
            suppressReason: "",
            truncated: false,
          });
        }
        for (const m of pick("telemetry", "mount-")) {
          const pct = Number(m.usedPercent ?? 0);
          if (pct >= g.diskWarnPercent) {
            add({
              id: `disk:${m.node}:${m.mount}`,
              severity: pct >= 95 ? "critical" : "warning",
              subject: String(m.node),
              headline: `${m.mount} is ${pct}% full`,
              detail: `${m.usedGiB} of ${m.totalGiB} GiB used`,
              source: "netdata",
              suppressed: false,
              suppressReason: "",
              truncated: false,
            });
          }
        }

        // ---- truenas: pools, certs, alerts --------------------------------
        for (const p of pick("nas", "pool-")) {
          if (!p.healthy) {
            add({
              id: `pool:${p.name}`,
              severity: "critical",
              subject: "nas",
              headline: `Pool ${p.name} is ${p.status}`,
              detail: `${p.usedPercent}% used`,
              source: "truenas",
              suppressed: false,
              suppressReason: "",
              truncated: false,
            });
          }
        }
        for (const c of pick("nas", "cert-")) {
          if (!c.expiryKnown) continue;
          const days = Number(c.daysRemaining);
          if (c.expired) {
            add({
              id: `cert:${c.name}`,
              severity: "critical",
              subject: "nas",
              headline: `Certificate ${c.name} expired`,
              detail: `${Math.abs(days)} days ago`,
              source: "truenas",
              suppressed: false,
              suppressReason: "",
              truncated: false,
            });
          } else if (c.expiringSoon) {
            add({
              id: `cert:${c.name}`,
              severity: days <= 7 ? "critical" : "warning",
              subject: "nas",
              headline: `Certificate ${c.name} expires in ${days} days`,
              detail: String(c.commonName || ""),
              source: "truenas",
              suppressed: false,
              suppressReason: "",
              truncated: false,
            });
          }
        }
        for (const a of pick("nas", "alert-")) {
          // TrueNAS raises its own alert for a cert we already evaluated
          // independently. Do not show the same fact twice -- fold the part
          // that only the alert knows (that a human dismissed it) into the
          // certificate row instead.
          if (String(a.klass) === "CertificateIsExpiring") {
            const certExc = exceptions.find((e) => e.id.startsWith("cert:"));
            if (certExc) {
              if (a.silenced) {
                certExc.detail += `${
                  certExc.detail ? " · " : ""
                }TrueNAS raised this and it was dismissed`;
              }
              continue;
            }
          }
          // A dismissed alert is invisible in the TrueNAS UI while the
          // condition behind it stays true. That is exactly what an external
          // view is for, so it is raised here regardless of dismissal.
          //
          // TrueNAS's own alert id (`a.id`, always populated by truenas.ts)
          // disambiguates the exception id: multiple alerts can share a
          // `klass` (e.g. two independent CertificateIsExpiring instances),
          // and keying on klass alone collapsed them onto one instance name.
          const formatted = String(a.formatted);
          const headlineTruncated = formatted.length > 160;
          add({
            id: `nasalert:${a.klass}:${String(a.id ?? a.__name ?? "")}`,
            severity: String(a.level).toUpperCase() === "CRITICAL"
              ? "critical"
              : "warning",
            subject: "nas",
            headline: formatted.slice(0, 160),
            detail: a.silenced
              ? "Dismissed in the TrueNAS UI — still true"
              : String(a.klass),
            source: "truenas",
            suppressed: false,
            suppressReason: "",
            truncated: headlineTruncated,
          });
        }

        // ---- ssh fleet reachability --------------------------------------
        // Only the exec probe measures reachability. `copy` and `script`
        // records also live under run-*, but a failed file upload says
        // nothing about whether the host is up -- and because render runs
        // before publish, the publish result is always a cycle stale.
        const runs = pick("homelab", "run-exec-");
        // "Latest" per host: findAllForModel's order is not guaranteed to be
        // chronological, so prefer a timestamp when the run record carries
        // one and fall back to listing order only when it doesn't.
        const runTime = (r: Record<string, unknown>): number => {
          for (
            const k of [
              "finishedAt",
              "completedAt",
              "endedAt",
              "startedAt",
              "timestamp",
            ]
          ) {
            const t = Date.parse(String(r[k] ?? ""));
            if (Number.isFinite(t)) return t;
          }
          return Number.NEGATIVE_INFINITY;
        };
        const latestPerHost = new Map<string, Record<string, unknown>>();
        for (const r of runs) {
          const h = String(r.host ?? "");
          if (!h) continue;
          const prev = latestPerHost.get(h);
          if (!prev || runTime(r) >= runTime(prev)) latestPerHost.set(h, r);
        }
        for (const [host, r] of latestPerHost) {
          // A record with no exit code is "unknown", not "succeeded" -- skip
          // it rather than let a missing field read as a clean probe.
          if (r.exitCode === undefined || r.exitCode === null) continue;
          if (Number(r.exitCode) !== 0) {
            const err = String(r.stderr ?? "").trim().split("\n").pop() ?? "";
            add({
              id: `ssh:${host}`,
              severity: "warning",
              subject: host,
              headline: "SSH probe failed — host unreachable",
              detail: err.slice(0, 140),
              source: "ssh",
              suppressed: false,
              suppressReason: "",
              truncated: err.length > 140,
            });
          }
        }

        // ---- apply suppressions ------------------------------------------
        const supMap = new Map(g.suppress.map((s) => [s.id, s.reason]));
        for (const e of exceptions) {
          const reason = supMap.get(e.id);
          if (reason !== undefined) {
            e.suppressed = true;
            e.suppressReason = reason;
          }
        }

        exceptions.sort((a, b) =>
          (SEV_RANK[a.severity] - SEV_RANK[b.severity]) ||
          a.subject.localeCompare(b.subject)
        );
        const active = exceptions.filter((e) => !e.suppressed);
        const expected = exceptions.filter((e) => e.suppressed);

        // ---- healthy-state counts ----------------------------------------
        const inv = pick("firewalla", "inventory")[0] ?? {};
        const nasSummary = pick("nas", "summary")[0] ?? {};
        const telSummary = pick("telemetry", "summary")[0] ?? {};
        const facts = [
          [`${inv.total ?? "?"}`, "devices"],
          [`${inv.machines ?? "?"}`, "machines"],
          [
            `${telSummary.nodesReachable ?? "?"}/${telSummary.nodes ?? "?"}`,
            "agents up",
          ],
          [`${nasSummary.pools ?? "?"}`, "pool"],
          [`${nasSummary.disks ?? "?"}`, "disks"],
        ];

        const now = new Date().toISOString();
        const html = renderHtml({
          title: g.title,
          now,
          active,
          expected,
          facts,
          stale,
          inv,
          nasSummary,
          telSummary,
          nodes,
          mounts: pick("telemetry", "mount-"),
          certs: pick("nas", "cert-"),
          machines: pick("firewalla", "machine-"),
        });

        // ---- write -----------------------------------------------------
        // No multi-resource transaction exists in the model API — each
        // writeResource/file write is its own commit, so an interruption
        // partway through can never be made fully atomic. Given that
        // constraint, order writes by what matters most if the run dies
        // mid-way:
        //   1. exception + render resources — the queryable data this
        //      model's own docs describe as the thing alerting is meant to
        //      be built on, so it is committed first;
        //   2. the HTML file — a re-render always regenerates it, so it is
        //      the cheapest thing to leave stale;
        //   3. pruning stale exceptions — destructive, so it runs only once
        //      the new generation is durably written, never before.
        const out = g.outputPath;
        const htmlBytes = new TextEncoder().encode(html).length;

        const handles = [];
        const liveNames = new Set<string>(["render"]);
        for (const e of exceptions) {
          const resName = exceptionResourceName(e.id);
          liveNames.add(resName);
          handles.push(
            await ctx.writeResource(
              "exception",
              resName,
              e,
              {
                tags: {
                  severity: e.severity,
                  subject: e.subject,
                  suppressed: String(e.suppressed),
                },
              },
            ),
          );
        }
        handles.push(
          await ctx.writeResource("render", "render", {
            outputPath: out,
            bytes: htmlBytes,
            exceptions: active.length,
            suppressed: expected.length,
            critical: active.filter((e) => e.severity === "critical").length,
            warning: active.filter((e) => e.severity === "warning").length,
            sourcesRead,
            sourcesStale: stale,
            renderedAt: now,
          }, {
            tags: {
              critical: String(
                active.filter((e) => e.severity === "critical").length,
              ),
              exceptions: String(active.length),
            },
          }),
        );

        const dir = out.slice(0, out.lastIndexOf("/"));
        if (dir) {
          try {
            await Deno.mkdir(dir, { recursive: true });
          } catch (e) {
            // Not fatal on its own — writeTextFile below will throw its own,
            // more specific error if the directory genuinely couldn't be
            // created. But a swallowed exception here previously left no
            // trace at all when it wasn't benign (e.g. a permissions error
            // on a parent path), so it's logged rather than dropped.
            ctx.logger.warning(
              "could not create output directory {dir}: {err}",
              { dir, err: (e as Error).message },
            );
          }
        }
        await Deno.writeTextFile(out, html);

        // An exception that no longer fires must disappear. Without this a
        // resolved problem stays on the page forever and the dashboard stops
        // meaning anything. `findAllForModel` is the only way to enumerate
        // this model instance's own prior resources (readResource takes a
        // single instance name, not a listing) — `deleteResource` is then
        // used for the actual delete, per the documented resource-cleanup
        // API, rather than dropping straight to dataRepository.delete.
        const existing = await ctx.dataRepository.findAllForModel(
          ctx.modelType,
          ctx.modelId,
        );
        let pruned = 0;
        for (const rec of existing) {
          if (rec.name.startsWith("exception-") && !liveNames.has(rec.name)) {
            await ctx.deleteResource(rec.name);
            pruned++;
          }
        }
        if (pruned > 0) {
          ctx.logger.info("pruned {n} resolved exception(s)", { n: pruned });
        }

        ctx.logger.info(
          "rendered {bytes} bytes: {active} exception(s), {sup} expected, " +
            "{stale} stale source(s)",
          {
            bytes: htmlBytes,
            active: active.length,
            sup: expected.length,
            stale: stale.length,
          },
        );

        return { dataHandles: handles };
      },
    },
  },
};

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

// deno-lint-ignore no-explicit-any
function renderHtml(d: any): string {
  const sevIcon: Record<string, string> = {
    critical: "●",
    warning: "▲",
    info: "•",
  };

  const excRow = (e: Exc, muted = false) => `
      <li class="exc ${e.severity}${muted ? " muted" : ""}">
        <span class="sev">${sevIcon[e.severity] ?? "•"}</span>
        <div class="body">
          <div class="head"><strong>${esc(e.subject)}</strong> ${
    esc(e.headline)
  }</div>
          <div class="det">${esc(e.detail)}${
    muted && e.suppressReason
      ? ` · <em>expected: ${esc(e.suppressReason)}</em>`
      : ""
  }</div>
        </div>
        <span class="src">${esc(e.source)}</span>
      </li>`;

  const nodeRow = (n: Record<string, unknown>) => `
        <tr><td>${esc(n.name)}</td><td>${esc(n.osName)} ${esc(n.osVersion)}</td>
        <td>${esc(n.version)}</td><td>${esc(n.transport)}</td>
        <td class="${n.reachable ? "ok" : "bad"}">${
    n.reachable ? "up" : "down"
  }</td>
        <td>${esc(n.claimedToCloud ? "yes" : "no")}</td></tr>`;

  const mountRow = (m: Record<string, unknown>) => {
    const pct = Number(m.usedPercent ?? 0);
    return `
        <tr><td>${esc(m.node)}</td><td class="mono">${esc(m.mount)}</td>
        <td class="num">${pct}%</td>
        <td class="barcell"><span class="bar"><i style="width:${
      Math.min(100, pct)
    }%"></i></span></td>
        <td class="num">${esc(m.totalGiB)} GiB</td></tr>`;
  };

  const certRow = (c: Record<string, unknown>) => `
        <tr><td>${esc(c.name)}</td>
        <td>${
    c.expiryKnown ? esc(c.daysRemaining) + " days" : "<em>no expiry</em>"
  }</td>
        <td>${esc(c.commonName)}</td></tr>`;

  const machineRow = (m: Record<string, unknown>) => `
        <tr><td>${esc(m.name)}</td><td class="mono">${esc(m.primaryIp)}</td>
        <td>${esc(m.deviceType)}</td><td>${
    esc((m.networks as string[] ?? []).join(", "))
  }</td>
        <td class="${m.online ? "ok" : "muted"}">${
    m.online ? "online" : "offline"
  }</td></tr>`;

  const allClear = d.active.length === 0;

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${esc(d.title)}</title>
<style>
:root{--bg:#fbfbfa;--fg:#1a1a19;--dim:#6b6b68;--line:#e4e4e1;--card:#fff;
--crit:#b4231f;--warn:#a4620a;--ok:#2f6b34;--accent:#1a1a19}
@media(prefers-color-scheme:dark){:root{--bg:#131313;--fg:#e8e8e6;--dim:#8f8f8b;
--line:#2a2a29;--card:#1b1b1a;--crit:#ef6d63;--warn:#d99a3e;--ok:#71b877;--accent:#e8e8e6}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
-webkit-text-size-adjust:100%}
.wrap{max-width:820px;margin:0 auto;padding:22px 16px 64px}
header{display:flex;justify-content:space-between;align-items:baseline;
gap:12px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:19px;margin:0;letter-spacing:-.01em}
.ts{color:var(--dim);font-size:12.5px;font-variant-numeric:tabular-nums}
.banner{border:1px solid var(--line);background:var(--card);border-radius:10px;
padding:14px 16px;margin-bottom:18px}
.banner.clear{border-color:color-mix(in srgb,var(--ok) 40%,var(--line))}
.banner h2{margin:0 0 2px;font-size:15px}
.banner .sub{color:var(--dim);font-size:13px}
ul.excs{list-style:none;margin:12px 0 0;padding:0;display:flex;flex-direction:column;gap:1px}
.exc{display:flex;gap:11px;align-items:flex-start;padding:11px 12px;
background:var(--card);border:1px solid var(--line);border-radius:8px}
.exc+.exc{margin-top:6px}
.exc .sev{font-size:12px;line-height:1.4;padding-top:2px}
.exc.critical .sev{color:var(--crit)}
.exc.warning .sev{color:var(--warn)}
.exc .body{flex:1;min-width:0}
.exc .head{font-size:14px}
.exc .det{color:var(--dim);font-size:12.5px;margin-top:2px;overflow-wrap:anywhere}
.exc .src{color:var(--dim);font-size:11px;text-transform:uppercase;
letter-spacing:.05em;padding-top:3px;white-space:nowrap}
.exc.muted{opacity:.62}
.facts{display:flex;flex-wrap:wrap;gap:6px 20px;margin-top:10px}
.facts div{font-size:13px;color:var(--dim)}
.facts b{color:var(--fg);font-variant-numeric:tabular-nums}
details{border-top:1px solid var(--line);margin-top:26px;padding-top:14px}
summary{cursor:pointer;font-size:13px;color:var(--dim);
text-transform:uppercase;letter-spacing:.05em}
summary::marker{color:var(--dim)}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px;
display:block;overflow-x:auto;white-space:nowrap}
th{text-align:left;font-weight:600;color:var(--dim);font-size:11px;
text-transform:uppercase;letter-spacing:.05em;padding:6px 10px 6px 0;
border-bottom:1px solid var(--line)}
td{padding:7px 10px 7px 0;border-bottom:1px solid var(--line)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.num{font-variant-numeric:tabular-nums;text-align:right}
.ok{color:var(--ok)} .bad{color:var(--crit)} .muted{color:var(--dim)}
.barcell{width:110px}
.bar{display:block;width:100px;height:6px;background:var(--line);border-radius:3px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--accent);opacity:.55}
.stale{margin-top:14px;font-size:12.5px;color:var(--warn)}
footer{margin-top:34px;color:var(--dim);font-size:12px;
border-top:1px solid var(--line);padding-top:12px}
</style></head><body><div class="wrap">

<header>
  <h1>${esc(d.title)}</h1>
  <div class="ts">rendered ${esc(ago(d.now))}</div>
</header>

<div class="banner${allClear ? " clear" : ""}">
  <h2>${
    allClear
      ? "Nothing needs you"
      : `${d.active.length} thing${d.active.length === 1 ? "" : "s"} need${
        d.active.length === 1 ? "s" : ""
      } you`
  }</h2>
  <div class="sub">${
    allClear
      ? "All checks passed at last collection."
      : `${
        d.active.filter((e: Exc) => e.severity === "critical").length
      } critical · ${
        d.active.filter((e: Exc) => e.severity === "warning").length
      } warning`
  }</div>
  <div class="facts">${
    d.facts.map(([v, k]: [string, string]) =>
      `<div><b>${esc(v)}</b> ${esc(k)}</div>`
    ).join("")
  }</div>
  ${
    d.stale.length
      ? `<div class="stale">⚠ no usable data from: ${
        esc(d.stale.join(", "))
      } (never collected, or unreadable — check the render log)</div>`
      : ""
  }
</div>

${
    d.active.length
      ? `<ul class="excs">${d.active.map((e: Exc) => excRow(e)).join("")}</ul>`
      : ""
  }

${
    d.expected.length
      ? `<details open><summary>Expected — ${d.expected.length} suppressed</summary>
<ul class="excs">${
        d.expected.map((e: Exc) => excRow(e, true)).join("")
      }</ul></details>`
      : ""
  }

<details><summary>Nodes — ${d.nodes.length}</summary>
<table><thead><tr><th>node</th><th>os</th><th>netdata</th><th>via</th><th>state</th><th>cloud</th></tr></thead>
<tbody>${d.nodes.map(nodeRow).join("")}</tbody></table></details>

<details><summary>Storage — ${d.mounts.length} mounts</summary>
<table><thead><tr><th>node</th><th>mount</th><th>used</th><th></th><th>size</th></tr></thead>
<tbody>${
    d.mounts.sort((a: Record<string, unknown>, b: Record<string, unknown>) =>
      Number(b.usedPercent) - Number(a.usedPercent)
    ).map(mountRow).join("")
  }</tbody></table></details>

<details><summary>Certificates — ${d.certs.length}</summary>
<table><thead><tr><th>name</th><th>remaining</th><th>common name</th></tr></thead>
<tbody>${d.certs.map(certRow).join("")}</tbody></table></details>

<details><summary>Machines — ${d.machines.length}</summary>
<table><thead><tr><th>machine</th><th>address</th><th>type</th><th>network</th><th>state</th></tr></thead>
<tbody>${
    d.machines.sort((a: Record<string, unknown>, b: Record<string, unknown>) =>
      String(a.name).localeCompare(String(b.name))
    ).map(machineRow).join("")
  }</tbody></table></details>

<footer>
  Rendered by swamp from stored model data — no live queries.
  Sources: Firewalla MSP · TrueNAS JSON-RPC · Netdata agents · SSH fleet.
  <br>Generated ${esc(d.now)}
</footer>

</div></body></html>`;
}
