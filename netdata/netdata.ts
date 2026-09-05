/**
 * Netdata standalone agent state, across a set of nodes.
 *
 * Deliberately NOT a metrics collector. Netdata already stores high-resolution
 * telemetry on each node and runs its own health engine. Duplicating either
 * in swamp would be slower and worse. What this model hauls out of the bog is
 * state truth: which nodes answer, what they are, which alarms are firing,
 * and how much headroom is left. The stuff you correlate against inventory
 * and actually act on.
 *
 * Chart names are platform-specific (macOS has no `system.cpu` and does have
 * `macos.gpu_*`, Linux differs again), so mount discovery reads the agent's
 * own chart list rather than assuming names. Alarm thresholds are Netdata's,
 * not ours.
 *
 * A node that does not answer is data, not an error. It gets written with
 * `reachable: false` and the sweep moves on. A homelab always has something
 * powered off. A node that answered before but only partially answers this
 * round (alarms or chart data timed out, say) keeps its last known detail
 * instead of being zeroed out or pruned. See the discover() comments below.
 */
import { z } from "npm:zod@4";

/**
 * Parse and validate one node base URL, returning the CANONICAL base string
 * swamp will actually talk to, or null if the value is not usable.
 *
 * ONE point of truth on purpose: the `url` refine below and pollNode() both go
 * through this, so what was validated and what is requested cannot drift. That
 * split is exactly how a query string got through. The refine only looked at
 * the scheme, the userinfo and the quote; the call site then did
 * `node.url.replace(/\/+$/, "")` and concatenated the endpoint onto it. For
 * `http://agent:19999/?k=v` that produced
 * `http://agent:19999/?k=v/api/v1/info` -- a GET of `/` with the endpoint
 * smuggled into the query string. Every /api/v1 endpoint the model believed it
 * had polled was in fact one response from one attacker-chosen resource, and
 * `/api/v1/info` answering anything JSON-shaped made the node read reachable.
 * A fragment did the same thing more quietly: fetch drops everything from `#`
 * on, so all four endpoints collapsed onto `/`.
 *
 * Rejected, and why:
 *  - a scheme other than http/https: Deno fetch honours `file:`, and the remote
 *    curl honours file:, ftp:, dict:, scp: -- an SSRF and local-read footgun.
 *  - userinfo: node.url is persisted and logged as non-sensitive data, so
 *    `user:pass@host` would write a credential into the datastore.
 *  - a query string or a fragment: the endpoint-construction break above, plus
 *    the same disclosure problem -- `?api_key=...` is how agent front-ends
 *    carry credentials in practice, and this value is persisted.
 *  - a single quote in the canonical base: over the ssh transport the base is
 *    interpolated into a single-quoted remote command, and `new URL()` does
 *    NOT percent-encode an apostrophe in a path.
 *
 * The returned base is rebuilt from the VALIDATED components rather than being
 * the operator's string minus its trailing slashes. `http://agent:19999?`
 * parses with an empty `search` while still carrying the delimiter, and
 * `new URL()` silently strips embedded tabs and newlines instead of rejecting
 * them; rebuilding means neither reaches the wire or the datastore.
 */
function parseNodeUrl(v: string): string | null {
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  if (u.username !== "" || u.password !== "") return null;
  if (v.includes("?") || v.includes("#")) return null;
  if (u.search !== "" || u.hash !== "") return null;
  // u.host carries the port and the IPv6 brackets; userinfo is excluded above.
  const base = `${u.protocol}//${u.host}${u.pathname}`.replace(/\/+$/, "");
  if (base.includes("'")) return null;
  return base;
}

const NodeSchema = z.object({
  // Bounded and de-controlled at the CONFIG boundary, because a node name is
  // not just a label: it is written to the `node`/`alarm`/`mount` records, it
  // becomes a resource TAG, it is hashed into every alarm and mount instance
  // name, and its slug IS the node instance name (`node-<slug>`). An
  // unbounded `z.string()` therefore made the generated instance identifier --
  // a datastore key, a filename and a CLI argument -- as long as the operator's
  // paste buffer, and a name carrying a raw NUL/CR/ESC put a control byte into
  // all of those at once. agentText() bounds the AGENT-supplied strings; this
  // is the same rule for the one identity string swamp itself is handed.
  // 64 characters is above any real hostname label (63) and any SSH fleet name.
  name: z
    .string()
    .min(1)
    .max(64)
    // deno-lint-ignore no-control-regex
    .regex(/^[^\u0000-\u001f\u007f]+$/, {
      message: "node name must not contain control characters; it becomes a " +
        "resource instance name, a tag and a log field",
    })
    .describe(
      "Logical node name; match the SSH fleet name. 1-64 characters, no " +
        "control characters: it becomes this model's resource instance names.",
    ),
  url: z
    .string()
    .refine(
      (v) => parseNodeUrl(v) !== null,
      {
        message: "url must be a valid http(s) URL with no credentials " +
          "(user:pass@host), no query string, no fragment and no single " +
          "quote. discover persists the node URL as non-sensitive data and " +
          "builds every endpoint by appending to it, so a `?`/`#` both leaks " +
          "and silently redirects every request to `/`. Use the ssh " +
          "transport for agents that require authentication.",
      },
    )
    .describe(
      "Agent base URL, e.g. http://netdata.example.com:19999",
    ),
  ssh: z
    .object({
      // host/user become the positional `user@host` argument to ssh. A value
      // starting with "-" would be parsed as an ssh option (-oProxyCommand=…).
      //
      // The charset bound is the other half, and it is not cosmetic. These two
      // values are the only operator-supplied strings that end up inside a
      // transport failure message, and a host or user containing whitespace
      // used to change the SHAPE of that message enough to walk straight past
      // the persisted-error classifier -- which matched `^ssh to \S+ failed:`
      // and fell back to echoing raw text when it missed. Errors now carry a
      // fixed class token rather than being re-parsed from prose (see
      // NodeFailure), so that specific bypass is gone; bounding the charset
      // keeps the values from being surprising to ssh, to argv and to a log
      // consumer in the first place. Hostnames, IPv4/IPv6 literals and real
      // usernames all fit.
      host: z
        .string()
        .min(1)
        .max(253)
        .regex(/^[A-Za-z0-9._:\-\[\]]+$/, {
          message:
            "ssh.host may only contain letters, digits and . _ - : [ ] " +
            "(hostname, IPv4 or bracketed IPv6)",
        })
        .refine((v) => !v.startsWith("-"), {
          message: "ssh.host must not start with '-'",
        }),
      user: z
        .string()
        .min(1)
        .max(64)
        .regex(/^[A-Za-z0-9._-]+$/, {
          message: "ssh.user may only contain letters, digits and . _ -",
        })
        .refine((v) => !v.startsWith("-"), {
          message: "ssh.user must not start with '-'",
        }),
      port: z.number().int().positive().max(65535).default(22),
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
  // The three caps below bound how much work ONE node can impose on a sweep.
  // Everything after /api/v1/info is attacker-influenced: the README's own
  // threat model says an on-path party can rewrite the agent's responses, and
  // nothing here is authenticated. Before these existed, a rewritten
  // /api/v1/charts listing 50,000 `disk_space.*` keys -- a tiny payload --
  // drove 50,000 sequential /api/v1/data calls, each one a fresh
  // `Deno.Command("ssh", ...)` subprocess on the ssh transport with its own
  // full timeoutSec, holding a maxConcurrency worker slot for hours. The
  // per-call timeoutSec bounded a call; nothing bounded a node.
  maxMountsPerNode: z
    .number()
    .int()
    .positive()
    .default(256)
    .describe(
      "Maximum disk_space.* charts polled per node. Past this the extra " +
        "mounts are skipped, the node is marked degraded, and its existing " +
        "mount records are preserved rather than pruned.",
    ),
  maxAlarmsPerNode: z
    .number()
    .int()
    .positive()
    .default(512)
    .describe(
      "Maximum active alarms recorded per node. Past this the extra alarms " +
        "are skipped, the node is marked degraded, and its existing alarm " +
        "records are preserved rather than pruned.",
    ),
  nodeBudgetSec: z
    .number()
    .int()
    .positive()
    .default(300)
    .describe(
      "Wall-clock ceiling for one node's ENTIRE poll (info + alarms + " +
        "charts + every per-mount data query). timeoutSec bounds a single " +
        "call; this bounds the node, so one slow or hostile agent cannot " +
        "hold a concurrency slot indefinitely.",
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
  /**
   * Nullable for the same reason the identity strings are, and it matters more
   * here than anywhere else on this record: this is a data-egress audit field.
   * null means the agent did not tell us (no cloud fields in /api/v1/info, or
   * the node was unreachable and this is carried forward). It is NOT `false`.
   * `false` is a positive claim that this agent does not stream to Netdata
   * Cloud, and a coercion used to make that claim for every agent that simply
   * omitted the field.
   */
  claimedToCloud: z.boolean().nullable(),
  mountsOverThreshold: z.number(),
});

const AlarmSchema = z.object({
  node: z.string(),
  name: z.string(),
  chart: z.string(),
  status: z.string(),
  /**
   * Nullable for the same reason the node identity fields are: "Netdata could
   * not calculate a value for this alarm" is a distinct state from "the value
   * is zero". Netdata serialises a nan calculation (collector gap, freshly
   * triggered alarm) as `null`, and the previous `Number(a.value ?? 0)` stored
   * that as a real-looking 0 -- indistinguishable from a genuine 0% free.
   * null means unknown. See the write site in discover().
   */
  value: z.number().nullable(),
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
  /** Reachable nodes that did not answer completely this sweep: an alarm or
   * chart sub-fetch failed, an individual mount's data query failed, or the
   * alarm/mount list hit its per-node cap. Their alarm/mount counts include
   * carried-forward values, not purely fresh ones. When > 0, treat the
   * alarm/mount roll-ups as a floor, not a current total. */
  nodesDegraded: z.number(),
  alarmsActive: z.number(),
  alarmsCritical: z.number(),
  mountsOverThreshold: z.number(),
  syncedAt: z.string(),
});

/**
 * Deterministic, non-cryptographic 64-bit FNV-1a hash, hex-encoded. Used only
 * to make instance names collision-resistant -- never for anything security
 * sensitive, and never as the ONLY thing standing between two records and one
 * name (discover() also refuses a second write to an already-claimed name).
 *
 * This was 32-bit. 32 bits is 4.3e9 values, so by the birthday bound a few
 * thousand alarm and mount records across a fleet's lifetime already carry a
 * fraction-of-a-percent chance of two identities landing on one instance name
 * -- and the consequence of that landing is not a warning, it is the second
 * write silently replacing the first, which can be a firing CRITICAL. 64 bits
 * takes that from "will eventually happen in a real homelab" to "will not".
 * BigInt rather than a two-lane Math.imul: this function decides record
 * identity, and being obviously correct matters more than the microseconds.
 */
const FNV64_OFFSET = 0xcbf29ce484222325n;
const FNV64_PRIME = 0x100000001b3n;
const U64 = 0xffffffffffffffffn;

function shortHash(input: string): string {
  let h = FNV64_OFFSET;
  for (let i = 0; i < input.length; i++) {
    h = (h ^ BigInt(input.charCodeAt(i))) * FNV64_PRIME & U64;
  }
  return h.toString(16).padStart(16, "0");
}

/**
 * Cap on the readable part of an instance name. Shared by instanceName() and
 * instanceNamePrefix() so the two can never drift -- a prefix computed with a
 * different cap silently stops matching stored names, which is exactly how the
 * prune-safety net broke for long node names.
 */
const LABEL_MAX = 48;

function slug(v: string): string {
  return v.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") ||
    "unnamed";
}

/**
 * Cap on ONE agent-supplied string, whether it is hashed into an instance name
 * or written into a resource field.
 *
 * MAX_RESPONSE_BYTES bounds a whole payload; it does not bound a field. A
 * single alarm carrying a multi-megabyte `info` string fits inside the 8 MiB
 * ceiling perfectly well and used to land in the datastore whole, as one
 * free-text value chosen end to end by an unauthenticated remote. 512
 * characters is an order of magnitude above any real Netdata alarm name, chart
 * id, status word, unit or info line.
 */
const MAX_AGENT_TEXT = 512;

/**
 * Normalise one agent-supplied string before it is hashed into an instance
 * name or written to a resource. Two jobs, one class of problem: an
 * unauthenticated remote (see the threat model in the GlobalArgsSchema cap
 * comments) choosing the exact bytes swamp stores.
 *
 * 1. C0 controls and DEL become U+FFFD. The load-bearing one is U+001F, the
 *    separator instanceName() joins identity fields with. That separator's
 *    entire job is to be a character that cannot occur INSIDE a field, so that
 *    ["a", "b c"] and ["a b", "c"] cannot hash to the same name. Nothing
 *    enforced that: an agent that put a literal U+001F in an alarm name could
 *    craft two distinct alarms that produced one instance name, and the second
 *    write silently overwrote the first -- a firing CRITICAL could be erased
 *    by a benign alarm named to collide with it. The rest of the C0 range goes
 *    with it because a stored field holding a raw NUL, CR or ESC is a
 *    terminal-escape and reads-as-binary problem for every consumer of this
 *    data, not only for us.
 * 2. Length is bounded. See MAX_AGENT_TEXT.
 *
 * Idempotent by construction: the truncation marker REPLACES the last kept
 * character instead of being appended, so the result is exactly
 * MAX_AGENT_TEXT characters and a second pass changes nothing. That matters
 * because instanceName() normalises its identity arguments and the write sites
 * normalise the same values -- if the two disagreed by even one character, a
 * record's name and its contents would describe different alarms.
 *
 * Deliberate trade: two alarms whose names agree in their first 511 characters
 * now collide. Real Netdata alarm names are tens of characters. An agent able
 * to mint 512-character alarm names is already choosing the entire alarm
 * payload wholesale, so the collision hands it nothing it did not already
 * have -- whereas leaving the field unbounded hands it the datastore.
 */
function agentText(v: unknown): string {
  const s = typeof v === "string"
    ? v
    : v === null || v === undefined
    ? ""
    : String(v);
  // deno-lint-ignore no-control-regex
  const clean = s.replace(/[\u0000-\u001f\u007f]/g, "\uFFFD");
  return clean.length > MAX_AGENT_TEXT
    ? clean.slice(0, MAX_AGENT_TEXT - 1) + "\u2026"
    : clean;
}

/**
 * Narrow an unvalidated API field to a plain object, or null if it is anything
 * else. `(al.alarms ?? {}) as Record<string, unknown>` typechecked but checked
 * nothing: an agent answering `{"alarms": "xxxxx"}` made Object.entries()
 * enumerate a STRING, yielding one entry per character -- ["0","x"], ["1","x"]
 * -- and each of those became a real writeResource call under a real-looking
 * instance name. An array did the same thing with its indices. A payload whose
 * shape is not what the endpoint promises is a failed sub-fetch, which this
 * model already knows how to represent; it is not a reading.
 */
function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? v as Record<string, unknown>
    : null;
}

/**
 * Require a whole API response to be a JSON object, and treat anything else as
 * a failed sub-fetch.
 *
 * asRecord() guarded the alarms/charts VALUES; the ENVELOPES around them were
 * still `await getJson(...) as Record<string, unknown>`, a cast that checks
 * nothing. That is not a cosmetic gap, it is the worst outcome this model can
 * produce. An agent (or an on-path rewriter, which the README's threat model
 * grants) answering `/api/v1/alarms` with a bare JSON string or array made
 * `al.alarms` read `undefined` -- the documented "absent means zero alarms"
 * path -- so the sub-fetch was marked SUCCESSFUL with an empty alarm list. A
 * successful empty list is not protected from the prune, so every stored
 * alarm record for that node was deleted, including a firing CRITICAL, and the
 * node reported alarmsActive: 0 with nodesDegraded: 0. Suppressing a critical
 * alarm fleet-wide cost one malformed four-byte body. The same cast on
 * `/api/v1/charts` zeroed the chart count and pruned every mount record; on
 * `/api/v1/info` it made a node reachable with no identity at all.
 *
 * This is only the OUTER check. "The envelope is an object" says nothing about
 * what is inside it, and an object with the wrong insides was the rest of the
 * same bug -- see the response schemas below, which every endpoint is now run
 * through before a single field is read.
 */
function expectObject(v: unknown, endpoint: string): Record<string, unknown> {
  const o = asRecord(v);
  if (o === null) {
    throw new NodeFailure(
      NODE_ERROR.malformed,
      `${endpoint}: expected a JSON object, got ${describeShape(v)}`,
    );
  }
  return o;
}

/**
 * A JSON object as a schema element: not null, and NOT an array.
 *
 * `z.object({})` and `z.record()` both already refuse an array, but the values
 * inside `alarms`/`charts` are open maps with agent-chosen keys, so there is no
 * key set to write an object schema over. This is the reusable "an object, and
 * nothing that merely behaves like one" element for those positions. It shares
 * asRecord()'s definition on purpose: the whole model has exactly one answer to
 * "is this a JSON object", so a payload cannot be one shape to the schema and a
 * different shape to the code that walks it afterwards.
 */
const jsonObject = z.custom<Record<string, unknown>>(
  (v) => asRecord(v) !== null,
);

/**
 * What `/api/v1/info` has to contain before this model will call a node
 * reachable and write an identity for it.
 *
 * Every field here was previously read with a `typeof x === "string"` ternary
 * or a countOrZero(), so a payload that simply OMITTED it produced a stored
 * value rather than a refusal:
 *
 *   - a missing `cores_total` or `collectors` became `0`. That is the failure
 *     this whole model is built to prevent, wearing a different hat: a count
 *     nobody measured, rendered as a measurement of zero. `cores: 0` is not a
 *     shape any real host has, so it reads as data while being the absence of
 *     data, and nothing anywhere marked the node degraded for it.
 *   - a missing `version`/`os_name`/`os_version` became `null`. null is the
 *     represented "never successfully reached this node" state -- see
 *     NodeStateSchema -- so writing it for a node that DID answer overloads one
 *     value with two meanings and quietly destroys the distinction. Requiring
 *     the fields here is what makes that schema comment true: on a reachable
 *     node these are now never null, and a null identity means exactly one
 *     thing.
 *
 * `hostname` is deliberately NOT required: /api/v1/info does not carry it (the
 * alarms payload does), so demanding it here would fail every real agent. It is
 * DECLARED, because an agent that does send it has its value stored.
 *
 * z.object, not z.looseObject: undeclared keys are dropped, so a field nothing
 * here names cannot reach a read site. That is only true if every consumed
 * field is named, which is why the four cloud-claim spellings appear below --
 * they used to be read straight off the raw payload with
 * `Boolean(info.cloud_enabled ?? info["cloud-enabled"])`, which turned the
 * STRING "false" into a claimed agent (non-empty strings are truthy) and a
 * missing field into a definitive `false`. Typed as optional booleans, a wrong
 * type is now a malformed /info -- and absence stays absence, which the write
 * site records as `claimedToCloud: null` (unknown) rather than "not claimed".
 */
const InfoResponseSchema = z.object({
  version: z.string(),
  os_name: z.string(),
  os_version: z.string(),
  hostname: z.string().optional(),
  // z.number() in zod 4 already rejects NaN and Infinity, which is the whole
  // point here -- a JSON body cannot carry either, so seeing one means the
  // value was coerced somewhere, and countOrZero() would have flattened it
  // to 0.
  cores_total: z.number(),
  collectors: z.array(z.unknown()),
  // Both spellings: netdata renamed these keys between major versions and a
  // real fleet runs both. Booleans only -- this is an audit field about data
  // egress, so "the agent said something we cannot type" must not resolve to a
  // confident answer in either direction.
  cloud_enabled: z.boolean().optional(),
  "cloud-enabled": z.boolean().optional(),
  agent_claimed: z.boolean().optional(),
  "agent-claimed": z.boolean().optional(),
});

/**
 * One alarm entry. The record's own `name` is NOT here: the object key is
 * authoritative and the payload's `name` is discarded at the read site.
 *
 *   - `status` required. It was read as `agentText(a.status)`, so an entry with
 *     no status stored `""`, and `""` is neither CRITICAL nor WARNING -- an
 *     alarm that exists but reads as firing nothing. Combine that with an
 *     entry that is a bare string (previously `asRecord(raw) ?? {}`, i.e. an
 *     alarm with no fields at all) and an agent could replace a node's whole
 *     alarm set with contentless records while the sub-fetch still reported
 *     SUCCESS -- which means the prune ran and every real alarm record went
 *     with it.
 *   - `chart` required. It is half of the alarm's stored identity and is
 *     hashed into the instance name; a missing one collapses every chartless
 *     alarm toward the same identity space for no reason.
 *   - `value` optional but, when present, a number or an explicit null.
 *     Netdata serialises an uncalculable alarm as `null` and that is a real,
 *     represented state (unknown, NOT zero) -- so absent and null both stay
 *     null, and only a present-but-non-numeric value is a malformed payload.
 *   - `units`/`info` optional strings. Absent is genuinely nothing to say;
 *     present-but-not-a-string is a payload that is not what the endpoint
 *     promises.
 */
const AlarmEntrySchema = z.object({
  status: z.string(),
  chart: z.string(),
  value: z.union([z.number(), z.null()]).optional(),
  units: z.string().optional(),
  info: z.string().optional(),
});

/**
 * `/api/v1/alarms?active=true`. The `alarms` key is REQUIRED.
 *
 * This is the finding that mattered most, and the previous version got it
 * exactly backwards: absent-or-null `alarms` was treated as "a healthy agent
 * with nothing firing" and the sub-fetch was marked SUCCESSFUL. A successful
 * alarm fetch is not protected from the prune, so `{}` -- two bytes, from an
 * agent that has been rewritten, downgraded, or is simply answering the wrong
 * endpoint -- DELETED every stored alarm record for that node, including a
 * firing CRITICAL, and reported alarmsActive: 0 / nodesDegraded: 0 while doing
 * it. Suppressing a critical alarm has to be harder than that.
 *
 * Netdata always emits the key (an agent with nothing firing sends
 * `"alarms": {}`), so requiring it costs a real deployment nothing and takes
 * the two-byte alarm-suppression payload off the table. An EMPTY object is
 * still zero alarms; that is the reading, and it is the only thing that is.
 */
const AlarmsResponseSchema = z.object({
  // /api/v1/info carries no hostname; this endpoint does, and it is the ONLY
  // source of the stored `hostname`. It is declared here so it can be read off
  // the PARSED response instead of off the raw envelope: the raw read happened
  // before this schema ran, so a payload with no `alarms` key at all -- a
  // failed sub-fetch by every other measure -- still got to choose the identity
  // written on the node record.
  hostname: z.string().optional(),
  // Every entry validated here rather than per-entry in the loop: one bad
  // entry among fifty thousand makes the whole sub-fetch failed, which is the
  // conservative direction. Skipping the bad entry instead would silently drop
  // an alarm AND still report success, so the prune would run.
  alarms: z.record(z.string(), AlarmEntrySchema),
});

/**
 * `/api/v1/charts`. Same reasoning as the alarms envelope, same required key.
 *
 * An absent `charts` was a successful read of "this host has no charts", which
 * zeroed the stored chart count AND emptied the mount list -- and an empty
 * mount list is not protected from the prune either, so every mount record for
 * the node was deleted and an over-threshold filesystem read as gone rather
 * than unread.
 *
 * The values are required to be objects even though only the KEYS are used
 * (the `disk_space.` filter). A map whose values are strings is not the shape
 * this endpoint promises, and the cost of noticing is one schema element.
 */
const ChartsResponseSchema = z.object({
  charts: z.record(z.string(), jsonObject),
});

/**
 * `/api/v1/data?...&format=json`. `labels` and `data` are both required.
 *
 * The read site used `Array.isArray(x) ? x : []`, so a MISSING `labels` became
 * an empty label list, indexOf() returned -1 for both dimensions, and the
 * mount landed in failedMounts -- the right outcome reached by accident. It
 * only worked because a later guard refuses to index at -1; state it here so
 * the outcome does not depend on that guard surviving an edit. Rows are
 * arrays: `data: ["25,75"]` is an array of STRINGS, and indexing a string by
 * dimension position returns characters that Number() will happily accept.
 *
 * A CELL is a finite number or an explicit null, and nothing else. This is the
 * `?? 0` failure that defines this model, arriving through the type system
 * instead of through a fallback: `Number(row[availIdx])` maps `null`, `false`
 * AND `""` to 0, so a dimension the agent could not measure -- or that an
 * on-path rewriter blanked -- was stored as `used: 0 / avail: 0`, a failed read
 * rendered as a healthy empty filesystem. z.number() in zod 4 rejects NaN and
 * Infinity, so a cell that parses is a reading; null is Netdata's own "no value
 * for this point", which the read site turns into a failed mount, never a zero.
 */
const DataResponseSchema = z.object({
  labels: z.array(z.string()),
  data: z.array(z.array(z.union([z.number(), z.null()]))),
});

/**
 * Walk a value along a zod issue path so a failure can say what was actually
 * at the offending position. Returns undefined the moment the path leaves the
 * value, which describeShape() renders as "undefined" -- exactly the right
 * word for a required field that was not sent.
 */
function valueAt(v: unknown, path: readonly PropertyKey[]): unknown {
  let cur = v;
  for (const key of path) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<PropertyKey, unknown>)[key];
  }
  return cur;
}

/**
 * Run a payload through its endpoint's schema and turn any failure into the
 * same NodeFailure a wrong-typed envelope raises -- fixed `malformed` class,
 * carried forward, node degraded.
 *
 * Returns the PARSED value, and every caller reads that and never the raw
 * payload again. When this was a checker whose callers carried on with
 * `raw as Record<string, unknown>`, the schemas above documented a boundary the
 * code did not actually stand behind: a cast asserts a type without testing
 * one, so every field still arrived as `unknown` and was re-narrowed ad hoc at
 * the read site -- with a `typeof` ternary here, a `Boolean()` there, an
 * `?? {}` somewhere else. Those improvised narrowings are where the wrong-shape
 * findings kept coming from. Reading the parsed result means a field's type is
 * decided once, in the schema, and undeclared keys are gone rather than merely
 * unmentioned. None of these schemas coerce or default, so the parsed value is
 * the payload minus what it was never allowed to contain.
 *
 * The message is assembled from OUR OWN vocabulary and nothing else.
 * `issue.path` is the key path, and `issue.expected` is the type name written
 * in the schema above; both are ours. zod's `issue.message` is deliberately
 * unused, because it quotes the failing input, and keeping agent-chosen bytes
 * out of error strings is the entire reason NodeFailure exists. The one part
 * of the path that is NOT ours is an agent-chosen map key (an alarm name), so
 * every segment goes through agentText() -- bounded and de-controlled, same
 * rule as any other agent text reaching a log field.
 */
function requireShape<T>(
  schema: z.ZodType<T>,
  v: unknown,
  endpoint: string,
): T {
  const parsed = schema.safeParse(v);
  if (parsed.success) return parsed.data;
  const issue = parsed.error.issues[0];
  const path = issue.path.map((p) => agentText(String(p))).join(".");
  const found = describeShape(valueAt(v, issue.path));
  throw new NodeFailure(
    NODE_ERROR.malformed,
    `${endpoint}: ${path ? `field '${path}' is` : "payload is"} ${found}, ` +
      "not the shape the endpoint promises",
  );
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
function instanceName(prefix: string, ...identity: unknown[]): string {
  // Normalisation happens HERE and ONLY here, and the parameter is `unknown`
  // so a caller cannot route around it with a String() of its own. The
  // separator below only makes the join unambiguous if it cannot occur INSIDE
  // a field; that guarantee has to hold for every caller that exists now or is
  // added later, and a call site that forgot would reintroduce the collision
  // with no type error and no failing parse. agentText() also bounds each
  // field, so an agent cannot make `raw` arbitrarily large by naming an alarm.
  const fields = identity.map(agentText);
  // Length-prefixed encoding, not a separator character.
  //
  // The requirement is that ["a","b c"] and ["a b","c"] cannot produce the same
  // encoding. A separator only satisfies that if it can never occur INSIDE a
  // field, which puts the guarantee in whatever sanitises the fields rather
  // than in the encoding -- and when that sanitiser did not exist, an agent
  // putting a literal U+001F in an alarm name could mint two distinct alarms
  // that hashed to one instance name, so the second write erased the first.
  // agentText() now replaces the whole C0 range, but a scheme whose
  // correctness depends on a downstream filter is one edit away from being
  // wrong again, and it still built this model's record identities around a
  // control character -- which is what made an earlier implementation's raw-NUL
  // encoding read as binary to grep and to any tool doing exact-text matching.
  //
  // `<length>:<field>` needs no forbidden character at all: it decodes left to
  // right, so it is injective over ARBITRARY field contents -- including a
  // field that itself contains digits, colons or control bytes.
  // ["a","b c"] -> "1:a3:b c"; ["a b","c"] -> "3:a b1:c".
  const raw = fields.map((f) => `${f.length}:${f}`).join("");
  // Build the readable label from EVERY non-empty identity field, not just the
  // first. Taking only the first made the visible part non-discriminating
  // wherever the caller passes a shared scope first: netdata's alarms pass the
  // node name ahead of the alarm name, so every alarm on one node rendered as
  // `alarm-<node>-<hash>` and differed only in an opaque hash. Names were
  // unique, but `swamp data list` became unreadable -- which is the entire
  // reason for having a readable part at all.
  // Capped so an unusually long identity cannot produce an unbounded name.
  // The hash covers the whole normalised identity, not just the part that
  // survives THIS cap, so uniqueness never depends on the readable label.
  // (agentText() applies its own, far looser, per-field cap upstream; see the
  // trade recorded there.)
  const parts = fields.filter((s) => s !== "").map(slug).filter((s) =>
    s !== ""
  );
  const label = parts.length ? parts.join("-").slice(0, LABEL_MAX) : "unnamed";
  return `${prefix}-${label}-${shortHash(raw)}`;
}

/**
 * The `startsWith` prefix that matches every instanceName() whose FIRST
 * identity field is `scope`. Used by discover()'s prune-safety net.
 *
 * Must go through the same LABEL_MAX truncation instanceName() applies, which
 * is why this is a shared helper and not a `${prefix}-${slug(scope)}-`
 * template at the call site. That template was the bug: for a node whose slug
 * ran past LABEL_MAX characters, the stored record was named
 * `alarm-<first-48-chars>-<hash>` while the protection pushed
 * `alarm-<full-60-char-slug>-`, so startsWith never matched and every
 * preserved alarm record for that node -- including a firing CRITICAL whose
 * fetch had just failed -- was deleted and logged only as "pruned {name}".
 *
 * Two nodes whose slugs share their first LABEL_MAX characters will protect
 * each other's records. That over-protects (a departed record lingers one
 * more sweep) rather than under-protects, which is the direction to fail in.
 */
function instanceNamePrefix(prefix: string, scope: string): string {
  return `${prefix}-${slug(scope).slice(0, LABEL_MAX)}-`;
}

/**
 * The COMPLETE set of failure classes that may be persisted in a node's
 * `error` resource field. If a value is not in here (or is not
 * httpErrorClass(), whose only variable part is an integer status swamp read
 * off the response itself), it does not reach the datastore.
 *
 * This is an allowlist because the previous design was a denylist and a
 * denylist cannot win this. sanitizeNodeError() used to RE-PARSE the English
 * failure message with regexes, and when none matched it fell through to
 * `raw.replace(/\S+@\S+/g, "<host>").slice(0, 120)` -- i.e. it persisted
 * arbitrary remote text with one narrow substitution applied. Two ways that
 * bit, both reachable without any special access:
 *
 *  - An agent front-end answering HTML instead of JSON made JSON.parse throw
 *    `Unexpected token '<', "<html>SECRE"... is not valid JSON`. No regex
 *    matched, so the RESPONSE BODY PREFIX -- chosen end to end by an
 *    unauthenticated remote, or by anyone on the path of a cleartext poll --
 *    was written into a stored field an operator reads as swamp's own words.
 *  - The ssh branch keyed on `^ssh to \S+ failed:`, so an ssh host or user
 *    containing whitespace broke the anchor, dropped the whole classification
 *    to that same fallback, and put raw ssh stderr (local key paths and all)
 *    into the record.
 *
 * The fix is structural, not another regex: every failure raised on the poll
 * path is a NodeFailure carrying a fixed class token chosen AT THE THROW SITE,
 * where the code already knows what went wrong. Nothing is recovered by
 * pattern-matching prose afterwards, so there is no shape for a payload to
 * take that reaches storage. Detail still goes to the log, which is a
 * documented operator-decision trade (see the README's Security section).
 */
const NODE_ERROR = {
  sshHostKey: "ssh transport: host key verification failed",
  sshAuth: "ssh transport: authentication failed",
  sshFailed: "ssh transport failed",
  redirect: "redirect refused; swamp does not follow redirects",
  malformed: "malformed response (not the shape the endpoint promises)",
  oversized: "response over the size cap",
  empty: "empty response",
  timedOut: "timed out",
  connection: "connection failed",
  unclassified: "unclassified failure",
} as const;

/**
 * The one class string with a variable part. `status` is a number swamp read
 * off the response line, so it is coerced to a bounded integer here rather
 * than being interpolated as whatever arrived. The endpoint path is
 * deliberately NOT included: on the /api/v1/data path it carries an
 * agent-supplied chart id, which is the same untrusted text this function
 * exists to keep out of stored fields.
 */
function httpErrorClass(status: number): string {
  const s = Number.isFinite(status) ? Math.trunc(status) : 0;
  return `HTTP ${s} (${classifyStatus(s)})`;
}

/**
 * A poll failure that already knows its own persisted class. `message` holds
 * the full diagnostic for the log; `errorClass` is the only part ever stored.
 */
class NodeFailure extends Error {
  readonly errorClass: string;
  constructor(errorClass: string, detail: string) {
    super(detail);
    this.name = "NodeFailure";
    this.errorClass = errorClass;
  }
}

/**
 * Map ssh's stderr to a class. This is still text matching, but the difference
 * from the old design is the failure mode: a miss here returns the fixed
 * `sshFailed` class, never the text it just failed to classify.
 */
function classifySshStderr(stderr: string, exitCode: number): string {
  if (/host key|known_hosts|verification failed/i.test(stderr)) {
    return NODE_ERROR.sshHostKey;
  }
  if (/permission denied|load key|auth|publickey|password/i.test(stderr)) {
    return NODE_ERROR.sshAuth;
  }
  const code = Number.isFinite(exitCode) ? Math.trunc(exitCode) : 0;
  return code ? `${NODE_ERROR.sshFailed} (exit ${code})` : NODE_ERROR.sshFailed;
}

/**
 * The class safe to PERSIST in a node's `error` field. Takes the thrown value,
 * not a message string, so nothing can be reconstructed from prose.
 *
 * Anything that is not a NodeFailure is something the poll path did not raise
 * on purpose -- a fetch-level network error, or a bug of ours. Those get a
 * class from the error's NAME (a runtime type, never content), and anything
 * unrecognised is `unclassified failure`. Losing detail is the point: this
 * function fails closed.
 */
function sanitizeNodeError(e: unknown): string {
  if (e instanceof NodeFailure) return e.errorClass;
  const name = typeof e === "object" && e !== null
    ? (e as { name?: unknown }).name
    : undefined;
  if (name === "TimeoutError" || name === "AbortError") {
    return NODE_ERROR.timedOut;
  }
  // Deno's fetch raises TypeError for DNS failures, refused connections and
  // TLS errors -- the ordinary "node is powered off" case.
  if (name === "TypeError") return NODE_ERROR.connection;
  return NODE_ERROR.unclassified;
}

/**
 * Describe an unexpected value by its TYPE, never by its content. Used in the
 * diagnostics attached to a malformed-response failure: even the log line has
 * no reason to echo a payload it has already refused.
 */
function describeShape(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

/**
 * Coerce an untrusted value to a finite count, falling back to 0. Every count
 * field on NodeStateSchema is a plain z.number(), which rejects NaN -- and
 * swamp's writeResource only warns on a schema mismatch rather than throwing,
 * so a NaN would be stored regardless. Nothing here is a case where NaN is
 * meaningful (unlike an alarm value or a mount dimension, where "unknown" is
 * real and gets represented, not defaulted).
 */
function countOrZero(v: unknown): number {
  const n = Number(v ?? 0);
  return Number.isFinite(n) ? n : 0;
}

/** Netdata's alarm status strings; anything else counts as neither. */
function isCritical(status: string): boolean {
  return status.toUpperCase() === "CRITICAL";
}
function isWarning(status: string): boolean {
  return status.toUpperCase() === "WARNING";
}

/** One validated /api/v1/alarms entry, plus the map key that names it. */
type AlarmRecord = z.infer<typeof AlarmEntrySchema> & { name: string };

interface NodeResult {
  name: string;
  url: string;
  reachable: boolean;
  error: string;
  /**
   * The PARSED /api/v1/info body, or null when this poll never got a valid one.
   * Typed rather than `Record<string, unknown>` so the identity write site
   * cannot re-narrow an agent field by hand -- which is how `"false"` became a
   * claimed cloud agent and a missing `cores_total` became `cores: 0`.
   */
  info: z.infer<typeof InfoResponseSchema> | null;
  alarms: AlarmRecord[];
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
  /** True when maxMountsPerNode / the node budget cut the mount sweep short. */
  mountsTruncated: boolean;
  /** True when maxAlarmsPerNode cut the alarm list short. */
  alarmsTruncated: boolean;
}

/**
 * Hard ceiling on a single API response body. Nothing about the agent API is
 * authenticated, so response size is attacker-influenced (see the cap comments
 * on GlobalArgsSchema): `await res.json()` on a rewritten multi-gigabyte body
 * buffers the whole thing into the sweep's heap before any of the count caps
 * downstream ever get a chance to look at it. 8 MiB is roughly two orders of
 * magnitude above the largest real /api/v1/charts payload.
 */
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

/**
 * Hard ceiling on what one ssh subprocess may write to stderr.
 *
 * `Deno.Command(...).output()` buffers stdout AND stderr to completion with no
 * ceiling of its own, so every size guarantee on this transport used to stop at
 * the curl invocation: `--max-filesize` bounds the HTTP body, and bounds
 * nothing that ssh, the remote login shell, a `ForceCommand`, or a
 * `.bashrc`/`sshrc` on the far end writes to the other stream. A remote that
 * simply printed to stderr forever filled this process's heap until the
 * subprocess timeout fired, which is a whole `timeoutSec` of unbounded
 * allocation per poll and per node, from a box the README's threat model
 * already treats as able to rewrite its own answers.
 *
 * 8 KiB is far more than any ssh diagnostic worth classifying -- only the first
 * 160 characters are ever used -- and the cap is enforced by killing the child,
 * not merely by slicing after the fact, because slicing happens after the bytes
 * have already been buffered.
 */
const MAX_SSH_STDERR_BYTES = 8 * 1024;

/**
 * Drain one subprocess stream, refusing to buffer more than `cap` bytes and
 * killing the child the instant the cap is passed. Returns what was kept plus
 * whether the cap was hit, so the caller can tell a truncated diagnostic (fine,
 * classify it) from a truncated response body (not fine, refuse the poll).
 *
 * The kill is the load-bearing half. Returning early without it leaves the
 * remote writing into a pipe nobody reads, so the subprocess lingers holding
 * the node's concurrency slot until its timeout -- the resource exhaustion the
 * cap exists to stop, minus only the memory.
 */
async function readStreamCapped(
  stream: ReadableStream<Uint8Array>,
  cap: number,
  kill: () => void,
  signal: AbortSignal,
): Promise<{ text: string; overflowed: boolean }> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let overflowed = false;
  const onAbort = () => {
    kill();
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    signal.throwIfAborted();
    while (true) {
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      const room = cap - total;
      if (value.byteLength > room) {
        chunks.push(value.subarray(0, Math.max(room, 0)));
        total = cap;
        overflowed = true;
        kill();
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
    // Cancel, not releaseLock: on the over-cap break the remote is still
    // sending and we want the pipe torn down rather than drained.
    void reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return { text: new TextDecoder().decode(buf), overflowed };
}

/**
 * The endpoint path as it may appear in a DIAGNOSTIC.
 *
 * Every path this model requests is one of its own literals -- except
 * /api/v1/data, whose query string carries an agent-chosen chart id. That made
 * the failure message for a per-mount query as long as the chart id: a rewritten
 * /api/v1/charts listing one 8 MiB `disk_space.<...>` key produced an 8 MiB
 * `{error}` log field, with the id's escape sequences intact for whatever
 * renders the log. Bounded through the same agentText() the stored fields use,
 * because the reason to bound a value is where it CAME from, not where it is
 * going.
 */
function pathLabel(path: string): string {
  return agentText(path);
}

/**
 * Read a response body, refusing to buffer more than MAX_RESPONSE_BYTES.
 * Checks the declared Content-Length first (cheap), then enforces the same cap
 * against what actually arrives, because Content-Length is attacker-supplied
 * too and may be absent or a lie.
 */
async function readBodyBounded(res: Response, path: string): Promise<string> {
  const declared = Number(res.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new NodeFailure(
      NODE_ERROR.oversized,
      `response too large on ${pathLabel(path)}: declared ${declared} ` +
        `bytes, cap is ${MAX_RESPONSE_BYTES}`,
    );
  }
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        throw new NodeFailure(
          NODE_ERROR.oversized,
          `response too large on ${pathLabel(path)}: over the ` +
            `${MAX_RESPONSE_BYTES}-byte cap`,
        );
      }
      chunks.push(value);
    }
  } finally {
    // Cancel rather than releaseLock: on the over-cap throw the remote is
    // still sending, and we want the connection torn down, not drained.
    await reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

/**
 * JSON.parse with the body kept out of the thrown error.
 *
 * `JSON.parse("<html>SECRET</html>")` throws
 * `Unexpected token '<', "<html>SECR"... is not valid JSON` -- V8 quotes the
 * input back at you. Both transports called JSON.parse bare, so that message
 * became the node's failure message, and the persisted-error classifier's old
 * regex denylist did not recognise it and fell through to storing it. A
 * response body is remote-chosen text (the README's threat model has an
 * on-path party writing it on a cleartext poll), so it must not appear in a
 * stored field OR in a log line just because a parser happened to include it.
 */
function parseJsonBody(body: string, path: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    throw new NodeFailure(
      NODE_ERROR.malformed,
      `${pathLabel(path)}: response is not valid JSON (${body.length} bytes)`,
    );
  }
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
  limits: {
    timeoutSec: number;
    maxMountsPerNode: number;
    maxAlarmsPerNode: number;
    nodeBudgetSec: number;
  },
  signal: AbortSignal,
  logger: PollLogger,
): Promise<NodeResult> {
  const { timeoutSec } = limits;
  // One deadline for this node's whole poll. Wired into every sub-fetch below
  // so that when it fires the in-flight call aborts, the remaining ones fail
  // fast, and the node lands in the normal degraded path -- `signal` (the
  // caller's) is untouched, so this never looks like a cancellation.
  const budget = AbortSignal.timeout(limits.nodeBudgetSec * 1000);
  // Canonicalised through the SAME function the schema validates with, so the
  // string every endpoint is appended to is the one that was checked. The old
  // `node.url.replace(/\/+$/, "")` was an independent, weaker normalisation at
  // the call site -- see parseNodeUrl for what a query string did to endpoint
  // construction when the two disagreed. Unreachable in practice (the schema
  // has already run) and loud on purpose if it ever is not.
  const base = parseNodeUrl(node.url);
  if (base === null) {
    throw new Error(
      `node '${node.name}' has an unusable url; it must be a credential-free ` +
        "http(s) URL with no query string or fragment",
    );
  }
  const result: NodeResult = {
    name: node.name,
    url: base,
    reachable: false,
    error: "",
    info: null,
    alarms: [],
    mounts: [],
    chartCount: 0,
    alarmsOk: false,
    chartsOk: false,
    failedMounts: [],
    mountsTruncated: false,
    alarmsTruncated: false,
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
    // string intact. Never assembled through a local shell.
    // No newline before the marker: curl's -w output is appended straight
    // after the body with no separator, and the marker string is
    // distinctive enough that a plain concatenation is unambiguous to
    // locate and strip below.
    // --max-filesize is the ssh transport's half of the response-size cap:
    // Deno.Command buffers the subprocess's whole stdout, so a multi-gigabyte
    // body has already landed in our heap by the time we could measure it.
    // Refusing it at curl means it never crosses the wire in full.
    //
    // `-q` MUST be first. It is what makes curl ignore /etc/curlrc,
    // ~/.curlrc and $CURL_HOME/.curlrc, and curl applies config-file contents
    // in argument order, so a `-q` placed later cannot undo what an earlier
    // config already set. Without it, every transport guarantee in this file
    // was the REMOTE box's to revoke: a one-line `.curlrc` in the reader
    // account's home directory saying `insecure` turned off TLS verification
    // for an https base, `location` re-enabled redirect following (the exact
    // https->http downgrade the direct path refuses), `proxy = ...` routed the
    // poll through a third party, and `user = ...` attached a credential to
    // every request. None of that would appear anywhere in swamp's config,
    // logs or stored data.
    //
    // Everything security-relevant is then stated explicitly rather than left
    // at whatever the default happens to be:
    //   --proto '=http,https'  the URL is already scheme-checked locally; this
    //                          is the same refusal enforced at the far end.
    //   (no -L / --location)   redirects are never followed, on either
    //                          transport.
    //   --noproxy '*'          this transport exists to reach an agent on the
    //                          node's OWN loopback. A proxy from the remote
    //                          environment is a relocation of the request, in
    //                          the same class as a redirect.
    //   -g                     globbing off. Not hardening but correctness:
    //                          curl reads the [ ] of a bracketed IPv6 base URL
    //                          as a glob range and fails the poll.
    //
    // The apostrophe is ENCODED, never deleted. The URL is wrapped in single
    // quotes for the remote shell, and `encodeURIComponent` -- which builds the
    // `chart=` value out of an agent-chosen chart id -- does not escape `'`, so
    // one had to be dealt with here. Deleting it (`path.replace(/'/g, "")`)
    // silently CHANGED the request: a chart named `disk_space./mnt/o'brien` was
    // requested as `/mnt/obrien`, and whatever that other chart returned was
    // stored under the apostrophed mount's identity -- one filesystem's
    // capacity written on another's record, with no failure anywhere. %27 is
    // the same character the agent will decode, so the request finally asks for
    // the chart the loop believes it is asking for, and the quoting still
    // holds because the byte never reaches the remote shell.
    const remote = `curl -q -s -g --proto '=http,https' --noproxy '*' ` +
      `--max-time ${timeoutSec} --max-filesize ${MAX_RESPONSE_BYTES} ` +
      `-w '${STATUS_MARKER}:%{http_code}' '${base}${
        path.replace(/'/g, "%27")
      }'`;
    const commandSignal = AbortSignal.any([
      signal,
      budget,
      AbortSignal.timeout((timeoutSec + 10) * 1000),
    ]);
    commandSignal.throwIfAborted();
    const child = new Deno.Command("ssh", {
      args: [
        "-o",
        "BatchMode=yes",
        // Explicit, because BatchMode alone does NOT guarantee it. BatchMode
        // only turns an interactive host-key PROMPT into a failure; it has no
        // effect when the operator's ssh_config already answers the question,
        // and `StrictHostKeyChecking no` / `accept-new` in ~/.ssh/config or
        // /etc/ssh/ssh_config are both common and both silently accept an
        // unknown or changed key -- i.e. a machine-in-the-middle for a
        // transport this extension's README calls fail-closed. A command-line
        // -o wins over both config files (ssh takes the first value obtained),
        // so stating it here makes the README's claim true regardless of how
        // the host running swamp is configured. `yes`, not `accept-new`: the
        // node's key must already be in known_hosts.
        "-o",
        "StrictHostKeyChecking=yes",
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
      signal: commandSignal,
    }).spawn();

    // spawn() + capped drains, not output(). output() buffers both pipes to
    // completion with no ceiling, so the remote decided how much memory this
    // sweep allocated; see MAX_SSH_STDERR_BYTES. Both streams are read
    // concurrently because they must be: consuming one to completion while the
    // other's pipe fills deadlocks the child.
    const kill = () => {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already exited between the cap being hit and the kill. Nothing to do.
      }
    };
    let rejectAbort: (reason: unknown) => void = () => {};
    const aborted = new Promise<never>((_resolve, reject) => {
      rejectAbort = reject;
    });
    const onAbort = () => {
      kill();
      rejectAbort(commandSignal.reason);
    };
    commandSignal.addEventListener("abort", onAbort, { once: true });
    const collected = Promise.all([
      readStreamCapped(child.stdout, MAX_RESPONSE_BYTES, kill, commandSignal),
      readStreamCapped(child.stderr, MAX_SSH_STDERR_BYTES, kill, commandSignal),
      child.status,
    ]);
    let results: Awaited<typeof collected>;
    try {
      if (commandSignal.aborted) onAbort();
      results = await Promise.race([collected, aborted]);
    } finally {
      commandSignal.removeEventListener("abort", onAbort);
    }
    const [outRes, errRes, processStatus] = results;

    // Checked BEFORE the exit-code branch below: killing the child to enforce
    // the cap makes it exit unsuccessfully, and reporting that as a generic
    // "ssh transport failed" would hide an oversized body behind a transport
    // error. The direct path calls this `oversized`; so does this one.
    if (outRes.overflowed || errRes.overflowed) {
      throw new NodeFailure(
        NODE_ERROR.oversized,
        `response or diagnostic too large over ssh on ${pathLabel(path)}`,
      );
    }
    if (!processStatus.success) {
      // De-controlled as well as bounded. ssh stderr is remote-chosen text and
      // it lands in a log field: a NUL makes the line read as binary and an ESC
      // sequence repaints the terminal of whoever tails the log. Slicing bounds
      // the length and does nothing about either.
      const err = agentText(errRes.text.trim().slice(0, 160));
      // The class is decided HERE, where the code knows this is an ssh
      // transport failure, and travels with the error. Nothing downstream
      // re-derives it from the message -- which is what let an ssh identity
      // containing whitespace push raw stderr into a stored field.
      throw new NodeFailure(
        classifySshStderr(errRes.text, processStatus.code),
        `ssh to ${ssh.user}@${ssh.host} failed: ${
          err || `exit ${processStatus.code}`
        }`,
      );
    }
    const raw = outRes.text;
    const markerIdx = raw.lastIndexOf(`${STATUS_MARKER}:`);
    if (markerIdx === -1) {
      throw new NodeFailure(
        NODE_ERROR.sshFailed,
        `no HTTP status marker in ssh response for ${pathLabel(path)}`,
      );
    }
    const body = raw.slice(0, markerIdx).trim();
    const status = Number(
      raw.slice(markerIdx + STATUS_MARKER.length + 1).trim(),
    );
    if (!Number.isFinite(status) || status === 0) {
      throw new NodeFailure(
        NODE_ERROR.connection,
        `no HTTP response (connection failure) for ${pathLabel(path)}`,
      );
    }
    // Refuse a redirect explicitly rather than letting it fall through as
    // "empty response". curl runs without -L so it never FOLLOWS one, but a
    // 3xx used to land here with an empty body and be reported as
    // `empty response over ssh`, which is the wrong class entirely -- it says
    // "the agent answered with nothing" when the agent actually said "go
    // somewhere else". Same refusal, same wording as the direct path below,
    // so an operator reads one behaviour across both transports.
    if (status >= 300 && status < 400) {
      throw new NodeFailure(
        NODE_ERROR.redirect,
        `redirect refused on ${pathLabel(path)} (HTTP ${status}); ` +
          "swamp does not follow redirects",
      );
    }
    if (status >= 400) {
      throw new NodeFailure(
        httpErrorClass(status),
        // The body prefix is bounded AND de-controlled: it is remote-chosen
        // text on its way to a log field, and slicing 200 bytes off a payload
        // that starts with NUL or an ESC sequence yields 200 bytes of NUL and
        // ESC. Same rule, same function as every other remote string here.
        `HTTP ${status} (${classifyStatus(status)}) on ${pathLabel(path)}${
          body ? `: ${agentText(body.slice(0, 200))}` : ""
        }`,
      );
    }
    if (!body) {
      throw new NodeFailure(
        NODE_ERROR.empty,
        `empty response over ssh for ${pathLabel(path)}`,
      );
    }
    return parseJsonBody(body, path);
  };

  const getDirect = async (path: string): Promise<unknown> => {
    const res = await fetch(`${base}${path}`, {
      headers: { Accept: "application/json" },
      // Do not let the remote relocate our request. fetch defaults to
      // redirect: "follow", which silently honoured an `https:` -> `http:`
      // Location: an operator who deliberately configured HTTPS had the
      // connection downgraded to cleartext by the server itself, and nothing
      // in the stored record or the log said so. No credential is ever sent,
      // but the whole point of the operator choosing https is that the
      // hostnames, OS/version, alarm text and mount paths in the answer are
      // not readable on-path -- and a followed redirect gives that away
      // without asking. "follow" also made the direct path behave differently
      // from the ssh path, where curl runs without -L.
      // "manual", not "error": "error" collapses every redirect into an
      // untyped TypeError with no status, which is undiagnosable in the log.
      redirect: "manual",
      signal: AbortSignal.any([
        signal,
        budget,
        AbortSignal.timeout(timeoutSec * 1000),
      ]),
    });
    // A 3xx is a refusal, not a response. Runtimes differ on what a manual
    // redirect looks like -- some hand back the real 3xx status, some an
    // opaqueredirect whose status reads 0 -- so check both shapes rather
    // than trusting one. The Location value is remote-supplied text and the
    // README's threat model has an on-path party choosing it, so it goes to
    // the log only; the thrown (and therefore persisted) message carries our
    // own literals, the path and the status, and nothing from the wire.
    const redirected = res.type === "opaqueredirect" ||
      (res.status >= 300 && res.status < 400);
    if (redirected) {
      await res.body?.cancel().catch(() => {});
      logger.warning(
        "netdata {node} refused a redirect on {endpoint}: {status} -> " +
          "{location} (following it can downgrade https to cleartext)",
        {
          node: node.name,
          endpoint: pathLabel(path),
          status: res.status,
          // A Location header is remote-chosen bytes; a slice is a length
          // bound and nothing else. agentText() is what keeps a NUL or an
          // ESC sequence out of the log line.
          location: agentText(
            (res.headers.get("location") ?? "<not exposed>").slice(0, 200),
          ),
        },
      );
      throw new NodeFailure(
        NODE_ERROR.redirect,
        `redirect refused on ${pathLabel(path)} (HTTP ${res.status}); ` +
          "swamp does not follow redirects",
      );
    }
    if (!res.ok) {
      // Swallow a read failure here (including the size cap) so the HTTP
      // status class still surfaces -- that is the useful part of the error,
      // and the body is discarded before storage anyway.
      const bodyText = await readBodyBounded(res, path).catch(() => "");
      throw new NodeFailure(
        httpErrorClass(res.status),
        // Bounded and de-controlled, same as the ssh branch above: the body is
        // remote-chosen and this message reaches a log field.
        `HTTP ${res.status} (${classifyStatus(res.status)}) on ${
          pathLabel(path)
        }${bodyText ? `: ${agentText(bodyText.slice(0, 200))}` : ""}`,
      );
    }
    // Not res.json(): that buffers an unbounded body before parsing.
    return parseJsonBody(await readBodyBounded(res, path), path);
  };

  const getJson = node.ssh ? getViaSsh : getDirect;

  try {
    // Reachability is claimed only after the payload is checked, not merely
    // after bytes arrive. An /info body that is an object but does not carry
    // the identity the endpoint promises is a node we could not read, and
    // `reachable: true` with a fabricated identity is a worse lie than
    // `reachable: false` -- the latter is a state the model already represents,
    // carries the last known identity forward and protects the node's alarm and
    // mount records from the prune.
    const info = requireShape(
      InfoResponseSchema,
      expectObject(await getJson("/api/v1/info"), "/api/v1/info"),
      "/api/v1/info",
    );
    result.reachable = true;
    result.info = info;

    // Alarms and charts are best-effort: a node that answers /info but not
    // these is still a reachable node, just with less detail. Failures are
    // logged (not just swallowed) so a degraded node is diagnosable without
    // reading stored data.
    try {
      // The `alarms` key must be PRESENT and must be a map of well-formed
      // entries. Absent, null, a string, an array, or a map with one unusable
      // entry are all the same thing: a payload that is not what the endpoint
      // promises, i.e. a failed sub-fetch, which this model already knows how
      // to carry forward and mark degraded. Throwing lands it in the catch
      // below, which is exactly that path.
      //
      // Absent used to mean "zero alarms". It cannot, because a successful
      // empty alarm list is not protected from the prune: `{}` deleted every
      // stored alarm for the node -- a firing CRITICAL included -- and reported
      // the node healthy while doing it. `{"alarms": {}}` is still zero alarms;
      // that distinction is now the difference between a reading and a refusal.
      const al = requireShape(
        AlarmsResponseSchema,
        expectObject(
          await getJson("/api/v1/alarms?active=true"),
          "/api/v1/alarms",
        ),
        "/api/v1/alarms",
      );
      // AFTER the schema, and off the PARSED response. /api/v1/info carries no
      // hostname and this payload does, so this line is the only thing that
      // ever sets the stored `hostname` -- and it used to run on the raw
      // envelope, before validation. A body of `{"hostname":"<whatever>"}` and
      // nothing else therefore chose a node's stored identity while failing
      // every check that follows: the sub-fetch was correctly classified as a
      // failure, the node was correctly marked degraded, and the attacker's
      // hostname was written to the record anyway. Reading it here means a
      // payload that is not an alarms response contributes nothing at all.
      if (info.hostname === undefined && al.hostname !== undefined) {
        result.info = { ...info, hostname: al.hostname };
      }
      const entries = Object.entries(al.alarms);
      // Cap the alarm list: every entry becomes a writeResource call, so an
      // agent (or an on-path rewriter) returning 50,000 alarms turned one
      // node into 50,000 sequential writes in a single sweep.
      if (entries.length > limits.maxAlarmsPerNode) {
        result.alarmsTruncated = true;
        logger.warning(
          "netdata {node} returned {count} active alarms, over the " +
            "maxAlarmsPerNode cap of {cap} -- recording the first {cap} and " +
            "marking the node degraded",
          {
            node: node.name,
            count: entries.length,
            cap: limits.maxAlarmsPerNode,
          },
        );
      }
      result.alarms = entries.slice(0, limits.maxAlarmsPerNode).map(
        ([name, entry]) => {
          // `entry` is the PARSED alarm, not the raw one. This was
          // `asRecord(raw) ?? {}`, and that `?? {}` is the same class of bug as
          // a `?? 0` on a capacity reading. An entry that is a bare string has
          // no fields to read, and reading none produced a REAL record with
          // status "" and value null under a real instance name -- an alarm
          // that exists and reads as firing nothing, written by a sub-fetch
          // that then reported success and let the prune run. An unreadable
          // entry is now a failed sub-fetch, never an empty alarm.
          //
          // The OBJECT KEY is authoritative; the payload's own `name` field is
          // discarded. This was `{ name, ...a }`, so the spread put an
          // agent-chosen `name` back on top of the key it came under, and two
          // entries under two different keys could both claim one name:
          //   {"cpu_high": {"name":"x", "status":"CRITICAL", ...},
          //    "mem_low":  {"name":"x", "status":"WARNING", ...}}
          // Both then hashed to one instance name and the second write
          // replaced the first, so a firing CRITICAL disappeared and the node
          // still reported a successful, non-degraded alarm fetch. The key is
          // the only part of the payload Netdata guarantees to be unique, so
          // the key wins -- and discover() additionally refuses a second write
          // to an already-claimed instance name, because being able to reason
          // about identity in ONE place beats trusting the whole chain.
          return { ...entry, name };
        },
      );
      result.alarmsOk = true;
    } catch (e) {
      // Cancellation is the run being pulled out from under us, not an
      // observation about this node. Without this the abort was absorbed
      // here, classified as "degraded sub-fetch", and discover() went on to
      // persist a full set of records plus a summary with a fresh syncedAt
      // for a sweep the caller had already cancelled. Same guard as the
      // outer catch below -- it must exist in EVERY catch on this path,
      // because with nodes.length <= maxConcurrency no later pollNode is
      // ever dequeued to rethrow on its behalf.
      if (signal.aborted) throw e;
      logger.warning(
        "netdata {node} /api/v1/alarms failed: {error}",
        {
          node: node.name,
          endpoint: "/api/v1/alarms",
          // Bounded and de-controlled on the way to the log. Every failure
          // this catch sees was composed from our own literals plus already
          // de-controlled parts, but that is a property of the throw sites,
          // not of this line -- and a runtime error raised by fetch itself
          // carries text this file never wrote.
          error: agentText((e as Error).message),
        },
      );
    }

    try {
      // Same rule as /api/v1/alarms above, for the same reason and with the
      // same correction: absent is NOT zero charts. This value feeds both
      // `chartCount` and the `disk_space.` filter, so a missing key produced a
      // stored chart count of 0 and an empty mount list -- and an empty mount
      // list from a SUCCESSFUL charts fetch is not protected from the prune,
      // so every mount record for the node was deleted and an over-threshold
      // filesystem read as gone rather than unread.
      const ch = requireShape(
        ChartsResponseSchema,
        expectObject(await getJson("/api/v1/charts"), "/api/v1/charts"),
        "/api/v1/charts",
      );
      const charts = ch.charts;
      result.chartCount = Object.keys(charts).length;
      result.chartsOk = true;

      // Discover filesystem charts instead of assuming names.
      const spaceCharts = Object.keys(charts).filter((k) =>
        k.startsWith("disk_space.")
      );
      // Cap the mount sweep. Each chart below costs a full /api/v1/data call
      // -- and on the ssh transport a fresh ssh subprocess with its own
      // timeoutSec -- so an unbounded chart list was an unbounded poll.
      if (spaceCharts.length > limits.maxMountsPerNode) {
        result.mountsTruncated = true;
        logger.warning(
          "netdata {node} listed {count} disk_space charts, over the " +
            "maxMountsPerNode cap of {cap} -- polling the first {cap} and " +
            "marking the node degraded",
          {
            node: node.name,
            count: spaceCharts.length,
            cap: limits.maxMountsPerNode,
          },
        );
      }
      for (const chart of spaceCharts.slice(0, limits.maxMountsPerNode)) {
        const mount = chart.slice("disk_space.".length);
        // Bounded and de-controlled BEFORE it is used as a log field. The
        // stored fields have gone through agentText() since the field-size cap
        // landed, but the log fields never did, and a chart id is exactly as
        // agent-chosen as an alarm name: one 8 MiB `disk_space.<...>` key
        // produced an 8 MiB log line per warning, with raw escape sequences
        // intact for whatever renders the log. Same rule, same function, both
        // destinations -- a value is bounded because of where it CAME from,
        // not because of where it is going.
        const mountLabel = agentText(mount);
        // Stop iterating once the node's overall budget is spent rather than
        // grinding through the remaining charts one aborted call at a time.
        // The mounts not reached are unknown, not gone: mountsTruncated keeps
        // their stored records from being pruned.
        if (budget.aborted) {
          result.mountsTruncated = true;
          logger.warning(
            "netdata {node} hit the {budget}s node budget with mounts still " +
              "unpolled -- keeping their last known records",
            { node: node.name, budget: limits.nodeBudgetSec },
          );
          break;
        }
        try {
          // Required, not `Array.isArray(x) ? x : []`: a MISSING `labels` used
          // to become an empty label list, which reached the right answer only
          // because indexOf() then returned -1 and the guard below refuses to
          // index at -1. Correctness that depends on a later guard is one edit
          // from being wrong, so state it at the boundary. A /data response of
          // the wrong shape is an unreadable mount -- already a represented
          // state (failedMounts -> preserved record, node degraded) -- and
          // never a zero-byte filesystem.
          const data = requireShape(
            DataResponseSchema,
            expectObject(
              await getJson(
                `/api/v1/data?chart=${encodeURIComponent(chart)}` +
                  `&after=-60&points=1&format=json`,
              ),
              "/api/v1/data",
            ),
            "/api/v1/data",
          );
          const labels = data.labels;
          const row = data.data[0];
          // `points=1` should give exactly one row. An empty `data` array is
          // well-formed and still tells us nothing about this filesystem.
          if (!Array.isArray(row)) {
            result.failedMounts.push(mount);
            continue;
          }
          // Resolve dimensions by label and REFUSE to guess. indexOf() returns
          // -1 for a missing label, and row[-1] is undefined -- a previous
          // `?? 0` fallback turned that into used:0/avail:0, i.e. a failed
          // read reported as a healthy, empty filesystem on every mount of
          // every node. A mount whose dimensions can't be resolved is a
          // failed mount, same as a failed /data call.
          //
          // `?? NaN`, never Number(). DataResponseSchema has already refused
          // every cell that is not a finite number or null, so the only two
          // things left here are a reading and an explicit "no value" -- but
          // `Number()` was the second half of the same `?? 0` mistake, not a
          // separate one: it maps null to 0, false to 0 and "" to 0, so the
          // one shape Netdata uses to say "I could not measure this point"
          // arrived in the datastore as a measured zero. NaN routes it to
          // failedMounts below, which preserves the mount's last known record
          // and marks the node degraded.
          const availIdx = labels.indexOf("avail");
          const usedIdx = labels.indexOf("used");
          const avail = availIdx === -1 ? NaN : row[availIdx] ?? NaN;
          const used = usedIdx === -1 ? NaN : row[usedIdx] ?? NaN;
          if (!Number.isFinite(avail) || !Number.isFinite(used)) {
            result.failedMounts.push(mount);
            logger.warning(
              "netdata {node} mount {mount}: avail/used dimensions not " +
                "found in chart data (labels: {labels}) -- keeping last known",
              {
                node: node.name,
                mount: mountLabel,
                // The label list is agent-chosen too, and there is no cap on
                // how many labels a /data response may claim.
                labels: agentText(
                  labels.slice(0, 16).map((l) => agentText(l)).join(","),
                ),
              },
            );
            continue;
          }
          result.mounts.push({ mount, avail, used });
        } catch (e) {
          // See the alarms catch: an abort on the CALLER's signal must not be
          // laundered into a per-mount failure and swallowed.
          if (signal.aborted) throw e;
          result.failedMounts.push(mount);
          logger.warning(
            "netdata {node} mount {mount} data query failed: {error}",
            {
              node: node.name,
              mount: mountLabel,
              endpoint: agentText(chart),
              // Bounded and de-controlled on the way to the log. Every failure
              // this catch sees was composed from our own literals plus already
              // de-controlled parts, but that is a property of the throw sites,
              // not of this line -- and a runtime error raised by fetch itself
              // carries text this file never wrote.
              error: agentText((e as Error).message),
            },
          );
        }
      }
    } catch (e) {
      // See the alarms catch.
      if (signal.aborted) throw e;
      logger.warning(
        "netdata {node} /api/v1/charts failed: {error}",
        {
          node: node.name,
          endpoint: "/api/v1/charts",
          // Bounded and de-controlled on the way to the log. Every failure
          // this catch sees was composed from our own literals plus already
          // de-controlled parts, but that is a property of the throw sites,
          // not of this line -- and a runtime error raised by fetch itself
          // carries text this file never wrote.
          error: agentText((e as Error).message),
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
    // detail (ssh user@host, ssh stderr, HTTP body) goes to the log. The
    // stored `error` gets only a sanitized class, see sanitizeNodeError.
    // sanitizeNodeError takes the THROWN VALUE, not its message: the class is
    // read off the error object where the throw site put it, never recovered
    // by pattern-matching prose that a remote may have contributed to.
    const rawMsg = (e as Error).message;
    result.error = sanitizeNodeError(e);
    logger.warning(
      "netdata {node} unreachable: {error}",
      { node: node.name, url: base, error: agentText(rawMsg.slice(0, 300)) },
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
  // Uniqueness has to hold on the SLUG, not just on the raw name. The node
  // record's instance name is `node-${slug(name)}` -- deliberately hash-free,
  // so it stays typeable in `swamp data get` -- and slug() is not injective:
  // `NAS` and `nas`, or `db 1` and `db-1`, are distinct raw names that both
  // become `node-nas` / `node-db-1`. Checking only the raw name let both
  // through, and the second node's write then silently overwrote the first's
  // record: one machine's reachability, version and alarm counts stored under
  // the other's name, with nothing anywhere saying a node had gone missing.
  // Rejecting the config is the right end to fix this: adding a hash to the
  // node instance name would rename every existing node record instead.
  const seenSlugs = new Map<string, string>();
  const slugClashes: string[] = [];
  for (const n of g.nodes) {
    if (seenNames.has(n.name)) duplicates.add(n.name);
    seenNames.add(n.name);
    const s = slug(n.name);
    const first = seenSlugs.get(s);
    if (first !== undefined && first !== n.name) {
      slugClashes.push(`'${first}' and '${n.name}' (both -> ${s})`);
    } else {
      seenSlugs.set(s, n.name);
    }
  }
  if (duplicates.size > 0) {
    throw new Error(
      `Duplicate node name(s): ${[...duplicates].join(", ")} -- node names ` +
        "must be unique; they become part of every resource instance name " +
        "this model writes.",
    );
  }
  if (slugClashes.length > 0) {
    throw new Error(
      `Node names collide once normalised: ${slugClashes.join("; ")} -- ` +
        "these produce the same resource instance name, so one node's " +
        "record would overwrite the other's. Rename one so the names differ " +
        "by more than case, spacing or punctuation.",
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
    (n) =>
      pollNode(
        n,
        {
          timeoutSec: g.timeoutSec,
          maxMountsPerNode: g.maxMountsPerNode,
          maxAlarmsPerNode: g.maxAlarmsPerNode,
          nodeBudgetSec: g.nodeBudgetSec,
        },
        ctx.signal,
        ctx.logger,
      ),
  );

  const handles = [];
  const live = new Set<string>();
  /**
   * Every instance name this sweep generates is claimed here exactly once, and
   * a second claim on the same name is REFUSED rather than allowed to overwrite.
   *
   * instanceName() is collision-resistant (64-bit hash over a length-prefixed
   * identity), and the node instance name is collision-CHECKED at config parse
   * above. Neither is a proof. Nothing in the alarm and mount identities is
   * operator-controlled -- the alarm name, chart id and mount path all come
   * off an unauthenticated agent -- so "resistant" is a probability statement
   * about an input somebody else chooses. The consequence of losing that bet
   * has always been the same and has never been visible: writeResource on an
   * existing name replaces the record, so the losing write is a firing
   * CRITICAL or an over-threshold filesystem that quietly stops existing,
   * with no warning and no degraded flag.
   *
   * Refusing the second write is the direction to fail in: keeping the first
   * record and marking the node degraded preserves data and says so, where
   * overwriting destroys data and says nothing. The node's prefix is also
   * protected from the prune, so neither record is deleted while the sweep is
   * knowingly incomplete.
   */
  const claimedNames = new Map<string, string>();
  const claimName = (name: string, describe: string): boolean => {
    const first = claimedNames.get(name);
    if (first !== undefined) return false;
    claimedNames.set(name, describe);
    return true;
  };
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
    // Set when two of this node's records generate one instance name. Feeds
    // the same degraded/preserve path a failed sub-fetch takes: this round's
    // write set is knowingly not the whole picture.
    let nameCollision = false;
    // agentText, not String(): these counts and the `status` field stored on
    // each alarm record must be derived from the SAME string, or a node could
    // report alarmsCritical: 0 while one of its own alarm records reads
    // CRITICAL.
    const nodeAlarmsCritical = r.alarms.filter((a) =>
      isCritical(agentText(a.status))
    ).length;
    const nodeAlarmsWarning =
      r.alarms.filter((a) => isWarning(agentText(a.status))).length;

    // ---- alarms ---------------------------------------------------------
    if (!r.alarmsOk || r.alarmsTruncated) {
      // Alarm fetch failed (or node unreachable, which never gets this far
      // truthfully -- alarmsOk starts false), or the list was capped so we
      // never saw the tail of it. Either way this round's write set is not a
      // complete picture of the node's alarms, so preserve whatever the
      // existing alarm-* records already say instead of pruning them.
      protectedPrefixes.push(instanceNamePrefix("alarm", r.name));
    }
    for (const a of r.alarms) {
      // The stored fields and the instance name are normalised by the SAME
      // function -- instanceName() does it internally for the values it
      // hashes, agentText() does it here for the values written. Passing the
      // raw values to instanceName() rather than pre-normalised ones is
      // deliberate: it keeps that guarantee in exactly one place instead of
      // depending on every call site remembering, which is what let an
      // agent-supplied U+001F reach the join in the first place.
      const aName = agentText(a.name);
      const aChart = agentText(a.chart);
      const aStatus = agentText(a.status);
      const an = instanceName("alarm", r.name, a.name, a.chart);
      if (!claimName(an, `alarm ${aName}`)) {
        nameCollision = true;
        ctx.logger.warning(
          "netdata {node}: alarm {alarm} generated an instance name already " +
            "claimed this sweep ({name}) -- refusing the second write so the " +
            "first record survives, and marking the node degraded",
          { node: r.name, alarm: aName, name: an },
        );
        continue;
      }
      live.add(an);
      // An alarm value we cannot read is null, NOT 0. `Number(a.value ?? 0)`
      // turned Netdata's `"value": null` (a nan calculation -- collector gap,
      // freshly-triggered alarm) into a stored 0, indistinguishable from a
      // genuine "0% free" reading, so anything paging off the value could not
      // tell unknown from critically-zero. It also let a non-numeric value
      // through as NaN, which writeResource only warns about rather than
      // rejecting. This is the same `?? 0` mistake already fixed for mount
      // dimensions in pollNode -- fixed the same way, by refusing to guess.
      const rawValue = a.value;
      const numericValue = rawValue === null || rawValue === undefined
        ? NaN
        : Number(rawValue);
      const value = Number.isFinite(numericValue) ? numericValue : null;
      if (value === null) {
        ctx.logger.warning(
          "netdata {node} alarm {alarm}: value is not a finite number " +
            "({raw}) -- stored as null (unknown), not 0",
          {
            node: r.name,
            // agentText, not String(): same rule as the stored fields. An
            // alarm name is agent-chosen, so it is bounded and de-controlled
            // wherever it goes, log line included.
            alarm: aName,
            raw: agentText(rawValue),
          },
        );
      }
      handles.push(
        await ctx.writeResource("alarm", an, {
          node: r.name,
          name: aName,
          chart: aChart,
          status: aStatus,
          value,
          // units and info are free text straight off an unauthenticated
          // agent. `info` in particular is Netdata's health-engine prose and
          // the README already flags it as injectable over plain HTTP; the
          // only thing that ever bounded it was the 8 MiB whole-payload cap,
          // which one alarm can consume by itself.
          units: agentText(a.units),
          info: agentText(a.info),
        }, {
          tags: { node: r.name, status: aStatus },
        }),
      );
    }
    // (summary accumulation happens once, from the written per-node values,
    // after the node record is built below)

    // ---- mounts ---------------------------------------------------------
    if (!r.chartsOk || r.mountsTruncated) {
      protectedPrefixes.push(instanceNamePrefix("mount", r.name));
    }
    let nodeOver = 0;
    for (const m of r.mounts) {
      const total = m.avail + m.used;
      const pct = total > 0 ? Math.round((m.used / total) * 1000) / 10 : 0;
      const over = pct >= g.diskWarnPercent;
      // Same rule as the alarm write above: the mount path comes out of an
      // agent-supplied chart id, so it is agent text like any other, and
      // instanceName() does its own normalising of the raw value.
      const mPath = agentText(m.mount);
      const mn = instanceName("mount", r.name, m.mount);
      if (!claimName(mn, `mount ${mPath}`)) {
        nameCollision = true;
        ctx.logger.warning(
          "netdata {node}: mount {mount} generated an instance name already " +
            "claimed this sweep ({name}) -- refusing the second write so the " +
            "first record survives, and marking the node degraded",
          { node: r.name, mount: mPath, name: mn },
        );
        continue;
      }
      live.add(mn);
      // Counted only once the write is going ahead. Counting before the claim
      // let a refused duplicate contribute a phantom over-threshold mount to
      // the node total and the summary roll-up.
      if (over) nodeOver++;
      handles.push(
        await ctx.writeResource("mount", mn, {
          node: r.name,
          mount: mPath,
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
    //
    // It must also keep being COUNTED. Previously the record survived here
    // but mountsOverThreshold was recomputed from this round's fresh mounts
    // alone, which excludes the failed one: a mount that was over threshold
    // last round and 500s this round dropped the node's count from 1 to 0 and
    // the summary's with it, while the mount's own preserved record still
    // read overThreshold:true. Nothing was marked degraded either, so the
    // SummarySchema's documented "treat the roll-ups as a floor when
    // nodesDegraded > 0" escape hatch never fired. It read as a disk that
    // drained rather than a reading we do not have.
    //
    // Counted per failed mount from its own preserved record rather than by
    // carrying forward the whole previous node total: carrying the total
    // would throw away the fresh readings from the mounts that DID answer,
    // and would report 0 whenever the previous sweep had never seen the node.
    let carriedOver = 0;
    for (const failedMount of r.failedMounts) {
      // Raw, exactly like the fresh-mount write above: this lookup has to
      // land on the SAME instance name that write produced, so it must go
      // through the same single normalisation. Normalising here and not there
      // (or the reverse) would make this miss the preserved record it exists
      // to find, and the carried-forward over-threshold count would read 0.
      const fn = instanceName("mount", r.name, failedMount);
      // Claimed like a write, because a duplicate here is the same defect
      // wearing different clothes: two failed mounts landing on one name would
      // read the SAME preserved record twice and count one over-threshold
      // filesystem as two.
      if (!claimName(fn, `mount ${agentText(failedMount)} (carried forward)`)) {
        nameCollision = true;
        continue;
      }
      live.add(fn);
      const prevMount = await ctx.readResource(fn);
      if (prevMount?.overThreshold === true) carriedOver++;
    }

    // ---- node -------------------------------------------------------------
    if (r.reachable) reachable++;
    const nn = `node-${slug(r.name)}`;
    // The node instance name stays hash-free -- typeable in `swamp data get`,
    // which is the whole reason it is not built like the alarm and mount names.
    //
    // The 2026-08-30 review asked for the alarm/mount identity scheme here
    // instead. Declining, deliberately, because the two cases are not alike:
    // a node name is OPERATOR-supplied and finite, so a collision can be
    // refused at parse time with an error naming both offenders (see the
    // slug-clash check at the top of discover()), whereas alarm and mount
    // identities arrive from an unauthenticated agent mid-sweep and can only
    // be made improbable. Adopting a hash here would trade a config error the
    // operator can fix in one edit for an opaque suffix on every node record,
    // and would rename every existing node record to do it.
    //
    // What the review is right about is that a check somewhere else is not a
    // guarantee here, so the generated ID is claimed like any other: if the
    // parse-time check is ever weakened or bypassed, this throws instead of
    // one machine's state landing silently under another's name.
    if (!claimName(nn, `node ${r.name}`)) {
      throw new Error(
        `Node '${r.name}' generated the instance name '${nn}', which another ` +
          "node in this sweep already claimed. Node names must stay distinct " +
          "after normalisation.",
      );
    }
    live.add(nn);

    // Identity and detail fields depend on this poll actually reaching
    // /api/v1/info (and, for charts/alarms counts, the relevant sub-fetch).
    // When that didn't happen this round, carry forward the last stored
    // values instead of writing blank/zeroed placeholders that would read
    // as "this host has no version" or "zero alarms", neither of which is
    // true. The node simply didn't answer (or answer fully) this time.
    //
    // `hostname` gets its own clause because it is the one identity field
    // /api/v1/info does not carry: it comes only from the alarms payload, so a
    // failed alarms fetch means it was NOT refreshed this round even though the
    // node answered. The reachable branch below wrote a flat `null` in that
    // case -- and null is this schema's "never successfully reached this node",
    // so a single 500 from /api/v1/alarms erased a hostname the sweep had read
    // correctly for months and replaced it with the value that means the
    // opposite. Reading the stored record here is what lets it carry forward.
    const hostnameFresh = info !== null && info.hostname !== undefined;
    const prevNode = (!r.reachable || !r.alarmsOk || !r.chartsOk ||
        !hostnameFresh)
      ? await ctx.readResource(nn)
      : null;

    // The four identity strings come from an unauthenticated /api/v1/info and
    // one of them (osName) also becomes a resource TAG, so they get the same
    // bound-and-de-control treatment as alarm text.
    //
    // They are read off the PARSED info, so `version`/`os_name`/`os_version`
    // are strings or this branch was never reached -- the hand-written
    // `typeof x === "string" ? … : null` tests that used to guard them are
    // gone, and that is the point of parsing rather than casting: a field is
    // typed once, at the boundary, instead of being re-narrowed by whatever
    // each read site happened to write. What has to stay true is the meaning
    // of null on a stored record, which is now exactly one thing: this node has
    // never been read successfully. Nothing on this branch may write one --
    // except `hostname`, whose null arm carries the stored value forward
    // instead (see below).
    const identity = info !== null
      ? {
        version: agentText(info.version),
        // Carried forward, not nulled, when this round did not refresh it.
        // See the hostnameFresh comment above: null here means "never read
        // successfully", which is a lie about a node whose hostname we have
        // and simply could not re-read. The node is already degraded on the
        // path that produces this -- the alarms sub-fetch failed -- so the
        // summary's "treat the roll-ups as a floor" flag is already set.
        hostname: info.hostname !== undefined
          ? agentText(info.hostname)
          : (prevNode?.hostname as string | null | undefined) ?? null,
        osName: agentText(info.os_name),
        osVersion: agentText(info.os_version),
        // Both counts are guaranteed present and well-typed by
        // InfoResponseSchema before this line can run, and that is the fix,
        // not a nicety. countOrZero() and `Array.isArray(x) ? x.length : 0`
        // are total functions: they answer 0 for a MISSING field just as
        // readily as for a genuinely idle host, so an /info body that simply
        // omitted `cores_total` stored `cores: 0` -- a measurement of zero for
        // something nobody measured, on a node the sweep then called healthy.
        // The coercions stay because they are still the last guard against a
        // NaN reaching writeResource (which only WARNS on a schema mismatch,
        // so a bad number lands in the store regardless); what changed is that
        // reaching them with nothing to coerce is no longer possible.
        cores: countOrZero(info.cores_total),
        collectors: Array.isArray(info.collectors) ? info.collectors.length : 0,
        // Whether this agent streams to Netdata Cloud. Recorded because it
        // is a data-egress fact worth being able to audit per node -- which is
        // exactly why it must not be guessed.
        //
        // This was `Boolean(info.cloud_enabled ?? info["cloud-enabled"]) &&
        // String(info.agent_claimed ?? …) !== "false"`, two generic coercions
        // over fields no schema described, and both of them answered
        // confidently to inputs that said nothing. `Boolean("false")` is TRUE
        // (every non-empty string is), so an agent sending the string "false"
        // -- or an on-path rewriter changing a JSON `false` to `"false"` --
        // was recorded as streaming to the cloud. And an /info body with no
        // cloud fields at all produced `false`, an audit record positively
        // asserting no egress for a question that was never answered: the
        // "unmeasured must not read as measured" failure on the one field
        // whose whole purpose is being trustworthy at an audit.
        //
        // Typed as booleans in InfoResponseSchema, the three real states are
        // now distinct: absent -> null (unknown), and only a real JSON `true`
        // reads as claimed. `agent_claimed` still only has to be not-false,
        // because agents that predate the field are claimed if cloud is on.
        claimedToCloud:
          (info.cloud_enabled ?? info["cloud-enabled"]) === undefined
            ? null
            : (info.cloud_enabled ?? info["cloud-enabled"]) === true &&
              (info.agent_claimed ?? info["agent-claimed"]) !== false,
      }
      : {
        version: (prevNode?.version as string | null | undefined) ?? null,
        hostname: (prevNode?.hostname as string | null | undefined) ?? null,
        osName: (prevNode?.osName as string | null | undefined) ?? null,
        osVersion: (prevNode?.osVersion as string | null | undefined) ?? null,
        cores: countOrZero(prevNode?.cores),
        collectors: countOrZero(prevNode?.collectors),
        // Carried forward including its null: a node we could not reach has
        // told us nothing about its cloud claim this round, and `false` would
        // be an assertion we did not earn. Boolean(undefined ?? false) said
        // "this agent does not stream to the cloud" about a node that was
        // simply powered off.
        claimedToCloud:
          (prevNode?.claimedToCloud as boolean | null | undefined) ?? null,
      };

    const chartsVal = r.chartsOk ? r.chartCount : countOrZero(prevNode?.charts);
    // Fresh over-threshold mounts, plus the ones we could not read this round
    // but which were over threshold when we last could (see carriedOver).
    const mountsOverVal = r.chartsOk
      ? nodeOver + carriedOver
      : countOrZero(prevNode?.mountsOverThreshold);
    const alarmsActiveVal = r.alarmsOk
      ? r.alarms.length
      : countOrZero(prevNode?.alarmsActive);
    const alarmsCriticalVal = r.alarmsOk
      ? nodeAlarmsCritical
      : countOrZero(prevNode?.alarmsCritical);
    const alarmsWarningVal = r.alarmsOk
      ? nodeAlarmsWarning
      : countOrZero(prevNode?.alarmsWarning);

    // Roll up the values actually written for this node (carried-forward
    // included), so the summary can never read "0 alarms" for a node whose
    // alarm fetch failed. A reachable node missing a sub-fetch is "degraded".
    alarmsActive += alarmsActiveVal;
    alarmsCritical += alarmsCriticalVal;
    overThreshold += mountsOverVal;
    // "Degraded" is any reachable node whose write set this round is not a
    // complete, fresh picture. A whole sub-fetch failing is the obvious case;
    // a single mount's /data call failing and a capped/truncated list are the
    // same thing at smaller scale, and used not to count -- so a node with a
    // stale mount reading looked perfectly healthy in the summary.
    // A refused duplicate instance name belongs in the same bucket: a record
    // this sweep observed but did not store is missing data, exactly like a
    // sub-fetch that failed, and it must not read as a healthy full picture.
    const partial = !r.alarmsOk || !r.chartsOk ||
      r.failedMounts.length > 0 || r.alarmsTruncated || r.mountsTruncated ||
      nameCollision;
    if (r.reachable && partial) nodesDegraded++;
    if (nameCollision) {
      // Nothing of this node's may be pruned while we know the write set is
      // short of what the node actually reported.
      protectedPrefixes.push(instanceNamePrefix("alarm", r.name));
      protectedPrefixes.push(instanceNamePrefix("mount", r.name));
    }

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

  // Prune only on a full sweep. A single-node run legitimately sees a
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
  version: "2026.09.05.1",
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
        "health engine. Swamp records the verdict, it does not re-derive it.",
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
