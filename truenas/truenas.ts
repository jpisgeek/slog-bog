/**
 * TrueNAS SCALE inventory and health, over JSON-RPC 2.0 on a WebSocket.
 *
 * Built in-house rather than pulling a community extension: this model holds a
 * TrueNAS API key at runtime, and the decision was to keep that inside code we
 * control. It is deliberately narrow. Read-only discovery of the things a
 * homelab baseline actually needs. It does not manage datasets, shares, or
 * services.
 *
 * Speaks JSON-RPC 2.0 over WebSocket at /api/current. It originally used REST
 * v2.0, but TrueNAS raised a RESTAPIUsage alert -- triggered by this very model
 * -- warning that the REST API is removed in 26.04. Ported 2026-08-21. One
 * connection is opened per discover: authenticate once with the API key, issue
 * every query over it, close.
 *
 * Verified against TrueNAS SCALE 25.10.6 (Goldeye).
 *
 * If this fails with "tcp connect error" / "No route to host" from a macOS
 * scheduler while the same call works from a shell, suspect macOS Local
 * Network privacy rather than anything in this file: same-subnet access is
 * gated, cross-subnet and internet access is not, and a launchd-spawned
 * runtime does not inherit a Terminal's grant.
 *
 * Certificates are collected because of a real finding: TrueNAS raised a
 * CertificateIsExpiring alert, it was dismissed in the UI, and the certificate
 * still did not renew. Dismissed alerts are invisible inside TrueNAS but the
 * underlying expiry keeps advancing, so expiry is tracked here independently
 * of alert state.
 */
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  baseUrl: z
    .string()
    .min(1)
    .describe(
      "Base URL of the TrueNAS host, e.g. https://nas.example.com. Prefer " +
        "the DNS name over an IP so TLS verification actually succeeds. The " +
        "WebSocket URL is rebuilt from this (https -> wss, /api/current), so " +
        "a host, port and path are fine but a query string or fragment is " +
        "rejected.",
    ),
  apiKey: z
    .string()
    .min(1)
    .meta({ sensitive: true })
    .describe("TrueNAS API key; source it from a vault expression"),
  allowInsecureHttp: z
    .boolean()
    .default(false)
    .describe(
      "Allow baseUrl to use http://, which becomes an unencrypted ws:// " +
        "connection carrying the API key in cleartext on every call. Off " +
        "by default; only set this for a trusted loopback/VPN path where " +
        "TLS genuinely cannot be terminated on the TrueNAS host.",
    ),
  allowedHosts: z
    .array(z.string().min(1))
    .default([])
    .describe(
      "Optional pin: exact hosts the API key may be sent to, e.g. " +
        "['nas.example.com', 'nas.example.com:8443']. When non-empty the " +
        "host derived from baseUrl must match one entry exactly or the run " +
        "fails before a socket is opened. Entries are bare hosts or " +
        "host:port; no scheme, path or wildcard. Set this whenever baseUrl " +
        "comes from anywhere but a literal in your workflow file.",
    ),
  timeoutSec: z.number().int().positive().default(20),
  certWarnDays: z
    .number()
    .int()
    .positive()
    .default(30)
    .describe("Certificates expiring within this many days are flagged"),
});

/** Longest remote string that may reach a log line or an error message. */
const MAX_REMOTE_CHARS = 200;

/**
 * Longest remote string that may be *stored* in a resource field. Alert
 * `formatted` is the one field here whose whole value is remote prose, and
 * these resources have `lifetime: "infinite"`, so an unbounded value is
 * unbounded forever. TrueNAS alert text runs to a line or two; 4 KB keeps
 * every real alert intact and refuses a pathological one.
 */
const MAX_STORED_REMOTE_CHARS = 4096;

/**
 * Strip the configured API key out of any remote-supplied text.
 *
 * This is defensive, not theoretical: `auth.login_with_api_key` takes the key
 * as its ONLY argument, and middlewared's own error prose habitually echoes
 * the argument that failed validation. Nothing in the JSON-RPC contract stops
 * a host -- a real one with a bad day, or one an operator was misdirected to
 * -- from putting the key back in `error.message`, which this model then puts
 * in a thrown Error that swamp logs. The README claims the key is never
 * logged; before this, that claim depended on the far end's discretion.
 *
 * The length floor matters. A one- or two-character `apiKey` (a test fixture,
 * a misconfigured vault lookup returning a stray char) would otherwise match
 * everywhere and shred every message into [REDACTED]. A real TrueNAS API key
 * is 64 characters; anything under 8 cannot be one, and mangling diagnostics
 * to protect a value that is not a credential is a worse trade.
 */
function redactKey(text: string, apiKey: string): string {
  if (apiKey.length < 8) return text;
  return text.split(apiKey).join("[REDACTED]");
}

/**
 * Neutralise the characters that let remote text act on whatever renders it.
 *
 * Remote strings from this socket do not only reach errors and logs; alert
 * `formatted`, `klass` and `level`, disk models and serials, pool names and
 * certificate CNs are all written into stored resources and, for several of
 * them, into resource TAGS -- which are how a workflow selects records. An
 * ESC]0;...BEL in an alert message rewrites the terminal title of whoever
 * runs `swamp data list`; a bidi override makes two different pool names
 * render identically to the person reading the gate output; a lone surrogate
 * is not valid UTF-8 and can fail a serializer downstream. None of that is
 * about the *length* of the text, which is why bounding it was not enough.
 */
function screenRemote(s: string): string {
  return s
    // deno-lint-ignore no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ")
    .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "")
    .replace(/[\ud800-\udbff](?![\udc00-\udfff])/g, "�")
    .replace(/(^|[^\ud800-\udbff])([\udc00-\udfff])/g, "$1�")
    .replace(/ {2,}/g, " ")
    .trim();
}

/**
 * The single boundary every remote-supplied value crosses on its way into an
 * error, a log line, a stored field or a tag.
 *
 * Three separate defects lived on this path and they are fixed together
 * because they are one class, not three sites:
 *
 *   - Unbounded. The non-array guard pasted a whole `JSON.stringify(raw)`
 *     into a thrown error, so a hostile or merely broken host chose how much
 *     text went into swamp's logs.
 *   - Unredacted. See redactKey(): the API key could come back to us in the
 *     server's own error message and go straight out to a log.
 *   - Unscreened. See screenRemote(): control, bidi and zero-width characters
 *     reached logs, errors, stored fields and tags verbatim.
 *
 * It truncates rather than blanking. The leading text is what makes a failure
 * diagnosable -- "TrueNAS RPC error 11: pool is busy" is the finding, and a
 * canned "RPC error" would make this model undiagnosable for exactly the
 * cases it exists to diagnose. What is removed is the ability of that text to
 * be unbounded, to carry the key, or to drive a terminal.
 */
function safeRemoteText(
  value: unknown,
  apiKey: string,
  max = MAX_REMOTE_CHARS,
): string {
  let s: string;
  if (typeof value === "string") {
    s = value;
  } else {
    try {
      s = JSON.stringify(value) ?? String(value);
    } catch {
      // Circular or otherwise unserialisable: the type is still diagnostic.
      s = `[unserialisable ${typeof value}]`;
    }
  }
  // Cap before the regex work so a multi-megabyte payload cannot turn
  // screening itself into the denial of service.
  const screened = screenRemote(redactKey(s.slice(0, 65_536), apiKey));
  return screened.length <= max
    ? screened
    : `${screened.slice(0, max)}… (${screened.length} chars, truncated)`;
}

/** The `safe()` closure threaded through everything that touches remote text. */
type Safe = (value: unknown, max?: number) => string;

/**
 * Runtime validation of baseUrl. Deliberately NOT an object-level zod
 * refinement: swamp calls .partial() on globalArguments, and zod 4 refuses
 * that on an object carrying refinements -- a superRefine here made every
 * discover() fail before it connected.
 *
 * Returns the parsed URL so the caller builds the WebSocket URL from its
 * components instead of pasting strings onto the raw argument.
 */
function assertBaseUrl(
  baseUrl: string,
  allowInsecureHttp: boolean,
  allowedHosts: string[],
): URL {
  if (!/^https?:\/\//i.test(baseUrl)) {
    throw new Error("baseUrl must start with http:// or https://");
  }
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    throw new Error("baseUrl is not a valid URL");
  }
  // The derived wsUrl is logged at info and appears in connection errors, so
  // baseUrl must not carry userinfo -- it would be copied into both.
  if (u.username !== "" || u.password !== "") {
    throw new Error(
      "baseUrl must not embed credentials (user:pass@host); the API key is " +
        "the only credential and is sent via apiKey.",
    );
  }
  if (u.protocol === "http:" && !allowInsecureHttp) {
    throw new Error(
      "baseUrl uses http://, which becomes an unencrypted ws:// connection " +
        "carrying the API key in cleartext. Use https://, or set " +
        "allowInsecureHttp: true to override (not recommended).",
    );
  }
  // A query string or fragment cannot mean anything to the JSON-RPC endpoint,
  // and the wsUrl used to be built by concatenation onto the raw argument, so
  // `https://nas.example.com/?debug=1` produced
  // `wss://nas.example.com/?debug=1/api/current` -- a URL whose path is buried
  // inside its query string. That never reaches /api/current, it fails with a
  // connection error that does not say why, and whatever the operator typed
  // there was logged at info and copied into every connection error along the
  // way. Reject both; the caller rebuilds the URL from `u` below.
  if (u.search !== "" || u.hash !== "") {
    throw new Error(
      "baseUrl must not carry a query string or fragment. It addresses the " +
        "TrueNAS JSON-RPC endpoint at /api/current and nothing else; anything " +
        "after ? or # corrupts the derived wss:// URL.",
    );
  }
  assertHostAllowed(u, allowedHosts);
  return u;
}

/**
 * Enforce the `allowedHosts` pin: the API key may only be put on a socket to
 * a host the operator named here, and the check runs before any socket opens.
 *
 * WHY THIS IS A PIN AND NOT A MANDATORY ALLOWLIST -- the deliberate trade.
 *
 * The security review asked for an allowlist that is always required. When
 * `baseUrl` is a literal in the workflow file, that allowlist is a second
 * copy of the same literal, written by the same hand at the same moment, and
 * a typo goes into both copies -- so it cannot catch the mistake it exists to
 * catch, while it can and does break every working configuration on upgrade.
 * That is ceremony, not a control.
 *
 * Where it IS a real control is the case the review is actually describing:
 * `baseUrl` resolved from a vault expression, a datastore value, or a
 * workflow variable, where the host is not visible in the file at all. There
 * the pin is an independent literal and the only thing standing between a
 * changed upstream value and a live API key leaving for a new destination.
 * So it is offered, enforced without exception once set, and the README says
 * plainly to set it whenever `baseUrl` is not a literal.
 *
 * Entries are validated rather than merely compared. A pin written as
 * `https://nas.example.com/` or `*.example.com` would never match anything,
 * so it would silently deny every run -- or worse, in an earlier draft that
 * skipped unmatched-but-malformed entries, silently allow every run. A pin
 * that cannot work is a configuration error and says so at parse time.
 */
function assertHostAllowed(u: URL, allowedHosts: string[]): void {
  if (allowedHosts.length === 0) return;
  const seen = allowedHosts.map((raw, i) => {
    const entry = raw.trim().toLowerCase();
    if (
      !/^[a-z0-9._~\-]+(:\d{1,5})?$|^\[[0-9a-f:.]+\](:\d{1,5})?$/.test(entry)
    ) {
      throw new Error(
        `allowedHosts[${i}] is not a bare host or host:port. Write ` +
          `"nas.example.com" or "nas.example.com:8443" (IPv6 in brackets); ` +
          `a scheme, a path, or a wildcard never matches anything and would ` +
          `silently break every run.`,
      );
    }
    return entry;
  });
  // Match host (with port) when the entry names a port, hostname otherwise, so
  // a pin does not have to guess whether the URL spelled out :443.
  const host = u.host.toLowerCase();
  const hostname = u.hostname.toLowerCase();
  const hasPort = (e: string) =>
    e.startsWith("[") ? /\]:\d+$/.test(e) : e.includes(":");
  const ok = seen.some((e) => (hasPort(e) ? e === host : e === hostname));
  if (!ok) {
    // The rejected host is operator-supplied config, not remote text, and
    // naming it is the whole diagnostic value of this error.
    throw new Error(
      `baseUrl host "${host}" is not in allowedHosts. The API key is not ` +
        `sent to a host that was not pinned.`,
    );
  }
}

const DiscoverArgsSchema = z.object({});

/**
 * Sentinel written in place of a numeric TrueNAS did not report.
 *
 * Every one of these fields used to be backfilled with `?? 0`, which is the
 * certificate `daysRemaining` mistake wearing a different hat: 0 is a
 * *legitimate* value for all of them. An empty pool really does have 0 bytes
 * allocated; a box that just came up really does have near-0 uptime. So a CEL
 * gate could not tell "TrueNAS did not say" from "TrueNAS said zero", and a
 * pool whose `allocated`/`free` came back null was written sizeBytes: 0,
 * usedPercent: 0 -- a capacity gate read that as plenty of room, on a pool it
 * knew nothing about.
 *
 * -1 is impossible for every field it stands in for, so a consumer that never
 * reads the companion `*Known` flag still sees an obviously-wrong number
 * rather than a reassuring one. The flag is the supported way to ask; the
 * sentinel is the safety net under consumers that forget, exactly as
 * `expiryKnown` sits over `daysRemaining: -9999`.
 */
const UNKNOWN_NUMBER = -1;

const SystemSchema = z.object({
  hostname: z.string(),
  version: z.string(),
  model: z.string(),
  cores: z.number(),
  physmemBytes: z.number(),
  uptimeSeconds: z.number(),
  loadavg: z.array(z.number()),
  /**
   * False when TrueNAS omitted any of `cores`, `physmem` or `uptime_seconds`;
   * those three are then UNKNOWN_NUMBER. Check this before comparing them --
   * `uptimeSeconds` in particular, since a backfilled 0 makes a "rebooted in
   * the last five minutes" gate fire on every single run.
   */
  metricsKnown: z.boolean(),
});

const PoolSchema = z.object({
  name: z.string(),
  status: z.string(),
  healthy: z.boolean(),
  allocatedBytes: z.number(),
  freeBytes: z.number(),
  sizeBytes: z.number(),
  usedPercent: z.number(),
  fragmentationPercent: z.number(),
  /**
   * False when TrueNAS reported no `allocated`/`free` for this pool;
   * `allocatedBytes`, `freeBytes`, `sizeBytes` and `usedPercent` are then all
   * UNKNOWN_NUMBER. Consumers must check this before gating on capacity.
   */
  capacityKnown: z.boolean(),
});

const DiskSchema = z.object({
  name: z.string(),
  serial: z.string(),
  model: z.string(),
  sizeBytes: z.number(),
  type: z.string(),
  pool: z.string(),
  /** False when TrueNAS reported no `size`; `sizeBytes` is UNKNOWN_NUMBER. */
  sizeKnown: z.boolean(),
  /**
   * True when TrueNAS actually answered the pool-membership question, whether
   * the answer was a pool name or "this disk is in no pool".
   *
   * `pool` used to be `d.pool ?? ""` with the tag `d.pool ?? "none"`, which
   * made two completely different facts render identically: a disk genuinely
   * outside every pool, and a run where the `extra: { pools: true }` join was
   * not honoured at all. In the second case EVERY disk reads "none", so an
   * "orphaned disk" gate fires across the whole array while a "which disks
   * back tank" gate silently returns nothing. When this is false the `pool`
   * field is "" and the tag reads "unknown", never "none".
   */
  poolKnown: z.boolean(),
});

const AlertSchema = z.object({
  id: z.string(),
  klass: z.string(),
  level: z.string(),
  formatted: z.string(),
  dismissed: z.boolean(),
  /**
   * True when the alert is real but hidden from the TrueNAS UI because
   * somebody dismissed it. These are the dangerous ones.
   */
  silenced: z.boolean(),
});

const CertificateSchema = z.object({
  name: z.string(),
  commonName: z.string(),
  notAfter: z.string(),
  daysRemaining: z.number(),
  /**
   * False for objects with no expiry at all, a CSR for instance. Without
   * this, the sentinel daysRemaining reads as a real (and alarming) number.
   * Consumers must check this before comparing daysRemaining.
   */
  expiryKnown: z.boolean(),
  expiringSoon: z.boolean(),
  expired: z.boolean(),
});

const SummarySchema = z.object({
  hostname: z.string(),
  version: z.string(),
  pools: z.number(),
  poolsUnhealthy: z.number(),
  /**
   * Pools whose capacity TrueNAS did not report this run. Counted here for the
   * same reason `certificatesWithoutExpiry` is: a workflow that gates on the
   * summary alone would otherwise have no way to see that the capacity numbers
   * underneath it are absent rather than low.
   */
  poolsCapacityUnknown: z.number(),
  disks: z.number(),
  alerts: z.number(),
  alertsSilenced: z.number(),
  certificates: z.number(),
  certificatesExpiringSoon: z.number(),
  certificatesExpired: z.number(),
  certificatesWithoutExpiry: z.number(),
  /**
   * True when `pool.query` came back as a well-formed EMPTY array. A NAS with
   * no pools is not a steady state; this is what a pool still importing after
   * a reboot, or failing to import at all, looks like from here.
   */
  poolsReportedEmpty: z.boolean(),
  /** Same, for `disk.query`. A NAS with no disks has no steady state at all. */
  disksReportedEmpty: z.boolean(),
  /**
   * The one field a workflow can gate on to refuse the whole roll-up.
   *
   * The summary used to report `pools: 0, poolsUnhealthy: 0` for an empty
   * response and say nothing else, which reads exactly like a clean bill of
   * health: zero pools, none of them unhealthy. The prune protection already
   * kept the underlying records, but it only WARNED when it had stale records
   * to keep -- so on a first run, where nothing stale exists, the run was
   * completely silent about having discovered nothing.
   *
   * This does not fail the run. Alerts and certificates come off the same
   * connection and are still valid, and an import window is transient, so
   * throwing away a good certificate-expiry reading to punish a missing pool
   * list is the wrong trade. The flag makes the incompleteness explicit and
   * lets the consumer decide; the run also warns unconditionally now.
   */
  discoveryDegraded: z.boolean(),
  syncedAt: z.string(),
});

/**
 * Raw TrueNAS response shapes for the fields this model actually reads.
 *
 * These validate an untrusted third-party payload. Unlike the resource
 * schemas above (which gate CEL and must be exact), a TrueNAS release that
 * ADDS a field must not break discovery, so `.strict()` is wrong here: a
 * point release that enriches `disk.query` would take the whole model down.
 *
 * They used to carry `.passthrough()`, defended as "extra fields we don't use
 * are expected and harmless". The first half of that is right and the second
 * half was the mistake. `.passthrough()` does not merely *accept* undeclared
 * keys, it RETAINS them on the parsed object -- so every raw record carried
 * an unbounded, entirely unvalidated blob of remote data through the rest of
 * discover(), one `...spread` away from being written into an
 * infinite-lifetime resource by a future edit that looked harmless. Zod's
 * default `strip` accepts exactly the same payloads and drops the undeclared
 * keys at the parse boundary, so nothing past this line can reach them by
 * accident. Forward compatibility was never the thing `.passthrough()` bought;
 * strip gives that for free and retention was pure downside.
 *
 * What each schema still asserts is that the fields the model RELIES on are
 * present and typed as expected, so contract drift throws here instead of the
 * mapping code silently writing placeholder 0/""/[] values as if they were
 * real data.
 */
const RawSystemSchema = z.object({
  hostname: z.string(),
  version: z.string(),
  model: z.string().nullable().optional(),
  cores: z.number().nullable().optional(),
  physmem: z.number().nullable().optional(),
  uptime_seconds: z.number().nullable().optional(),
  // `model` stays optional on purpose and is NOT part of the class fixed
  // below: its backfill is the literal string "unknown", which names itself
  // as a placeholder. The defect being fixed elsewhere is a backfill that a
  // consumer cannot tell from data, and "unknown" is not one.
  loadavg: z.array(z.number()).nullable().optional(),
});

const RawPoolSchema = z.object({
  name: z.string(),
  id: z.union([z.string(), z.number()]).optional(),
  status: z.string().nullable().optional(),
  healthy: z.boolean().nullable().optional(),
  allocated: z.number().nullable().optional(),
  free: z.number().nullable().optional(),
  // Confirmed against TrueNAS API v25.10: "Percentage of pool fragmentation
  // as a string, or null if not available."
  fragmentation: z.union([z.string(), z.number()]).nullable().optional(),
}).refine(
  // Presence, not truthiness -- the same shape as the certificate expiry
  // check below, for the same reason.
  //
  // `status` and `healthy` are core `pool.query` fields, not `extra`-gated
  // ones, so their KEYS are always present on a host whose contract has not
  // drifted. While they were merely optional, a rename made `Boolean(
  // undefined)` false for every pool on the box: `poolsUnhealthy` equalled
  // `pools` on every run, forever, and `status` read "UNKNOWN" -- which looks
  // like a real ZFS status string rather than like a parse failure. A
  // permanent, box-wide false degrade is not a safe failure mode; it trains
  // an operator to ignore the one signal pools exist to give.
  (p) => p.status !== undefined && p.healthy !== undefined,
  {
    message:
      "pool.query row is missing `status` and/or `healthy`; the TrueNAS pool " +
      "contract has changed and pool health can no longer be read",
  },
);

/**
 * The refinements on the three schemas below exist because every field in
 * them was optional, which made the contract this block claims a no-op for
 * them: `.parse()` could not fail, so a renamed field fell through to the
 * `?? ""` defaults in the mapping code and was written as if it were real
 * data. Each refinement asserts only the *identity or date* fields the model
 * genuinely cannot work without, so a rename throws while a merely enriched
 * payload still passes.
 */
const RawDiskSchema = z.object({
  devname: z.string().nullable().optional(),
  identifier: z.string().nullable().optional(),
  serial: z.string().nullable().optional(),
  model: z.string().nullable().optional(),
  size: z.number().nullable().optional(),
  type: z.string().nullable().optional(),
  // Only populated when disk.query is called with extra.pools: true, and the
  // absent-vs-null distinction is load-bearing -- see `poolKnown` on
  // DiskSchema. Left optional rather than required precisely BECAUSE the
  // model can now represent "not answered" honestly: making it required
  // would take a whole NAS's discovery down over a join that has a correct
  // non-fatal reading.
  pool: z.string().nullable().optional(),
}).refine(
  // With neither field, instanceName() falls back to `idx<n>`, so the disk's
  // instance name is its position in the response -- it changes whenever the
  // enumeration order does, and every poll then prunes and re-creates the
  // same disk under a new name.
  (d) => d.identifier != null || d.devname != null,
  {
    message:
      "disk.query row has neither `identifier` nor `devname`; the TrueNAS " +
      "disk contract has changed and disks can no longer be identified",
  },
);

const RawAlertSchema = z.object({
  uuid: z.string().optional(),
  id: z.union([z.string(), z.number()]).optional(),
  key: z.string().optional(),
  klass: z.string().nullable().optional(),
  level: z.string().nullable().optional(),
  formatted: z.string().nullable().optional(),
  dismissed: z.boolean().nullable().optional(),
}).refine(
  // Same index-fallback churn as disks, and worse here: alert-* records are
  // pruned on absence by design, so unstable names mean every run deletes
  // and re-adds the whole alert set.
  (a) => a.uuid != null || a.id != null || a.key != null,
  {
    message:
      "alert.list row has none of `uuid`, `id`, `key`; the TrueNAS alert " +
      "contract has changed and alerts can no longer be identified",
  },
).refine(
  // Presence again. `klass`, `level` and `formatted` are the entire content
  // of an alert -- the class it belongs to, how bad it is, and what it says.
  // Backfilled to "" they produce a record that exists, counts toward
  // `summary.alerts`, and matches no `klass ==` or `level ==` gate anywhere,
  // so a box full of CRITICAL alerts reports as a box full of alerts nobody
  // wrote a rule for. Present-and-null is still accepted and still maps to
  // "": what must not pass silently is the key being gone.
  (a) =>
    a.klass !== undefined && a.level !== undefined && a.formatted !== undefined,
  {
    message:
      "alert.list row is missing `klass`, `level` and/or `formatted`; the " +
      "TrueNAS alert contract has changed and alert severity can no longer " +
      "be read",
  },
);

const RawCertificateSchema = z.object({
  id: z.union([z.string(), z.number()]).optional(),
  name: z.string().nullable().optional(),
  common: z.string().nullable().optional(),
  common_name: z.string().nullable().optional(),
  until: z.unknown().optional(),
  not_after: z.unknown().optional(),
}).refine(
  // Presence, not truthiness: `until: null` is a legitimate payload -- a CSR
  // has no expiry, which is exactly what expiryKnown:false exists to record
  // -- so requiring a non-null value here would reject valid data. What must
  // never pass silently is the key being GONE, because toIso(undefined) is
  // "" and every certificate would then be written notAfter:"",
  // expiryKnown:false, daysRemaining:-9999. summary.certificatesWithoutExpiry
  // would quietly equal certs.length on every run, including for a cert two
  // days from lapsing -- the precise failure certificates are collected to
  // catch (see the module header).
  (c) => c.until !== undefined || c.not_after !== undefined,
  {
    message: "certificate.query row has neither `until` nor `not_after`; the " +
      "TrueNAS certificate contract has changed and expiry can no longer " +
      "be read",
  },
);

/**
 * Unambiguous encoding of an identity tuple: each field is prefixed with its
 * own length, so no content inside a field can be mistaken for the boundary
 * between two fields.
 *
 * This replaces `identity.join(U+001F)`. A separator-based encoding is only
 * injective while the separator cannot occur inside a field, and NOTHING
 * enforced that: every one of these fields is remote text straight out of a
 * TrueNAS payload, so a disk `identifier` or an alert `klass` containing a
 * Unit Separator collapsed two different identity tuples onto one digest --
 * and a digest collision here means two different objects sharing one
 * `infinite`-lifetime record, each run overwriting the other's state.
 * (Screening the fields instead would be worse: mapping U+001F to a space
 * makes DIFFERENT identities encode identically, which is the same bug.)
 * Length prefixes need no such assumption; ["a","b c"] and ["a b","c"] encode
 * as "1:a3:b c" and "3:a b1:c" whatever the fields contain.
 */
function encodeIdentity(identity: string[]): string {
  return identity.map((s) => `${s.length}:${s}`).join("");
}

/** Longest readable half of an instance name. The name is a storage path
 * component, so it is bounded well inside the ext4/APFS 255-byte limit. */
const MAX_SLUG_CHARS = 48;

/**
 * SHA-256 over the encoded identity, truncated to 128 bits and hex-encoded.
 *
 * This was a 32-bit FNV-1a. 32 bits gives a ~50% chance of some collision
 * across roughly 77,000 distinct identities, and the readable half of the
 * name cannot break a tie because it is truncated to MAX_SLUG_CHARS and is
 * not injective anyway (`foo/bar` and `foo-bar` both slug to `foo-bar`). A
 * collision means two disks, or two alerts, silently sharing one record.
 * 128 bits is not a number of buckets anything collides in.
 *
 * "Non-cryptographic is fine, this is not security sensitive" was the old
 * justification and it does not hold: the inputs are attacker-influencable
 * remote strings, and FNV-1a is trivially invertible to a chosen digest, so
 * a hostile payload could aim one object's record at another's on purpose.
 *
 * Widening the digest RENAMES every stored instance. The run after this
 * change writes new records and prunes the old ones, exactly as documented in
 * the README, and history under the old names is lost once. That is a
 * one-time cost paid deliberately; it is the same trade the `cert-` prefix
 * comment declines to pay for a cosmetic rename, and is worth paying here
 * because the alternative is silent record merging.
 */
async function shortHash(input: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(digest).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Resource instance names must be stable and filesystem-safe. */
function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(
    /^-+|-+$/g,
    "",
  ) || "unnamed";
}

/**
 * Build a collision-safe, filesystem-safe instance name. `slug()` alone is
 * not injective -- distinct raw identifiers can slug to the same string
 * (`foo/bar` and `foo-bar` both become `foo-bar`), and a fully missing
 * identifier always slugs to the literal string "unnamed" for every record
 * that has one. Every name here therefore also carries a short hash of the
 * *raw*, pre-slug identity fields, so two records only ever produce the
 * same instance name when their raw identity is actually identical.
 *
 * Identity fields must be stable across polls (real IDs, not mutable state
 * like a formatted message or a status string) -- otherwise the instance
 * name would change every time the underlying data changes, breaking
 * garbage collection and history for what is still the same resource.
 */
async function instanceName(
  prefix: string,
  ...identity: string[]
): Promise<string> {
  // Length-prefixed rather than separator-joined; see encodeIdentity(). The
  // previous separators (a raw NUL, then U+001F) both assumed that byte could
  // not occur inside an identifier, and nothing enforced it -- every field
  // here is remote text off a TrueNAS payload.
  const raw = encodeIdentity(identity);
  // Build the readable label from EVERY non-empty identity field, not just the
  // first. Taking only the first made the visible part non-discriminating
  // wherever a caller passes a shared scope first: netdata's alarms pass the
  // node name ahead of the alarm name, so every alarm on one node rendered as
  // `alarm-<node>-<hash>` and differed only in an opaque hash. Unique, but
  // `swamp data list` became unreadable -- the whole reason for a readable part.
  // Capped so an unusually long identity cannot produce an unbounded name.
  // The hash still covers the full raw identity, so uniqueness never depends on
  // what survives truncation.
  const parts = identity.filter((s) => s !== "").map(slug).filter((s) =>
    s !== ""
  );
  const label =
    (parts.length ? parts.join("-").slice(0, MAX_SLUG_CHARS) : "").replace(
      /-+$/,
      "",
    ) || "unnamed";
  return `${prefix}-${label}-${await shortHash(raw)}`;
}

/**
 * TrueNAS reports pool fragmentation as a nullable percentage, sometimes with
 * a trailing "%".
 *
 * ABSENT still means 0, and that is argued, not overlooked. Unlike a missing
 * capacity or a missing certificate expiry, 0% fragmentation is not itself an
 * alarming value, so no gate can be lulled by it -- the worst a consumer does
 * is see a healthy fragmentation figure for a pool that reported none.
 *
 * MALFORMED is a completely different fact and used to be folded into the
 * same 0. `Number("busy")` is NaN, `Number.isFinite(NaN)` is false, and the
 * old line answered 0 -- so `fragmentation: "ERROR"`, or a future release
 * changing the field to an object, or a value of 4e9, all reported as a
 * pristine pool. That is contract drift or a hostile payload wearing the
 * exact disguise this model exists to strip off, so it throws. Bounds too:
 * a percentage outside 0-100 is not a percentage.
 */
function parsePercent(
  value: string | number | null | undefined,
  safe: Safe,
): number {
  if (value === null || value === undefined) return 0;
  const n = typeof value === "number"
    ? value
    : Number(value.replace(/%\s*$/, "").trim());
  if (!Number.isFinite(n) || n < 0 || n > 100) {
    throw new Error(
      `pool.query returned a fragmentation value that is not a 0-100 ` +
        `percentage: ${safe(value, 64)}`,
    );
  }
  return n;
}

function daysUntil(iso: string): number {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return Number.NaN;
  return Math.floor((then - Date.now()) / 86_400_000);
}

/**
 * Normalize a TrueNAS expiry field to an ISO string, or null when the record
 * legitimately has no expiry.
 *
 * The three-way distinction is the whole point, and the old `toIso` collapsed
 * it to two. It returned "" for anything it could not read -- an unparseable
 * date string, a `{ $date: ... }` wrapper of an unexpected shape, a boolean,
 * a number out of Date range -- and the caller turned "" into
 * `expiryKnown: false`, which is the SAME state a CSR produces. So "we could
 * not read this certificate's expiry" and "this object has no expiry, by
 * design" were indistinguishable, on the one field this model was written to
 * watch (see the module header: a dismissed CertificateIsExpiring alert is
 * why certificates are collected at all).
 *
 *   - absent / null / empty string -> null, a real "no expiry" (a CSR).
 *   - a value this function can turn into a date -> that date.
 *   - anything else -> throw. Present but unreadable is drift, not absence.
 */
function toIsoOrNull(value: unknown, safe: Safe): string | null {
  const fail = () =>
    new Error(
      `certificate.query returned an expiry this model cannot read: ` +
        `${safe(value, 64)}. Present-but-unreadable is contract drift; it is ` +
        `not reported as "no expiry", because a CSR reports that legitimately.`,
    );
  const fromEpoch = (ms: number): string => {
    if (!Number.isFinite(ms)) throw fail();
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) throw fail();
    return d.toISOString();
  };
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    if (value.trim() === "") return null;
    if (Number.isNaN(Date.parse(value))) throw fail();
    return value;
  }
  if (typeof value === "number") return fromEpoch(value);
  if (typeof value === "object") {
    const d = (value as Record<string, unknown>)["$date"];
    if (typeof d === "number") return fromEpoch(d);
    if (typeof d === "string") {
      if (d.trim() === "") return null;
      if (Number.isNaN(Date.parse(d))) throw fail();
      return d;
    }
  }
  throw fail();
}

/**
 * `auth.login_with_api_key` is deprecated and scheduled for removal in
 * TrueNAS 27. `auth.login_ex` with the API_KEY_PLAIN mechanism is the
 * replacement, but it also requires a `username`, which this model does not
 * currently collect. Rather than ship an auth path that has never been run
 * against a real host, support is capped explicitly and the limit is stated
 * wherever an operator can actually hit it.
 *
 * That last part was the defect. The hint used to live *only* in the
 * post-connect warning below, which runs after `system.info` -- i.e. only on a
 * run where authentication already succeeded. On the host the hint exists for,
 * the one where the call is gone, auth is what fails, `system.info` never runs
 * and the warning never printed. The operator got a bare RPC error and no
 * explanation. So the hint is now attached to the auth failure itself
 * (AUTH_REMOVAL_HINT, used in discover()), and this warning covers the other
 * case: a 27+ host where the deprecated call still happens to work, which is a
 * heads-up rather than a diagnosis.
 */
const AUTH_REMOVAL_HINT =
  "If this host is TrueNAS 27 or newer, auth.login_with_api_key has been " +
  "removed: this model has not moved to auth.login_ex, which additionally " +
  "requires a username it does not collect.";

function warnIfVersionUnsupported(
  version: string,
  logger: { warning: (msg: string, props?: Record<string, unknown>) => void },
  safe: Safe,
): void {
  const m = version.match(/(\d{2,4})\.(\d{1,2})\.(\d{1,2})/);
  if (!m) return;
  const major = Number(m[1]);
  if (Number.isFinite(major) && major >= 27) {
    logger.warning(
      "TrueNAS reports version {version}; auth.login_with_api_key is " +
        "scheduled for removal starting with 27. It still worked this run, " +
        "but this model has not moved to auth.login_ex, so a later upgrade " +
        "will break discovery.",
      // Remote free text; bound it like every other remote string that
      // reaches a log line.
      { version: safe(version, 64) },
    );
  }
}

/**
 * A single inbound frame, after validation.
 *
 * `notification` covers a well-formed frame with no id: middlewared pushes
 * `collection_update` events down the same socket, and those correlate to
 * nothing we sent. They are dropped silently -- flagging them would turn a
 * normal TrueNAS behaviour into a warning on every run.
 */
type RpcFrame =
  | { kind: "notification" }
  | { kind: "result"; id: number; result: unknown }
  | { kind: "error"; id: number; code: string; message: string }
  | { kind: "invalid"; id?: number; detail: string };

/**
 * Validate an inbound JSON-RPC frame before anything correlates on it.
 *
 * The old code did `msg = JSON.parse(...)` and immediately asserted the
 * result was a `Record<string, unknown>`, then `const id = msg.id as number`.
 * Every one of the following was a real outcome of that:
 *
 *   - A frame of `null`, or a bare number/string/array. `msg.id` on `null`
 *     throws a TypeError inside `ws.onmessage`, which is not inside any
 *     try/catch and not attached to any promise, so it escapes as an
 *     unhandled error while the pending call sits waiting for its timeout.
 *   - A STRING id. `#pending` is keyed by number, so `get("3")` misses, the
 *     reply is dropped on the floor, and the call fails the full timeoutSec
 *     later reporting "timed out waiting for pool.query" -- a diagnosis
 *     pointing at the network for what is a protocol mismatch.
 *   - `error: 0` or `error: ""`. `if (msg.error)` is false for both, so the
 *     frame took the SUCCESS branch and resolved the call with
 *     `result: undefined`. For `auth.login_with_api_key` that lands on
 *     `authed !== true` and reports a revoked API key; for `pool.query` it
 *     lands on the non-array guard. Both blame the wrong thing.
 *   - `error` present as a string or array. `e.code`/`e.message` are then
 *     undefined and the error reads "TrueNAS RPC error ?: (no message)",
 *     which says nothing at all.
 *   - Neither `result` nor `error`. Silently resolved with undefined.
 *
 * Anything that fails validation is reported as such -- rejecting the pending
 * call immediately when the id is usable, so the caller gets the protocol
 * fault instead of a timeout that misdescribes it.
 */
function classifyFrame(raw: unknown, safe: Safe): RpcFrame {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    const what = raw === null
      ? "null"
      : Array.isArray(raw)
      ? "an array"
      : `a ${typeof raw}`;
    return {
      kind: "invalid",
      detail: `frame is ${what}, not a JSON-RPC object`,
    };
  }
  const m = raw as Record<string, unknown>;
  if (m.jsonrpc !== undefined && m.jsonrpc !== "2.0") {
    return {
      kind: "invalid",
      detail: `frame declares jsonrpc ${safe(m.jsonrpc, 32)}, not "2.0"`,
    };
  }
  // No id (or a null id) and nothing to correlate: a notification.
  if (m.id === undefined || m.id === null) return { kind: "notification" };
  if (typeof m.id !== "number" || !Number.isSafeInteger(m.id)) {
    return {
      kind: "invalid",
      detail: `frame id is ${safe(m.id, 32)} (${typeof m.id}), not the ` +
        `integer this client sends; the reply cannot be matched to a call`,
    };
  }
  const id = m.id;
  const hasResult = "result" in m;
  // Presence, not truthiness. `error: 0` used to read as success.
  const hasError = "error" in m && m.error !== null && m.error !== undefined;
  if (hasError && hasResult) {
    return {
      kind: "invalid",
      id,
      detail: "frame carries both result and error",
    };
  }
  if (hasError) {
    const e = m.error;
    if (e === null || typeof e !== "object" || Array.isArray(e)) {
      return {
        kind: "invalid",
        id,
        detail: `error member is ${safe(e, 32)} (${typeof e}), not an object`,
      };
    }
    const eo = e as Record<string, unknown>;
    if (typeof eo.code !== "number") {
      return {
        kind: "invalid",
        id,
        detail: `error.code is ${safe(eo.code, 32)}, not a number`,
      };
    }
    if (typeof eo.message !== "string") {
      return {
        kind: "invalid",
        id,
        detail: `error.message is ${typeof eo.message}, not a string`,
      };
    }
    return { kind: "error", id, code: String(eo.code), message: eo.message };
  }
  if (!hasResult) {
    return {
      kind: "invalid",
      id,
      detail: "frame carries neither a result nor an error member",
    };
  }
  return { kind: "result", id, result: m.result };
}

/**
 * Minimal JSON-RPC 2.0 client over one WebSocket. TrueNAS keys responses by
 * request id, so calls are correlated through a pending-map rather than
 * assuming ordered replies.
 */
class TrueNasRpc {
  #ws: WebSocket;
  #signal: AbortSignal;
  #onProtocolError: (detail: string) => void;
  #safe: Safe;
  #id = 0;
  #pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >();
  #closed = false;

  private constructor(
    ws: WebSocket,
    signal: AbortSignal,
    onProtocolError: (detail: string) => void,
    safe: Safe,
  ) {
    this.#ws = ws;
    this.#signal = signal;
    this.#onProtocolError = onProtocolError;
    this.#safe = safe;
    ws.onmessage = (ev) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(ev.data as string);
      } catch (e) {
        // Previously silently ignored until the pending call timed out.
        // Surface it so a persistently malformed stream is diagnosable.
        this.#onProtocolError(
          `malformed frame: ${this.#safe((e as Error).message)}`,
        );
        return;
      }
      const frame = classifyFrame(parsed, this.#safe);
      if (frame.kind === "notification") return;
      if (frame.kind === "invalid") {
        // Fail the waiting call rather than letting it run out its timeout
        // and report a network problem for a protocol one. With no usable
        // id there is nothing to fail, so it is logged and dropped.
        const waiter = frame.id !== undefined
          ? this.#pending.get(frame.id)
          : undefined;
        if (waiter && frame.id !== undefined) {
          this.#pending.delete(frame.id);
          waiter.reject(
            new Error(
              `TrueNAS sent an invalid JSON-RPC frame: ${frame.detail}`,
            ),
          );
        } else {
          this.#onProtocolError(frame.detail);
        }
        return;
      }
      const waiter = this.#pending.get(frame.id);
      if (!waiter) return;
      this.#pending.delete(frame.id);
      if (frame.kind === "error") {
        // Only the human `message` is surfaced. The `data` object is a
        // middlewared traceback (frames with locals, `formatted`) whose
        // contents are not guaranteed to redact call arguments -- and one
        // call, auth.login_with_api_key, takes the API key as its only
        // argument. Stringifying `data` into an error that can reach a swamp
        // log would risk persisting the key, so it is dropped. A failing call
        // is still identified by its RPC error code + message.
        waiter.reject(
          new Error(
            // `message` is remote free text of unbounded length, and it is
            // the reply to a call that took the API key as its argument, so
            // it is bounded, key-redacted and screened like every other
            // remote string that ends up in an error a caller may log.
            `TrueNAS RPC error ${frame.code}: ${this.#safe(frame.message)}`,
          ),
        );
      } else {
        waiter.resolve(frame.result);
      }
    };
    ws.onclose = () => {
      this.#closed = true;
      for (const [, w] of this.#pending) {
        w.reject(new Error("connection closed before reply"));
      }
      this.#pending.clear();
    };
  }

  static connect(
    wsUrl: string,
    timeoutMs: number,
    signal: AbortSignal,
    safe: Safe,
    onProtocolError: (detail: string) => void = () => {},
  ): Promise<TrueNasRpc> {
    return new Promise((resolve, reject) => {
      // An AbortSignal that is ALREADY aborted before we get here never fires
      // another "abort" event, so the listener registered below would never
      // run. The old code therefore opened the socket for a run that had
      // already been cancelled -- and the very first thing discover() does on
      // a connected socket is send auth.login_with_api_key, i.e. it put the
      // plaintext API key on the wire for work nobody was waiting for, then
      // reported the eventual hang as "timed out connecting" rather than
      // "aborted". Check the flag before anything else, socket included.
      if (signal.aborted) {
        reject(new Error("aborted before connecting"));
        return;
      }
      let settled = false;
      let ws: WebSocket;
      try {
        ws = new WebSocket(wsUrl);
      } catch (e) {
        reject(new Error(`cannot open ${wsUrl}: ${(e as Error).message}`));
        return;
      }
      const cleanup = () => {
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        ws.onopen = null;
        ws.onerror = null;
      };
      const failOnce = (err: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        try {
          ws.close();
        } catch { /* already closing */ }
        reject(err);
      };
      const timer = setTimeout(() => {
        failOnce(new Error(`timed out connecting to ${wsUrl}`));
      }, timeoutMs);
      const onAbort = () => failOnce(new Error("aborted"));
      signal.addEventListener("abort", onAbort, { once: true });
      ws.onopen = () => {
        if (settled) {
          // A late open arriving after we already failed this connection
          // (timeout, abort, or a prior error event) -- close it rather
          // than leaving an authenticated-capable socket open and
          // unreferenced.
          try {
            ws.close();
          } catch { /* already closing */ }
          return;
        }
        settled = true;
        cleanup();
        resolve(new TrueNasRpc(ws, signal, onProtocolError, safe));
      };
      ws.onerror = (ev) => {
        // Surface whatever the runtime actually said. Swallowing it turns
        // every distinct failure -- TLS, DNS, permissions, refused -- into
        // one indistinguishable message.
        const detail = (ev as ErrorEvent)?.message ??
          ((ev as unknown as { error?: Error })?.error?.message) ??
          "(runtime gave no detail)";
        failOnce(
          new Error(`WebSocket error against ${wsUrl}: ${safe(detail)}`),
        );
      };
    });
  }

  call(method: string, params: unknown[], timeoutMs: number): Promise<unknown> {
    if (this.#closed) return Promise.reject(new Error("connection closed"));
    // Same reason as connect(): addEventListener("abort", ...) on a signal
    // that has already aborted never fires, so the old code fell straight
    // through to #ws.send() and wrote the request -- for the auth call, the
    // API key itself -- to a socket belonging to a cancelled run, then sat
    // there for the full timeout waiting on a reply nobody wanted. The abort
    // can land between connect() resolving and this call starting, so the
    // guard has to be here as well, not only in connect().
    if (this.#signal.aborted) {
      return Promise.reject(new Error(`aborted before sending ${method}`));
    }
    const id = ++this.#id;
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(new Error(`aborted waiting for ${method}`));
      };
      const settle = () => {
        clearTimeout(timer);
        this.#signal.removeEventListener("abort", onAbort);
      };
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        this.#signal.removeEventListener("abort", onAbort);
        reject(new Error(`timed out waiting for ${method}`));
      }, timeoutMs);
      this.#pending.set(id, {
        resolve: (v) => {
          settle();
          resolve(v);
        },
        reject: (e) => {
          settle();
          reject(e);
        },
      });
      this.#signal.addEventListener("abort", onAbort, { once: true });
      this.#ws.send(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    });
  }

  close() {
    try {
      this.#ws.close();
    } catch { /* already closing */ }
  }
}

async function discover(_args: unknown, ctx: {
  signal: AbortSignal;
  globalArgs: Record<string, unknown>;
  modelType: string;
  modelId: string;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
    warning: (msg: string, props?: Record<string, unknown>) => void;
  };
  // deno-lint-ignore no-explicit-any
  writeResource: (...a: any[]) => Promise<any>;
  dataRepository: {
    findAllForModel: (
      t: string,
      id: string,
    ) => Promise<Array<{ name: string }>>;
    delete: (t: string, id: string, name: string) => Promise<void>;
  };
}) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  // One boundary for every remote-supplied string in this run: bounded,
  // key-redacted, control/bidi screened. Built here because it needs the key,
  // and threaded rather than duplicated so no site can be missed.
  const safe: Safe = (value, max) => safeRemoteText(value, g.apiKey, max);
  const base = assertBaseUrl(g.baseUrl, g.allowInsecureHttp, g.allowedHosts);
  // Built from the parsed URL's components, not by pasting "/api/current"
  // onto the raw argument. The old concatenation swapped the scheme with a
  // regex and appended blindly, so anything after the host that was not a
  // plain path (a query string, a fragment) ended up in front of the path
  // segment it was supposed to precede. assertBaseUrl now rejects those, and
  // rebuilding here means the endpoint path is correct by construction rather
  // than by the argument happening to be well shaped. A reverse-proxied
  // subpath (https://nas.example.com/truenas/) still resolves.
  const wsScheme = base.protocol === "https:" ? "wss:" : "ws:";
  const basePath = base.pathname.replace(/\/+$/, "");
  const wsUrl = `${wsScheme}//${base.host}${basePath}/api/current`;
  const timeoutMs = g.timeoutSec * 1000;

  // wsUrl is built entirely from operator-supplied config that assertBaseUrl
  // has already stripped of userinfo, query and fragment, so what is logged is
  // scheme + host + path and nothing else. Screened anyway: it costs nothing
  // and keeps "everything that reaches a log line goes through one function"
  // true without exception.
  ctx.logger.info("connecting to {url}", { url: screenRemote(wsUrl) });

  const rpc = await TrueNasRpc.connect(
    wsUrl,
    timeoutMs,
    ctx.signal,
    safe,
    (detail) =>
      ctx.logger.warning("TrueNAS RPC protocol issue: {detail}", { detail }),
  );

  let sysRaw: unknown, poolsRaw: unknown, disksRaw: unknown;
  let alertsRaw: unknown, certsRaw: unknown;
  try {
    // Both auth failure paths carry AUTH_REMOVAL_HINT. The version warning
    // further down only runs after system.info, so it is unreachable on a host
    // where auth.login_with_api_key has been removed -- which is the single
    // case the hint was written for. See the comment on AUTH_REMOVAL_HINT.
    let authed: unknown;
    try {
      authed = await rpc.call(
        "auth.login_with_api_key",
        [g.apiKey],
        timeoutMs,
      );
    } catch (e) {
      const err = e as Error;
      // Not on a cancellation. An aborted run failed for a reason that has
      // nothing to do with the deprecated call, and pointing an operator at
      // TrueNAS 27 when they hit Ctrl-C is worse than saying nothing.
      if (ctx.signal.aborted) throw err;
      throw new Error(`${err.message} ${AUTH_REMOVAL_HINT}`);
    }
    if (authed !== true) {
      throw new Error(
        `TrueNAS rejected the API key. Check it has not been revoked. ${AUTH_REMOVAL_HINT}`,
      );
    }

    // One call per object type over the single authenticated connection.
    // disk.query needs extra.pools: true -- pool joining defaults to false,
    // and without it every disk's `pool` field comes back empty.
    [sysRaw, poolsRaw, disksRaw, alertsRaw, certsRaw] = await Promise.all([
      rpc.call("system.info", [], timeoutMs),
      rpc.call("pool.query", [], timeoutMs),
      rpc.call("disk.query", [[], { extra: { pools: true } }], timeoutMs),
      rpc.call("alert.list", [], timeoutMs),
      rpc.call("certificate.query", [], timeoutMs),
    ]);
  } finally {
    rpc.close();
  }

  // ---- validate every response before writing or pruning anything --------
  // A malformed non-array result used to be silently treated as an empty
  // list, which would then prune every existing resource of that kind on
  // the next step. Throw instead: partial-but-wrong data must never look
  // like "nothing exists any more."
  for (
    const [label, raw] of [
      ["pool.query", poolsRaw],
      ["disk.query", disksRaw],
      ["alert.list", alertsRaw],
      ["certificate.query", certsRaw],
    ] as const
  ) {
    if (!Array.isArray(raw)) {
      // The type is the diagnostic fact; the payload is a bounded preview.
      // This used to stringify the entire unexpected response into the
      // message, which put an unbounded amount of remote text -- hostnames,
      // share paths, alert prose -- into whatever log caught the throw.
      throw new Error(
        `TrueNAS ${label} returned a non-array result (${typeof raw}): ${
          safe(raw)
        }`,
      );
    }
  }

  const sys = RawSystemSchema.parse(sysRaw ?? {});
  const pools = z.array(RawPoolSchema).parse(poolsRaw);
  const disks = z.array(RawDiskSchema).parse(disksRaw);
  const alerts = z.array(RawAlertSchema).parse(alertsRaw);
  const certs = z.array(RawCertificateSchema).parse(certsRaw);

  warnIfVersionUnsupported(sys.version, ctx.logger, safe);

  const handles = [];
  const live = new Set<string>();

  // ---- system -------------------------------------------------------------
  // `?? 0` here wrote a real-looking number for a field TrueNAS never sent.
  // uptimeSeconds was the sharp one: 0 is the value a box that just rebooted
  // reports, so a "rebooted recently" gate fired on every run where the field
  // was simply absent. UNKNOWN_NUMBER + metricsKnown separates the two.
  const metricsKnown = sys.cores != null && sys.physmem != null &&
    sys.uptime_seconds != null;
  handles.push(
    await ctx.writeResource("system", "system", {
      hostname: safe(sys.hostname, 128),
      version: safe(sys.version, 64),
      model: sys.model == null ? "unknown" : safe(sys.model, 128),
      cores: sys.cores ?? UNKNOWN_NUMBER,
      physmemBytes: sys.physmem ?? UNKNOWN_NUMBER,
      uptimeSeconds: sys.uptime_seconds ?? UNKNOWN_NUMBER,
      // An absent loadavg stays []. Unlike a number, an empty array is not
      // mistakable for a reading: there is no element to compare against.
      loadavg: sys.loadavg ?? [],
      metricsKnown,
    }, {
      tags: {
        // A tag is a selector, so a bidi override or an ESC sequence in a
        // hostname is worse here than in a field: it changes what the operator
        // believes they are selecting.
        hostname: safe(sys.hostname, 128),
        metricsKnown: String(metricsKnown),
      },
    }),
  );
  live.add("system");

  // ---- pools --------------------------------------------------------------
  let poolsUnhealthy = 0;
  let poolsCapacityUnknown = 0;
  for (const [i, p] of pools.entries()) {
    // The worst instance of the `?? 0` class. A pool reporting neither
    // `allocated` nor `free` was written sizeBytes: 0, usedPercent: 0, and
    // `usedPercent > 90` then read as "plenty of room" on a pool whose fill
    // level was in fact unknown. Both fields are needed for either number to
    // mean anything, so they are known together or not at all.
    const capacityKnown = p.allocated != null && p.free != null;
    if (!capacityKnown) poolsCapacityUnknown++;
    const allocated = capacityKnown ? p.allocated! : UNKNOWN_NUMBER;
    const free = capacityKnown ? p.free! : UNKNOWN_NUMBER;
    const size = capacityKnown ? allocated + free : UNKNOWN_NUMBER;
    // `healthy: null` (the key is present -- RawPoolSchema now requires that
    // much -- but carries no value) is treated as NOT healthy on purpose. For
    // capacity, guessing benign is the danger, so an unknown capacity gets a
    // sentinel; for a HEALTH field the safe direction is inverted. An
    // unreadable health is not a healthy pool, and erring toward "unhealthy"
    // produces a visible alert an operator resolves, where erring toward
    // "healthy" produces silence over a degraded array.
    const healthy = p.healthy === true;
    if (!healthy) poolsUnhealthy++;
    const name = await instanceName(
      "pool",
      p.name,
      String(p.id ?? ""),
      p.name ? "" : `idx${i}`,
    );
    live.add(name);
    handles.push(
      await ctx.writeResource("pool", name, {
        name: safe(p.name, 128),
        status: p.status == null ? "UNKNOWN" : safe(p.status, 64),
        healthy,
        allocatedBytes: allocated,
        freeBytes: free,
        sizeBytes: size,
        usedPercent: !capacityKnown
          ? UNKNOWN_NUMBER
          : size > 0
          ? Math.round((allocated / size) * 1000) / 10
          : 0,
        // parsePercent still defaults an ABSENT fragmentation to 0, and that
        // stays: unlike capacity, 0% fragmentation is not itself an alarming
        // value, so a gate reading it cannot be lulled the way a capacity
        // gate could. Argued rather than swept in with the rest of the class.
        // A MALFORMED or out-of-range fragmentation is a different fact and
        // now throws rather than reporting the same reassuring 0.
        fragmentationPercent: parsePercent(p.fragmentation ?? null, safe),
        capacityKnown,
      }, {
        tags: {
          healthy: String(healthy),
          status: p.status == null ? "" : safe(p.status, 64),
          capacityKnown: String(capacityKnown),
        },
      }),
    );
  }

  // ---- disks --------------------------------------------------------------
  for (const [i, d] of disks.entries()) {
    // Same class as the pool capacity above: a disk whose `size` TrueNAS did
    // not report was written sizeBytes: 0, which reads as a real (and absurd)
    // capacity rather than as an absent one.
    const sizeKnown = d.size != null;
    // Absent key vs. present-and-null, kept apart. `d.pool ?? "none"` said
    // "this disk belongs to no pool" for both, and only one of them means
    // that: the other means the extra.pools join did not happen, in which
    // case EVERY disk on the box claims to be orphaned. See `poolKnown`.
    const poolKnown = d.pool !== undefined;
    const rawId = d.identifier ?? d.devname ?? "";
    const name = await instanceName(
      "disk",
      rawId,
      d.serial ?? "",
      rawId ? "" : `idx${i}`,
    );
    live.add(name);
    handles.push(
      await ctx.writeResource("disk", name, {
        name: d.devname == null ? "" : safe(d.devname, 128),
        serial: d.serial == null ? "" : safe(d.serial, 128),
        model: d.model == null ? "" : safe(d.model, 128),
        sizeBytes: sizeKnown ? d.size! : UNKNOWN_NUMBER,
        type: d.type == null ? "" : safe(d.type, 64),
        pool: d.pool == null ? "" : safe(d.pool, 128),
        sizeKnown,
        poolKnown,
      }, {
        tags: {
          pool: !poolKnown
            ? "unknown"
            : d.pool == null
            ? "none"
            : safe(d.pool, 128),
          type: d.type == null ? "" : safe(d.type, 64),
          sizeKnown: String(sizeKnown),
          poolKnown: String(poolKnown),
        },
      }),
    );
  }

  // ---- alerts -------------------------------------------------------------
  let silenced = 0;
  for (const [i, a] of alerts.entries()) {
    const dismissed = Boolean(a.dismissed);
    if (dismissed) silenced++;
    const rawId = a.uuid ?? (a.id !== undefined ? String(a.id) : undefined) ??
      a.key ?? "";
    const name = await instanceName(
      "alert",
      rawId,
      a.klass ?? "",
      rawId ? "" : `idx${i}`,
    );
    live.add(name);
    handles.push(
      await ctx.writeResource("alert", name, {
        id: safe(rawId, 128),
        klass: a.klass == null ? "" : safe(a.klass, 128),
        level: a.level == null ? "" : safe(a.level, 64),
        // The one stored field that is entirely remote prose. Kept in full
        // (up to 4 KB) rather than dropped or redacted -- an alert you cannot
        // read is an alert you cannot act on, and the disclosure this carries
        // is stated in the README Security section rather than papered over.
        // What is removed is the ability of that prose to be unbounded in an
        // infinite-lifetime record, to carry the API key back to us, or to
        // drive the terminal of whoever runs `swamp data list`.
        formatted: a.formatted == null
          ? ""
          : safe(a.formatted, MAX_STORED_REMOTE_CHARS),
        dismissed,
        // A dismissed alert is hidden in the TrueNAS UI but the condition
        // behind it is still true. Surface it rather than inherit the
        // dismissal.
        silenced: dismissed,
      }, {
        tags: {
          level: a.level == null ? "" : safe(a.level, 64),
          klass: a.klass == null ? "" : safe(a.klass, 128),
          silenced: String(dismissed),
        },
      }),
    );
  }

  // ---- certificates -------------------------------------------------------
  let expiringSoon = 0, expired = 0, withoutExpiry = 0;
  for (const [i, c] of certs.entries()) {
    // `c.until ?? c.not_after` rather than `c.until ?? c.not_after ?? ""`:
    // toIsoOrNull() distinguishes "no expiry" (null) from "present but
    // unreadable" (throws), and collapsing both to "" here would put the
    // distinction back.
    const notAfter = toIsoOrNull(
      c.until !== undefined ? c.until : c.not_after,
      safe,
    );
    const days = notAfter === null ? Number.NaN : daysUntil(notAfter);
    const isExpired = Number.isFinite(days) && days < 0;
    const soon = Number.isFinite(days) && days >= 0 && days <= g.certWarnDays;
    if (isExpired) expired++;
    if (soon) expiringSoon++;
    if (!Number.isFinite(days)) withoutExpiry++;
    const rawId = String(c.id ?? c.name ?? "");
    // Prefix is `cert-` while the resource kind is `certificate`. Reviewed and
    // kept: the instance name is the record's identity in the datastore, so
    // renaming the prefix orphans every stored certificate record -- the next
    // run prunes all of them and writes new ones, losing their history -- to
    // buy nothing but a tidier spelling. The prefix is documented in the
    // README instead. (Note the prune protection above keys on `pool-`/`disk-`
    // for the same reason: prefixes here are load-bearing, not cosmetic.)
    const name = await instanceName(
      "cert",
      rawId,
      c.common ?? c.common_name ?? "",
      rawId ? "" : `idx${i}`,
    );
    const commonName = c.common ?? c.common_name ?? "";
    live.add(name);
    handles.push(
      await ctx.writeResource("certificate", name, {
        name: c.name == null ? "" : safe(c.name, 128),
        commonName: safe(commonName, 253),
        notAfter: notAfter ?? "",
        daysRemaining: Number.isFinite(days) ? days : -9999,
        expiryKnown: Number.isFinite(days),
        expiringSoon: soon,
        expired: isExpired,
      }, {
        tags: {
          expiringSoon: String(soon),
          expired: String(isExpired),
          expiryKnown: String(Number.isFinite(days)),
        },
      }),
    );
  }

  // ---- summary ------------------------------------------------------------
  // An empty pool.query or disk.query is reported as such, unconditionally,
  // instead of rolling up as "0 pools, 0 of them unhealthy" -- which is what
  // a perfectly healthy NAS with nothing wrong also looks like. See
  // SummarySchema.discoveryDegraded for why this flags rather than throws.
  const poolsReportedEmpty = pools.length === 0;
  const disksReportedEmpty = disks.length === 0;
  const discoveryDegraded = poolsReportedEmpty || disksReportedEmpty;
  handles.push(
    await ctx.writeResource("summary", "summary", {
      hostname: safe(sys.hostname, 128),
      version: safe(sys.version, 64),
      pools: pools.length,
      poolsUnhealthy,
      poolsCapacityUnknown,
      disks: disks.length,
      alerts: alerts.length,
      alertsSilenced: silenced,
      certificates: certs.length,
      certificatesExpiringSoon: expiringSoon,
      certificatesExpired: expired,
      certificatesWithoutExpiry: withoutExpiry,
      poolsReportedEmpty,
      disksReportedEmpty,
      discoveryDegraded,
      syncedAt: new Date().toISOString(),
    }, {
      tags: {
        poolsUnhealthy: String(poolsUnhealthy),
        poolsCapacityUnknown: String(poolsCapacityUnknown),
        certsExpiring: String(expiringSoon),
        discoveryDegraded: String(discoveryDegraded),
      },
    }),
  );
  live.add("summary");

  // Prune anything the box no longer reports, resolved alerts especially.
  // This uses dataRepository.findAllForModel/delete directly rather than
  // context.readResource because readResource addresses one named instance.
  // There is no "list every stored instance for this model" call in the
  // readResource surface, and bulk stale-resource pruning genuinely needs
  // one. This mirrors @swamp/ssh's own `apply` method (see
  // .swamp/pulled-extensions/@swamp/ssh/models/_lib/operations.ts), which
  // prunes stale host-* resources the identical way.
  //
  // A kind that came back COMPLETELY empty is not evidence that the kind is
  // gone, and the validation above cannot tell the two apart: `[]` is a
  // well-formed array, so it passes and no name of that kind enters `live`.
  // pool.query answers `[]` while ZFS is still importing after a reboot or
  // update, and while a pool is failing to import at all; disk.query
  // answering `[]` has no legitimate steady state on a NAS. The old code
  // took that single empty response as authoritative and hard-deleted every
  // stored pool-*/disk-* record in one pass, during exactly the window a
  // pool is missing. Protect those two prefixes when the kind is empty but
  // the datastore still holds records for it, the way netdata.ts protects a
  // node whose sub-fetch failed. Alerts and certificates are deliberately
  // NOT protected: an empty alert list is the normal healthy state and a
  // resolved alert must be pruned or it is reported forever.
  const protectedPrefixes: string[] = [];
  if (poolsReportedEmpty) protectedPrefixes.push("pool-");
  if (disksReportedEmpty) protectedPrefixes.push("disk-");

  const existing = await ctx.dataRepository.findAllForModel(
    ctx.modelType,
    ctx.modelId,
  );
  let keptStale = 0;
  for (const rec of existing) {
    if (live.has(rec.name)) continue;
    if (protectedPrefixes.some((p) => rec.name.startsWith(p))) {
      keptStale++;
      continue;
    }
    await ctx.dataRepository.delete(ctx.modelType, ctx.modelId, rec.name);
    ctx.logger.info("pruned {name}", { name: rec.name });
  }
  // Warned on the EMPTY RESPONSE, not on having kept something. The old
  // `if (keptStale > 0)` made the warning conditional on prior state, so the
  // single run where it matters most -- a first run, or the first run after a
  // datastore reset, where no stale record exists to keep -- discovered
  // nothing and said nothing at all, and the summary underneath it read as a
  // clean bill of health. The kept-record sentence is now the part that is
  // conditional.
  if (discoveryDegraded) {
    ctx.logger.warning(
      "TrueNAS reported {pools} pool(s) and {disks} disk(s). An empty pool " +
        "or disk list is not a steady state on a NAS: it is what a pool " +
        "still importing (or failing to import) after a reboot looks like. " +
        "summary.discoveryDegraded is true for this run, so gate on that " +
        "rather than on the counts. Kept {kept} existing record(s) rather " +
        "than deleting them. Once any object of that kind is reported again, " +
        "records that really did go away are pruned on that run; if the last " +
        "pool or disk was genuinely removed, delete the stale record by hand.",
      { pools: pools.length, disks: disks.length, kept: keptStale },
    );
  }

  ctx.logger.info(
    "discovered {pools} pool(s), {disks} disk(s), {alerts} alert(s) " +
      "({silenced} silenced), {certs} certificate(s)",
    {
      pools: pools.length,
      disks: disks.length,
      alerts: alerts.length,
      silenced,
      certs: certs.length,
    },
  );

  return { dataHandles: handles };
}

/**
 * Test-only surface. Not part of the model contract, not addressed by any
 * workflow, and not referenced anywhere inside this file.
 *
 * It exists because several of the properties this module now guarantees are
 * invisible from `model` alone -- that the raw schemas STRIP undeclared keys
 * instead of retaining them, that two identity tuples differing only by a
 * control character get different digests, that a malformed JSON-RPC frame is
 * classified rather than cast. A fix nobody can observe is a fix that ships
 * dead, which has happened in this repo often enough to be the rule these
 * exports exist to break.
 */
export const __testOnly = {
  RawSystemSchema,
  RawPoolSchema,
  RawDiskSchema,
  RawAlertSchema,
  RawCertificateSchema,
  classifyFrame,
  encodeIdentity,
  instanceName,
  parsePercent,
  safeRemoteText,
  toIsoOrNull,
};

/**
 * The `@jpisgeek/truenas` model definition: a single `discover` method
 * producing five read-only resource types (system, pool, disk, alert,
 * certificate) plus a `summary` roll-up. See the module header above for
 * the JSON-RPC migration story and why certificate expiry is tracked
 * independently of TrueNAS's own alert state, which a dismissal can hide.
 */
export const model = {
  type: "@jpisgeek/truenas",
  version: "2026.08.23.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    system: {
      description:
        "Host identity, version, CPU, memory, uptime, load. `metricsKnown` " +
        "is false when TrueNAS omitted cores/memory/uptime; those read -1 " +
        "rather than 0 so an absent uptime cannot look like a fresh reboot.",
      schema: SystemSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    pool: {
      description: "One record per ZFS pool with status, health, capacity, " +
        "fragmentation. Check `capacityKnown` before gating on capacity: " +
        "when TrueNAS reports no allocated/free the four capacity fields are " +
        "-1, not 0, so an unknown pool cannot read as an empty one.",
      schema: PoolSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    disk: {
      description:
        "One record per physical disk and its pool membership. `sizeKnown` " +
        "is false when TrueNAS reported no size; `sizeBytes` is then -1. " +
        "`poolKnown` is false when TrueNAS did not answer the pool-membership " +
        "question at all, which is a different fact from a disk that is in " +
        "no pool; the tag reads `unknown` there, never `none`.",
      schema: DiskSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    alert: {
      description:
        "One record per active TrueNAS alert. `silenced` marks alerts that " +
        "were dismissed in the UI. Still true, just no longer visible there.",
      schema: AlertSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    certificate: {
      description: "One record per certificate with days remaining, tracked " +
        "independently of TrueNAS alert state so a dismissed expiry warning " +
        "cannot hide a cert that is about to lapse.",
      schema: CertificateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    summary: {
      description: "Single roll-up of the most recent discover. Gate on " +
        "`discoveryDegraded` before trusting the counts: it is true when " +
        "pool.query or disk.query came back empty, which is what an " +
        "importing pool looks like and is indistinguishable from a healthy " +
        "box by the counts alone.",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  methods: {
    discover: {
      description:
        "Read-only sweep of system info, pools, disks, alerts, and " +
        "certificates in one pass. Writes one resource per object plus a " +
        "summary, and prunes objects the box no longer reports. All or " +
        "nothing: the five sub-fetches are issued together and any failure " +
        "or contract violation among them aborts the whole run before " +
        "anything is written or pruned.",
      arguments: DiscoverArgsSchema,
      execute: discover,
    },
  },
};
