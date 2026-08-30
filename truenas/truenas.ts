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
  timeoutSec: z.number().int().positive().default(20),
  certWarnDays: z
    .number()
    .int()
    .positive()
    .default(30)
    .describe("Certificates expiring within this many days are flagged"),
});

/**
 * Bound a remote-supplied value before it is interpolated into an error
 * message or a log line.
 *
 * Everything on the far side of this socket is remote text: RPC error
 * messages, an unexpected result payload, whatever string a runtime puts on a
 * WebSocket error event. The non-array guard below used to paste a whole
 * `JSON.stringify(raw)` into the thrown error verbatim, which is unbounded and
 * carries whatever hostnames, share paths or alert prose the payload happened
 * to hold straight into swamp's logs.
 *
 * This truncates, it does not redact. The leading text is what makes a failure
 * diagnosable and blanking it would hand an operator an error that says
 * nothing. The defect being fixed is the *unbounded* part, not the presence of
 * remote text.
 */
function preview(value: unknown, max = 200): string {
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
  return s.length <= max
    ? s
    : `${s.slice(0, max)}… (${s.length} chars, truncated)`;
}

/**
 * Runtime validation of baseUrl. Deliberately NOT an object-level zod
 * refinement: swamp calls .partial() on globalArguments, and zod 4 refuses
 * that on an object carrying refinements -- a superRefine here made every
 * discover() fail before it connected.
 *
 * Returns the parsed URL so the caller builds the WebSocket URL from its
 * components instead of pasting strings onto the raw argument.
 */
function assertBaseUrl(baseUrl: string, allowInsecureHttp: boolean): URL {
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
  return u;
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
  syncedAt: z.string(),
});

/**
 * Raw TrueNAS response shapes for the fields this model actually reads.
 * `.passthrough()` here is correct and intentional. Unlike the resource
 * schemas above (which gate CEL and must be strict), these validate an
 * untrusted third-party payload where extra fields we don't use are
 * expected and harmless. What matters is that the fields we *do* rely on
 * are actually present and typed as expected. If TrueNAS's contract has
 * drifted, `.parse()` throws here instead of the mapping code silently
 * writing placeholder 0/""/[] values as if they were real data.
 */
const RawSystemSchema = z.object({
  hostname: z.string(),
  version: z.string(),
  model: z.string().nullable().optional(),
  cores: z.number().nullable().optional(),
  physmem: z.number().nullable().optional(),
  uptime_seconds: z.number().nullable().optional(),
  loadavg: z.array(z.number()).nullable().optional(),
}).passthrough();

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
}).passthrough();

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
  // Only populated when disk.query is called with extra.pools: true.
  pool: z.string().nullable().optional(),
}).passthrough().refine(
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
}).passthrough().refine(
  // Same index-fallback churn as disks, and worse here: alert-* records are
  // pruned on absence by design, so unstable names mean every run deletes
  // and re-adds the whole alert set.
  (a) => a.uuid != null || a.id != null || a.key != null,
  {
    message:
      "alert.list row has none of `uuid`, `id`, `key`; the TrueNAS alert " +
      "contract has changed and alerts can no longer be identified",
  },
);

const RawCertificateSchema = z.object({
  id: z.union([z.string(), z.number()]).optional(),
  name: z.string().nullable().optional(),
  common: z.string().nullable().optional(),
  common_name: z.string().nullable().optional(),
  until: z.unknown().optional(),
  not_after: z.unknown().optional(),
}).passthrough().refine(
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
function instanceName(prefix: string, ...identity: string[]): string {
  // Unit Separator, written as an escape rather than a raw control byte.
  // The join separator must be a character that cannot occur inside an
  // identifier, or ["a","b c"] and ["a b","c"] hash identically. truenas
  // previously used a RAW NUL here, which achieved that but made the file
  // read as binary to grep and to any tool doing exact-text matching.
  const raw = identity.join("\u001f");
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
  const label = parts.length ? parts.join("-").slice(0, 48) : "unnamed";
  return `${prefix}-${label}-${shortHash(raw)}`;
}

/** TrueNAS reports pool fragmentation as a nullable percentage, sometimes
 * with a trailing "%". 0 is used when TrueNAS reports none -- a benign
 * "nothing to report" default here, unlike a missing certificate expiry,
 * since 0% fragmentation is never itself an alarming value. */
function parsePercent(value: string | number | null | undefined): number {
  if (value === null || value === undefined) return 0;
  if (typeof value === "number") return value;
  const n = Number(value.replace(/%\s*$/, "").trim());
  return Number.isFinite(n) ? n : 0;
}

function daysUntil(iso: string): number {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return Number.NaN;
  return Math.floor((then - Date.now()) / 86_400_000);
}

/** TrueNAS returns dates in several shapes; normalize to an ISO string. */
function toIso(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number") return new Date(value).toISOString();
  if (value && typeof value === "object") {
    const d = (value as Record<string, unknown>)["$date"];
    if (typeof d === "number") return new Date(d).toISOString();
    if (typeof d === "string") return d;
  }
  return "";
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
      { version: preview(version, 64) },
    );
  }
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
  ) {
    this.#ws = ws;
    this.#signal = signal;
    this.#onProtocolError = onProtocolError;
    ws.onmessage = (ev) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(ev.data as string);
      } catch (e) {
        // Previously silently ignored until the pending call timed out.
        // Surface it so a persistently malformed stream is diagnosable.
        this.#onProtocolError(
          `malformed frame: ${preview((e as Error).message)}`,
        );
        return;
      }
      const id = msg.id as number | undefined;
      if (id === undefined) return;
      const waiter = this.#pending.get(id);
      if (!waiter) return;
      this.#pending.delete(id);
      if (msg.error) {
        const e = msg.error as Record<string, unknown>;
        const code = e.code !== undefined ? String(e.code) : "?";
        // Only the human `message` is surfaced. The `data` object is a
        // middlewared traceback (frames with locals, `formatted`) whose
        // contents are not guaranteed to redact call arguments -- and one
        // call, auth.login_with_api_key, takes the API key as its only
        // argument. Stringifying `data` into an error that can reach a swamp
        // log would risk persisting the key, so it is dropped. A failing call
        // is still identified by its RPC error code + message.
        waiter.reject(
          new Error(
            // `message` is remote free text of unbounded length, so it goes
            // through preview() like every other remote string that ends up
            // in an error a caller may log.
            `TrueNAS RPC error ${code}: ${
              preview(String(e.message ?? "(no message)"))
            }`,
          ),
        );
      } else {
        waiter.resolve(msg.result);
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
        resolve(new TrueNasRpc(ws, signal, onProtocolError));
      };
      ws.onerror = (ev) => {
        // Surface whatever the runtime actually said. Swallowing it turns
        // every distinct failure -- TLS, DNS, permissions, refused -- into
        // one indistinguishable message.
        const detail = (ev as ErrorEvent)?.message ??
          ((ev as unknown as { error?: Error })?.error?.message) ??
          "(runtime gave no detail)";
        failOnce(
          new Error(`WebSocket error against ${wsUrl}: ${preview(detail)}`),
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
  const base = assertBaseUrl(g.baseUrl, g.allowInsecureHttp);
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

  ctx.logger.info("connecting to {url}", { url: wsUrl });

  const rpc = await TrueNasRpc.connect(
    wsUrl,
    timeoutMs,
    ctx.signal,
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
          preview(raw)
        }`,
      );
    }
  }

  const sys = RawSystemSchema.parse(sysRaw ?? {});
  const pools = z.array(RawPoolSchema).parse(poolsRaw);
  const disks = z.array(RawDiskSchema).parse(disksRaw);
  const alerts = z.array(RawAlertSchema).parse(alertsRaw);
  const certs = z.array(RawCertificateSchema).parse(certsRaw);

  warnIfVersionUnsupported(sys.version, ctx.logger);

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
      hostname: sys.hostname,
      version: sys.version,
      model: sys.model ?? "unknown",
      cores: sys.cores ?? UNKNOWN_NUMBER,
      physmemBytes: sys.physmem ?? UNKNOWN_NUMBER,
      uptimeSeconds: sys.uptime_seconds ?? UNKNOWN_NUMBER,
      // An absent loadavg stays []. Unlike a number, an empty array is not
      // mistakable for a reading: there is no element to compare against.
      loadavg: sys.loadavg ?? [],
      metricsKnown,
    }, {
      tags: {
        hostname: sys.hostname,
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
    const healthy = Boolean(p.healthy);
    if (!healthy) poolsUnhealthy++;
    const name = instanceName(
      "pool",
      p.name,
      String(p.id ?? ""),
      p.name ? "" : `idx${i}`,
    );
    live.add(name);
    handles.push(
      await ctx.writeResource("pool", name, {
        name: p.name,
        status: p.status ?? "UNKNOWN",
        healthy,
        allocatedBytes: allocated,
        freeBytes: free,
        sizeBytes: size,
        usedPercent: !capacityKnown
          ? UNKNOWN_NUMBER
          : size > 0
          ? Math.round((allocated / size) * 1000) / 10
          : 0,
        // parsePercent still defaults an absent fragmentation to 0, and that
        // stays: unlike capacity, 0% fragmentation is not itself an alarming
        // value, so a gate reading it cannot be lulled the way a capacity
        // gate could. Argued rather than swept in with the rest of the class.
        fragmentationPercent: parsePercent(p.fragmentation ?? null),
        capacityKnown,
      }, {
        tags: {
          healthy: String(healthy),
          status: p.status ?? "",
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
    const rawId = d.identifier ?? d.devname ?? "";
    const name = instanceName(
      "disk",
      rawId,
      d.serial ?? "",
      rawId ? "" : `idx${i}`,
    );
    live.add(name);
    handles.push(
      await ctx.writeResource("disk", name, {
        name: d.devname ?? "",
        serial: d.serial ?? "",
        model: d.model ?? "",
        sizeBytes: sizeKnown ? d.size! : UNKNOWN_NUMBER,
        type: d.type ?? "",
        pool: d.pool ?? "",
        sizeKnown,
      }, {
        tags: {
          pool: d.pool ?? "none",
          type: d.type ?? "",
          sizeKnown: String(sizeKnown),
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
    const name = instanceName(
      "alert",
      rawId,
      a.klass ?? "",
      rawId ? "" : `idx${i}`,
    );
    live.add(name);
    handles.push(
      await ctx.writeResource("alert", name, {
        id: rawId,
        klass: a.klass ?? "",
        level: a.level ?? "",
        formatted: a.formatted ?? "",
        dismissed,
        // A dismissed alert is hidden in the TrueNAS UI but the condition
        // behind it is still true. Surface it rather than inherit the
        // dismissal.
        silenced: dismissed,
      }, {
        tags: {
          level: a.level ?? "",
          klass: a.klass ?? "",
          silenced: String(dismissed),
        },
      }),
    );
  }

  // ---- certificates -------------------------------------------------------
  let expiringSoon = 0, expired = 0, withoutExpiry = 0;
  for (const [i, c] of certs.entries()) {
    const notAfter = toIso(c.until ?? c.not_after ?? "");
    const days = notAfter ? daysUntil(notAfter) : Number.NaN;
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
    const name = instanceName(
      "cert",
      rawId,
      c.common ?? c.common_name ?? "",
      rawId ? "" : `idx${i}`,
    );
    live.add(name);
    handles.push(
      await ctx.writeResource("certificate", name, {
        name: c.name ?? "",
        commonName: c.common ?? c.common_name ?? "",
        notAfter,
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
  handles.push(
    await ctx.writeResource("summary", "summary", {
      hostname: sys.hostname,
      version: sys.version,
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
      syncedAt: new Date().toISOString(),
    }, {
      tags: {
        poolsUnhealthy: String(poolsUnhealthy),
        poolsCapacityUnknown: String(poolsCapacityUnknown),
        certsExpiring: String(expiringSoon),
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
  if (pools.length === 0) protectedPrefixes.push("pool-");
  if (disks.length === 0) protectedPrefixes.push("disk-");

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
  if (keptStale > 0) {
    ctx.logger.warning(
      "TrueNAS reported zero pools and/or zero disks, which is what a pool " +
        "still importing (or failing to import) looks like. Kept {kept} " +
        "existing record(s) rather than deleting them. Note the summary " +
        "resource still reports what the box actually said this run. Once " +
        "any object of that kind is reported again, records that really did " +
        "go away are pruned on that run; if the last pool or disk was " +
        "genuinely removed, delete the stale record by hand.",
      { kept: keptStale },
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
        "is false when TrueNAS reported no size; `sizeBytes` is then -1.",
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
      description: "Single roll-up of the most recent discover.",
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
        "summary, and prunes objects the box no longer reports.",
      arguments: DiscoverArgsSchema,
      execute: discover,
    },
  },
};
