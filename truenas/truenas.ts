/**
 * TrueNAS SCALE inventory and health, over the REST API v2.0.
 *
 * Built in-house rather than pulling a community extension: this model holds a
 * TrueNAS API key at runtime, and the decision was to keep that inside code we
 * control. It is deliberately narrow — read-only discovery of the things a
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
        "WebSocket URL is derived from this (https -> wss, /api/current).",
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
 * Runtime validation of baseUrl. Deliberately NOT an object-level zod
 * refinement: swamp calls .partial() on globalArguments, and zod 4 refuses
 * that on an object carrying refinements -- a superRefine here made every
 * discover() fail before it connected.
 */
function assertBaseUrl(baseUrl: string, allowInsecureHttp: boolean): void {
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
}

const DiscoverArgsSchema = z.object({});

const SystemSchema = z.object({
  hostname: z.string(),
  version: z.string(),
  model: z.string(),
  cores: z.number(),
  physmemBytes: z.number(),
  uptimeSeconds: z.number(),
  loadavg: z.array(z.number()),
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
});

const DiskSchema = z.object({
  name: z.string(),
  serial: z.string(),
  model: z.string(),
  sizeBytes: z.number(),
  type: z.string(),
  pool: z.string(),
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
   * False for objects with no expiry at all — a CSR, for instance. Without
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
 * `.passthrough()` here is correct and intentional — unlike the resource
 * schemas above (which gate CEL and must be strict), these validate an
 * untrusted third-party payload where extra fields we don't use are
 * expected and harmless. What matters is that the fields we *do* rely on
 * are actually present and typed as expected; if TrueNAS's contract has
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

const RawDiskSchema = z.object({
  devname: z.string().nullable().optional(),
  identifier: z.string().nullable().optional(),
  serial: z.string().nullable().optional(),
  model: z.string().nullable().optional(),
  size: z.number().nullable().optional(),
  type: z.string().nullable().optional(),
  // Only populated when disk.query is called with extra.pools: true.
  pool: z.string().nullable().optional(),
}).passthrough();

const RawAlertSchema = z.object({
  uuid: z.string().optional(),
  id: z.union([z.string(), z.number()]).optional(),
  key: z.string().optional(),
  klass: z.string().nullable().optional(),
  level: z.string().nullable().optional(),
  formatted: z.string().nullable().optional(),
  dismissed: z.boolean().nullable().optional(),
}).passthrough();

const RawCertificateSchema = z.object({
  id: z.union([z.string(), z.number()]).optional(),
  name: z.string().nullable().optional(),
  common: z.string().nullable().optional(),
  common_name: z.string().nullable().optional(),
  until: z.unknown().optional(),
  not_after: z.unknown().optional(),
}).passthrough();

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
  // Capped so an unusually long identity cannot produce an unbounded name; the
  // hash still covers the full raw identity, so uniqueness never depends on
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
 * TrueNAS 27; `auth.login_ex` with the API_KEY_PLAIN mechanism is the
 * replacement, but it also requires a `username`, which this model does
 * not currently collect. Rather than guess at an untested auth path against
 * infrastructure this review has no access to, this caps support
 * explicitly: warn loudly once the connected host is running a version
 * where the call is expected to be gone, so the failure is diagnosable
 * instead of a bare RPC error.
 */
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
        "scheduled for removal starting with 27 and this model has not " +
        "moved to auth.login_ex. If authentication just failed, this is " +
        "likely why.",
      { version },
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
          `malformed frame: ${(e as Error).message}`,
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
        // log would risk persisting the key, so it is dropped; a failing call
        // is still identified by its RPC error code + message.
        waiter.reject(
          new Error(
            `TrueNAS RPC error ${code}: ${String(e.message ?? "(no message)")}`,
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
          new Error(`WebSocket error against ${wsUrl}: ${detail}`),
        );
      };
    });
  }

  call(method: string, params: unknown[], timeoutMs: number): Promise<unknown> {
    if (this.#closed) return Promise.reject(new Error("connection closed"));
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
  assertBaseUrl(g.baseUrl, g.allowInsecureHttp);
  const wsUrl = g.baseUrl.replace(/\/+$/, "").replace(/^http/i, "ws") +
    "/api/current";
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
    const authed = await rpc.call(
      "auth.login_with_api_key",
      [g.apiKey],
      timeoutMs,
    );
    if (authed !== true) {
      throw new Error(
        "TrueNAS rejected the API key. Check it has not been revoked.",
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
      throw new Error(
        `TrueNAS ${label} returned a non-array result: ${JSON.stringify(raw)}`,
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
  const uptimeSeconds = sys.uptime_seconds ?? 0;
  handles.push(
    await ctx.writeResource("system", "system", {
      hostname: sys.hostname,
      version: sys.version,
      model: sys.model ?? "unknown",
      cores: sys.cores ?? 0,
      physmemBytes: sys.physmem ?? 0,
      uptimeSeconds,
      loadavg: sys.loadavg ?? [],
    }, { tags: { hostname: sys.hostname } }),
  );
  live.add("system");

  // ---- pools --------------------------------------------------------------
  let poolsUnhealthy = 0;
  for (const [i, p] of pools.entries()) {
    const allocated = p.allocated ?? 0;
    const free = p.free ?? 0;
    const size = allocated + free;
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
        usedPercent: size > 0 ? Math.round((allocated / size) * 1000) / 10 : 0,
        fragmentationPercent: parsePercent(p.fragmentation ?? null),
      }, {
        tags: { healthy: String(healthy), status: p.status ?? "" },
      }),
    );
  }

  // ---- disks --------------------------------------------------------------
  for (const [i, d] of disks.entries()) {
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
        sizeBytes: d.size ?? 0,
        type: d.type ?? "",
        pool: d.pool ?? "",
      }, {
        tags: { pool: d.pool ?? "none", type: d.type ?? "" },
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
        certsExpiring: String(expiringSoon),
      },
    }),
  );
  live.add("summary");

  // Prune anything the box no longer reports — resolved alerts especially.
  // This uses dataRepository.findAllForModel/delete directly rather than
  // context.readResource because readResource addresses one named instance;
  // there is no "list every stored instance for this model" call in the
  // readResource surface, and bulk stale-resource pruning genuinely needs
  // one. This mirrors @swamp/ssh's own `apply` method (see
  // .swamp/pulled-extensions/@swamp/ssh/models/_lib/operations.ts), which
  // prunes stale host-* resources the identical way.
  const existing = await ctx.dataRepository.findAllForModel(
    ctx.modelType,
    ctx.modelId,
  );
  for (const rec of existing) {
    if (!live.has(rec.name)) {
      await ctx.dataRepository.delete(ctx.modelType, ctx.modelId, rec.name);
      ctx.logger.info("pruned {name}", { name: rec.name });
    }
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
      description: "Host identity, version, CPU, memory, uptime, load.",
      schema: SystemSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    pool: {
      description:
        "One record per ZFS pool with status, health, capacity, fragmentation.",
      schema: PoolSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    disk: {
      description: "One record per physical disk and its pool membership.",
      schema: DiskSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    alert: {
      description:
        "One record per active TrueNAS alert. `silenced` marks alerts that " +
        "were dismissed in the UI — still true, just no longer visible there.",
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
