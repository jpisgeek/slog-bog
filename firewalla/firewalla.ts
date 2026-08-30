/**
 * Firewalla Gold Pro inventory model, backed by the Firewalla MSP API.
 *
 * The firewall is the authoritative view of the network: it knows every device
 * that has ever been seen, including ones that are offline right now, which no
 * amount of SSH scanning can tell you. This model turns `GET /v2/devices` into
 * one `device` resource per device, one `machine` resource per deduplicated
 * host (NICs collapsed), and a single `inventory` roll-up, so the rest of the
 * homelab automation can be generated from real data instead of a
 * hand-maintained host list.
 *
 * Instance names are deterministic so a re-sync updates rather than
 * duplicates: `device-<slug>-<fnv1a>`, `machine-<slug>-<fnv1a>`, `inventory`.
 *
 * Devices are split into two tiers:
 *   deep     = infrastructure worth logging into and checking properly
 *   presence = everything else. The firewall's online/offline signal covers
 *              the shallow end of the swamp.
 *
 * The token comes from a swamp vault expression, never a literal:
 *   token: ${{ vault.get('myvault', 'ExampleVault/API Key') }}
 *
 * (The named secret manager used to be spelled out here. It is operator-
 * environment detail on a published surface and told a reader nothing about
 * how to configure the model, so it is stated generically now.)
 */
import { z } from "npm:zod@4";

// Firewalla reports access points as fwap-D / fwap-F / etc., so the deep tier
// matches on prefix rather than listing every hardware revision.
const DEFAULT_DEEP_TYPES = [
  "desktop",
  "nas&server",
  "switch",
  "goldpro",
  "fwap",
];

const GlobalArgsSchema = z.object({
  mspDomain: z
    .string()
    .min(1)
    .refine(
      (v) => mspHost(v) !== null,
      "must be a bare *.firewalla.net MSP hostname (scheme optional; no " +
        "path, query, fragment, port, or userinfo). This is where the API " +
        "token is sent, and a typo'd or malicious host would otherwise " +
        "receive it",
    )
    .describe(
      "MSP domain, e.g. example-msp.firewalla.net (scheme optional). " +
        "Must resolve under firewalla.net. The token is sent here.",
    ),
  token: z
    .string()
    .min(1)
    .meta({ sensitive: true })
    .describe("MSP personal access token; source it from a vault expression"),
  deepCheckTypes: z
    .array(z.string())
    .default(DEFAULT_DEEP_TYPES)
    .describe("deviceType values (prefix match) that belong to the deep tier"),
  timeoutSec: z
    .number()
    .int()
    .positive()
    .default(30)
    .describe("HTTP timeout for MSP API calls"),
  wiredSuffixes: z
    .array(z.string())
    .default(["eth", "lan", "en0"])
    .describe(
      "Interface suffixes considered wired. A wired address wins the " +
        "primaryIp race. It is the more reliable path to monitor over.",
    ),
  interfaceSuffixes: z
    .array(z.string())
    .default(["eth", "wifi", "wl", "awg", "lan", "en0"])
    .describe(
      "Trailing name segments that denote a NIC rather than a distinct " +
        "machine. 'example-host-eth' and 'example-host-wifi' collapse to " +
        "one machine, 'example-host'.",
    ),
  apiManaged: z
    .array(z.string())
    .default([])
    .describe(
      "Machines reached through their own API rather than SSH. They stay in " +
        "the inventory but are never SSH fleet candidates. The Firewalla " +
        "itself is handled automatically; add hosts like a TrueNAS box here.",
    ),
  excludeNetworks: z
    .array(z.string())
    .default([])
    .describe(
      "Firewalla networks that are off limits entirely. Devices on these " +
        "are skipped before anything is written. Not collected, not " +
        "counted, not stored. Use for VLANs outside the scope of this " +
        "automation (a work network, a guest network you do not own).",
    ),
  exclude: z
    .array(z.string())
    .default([])
    .describe(
      "Device names that must never be treated as machines, even if their " +
        "deviceType lands them in the deep tier. Supports a trailing '*'. " +
        "Thunderbolt docks are the motivating case: they hold a MAC and take " +
        "an IP, so Firewalla reports them as 'desktop'.",
    ),
  dependencies: z
    .record(z.string(), z.string())
    .default({})
    .describe(
      "machine -> machine it runs on or depends upon. A dependent being " +
        "unreachable while its parent is down is a consequence, not a " +
        "separate incident; downstream alerting can suppress on this.",
    ),
  pruneMaxShrink: z
    .number()
    .min(0)
    .max(1)
    .default(0.5)
    .describe(
      "Largest fraction of the previous sync's device total that may " +
        "vanish in one run and still be pruned. 0.5 means a run seeing " +
        "fewer than half of last run's devices refuses to delete anything " +
        "and warns instead, on the assumption the fetch was not " +
        "representative. Set to 1 to disable the shrink guard (a zero-" +
        "device response still never prunes without forcePrune).",
    ),
});

const SyncArgsSchema = z.object({
  network: z
    .string()
    .optional()
    .describe("Only sync devices on this Firewalla network (e.g. 'Root')"),
  tier: z
    .enum(["deep", "presence", "all"])
    .default("all")
    .describe("Restrict the sync to one tier"),
  forcePrune: z
    .boolean()
    .default(false)
    .describe(
      "Prune departed records even when the plausibility guards say the " +
        "fetch looks unrepresentative (zero devices, or a drop larger " +
        "than pruneMaxShrink). Use after a genuine mass decommission.",
    ),
});

/**
 * Device fields are declared explicitly rather than passthrough so that CEL
 * expressions in other models can resolve `attributes.<field>`.
 */
const DeviceSchema = z.object({
  id: z.string(),
  gid: z.string().optional(),
  name: z.string(),
  /**
   * Omitted, not "", when the firewall reports no current address. An empty
   * string would be indistinguishable from a genuinely blank value. A
   * missing key mechanically means "unknown" to anything reading it.
   */
  ip: z.string().optional(),
  mac: z.string(),
  macVendor: z.string(),
  deviceType: z.string(),
  network: z.string(),
  online: z.boolean(),
  ipReserved: z.boolean(),
  isRouter: z.boolean(),
  isFirewalla: z.boolean(),
  /**
   * Omitted, not 0, when the firewall reports no counter — the same rule `ip`
   * follows above. These used to be `Number(raw.totalDownload ?? 0)`, which
   * turned "the MSP did not send this field" into the assertion "this device
   * moved zero bytes". A renamed or scope-restricted field then read as a
   * fleet that had gone completely silent, which is a plausible-looking
   * number and therefore the worst kind of wrong. A missing key mechanically
   * means "unknown" to anything reading it.
   */
  totalDownload: z.number().optional(),
  totalUpload: z.number().optional(),
  /** "deep" or "presence", the monitoring tier this device falls into. */
  tier: z.string(),
  /** True when the device can plausibly be reached over SSH by the fleet. */
  sshCandidate: z.boolean(),
  /** True when `exclude` name-matched this device. Reported, not silent. */
  excluded: z.boolean(),
});

/**
 * A physical/logical machine, collapsed from one or more Firewalla devices.
 * A multi-homed Mac shows up as several devices (one per NIC). It is one
 * machine, and must be checked once.
 */
const MachineSchema = z.object({
  name: z.string(),
  primaryIp: z.string(),
  deviceType: z.string(),
  macVendor: z.string(),
  tier: z.string(),
  sshCandidate: z.boolean(),
  online: z.boolean(),
  networks: z.array(z.string()),
  interfaces: z.array(z.object({
    name: z.string(),
    ip: z.string(),
    mac: z.string(),
    network: z.string(),
    online: z.boolean(),
  })),
  interfaceCount: z.number(),
  /** Omitted when no dependency is configured for this machine. */
  dependsOn: z.string().optional(),
});

const InventorySchema = z.object({
  mspDomain: z.string(),
  total: z.number(),
  online: z.number(),
  offline: z.number(),
  deep: z.number(),
  presence: z.number(),
  reserved: z.number(),
  skippedByNetwork: z.number(),
  excludedNetworks: z.array(z.string()),
  machines: z.number(),
  sshCandidates: z.number(),
  excluded: z.number(),
  networks: z.array(z.string()),
  deviceTypes: z.record(z.string(), z.number()),
  syncedAt: z.string(),
});

/**
 * Resolve `mspDomain` to the bare hostname the token will be sent to, or
 * null if it is anything other than a plain *.firewalla.net host.
 *
 * This is parsed with the URL parser and checked on `hostname`, never on the
 * raw string: a suffix regex over the string accepted values like
 * `evil.example/#.firewalla.net`, which *ends with* ".firewalla.net" but
 * sends the request (and the token) to evil.example. Path, query, fragment,
 * port and userinfo are all rejected. The only legitimate shape is the host.
 */
function mspHost(raw: string): string | null {
  const trimmed = raw.trim().replace(/\/+$/, "");
  let u: URL;
  try {
    u = new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
  } catch {
    return null;
  }
  if (u.username !== "" || u.password !== "") return null;
  if (u.port !== "" || u.search !== "" || u.hash !== "") return null;
  if (u.pathname !== "/" && u.pathname !== "") return null;
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*\.firewalla\.net$/i.test(u.hostname)) {
    return null;
  }
  return u.hostname.toLowerCase();
}

/**
 * Deterministic 32-bit FNV-1a hash, rendered as 8 lowercase hex characters.
 * Same input always produces the same output, so a resource name built from
 * it is stable across re-syncs of the same device/machine (required so a
 * repeat sync updates the existing resource rather than creating a
 * duplicate) while still disambiguating inputs that collide after slugging.
 */
function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

/**
 * Resource names must be stable and filesystem-safe. `gid` (the Firewalla
 * box group id) is folded in so the same device id reported by two boxes on
 * one MSP account gets two distinct resource names instead of overwriting
 * each other, and the identity tuple is hashed so a device missing both mac
 * and id (which `syncDevices` otherwise skips, but tags/id come from
 * differently-shaped raw records in tests and future API changes) can't
 * collapse onto every other malformed record's name.
 */
function deviceResourceName(
  gid: string | undefined,
  mac: string,
  id: string,
): string {
  const slug = (mac || id).toLowerCase().replace(/[^a-z0-9]+/g, "");
  const h = fnv1a(`${gid ?? ""}|${mac}|${id}`);
  return `device-${slug || "unknown"}-${h}`;
}

/** Same collision-safety technique as `deviceResourceName`, for machines. */
function machineResourceName(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(
    /^-+|-+$/g,
    "",
  );
  return `machine-${slug || "unnamed"}-${fnv1a(name)}`;
}

/** Collapse an interface-suffixed device name to its machine name. */
function machineKey(name: string, suffixes: string[]): string {
  const idx = name.lastIndexOf("-");
  if (idx <= 0) return name;
  const tail = name.slice(idx + 1).toLowerCase();
  return suffixes.some((sfx) => sfx.toLowerCase() === tail)
    ? name.slice(0, idx)
    : name;
}

/**
 * The single fold applied to BOTH sides of every operator-config-vs-API string
 * comparison in this model: `excludeNetworks`, `exclude`, `apiManaged`, and
 * the `dependencies` keys.
 *
 * This started life as `foldNetwork`, for `excludeNetworks`, because that
 * matcher used to be a bare `includes(network)` -- exact, case-sensitive,
 * untrimmed -- while its sibling `isExcluded` lowercased both sides. An
 * operator who copied the README's `excludeNetworks: [Guest]` for a VLAN the
 * MSP reports as `guest` (or with stray whitespace from a YAML quirk) got no
 * match, every device on that network written to the datastore, and no signal
 * beyond `skippedByNetwork: 0` in the roll-up.
 *
 * The same defect was still live in the two matchers that were not audited at
 * the time, so it is now one function rather than one per call site:
 *   - `apiManaged` was an exact `includes()`, so `apiManaged: [nas]` against a
 *     machine the firewall names `NAS` left that host an SSH fleet candidate.
 *     The generated fleet then SSHes a box that is supposed to be reached
 *     through its own API -- the precise outcome the option exists to prevent.
 *   - `dependencies` was an exact object-key lookup, so `{App-Server: nas}`
 *     against machine `app-server` produced no edge, and downstream alerting
 *     lost the suppression it needed to tell a consequence from an incident.
 * A scope control that silently matches nothing is worse than one that errors.
 */
function fold(s: string): string {
  return s.trim().toLowerCase();
}

/** Name-based exclusion with optional trailing wildcard. */
function isExcluded(name: string, patterns: string[]): boolean {
  const n = fold(name);
  return patterns.some((p) => {
    const pat = fold(p);
    return pat.endsWith("*") ? n.startsWith(pat.slice(0, -1)) : n === pat;
  });
}

/** True when a device name ends in a suffix denoting a wired NIC. */
function isWired(name: string, wired: string[]): boolean {
  const idx = name.lastIndexOf("-");
  if (idx <= 0) return false;
  const tail = name.slice(idx + 1).toLowerCase();
  return wired.some((w) => w.toLowerCase() === tail);
}

function isDeep(deviceType: string, deepTypes: string[]): boolean {
  const t = (deviceType || "").toLowerCase();
  return deepTypes.some((d) => t.startsWith(d.toLowerCase()));
}

/**
 * The MSP API has returned both a bare array and an envelope; accept either.
 *
 * Returns `unknown[]`, deliberately. This used to hand back
 * `Record<string, unknown>[]` via a blind `as` cast, which is a lie about
 * data that arrives over the network: a `null` or a bare string in the array
 * typechecked as a device record and then threw a context-free
 * `TypeError: Cannot read properties of null` out of the middle of the sync,
 * killing a run that had already written most of its records. The caller now
 * has to narrow each element, and can skip and report the bad ones.
 */
function unwrapDevices(payload: unknown): unknown[] {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === "object") {
    const rec = payload as Record<string, unknown>;
    for (const key of ["results", "data", "devices", "items"]) {
      if (Array.isArray(rec[key])) return rec[key];
    }
  }
  throw new Error(
    "Unexpected /v2/devices response shape. Expected an array or an " +
      "envelope containing one.",
  );
}

/*
 * Field narrowing for raw MSP records.
 *
 * Every one of these returns `undefined` for "the API did not give me a usable
 * value", so the CALLER decides, in one visible place, what each absence
 * means. The rule this enforces is the one `DeviceSchema.ip` already
 * documents: absence must stay distinguishable from a value. The previous
 * `Number(raw.x ?? 0)` / `Boolean(raw.x)` / `String(raw.x ?? "")` coercions
 * all collapsed the two, so a field the MSP stopped sending was backfilled
 * with something that reads as a measurement.
 *
 * Deliberately NOT a `z.object({...}).strict()` over the raw record, which the
 * review suggested. Strict parsing makes any field the MSP ADDS a hard failure
 * of the whole sync -- an inventory model going dark because the vendor
 * shipped a new attribute is a worse outcome than the coercion this replaces,
 * and the unknown-key rejection buys nothing here because unknown keys are
 * never read. Validation is per-field and by type; unknown keys are ignored.
 */

/** A JSON scalar as a string, or undefined. Objects/arrays are not names. */
function optStr(v: unknown): string | undefined {
  if (typeof v === "string") return v === "" ? undefined : v;
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  if (typeof v === "bigint") return String(v);
  return undefined;
}

/** A finite number, accepting the numeric strings some MSP builds send. */
function optNum(v: unknown): number | undefined {
  if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
  if (typeof v === "string" && v.trim() !== "") {
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

/**
 * A boolean. `Boolean(raw.x)` was wrong in both directions here: the JSON
 * string `"false"` is truthy, and any absent field became a hard `false`.
 */
function optBool(v: unknown): boolean | undefined {
  if (typeof v === "boolean") return v;
  if (typeof v === "string") {
    const s = fold(v);
    if (s === "true") return true;
    if (s === "false") return false;
  }
  return undefined;
}

function networkName(value: unknown): string {
  if (typeof value === "string") return value;
  if (value && typeof value === "object") {
    const n = (value as Record<string, unknown>).name;
    if (typeof n === "string") return n;
  }
  return "(unknown)";
}

/**
 * Fetch with a small bounded retry for the two transient MSP failure modes
 * (429 rate limit, 503 unavailable), honoring `Retry-After` when the server
 * sends one and falling back to exponential backoff otherwise. Every other
 * status (including 401/403) is returned as-is for the caller to
 * classify. This only ever retries a *transient* failure, never interprets
 * a permanent one. Network errors and timeouts are wrapped with the URL so
 * they don't escape as a bare, context-free fetch exception.
 *
 * Two abort signals, not one, and both are needed:
 *   - `caller` is the workflow cancelling the run. Reported as CANCELLED.
 *   - `effective` is caller OR the request timeout, and is what the retry
 *     sleep listens to.
 * This used to read `ctx.signal` directly for both jobs. The sleep therefore
 * watched only the caller, so `timeoutSec: 1` against a server sending
 * `Retry-After: 5` sat in a wait for the full five seconds -- three times over
 * across the retry budget -- after the timeout the operator configured had
 * already fired. The timeout bounded a single fetch, never the call.
 */
async function fetchWithRetry(
  url: string,
  init: RequestInit,
  // deno-lint-ignore no-explicit-any
  ctx: any,
  signals: { caller?: AbortSignal; effective: AbortSignal },
  redact: (text: string) => string,
  maxAttempts = 3,
): Promise<Response> {
  // Upper bound on a single retry wait regardless of what Retry-After asks
  // for: this is an inventory sync, not a production client, and a hostile
  // or misconfigured header must not be able to park a workflow step for
  // hours.
  const MAX_RETRY_DELAY_MS = 5000;
  const { caller, effective } = signals;

  /** CANCELLED only when the CALLER aborted; a timeout is not a cancellation. */
  const abortError = (where: string) =>
    new Error(
      caller?.aborted
        ? `CANCELLED: request to MSP API ${url} was cancelled by the caller ${where}`
        : `MSP API ${url} timed out ${where}`,
    );

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let response: Response;
    try {
      response = await fetch(url, init);
    } catch (e) {
      // The caller pulling the plug is not an outage -- say so, rather than
      // reporting a cancelled run as "failed to reach".
      if (effective.aborted) throw abortError("mid-request");
      // Redacted for the same reason the HTTP-error body is: this message is
      // foreign text, and no foreign text reaches an error unscrubbed.
      throw new Error(
        `Failed to reach MSP API ${url}: ${redact((e as Error).message)}`,
      );
    }

    const transient = response.status === 429 || response.status === 503;
    if (!transient || attempt >= maxAttempts) return response;

    const retryAfterHeader = response.headers.get("Retry-After");
    const retryAfterSec = retryAfterHeader === null
      ? NaN
      : Number(retryAfterHeader);
    const wanted = Number.isFinite(retryAfterSec) && retryAfterSec >= 0
      ? retryAfterSec * 1000
      : 500 * 2 ** (attempt - 1);
    const delayMs = Math.min(wanted, MAX_RETRY_DELAY_MS);
    // A response we're discarding still holds an open stream until drained.
    await response.body?.cancel().catch(() => {});
    ctx.logger.warning(
      "MSP API {url} returned {status}; retrying in {ms}ms " +
        "(attempt {n}/{max})",
      {
        url,
        status: response.status,
        ms: delayMs,
        n: attempt,
        max: maxAttempts,
      },
    );
    // Abortable wait: a cancelled OR timed-out run must not sit in a sleep
    // nobody is waiting on any more. Listening on `effective` rather than the
    // caller signal is what makes `timeoutSec` bound the whole call.
    await new Promise<void>((resolve) => {
      if (effective.aborted) return resolve();
      const timer = setTimeout(() => {
        effective.removeEventListener("abort", onAbort);
        resolve();
      }, delayMs);
      const onAbort = () => {
        clearTimeout(timer);
        resolve();
      };
      effective.addEventListener("abort", onAbort, { once: true });
    });
    if (effective.aborted) {
      throw abortError(`while waiting to retry after HTTP ${response.status}`);
    }
  }
  // Unreachable: the loop always returns on its last iteration.
  throw new Error(`Failed to reach MSP API ${url}: exhausted retries`);
}

async function syncDevices(
  args: z.infer<typeof SyncArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  // Already validated by the schema refine, so the non-null assertion is safe.
  const domain = mspHost(g.mspDomain)!;
  const url = `https://${domain}/v2/devices`;
  /** Strip the MSP token from any text before it can reach an error message. */
  const redact = (text: string) =>
    g.token ? text.split(g.token).join("[REDACTED]") : text;

  ctx.logger.info("fetching device inventory from {url}", { url });

  const timeout = AbortSignal.timeout(g.timeoutSec * 1000);
  // `ctx.signal` is typed optional and reduced harnesses really do omit it.
  // `AbortSignal.any([undefined, timeout])` is a TypeError, so this used to
  // blow up before the first fetch on any context without a signal -- the
  // timeout, the only bound on a token-bearing request, taking the run down
  // with it. Build the list from the signals that exist.
  const callerSignal: AbortSignal | undefined = ctx.signal;
  const effectiveSignal = callerSignal
    ? AbortSignal.any([callerSignal, timeout])
    : timeout;
  const response = await fetchWithRetry(
    url,
    {
      headers: {
        // MSP uses the "Token" scheme, not "Bearer".
        Authorization: `Token ${g.token}`,
        Accept: "application/json",
      },
      // A redirect is never a legitimate answer from the MSP API, and this
      // request carries a live credential. Whether the Authorization header
      // survives a cross-origin (or https -> http) redirect is the runtime's
      // fetch implementation's business; leaving the default `follow` in place
      // outsourced the "the token only ever goes to *.firewalla.net" guarantee
      // to somebody else's stripping rules. `error` keeps it here, where the
      // hostname was validated.
      redirect: "error",
      signal: effectiveSignal,
    },
    ctx,
    { caller: callerSignal, effective: effectiveSignal },
    redact,
  );

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      // Consume the body before throwing -- an HTTP response stream left
      // undisposed on an error path is a resource leak.
      await response.body?.cancel().catch(() => {});
      throw new Error(
        `MSP API ${url} returned HTTP ${response.status}: check the ` +
          "personal access token and its MSP permissions",
      );
    }
    // Redaction point: a misconfigured proxy's error page could echo request
    // headers. Scrub the token before the body reaches an error message.
    const detail = await response.text().then((t) => redact(t).slice(0, 200))
      .catch(() => "");
    throw new Error(
      `MSP API ${url} returned HTTP ${response.status}. ${detail}`,
    );
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch (e) {
    // V8's SyntaxError quotes a prefix of the offending body verbatim
    // ("Unexpected token 'x', \"<the body>\" is not valid JSON"). A proxy or
    // captive portal that answers 200 with an HTML page echoing the request
    // headers therefore put the token straight into this message -- the one
    // body-derived path that was not scrubbed, while the README promised the
    // token is "redacted from any error body before it can reach a message".
    // It is now the same rule everywhere: no foreign text reaches an Error
    // without passing through redact(), and the quote is length-capped like
    // the HTTP-error detail beside it.
    throw new Error(
      `MSP API ${url} returned a response that could not be parsed as ` +
        `JSON: ${redact((e as Error).message).slice(0, 200)}`,
    );
  }
  const devices = unwrapDevices(payload);

  // Read the PREVIOUS roll-up before the new one overwrites it. It is the
  // only record of how large this inventory is supposed to be, and the
  // prune guard below needs it. A first-ever run has no `inventory`
  // resource, and a ctx without readResource is possible in reduced
  // harnesses, so a miss is "unknown", never "zero" -- treating a failed
  // read as a previous total of 0 would turn the guard off exactly when it
  // is least verifiable.
  let previousTotal: number | null = null;
  try {
    const prior = await ctx.readResource?.("inventory");
    const t = (prior as Record<string, unknown> | null | undefined)?.total;
    if (typeof t === "number" && Number.isFinite(t) && t >= 0) {
      previousTotal = t;
    }
  } catch {
    previousTotal = null;
  }

  /** Wraps writeResource failures with which resource was being written. */
  async function writeOrThrow(
    specName: string,
    name: string,
    data: Record<string, unknown>,
    opts?: Record<string, unknown>,
    // deno-lint-ignore no-explicit-any
  ): Promise<any> {
    try {
      return await ctx.writeResource(specName, name, data, opts);
    } catch (e) {
      // Redacted like every other foreign message in this file. A datastore
      // driver that echoes the model's rendered configuration into its error
      // (several do) would otherwise carry the token out through the one
      // error path nobody was looking at, because it is not "the response
      // body" and so escaped the review of the HTTP paths.
      throw new Error(
        `Failed to write ${specName} resource "${name}": ${
          redact((e as Error).message)
        }`,
      );
    }
  }

  // Folded once rather than per device: the comparison is case- and
  // whitespace-insensitive on BOTH sides, so `[Guest]` in config matches a
  // network the MSP calls `guest ` and vice versa. Same treatment for the two
  // sibling matchers -- see `fold` for what each of them silently missed.
  const excludedNetworkSet = new Set(g.excludeNetworks.map(fold));
  const apiManagedSet = new Set(g.apiManaged.map(fold));
  const dependencyByMachine = new Map<string, string>();
  for (const [parent, child] of Object.entries(g.dependencies)) {
    const key = fold(parent);
    if (dependencyByMachine.has(key)) {
      // Two config keys folding to one machine is an ambiguity, not a merge.
      // Report it rather than letting object-iteration order pick a winner.
      ctx.logger.warning(
        "dependencies has more than one entry for machine {machine} after " +
          "case/whitespace folding; keeping {kept} and ignoring {dropped}",
        { machine: key, kept: dependencyByMachine.get(key), dropped: child },
      );
      continue;
    }
    dependencyByMachine.set(key, child);
  }

  const handles = [];
  const liveNames = new Set<string>();
  const typeCounts: Record<string, number> = {};
  const networks = new Set<string>();
  let online = 0, deep = 0, reserved = 0, excluded = 0, skippedNetworks = 0;
  // Counted, not logged per record: a systemic MSP field rename would
  // otherwise emit one warning line per device.
  let malformed = 0, missingOnline = 0;

  // machineName -> accumulating record, built as devices stream past.
  const machines = new Map<string, {
    name: string;
    primaryIp: string;
    deviceType: string;
    macVendor: string;
    tier: string;
    sshCandidate: boolean;
    online: boolean;
    /** True when this machine's key came from stripping a NIC suffix. */
    hadSuffix: boolean;
    /** True when primaryIp currently comes from a wired interface. */
    primaryWired: boolean;
    /**
     * True when the interface currently holding primaryIp was online. Kept
     * separate from `online`, which is the OR across every interface: once
     * any NIC is online the machine-wide flag is true forever, so it cannot
     * answer "is the address we picked a live one?".
     */
    primaryOnline: boolean;
    networks: Set<string>;
    interfaces: Array<
      {
        name: string;
        ip: string;
        mac: string;
        network: string;
        online: boolean;
      }
    >;
  }>();

  for (const element of devices) {
    // The array elements are `unknown` because that is what came off the wire.
    // A `null` or a bare string here used to reach `raw.id` and throw a
    // context-free TypeError out of the middle of the loop, abandoning a run
    // that had already written most of its resources. One bad element is not
    // a reason to lose the other four hundred.
    if (
      element === null || typeof element !== "object" || Array.isArray(element)
    ) {
      malformed++;
      continue;
    }
    const raw = element as Record<string, unknown>;

    // The documented /v2/devices response identifies every device by `id`
    // (shown as a MAC address) and its example has no separate `mac` field
    // at all. `id` doubling as the MAC is the norm, not an edge case. A
    // record with neither is too malformed to name or deduplicate safely,
    // so it's skipped and logged rather than silently coerced into an
    // empty-string identity that would collide with every other such record.
    const rawId = optStr(raw.id) ?? "";
    if (!rawId) {
      ctx.logger.warning(
        "skipping device with no id in /v2/devices response: {name}",
        { name: optStr(raw.name) ?? "(unnamed)" },
      );
      continue;
    }

    const deviceType = optStr(raw.deviceType) ?? "";
    const network = networkName(raw.network);

    // Off-limits networks are dropped before any resource is written, so no
    // trace of them enters the datastore. Counted only so the skip is
    // reported rather than silent.
    if (excludedNetworkSet.has(fold(network))) {
      skippedNetworks++;
      continue;
    }

    const tier = isDeep(deviceType, g.deepCheckTypes) ? "deep" : "presence";

    if (args.tier !== "all" && args.tier !== tier) continue;
    if (args.network && network !== args.network) continue;

    const rawName = optStr(raw.name) ?? "(unnamed)";
    const dropped = isExcluded(rawName, g.exclude);
    if (dropped) excluded++;

    const isFirewalla = optBool(raw.isFirewalla) ?? false;
    // `online` absent is recorded as false, deliberately, and NOT made
    // optional the way the traffic counters were. Every consumer of this
    // model -- the machine-wide OR, the roll-up counts, the `online` tag,
    // downstream CEL -- asks a two-state question, and a third state would
    // have to be handled correctly in all of them or it is worse than useless.
    // The direction of error matters too: reading an absent field as offline
    // fails LOUD (the whole fleet reports down, alerts fire, someone looks)
    // where reading it as online fails silent-and-green, which is the failure
    // a presence tier exists to prevent. The count below names the reason in
    // the log so the loud failure is diagnosable in one line.
    const onlineFlag = optBool(raw.online);
    if (onlineFlag === undefined) missingOnline++;
    const isOnline = onlineFlag ?? false;
    const totalDownload = optNum(raw.totalDownload);
    const totalUpload = optNum(raw.totalUpload);
    const device = {
      id: rawId,
      gid: optStr(raw.gid),
      name: rawName,
      ip: optStr(raw.ip),
      // `mac` falls back to `id` per the documented response shape above,
      // not to "", which would silently misrepresent a present-but-elided
      // field as a genuinely absent one.
      mac: optStr(raw.mac) ?? rawId,
      macVendor: optStr(raw.macVendor) ?? "(unknown)",
      deviceType: deviceType || "(unset)",
      network,
      online: isOnline,
      ipReserved: optBool(raw.ipReserved) ?? false,
      isRouter: optBool(raw.isRouter) ?? false,
      isFirewalla,
      // Spread rather than assigned: an absent counter leaves the key off the
      // record entirely, which is how DeviceSchema encodes "unknown".
      ...(totalDownload === undefined ? {} : { totalDownload }),
      ...(totalUpload === undefined ? {} : { totalUpload }),
      tier,
      // The Firewalla itself is deep-tier but has SSH disabled by default, so
      // it is never an SSH fleet candidate. Excluded names (docks and
      // friends) are reported but never targeted.
      sshCandidate: tier === "deep" && !isFirewalla && !dropped &&
        !apiManagedSet.has(fold(machineKey(rawName, g.interfaceSuffixes))),
      excluded: dropped,
    };

    const name = deviceResourceName(device.gid, device.mac, device.id);
    liveNames.add(name);

    typeCounts[device.deviceType] = (typeCounts[device.deviceType] ?? 0) + 1;
    networks.add(network);
    if (device.online) online++;
    if (tier === "deep") deep++;
    if (device.ipReserved) reserved++;

    // Collapse NICs onto one machine. Prefer a wired, online, reserved
    // address as the primary. That is the one worth SSH-ing.
    //
    // Two genuinely different devices can share a name (a pair of identical
    // air purifiers, say). Those are separate machines and must not be folded
    // together just because the strings match.
    //
    // The test for "already taken by a different host" is whether the machine
    // we would merge into already holds an interface with this exact device
    // name. One host never reports two NICs under the same Firewalla name --
    // the whole premise of suffix stripping is that the NICs differ in their
    // trailing segment -- so an exact name repeat means a second host.
    //
    // The old guard was `!hadSuffix && !collision.hadSuffix`, which only
    // separated same-named devices when NEITHER name had a NIC suffix
    // stripped. A retired `pi-eth` still known to the firewall plus its
    // same-named replacement both set hadSuffix, so the guard never fired and
    // the two collapsed into one `machine` whose interface list mixed both
    // hosts -- one host silently gone from the SSH fleet and from monitoring,
    // which is the exact inventory loss this model exists to prevent. The
    // interface-name test subsumes the old condition (neither side having a
    // suffix means both names equal `stripped`, so the name is necessarily
    // already in the collision's interface list) and additionally catches the
    // suffixed case, so the old clause is not kept alongside it.
    //
    // Deliberately NOT gated on mac-vendor agreement: a multi-homed Mac's
    // built-in ethernet and its Wi-Fi radio routinely report different
    // vendors, so requiring agreement would split real hosts. Splitting is
    // the safe direction of error here anyway -- a duplicated SSH target is
    // noise, a merged one is a lost machine.
    const stripped = machineKey(device.name, g.interfaceSuffixes);
    const hadSuffix = stripped !== device.name;
    const collision = machines.get(stripped);
    const nameTaken = Boolean(
      collision?.interfaces.some((i) => i.name === device.name),
    );
    const mKey = nameTaken
      ? `${stripped}-${device.mac.replace(/[^a-zA-Z0-9]/g, "").slice(-4)}`
      : stripped;
    const existingMachine = machines.get(mKey);
    if (!existingMachine) {
      machines.set(mKey, {
        name: mKey,
        hadSuffix,
        primaryWired: isWired(device.name, g.wiredSuffixes),
        primaryOnline: device.online,
        primaryIp: device.ip ?? "",
        deviceType: device.deviceType,
        macVendor: device.macVendor,
        tier,
        sshCandidate: device.sshCandidate,
        online: device.online,
        networks: new Set([network]),
        interfaces: [{
          name: device.name,
          ip: device.ip ?? "",
          mac: device.mac,
          network,
          online: device.online,
        }],
      });
    } else {
      existingMachine.interfaces.push({
        name: device.name,
        ip: device.ip ?? "",
        mac: device.mac,
        network,
        online: device.online,
      });
      existingMachine.networks.add(network);
      existingMachine.hadSuffix = existingMachine.hadSuffix || hadSuffix;
      // Snapshot the state the primaryIp tiebreak needs BEFORE the roll-up
      // fields are updated. `existingMachine.online` is the machine-wide OR
      // across interfaces, but rule 2 below asks a narrower question: was the
      // interface currently holding primaryIp online? Reading the field after
      // the OR-assignment made `!existingMachine.online` false whenever this
      // device was online -- which is precisely when the clause is consulted
      // -- so the whole "online beats offline" preference was dead code. A
      // host whose offline `nas-eth` was processed before its online
      // `nas-lan` kept the stale interface's address as primaryIp, and that
      // address is what the generated SSH fleet targets.
      const primaryWasOnline = existingMachine.primaryOnline;
      existingMachine.online = existingMachine.online || device.online;
      existingMachine.sshCandidate = existingMachine.sshCandidate ||
        device.sshCandidate;
      // Preference order for primaryIp, strongest first:
      //   1. wired beats wireless   2. online beats offline   3. any address
      // beats none. A wired address is only displaced by another wired one.
      const wired = isWired(device.name, g.wiredSuffixes);
      const better = Boolean(device.ip) && (
        !existingMachine.primaryIp ||
        (wired && !existingMachine.primaryWired) ||
        (wired === existingMachine.primaryWired &&
          device.online && !primaryWasOnline)
      );
      if (better) {
        existingMachine.primaryIp = device.ip ?? "";
        existingMachine.primaryWired = wired;
        existingMachine.primaryOnline = device.online;
      }
    }

    handles.push(
      await writeOrThrow("device", name, device, {
        tags: {
          tier,
          network,
          deviceType: device.deviceType,
          online: String(device.online),
          sshCandidate: String(device.sshCandidate),
          machine: machineKey(device.name, g.interfaceSuffixes),
        },
      }),
    );
  }

  const deviceCount = handles.length;

  // Both of these are warnings, not info: they mean the response did not have
  // the shape this model was written against, and the roll-up that follows is
  // built on whatever survived. A silent partial sync is the failure mode that
  // makes generated fleets quietly wrong.
  if (malformed > 0) {
    ctx.logger.warning(
      "skipped {n} non-object entr(ies) in the /v2/devices array; the " +
        "response shape is not what this model expects",
      { n: malformed },
    );
  }
  if (missingOnline > 0) {
    ctx.logger.warning(
      "{n} device(s) had no usable `online` field and were recorded as " +
        "offline. If that is most of the fleet, the MSP has probably " +
        "renamed the field rather than everything having gone down.",
      { n: missingOnline },
    );
  }

  // One resource per machine. This is what the SSH fleet is generated from.
  // Never the raw device list, which double-counts multi-homed hosts.
  let sshCandidates = 0;
  for (const m of machines.values()) {
    if (m.sshCandidate) sshCandidates++;
    const mName = machineResourceName(m.name);
    liveNames.add(mName);
    const dependsOn = dependencyByMachine.get(fold(m.name));
    handles.push(
      await writeOrThrow("machine", mName, {
        name: m.name,
        primaryIp: m.primaryIp,
        deviceType: m.deviceType,
        macVendor: m.macVendor,
        tier: m.tier,
        sshCandidate: m.sshCandidate,
        online: m.online,
        networks: [...m.networks].sort(),
        interfaces: m.interfaces,
        interfaceCount: m.interfaces.length,
        ...(dependsOn ? { dependsOn } : {}),
      }, {
        tags: {
          tier: m.tier,
          online: String(m.online),
          sshCandidate: String(m.sshCandidate),
          multiHomed: String(m.interfaces.length > 1),
          dependsOn: dependsOn ?? "",
        },
      }),
    );
  }

  const counted = deviceCount;
  handles.push(
    await writeOrThrow("inventory", "inventory", {
      mspDomain: domain,
      total: counted,
      online,
      offline: counted - online,
      deep,
      presence: counted - deep,
      reserved,
      skippedByNetwork: skippedNetworks,
      excludedNetworks: g.excludeNetworks,
      machines: machines.size,
      sshCandidates,
      excluded,
      networks: [...networks].sort(),
      deviceTypes: typeCounts,
      syncedAt: new Date().toISOString(),
    }, { tags: { total: String(counted), deep: String(deep) } }),
  );

  // Prune devices the firewall no longer reports. Only safe on a full sync.
  // A filtered sync legitimately sees a subset and must not delete the rest.
  // `findAllForModel` is the only way to enumerate this model instance's own
  // prior resources (`readResource` takes a single instance name, not a
  // listing). The actual delete then goes through `deleteResource`, the
  // documented API for removing a named resource, rather than reaching for
  // `dataRepository.delete` a second time.
  //
  // "Full sync" is a necessary condition, not a sufficient one. The fetch
  // also has to look REPRESENTATIVE. A structurally valid HTTP 200 carrying
  // zero devices -- a transient MSP backend fault, a briefly unlinked box, a
  // token whose scope narrowed, or (if /v2/devices ever paginates) a
  // truncated envelope -- reaches this block by exactly the same path as a
  // genuine empty network, and the old code answered it by deleting every
  // stored device-* and machine-* record one at a time under routine
  // `pruned departed record` info lines. Everything generated from the
  // `machine` resources, the SSH fleet included, then read an empty fleet
  // until some later sync happened to succeed.
  //
  // Two guards, both overridable with forcePrune for a real mass
  // decommission:
  //   - zero devices never prunes, whatever pruneMaxShrink says;
  //   - a live count below (previous total * (1 - pruneMaxShrink)) does not
  //     prune either.
  // Refusing is logged as a WARNING, not info: a run that declined to prune
  // has to be visible, and so does the reason. The run itself still
  // succeeds and still writes the roll-up -- failing the whole sync would
  // discard a device list that is probably fine, and preserving data is the
  // entire point of the guard.
  const shrinkFloor = previousTotal === null
    ? 0
    : previousTotal * (1 - g.pruneMaxShrink);
  let pruneBlockedBy: string | null = null;
  if (!args.forcePrune) {
    // The zero test is on what this run actually WROTE, not on the raw fetch
    // length: a run that recorded nothing has no evidence at all about which
    // records are departed, whether the list came back empty or every entry
    // fell to an exclusion.
    if (deviceCount === 0) {
      pruneBlockedBy =
        `this run wrote no device records (${devices.length} returned ` +
        `by the MSP)`;
    } else if (previousTotal !== null && deviceCount < shrinkFloor) {
      pruneBlockedBy = `${deviceCount} device(s) is below the shrink floor ` +
        `of ${shrinkFloor} (previous total ${previousTotal}, ` +
        `pruneMaxShrink ${g.pruneMaxShrink})`;
    }
  }

  if (args.tier === "all" && !args.network && pruneBlockedBy) {
    ctx.logger.warning(
      "refusing to prune departed records: {reason}. The fetch does not " +
        "look representative, so stored records are kept. Re-run with " +
        "forcePrune once you have confirmed the loss is real.",
      { reason: pruneBlockedBy },
    );
  } else if (args.tier === "all" && !args.network) {
    let existing: Array<{ name: string }>;
    try {
      existing = await ctx.dataRepository.findAllForModel(
        ctx.modelType,
        ctx.modelId,
      );
    } catch (e) {
      throw new Error(
        `Failed to list existing device/machine records for pruning: ${
          redact((e as Error).message)
        }`,
      );
    }
    for (const rec of existing) {
      const tracked = rec.name.startsWith("device-") ||
        rec.name.startsWith("machine-");
      if (tracked && !liveNames.has(rec.name)) {
        try {
          await ctx.deleteResource(rec.name);
        } catch (e) {
          throw new Error(
            `Failed to prune departed record ${rec.name}: ${
              redact((e as Error).message)
            }`,
          );
        }
        ctx.logger.info("pruned departed record {name}", { name: rec.name });
      }
    }
  } else {
    ctx.logger.info(
      "filtered sync: skipping prune so unmatched devices are preserved",
    );
  }

  if (skippedNetworks > 0) {
    ctx.logger.info(
      "skipped {n} device(s) on off-limits network(s): {nets}",
      { n: skippedNetworks, nets: g.excludeNetworks.join(", ") },
    );
  }

  ctx.logger.info(
    "synced {count} devices -> {machines} machines " +
      "({ssh} ssh candidates, {deep} deep, {online} online)",
    {
      count: counted,
      machines: machines.size,
      ssh: sshCandidates,
      deep,
      online,
    },
  );

  return { dataHandles: handles };
}

/**
 * The `@jpisgeek/firewalla` model definition: a single `syncDevices` method
 * that turns the MSP device list into `device`, `machine`, and `inventory`
 * resources. See the module header above for the deep/presence tiering
 * rationale and why the collapsed `machine` resource, not `device`, is the
 * correct source for generating an SSH fleet.
 */
export const model = {
  type: "@jpisgeek/firewalla",
  version: "2026.08.22.2",
  globalArguments: GlobalArgsSchema,

  checks: {
    "full-sync-prunes-departed-records": {
      description:
        "A full sync (no tier or network filter) deletes any stored " +
        "device or machine record the firewall no longer reports, unless " +
        "the run looks unrepresentative: it wrote no devices at all, or " +
        "the count fell further than pruneMaxShrink below the previous " +
        "roll-up's total. Those runs warn and keep the records; " +
        "forcePrune overrides. This check always passes. Its purpose is " +
        "to make the destructive deletion policy visible before the " +
        "method runs and give it a name that can be skipped " +
        "(--skip-check) when investigating suspected data loss, not to " +
        "gate on the specific args of a given call.",
      labels: ["policy"],
      appliesTo: ["syncDevices"],
      execute: () => Promise.resolve({ pass: true }),
    },
  },

  resources: {
    device: {
      description:
        "One record per device known to the Firewalla, including devices " +
        "that are currently offline. Tagged with tier, network, deviceType, " +
        "online, and sshCandidate so workflow CEL can select subsets.",
      schema: DeviceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    machine: {
      description:
        "One record per machine, collapsed from the device list so a " +
        "multi-homed host is checked once rather than once per NIC. This is " +
        "the correct source for generating an SSH fleet. Tagged with tier, " +
        "online, sshCandidate, multiHomed, and dependsOn.",
      schema: MachineSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    inventory: {
      description:
        "Single roll-up of the most recent sync: totals by tier and state, " +
        "the network list, and a deviceType histogram.",
      schema: InventorySchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  methods: {
    syncDevices: {
      description:
        "Fetch every device from the MSP API and write one device resource " +
        "per device, one machine resource per deduplicated host, and an " +
        "inventory roll-up. Classifies each device into the deep or presence " +
        "tier, collapses NICs onto their machine, and applies name " +
        "exclusions. A full sync prunes departed records; a filtered sync, " +
        "or one whose device count looks unrepresentative, does not.",
      arguments: SyncArgsSchema,
      execute: syncDevices,
    },
  },
};
