/**
 * Firewalla Gold Pro inventory model, backed by the Firewalla MSP API.
 *
 * The firewall is the authoritative view of the network: it knows every device
 * that has ever been seen, including ones that are offline right now, which no
 * amount of SSH scanning can tell you. This model turns `GET /v2/devices` into
 * one `device` resource per device plus a single `inventory` roll-up, so the
 * rest of the homelab automation can be generated from real data instead of a
 * hand-maintained host list.
 *
 * Devices are split into two tiers:
 *   deep     = infrastructure worth logging into and checking properly
 *   presence = everything else. The firewall's online/offline signal covers
 *              the shallow end of the swamp.
 *
 * The token is expected to arrive from Proton Pass:
 *   token: ${{ vault.get('myvault', 'ExampleVault/API Key') }}
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
  totalDownload: z.number(),
  totalUpload: z.number(),
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

/** Name-based exclusion with optional trailing wildcard. */
function isExcluded(name: string, patterns: string[]): boolean {
  const n = name.toLowerCase();
  return patterns.some((p) => {
    const pat = p.toLowerCase();
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

/** The MSP API has returned both a bare array and an envelope; accept either. */
function unwrapDevices(payload: unknown): Record<string, unknown>[] {
  if (Array.isArray(payload)) return payload as Record<string, unknown>[];
  if (payload && typeof payload === "object") {
    const rec = payload as Record<string, unknown>;
    for (const key of ["results", "data", "devices", "items"]) {
      if (Array.isArray(rec[key])) return rec[key] as Record<string, unknown>[];
    }
  }
  throw new Error(
    "Unexpected /v2/devices response shape. Expected an array or an " +
      "envelope containing one.",
  );
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
 */
async function fetchWithRetry(
  url: string,
  init: RequestInit,
  // deno-lint-ignore no-explicit-any
  ctx: any,
  maxAttempts = 3,
): Promise<Response> {
  // Upper bound on a single retry wait regardless of what Retry-After asks
  // for: this is an inventory sync, not a production client, and a hostile
  // or misconfigured header must not be able to park a workflow step for
  // hours.
  const MAX_RETRY_DELAY_MS = 5000;
  const signal: AbortSignal | undefined = ctx.signal;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let response: Response;
    try {
      response = await fetch(url, init);
    } catch (e) {
      // The caller pulling the plug is not an outage -- say so, rather than
      // reporting a cancelled run as "failed to reach".
      if (signal?.aborted) {
        throw new Error(
          `CANCELLED: request to MSP API ${url} was cancelled by the caller`,
        );
      }
      throw new Error(
        `Failed to reach MSP API ${url}: ${(e as Error).message}`,
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
    // Abortable wait: a cancelled run must not sit in a sleep nobody is
    // waiting on any more.
    await new Promise<void>((resolve) => {
      if (signal?.aborted) return resolve();
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, delayMs);
      const onAbort = () => {
        clearTimeout(timer);
        resolve();
      };
      signal?.addEventListener("abort", onAbort, { once: true });
    });
    if (signal?.aborted) {
      throw new Error(
        `CANCELLED: request to MSP API ${url} was cancelled while waiting ` +
          `to retry after HTTP ${response.status}`,
      );
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
  const response = await fetchWithRetry(url, {
    headers: {
      // MSP uses the "Token" scheme, not "Bearer".
      Authorization: `Token ${g.token}`,
      Accept: "application/json",
    },
    signal: AbortSignal.any([ctx.signal, timeout]),
  }, ctx);

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
    throw new Error(
      `MSP API ${url} returned a response that could not be parsed as ` +
        `JSON: ${(e as Error).message}`,
    );
  }
  const devices = unwrapDevices(payload);

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
      throw new Error(
        `Failed to write ${specName} resource "${name}": ${
          (e as Error).message
        }`,
      );
    }
  }

  const handles = [];
  const liveNames = new Set<string>();
  const typeCounts: Record<string, number> = {};
  const networks = new Set<string>();
  let online = 0, deep = 0, reserved = 0, excluded = 0, skippedNetworks = 0;

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

  for (const raw of devices) {
    // The documented /v2/devices response identifies every device by `id`
    // (shown as a MAC address) and its example has no separate `mac` field
    // at all. `id` doubling as the MAC is the norm, not an edge case. A
    // record with neither is too malformed to name or deduplicate safely,
    // so it's skipped and logged rather than silently coerced into an
    // empty-string identity that would collide with every other such record.
    const rawId = raw.id == null ? "" : String(raw.id);
    if (!rawId) {
      ctx.logger.warning(
        "skipping device with no id in /v2/devices response: {name}",
        { name: String(raw.name ?? "(unnamed)") },
      );
      continue;
    }

    const deviceType = String(raw.deviceType ?? "");
    const network = networkName(raw.network);

    // Off-limits networks are dropped before any resource is written, so no
    // trace of them enters the datastore. Counted only so the skip is
    // reported rather than silent.
    if (g.excludeNetworks.includes(network)) {
      skippedNetworks++;
      continue;
    }

    const tier = isDeep(deviceType, g.deepCheckTypes) ? "deep" : "presence";

    if (args.tier !== "all" && args.tier !== tier) continue;
    if (args.network && network !== args.network) continue;

    const rawName = String(raw.name ?? "(unnamed)");
    const dropped = isExcluded(rawName, g.exclude);
    if (dropped) excluded++;

    const isFirewalla = Boolean(raw.isFirewalla);
    const rawIp = raw.ip == null ? undefined : String(raw.ip);
    const device = {
      id: rawId,
      gid: raw.gid === undefined ? undefined : String(raw.gid),
      name: String(raw.name ?? "(unnamed)"),
      ip: rawIp,
      // `mac` falls back to `id` per the documented response shape above,
      // not to "", which would silently misrepresent a present-but-elided
      // field as a genuinely absent one.
      mac: raw.mac == null ? rawId : String(raw.mac),
      macVendor: String(raw.macVendor ?? "(unknown)"),
      deviceType: deviceType || "(unset)",
      network,
      online: Boolean(raw.online),
      ipReserved: Boolean(raw.ipReserved),
      isRouter: Boolean(raw.isRouter),
      isFirewalla,
      totalDownload: Number(raw.totalDownload ?? 0),
      totalUpload: Number(raw.totalUpload ?? 0),
      tier,
      // The Firewalla itself is deep-tier but has SSH disabled by default, so
      // it is never an SSH fleet candidate. Excluded names (docks and
      // friends) are reported but never targeted.
      sshCandidate: tier === "deep" && !isFirewalla && !dropped &&
        !g.apiManaged.includes(machineKey(rawName, g.interfaceSuffixes)),
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
    // Only merge when a suffix was actually stripped from at least one side.
    // Two genuinely different devices can share a name (a pair of identical
    // air purifiers, say). Those are separate machines and must not be folded
    // together just because the strings match.
    const stripped = machineKey(device.name, g.interfaceSuffixes);
    const hadSuffix = stripped !== device.name;
    const collision = machines.get(stripped);
    const mKey = (collision && !hadSuffix && !collision.hadSuffix)
      ? `${stripped}-${device.mac.replace(/[^a-zA-Z0-9]/g, "").slice(-4)}`
      : stripped;
    const existingMachine = machines.get(mKey);
    if (!existingMachine) {
      machines.set(mKey, {
        name: mKey,
        hadSuffix,
        primaryWired: isWired(device.name, g.wiredSuffixes),
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
          device.online && !existingMachine.online)
      );
      if (better) {
        existingMachine.primaryIp = device.ip ?? "";
        existingMachine.primaryWired = wired;
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

  // One resource per machine. This is what the SSH fleet is generated from.
  // Never the raw device list, which double-counts multi-homed hosts.
  let sshCandidates = 0;
  for (const m of machines.values()) {
    if (m.sshCandidate) sshCandidates++;
    const mName = machineResourceName(m.name);
    liveNames.add(mName);
    const dependsOn = g.dependencies[m.name];
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
          dependsOn: g.dependencies[m.name] ?? "",
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
  if (args.tier === "all" && !args.network) {
    let existing: Array<{ name: string }>;
    try {
      existing = await ctx.dataRepository.findAllForModel(
        ctx.modelType,
        ctx.modelId,
      );
    } catch (e) {
      throw new Error(
        `Failed to list existing device/machine records for pruning: ${
          (e as Error).message
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
              (e as Error).message
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
        "device or machine record the firewall no longer reports. This " +
        "check always passes. Its purpose is to make that destructive " +
        "deletion policy visible before the method runs and give it a " +
        "name that can be skipped (--skip-check) when investigating " +
        "suspected data loss, not to gate on the specific args of a " +
        "given call.",
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
        "exclusions. A full sync prunes departed records; a filtered sync " +
        "does not.",
      arguments: SyncArgsSchema,
      execute: syncDevices,
    },
  },
};
