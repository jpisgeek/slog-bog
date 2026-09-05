import {
  assertEquals,
  assertMatch,
  assertNotEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import {
  EvidenceReferenceSchema,
  normalize,
  report,
} from "./dashboard_homelab.ts";

type Json = Record<string, unknown>;

/**
 * A value that must never appear in a bundle. Used as the payload of every
 * text channel the security review flagged, so a test that greps the whole
 * serialized bundle for it fails the moment any of those channels reopens.
 */
const SECRET = "s3cr3t-Bearer-9f2a";

/**
 * Case-insensitive, because the ways this report reshapes source text are not
 * redaction: slugifying a name lowercases it, and a lowercased secret is still
 * the secret. An exact-case search would have passed over a metric id built
 * from `slug(pool.name)`.
 */
function assertAbsent(bundle: unknown, ...forbidden: string[]) {
  const json = JSON.stringify(bundle).toLowerCase();
  for (const value of forbidden) {
    assertEquals(json.includes(value.toLowerCase()), false, `leaked ${value}`);
  }
}

function context(
  modelType: string,
  artifacts: Array<
    { spec: string; name: string; value?: Json; fail?: boolean | string }
  >,
  methodArgs: Json = {},
) {
  const encoded = new Map(
    artifacts.filter((a) => a.value).map((a) => [
      a.name,
      new TextEncoder().encode(JSON.stringify(a.value)),
    ]),
  );
  // `fail` may carry the exact message the data repository throws, so a test
  // can prove that message does not reach the report output.
  const failures = new Map(
    artifacts.filter((a) => a.fail).map((a) => [
      a.name,
      typeof a.fail === "string" ? a.fail : "synthetic partial read",
    ]),
  );
  return {
    scope: "method" as const,
    modelType,
    modelId: "synthetic-model-id",
    definition: { name: "synthetic", version: 1 },
    methodName: modelType.endsWith("firewalla") ? "syncDevices" : "discover",
    methodArgs,
    executionStatus: "succeeded" as const,
    dataHandles: artifacts.map((a, version) => ({
      name: a.name,
      specName: a.spec,
      version: version + 1,
    })),
    dataRepository: {
      getContent: (_type: string, _id: string, name: string) => {
        if (failures.has(name)) throw new Error(failures.get(name)!);
        return Promise.resolve(encoded.get(name) ?? null);
      },
    },
  };
}

const now = () => new Date().toISOString();

const netdataNode = (extra: Json = {}) => ({
  name: "node-a",
  url: "https://node-a.example.com",
  reachable: true,
  error: "",
  transport: "http",
  version: "2.1",
  hostname: "node-a",
  osName: "linux",
  osVersion: "1",
  cores: 4,
  collectors: 20,
  charts: 100,
  alarmsActive: 0,
  alarmsCritical: 0,
  alarmsWarning: 0,
  claimedToCloud: false,
  mountsOverThreshold: 0,
  ...extra,
});

const netdataSummary = () => ({
  nodes: 1,
  nodesReachable: 1,
  nodesUnreachable: 0,
  nodesDegraded: 0,
  alarmsActive: 0,
  alarmsCritical: 0,
  mountsOverThreshold: 0,
  syncedAt: now(),
});

const trueNasSummary = () => ({
  hostname: "nas",
  version: "25.10",
  pools: 1,
  poolsUnhealthy: 0,
  disks: 1,
  alerts: 1,
  alertsSilenced: 0,
  certificates: 2,
  certificatesExpiringSoon: 1,
  certificatesExpired: 0,
  certificatesWithoutExpiry: 0,
  syncedAt: now(),
});

const firewallaInventory = () => ({
  mspDomain: "synthetic.firewalla.net",
  total: 1,
  online: 1,
  offline: 0,
  deep: 1,
  presence: 0,
  reserved: 1,
  skippedByNetwork: 0,
  excludedNetworks: [],
  machines: 1,
  sshCandidates: 1,
  excluded: 0,
  networks: ["Synthetic"],
  deviceTypes: { desktop: 1 },
  syncedAt: now(),
});

const firewallaDevice = (extra: Json = {}) => ({
  id: "device-a",
  name: "device-a",
  ip: "192.0.2.10",
  mac: "aa:bb:cc:dd:ee:ff",
  macVendor: "Example",
  deviceType: "desktop",
  network: "Synthetic",
  online: true,
  ipReserved: true,
  isRouter: false,
  isFirewalla: false,
  totalDownload: 0,
  totalUpload: 0,
  tier: "deep",
  sshCandidate: true,
  excluded: false,
  ...extra,
});

const firewallaMachine = (extra: Json = {}) => ({
  name: "machine-a",
  primaryIp: "192.0.2.10",
  deviceType: "desktop",
  macVendor: "Example",
  tier: "deep",
  sshCandidate: true,
  online: true,
  networks: ["Synthetic"],
  interfaces: [],
  interfaceCount: 1,
  ...extra,
});

/** A TrueNAS summary describing exactly one alert and nothing else. */
const trueNasAlertOnlySummary = (silenced: number) => ({
  ...trueNasSummary(),
  pools: 0,
  poolsUnhealthy: 0,
  disks: 0,
  alerts: 1,
  alertsSilenced: silenced,
  certificates: 0,
  certificatesExpiringSoon: 0,
  certificatesExpired: 0,
  certificatesWithoutExpiry: 0,
});

const trueNasAlert = (level: string, silenced: boolean) => ({
  id: "alert-1",
  klass: "SyntheticCondition",
  level,
  formatted: "Synthetic condition is active",
  dismissed: silenced,
  silenced,
});

async function trueNasAlertBundle(level: string, silenced: boolean) {
  return await normalize(context("@jpisgeek/truenas", [
    { spec: "alert", name: "alert-1", value: trueNasAlert(level, silenced) },
    {
      spec: "summary",
      name: "summary",
      value: trueNasAlertOnlySummary(silenced ? 1 : 0),
    },
  ]));
}

Deno.test("a dismissed TrueNAS alert still decides state", async () => {
  // The collector sets `silenced` from the TrueNAS `dismissed` flag precisely
  // so the dismissal does NOT hide the condition. Mapping it onto the
  // contract's `suppressed` field put it right back: suppressed exceptions are
  // filtered out of both the section ladder and deriveOverallState, so a
  // dismissed CRITICAL published as a healthy bundle.
  const bundle = await trueNasAlertBundle("CRITICAL", true);
  assertEquals(bundle.state, "critical");
  assertEquals(bundle.sections[0].state, "critical");
  const alert = bundle.sections[0].exceptions.find((e) =>
    e.source === "truenas:alert"
  )!;
  assertEquals(alert.severity, "critical");
  // The property that matters: nothing about this exception may remove it from
  // the state calculation.
  assertEquals(alert.suppressed, false);
  // The dismissal is still reported, just as detail rather than as state.
  assertStringIncludes(alert.detail, "dismissed in the TrueNAS UI");
});

Deno.test("a dismissed warning still takes the section out of healthy", async () => {
  const bundle = await trueNasAlertBundle("WARNING", true);
  assertEquals(bundle.state, "degraded");
});

Deno.test("alert levels outside the mapped vocabulary do not vanish into info", async () => {
  // Every one of these is reachable: truenas.ts types the raw level as
  // `z.string().nullable().optional()` and writes `level: a.level ?? ""`, so a
  // payload missing the key persists as "". The old fall-through classified
  // all of them "info", and info exceptions move neither the section ladder
  // nor the bundle state.
  const cases: Array<[string, string, string]> = [
    ["", "warning", "degraded"],
    ["  ", "warning", "degraded"],
    ["SOMETHING_NEW", "warning", "degraded"],
    ["ERROR", "critical", "critical"],
    ["error", "critical", "critical"],
    ["EMERGENCY", "critical", "critical"],
    ["WARNING", "warning", "degraded"],
    ["CRITICAL", "critical", "critical"],
    // These genuinely mean "not a raised condition" and must stay quiet, or
    // every idle run reads as degraded.
    ["INFO", "info", "healthy"],
    ["NOTICE", "info", "healthy"],
    ["CLEAR", "info", "healthy"],
  ];
  for (const [level, expectedSeverity, expectedState] of cases) {
    const bundle = await trueNasAlertBundle(level, false);
    const alert = bundle.sections[0].exceptions.find((e) =>
      e.source === "truenas:alert"
    )!;
    const label = JSON.stringify(level);
    assertEquals(alert.severity, expectedSeverity, `severity for ${label}`);
    assertEquals(bundle.state, expectedState, `state for ${label}`);
  }
});

Deno.test("an unrecognized alert level is named in the exception detail", async () => {
  const bundle = await trueNasAlertBundle("SOMETHING_NEW", false);
  const alert = bundle.sections[0].exceptions.find((e) =>
    e.source === "truenas:alert"
  )!;
  assertStringIncludes(alert.detail, "unrecognized alert level");
  assertStringIncludes(alert.detail, "SOMETHING_NEW");
  // A level the report does understand must not be annotated.
  const known = await trueNasAlertBundle("WARNING", false);
  const knownAlert = known.sections[0].exceptions.find((e) =>
    e.source === "truenas:alert"
  )!;
  assertEquals(knownAlert.detail.includes("unrecognized"), false);
});

Deno.test("device records contradicting the inventory rollup are surfaced", async () => {
  // firewalla.ts derives inventory.total from the device handle count and
  // increments inventory.online inside the same loop, so these two figures are
  // exact, not approximate. A rollup that disagrees with the device records is
  // real drift and must not be published as a verified reading — nor as any
  // reading at all: an uncorroborated count is emitted as an unavailable
  // metric carrying no value, because a number published beside a "drift"
  // exception is still a number a dashboard will plot.
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    { spec: "device", name: "device-a", value: firewallaDevice() },
    { spec: "machine", name: "machine-a", value: firewallaMachine() },
    {
      spec: "inventory",
      name: "inventory",
      // Internally consistent (online + offline == total, deep + presence ==
      // total) and still contradicted by the single device record.
      value: {
        ...firewallaInventory(),
        total: 4,
        online: 4,
        offline: 0,
        deep: 4,
        presence: 0,
      },
    },
  ]));
  assertEquals(bundle.state, "partial");
  assertEquals(bundle.sections[0].completeness.state, "partial");
  assertEquals(bundle.sections[0].coverage.kind, "unknown");
  const metric = bundle.sections[0].metrics.find((m) =>
    m.id === "devices.online"
  )!;
  assertEquals(metric.availability, "unknown");
  assertEquals("value" in metric, false);
  const drift = bundle.sections[0].exceptions.find((e) =>
    e.source === "firewalla:inventory"
  )!;
  assertStringIncludes(drift.detail, "4/4");
  assertStringIncludes(drift.detail, "1/1");
});

Deno.test("an inventory reporting devices with no device record is drift", async () => {
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    { spec: "machine", name: "machine-a", value: firewallaMachine() },
    { spec: "inventory", name: "inventory", value: firewallaInventory() },
  ]));
  assertEquals(bundle.state, "partial");
  const metric = bundle.sections[0].metrics.find((m) =>
    m.id === "devices.online"
  )!;
  assertEquals(metric.availability, "unknown");
  assertEquals("value" in metric, false);
  assertStringIncludes(metric.reason as string, "unmeasured");
});

Deno.test("corroborated device counts keep the online metric exact", async () => {
  // The negative control: the cross-check must stay quiet on a consistent run,
  // otherwise it is just an always-on alarm and proves nothing above.
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    { spec: "device", name: "device-a", value: firewallaDevice() },
    { spec: "machine", name: "machine-a", value: firewallaMachine() },
    { spec: "inventory", name: "inventory", value: firewallaInventory() },
  ]));
  assertEquals(bundle.state, "healthy");
  assertEquals(bundle.sections[0].completeness.state, "exact");
  const metric = bundle.sections[0].metrics.find((m) =>
    m.id === "devices.online"
  )!;
  assertEquals(metric.confidence, "exact");
});

Deno.test("partial read is explicit and cannot become healthy", async () => {
  const bundle = await normalize(context("@jpisgeek/netdata", [
    { spec: "node", name: "node-a", value: netdataNode() },
    { spec: "alarm", name: "alarm-broken", fail: true },
    { spec: "summary", name: "summary", value: netdataSummary() },
  ]));
  assertEquals(bundle.state, "partial");
  assertEquals(bundle.sections[0].completeness.state, "partial");
  assertEquals(bundle.sections[0].completeness.rejected, 1);
});

Deno.test("missing usedPercent is rejected rather than normalized to zero", async () => {
  const bundle = await normalize(context("@jpisgeek/netdata", [
    { spec: "node", name: "node-a", value: netdataNode() },
    {
      spec: "mount",
      name: "mount-broken",
      value: {
        node: "node-a",
        mount: "/data",
        availGiB: 10,
        usedGiB: 90,
        totalGiB: 100,
        overThreshold: false,
      },
    },
    { spec: "summary", name: "summary", value: netdataSummary() },
  ]));
  assertEquals(bundle.state, "partial");
  assertEquals(bundle.sections[0].metrics.some((m) => m.value === 0), false);
});

Deno.test("certificate alert remains independent without stable identity", async () => {
  const bundle = await normalize(context("@jpisgeek/truenas", [
    {
      spec: "certificate",
      name: "certificate-alpha",
      value: {
        name: "alpha",
        commonName: "alpha.example.com",
        notAfter: "2026-09-01T00:00:00Z",
        daysRemaining: 7,
        expiryKnown: true,
        expiringSoon: true,
        expired: false,
      },
    },
    {
      spec: "certificate",
      name: "certificate-beta",
      value: {
        name: "beta",
        commonName: "beta.example.com",
        notAfter: "2027-09-01T00:00:00Z",
        daysRemaining: 372,
        expiryKnown: true,
        expiringSoon: false,
        expired: false,
      },
    },
    {
      spec: "alert",
      name: "alert-beta",
      value: {
        id: "alert-beta",
        klass: "CertificateIsExpiring",
        level: "WARNING",
        formatted: "Certificate beta is expiring",
        dismissed: false,
        silenced: false,
      },
    },
    {
      spec: "summary",
      name: "summary",
      value: { ...trueNasSummary(), pools: 0, poolsUnhealthy: 0, disks: 0 },
    },
  ]));
  const exceptions = bundle.sections[0].exceptions;
  assertEquals(exceptions.length, 2);
  assertEquals(exceptions.some((e) => e.source === "truenas:alert"), true);
  assertEquals(exceptions.some((e) => e.subject === "alpha"), true);
});

// ---------------------------------------------------------------------------
// Untrusted text must not reach the bundle
// ---------------------------------------------------------------------------

Deno.test("a repository error message is never persisted, only its class", async () => {
  // The read path used to end in `${handle.name}: ${error.message}`. The
  // message belongs to the data repository, is unbounded, and on a real
  // failure carries the storage URL, the path, or the credential that was
  // rejected. Every part of it below is a real shape of a Deno/Swamp read
  // error.
  const bundle = await normalize(context("@jpisgeek/netdata", [
    { spec: "node", name: "node-a", value: netdataNode() },
    {
      spec: "alarm",
      name: "alarm-broken",
      fail:
        `GET https://svc:${SECRET}@store.example.internal/v1/objects failed; ` +
        `no such file or directory: /var/swamp/data/netdata/alarm-broken.json`,
    },
    { spec: "summary", name: "summary", value: netdataSummary() },
  ]));
  // The handle name is a collector-derived resource name and is not published
  // either; the failing record is named by an opaque digest.
  assertAbsent(
    bundle,
    SECRET,
    "store.example.internal",
    "/var/swamp",
    "alarm-broken",
  );
  const rejected = bundle.sections[0].exceptions.find((e) =>
    e.headline === "Collector record rejected"
  )!;
  assertMatch(
    rejected.detail,
    /^record [0-9a-f]{32} rejected: repository-read-failed$/,
  );
});

Deno.test("a node transport error is classified, never quoted", async () => {
  const bundle = await normalize(context("@jpisgeek/netdata", [
    {
      spec: "node",
      name: "node-a",
      value: netdataNode({
        reachable: false,
        error:
          `connect https://collector.example.internal/api/v1/info?api_key=${SECRET} timed out after 5s`,
      }),
    },
    {
      spec: "summary",
      name: "summary",
      value: { ...netdataSummary(), nodesReachable: 0, nodesUnreachable: 1 },
    },
  ]));
  assertAbsent(bundle, SECRET, "collector.example.internal", "api_key");
  assertEquals(
    bundle.sections[0].exceptions[0].detail,
    "node did not answer: request timed out",
  );
});

Deno.test("alarm info prose never reaches the bundle", async () => {
  const bundle = await normalize(context("@jpisgeek/netdata", [
    {
      spec: "alarm",
      name: "alarm-a",
      value: {
        node: "node-a",
        name: "disk_space_usage",
        chart: "disk.space",
        status: "WARNING",
        value: 91.5,
        units: "%",
        info:
          `runbook https://wiki.example.internal/x — mount /srv/backup, token=${SECRET}`,
      },
    },
    {
      spec: "summary",
      name: "summary",
      value: {
        ...netdataSummary(),
        nodes: 0,
        nodesReachable: 0,
        alarmsActive: 1,
      },
    },
  ]));
  assertAbsent(bundle, SECRET, "wiki.example.internal", "/srv/backup");
  const alarm = bundle.sections[0].exceptions.find((e) =>
    e.source === "netdata:alarm"
  )!;
  // The reading survives; the prose does not.
  assertStringIncludes(alarm.detail, "91.5");
  assertEquals(alarm.headline, "disk_space_usage");
});

Deno.test("a formatted TrueNAS alert message never reaches the bundle", async () => {
  const bundle = await normalize(context("@jpisgeek/truenas", [
    {
      spec: "alert",
      name: "alert-1",
      value: {
        ...trueNasAlert("WARNING", false),
        formatted:
          `Replication to backup@nas.example.internal failed: ssh key ${SECRET} rejected (/mnt/tank/private)`,
      },
    },
    { spec: "summary", name: "summary", value: trueNasAlertOnlySummary(0) },
  ]));
  assertAbsent(bundle, SECRET, "nas.example.internal", "/mnt/tank/private");
  const alert = bundle.sections[0].exceptions.find((e) =>
    e.source === "truenas:alert"
  )!;
  assertStringIncludes(alert.detail, "alert severity warning");
});

Deno.test("a source name shaped like a credential is withheld", async () => {
  // Names are the one class of source text that still publishes, so a name is
  // the remaining smuggling channel: an attacker who can set a pool name can
  // set it to a URL with userinfo. The allow-list decides what may pass, so an
  // unanticipated shape fails closed rather than open.
  const bundle = await normalize(context("@jpisgeek/truenas", [
    {
      spec: "pool",
      name: "pool-a",
      value: {
        name: `https://root:${SECRET}@nas.example.internal/pool`,
        status: "DEGRADED",
        healthy: false,
        allocatedBytes: 1,
        freeBytes: 1,
        sizeBytes: 2,
        usedPercent: 50,
        fragmentationPercent: 0,
      },
    },
    {
      spec: "summary",
      name: "summary",
      value: {
        ...trueNasSummary(),
        pools: 1,
        poolsUnhealthy: 1,
        disks: 0,
        alerts: 0,
        certificates: 0,
        certificatesExpiringSoon: 0,
      },
    },
  ]));
  // Not just the exception subject: the pool name also feeds the metric id's
  // readability slug, which lowercases rather than redacts.
  assertAbsent(bundle, SECRET, "nas.example.internal");
  const pool = bundle.sections[0].exceptions.find((e) =>
    e.source === "truenas:pool"
  )!;
  assertStringIncludes(pool.subject, "withheld");
});

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/**
 * One unreachable node and a summary that disagrees with the records, so every
 * bundle below carries both a per-record exception and a section-wide one.
 */
function netdataInstance(modelId: string, nodeName: string) {
  return {
    ...context("@jpisgeek/netdata", [
      {
        spec: "node",
        name: "node",
        value: netdataNode({ name: nodeName, reachable: false }),
      },
      {
        spec: "summary",
        name: "summary",
        value: {
          ...netdataSummary(),
          nodes: 5,
          nodesReachable: 0,
          nodesUnreachable: 1,
        },
      },
    ]),
    modelId,
  };
}

Deno.test("two collectors of the same type do not share identities", async () => {
  // The bundle id was `${section.id}-observability` — one fixed string per
  // collector TYPE. A production Netdata and a lab Netdata published the same
  // bundle id on every run, so a consumer keyed by bundle id kept one history
  // for both and each run silently overwrote the other. The same held for
  // every record id, which was derived from record fields alone.
  const a = await normalize(netdataInstance("model-a", "node-a"));
  const b = await normalize(netdataInstance("model-b", "node-a"));
  assertNotEquals(a.id, b.id);
  assertMatch(a.id, /^netdata-observability:[0-9a-f]{32}$/);
  assertMatch(b.id, /^netdata-observability:[0-9a-f]{32}$/);
  // Same inputs, different producer: no identifier may be shared, including
  // the section-wide ones that used to be one hard-coded string per collector
  // type.
  const idsOf = (bundle: typeof a) =>
    new Set(bundle.sections[0].exceptions.map((e) => e.id));
  assertNotEquals(idsOf(a).size, 0);
  assertEquals(idsOf(a).size, idsOf(b).size);
  for (const id of idsOf(a)) assertEquals(idsOf(b).has(id), false, id);
  // And the same producer is stable across runs, or history never accumulates.
  const again = await normalize(netdataInstance("model-a", "node-a"));
  assertEquals(again.id, a.id);
  assertEquals(
    again.sections[0].exceptions.map((e) => e.id),
    a.sections[0].exceptions.map((e) => e.id),
  );
});

Deno.test("the private model ID is not published", async () => {
  const bundle = await normalize(netdataInstance("private-model-id-42", "n"));
  assertAbsent(bundle, "private-model-id-42");
  assertEquals("modelId" in bundle.producer, false);
});

Deno.test("record identity is length-prefixed, so fields cannot be traded", async () => {
  // Two different alarms whose (node, chart) tuples differ only in where the
  // boundary falls. Any identity built by concatenating the parts — with any
  // separator the parts are allowed to contain — gives both the same id, and
  // then one alarm's history overwrites the other's.
  //
  // This one is a property guard rather than a repair: the previous
  // implementation already length-prefixed its tuple, and what it lacked was
  // the producer namespace, a collision-resistant digest and collision
  // detection (the three tests around this one). The property is asserted
  // directly so a future "simplification" back to a separator join fails here.
  const alarmId = async (node: string, chart: string) => {
    const bundle = await normalize(context("@jpisgeek/netdata", [
      {
        spec: "alarm",
        name: "alarm",
        value: {
          node,
          name: "x",
          chart,
          status: "WARNING",
          value: 1,
          units: "%",
          info: "",
        },
      },
      {
        spec: "summary",
        name: "summary",
        value: {
          ...netdataSummary(),
          nodes: 0,
          nodesReachable: 0,
          alarmsActive: 1,
        },
      },
    ]));
    return bundle.sections[0].exceptions.find((e) =>
      e.source === "netdata:alarm"
    )!.id;
  };
  assertNotEquals(await alarmId("ab", "c"), await alarmId("a", "bc"));
  assertNotEquals(await alarmId("a-b", "c"), await alarmId("a", "b-c"));
  assertNotEquals(await alarmId("", "abc"), await alarmId("abc", ""));
});

Deno.test("records the source cannot distinguish still get distinct ids", async () => {
  // Two alerts carrying the same TrueNAS alert id. They hash identically and
  // legitimately, so collision resistance cannot help; without detection one
  // exception would take the other's key and a consumer would keep one.
  const bundle = await normalize(context("@jpisgeek/truenas", [
    { spec: "alert", name: "alert-1", value: trueNasAlert("WARNING", false) },
    { spec: "alert", name: "alert-2", value: trueNasAlert("WARNING", false) },
    {
      spec: "summary",
      name: "summary",
      value: { ...trueNasAlertOnlySummary(0), alerts: 2 },
    },
  ]));
  const alerts = bundle.sections[0].exceptions.filter((e) =>
    e.source === "truenas:alert"
  );
  assertEquals(alerts.length, 2);
  assertNotEquals(alerts[0].id, alerts[1].id);
});

// ---------------------------------------------------------------------------
// Impossible and unmeasured inventory counts
// ---------------------------------------------------------------------------

Deno.test("an impossible inventory count is rejected, not published", async () => {
  // The review's example: `online: 5, total: 0` rendered as "5/0 devices
  // online" under a healthy state. A count of things is a nonnegative integer
  // and online + offline is the total; a payload that says otherwise is
  // corrupt or forged, and there is no honest way to publish it.
  const impossible: Json[] = [
    { total: 0, online: 5, offline: 0, deep: 0, presence: 0, machines: 0 },
    { total: -1, online: 0, offline: -1, deep: 0, presence: -1, machines: 0 },
    {
      total: 1.5,
      online: 1.5,
      offline: 0,
      deep: 1.5,
      presence: 0,
      machines: 0,
    },
    { total: 2, online: 2, offline: 2, deep: 2, presence: 0, machines: 0 },
    { total: 1, online: 1, offline: 0, deep: 1, presence: 0, machines: 9 },
  ];
  for (const counts of impossible) {
    const bundle = await normalize(context("@jpisgeek/firewalla", [
      {
        spec: "inventory",
        name: "inventory",
        value: { ...firewallaInventory(), ...counts, deviceTypes: {} },
      },
    ]));
    const label = JSON.stringify(counts);
    assertEquals(
      bundle.sections[0].summary,
      "Firewalla inventory unavailable",
      label,
    );
    assertNotEquals(bundle.state, "healthy", label);
    assertEquals(bundle.sections[0].metrics.length, 0, label);
    assertEquals(JSON.stringify(bundle).includes("5/0"), false, label);
  }
});

Deno.test("no device records is unmeasured, not a healthy zero", async () => {
  // Zero devices and zero device records are indistinguishable from a device
  // scan whose handles never landed. Publishing `value: 0` at confidence
  // "exact" under a healthy state turns a lost scan into an all-clear.
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    {
      spec: "inventory",
      name: "inventory",
      value: {
        ...firewallaInventory(),
        machines: 0,
        total: 0,
        online: 0,
        offline: 0,
        deep: 0,
        presence: 0,
        reserved: 0,
        sshCandidates: 0,
        deviceTypes: {},
      },
    },
  ]));
  assertNotEquals(bundle.state, "healthy");
  assertEquals(bundle.sections[0].coverage.kind, "unknown");
  assertEquals(bundle.sections[0].completeness.state, "partial");
  const metric = bundle.sections[0].metrics.find((m) =>
    m.id === "devices.online"
  )!;
  assertEquals(metric.availability, "unknown");
  // Not "zero online devices" — no number at all.
  assertEquals("value" in metric, false);
  assertEquals(bundle.sections[0].summary.includes("0/0"), false);
  assertStringIncludes(bundle.sections[0].summary, "unmeasured");
  assertEquals(
    bundle.sections[0].exceptions.some((e) =>
      e.headline === "Device coverage unmeasured"
    ),
    true,
  );
});

// ---------------------------------------------------------------------------
// Documentation and sensitivity metadata
// ---------------------------------------------------------------------------

Deno.test("the bundle declares the fields it emits, and the README lists them", async () => {
  // The Security section used to claim errors carry "resource names and
  // validation classes" while the code emitted raw repository errors, and the
  // sensitivity block claimed `fields: []`, `redacted: false` — that nothing
  // sensitive was present and nothing was withheld. Both are checkable.
  const readme = await Deno.readTextFile(
    new URL("./README.md", import.meta.url),
  );
  const bundles = [
    await normalize(context("@jpisgeek/netdata", [])),
    await normalize(context("@jpisgeek/truenas", [])),
    await normalize(context("@jpisgeek/firewalla", [])),
  ];
  for (const bundle of bundles) {
    assertEquals(bundle.sensitivity.redacted, true);
    assertNotEquals(bundle.sensitivity.fields.length, 0);
    const section = bundle.sections[0];
    assertEquals(section.sensitivity.redacted, true);
    assertNotEquals(section.sensitivity.fields.length, 0);
    for (const field of section.sensitivity.fields) {
      assertStringIncludes(readme, field);
    }
  }
  // Producer metadata is exactly what the README says it is.
  assertEquals(Object.keys(bundles[0].producer).sort(), [
    "dataName",
    "extension",
    "extensionVersion",
    "modelName",
    "modelType",
    "reportName",
  ]);
});

Deno.test("scalar machine networks is rejected without aborting", async () => {
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    {
      spec: "machine",
      name: "machine-broken",
      value: {
        name: "machine-a",
        primaryIp: "192.0.2.10",
        deviceType: "desktop",
        macVendor: "Example",
        tier: "deep",
        sshCandidate: true,
        online: true,
        networks: "Synthetic",
        interfaces: [],
        interfaceCount: 1,
      },
    },
    { spec: "inventory", name: "inventory", value: firewallaInventory() },
  ]));
  assertEquals(bundle.state, "partial");
  assertEquals(
    bundle.sections[0].exceptions[0].headline,
    "Collector record rejected",
  );
  // The reason is one of the enumerated classes, and Zod's own message — which
  // quotes the received value — is not in it.
  assertMatch(
    bundle.sections[0].exceptions[0].detail,
    /^record [0-9a-f]{32} rejected: schema-validation-failed$/,
  );
  assertAbsent(bundle, "machine-broken");
});

Deno.test("valid synthetic signals survive normalization", async () => {
  const bundle = await normalize(context("@jpisgeek/netdata", [
    {
      spec: "node",
      name: "node-a",
      value: netdataNode({ reachable: false, error: "timed out" }),
    },
    {
      spec: "summary",
      name: "summary",
      value: { ...netdataSummary(), nodesReachable: 0, nodesUnreachable: 1 },
    },
  ]));
  assertEquals(bundle.state, "critical");
  assertStringIncludes(
    bundle.sections[0].exceptions[0].headline,
    "unreachable",
  );
});

Deno.test("filtered Firewalla coverage declares its scope", async () => {
  // The inventory has to report zero devices as well as zero machines. An
  // inventory claiming devices with no device record alongside it is now
  // coverage drift, which is the point of the device cross-check below; this
  // fixture is about the filter declaration, so it states an empty run.
  //
  // An empty run is NOT a healthy run: see the unmeasured-coverage test below.
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    {
      spec: "inventory",
      name: "inventory",
      value: {
        ...firewallaInventory(),
        machines: 0,
        total: 0,
        online: 0,
        offline: 0,
        deep: 0,
        presence: 0,
        reserved: 0,
        sshCandidates: 0,
        deviceTypes: {},
      },
    },
  ], { network: "Synthetic" }));
  assertEquals(bundle.state, "partial");
  assertEquals(bundle.sections[0].coverage.scope, "requested collector filter");
});

Deno.test("summary counts without matching records make coverage partial", async () => {
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    { spec: "inventory", name: "inventory", value: firewallaInventory() },
  ]));
  assertEquals(bundle.state, "partial");
  assertEquals(bundle.sections[0].completeness.state, "partial");
  assertEquals(
    bundle.sections[0].exceptions[0].headline,
    "Inventory and record coverage differ",
  );
});

Deno.test("collector-side Firewalla exclusions declare filtered coverage", async () => {
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    {
      spec: "inventory",
      name: "inventory",
      value: {
        ...firewallaInventory(),
        machines: 0,
        skippedByNetwork: 1,
        excludedNetworks: ["Guest"],
      },
    },
  ]));
  assertEquals(bundle.sections[0].coverage.scope, "requested collector filter");
});

Deno.test("unsupported model types fail closed", async () => {
  await assertRejects(
    () => normalize(context("@jpisgeek/other", [])),
    Error,
    "unsupported homelab collector type",
  );
});

Deno.test("authorization failures are explicit and raw errors are not persisted", async () => {
  const ctx = context("@jpisgeek/truenas", []);
  const failed = {
    ...ctx,
    executionStatus: "failed" as const,
    errorMessage: "401 unauthorized for secret-token-value",
  };
  const bundle = await normalize(failed);
  assertEquals(bundle.state, "unauthorized");
  assertEquals(JSON.stringify(bundle).includes("secret-token-value"), false);
});

Deno.test("report emits the exact persisted JSON contract name", async () => {
  const result = await report.execute(context("@jpisgeek/netdata", [
    { spec: "node", name: "node-a", value: netdataNode() },
    { spec: "summary", name: "summary", value: netdataSummary() },
  ]));
  assertEquals(
    result.json.producer.dataName,
    "report-jpisgeek-dashboard-homelab-json",
  );
  assertStringIncludes(result.markdown, "State");
});

Deno.test("live coercible ModelType values select the correct adapter", async () => {
  const base = context("@jpisgeek/netdata", [
    { spec: "node", name: "node-a", value: netdataNode() },
    { spec: "summary", name: "summary", value: netdataSummary() },
  ]);
  const liveLike = {
    ...base,
    modelType: { toString: () => "@jpisgeek/netdata" },
  };
  const bundle = await normalize(liveLike);
  assertEquals(bundle.sections[0].id, "netdata");
});

Deno.test("published entry point contains the canonical contract verbatim", async () => {
  const entry = await Deno.readTextFile(
    new URL("./dashboard_homelab.ts", import.meta.url),
  );
  const canonical = await Deno.readTextFile(
    new URL("../dashboard-contract/dashboard_bundle.ts", import.meta.url),
  );
  const inlined = entry.split("// BEGIN INLINED DASHBOARD CONTRACT V1\n")[1]
    .split("// END INLINED DASHBOARD CONTRACT V1")[0].trim();
  const canonicalBody = canonical.slice(
    canonical.indexOf("/** Current bundle schema version"),
  ).trim();
  assertEquals(inlined, canonicalBody);
});

// ---------------------------------------------------------------------------
// Second review round: text with no validation, rollups with no cardinality,
// identities with no uniqueness
// ---------------------------------------------------------------------------

Deno.test("the operator-chosen model definition name is validated like any other name", async () => {
  // `ctx.definition.name` was the one source-controlled string in the file that
  // reached the bundle untouched — into `producer.modelName` and into the
  // subject of every source-failure exception. Swamp does not constrain a model
  // definition name, so it is free-form operator text, and a definition named
  // after the endpoint it polls carries that endpoint's query string with it.
  const base = context("@jpisgeek/truenas", [
    { spec: "unrecognized", name: "stray-handle", value: { a: 1 } },
  ]);
  const bundle = await normalize({
    ...base,
    definition: { name: `truenas?token=${SECRET}`, version: 1 },
  });
  assertAbsent(bundle, SECRET);
  assertStringIncludes(bundle.producer.modelName as string, "withheld");
  const rejected = bundle.sections[0].exceptions.find((e) =>
    e.headline === "Collector record rejected"
  )!;
  assertStringIncludes(rejected.subject, "withheld");
});

Deno.test("an unsupported collector type is not echoed back in the thrown error", async () => {
  // `modelType` is `String(ctx.modelType)` off a caller-supplied model object.
  // Interpolating it into the guard's message made the guard an echo: the
  // rejected value lands in the Swamp run log and in any caller that renders
  // the message.
  const error = await assertRejects(
    () => normalize(context(`@jpisgeek/${SECRET}`, [])),
    Error,
    "unsupported homelab collector type",
  );
  assertEquals(
    error.message.toLowerCase().includes(SECRET.toLowerCase()),
    false,
  );
});

Deno.test("duplicate pool names do not collapse onto one metric id", async () => {
  // The pool metric id is derived from the pool name alone, so two pool
  // records reported under one name produced byte-identical ids and a consumer
  // keyed by metric id kept one utilization series. Duplicate detection was
  // applied to exceptions but not to metrics.
  const pool = (usedPercent: number) => ({
    name: "tank",
    status: "ONLINE",
    healthy: true,
    allocatedBytes: 1,
    freeBytes: 1,
    sizeBytes: 2,
    usedPercent,
    fragmentationPercent: 0,
  });
  const bundle = await normalize(context("@jpisgeek/truenas", [
    { spec: "pool", name: "pool-1", value: pool(50) },
    { spec: "pool", name: "pool-2", value: pool(91) },
    {
      spec: "summary",
      name: "summary",
      value: {
        ...trueNasSummary(),
        pools: 2,
        poolsUnhealthy: 0,
        disks: 0,
        alerts: 0,
        certificates: 0,
        certificatesExpiringSoon: 0,
      },
    },
  ]));
  const metrics = bundle.sections[0].metrics;
  assertEquals(metrics.length, 2);
  assertNotEquals(metrics[0].id, metrics[1].id);
});

Deno.test("a second rollup record is rejected coverage, not a silent discard", async () => {
  // `records.summary[0]` cannot tell "no rollup" from "two rollups": it
  // believes the first and drops the rest, so the section published a healthy,
  // fresh, exact headline off one rollup while a contradicting second rollup
  // sat beside it in the same execution.
  const bundle = await normalize(context("@jpisgeek/netdata", [
    { spec: "node", name: "node-a", value: netdataNode() },
    { spec: "summary", name: "summary-a", value: netdataSummary() },
    {
      spec: "summary",
      name: "summary-b",
      value: {
        ...netdataSummary(),
        nodes: 9,
        nodesReachable: 0,
        nodesUnreachable: 9,
      },
    },
  ]));
  const section = bundle.sections[0];
  assertEquals(section.summary, "Netdata summary unavailable");
  assertEquals(section.completeness.state, "partial");
  assertEquals(section.freshness.state, "unknown");
});

Deno.test("an evidence URL carrying credentials is rejected by the public schema", () => {
  // `https://user:pass@host/` is a valid https URL, so a protocol-only check
  // accepted a reference whose credential sits in the authority — and this
  // schema is the published parser, so the reference is persisted, rendered as
  // a link, and sent in a Referer header.
  const reference = (url: string) => ({ kind: "url", label: "run log", url });
  assertEquals(
    EvidenceReferenceSchema.safeParse(reference("https://example.com/run"))
      .success,
    true,
  );
  assertEquals(
    EvidenceReferenceSchema.safeParse(
      reference(`https://svc:${SECRET}@example.com/run`),
    ).success,
    false,
  );
  assertEquals(
    EvidenceReferenceSchema.safeParse(
      reference(`https://${SECRET}@example.com/run`),
    ).success,
    false,
  );
});

Deno.test("emitted source fields are declared under their real record keys", async () => {
  // The sensitivity block is the machine-readable half of the README's "that is
  // the whole list" claim, so a field the code emits and the list omits makes
  // both wrong. `mount.path` was worse than an omission: the mount record has
  // no `path` key at all, so the list could not be diffed against the collector.
  const netdata = await normalize(context("@jpisgeek/netdata", [
    {
      spec: "mount",
      name: "mount-a",
      value: {
        node: "node-a",
        mount: "/srv",
        availGiB: 1,
        usedGiB: 9,
        totalGiB: 10,
        usedPercent: 90,
        overThreshold: true,
      },
    },
    {
      spec: "alarm",
      name: "alarm-a",
      value: {
        node: "node-a",
        name: "cpu",
        chart: "system.cpu",
        status: "SOMETHING_NEW",
        value: 1,
        units: "%",
        info: "alarm template prose",
      },
    },
  ]));
  const netdataFields = netdata.sections[0].sensitivity.fields;
  assertEquals(netdataFields.includes("mount.path"), false);
  assertEquals(netdataFields.includes("mount.mount"), true);
  assertEquals(netdataFields.includes("mount.usedPercent"), true);
  assertEquals(netdataFields.includes("alarm.status"), true);
  // The values those entries account for really are published.
  const alarm = netdata.sections[0].exceptions.find((e) =>
    e.source === "netdata:alarm"
  )!;
  assertStringIncludes(alarm.detail, "SOMETHING_NEW");
  const mount = netdata.sections[0].exceptions.find((e) =>
    e.source === "netdata:mount"
  )!;
  assertStringIncludes(mount.detail, "/srv");
  assertStringIncludes(mount.detail, "90");

  const truenas = await trueNasAlertBundle("SOMETHING_NEW", true);
  const truenasFields = truenas.sections[0].sensitivity.fields;
  assertEquals(truenasFields.includes("alert.level"), true);
  assertEquals(truenasFields.includes("alert.silenced"), true);
  const alert = truenas.sections[0].exceptions.find((e) =>
    e.source === "truenas:alert"
  )!;
  assertStringIncludes(alert.detail, "SOMETHING_NEW");
  assertStringIncludes(alert.detail, "dismissed in the TrueNAS UI");
});
