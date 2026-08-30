import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { normalize, report } from "./dashboard_homelab.ts";

type Json = Record<string, unknown>;

function context(
  modelType: string,
  artifacts: Array<
    { spec: string; name: string; value?: Json; fail?: boolean }
  >,
  methodArgs: Json = {},
) {
  const encoded = new Map(
    artifacts.filter((a) => a.value).map((a) => [
      a.name,
      new TextEncoder().encode(JSON.stringify(a.value)),
    ]),
  );
  const failures = new Set(artifacts.filter((a) => a.fail).map((a) => a.name));
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
        if (failures.has(name)) throw new Error("synthetic partial read");
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
  // real drift and must not be published as a verified reading.
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    { spec: "device", name: "device-a", value: firewallaDevice() },
    { spec: "machine", name: "machine-a", value: firewallaMachine() },
    {
      spec: "inventory",
      name: "inventory",
      value: { ...firewallaInventory(), total: 4, online: 4, offline: 0 },
    },
  ]));
  assertEquals(bundle.state, "partial");
  assertEquals(bundle.sections[0].completeness.state, "partial");
  const metric = bundle.sections[0].metrics.find((m) =>
    m.id === "devices.online"
  )!;
  assertEquals(metric.confidence, "inferred");
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
  assertEquals(metric.confidence, "inferred");
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
  assertEquals(bundle.state, "healthy");
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
