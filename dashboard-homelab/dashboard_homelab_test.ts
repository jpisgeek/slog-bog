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
  const bundle = await normalize(context("@jpisgeek/firewalla", [
    {
      spec: "inventory",
      name: "inventory",
      value: { ...firewallaInventory(), machines: 0 },
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
    "Inventory and machine coverage differ",
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
