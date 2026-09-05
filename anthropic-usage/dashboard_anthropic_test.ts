import { assertEquals } from "jsr:@std/assert@1";
import { normalize } from "./dashboard_anthropic.ts";
type Json = Record<string, unknown>;
const status = (state = "complete", errorKind = "", message = "") => ({
  state,
  pagesRead: state === "complete" ? 1 : 0,
  errorKind,
  message,
});
function snapshot(overrides: Json = {}): Json {
  return {
    provider: "anthropic",
    accountKind: "platform",
    collectedAt: "2026-08-25T20:00:00.000Z",
    coverageStart: "2026-08-01T00:00:00.000Z",
    coverageEnd: "2026-08-25T00:00:00.000Z",
    usageRefreshedAt: null,
    usageRefreshState: "absent",
    costRefreshedAt: null,
    costRefreshState: "absent",
    usageStatus: status(),
    costStatus: status(),
    usage: {
      uncachedInputTokens: 10,
      cacheCreation5mTokens: 2,
      cacheCreation1hTokens: 3,
      cacheReadTokens: 4,
      outputTokens: 5,
      requests: null,
      breakdowns: [{
        product: null,
        model: "claude-example",
        workspaceId: "wrkspc_example",
        uncachedInputTokens: 10,
        cacheCreation5mTokens: 2,
        cacheCreation1hTokens: 3,
        cacheReadTokens: 4,
        outputTokens: 5,
        requests: null,
      }],
      groupedTop100Cap: false,
    },
    costs: {
      totals: [{ currency: "USD", amountMinor: "1.25" }],
      breakdowns: [{
        product: null,
        model: "claude-example",
        workspaceId: "wrkspc_example",
        description: "example",
        amountMinor: "1.25",
        currency: "USD",
      }],
      groupedTop100Cap: false,
    },
    ...overrides,
  };
}
function context(value: Json | null) {
  const bytes = value ? new TextEncoder().encode(JSON.stringify(value)) : null;
  return {
    scope: "method" as const,
    modelType: { toString: () => "@jpisgeek/anthropic-usage" },
    modelId: "synthetic",
    definition: { name: "anthropic-example", version: 1 },
    methodName: "collect",
    executionStatus: "succeeded" as const,
    dataHandles: value
      ? [{ name: "organization-usage", specName: "snapshot", version: 1 }]
      : [],
    dataRepository: { getContent: () => Promise.resolve(bytes) },
  };
}
Deno.test("report contains canonical contract verbatim", async () => {
  const entry = await Deno.readTextFile(
    new URL("./dashboard_anthropic.ts", import.meta.url),
  );
  const canonical = await Deno.readTextFile(
    new URL("../dashboard-contract/dashboard_bundle.ts", import.meta.url),
  );
  assertEquals(
    entry.split("// BEGIN INLINED DASHBOARD CONTRACT V1\n")[1].split(
      "// END INLINED DASHBOARD CONTRACT V1",
    )[0].trim(),
    canonical.trim(),
  );
});
Deno.test("platform request count is unsupported without harming exact tokens", async () => {
  const bundle = await normalize(context(snapshot()));
  assertEquals(bundle.state, "healthy");
  assertEquals(
    bundle.sections[0].metrics.find((m) => m.id === "requests")?.availability,
    "unsupported",
  );
  assertEquals(
    bundle.sections[0].metrics.find((m) => m.id === "output-tokens")?.value,
    5,
  );
});
const enterpriseUsage = (groupedTop100Cap: boolean) => ({
  uncachedInputTokens: 10,
  cacheCreation5mTokens: 0,
  cacheCreation1hTokens: 0,
  cacheReadTokens: 0,
  outputTokens: 5,
  requests: 2,
  breakdowns: [{
    product: "claude_code",
    model: "claude-example",
    workspaceId: null,
    uncachedInputTokens: 10,
    cacheCreation5mTokens: 0,
    cacheCreation1hTokens: 0,
    cacheReadTokens: 0,
    outputTokens: 5,
    requests: 2,
  }],
  groupedTop100Cap,
});
const enterpriseCosts = (groupedTop100Cap: boolean) => ({
  totals: [{ currency: "USD", amountMinor: "125" }],
  breakdowns: [{
    product: "claude_code",
    model: "claude-example",
    workspaceId: null,
    description: null,
    amountMinor: "125",
    currency: "USD",
  }],
  groupedTop100Cap,
});
Deno.test("an observed grouped cap forces partial coverage", async () => {
  const bundle = await normalize(context(snapshot({
    accountKind: "enterprise",
    usage: enterpriseUsage(true),
    costs: enterpriseCosts(true),
  })));
  assertEquals(bundle.state, "partial");
  assertEquals(
    bundle.sections.every((s) => s.completeness.state === "partial"),
    true,
  );
  assertEquals(
    (bundle.extensions["jpisgeek/anthropic-usage"] as Json)
      .groupedEnterpriseTop100Cap,
    true,
  );
});
// The collector used to set groupedTop100Cap from accountKind alone, so a
// complete Enterprise result arrived here flagged as truncated and the
// dashboard degraded it to partial with a standing warning exception. A cap
// flag that is always on for Enterprise trains operators to ignore the warning.
Deno.test("a complete enterprise result stays healthy and raises no cap warning", async () => {
  const bundle = await normalize(context(snapshot({
    accountKind: "enterprise",
    usage: enterpriseUsage(false),
    costs: enterpriseCosts(false),
  })));
  assertEquals(bundle.state, "healthy");
  assertEquals(
    bundle.sections.every((s) => s.completeness.state === "exact"),
    true,
  );
  assertEquals(bundle.sections.every((s) => s.exceptions.length === 0), true);
  assertEquals(
    bundle.sections.every((s) => s.coverage.kind === "exact"),
    true,
  );
  assertEquals(
    (bundle.extensions["jpisgeek/anthropic-usage"] as Json)
      .groupedEnterpriseTop100Cap,
    false,
  );
});
// The API reports fractional cents, which must not be labelled dollars.
Deno.test("cost summary and metrics explicitly state minor units", async () => {
  const bundle = await normalize(context(snapshot()));
  assertEquals(bundle.sections[1].summary, "1.25 USD minor units");
  assertEquals(
    bundle.sections[1].metrics.find((m) => m.id === "cost-usd")?.value,
    1.25,
  );
});
Deno.test("authorization and unsupported capabilities remain distinct", async () => {
  const unauthorized = await normalize(
    context(
      snapshot({
        usage: null,
        usageStatus: status("unavailable", "unauthorized", "rejected"),
      }),
    ),
  );
  assertEquals(unauthorized.sections[0].state, "unauthorized");
  const unsupported = await normalize(
    context(
      snapshot({
        usage: null,
        usageStatus: status("unsupported", "unsupported", "not available"),
      }),
    ),
  );
  assertEquals(unsupported.sections[0].state, "unsupported");
});

Deno.test("successful-prefix failures retain authorization and capability state", async () => {
  const unauthorized = await normalize(context(snapshot({
    usageStatus: status("partial", "unauthorized", "rejected"),
  })));
  assertEquals(unauthorized.sections[0].state, "unauthorized");
  assertEquals(unauthorized.sections[0].exceptions[0].severity, "critical");

  const unsupported = await normalize(context(snapshot({
    costStatus: status("partial", "unsupported", "not available"),
  })));
  assertEquals(unsupported.sections[1].state, "unsupported");
});
Deno.test("missing cost currency is unknown rather than zero", async () => {
  const bundle = await normalize(
    context(
      snapshot({
        costs: { totals: [], breakdowns: [], groupedTop100Cap: false },
      }),
    ),
  );
  assertEquals(bundle.sections[1].state, "unknown");
  assertEquals(bundle.sections[1].metrics[0].availability, "unknown");
  assertEquals("value" in bundle.sections[1].metrics[0], false);
});
// A present-but-unusable data_refreshed_at used to be discarded by the
// collector, after which `observedAt: s.dataRefreshedAt ?? s.collectedAt` made
// the section fresh as of collection time. Malformed freshness evidence became
// a healthy dashboard.
Deno.test("unreadable vendor refresh evidence is never rendered as a fresh observation", async () => {
  const bundle = await normalize(
    context(
      snapshot({
        usageRefreshedAt: null,
        usageRefreshState: "invalid",
        costRefreshedAt: null,
        costRefreshState: "invalid",
      }),
    ),
  );
  for (const section of bundle.sections) {
    assertEquals(section.freshness.state, "unknown");
    assertEquals("observedAt" in section.freshness, false);
    assertEquals(section.state === "healthy", false);
    assertEquals(
      section.exceptions.some((e) =>
        e.id === "anthropic:refresh:invalid-response"
      ),
      true,
    );
  }
  assertEquals(bundle.state === "healthy", false);
});
Deno.test("observed refresh evidence is the vendor timestamp, not collection time", async () => {
  const bundle = await normalize(context(snapshot({
    usageRefreshedAt: "2026-08-24T06:00:00.000Z",
    usageRefreshState: "observed",
  })));
  assertEquals(bundle.sections[0].freshness.state, "fresh");
  assertEquals(
    bundle.sections[0].freshness.observedAt,
    "2026-08-24T06:00:00.000Z",
  );
  assertEquals(bundle.state, "healthy");
});
// Absent is the third case: collection time is still the honest observation
// time, and the bundle now says that is what it is rather than passing it off
// as Anthropic's own refresh time.
Deno.test("absent refresh evidence is labelled as collection time", async () => {
  const bundle = await normalize(context(snapshot()));
  assertEquals(bundle.sections[0].freshness.state, "fresh");
  assertEquals(
    bundle.sections[0].freshness.observedAt,
    "2026-08-25T20:00:00.000Z",
  );
  assertEquals(
    (bundle.sections[0].freshness.reason ?? "").includes("collection time"),
    true,
  );
});
// A snapshot that cannot state which of the three refresh cases it is cannot be
// rendered honestly, so it is not rendered at all.
Deno.test("a snapshot without an explicit refresh state is not rendered", async () => {
  const legacy = snapshot();
  delete legacy.usageRefreshState;
  const bundle = await normalize(context(legacy));
  assertEquals(bundle.state, "unknown");
  assertEquals(
    bundle.sections.every((s) => s.metrics[0].availability === "unknown"),
    true,
  );
});
// producer.modelName and producer.modelId are the operator's own Swamp model
// name and instance ID. They are written into the exportable JSON, so the
// bundle's sensitivity field list has to name them.
Deno.test("producer identifiers are disclosed in bundle sensitivity", async () => {
  const bundle = await normalize(context(snapshot()));
  assertEquals(bundle.producer.modelName, "anthropic-example");
  assertEquals(bundle.producer.modelId, "synthetic");
  for (const field of ["producer.modelName", "producer.modelId"]) {
    assertEquals(bundle.sensitivity.fields.includes(field), true);
  }
  assertEquals(
    (bundle.sensitivity.note ?? "").includes("Swamp model"),
    true,
  );
});
Deno.test("missing snapshot exposes both coverage gaps", async () => {
  const bundle = await normalize(context(null));
  assertEquals(bundle.state, "unknown");
  assertEquals(
    bundle.sections.every((s) => s.metrics[0].availability === "unknown"),
    true,
  );
});

Deno.test("a high-precision minor-unit cost never becomes a rounded exact metric", async () => {
  const value = snapshot();
  const exact = "999999999999999.9999";
  (value.costs as Json).totals = [{ currency: "USD", amountMinor: exact }];
  ((value.costs as Json).breakdowns as Json[])[0].amountMinor = exact;
  const bundle = await normalize(context(value));
  const cost = bundle.sections[1];
  assertEquals(cost.summary, `${exact} USD minor units`);
  assertEquals(cost.metrics[0].unit, "custom:currency-minor");
  assertEquals(cost.metrics[0].availability, "unknown");
  assertEquals("value" in cost.metrics[0], false);
  assertEquals(cost.facts.find((f) => f.id === "cost-usd-exact")?.value, exact);
});

Deno.test("cost freshness never inherits the usage endpoint timestamp", async () => {
  const bundle = await normalize(context(snapshot({
    usageRefreshState: "observed",
    usageRefreshedAt: "2026-08-24T06:00:00.000Z",
    costRefreshState: "invalid",
    costRefreshedAt: null,
  })));
  assertEquals(bundle.sections[0].freshness.state, "fresh");
  assertEquals(bundle.sections[1].freshness.state, "unknown");
  assertEquals("observedAt" in bundle.sections[1].freshness, false);
});

Deno.test("bundle IDs retain distinct Platform and Enterprise instances across reruns", async () => {
  const platform = { ...context(snapshot()), modelId: "EXAMPLE_PLATFORM" };
  const enterprise = {
    ...context(snapshot({
      accountKind: "enterprise",
      usage: enterpriseUsage(false),
      costs: enterpriseCosts(false),
    })),
    modelId: "EXAMPLE_ENTERPRISE",
  };
  const [a, b, rerun] = await Promise.all([
    normalize(platform),
    normalize(enterprise),
    normalize({
      ...platform,
      definition: { name: "renamed-example", version: 2 },
    }),
  ]);
  assertEquals(a.id === b.id, false);
  assertEquals(a.id, rerun.id);
  assertEquals(/^anthropic-organization-[a-f0-9]{64}$/.test(a.id), true);
  assertEquals(a.id.includes(platform.modelId), false);
  const byId = new Map([a, b].map((bundle) => [bundle.id, bundle]));
  assertEquals(byId.size, 2);
  assertEquals(byId.get(a.id)?.producer.modelId, platform.modelId);
  assertEquals(byId.get(b.id)?.producer.modelId, enterprise.modelId);
});
