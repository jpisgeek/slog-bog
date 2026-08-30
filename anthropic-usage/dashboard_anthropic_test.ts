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
    dataRefreshedAt: null,
    usageStatus: status(),
    costStatus: status(),
    usage: {
      uncachedInputTokens: 10,
      cacheCreation5mTokens: 2,
      cacheCreation1hTokens: 3,
      cacheReadTokens: 4,
      outputTokens: 5,
      requests: null,
      breakdowns: [{}],
      groupedTop100Cap: false,
    },
    costs: {
      totals: [{ currency: "USD", amount: "1.25" }],
      breakdowns: [{}],
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
  breakdowns: [{}],
  groupedTop100Cap,
});
const enterpriseCosts = (groupedTop100Cap: boolean) => ({
  totals: [{ currency: "USD", amount: "125" }],
  breakdowns: [{}],
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
// The value is a major-unit decimal; the summary used to append "minor units",
// inviting a consumer to divide by 100 against an unscaled number.
Deno.test("cost summary states the currency without claiming minor units", async () => {
  const bundle = await normalize(context(snapshot()));
  assertEquals(bundle.sections[1].summary, "1.25 USD");
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
Deno.test("missing snapshot exposes both coverage gaps", async () => {
  const bundle = await normalize(context(null));
  assertEquals(bundle.state, "unknown");
  assertEquals(
    bundle.sections.every((s) => s.metrics[0].availability === "unknown"),
    true,
  );
});
