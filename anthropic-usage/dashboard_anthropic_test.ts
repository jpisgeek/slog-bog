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
      totalsMinor: [{ currency: "USD", amountMinor: "1.25" }],
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
Deno.test("enterprise grouped cap forces partial coverage", async () => {
  const bundle = await normalize(context(snapshot({
    accountKind: "enterprise",
    usage: {
      uncachedInputTokens: 10,
      cacheCreation5mTokens: 0,
      cacheCreation1hTokens: 0,
      cacheReadTokens: 0,
      outputTokens: 5,
      requests: 2,
      breakdowns: [{}],
      groupedTop100Cap: true,
    },
    costs: {
      totalsMinor: [{ currency: "USD", amountMinor: "125" }],
      breakdowns: [{}],
      groupedTop100Cap: true,
    },
  })));
  assertEquals(bundle.state, "partial");
  assertEquals(
    bundle.sections.every((s) => s.completeness.state === "partial"),
    true,
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
        costs: { totalsMinor: [], breakdowns: [], groupedTop100Cap: false },
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
