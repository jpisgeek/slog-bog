import { assertEquals } from "jsr:@std/assert@1";
import { normalize } from "./dashboard_openai.ts";
type Json = Record<string, unknown>;
const status = (state = "complete", errorKind = "", message = "") => ({
  state,
  pagesRead: state === "unavailable" ? 0 : 1,
  errorKind,
  message,
});
function context(snapshot: Json | null) {
  const bytes = snapshot
    ? new TextEncoder().encode(JSON.stringify(snapshot))
    : null;
  return {
    scope: "method" as const,
    modelType: { toString: () => "@jpisgeek/openai-usage" },
    modelId: "synthetic-id",
    definition: { name: "openai-example", version: 1 },
    methodName: "collect",
    executionStatus: "succeeded" as const,
    dataHandles: snapshot
      ? [{ name: "organization-usage", specName: "snapshot", version: 1 }]
      : [],
    dataRepository: { getContent: () => Promise.resolve(bytes) },
  };
}
function snapshot(overrides: Json = {}): Json {
  return {
    provider: "openai",
    collectedAt: "2026-08-25T20:00:00.000Z",
    coverageStart: "2026-08-01T00:00:00.000Z",
    coverageEnd: "2026-08-25T00:00:00.000Z",
    usageStatus: status(),
    costStatus: status(),
    usage: {
      inputTokens: 10,
      outputTokens: 5,
      cachedInputTokens: 2,
      requests: 1,
      breakdowns: [{
        projectId: null,
        model: null,
        inputTokens: 10,
        outputTokens: 5,
        cachedInputTokens: 2,
        requests: 1,
      }],
    },
    costs: {
      totals: [{ currency: "usd", value: 1.25 }],
      breakdowns: [{
        projectId: null,
        lineItem: null,
        currency: "usd",
        value: 1.25,
      }],
    },
    ...overrides,
  };
}
Deno.test("report contains canonical contract verbatim", async () => {
  const entry = await Deno.readTextFile(
    new URL("./dashboard_openai.ts", import.meta.url),
  );
  const canonical = await Deno.readTextFile(
    new URL("../dashboard-contract/dashboard_bundle.ts", import.meta.url),
  );
  const inlined = entry.split("// BEGIN INLINED DASHBOARD CONTRACT V1\n")[1]
    .split("// END INLINED DASHBOARD CONTRACT V1")[0].trim();
  assertEquals(inlined, canonical.trim());
});
Deno.test("exact usage and currency remain distinct authoritative metrics", async () => {
  const bundle = await normalize(context(snapshot()));
  assertEquals(bundle.state, "healthy");
  assertEquals(
    bundle.sections[0].metrics.find((metric) => metric.id === "input-tokens")
      ?.value,
    10,
  );
  assertEquals(bundle.sections[1].metrics[0].id, "cost-usd");
  assertEquals(bundle.sections[1].metrics[0].value, 1.25);
});
Deno.test("partial usage is visible while complete costs survive", async () => {
  const bundle = await normalize(
    context(
      snapshot({
        usageStatus: status(
          "partial",
          "rate-limited",
          "OpenAI rate-limited this observation",
        ),
      }),
    ),
  );
  assertEquals(bundle.state, "partial");
  assertEquals(bundle.sections[0].completeness.state, "partial");
  assertEquals(bundle.sections[1].state, "healthy");
});
Deno.test("authorization failure never becomes a zero", async () => {
  const bundle = await normalize(
    context(
      snapshot({
        usageStatus: status(
          "unavailable",
          "unauthorized",
          "OpenAI rejected the configured Admin API credential",
        ),
        usage: null,
      }),
    ),
  );
  const metric = bundle.sections[0].metrics[0];
  assertEquals(bundle.state, "critical");
  assertEquals(bundle.sections[0].state, "unauthorized");
  assertEquals(metric.availability, "unauthorized");
  assertEquals("value" in metric, false);
});
Deno.test("missing currency stays unknown rather than zero", async () => {
  const bundle = await normalize(
    context(snapshot({ costs: { totals: [], breakdowns: [] } })),
  );
  assertEquals(bundle.sections[1].state, "unknown");
  assertEquals(bundle.state, "unknown");
  assertEquals(bundle.sections[1].metrics[0].availability, "unknown");
  assertEquals("value" in bundle.sections[1].metrics[0], false);
});
Deno.test("missing snapshot degrades both dimensions explicitly", async () => {
  const bundle = await normalize(context(null));
  assertEquals(bundle.state, "unknown");
  assertEquals(
    bundle.sections.every((section) =>
      section.metrics[0].availability === "unknown"
    ),
    true,
  );
});
