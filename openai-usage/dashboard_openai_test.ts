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
      inputAudioTokens: 3,
      outputAudioTokens: 4,
      requests: 1,
      breakdowns: [{
        projectId: null,
        model: null,
        inputTokens: 10,
        outputTokens: 5,
        cachedInputTokens: 2,
        inputAudioTokens: 3,
        outputAudioTokens: 4,
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
  // Audio is a separate modality in OpenAI's counters, so the headline total
  // includes it: 10 input + 5 output + 3 input audio + 4 output audio.
  assertEquals(bundle.sections[0].summary, "1 requests used 22 tokens");
  assertEquals(
    bundle.sections[0].metrics.find((metric) =>
      metric.id === "output-audio-tokens"
    )?.value,
    4,
  );
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

Deno.test("later-page authorization failure stays unauthorized", async () => {
  const bundle = await normalize(context(snapshot({
    usageStatus: status(
      "partial",
      "unauthorized",
      "OpenAI rejected the configured Admin API credential",
    ),
  })));
  assertEquals(bundle.sections[0].state, "unauthorized");
  assertEquals(bundle.sections[0].exceptions[0].severity, "critical");
});

Deno.test("later-page cost authorization failure stays unauthorized", async () => {
  const bundle = await normalize(context(snapshot({
    costStatus: status(
      "partial",
      "unauthorized",
      "OpenAI rejected the configured Admin API credential",
    ),
  })));
  assertEquals(bundle.sections[1].state, "unauthorized");
  assertEquals(bundle.sections[1].exceptions[0].severity, "critical");
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

// Review finding 5 (2026-08-30): the producer block carries the operator's own
// Swamp model name and instance ID into the JSON report, but the bundle's
// sensitivity metadata listed only the OpenAI breakdown dimensions. An
// operator deciding what was safe to publish read a field list that did not
// mention two identifiers naming their own infrastructure.
Deno.test("bundle sensitivity discloses the producer identifiers it emits", async () => {
  const bundle = await normalize(context(snapshot()));
  assertEquals(bundle.producer.modelName, "openai-example");
  assertEquals(bundle.producer.modelId, "synthetic-id");
  for (const field of ["producer.modelName", "producer.modelId"]) {
    assertEquals(
      bundle.sensitivity.fields.includes(field),
      true,
      `${field} is written into the report but absent from sensitivity.fields`,
    );
  }
  // Section-level metadata still describes only what a section carries; the
  // producer identifiers live on the bundle, not inside a section.
  assertEquals(
    bundle.sections.every((section) =>
      !section.sensitivity.fields.some((field) => field.startsWith("producer."))
    ),
    true,
  );
});

Deno.test("bundle IDs retain distinct model instances and remain stable across runs", async () => {
  const first = { ...context(snapshot()), modelId: "EXAMPLE_MODEL_A" };
  const second = { ...context(snapshot()), modelId: "EXAMPLE_MODEL_B" };
  const [a, b, rerun] = await Promise.all([
    normalize(first),
    normalize(second),
    normalize({
      ...first,
      definition: { name: "renamed-example", version: 2 },
    }),
  ]);
  assertEquals(a.id === b.id, false);
  assertEquals(a.id, rerun.id);
  assertEquals(/^openai-organization-[a-f0-9]{64}$/.test(a.id), true);
  assertEquals(a.id.includes(first.modelId), false);
  const byId = new Map([a, b].map((bundle) => [bundle.id, bundle]));
  assertEquals(byId.size, 2);
  assertEquals(byId.get(a.id)?.producer.modelId, first.modelId);
  assertEquals(byId.get(b.id)?.producer.modelId, second.modelId);
});
