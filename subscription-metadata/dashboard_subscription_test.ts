import { assertEquals } from "jsr:@std/assert@1";
import { normalize, report } from "./dashboard_subscription.ts";
import { model } from "./subscription_metadata.ts";
type Json = Record<string, unknown>;
function context(snapshot: Json | null) {
  const bytes = snapshot
    ? new TextEncoder().encode(JSON.stringify(snapshot))
    : null;
  return {
    scope: "method" as const,
    modelType: { toString: () => "@jpisgeek/subscription-metadata" },
    modelId: "synthetic",
    definition: { name: "example-plan", version: 1 },
    methodName: "capture",
    executionStatus: "succeeded" as const,
    dataHandles: snapshot
      ? [{ name: "subscription-metadata", specName: "snapshot", version: 1 }]
      : [],
    dataRepository: { getContent: () => Promise.resolve(bytes) },
  };
}
const snapshot = (overrides: Json = {}) => ({
  provider: "Example AI",
  declaredLimits: [],
  provenance: { kind: "operator-config", capturedAt: "2026-08-25T20:00:00Z" },
  ...overrides,
});
Deno.test("report contains canonical contract verbatim", async () => {
  const entry = await Deno.readTextFile(
    new URL("./dashboard_subscription.ts", import.meta.url),
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
Deno.test("unknown fields stay absent", async () => {
  const bundle = await normalize(context(snapshot()));
  assertEquals(bundle.sections[0].metrics.length, 0);
  assertEquals(
    bundle.sections[0].facts.some((f) => f.id === "plan-name"),
    false,
  );
});
Deno.test("explicit zero seats and limits remain observed zero", async () => {
  const bundle = await normalize(
    context(
      snapshot({
        seats: 0,
        declaredLimits: [{
          name: "Included requests",
          value: 0,
          unit: "requests",
          period: "month",
        }],
      }),
    ),
  );
  assertEquals(
    bundle.sections[0].metrics.find((m) => m.id === "declared-seats")?.value,
    0,
  );
  assertEquals(
    bundle.sections[0].metrics.find((m) => m.id === "declared-limit-1")?.value,
    0,
  );
});
Deno.test("subscription price is not usage cost", async () => {
  const bundle = await normalize(
    context(snapshot({ priceMinor: "2500", currency: "USD" })),
  );
  assertEquals(bundle.sections[0].metrics[0].id, "subscription-price-usd");
  assertEquals(bundle.extensions["jpisgeek/subscription-metadata"], {
    dataClass: "subscription-metadata",
    apiMetering: false,
    remainingQuotaDerived: false,
    perTokenCostDerived: false,
  });
  assertEquals(JSON.stringify(bundle).includes("usage-cost"), false);
});
Deno.test("missing snapshot is informational unknown", async () => {
  const bundle = await normalize(context(null));
  assertEquals(bundle.sections[0].state, "unknown");
  assertEquals(bundle.state, "unknown");
});

// The read path used to enforce less than the write path: its LimitSchema had
// no forbidden-declaration guard and its SnapshotSchema was not .strict(), so a
// snapshot written by another route — a direct Swamp data write, or a capture
// from an older, looser version of this model still inside its 365-day lifetime
// — was rendered as a healthy exact metric. Drive candidates through capture()
// and through normalize() and assert the two verdicts agree, so the duplicated
// copies cannot drift apart again without a test failing.
Deno.test("read path and write path accept and reject the same snapshots", async () => {
  const candidates: Json[] = [
    { provider: "Example AI" },
    {
      provider: "Example AI",
      declaredLimits: [{
        name: "Included requests",
        value: 1000,
        unit: "requests",
        period: "month",
      }],
    },
    { provider: "Example AI", priceMinor: "2500", currency: "USD", seats: 4 },
    {
      provider: "Example AI",
      declaredLimits: [{
        name: "remaining tokens",
        value: 500,
        unit: "tokens",
      }],
    },
    {
      provider: "Example AI",
      declaredLimits: [{ name: "Rate", value: 0.002, unit: "usd-per-token" }],
    },
    {
      provider: "Example AI",
      declaredLimits: [{
        name: "Budget",
        value: 5,
        unit: "usd",
        period: "per token",
      }],
    },
    { provider: "Example AI", priceMinor: "9".repeat(500), currency: "USD" },
    { provider: "Example AI", priceMinor: "2500" },
    { provider: "", declaredLimits: [] },
    { provider: "Example AI", billingCadence: "biweekly" },
    { provider: "Example AI", remainingQuota: 10 },
  ];
  for (const candidate of candidates) {
    let captureAccepted = true;
    try {
      await model.methods.capture.execute({}, {
        globalArgs: candidate,
        writeResource: () => Promise.resolve({}),
      });
    } catch {
      captureAccepted = false;
    }
    const bundle = await normalize(context({
      declaredLimits: [],
      ...candidate,
      provenance: {
        kind: "operator-config",
        capturedAt: "2026-08-25T20:00:00Z",
      },
    }));
    const readAccepted = bundle.sections[0].state !== "unknown";
    assertEquals(
      readAccepted,
      captureAccepted,
      `read/write disagree on ${
        JSON.stringify(candidate)
      }: capture ${captureAccepted}, read ${readAccepted}`,
    );
  }
});

// An over-long priceMinor that predates the capture-side bound used to reach
// Number() as Infinity, and ObservedMetricSchema requires .finite() — the whole
// bundle parse threw. It must now degrade to the informational unknown section.
Deno.test("an unrenderable persisted priceMinor degrades instead of throwing", async () => {
  const bundle = await normalize(
    context(snapshot({ priceMinor: "9".repeat(500), currency: "USD" })),
  );
  assertEquals(bundle.sections[0].state, "unknown");
  assertEquals(bundle.sections[0].metrics.length, 0);
});

Deno.test("operator strings cannot inject raw Markdown or HTML", async () => {
  const ctx = context(snapshot({
    provider: "<script>alert(1)</script>",
    planName: "[click](javascript:alert(1))",
  }));
  const result = await report.execute(ctx);
  assertEquals(result.markdown.includes("<script>"), false);
  assertEquals(result.markdown.includes("[click](javascript:"), false);
});
