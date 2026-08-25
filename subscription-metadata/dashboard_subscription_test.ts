import { assertEquals } from "jsr:@std/assert@1";
import { normalize } from "./dashboard_subscription.ts";
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
