import { assertEquals, assertRejects } from "jsr:@std/assert@1";
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
Deno.test("capture time is provenance, never evidence of live freshness", async () => {
  for (const capturedAt of ["2025-01-01T00:00:00Z", new Date().toISOString()]) {
    const bundle = await normalize(context(snapshot({
      provenance: { kind: "operator-config", capturedAt },
    })));
    assertEquals(bundle.sections[0].freshness.state, "unknown");
    assertEquals(bundle.sections[0].freshness.observedAt, capturedAt);
    assertEquals(bundle.sections[0].impact, "informational");
    assertEquals(bundle.state, "unknown");
  }
});

Deno.test("invalid labels, unsafe counts and case-variant duplicates fail capture and render unknown", async () => {
  const limit = { name: "Included requests", unit: "requests", value: 1 };
  for (
    const invalid of [
      { provider: "   " },
      { provider: "Example\u0000AI" },
      { provider: "\u200b" },
      { provider: "\u0301" },
      { provider: "\u2800" },
      { planName: "Plan\u202eInjected" },
      { planName: "\u3164" },
      { planName: "x".repeat(121) },
      { planName: "Plan\nInjected" },
      { seats: Number.MAX_SAFE_INTEGER + 1 },
      { declaredLimits: [{ ...limit, value: Number.MAX_SAFE_INTEGER + 1 }] },
      {
        declaredLimits: [{
          name: "Throughput",
          unit: "tokens-per-second",
          value: 1.5,
        }],
      },
      {
        declaredLimits: [limit, {
          ...limit,
          name: "INCLUDED REQUESTS",
          value: 2,
        }],
      },
    ]
  ) {
    await assertRejects(() =>
      model.methods.capture.execute({}, {
        globalArgs: { provider: "Example AI", ...invalid },
        writeResource: async () => ({}),
      })
    );
    const bundle = await normalize(context(snapshot(invalid)));
    assertEquals(bundle.sections[0].state, "unknown");
    assertEquals(bundle.sections[0].metrics, []);
  }
  const lower = await normalize(context(snapshot({ declaredLimits: [limit] })));
  const upper = await normalize(
    context(
      snapshot({ declaredLimits: [{ ...limit, name: "INCLUDED REQUESTS" }] }),
    ),
  );
  assertEquals(
    lower.sections[0].metrics[0].id,
    upper.sections[0].metrics[0].id,
  );
});

Deno.test("report accepts only this successful capture's exact versioned snapshot", async () => {
  const original = context(snapshot({ seats: 4 }));
  for (
    const override of [
      { methodName: "other" },
      { executionStatus: "failed" as const },
      { modelType: { toString: () => "@example/unrelated" } },
      {
        dataHandles: [{
          name: "subscription-metadata",
          specName: "other",
          version: 1,
        }],
      },
      { dataHandles: [{ name: "other", specName: "snapshot", version: 1 }] },
      {
        dataHandles: [{
          name: "subscription-metadata",
          specName: "snapshot",
          version: 0,
        }],
      },
    ]
  ) {
    const bundle = await normalize({ ...original, ...override });
    assertEquals(bundle.sections[0].state, "unknown");
    assertEquals(bundle.sections[0].metrics, []);
  }
  const bundle = await normalize({
    ...original,
    dataRepository: {
      getContent: (_type, _id, _name, version) =>
        Promise.resolve(
          new TextEncoder().encode(
            JSON.stringify(snapshot({ seats: version === 1 ? 4 : 99 })),
          ),
        ),
    },
  });
  assertEquals(bundle.sections[0].metrics[0].value, 4);
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
    bundle.sections[0].metrics.find((m) => m.label === "Included requests")
      ?.value,
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

Deno.test("legacy references with normalized-away bytes are rejected on every read path", async () => {
  for (
    const sourceReference of [
      "https://openai.com/pricing\u0000",
      "https://ope\nnai.com/pricing",
      "https://openai.com/other/../pricing",
    ]
  ) {
    for (
      const fields of [
        { sourceReference },
        {
          declaredLimits: [{
            name: "Included requests",
            value: 7,
            unit: "requests",
            sourceReference,
          }],
        },
        {
          provenance: {
            kind: "operator-config",
            capturedAt: "2026-01-01T00:00:00Z",
            sourceReference,
          },
        },
      ]
    ) {
      const bundle = await normalize(context(snapshot(fields)));
      assertEquals(bundle.sections[0].state, "unknown");
      assertEquals(bundle.sections[0].metrics, []);
      assertEquals(bundle.sections[0].references, []);
    }
  }
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

// A word blacklist missed ordinary balance/price labels. Both new captures and
// old persisted snapshots must fail closed; parity alone could miss both paths
// wrongly accepting the same unsupported declaration.
Deno.test("unsupported capacity declarations never persist or render exact metrics", async () => {
  for (
    const limit of [
      { name: "token cost", value: 0.002, unit: "tokens" },
      { name: "price/token", value: 0.003, unit: "count" },
      { name: "quota balance", value: 13, unit: "requests" },
      { name: "unused requests", value: 17, unit: "requests" },
      { name: "Context window", value: 0.004, unit: "currency" },
      { name: "Included requests", value: 19, unit: "tokens" },
      {
        name: "Throughput",
        value: 23,
        unit: "tokens-per-second",
        period: "credit balance",
      },
      {
        name: "Context window",
        value: 29,
        unit: "tokens",
        period: "token cost",
      },
      { name: "Context wіndow", value: 31, unit: "tokens" }, // Cyrillic і
      { name: "Included requests (unused)", value: 37, unit: "requests" },
    ]
  ) {
    let writes = 0;
    await assertRejects(() =>
      model.methods.capture.execute({}, {
        globalArgs: { provider: "Example AI", declaredLimits: [limit] },
        writeResource: () => {
          writes++;
          return Promise.resolve({});
        },
      })
    );
    assertEquals(writes, 0);
    const bundle = await normalize(
      context(snapshot({ declaredLimits: [limit] })),
    );
    assertEquals(bundle.sections[0].state, "unknown");
    assertEquals(bundle.sections[0].metrics, []);
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

// The two schema copies are compared as whole snapshots here, not only through
// capture(): capture builds provenance itself and applies the declaredLimits
// default, so the harness above cannot reach the nested provenance object or a
// snapshot that simply omits a key. Each candidate is parsed by the model's own
// published resource schema and rendered through the report, and the verdicts
// must match. Without the nested .strict() calls the first two candidates below
// are written happily and then rejected on read.
Deno.test("both schema copies agree on whole snapshots, nested keys included", async () => {
  const provenance = {
    kind: "operator-config",
    capturedAt: "2026-08-25T20:00:00Z",
  };
  const limit = { name: "Included requests", value: 1000, unit: "requests" };
  const candidates: Json[] = [
    { provider: "Example AI", declaredLimits: [], provenance },
    // unknown key inside a declared limit
    {
      provider: "Example AI",
      declaredLimits: [{ ...limit, remaining: 12 }],
      provenance,
    },
    // unknown key inside provenance
    {
      provider: "Example AI",
      declaredLimits: [],
      provenance: { ...provenance, capturedBy: "scraper" },
    },
    // declaredLimits omitted entirely
    { provider: "Example AI", provenance },
    // duplicate limit identity
    {
      provider: "Example AI",
      declaredLimits: [limit, { ...limit, value: 2000 }],
      provenance,
    },
    // same name and unit, different period — a distinct limit, not a duplicate
    {
      provider: "Example AI",
      declaredLimits: [limit, { ...limit, period: "day" }],
      provenance,
    },
    // a price the report's Number() conversion cannot return unchanged
    {
      provider: "Example AI",
      declaredLimits: [],
      priceMinor: "999999999999999.9999",
      currency: "USD",
      provenance,
    },
    {
      provider: "Example AI",
      declaredLimits: [],
      priceMinor: "2500.0001",
      currency: "USD",
      provenance,
    },
  ];
  for (const candidate of candidates) {
    const written =
      model.resources.snapshot.schema.safeParse(candidate).success;
    const bundle = await normalize(context(candidate));
    const read = bundle.sections[0].state !== "unknown";
    assertEquals(
      read,
      written,
      `read/write disagree on ${
        JSON.stringify(candidate)
      }: write ${written}, read ${read}`,
    );
  }
});

// `declared-limit-${index + 1}` named a slot in an array, so the id a consumer
// tracked followed whatever limit happened to sit in that slot. Both halves are
// asserted: the same limit keeps its id when the operator reorders the array,
// and two different limits in the same position never share one.
Deno.test("declared limit ids follow the limit, not its array position", async () => {
  const context200k = {
    name: "Context window",
    value: 200000,
    unit: "tokens",
  };
  const requests = {
    name: "Included requests",
    value: 1000,
    unit: "requests",
    period: "month",
  };
  const idFor = async (limits: Json[], label: string) => {
    const bundle = await normalize(
      context(snapshot({ declaredLimits: limits })),
    );
    return bundle.sections[0].metrics.find((m) => m.label === label)?.id;
  };
  const forward = await idFor([context200k, requests], "Context window");
  const reversed = await idFor([requests, context200k], "Context window");
  assertEquals(forward, reversed);
  const firstIsRequests = await idFor([requests], "Included requests");
  const firstIsContext = await idFor([context200k], "Context window");
  assertEquals(firstIsRequests === firstIsContext, false);
  assertEquals(typeof forward, "string");
  // A different period is a different limit and must not reuse the id.
  const daily = await idFor(
    [{ ...requests, period: "day" }],
    "Included requests",
  );
  assertEquals(daily === firstIsRequests, false);
});

// Two limits sharing one identity produce two metrics with one id; a renderer
// keyed by id keeps one and drops the other. The section must not be published.
Deno.test("duplicate declared limit identities are not rendered", async () => {
  const limit = { name: "Included requests", value: 1000, unit: "requests" };
  const bundle = await normalize(
    context(snapshot({ declaredLimits: [limit, { ...limit, value: 5 }] })),
  );
  assertEquals(bundle.sections[0].state, "unknown");
  assertEquals(bundle.sections[0].metrics.length, 0);
});

// A price with more significant digits than a double holds used to be published
// as an exact observed metric with a different value than the operator declared.
Deno.test("a price that cannot survive Number() is never published as exact", async () => {
  const lossy = await normalize(
    context(snapshot({ priceMinor: "999999999999999.9999", currency: "USD" })),
  );
  assertEquals(lossy.sections[0].state, "unknown");
  assertEquals(JSON.stringify(lossy).includes("1000000000000000"), false);
  const exact = await normalize(
    context(snapshot({ priceMinor: "2500.0001", currency: "USD" })),
  );
  const metric = exact.sections[0].metrics.find((m) =>
    m.id === "subscription-price-usd"
  );
  assertEquals(metric?.value, 2500.0001);
  assertEquals(String(metric?.value), "2500.0001");
});

// Classified "operational", every one of these values is safe for a
// publication-aware renderer to put on a shared wall.
Deno.test("commercial fields and model identity are classified sensitive", async () => {
  const bundle = await normalize(context(snapshot({
    planName: "Team",
    billingCadence: "monthly",
    priceMinor: "2500",
    currency: "USD",
    seats: 4,
    renewalStart: "2026-01-01T00:00:00Z",
    renewalEnd: "2026-12-31T00:00:00Z",
    sourceReference: "https://www.anthropic.com/pricing",
    declaredLimits: [{ name: "Context window", value: 200000, unit: "tokens" }],
  })));
  assertEquals(bundle.sensitivity.classification, "sensitive");
  assertEquals(bundle.sections[0].sensitivity.classification, "sensitive");
  for (
    const field of [
      "provider",
      "planName",
      "billingCadence",
      "priceMinor",
      "currency",
      "renewalStart",
      "renewalEnd",
      "seats",
      "declaredLimits",
      "sourceReference",
    ]
  ) {
    assertEquals(
      bundle.sensitivity.fields.includes(field),
      true,
      `${field} missing from the bundle sensitivity enumeration`,
    );
    assertEquals(
      bundle.sections[0].sensitivity.fields.includes(field),
      true,
      `${field} missing from the section sensitivity enumeration`,
    );
  }
  for (const metric of bundle.sections[0].metrics) {
    assertEquals(metric.sensitivity, "sensitive", `metric ${metric.id}`);
  }
  // Every fact except the constant provenance marker carries snapshot content.
  for (const fact of bundle.sections[0].facts) {
    assertEquals(
      fact.sensitivity,
      fact.id === "provenance" ? "operational" : "sensitive",
      `fact ${fact.id}`,
    );
  }
  assertEquals(
    bundle.sections[0].references[0].sensitivity,
    "sensitive",
  );
  // modelId identified a model instance inside the operator's deployment.
  assertEquals("modelId" in bundle.producer, false);
  assertEquals(JSON.stringify(bundle).includes("synthetic"), false);
  assertEquals(JSON.stringify(bundle).includes("example-plan"), false);
  assertEquals(bundle.producer.modelName, "Subscription metadata");
  assertEquals(bundle.sensitivity.redacted, true);
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

// Every instance emitted the same constant bundle id, so two subscriptions in
// one deployment produced two bundles a consumer keyed by id read as one.
Deno.test("bundle id is unique per model instance and hides the model id", async () => {
  const first = await normalize(context(snapshot()));
  const second = await normalize({
    ...context(snapshot()),
    modelId: "another-instance",
  });
  assertEquals(
    first.id === second.id,
    false,
    "two instances share a bundle id",
  );
  // Stable for the same instance: a consumer must keep following one bundle.
  const again = await normalize(context(snapshot()));
  assertEquals(again.id, first.id);
  assertEquals(first.id.includes("synthetic"), false);
  assertEquals(second.id.includes("another-instance"), false);
});

// The rendered Markdown carries none of the sensitivity metadata attached to
// the JSON bundle, so it must carry none of the values that metadata protects.
Deno.test("rendered Markdown carries no sensitive value", async () => {
  const result = await report.execute(context(snapshot({
    planName: "Team",
    billingCadence: "monthly",
    priceMinor: "2500",
    currency: "USD",
    seats: 4,
    sourceReference: "https://www.anthropic.com/pricing",
    declaredLimits: [{ name: "Context window", value: 200000, unit: "tokens" }],
  })));
  for (
    const value of [
      "Example AI",
      "Team",
      "monthly",
      "2500",
      "USD",
      "Context window",
      "anthropic.com",
    ]
  ) {
    assertEquals(
      result.markdown.includes(value),
      false,
      `markdown leaked ${value}`,
    );
  }
});
