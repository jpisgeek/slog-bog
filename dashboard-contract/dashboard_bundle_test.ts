import {
  assertEquals,
  assertInstanceOf,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  DASHBOARD_BUNDLE_VERSION,
  DashboardBundleV1Schema,
  deriveOverallState,
  parseDashboardBundle,
  UnsupportedBundleVersionError,
} from "./dashboard_bundle.ts";

type Json = Record<string, unknown>;

function section(state: string): Json {
  return {
    id: "service",
    title: "Service",
    state,
    impact: "required",
    summary: `Service is ${state}`,
    coverage: { kind: "exact", scope: "one synthetic service" },
    freshness: {
      state: state === "stale" ? "stale" : "fresh",
      observedAt: state === "stale" ? undefined : "2026-08-25T12:00:00Z",
      reason: state === "stale" ? "observation exceeded max age" : undefined,
    },
    completeness: state === "partial"
      ? { state: "partial", reason: "one record was rejected", rejected: 1 }
      : { state: "exact", rejected: 0 },
    metrics: [],
    facts: [],
    exceptions: [],
    references: [],
    sensitivity: {
      classification: "public",
      fields: [],
      redacted: false,
    },
  };
}

function bundle(state = "healthy"): Json {
  return {
    schemaVersion: DASHBOARD_BUNDLE_VERSION,
    id: "synthetic-bundle",
    title: "Synthetic bundle",
    generatedAt: "2026-08-25T12:00:01Z",
    producer: {
      extension: "@jpisgeek/synthetic",
      extensionVersion: "2026.08.25.1",
      modelType: "@jpisgeek/synthetic",
      modelName: "synthetic",
      dataName: "current",
    },
    state,
    sections: [section(state)],
    exceptions: [],
    sensitivity: {
      classification: "public",
      fields: [],
      redacted: false,
    },
    extensions: {},
  };
}

function setPath(target: Json, path: string, value: unknown): void {
  const parts = path.split(".");
  let cursor: unknown = target;
  for (const part of parts.slice(0, -1)) {
    cursor = /^\d+$/.test(part)
      ? (cursor as unknown[])[Number(part)]
      : (cursor as Json)[part];
  }
  const key = parts.at(-1)!;
  if (/^\d+$/.test(key)) (cursor as unknown[])[Number(key)] = value;
  else (cursor as Json)[key] = value;
}

Deno.test("all required operational states conform", async () => {
  const states = JSON.parse(
    await Deno.readTextFile(new URL("./fixtures/states.json", import.meta.url)),
  ) as Array<{ name: string; state: string }>;
  for (const fixture of states) {
    const parsed = parseDashboardBundle(bundle(fixture.state));
    assertEquals(parsed.state, fixture.name);
  }
});

Deno.test("unknown additive v1 fields are preserved", () => {
  const input = bundle();
  input.futureTopLevel = { enabled: true };
  (input.sections as Json[])[0].futureSectionField = "kept";
  const parsed = parseDashboardBundle(input) as Json;
  assertEquals(parsed.futureTopLevel, { enabled: true });
  assertEquals(
    (parsed.sections as Json[])[0].futureSectionField,
    "kept",
  );
});

Deno.test("unsupported major versions fail before v1 parsing", () => {
  const input = bundle();
  input.schemaVersion = "2.0.0";
  const error = assertThrows(() => parseDashboardBundle(input));
  assertInstanceOf(error, UnsupportedBundleVersionError);
  assertEquals(error.version, "2.0.0");
});

Deno.test("reported state must match derived required coverage", () => {
  const input = bundle("partial");
  input.state = "healthy";
  assertThrows(
    () => parseDashboardBundle(input),
    Error,
    "does not match derived state partial",
  );
});

Deno.test("optional sections remain visible without changing overall state", () => {
  const required = section("healthy");
  const optional = {
    ...section("unsupported"),
    id: "optional",
    impact: "optional",
  };
  assertEquals(deriveOverallState([required, optional] as never), "healthy");
});

Deno.test("unsuppressed exceptions affect state but suppressed ones do not", () => {
  const healthy = section("healthy");
  const warning = {
    id: "warning:one",
    severity: "warning",
    subject: "service",
    headline: "Needs attention",
    detail: "Synthetic warning",
    source: "fixture",
    suppressed: false,
    suppressReason: "",
    sensitivity: "public",
  };
  assertEquals(
    deriveOverallState([healthy] as never, [warning] as never),
    "degraded",
  );
  assertEquals(
    deriveOverallState(
      [healthy] as never,
      [{ ...warning, suppressed: true, suppressReason: "accepted" }] as never,
    ),
    "healthy",
  );
});

Deno.test("unavailable metrics cannot carry a value", () => {
  const input = bundle();
  ((input.sections as Json[])[0].metrics as unknown[]) = [{
    id: "quota",
    label: "Remaining quota",
    unit: "tokens",
    confidence: "unknown",
    availability: "unknown",
    reason: "provider does not expose remaining quota",
    value: 0,
  }];
  assertThrows(() => DashboardBundleV1Schema.parse(input));
});

Deno.test("adversarial fixtures enforce contract boundaries", async () => {
  const fixtures = JSON.parse(
    await Deno.readTextFile(
      new URL("./fixtures/adversarial.json", import.meta.url),
    ),
  ) as Array<{ name: string; path: string; patch: unknown; valid: boolean }>;

  for (const fixture of fixtures) {
    const input = structuredClone(bundle());
    setPath(input, fixture.path, fixture.patch);
    const result = DashboardBundleV1Schema.safeParse(input);
    assertEquals(result.success, fixture.valid, fixture.name);
    if (fixture.name === "HTML-bearing text remains data" && result.success) {
      assertEquals(result.data.sections[0].summary, fixture.patch);
    }
  }
});

Deno.test("fresh observations require a timestamp", () => {
  const input = bundle();
  delete (((input.sections as Json[])[0].freshness as Json).observedAt);
  assertThrows(() => DashboardBundleV1Schema.parse(input));
});

Deno.test("coverage windows cannot run backwards", () => {
  const input = bundle();
  ((input.sections as Json[])[0].coverage as Json).start =
    "2026-08-25T13:00:00Z";
  ((input.sections as Json[])[0].coverage as Json).end = "2026-08-25T12:00:00Z";
  assertThrows(() => DashboardBundleV1Schema.parse(input));
});
