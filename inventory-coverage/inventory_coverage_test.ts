import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { capture, model } from "./inventory_coverage.ts";

const now = Date.parse("2026-10-14T12:00:00.500Z");
const source = {
  category: "storage" as const,
  modelType: "@example/operational-metadata",
  modelId: "00000000-0000-4000-8000-000000000001",
  dataName: "summary",
};
const clear = {
  schemaVersion: 1,
  observedAt: new Date(now).toISOString(),
  collectorStatus: "succeeded",
  counts: { expected: 9, observed: 9, unhealthy: 0, unknown: 0 },
  flags: { reachable: true, configured: true },
};
const encode = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));
const type = {
  toString: () => source.modelType,
  toDirectoryPath: () => source.modelType,
};
const modelRepository = { findAllByIdGlobal: async () => [{ type }] };
const repo = (value: unknown) => ({
  findByName: async () => ({
    name: "summary",
    version: 4,
    size: encode(value).length,
    createdAt: new Date(now),
  }),
  stream: async function* (
    _t: unknown,
    _i: string,
    _n: string,
    version?: number,
  ) {
    yield encode(version === 4 ? value : {});
  },
});
Deno.test("complete evidence can describe degradation; failed collectors never yield complete coverage", async () => {
  for (
    const [value, condition, complete] of [
      [clear, "clear", true],
      [
        { ...clear, counts: { ...clear.counts, unhealthy: 2 } },
        "degraded",
        true,
      ],
      [
        { ...clear, flags: { reachable: false, configured: true } },
        "degraded",
        true,
      ],
      [{ ...clear, collectorStatus: "failed" }, "degraded", false],
      [{ ...clear, collectorStatus: "unknown" }, "unknown", false],
      [
        { ...clear, counts: { ...clear.counts, observed: 7 } },
        "unknown",
        false,
      ],
      [{ ...clear, counts: { ...clear.counts, unknown: 1 } }, "unknown", false],
      [
        { ...clear, flags: { reachable: null, configured: true } },
        "unknown",
        false,
      ],
      [
        { ...clear, counts: { ...clear.counts, unknown: 1, unhealthy: 2 } },
        "degraded",
        false,
      ],
    ] as const
  ) {
    const result = await capture(
      { sources: [source] },
      repo(value),
      modelRepository,
      now,
    );
    assertEquals<unknown>(result.rows[0].observation.metadata, value);
    assertEquals(result.rows[0].observation.version, 4);
    assertEquals([result.rows[0].condition, result.coverageComplete], [
      condition,
      complete,
    ]);
    assertEquals(result.degraded, condition === "degraded" ? 1 : 0);
  }
});
Deno.test("exact freshness boundary, future time and null time do not borrow resource creation time", async () => {
  for (
    const [age, freshness] of [[3_600_000, "fresh"], [3_600_001, "stale"], [
      -1,
      "unknown",
    ], [null, "unknown"]] as const
  ) {
    const observedAt = age === null ? null : new Date(now - age).toISOString();
    const result = await capture(
      { sources: [source], maxAgeSeconds: 3600 },
      repo({ ...clear, observedAt }),
      modelRepository,
      now,
    );
    assertEquals(result.rows[0].freshness, freshness);
    assertEquals(result.rows[0].observation.metadata?.observedAt, observedAt);
    assertEquals(result.coverageComplete, freshness === "fresh");
  }
});
Deno.test("errors and missing evidence are distinct and cannot erase the other source", async () => {
  for (
    const failure of [
      "missing",
      "json",
      "utf8",
      "oversized",
      "extra",
      "exception",
      "version",
    ]
  ) {
    const result = await capture(
      {
        sources: [source, {
          ...source,
          category: "network",
          dataName: "other",
        }],
      },
      {
        findByName: async (_t, _i, name) => {
          if (name === "summary" && failure === "missing") return null;
          return {
            name,
            version: name === "summary" && failure === "version" ? NaN : 4,
            size: name === "other"
              ? encode(clear).length
              : failure === "utf8"
              ? 1
              : failure === "oversized"
              ? 64_001
              : 2,
          };
        },
        stream: async function* (_t, _i, name) {
          if (name === "other") {
            yield encode(clear);
            return;
          }
          if (failure === "exception") throw Error("PRIVATE_DETAIL");
          if (failure === "utf8") {
            yield new Uint8Array([255]);
            return;
          }
          if (failure === "oversized") {
            yield new Uint8Array(64_001);
            return;
          }
          yield encode(
            failure === "extra" ? { ...clear, password: "PRIVATE_DETAIL" } : [],
          );
        },
      },
      modelRepository,
      now,
    );
    assertEquals(result.rows.map((r) => r.freshness), [
      failure === "missing" ? "unavailable" : "error",
      "fresh",
    ]);
    assertEquals(result.rows.map((r) => r.condition), ["unknown", "clear"]);
    assertEquals([
      result.sources,
      result.fresh,
      result.degraded,
      result.coverageComplete,
    ], [2, 1, 0, false]);
    assertEquals(JSON.stringify(result).includes("PRIVATE_DETAIL"), false);
  }
});
Deno.test("capture rejects projections, extra arguments, duplicates and invalid freshness budgets", async () => {
  assertEquals(model.methods.capture.arguments.safeParse({}).success, true);
  for (const key of ["fields", "__proto__", "constructor", ""]) {
    assertEquals(
      model.methods.capture.arguments.safeParse({ [key]: "PRIVATE_VALUE" })
        .success,
      false,
    );
  }
  for (
    const globalArgs of [
      { sources: [{ ...source, ["__proto__"]: "PRIVATE_VALUE" }] },
      { sources: [source], ["__proto__"]: "PRIVATE_VALUE" },
      { sources: [{ ...source, fields: ["password"] }] },
      { sources: [{ ...source, zeroFields: ["unhealthy"] }] },
      { sources: [{ ...source, label: "PRIVATE_LABEL" }] },
      { sources: [source, source] },
      { sources: [source, { ...source, category: "network" }] },
      {
        sources: [{
          ...source,
          modelId: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        }],
      },
      ...[0, -1, 31_536_001, 0.5, "3600"].map((maxAgeSeconds) => ({
        sources: [source],
        maxAgeSeconds,
      })),
    ]
  ) {
    let writes = 0;
    await assertRejects(() =>
      model.methods.capture.execute({}, {
        globalArgs,
        definitionRepository: modelRepository,
        dataRepository: repo(clear),
        writeResource: async () => {
          writes++;
          return { name: "summary" };
        },
      })
    );
    assertEquals(writes, 0);
  }
});
Deno.test("capture writes a schema-conforming summary and sanitizes write failure", async () => {
  let saved: unknown;
  await model.methods.capture.execute({}, {
    globalArgs: { sources: [source] },
    definitionRepository: modelRepository,
    dataRepository: repo(clear),
    writeResource: async (spec, name, data) => {
      assertEquals([spec, name], ["summary", "summary"]);
      saved = data;
      return { name };
    },
  });
  assertEquals((saved as { rows: unknown[] }).rows.length, 1);
  const error = await assertRejects(() =>
    model.methods.capture.execute({}, {
      globalArgs: { sources: [source] },
      definitionRepository: modelRepository,
      dataRepository: repo(clear),
      writeResource: async () => {
        throw Error("PRIVATE_WRITE_DETAIL");
      },
    })
  );
  assertEquals(String(error).includes("PRIVATE_WRITE_DETAIL"), false);
});
Deno.test("capture cancellation is not converted to an error row or persisted", async () => {
  const controller = new AbortController();
  const reason = new DOMException("Cancelled coverage", "AbortError");
  let writes = 0;
  const error = await assertRejects(() =>
    model.methods.capture.execute({}, {
      globalArgs: { sources: [source] },
      signal: controller.signal,
      definitionRepository: modelRepository,
      dataRepository: {
        ...repo(clear),
        stream: async function* () {
          controller.abort(reason);
          yield encode(clear);
        },
      },
      writeResource: async () => {
        writes++;
        return { name: "summary" };
      },
    })
  );
  assertEquals(error, reason);
  assertEquals(writes, 0);
});

Deno.test("ambiguous producer UUIDs are error evidence, never complete coverage", async () => {
  const result = await capture(
    { sources: [source] },
    repo(clear),
    { findAllByIdGlobal: async () => [{ type }, { type }] },
    now,
  );
  assertEquals(result.rows[0].freshness, "error");
  assertEquals(result.rows[0].observation.available, false);
  assertEquals(result.coverageComplete, false);
});
