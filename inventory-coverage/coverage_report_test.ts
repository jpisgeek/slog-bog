import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { report } from "./coverage_report.ts";
const summary = {
  assessedAt: "2026-10-14T12:00:00.500Z",
  maxAgeSeconds: 3600,
  coverageComplete: true,
  sources: 1,
  fresh: 1,
  degraded: 1,
  rows: [{
    observation: {
      category: "storage",
      version: 4,
      available: true,
      metadata: {
        schemaVersion: 1,
        observedAt: "2026-10-14T11:00:00.500Z",
        collectorStatus: "succeeded",
        counts: { expected: 9, observed: 9, unhealthy: 2, unknown: 0 },
        flags: { reachable: false, configured: true },
      },
    },
    freshness: "fresh",
    condition: "degraded",
    complete: true,
  }],
};
const encode = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));
const repository = (bytes: Uint8Array | null = encode(summary)) => ({
  findByName: async () => ({
    name: "summary",
    version: 3,
    size: bytes?.length ?? 0,
  }),
  stream: async function* (_t: unknown, _i: string, _n: string, v: number) {
    if (bytes) yield v === 3 ? bytes : encode({});
  },
});
const context = {
  modelType: {
    toString: () => "@jpisgeek/inventory-coverage",
    toDirectoryPath: () => "@jpisgeek/inventory-coverage",
  },
  modelId: "00000000-0000-4000-8000-000000000002",
  executionStatus: "succeeded",
  dataHandles: [{ name: "summary", specName: "summary", version: 3 }],
  dataRepository: repository(),
};
Deno.test("report pins the run version and preserves assessment time, not retrieval time", async () => {
  const result = await report.execute(context);
  assertEquals<unknown>(result.json, summary);
  assert(
    result.markdown.includes(
      "storage: fresh; condition degraded; complete true.",
    ),
  );
  assert(result.markdown.includes(summary.assessedAt));
});
Deno.test("report rejects wrong run binding, free text and forged derived counters/states", async () => {
  for (
    const override of [
      { executionStatus: "failed" },
      { modelType: { ...context.modelType, toString: () => "@example/other" } },
      { dataHandles: [] },
      { dataHandles: [{ name: "other", specName: "summary", version: 3 }] },
      { dataHandles: [{ name: "summary", specName: "other", version: 3 }] },
      { dataHandles: [{ name: "summary", specName: "summary", version: 0 }] },
      ...[
        { ...summary, coverageComplete: false },
        { ...summary, fresh: 0 },
        { ...summary, rows: [{ ...summary.rows[0], condition: "clear" }] },
        { ...summary, rows: [{ ...summary.rows[0], freshness: "stale" }] },
        { ...summary, rows: [{ ...summary.rows[0], complete: false }] },
        { ...summary, rows: [{ ...summary.rows[0], label: "PRIVATE_TEXT" }] },
      ].map((s) => ({ dataRepository: repository(encode(s)) })),
    ]
  ) await assertRejects(() => report.execute({ ...context, ...override }));
});
Deno.test("report rejects malformed/oversized reads, sanitizes errors and preserves cancellation", async () => {
  for (
    const dataRepository of [
      repository(null),
      repository(new Uint8Array([255])),
      repository(new Uint8Array(64_001)),
      {
        ...repository(),
        stream: async function* () {
          throw Error("PRIVATE_DETAIL");
        },
      },
    ]
  ) {
    const error = await assertRejects(() =>
      report.execute({ ...context, dataRepository })
    );
    assertEquals(String(error).includes("PRIVATE_DETAIL"), false);
  }
  const controller = new AbortController();
  const reason = new DOMException("Cancelled report", "AbortError");
  const error = await assertRejects(() =>
    report.execute({
      ...context,
      signal: controller.signal,
      dataRepository: {
        ...repository(),
        stream: async function* () {
          controller.abort(reason);
          yield encode(summary);
        },
      },
    })
  );
  assertEquals(error, reason);
});
