import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { report } from "./infrastructure_guide.ts";

const saved = {
  collectedAt: "2026-10-14T12:01:00.000Z",
  observations: [{
    category: "storage",
    version: 7,
    available: true,
    metadata: {
      schemaVersion: 1,
      observedAt: null,
      collectorStatus: "failed",
      counts: { expected: 9, observed: 7, unhealthy: 2, unknown: 1 },
      flags: { reachable: false, configured: null },
    },
  }],
};
const encode = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));
const repository = (bytes: Uint8Array | null = encode(saved)) => ({
  findByName: async () => ({
    name: "snapshot",
    version: 3,
    size: bytes?.length ?? 0,
  }),
  stream: async function* (_t: unknown, _i: string, _n: string, v: number) {
    if (bytes) yield v === 3 ? bytes : encode({});
  },
});
const context = {
  modelType: {
    toString: () => "@jpisgeek/documentation-evidence",
    toDirectoryPath: () => "@jpisgeek/documentation-evidence",
  },
  modelId: "00000000-0000-4000-8000-000000000002",
  executionStatus: "succeeded",
  dataHandles: [{ specName: "snapshot", name: "snapshot", version: 3 }],
  dataRepository: repository(),
};
Deno.test("guide renders exact successful run version and fixed unknown/failed values", async () => {
  const result = await report.execute(context);
  assertEquals<unknown>(result.json.observations, saved.observations);
  assert(
    result.markdown.includes("Source observation: unknown. Collector: failed."),
  );
  assert(
    result.markdown.includes(
      "Expected: 9; observed: 7; unhealthy: 2; unknown: 1.",
    ),
  );
  assert(result.markdown.includes("Reachable: false; configured: unknown."));
  assertEquals(result.json.sections, [{
    key: "infrastructure-observations",
    markdown: result.markdown,
  }]);
});
Deno.test("guide refuses fallback, free-text snapshots, malformed reads and backend detail", async () => {
  for (
    const override of [
      { executionStatus: "failed" },
      { modelType: { ...context.modelType, toString: () => "@example/other" } },
      { dataHandles: [] },
      { dataHandles: [{ specName: "other", name: "snapshot", version: 3 }] },
      { dataHandles: [{ specName: "snapshot", name: "other", version: 3 }] },
      { dataHandles: [{ specName: "snapshot", name: "snapshot", version: 0 }] },
      ...[
        null,
        new Uint8Array([255]),
        new Uint8Array(64_001),
        encode({ ...saved, markdown: "PRIVATE_TEXT" }),
        encode({
          ...saved,
          observations: [{ ...saved.observations[0], label: "PRIVATE_TEXT" }],
        }),
      ].map((bytes) => ({ dataRepository: repository(bytes) })),
      {
        dataRepository: {
          ...repository(),
          stream: async function* () {
            throw Error("PRIVATE_DETAIL");
          },
        },
      },
    ]
  ) {
    const error = await assertRejects(() =>
      report.execute({ ...context, ...override })
    );
    assertEquals(String(error).includes("PRIVATE_"), false);
  }
});
Deno.test("guide preserves cancellation instead of reclassifying it", async () => {
  const controller = new AbortController();
  const reason = new DOMException("Cancelled guide", "AbortError");
  const error = await assertRejects(() =>
    report.execute({
      ...context,
      signal: controller.signal,
      dataRepository: {
        ...repository(),
        stream: async function* () {
          controller.abort(reason);
          yield encode(saved);
        },
      },
    })
  );
  assertEquals(error, reason);
});
