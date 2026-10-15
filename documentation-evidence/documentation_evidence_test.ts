import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { model, Snapshot } from "./documentation_evidence.ts";

const source = {
  category: "storage",
  modelType: "@example/operational-metadata",
  modelId: "00000000-0000-4000-8000-000000000001",
  dataName: "summary",
};
const metadata = {
  schemaVersion: 1,
  observedAt: "2026-10-14T12:00:00.123Z",
  collectorStatus: "succeeded",
  counts: { expected: 9, observed: 7, unhealthy: 2, unknown: 1 },
  flags: { reachable: false, configured: null },
};
const encode = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));
const type = {
  toString: () => source.modelType,
  toDirectoryPath: () => source.modelType,
};
const modelRepository = { findByIdGlobal: async () => ({ type }) };
const repo = (bytes: Uint8Array | null = encode(metadata)) => ({
  findByName: async () => ({
    name: "summary",
    version: 7,
    size: bytes?.length ?? 0,
  }),
  stream: async function* (
    _t: unknown,
    _i: string,
    _n: string,
    version?: number,
  ) {
    if (bytes) {
      yield version === 7 ? bytes : encode({
        ...metadata,
        counts: { expected: 0, observed: 0, unhealthy: 0, unknown: 0 },
      });
    }
  },
});

Deno.test("capture pins latest named version and preserves fixed metadata without source routing", async () => {
  let saved: unknown;
  const result = await model.methods.capture.execute({}, {
    globalArgs: { sources: [source] },
    definitionRepository: modelRepository,
    dataRepository: repo(),
    writeResource: async (spec, name, value) => {
      assertEquals([spec, name], ["snapshot", "snapshot"]);
      saved = value;
      return { name };
    },
  });
  const snapshot = Snapshot.parse(saved);
  assertEquals(result.dataHandles, [{ name: "snapshot" }]);
  assertEquals<unknown>(snapshot.observations, [{
    category: "storage",
    version: 7,
    available: true,
    metadata,
  }]);
  assertEquals(JSON.stringify(snapshot).includes(source.modelId), false);
  assertEquals(JSON.stringify(snapshot).includes(source.modelType), false);
  assert(snapshot.collectedAt !== metadata.observedAt);
});

Deno.test("unknown time, explicit zero/false/null and unavailable resources remain distinct", async () => {
  for (
    const value of [null, {
      ...metadata,
      observedAt: null,
      counts: { expected: 0, observed: 0, unhealthy: 0, unknown: 0 },
      flags: { reachable: false, configured: null },
    }]
  ) {
    let saved: unknown;
    await model.methods.capture.execute({}, {
      globalArgs: { sources: [source] },
      definitionRepository: modelRepository,
      dataRepository: repo(value === null ? null : encode(value)),
      writeResource: async (_s, name, data) => {
        saved = data;
        return { name };
      },
    });
    const row = Snapshot.parse(saved).observations[0];
    assertEquals(row.available, value !== null);
    assertEquals<unknown>(row.metadata, value);
  }
});

Deno.test("reject arbitrary projections, labels, unknown arguments, duplicate categories and unsafe routing", async () => {
  for (
    const globalArgs of [
      { sources: [{ ...source, fields: ["password"] }] },
      { sources: [{ ...source, label: "PRIVATE_LABEL" }] },
      { sources: [{ ...source, category: "PRIVATE_CATEGORY" }] },
      { sources: [source, source] },
      { sources: [{ ...source, dataName: "../private" }] },
      { sources: [{ ...source, modelType: "../../private" }] },
      { sources: [source], unexpected: true },
    ]
  ) {
    let writes = 0;
    const error = await assertRejects(() =>
      model.methods.capture.execute({}, {
        globalArgs,
        definitionRepository: modelRepository,
        dataRepository: repo(),
        writeResource: async () => {
          writes++;
          return { name: "snapshot" };
        },
      })
    );
    assertEquals(writes, 0);
    assertEquals(String(error).includes("PRIVATE_"), false);
  }
});

Deno.test("strict operational contract rejects extra/missing keys, coercion, invalid dates and inconsistent counts", async () => {
  for (
    const value of [
      { ...metadata, token: "PRIVATE_VALUE" },
      { ...metadata, counts: { ...metadata.counts, note: "PRIVATE_VALUE" } },
      { ...metadata, flags: { ...metadata.flags, note: "PRIVATE_VALUE" } },
      { ...metadata, schemaVersion: 2 },
      { ...metadata, collectorStatus: "healthy" },
      { ...metadata, flags: { reachable: "false", configured: true } },
      { ...metadata, flags: { reachable: true } },
      ...[-1, 1.5, 1_000_001, "7", null].map((observed) => ({
        ...metadata,
        counts: { ...metadata.counts, observed },
      })),
      {
        ...metadata,
        counts: { expected: 2, observed: 3, unhealthy: 0, unknown: 0 },
      },
      {
        ...metadata,
        counts: { expected: 9, observed: 7, unhealthy: 6, unknown: 2 },
      },
      ...[
        "2026-02-30T00:00:00.000Z",
        "2026-10-14T00:00:00Z",
        "PRIVATE_VALUE",
        0,
      ].map((observedAt) => ({ ...metadata, observedAt })),
      [],
      null,
    ]
  ) {
    let writes = 0;
    const error = await assertRejects(() =>
      model.methods.capture.execute({}, {
        globalArgs: { sources: [source] },
        definitionRepository: modelRepository,
        dataRepository: repo(encode(value)),
        writeResource: async () => {
          writes++;
          return { name: "snapshot" };
        },
      })
    );
    assertEquals(writes, 0);
    assertEquals(String(error).includes("PRIVATE_VALUE"), false);
  }
});

Deno.test("hostile numeric literals cannot round or underflow into valid bounded counts", async () => {
  for (
    const literal of [
      "1e-400",
      "1.00000000000000001",
      "9007199254740993",
      "-0",
      "-0.0",
      "1e400",
    ]
  ) {
    let writes = 0;
    const bytes = new TextEncoder().encode(
      JSON.stringify({
        ...metadata,
        counts: { expected: 9, observed: 7, unhealthy: 0, unknown: 0 },
      })
        .replace('"observed":7', `"observed":${literal}`),
    );
    await assertRejects(
      () =>
        model.methods.capture.execute({}, {
          globalArgs: { sources: [source] },
          definitionRepository: modelRepository,
          dataRepository: repo(bytes),
          writeResource: async () => {
            writes++;
            return { name: "snapshot" };
          },
        }),
      Error,
      "Documentation evidence capture failed",
    );
    assertEquals(writes, 0, literal);
  }
});

Deno.test("later corrupt source never persists partial capture; errors are sanitized", async () => {
  for (
    const failure of ["utf8", "oversized", "json", "version", "repository"]
  ) {
    let writes = 0;
    const error = await assertRejects(() =>
      model.methods.capture.execute({}, {
        globalArgs: {
          sources: [source, {
            ...source,
            category: "network",
            dataName: "second",
          }],
        },
        definitionRepository: modelRepository,
        dataRepository: {
          findByName: async (_t, _i, name) => ({
            name,
            version: name === "second" && failure === "version" ? NaN : 7,
            size: name === "summary"
              ? encode(metadata).length
              : failure === "utf8"
              ? 1
              : failure === "oversized"
              ? 64_001
              : 2,
          }),
          stream: async function* (_t, _i, name) {
            if (name === "summary") {
              yield encode(metadata);
              return;
            }
            if (failure === "repository") throw Error("PRIVATE_STORAGE_DETAIL");
            yield failure === "utf8"
              ? new Uint8Array([255])
              : failure === "oversized"
              ? new Uint8Array(64_001)
              : encode([]);
          },
        },
        writeResource: async () => {
          writes++;
          return { name: "snapshot" };
        },
      })
    );
    assertEquals(writes, 0);
    assertEquals(String(error).includes("PRIVATE_STORAGE_DETAIL"), false);
  }
});

Deno.test("capture cancellation and write failure are not successful evidence", async () => {
  for (const stage of ["before", "metadata", "content", "write", "failure"]) {
    const controller = new AbortController();
    const reason = new DOMException("Cancelled capture", "AbortError");
    if (stage === "before") controller.abort(reason);
    let writes = 0;
    const error = await assertRejects(() =>
      model.methods.capture.execute({}, {
        globalArgs: { sources: [source] },
        signal: controller.signal,
        definitionRepository: modelRepository,
        dataRepository: {
          findByName: async () => {
            if (stage === "metadata") controller.abort(reason);
            return {
              name: "summary",
              version: 7,
              size: encode(metadata).length,
            };
          },
          stream: async function* () {
            if (stage === "content") controller.abort(reason);
            yield encode(metadata);
          },
        },
        writeResource: async () => {
          writes++;
          if (stage === "write") controller.abort(reason);
          throw Error("PRIVATE_WRITE_DETAIL");
        },
      })
    );
    assertEquals(writes, stage === "write" || stage === "failure" ? 1 : 0);
    if (stage !== "failure") assertEquals(error, reason);
    else assertEquals(String(error).includes("PRIVATE_WRITE_DETAIL"), false);
  }
});

Deno.test("capture accepts the exact byte boundary and rejects oversized or mis-sized streams without a snapshot", async () => {
  for (
    const [length, recordedSize] of [
      [64_000, 64_000],
      [64_001, 64_001],
      [64_001, 64_000],
      [64_000, 63_999],
      [63_999, 64_000],
    ]
  ) {
    const text = JSON.stringify(metadata).padEnd(length, " ");
    const bytes = new TextEncoder().encode(text);
    let saved: unknown;
    let closed = false;
    const run = () =>
      model.methods.capture.execute({}, {
        globalArgs: { sources: [source] },
        definitionRepository: modelRepository,
        dataRepository: {
          findByName: async () => ({
            name: "summary",
            version: 7,
            size: recordedSize,
          }),
          stream: async function* () {
            try {
              for (let i = 0; i < bytes.length; i += 8192) {
                yield bytes.subarray(i, i + 8192);
              }
            } finally {
              closed = true;
            }
          },
        },
        writeResource: async (_s, name, value) => {
          saved = value;
          return { name };
        },
      });
    if (length === 64_000 && recordedSize === length) {
      await run();
      assertEquals<unknown>(
        Snapshot.parse(saved).observations[0].metadata,
        metadata,
      );
    } else {
      await assertRejects(run, Error, "Documentation evidence capture failed");
      assertEquals(saved, undefined);
    }
    if (recordedSize <= 64_000) assertEquals(closed, true);
  }
});

Deno.test("exact-name lookup rejects rename redirects, invalid metadata and wrong producer UUID/type", async () => {
  for (
    const override of [
      { name: "renamed" },
      { version: 0 },
      { size: undefined },
      { size: -1 },
    ]
  ) {
    let saved: unknown;
    await assertRejects(() =>
      model.methods.capture.execute({}, {
        globalArgs: { sources: [source] },
        definitionRepository: modelRepository,
        dataRepository: {
          ...repo(),
          findByName: async () => ({
            name: "summary",
            version: 7,
            size: encode(metadata).length,
            ...override,
          }),
        },
        writeResource: async (_s, name, value) => {
          saved = value;
          return { name };
        },
      })
    );
    assertEquals(saved, undefined);
  }
  for (
    const producer of [null, {
      type: { ...type, toString: () => "@example/other" },
    }]
  ) {
    await assertRejects(
      () =>
        model.methods.capture.execute({}, {
          globalArgs: { sources: [source] },
          definitionRepository: { findByIdGlobal: async () => producer },
          dataRepository: repo(),
          writeResource: async () => {
            throw Error("Unexpected write");
          },
        }),
      Error,
      "Documentation evidence capture failed",
    );
  }
});
