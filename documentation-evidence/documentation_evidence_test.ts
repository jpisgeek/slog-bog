import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { FakeTime } from "jsr:@std/testing@1.0.21/time";
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
const modelRepository = { findAllByIdGlobal: async () => [{ type }] };
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
      { sources: [{ ...source, label: "PRIVATE_LABEL" }] },
      { sources: [{ ...source, category: "PRIVATE_CATEGORY" }] },
      { sources: [source, source] },
      { sources: [source, { ...source, category: "network" }] },
      {
        sources: [{
          ...source,
          modelId: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        }],
      },
      {
        sources: [
          { ...source, modelId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
          {
            ...source,
            category: "network",
            modelId: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
          },
        ],
      },
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
      { ...metadata, ["__proto__"]: "PRIVATE_VALUE" },
      {
        ...metadata,
        counts: { ...metadata.counts, ["__proto__"]: "PRIVATE_VALUE" },
      },
      {
        ...metadata,
        flags: { ...metadata.flags, ["__proto__"]: "PRIVATE_VALUE" },
      },
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

Deno.test("duplicate decoded JSON members at every object depth are rejected before conflicting values disappear", async () => {
  const text = JSON.stringify(metadata);
  for (
    const raw of [
      text.replace(
        '"collectorStatus":"succeeded"',
        '"collectorStatus":"failed","collectorStatus":"succeeded"',
      ),
      text.replace(
        '"collectorStatus":"succeeded"',
        '"collector\\u0053tatus":"failed","collectorStatus":"succeeded"',
      ),
      text.replace('"unhealthy":2', '"unhealthy":3,"unhealthy":2'),
      text.replace(
        '"reachable":false',
        '"reach\\u0061ble":true,"reachable":false',
      ),
    ]
  ) {
    // Every fixture would otherwise parse to the valid payload; malformed JSON
    // must not accidentally make a duplicate-key regression test pass.
    assertEquals(JSON.parse(raw), metadata);
    let writes = 0;
    await assertRejects(() =>
      model.methods.capture.execute({}, {
        globalArgs: { sources: [source] },
        definitionRepository: modelRepository,
        dataRepository: repo(new TextEncoder().encode(raw)),
        writeResource: async () => {
          writes++;
          return { name: "snapshot" };
        },
      })
    );
    assertEquals(writes, 0);
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

Deno.test("capture permits empty chunks but does not starve timer-driven cancellation", async () => {
  for (const cancel of [false, true]) {
    const controller = new AbortController();
    const reason = new DOMException("Cancelled immediate stream", "AbortError");
    let writes = 0;
    const timer = cancel
      ? setTimeout(() => controller.abort(reason), 0)
      : undefined;
    try {
      const result = model.methods.capture.execute({}, {
        globalArgs: { sources: [source] },
        signal: controller.signal,
        definitionRepository: modelRepository,
        dataRepository: {
          ...repo(),
          stream: async function* () {
            for (let i = 0; i < 5000; i++) yield new Uint8Array();
            yield encode(metadata);
          },
        },
        writeResource: async () => {
          writes++;
          return { name: "snapshot" };
        },
      });
      if (cancel) assertEquals(await assertRejects(() => result), reason);
      else await result;
      assertEquals(writes, cancel ? 0 : 1);
    } finally {
      clearTimeout(timer);
    }
  }
});

Deno.test("capture permits 64000 one-byte chunks but bounds an endless empty stream", async () => {
  for (const endless of [false, true]) {
    const text = JSON.stringify(metadata);
    const bytes = new TextEncoder().encode(text.padEnd(64_000));
    let pulls = 0;
    let writes = 0;
    let closed = false;
    const result = model.methods.capture.execute({}, {
      globalArgs: { sources: [source] },
      definitionRepository: modelRepository,
      dataRepository: {
        findByName: async () => ({ name: "summary", version: 7, size: 64_000 }),
        stream: async function* () {
          try {
            while (endless || pulls < bytes.length) {
              pulls++;
              yield endless
                ? new Uint8Array()
                : bytes.subarray(pulls - 1, pulls);
            }
          } finally {
            closed = true;
          }
        },
      },
      writeResource: async () => {
        writes++;
        return { name: "snapshot" };
      },
    }).then(() => true, () => false);
    assertEquals(await result, !endless);
    assertEquals(pulls, endless ? 64_001 : 64_000);
    assertEquals(writes, endless ? 0 : 1);
    assertEquals(closed, true);
  }
});

Deno.test("an expired deadline cannot lose to an already fulfilled repository promise", async () => {
  for (const stage of ["definition", "metadata", "stream"]) {
    using time = new FakeTime();
    let writes = 0;
    let sent = false;
    await assertRejects(
      () =>
        model.methods.capture.execute({}, {
          globalArgs: { sources: [source] },
          definitionRepository: {
            findAllByIdGlobal: () => {
              if (stage === "definition") time.tick(30_000);
              return Promise.resolve([{ type }]);
            },
          },
          dataRepository: {
            findByName: () => {
              if (stage === "metadata") time.tick(30_000);
              return Promise.resolve({
                name: "summary",
                version: 7,
                size: encode(metadata).length,
              });
            },
            stream: () => ({
              [Symbol.asyncIterator]: () => ({
                next: () => {
                  if (stage === "stream" && !sent) time.tick(30_000);
                  const item = sent
                    ? { done: true as const, value: undefined }
                    : { done: false as const, value: encode(metadata) };
                  sent = true;
                  return Promise.resolve(item);
                },
              }),
            }),
          },
          writeResource: async () => {
            writes++;
            return { name: "snapshot" };
          },
        }),
      Error,
      "Documentation evidence capture failed",
    );
    assertEquals(writes, 0);
  }
});

Deno.test("pending definition, metadata and stream reads cancel promptly without waiting for backend close", async () => {
  for (const stage of ["definition", "metadata", "stream"]) {
    const controller = new AbortController();
    const reason = new DOMException("Cancelled pending read", "AbortError");
    let closeRequested = false;
    let writes = 0;
    const stall = <T>(): Promise<T> => {
      controller.abort(reason);
      return new Promise(() => {});
    };
    let timer: ReturnType<typeof setTimeout>;
    try {
      const result = model.methods.capture.execute({}, {
        globalArgs: { sources: [source] },
        signal: controller.signal,
        definitionRepository: {
          findAllByIdGlobal: () =>
            stage === "definition" ? stall() : Promise.resolve([{ type }]),
        },
        dataRepository: {
          ...repo(),
          findByName: () =>
            stage === "metadata" ? stall() : repo().findByName(),
          stream: () => ({
            [Symbol.asyncIterator]: () => ({
              next: () => stall<IteratorResult<Uint8Array>>(),
              return: () => {
                closeRequested = true;
                return new Promise<IteratorResult<Uint8Array>>(() => {});
              },
            }),
          }),
        },
        writeResource: async () => {
          writes++;
          return { name: "snapshot" };
        },
      });
      const error = await assertRejects(() =>
        Promise.race([
          result,
          new Promise((_, reject) => {
            timer = setTimeout(
              () => reject(Error("Cancellation stalled")),
              1000,
            );
          }),
        ])
      );
      assertEquals(error, reason, stage);
      assertEquals(writes, 0);
      assertEquals(closeRequested, stage === "stream");
    } finally {
      clearTimeout(timer!);
    }
  }
});

Deno.test("definition lookups and entire metadata/content reads have a 30-second deadline, not a renewed chunk timeout", async () => {
  using time = new FakeTime();
  for (const stage of ["definition", "metadata", "stream"]) {
    let writes = 0;
    let pulls = 0;
    let closed = false;
    let settled = false;
    const pending = new Promise<never>(() => {});
    const result = assertRejects(
      () =>
        model.methods.capture.execute({}, {
          globalArgs: { sources: [source] },
          definitionRepository: {
            findAllByIdGlobal: () =>
              stage === "definition" ? pending : Promise.resolve([{ type }]),
          },
          dataRepository: {
            ...repo(),
            findByName: () =>
              stage === "metadata" ? pending : repo().findByName(),
            stream: () => ({
              [Symbol.asyncIterator]: () => ({
                next: () =>
                  ++pulls > 1
                    ? pending
                    : new Promise<IteratorResult<Uint8Array>>((resolve) => {
                      setTimeout(
                        () => resolve({ done: false, value: new Uint8Array() }),
                        10_000,
                      );
                    }),
                return: async () => {
                  closed = true;
                  return { done: true as const, value: undefined };
                },
              }),
            }),
          },
          writeResource: async () => {
            writes++;
            return { name: "snapshot" };
          },
        }),
      Error,
      "Documentation evidence capture failed",
    ).then(() => {
      settled = true;
    });
    await time.tickAsync(29_999);
    assertEquals(settled, false, stage);
    await time.tickAsync(1);
    await time.runMicrotasks();
    assertEquals(settled, true, stage);
    await result;
    assertEquals(writes, 0);
    assertEquals(closed, stage === "stream");
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
  const other = { type: { ...type, toString: () => "@example/other" } };
  for (const producers of [[], [other], [{ type }, { type }]]) {
    await assertRejects(
      () =>
        model.methods.capture.execute({}, {
          globalArgs: { sources: [source] },
          definitionRepository: { findAllByIdGlobal: async () => producers },
          dataRepository: repo(),
          writeResource: async () => {
            throw Error("Unexpected write");
          },
        }),
      Error,
      "Documentation evidence capture failed",
    );
  }
  let saved: unknown;
  await model.methods.capture.execute({}, {
    globalArgs: { sources: [source] },
    definitionRepository: {
      findAllByIdGlobal: async () => [other, { type }],
    },
    dataRepository: repo(),
    writeResource: async (_s, name, data) => {
      saved = data;
      return { name };
    },
  });
  assertEquals(Snapshot.parse(saved).observations[0].available, true);
});
