import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { model, setFetcherForTest } from "./openai_usage.ts";

type Json = Record<string, unknown>;
const bucket = (results: unknown[]) => ({
  object: "bucket",
  start_time: 1,
  end_time: 2,
  results,
});
const page = (
  results: unknown[],
  hasMore = false,
  next: string | null = null,
) => ({
  object: "page",
  data: [bucket(results)],
  has_more: hasMore,
  next_page: next,
});
const usage = (overrides: Json = {}) => ({
  input_tokens: 10,
  output_tokens: 5,
  input_cached_tokens: 2,
  num_model_requests: 1,
  project_id: "proj_example",
  model: "gpt-example",
  ...overrides,
});
const cost = (overrides: Json = {}) => ({
  amount: { value: 1.25, currency: "usd" },
  project_id: "proj_example",
  line_item: "example",
  ...overrides,
});

async function run(fetchImpl: typeof fetch) {
  const written: Json[] = [];
  setFetcherForTest(fetchImpl);
  try {
    await model.methods.collect.execute({ startTime: 1, endTime: 3 }, {
      globalArgs: {
        apiKey: "secret-admin-key",
        timeoutMs: 100,
      },
      signal: new AbortController().signal,
      writeResource: (_spec: string, _name: string, data: Json) => {
        written.push(data);
        return Promise.resolve({});
      },
    });
  } finally {
    setFetcherForTest();
  }
  return written[0];
}

Deno.test("collector paginates both dimensions and preserves exact totals", async () => {
  const calls: string[] = [];
  const result = await run((input) => {
    const url = String(input);
    calls.push(url);
    const second = url.includes("page=next");
    const isCost = url.includes("organization%2Fcosts") ||
      url.includes("/costs?");
    return Promise.resolve(
      Response.json(
        isCost
          ? page(
            [cost({ amount: { value: second ? 2.5 : 1.25, currency: "usd" } })],
            !second,
            second ? null : "next",
          )
          : page(
            [usage({ input_tokens: second ? 20 : 10 })],
            !second,
            second ? null : "next",
          ),
      ),
    );
  });
  assertEquals(calls.length, 4);
  assertEquals((result.usageStatus as Json).state, "complete");
  assertEquals((result.usage as Json).inputTokens, 30);
  assertEquals(((result.costs as Json).totals as Json[])[0].value, 3.75);
  assertEquals(calls.every((url) => !url.includes("secret-admin-key")), true);
});

Deno.test("later page failure retains partial data without false completeness", async () => {
  const result = await run((input) =>
    String(input).includes("page=next")
      ? Promise.resolve(new Response("private response", { status: 429 }))
      : Promise.resolve(
        Response.json(
          page(
            String(input).includes("/costs?") ? [cost()] : [usage()],
            true,
            "next",
          ),
        ),
      )
  );
  assertEquals((result.usageStatus as Json).state, "partial");
  assertEquals((result.costStatus as Json).errorKind, "rate-limited");
  assertEquals((result.usage as Json).inputTokens, 10);
});

Deno.test("authorization failures are separate for usage and cost", async () => {
  const result = await run((input) =>
    Promise.resolve(
      String(input).includes("/costs?")
        ? Response.json(page([cost()]))
        : new Response("credential text", { status: 403 }),
    )
  );
  assertEquals((result.usageStatus as Json).errorKind, "unauthorized");
  assertEquals(result.usage, null);
  assertEquals((result.costStatus as Json).state, "complete");
});

Deno.test("malformed records become unavailable and never become zero", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost()]
        : [usage({ input_tokens: "ten" })],
    )))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
});

Deno.test("malformed buckets become invalid instead of complete zero", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(
      String(input).includes("costs")
        ? page([])
        : { ...page([]), data: [{ starting_at: 1 }] },
    ))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
});

Deno.test("invalid JSON is classified without persisting response text", async () => {
  const result = await run(() =>
    Promise.resolve(
      new Response("private malformed response", {
        headers: { "content-type": "application/json" },
      }),
    )
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(JSON.stringify(result).includes("private malformed"), false);
});

Deno.test("per-endpoint timeout becomes unavailable without a false zero", async () => {
  const result = await run((_input, init) =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener(
        "abort",
        () => reject(init.signal?.reason),
      );
    })
  );
  assertEquals((result.usageStatus as Json).errorKind, "timeout");
  assertEquals((result.costStatus as Json).errorKind, "timeout");
  assertEquals(result.usage, null);
  assertEquals(result.costs, null);
});

Deno.test("caller cancellation aborts collection instead of persisting partial data", async () => {
  const controller = new AbortController();
  setFetcherForTest((_input, init) =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener(
        "abort",
        () => reject(init.signal?.reason),
      );
    })
  );
  let written = false;
  const pending = model.methods.collect.execute({ startTime: 1, endTime: 3 }, {
    globalArgs: {
      apiKey: "secret-admin-key",
      timeoutMs: 1000,
    },
    signal: controller.signal,
    writeResource: () => {
      written = true;
      return Promise.resolve({});
    },
  });
  controller.abort(new Error("caller cancelled"));
  try {
    await pending;
    throw new Error("expected cancellation");
  } catch (error) {
    assertEquals((error as Error).message, "caller cancelled");
  } finally {
    setFetcherForTest();
  }
  assertEquals(written, false);
});

// OpenAI's UsageCompletionsResult marks input_cached_tokens optional. Treating
// its absence as a failure blacked out the whole usage dimension for a
// spec-legal page.
Deno.test("absent optional cached-token counter reads as zero, not a blackout", async () => {
  const withoutCached = usage();
  delete (withoutCached as Json).input_cached_tokens;
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?") ? [cost()] : [withoutCached],
    )))
  );
  assertEquals((result.usageStatus as Json).state, "complete");
  assertEquals((result.usage as Json).cachedInputTokens, 0);
  assertEquals((result.usage as Json).inputTokens, 10);
});

// The tolerance above is for absence only. A counter that is present but
// wrongly typed is still a protocol violation.
Deno.test("present but wrongly typed cached-token counter still invalidates usage", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost()]
        : [usage({ input_cached_tokens: "two" })],
    )))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
});

// CostsResult requires only `object`; amount is optional. One amount-less row
// used to null the entire cost dimension.
Deno.test("cost rows without an amount are dropped and marked partial, not blacked out", async () => {
  const withoutAmount = cost();
  delete (withoutAmount as Json).amount;
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost({ amount: { value: 4, currency: "usd" } }), withoutAmount]
        : [usage()],
    )))
  );
  const costs = result.costs as Json;
  assertEquals(costs === null, false);
  assertEquals((costs.breakdowns as Json[]).length, 1);
  assertEquals((costs.totals as Json[])[0].value, 4);
  assertEquals((result.costStatus as Json).state, "partial");
  assertStringIncludes((result.costStatus as Json).message as string, "1 cost");
});

Deno.test("cost amount present but wrongly typed still invalidates costs", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost({ amount: { value: "1.25", currency: "usd" } })]
        : [usage()],
    )))
  );
  assertEquals((result.costStatus as Json).errorKind, "invalid-response");
  assertEquals(result.costs, null);
});

// Number.isInteger accepted 1e21, which the snapshot schema's .int() rejects,
// so the value reached SnapshotSchema.parse and threw a ZodError out of
// collect() — taking the healthy cost dimension down with it.
Deno.test("token count above MAX_SAFE_INTEGER degrades usage without rejecting the run", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost()]
        : [usage({ input_tokens: 1e21 })],
    )))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
  assertEquals((result.costStatus as Json).state, "complete");
  assertEquals(((result.costs as Json).totals as Json[])[0].value, 1.25);
});

// Individually safe integers can still sum past MAX_SAFE_INTEGER.
Deno.test("token totals overflowing MAX_SAFE_INTEGER degrade usage rather than throw", async () => {
  const big = Number.MAX_SAFE_INTEGER;
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost()]
        : [usage({ input_tokens: big }), usage({ input_tokens: big })],
    )))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
  assertEquals((result.costStatus as Json).state, "complete");
});

// Two finite amounts near Number.MAX_VALUE sum to Infinity, which the schema's
// .finite() rejects. Same crash, opposite dimension.
Deno.test("cost totals overflowing to Infinity degrade costs rather than throw", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [
          cost({ amount: { value: 1.7e308, currency: "usd" } }),
          cost({ amount: { value: 1.7e308, currency: "usd" } }),
        ]
        : [usage()],
    )))
  );
  assertEquals((result.costStatus as Json).errorKind, "invalid-response");
  assertEquals(result.costs, null);
  assertEquals((result.usageStatus as Json).state, "complete");
  assertEquals((result.usage as Json).inputTokens, 10);
});

// CollectArgsSchema accepts any nonnegative integer, but Date#toISOString()
// throws a bare "Invalid time value" past ~8.64e12 seconds.
Deno.test("an unrepresentable window fails with a message naming the arguments", async () => {
  setFetcherForTest(() => Promise.resolve(Response.json(page([]))));
  try {
    await model.methods.collect.execute({
      startTime: 1e15,
      endTime: 1e15 + 1,
    }, {
      globalArgs: { apiKey: "secret-admin-key", timeoutMs: 100 },
      signal: new AbortController().signal,
      writeResource: () => Promise.resolve({}),
    });
    throw new Error("expected rejection");
  } catch (error) {
    assertStringIncludes(
      (error as Error).message,
      "startTime and endTime must be representable Unix seconds",
    );
  } finally {
    setFetcherForTest();
  }
});

Deno.test("requests contain explicit windows and grouping dimensions", async () => {
  const urls: string[] = [];
  await run((input) => {
    urls.push(String(input));
    return Promise.resolve(Response.json(page([])));
  });
  const usageUrl = urls.find((url) => url.includes("/usage/completions"))!;
  assertStringIncludes(usageUrl, "start_time=1");
  assertStringIncludes(usageUrl, "end_time=3");
  assertStringIncludes(usageUrl, "group_by=project_id");
  assertStringIncludes(usageUrl, "group_by=model");
});
