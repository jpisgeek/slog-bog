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
