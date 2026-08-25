import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { model, setFetcherForTest } from "./anthropic_usage.ts";
type Json = Record<string, unknown>;
const bucket = (results: unknown[]) => ({
  starting_at: "2026-08-01T00:00:00Z",
  ending_at: "2026-08-02T00:00:00Z",
  results,
});
const page = (
  results: unknown[],
  more = false,
  next: string | null = null,
  refreshed = "2026-08-02T04:00:00Z",
) => ({
  data: [bucket(results)],
  has_more: more,
  next_page: next,
  data_refreshed_at: refreshed,
});
const usage = (enterprise: boolean, overrides: Json = {}) => ({
  uncached_input_tokens: 10,
  cache_creation: {
    ephemeral_5m_input_tokens: 2,
    ephemeral_1h_input_tokens: 3,
  },
  cache_read_input_tokens: 4,
  output_tokens: 5,
  requests: enterprise ? 2 : undefined,
  workspace_id: enterprise ? undefined : "wrkspc_example",
  product: enterprise ? "claude_code" : undefined,
  model: "claude-example",
  ...overrides,
});
const cost = (enterprise: boolean, overrides: Json = {}) => ({
  amount: enterprise ? "125" : "1.25",
  currency: "USD",
  workspace_id: enterprise ? undefined : "wrkspc_example",
  product: enterprise ? "claude_code" : undefined,
  model: "claude-example",
  description: "example",
  ...overrides,
});
async function run(
  kind: "platform" | "enterprise",
  fetchImpl: typeof fetch,
  authentication: "api-key" | "oauth" = "api-key",
) {
  const written: Json[] = [];
  setFetcherForTest(fetchImpl);
  try {
    await model.methods.collect.execute({
      startingAt: "2026-08-01T00:00:00Z",
      endingAt: "2026-08-03T00:00:00Z",
    }, {
      globalArgs: {
        credential: "private-credential",
        accountKind: kind,
        authentication,
        timeoutMs: 50,
      },
      signal: new AbortController().signal,
      writeResource: (_s: string, _n: string, data: Json) => {
        written.push(data);
        return Promise.resolve({});
      },
    });
  } finally {
    setFetcherForTest();
  }
  return written[0];
}
Deno.test("platform uses Admin endpoints and leaves undocumented request count unavailable", async () => {
  const urls: string[] = [];
  const result = await run("platform", (input, init) => {
    urls.push(String(input));
    assertEquals((init?.headers as Json)["x-api-key"], "private-credential");
    return Promise.resolve(
      Response.json(
        page(
          String(input).includes("cost_report")
            ? [cost(false)]
            : [usage(false)],
        ),
      ),
    );
  });
  assertEquals((result.usage as Json).requests, null);
  assertEquals(
    ((result.costs as Json).totalsMinor as Json[])[0].amountMinor,
    "1.25",
  );
  assertEquals(urls.some((url) => url.includes("usage_report/messages")), true);
});
Deno.test("platform OAuth uses bearer without leaking credential into URL", async () => {
  const urls: string[] = [];
  await run("platform", (input, init) => {
    urls.push(String(input));
    assertEquals(
      (init?.headers as Json).authorization,
      "Bearer private-credential",
    );
    return Promise.resolve(
      Response.json(
        page(
          String(input).includes("cost_report")
            ? [cost(false)]
            : [usage(false)],
        ),
      ),
    );
  }, "oauth");
  assertEquals(urls.every((url) => !url.includes("private-credential")), true);
});
Deno.test("enterprise uses Analytics endpoints and preserves minor-unit decimal totals", async () => {
  const result = await run(
    "enterprise",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(true)] : [usage(true)],
      ))),
  );
  assertEquals((result.usage as Json).requests, 2);
  assertEquals(
    ((result.costs as Json).totalsMinor as Json[])[0].amountMinor,
    "125",
  );
  assertEquals(result.dataRefreshedAt, "2026-08-02T04:00:00Z");
});
Deno.test("pagination exact totals and later-page rate limit remains partial", async () => {
  let calls = 0;
  const result = await run("enterprise", (input) => {
    calls++;
    return Promise.resolve(
      String(input).includes("page=next")
        ? new Response("private", { status: 429 })
        : Response.json(
          page(
            String(input).includes("cost_report")
              ? [cost(true)]
              : [usage(true)],
            true,
            "next",
          ),
        ),
    );
  });
  assertEquals(calls, 4);
  assertEquals((result.usageStatus as Json).state, "partial");
  assertEquals((result.costStatus as Json).errorKind, "rate-limited");
  assertEquals((result.usage as Json).uncachedInputTokens, 10);
});
Deno.test("unauthorized and unsupported are distinct capability states", async () => {
  const unauthorized = await run(
    "platform",
    () => Promise.resolve(new Response("private", { status: 403 })),
  );
  assertEquals((unauthorized.usageStatus as Json).errorKind, "unauthorized");
  const unsupported = await run(
    "enterprise",
    () => Promise.resolve(new Response("private", { status: 404 })),
  );
  assertEquals((unsupported.usageStatus as Json).state, "unsupported");
});
Deno.test("malformed dimensions never become zero", async () => {
  const result = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? [cost(false)]
          : [usage(false, { output_tokens: "five" })],
      ))),
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
});
Deno.test("enterprise rejects incompatible OAuth mode before network", async () => {
  setFetcherForTest(() => {
    throw new Error("must not fetch");
  });
  try {
    await assertRejects(
      () =>
        model.methods.collect.execute({
          startingAt: "2026-08-01T00:00:00Z",
          endingAt: "2026-08-02T00:00:00Z",
        }, {
          globalArgs: {
            credential: "private",
            accountKind: "enterprise",
            authentication: "oauth",
          },
          signal: new AbortController().signal,
          writeResource: () => Promise.resolve({}),
        }),
      Error,
      "requires authentication=api-key",
    );
  } finally {
    setFetcherForTest();
  }
});
Deno.test("queries carry exact windows and stable grouping", async () => {
  const urls: string[] = [];
  await run("enterprise", (input) => {
    urls.push(String(input));
    return Promise.resolve(
      Response.json(page(String(input).includes("cost_report") ? [] : [])),
    );
  });
  assertStringIncludes(urls[0], "starting_at=2026-08-01T00%3A00%3A00Z");
  assertStringIncludes(urls[0], "group_by%5B%5D=product");
});
