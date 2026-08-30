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
  window: { startingAt: string; endingAt: string } = {
    startingAt: "2026-08-01T00:00:00Z",
    endingAt: "2026-08-03T00:00:00Z",
  },
) {
  const written: Json[] = [];
  setFetcherForTest(fetchImpl);
  try {
    await model.methods.collect.execute(window, {
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
    assertEquals(init?.redirect, "error");
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
    ((result.costs as Json).totals as Json[])[0].amount,
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
Deno.test("enterprise uses Analytics endpoints and preserves decimal totals", async () => {
  const result = await run(
    "enterprise",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(true)] : [usage(true)],
      ))),
  );
  assertEquals((result.usage as Json).requests, 2);
  assertEquals(
    ((result.costs as Json).totals as Json[])[0].amount,
    "125",
  );
  assertEquals(result.dataRefreshedAt, "2026-08-02T04:00:00.000Z");
});
// Guards the amountMinor rename. The old field claimed minor units while doing
// no conversion, and the enterprise/platform ternary stored the same value two
// different ways: an Enterprise "125.00" breakdown sat next to a "125" total.
Deno.test("cost amounts are major-unit decimals under one field name for both account kinds", async () => {
  const platform = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(false)] : [usage(false)],
      ))),
  );
  const platformCosts = platform.costs as Json;
  assertEquals((platformCosts.totals as Json[])[0].amount, "1.25");
  assertEquals("totalsMinor" in platformCosts, false);
  assertEquals("amountMinor" in (platformCosts.breakdowns as Json[])[0], false);
  assertEquals((platformCosts.breakdowns as Json[])[0].amount, "1.25");

  const enterprise = await run(
    "enterprise",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? [cost(true, { amount: "125.00" })]
          : [usage(true)],
      ))),
  );
  const enterpriseCosts = enterprise.costs as Json;
  assertEquals("totalsMinor" in enterpriseCosts, false);
  assertEquals(
    (enterpriseCosts.breakdowns as Json[])[0].amount,
    (enterpriseCosts.totals as Json[])[0].amount,
  );
  assertEquals((enterpriseCosts.totals as Json[])[0].amount, "125");
});
// Anthropic documents data_refreshed_at as RFC 3339, which permits a numeric
// offset. The snapshot schema is Z-only, so the unchecked passthrough turned a
// legal value into an uncaught ZodError after both fetches had succeeded.
Deno.test("offset-form and unusable refresh timestamps never abort a good collection", async () => {
  const offset = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json({
        ...page(
          String(input).includes("cost_report")
            ? [cost(false)]
            : [usage(false)],
        ),
        data_refreshed_at: "2026-08-02T04:00:00+02:00",
      })),
  );
  assertEquals(offset.dataRefreshedAt, "2026-08-02T02:00:00.000Z");
  assertEquals((offset.usageStatus as Json).state, "complete");

  const junk = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json({
        ...page(
          String(input).includes("cost_report")
            ? [cost(false)]
            : [usage(false)],
        ),
        data_refreshed_at: "soon",
      })),
  );
  assertEquals(junk.dataRefreshedAt, null);
  assertEquals((junk.usageStatus as Json).state, "complete");
});
// CollectArgsSchema describes its inputs as RFC 3339 but inherited zod's Z-only
// restriction, so a caller passing a legal offset window got a raw ZodError.
Deno.test("offset-form collect window is accepted and stored canonically", async () => {
  const result = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(false)] : [usage(false)],
      ))),
    "api-key",
    {
      startingAt: "2026-08-01T02:00:00+02:00",
      endingAt: "2026-08-03T02:00:00+02:00",
    },
  );
  assertEquals(result.coverageStart, "2026-08-01T00:00:00.000Z");
  assertEquals(result.coverageEnd, "2026-08-03T00:00:00.000Z");
});
// integer() accepts anything Number.isInteger says is an integer, but
// UsageRowSchema's z.number().int() stops at Number.MAX_SAFE_INTEGER. That
// mismatch used to throw out of SnapshotSchema.parse at the end of collect()
// and write nothing; the rest of the extension degrades instead.
Deno.test("a late schema violation degrades to a written snapshot instead of throwing", async () => {
  const result = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? [cost(false)]
          : [usage(false, { uncached_input_tokens: 9007199254740992 })],
      ))),
  );
  assertEquals(result.provider, "anthropic");
  assertEquals(result.usage, null);
  assertEquals(result.costs, null);
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
});
// timeoutMs bounds one request and was rebuilt every iteration, so a paginator
// minting a fresh cursor forever defeated the repeated-cursor guard and ran
// without bound. Both walks must stop themselves at the page ceiling.
Deno.test("pagination stops at a fixed page ceiling against an endless paginator", async () => {
  let calls = 0;
  const result = await run("enterprise", (input) => {
    calls++;
    // Escape hatch: without the ceiling the loop is infinite, and a hanging
    // test reports nothing. Fail loudly instead, well past the real cap.
    if (calls > 1200) return Promise.resolve(new Response("", { status: 500 }));
    return Promise.resolve(Response.json(
      page(
        String(input).includes("cost_report") ? [cost(true)] : [usage(true)],
        true,
        `cursor-${calls}`,
      ),
    ));
  });
  assertEquals(calls, 1000);
  assertEquals((result.usageStatus as Json).state, "partial");
  assertEquals((result.usageStatus as Json).pagesRead, 500);
  assertEquals((result.costStatus as Json).pagesRead, 500);
});
// groupedTop100Cap used to be `accountKind === "enterprise"` — asserted on
// every Enterprise snapshot regardless of the response — which made the
// dashboard permanently partial with a standing warning nobody could clear.
Deno.test("grouped top-100 cap reflects the response, not the account kind", async () => {
  const small = await run(
    "enterprise",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(true)] : [usage(true)],
      ))),
  );
  assertEquals((small.usage as Json).groupedTop100Cap, false);
  assertEquals((small.costs as Json).groupedTop100Cap, false);

  const full = await run(
    "enterprise",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? Array.from(
            { length: 100 },
            (_, i) => cost(true, { model: `m${i}` }),
          )
          : [usage(true)],
      ))),
  );
  assertEquals((full.usage as Json).groupedTop100Cap, false);
  assertEquals((full.costs as Json).groupedTop100Cap, true);
});
// The `: {}` fallback anticipated an absent cache_creation but delivered the
// same outcome as no fallback: integer(undefined) was null, and one such row
// discarded usage for the entire window.
Deno.test("absent cache fields count as zero while malformed ones still reject", async () => {
  const absent = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(false)] : [
          usage(false, {
            cache_creation: { ephemeral_5m_input_tokens: 2 },
          }),
          usage(false, { cache_creation: undefined }),
        ],
      ))),
  );
  assertEquals((absent.usage as Json).cacheCreation1hTokens, 0);
  assertEquals((absent.usage as Json).cacheCreation5mTokens, 2);
  assertEquals((absent.usageStatus as Json).errorKind, "");

  const malformed = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(false)] : [
          usage(false, {
            cache_creation: { ephemeral_1h_input_tokens: "three" },
          }),
        ],
      ))),
  );
  assertEquals(malformed.usage, null);
  assertEquals((malformed.usageStatus as Json).errorKind, "invalid-response");

  const wrongShape = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? [cost(false)]
          : [usage(false, { cache_creation: "none" })],
      ))),
  );
  assertEquals(wrongShape.usage, null);
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

Deno.test("malformed result buckets never become complete zero usage", async () => {
  const result = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(
        String(input).includes("cost_report")
          ? page([cost(false)])
          : { ...page([]), data: [{ starting_at: "x" }] },
      )),
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
