import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { model } from "./anthropic_usage.ts";
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
// cost_type is one of the group_by[] values the Enterprise cost walk requests,
// so a row that omits it is not the report that was asked for and no longer
// parses. See "a requested grouping that is absent or mistyped …" below.
const cost = (enterprise: boolean, overrides: Json = {}) => ({
  amount: enterprise ? "125" : "1.25",
  currency: "USD",
  workspace_id: enterprise ? undefined : "wrkspc_example",
  product: enterprise ? "claude_code" : undefined,
  cost_type: enterprise ? "tokens" : undefined,
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
  await model.methods.collect.execute(window, {
    globalArgs: {
      credential: "private-credential",
      accountKind: kind,
      authentication,
      timeoutMs: 50,
    },
    fetch: fetchImpl,
    signal: new AbortController().signal,
    writeResource: (_s: string, _n: string, data: Json) => {
      written.push(data);
      return Promise.resolve({});
    },
  });
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
    ((result.costs as Json).totals as Json[])[0].amountMinor,
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
    ((result.costs as Json).totals as Json[])[0].amountMinor,
    "125",
  );
  assertEquals(result.usageRefreshedAt, "2026-08-02T04:00:00.000Z");
});
// Both vendor endpoints report fractional cents, retained without rescaling.
Deno.test("cost amounts remain exact minor-unit decimals for both account kinds", async () => {
  const platform = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(false)] : [usage(false)],
      ))),
  );
  const platformCosts = platform.costs as Json;
  assertEquals((platformCosts.totals as Json[])[0].amountMinor, "1.25");
  assertEquals("totalsMinor" in platformCosts, false);
  assertEquals("amount" in (platformCosts.breakdowns as Json[])[0], false);
  assertEquals((platformCosts.breakdowns as Json[])[0].amountMinor, "1.25");

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
    (enterpriseCosts.breakdowns as Json[])[0].amountMinor,
    (enterpriseCosts.totals as Json[])[0].amountMinor,
  );
  assertEquals((enterpriseCosts.totals as Json[])[0].amountMinor, "125");
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
  assertEquals(offset.usageRefreshedAt, "2026-08-02T02:00:00.000Z");
  assertEquals(offset.usageRefreshState, "observed");
  assertEquals((offset.usageStatus as Json).state, "complete");
});
// A present-but-unusable refresh timestamp used to be discarded on
// `if (refreshed) refreshedAt = refreshed`, leaving a snapshot identical to one
// where Anthropic sent no refresh evidence at all — after which the dashboard
// substituted collection time and called the section fresh. The three cases are
// now distinct in the snapshot, and only "observed" can become a fresh
// observation downstream.
Deno.test("absent, observed and invalid refresh evidence are three distinct states", async () => {
  const absent = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json({
        ...page(
          String(input).includes("cost_report")
            ? [cost(false)]
            : [usage(false)],
        ),
        data_refreshed_at: undefined,
      })),
  );
  assertEquals(absent.usageRefreshState, "absent");
  assertEquals(absent.usageRefreshedAt, null);

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
  assertEquals(junk.usageRefreshState, "invalid");
  assertEquals(junk.usageRefreshedAt, null);

  // Each endpoint retains its own evidence; cost freshness cannot certify usage.
  const mixed = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json({
        ...page(
          String(input).includes("cost_report")
            ? [cost(false)]
            : [usage(false)],
        ),
        data_refreshed_at: String(input).includes("cost_report")
          ? "2026-08-02T04:00:00Z"
          : "soon",
      })),
  );
  assertEquals(mixed.usageRefreshState, "invalid");
  assertEquals(mixed.usageRefreshedAt, null);
  assertEquals(mixed.costRefreshState, "observed");
  assertEquals(mixed.costRefreshedAt, "2026-08-02T04:00:00.000Z");
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
// A token count past Number.MAX_SAFE_INTEGER is now refused at the response
// boundary, so it degrades only its own dimension: the cost walk succeeded and
// keeps its result instead of being discarded by a ZodError raised on the other
// dimension's behalf.
Deno.test("an unrepresentable counter degrades its own dimension and spares the other", async () => {
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
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals((result.costStatus as Json).state, "complete");
  assertEquals(
    ((result.costs as Json).totals as Json[])[0].amountMinor,
    "1.25",
  );
});
// Row-level guards do not survive addition: two individually legal counters can
// still sum past Number.MAX_SAFE_INTEGER. That used to throw an uncaught
// ZodError after both paginated fetches had succeeded and nothing at all was
// written; the last-resort net degrades to a written snapshot instead.
Deno.test("a total that overflows after summing still degrades to a written snapshot", async () => {
  const half = 2 ** 52;
  const result = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(false)] : [
          usage(false, { uncached_input_tokens: half, model: "a" }),
          usage(false, { uncached_input_tokens: half, model: "b" }),
        ],
      ))),
  );
  assertEquals(result.provider, "anthropic");
  assertEquals(result.usage, null);
  assertEquals(result.costs, null);
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
});
// `if (object.has_more !== true)` read a missing, null or string pagination flag
// as "no next page" — the one answer that both ends the walk and marks the
// dimension complete. A truncated response was stored as an authoritative total
// and rendered healthy.
Deno.test("a missing or mistyped has_more flag is never read as a finished walk", async () => {
  const body = (input: RequestInfo | URL, flag: Json) =>
    Response.json(
      String(input).includes("cost_report") ? page([cost(false)]) : {
        data: [bucket([usage(false)])],
        next_page: "next",
        data_refreshed_at: "2026-08-02T04:00:00Z",
        ...flag,
      },
    );
  for (const flag of [{}, { has_more: "true" }, { has_more: null }]) {
    const result = await run(
      "platform",
      (input) => Promise.resolve(body(input, flag)),
    );
    assertEquals(result.usage, null);
    assertEquals((result.usageStatus as Json).state, "unavailable");
    assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
    // The cost walk answered correctly and is untouched by the other
    // dimension's malformed pagination.
    assertEquals((result.costStatus as Json).state, "complete");
  }
});
// `typeof item.model === "string" ? item.model : null` turned a grouping this
// collector explicitly asked Anthropic for — missing, or a number — into the
// same null the API sends for a genuinely unattributed row. A malformed
// breakdown was indistinguishable from an honest one and was summed into a
// "complete" total.
Deno.test("a requested grouping that is absent or mistyped invalidates the dimension", async () => {
  const cases: Json[] = [
    { model: undefined },
    { model: 7 },
    { workspace_id: undefined },
    { workspace_id: { id: "wrkspc_example" } },
  ];
  for (const override of cases) {
    const result = await run(
      "platform",
      (input) =>
        Promise.resolve(Response.json(page(
          String(input).includes("cost_report")
            ? [cost(false)]
            : [usage(false, override)],
        ))),
    );
    assertEquals(result.usage, null);
    assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  }
  // The Enterprise cost walk requests cost_type, so a row without it is not the
  // grouped report that was asked for.
  const enterprise = await run(
    "enterprise",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? [cost(true, { cost_type: undefined })]
          : [usage(true)],
      ))),
  );
  assertEquals(enterprise.costs, null);
  assertEquals((enterprise.costStatus as Json).errorKind, "invalid-response");
});
// An explicit null is a value Anthropic chose to send. It is legal on the
// identifier dimensions it genuinely leaves unattributed, and never on a
// counter or on a currency amount.
Deno.test("explicit null is accepted on identifiers and refused on counters", async () => {
  const ungrouped = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? [cost(false)]
          : [usage(false, { workspace_id: null })],
      ))),
  );
  assertEquals(
    ((ungrouped.usage as Json).breakdowns as Json[])[0].workspaceId,
    null,
  );
  assertEquals((ungrouped.usageStatus as Json).state, "complete");

  for (
    const override of [
      { output_tokens: null },
      { cache_creation: { ephemeral_5m_input_tokens: null } },
    ]
  ) {
    const result = await run(
      "platform",
      (input) =>
        Promise.resolve(Response.json(page(
          String(input).includes("cost_report")
            ? [cost(false)]
            : [usage(false, override)],
        ))),
    );
    assertEquals(result.usage, null);
    assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  }
});
// An unmodelled key is an unvalidated key. Nothing from a row this version
// cannot fully account for reaches the stored snapshot.
Deno.test("an unmodelled field anywhere in the response degrades that dimension", async () => {
  const row = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? [cost(false)]
          : [usage(false, { surprise_tokens: 5 })],
      ))),
  );
  assertEquals(row.usage, null);
  assertEquals((row.usageStatus as Json).errorKind, "invalid-response");

  const costRow = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? [cost(false, { surprise_amount: "1.00" })]
          : [usage(false)],
      ))),
  );
  assertEquals(costRow.costs, null);
  assertEquals((costRow.costStatus as Json).errorKind, "invalid-response");

  const envelope = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json({
        ...page(
          String(input).includes("cost_report")
            ? [cost(false)]
            : [usage(false)],
        ),
        surprise: true,
      })),
  );
  assertEquals(envelope.usage, null);
  assertEquals(envelope.costs, null);
});
// Anthropic's reports carry no `object` discriminator, so the required field
// set is the discriminator. A cost body served on the usage path cannot be
// summed as usage, and a Platform row cannot be counted as an Enterprise one.
Deno.test("a body from the wrong endpoint or account kind is never counted", async () => {
  const swapped = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(false)] : [cost(false)],
      ))),
  );
  assertEquals(swapped.usage, null);
  assertEquals((swapped.usageStatus as Json).errorKind, "invalid-response");

  // Platform usage rows carry no request count, which is why this package
  // reports the Platform request metric unsupported. An Enterprise-shaped row
  // arriving on the Platform path would make that claim false, so it degrades.
  const wrongKind = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report") ? [cost(false)] : [usage(true)],
      ))),
  );
  assertEquals(wrongKind.usage, null);
  assertEquals((wrongKind.usageStatus as Json).errorKind, "invalid-response");
});
// Strictness must not quietly become "reject anything unfamiliar": a row
// carrying every dimension this version models still reads complete.
Deno.test("a fully populated live-shaped row still parses complete", async () => {
  const result = await run(
    "platform",
    (input) =>
      Promise.resolve(Response.json(page(
        String(input).includes("cost_report")
          ? [cost(false, {
            cost_type: "tokens",
            context_window: "0-200k",
            token_type: "input",
            service_tier: "standard",
            product: null,
          })]
          : [usage(false, {
            api_key_id: "apikey_example",
            service_tier: "standard",
            context_window: "0-200k",
            server_tool_use: { web_search_requests: 1 },
          })],
      ))),
  );
  assertEquals((result.usageStatus as Json).state, "complete");
  assertEquals((result.costStatus as Json).state, "complete");
  assertEquals((result.usage as Json).uncachedInputTokens, 10);
});
// timeoutMs bounds one request and was rebuilt every iteration, so a paginator
// minting a fresh cursor forever defeated the repeated-cursor guard and ran
// without bound. Both walks must stop themselves at the page ceiling.
Deno.test("pagination stops at a fixed page ceiling against an endless paginator", async () => {
  let calls = 0;
  const result = await run("enterprise", () => {
    calls++;
    // Escape hatch: without the ceiling the loop is infinite, and a hanging
    // test reports nothing. Fail loudly instead, well past the real cap.
    if (calls > 1200) return Promise.resolve(new Response("", { status: 500 }));
    return Promise.resolve(Response.json({
      data: [],
      has_more: true,
      next_page: `cursor-${calls}`,
    }));
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
        fetch: () => {
          throw new Error("must not fetch");
        },
        signal: new AbortController().signal,
        writeResource: () => Promise.resolve({}),
      }),
    Error,
    "requires authentication=api-key",
  );
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

Deno.test("concurrent caller transports cannot receive another caller's credential", async () => {
  const execute = async (credential: string) => {
    let calls = 0;
    await model.methods.collect.execute({
      startingAt: "2026-08-01T00:00:00Z",
      endingAt: "2026-08-03T00:00:00Z",
    }, {
      globalArgs: { credential, accountKind: "platform" },
      signal: new AbortController().signal,
      fetch: async (input, init) => {
        await Promise.resolve();
        assertEquals(new Headers(init?.headers).get("x-api-key"), credential);
        calls++;
        return Response.json(
          page(
            String(input).includes("cost_report")
              ? [cost(false)]
              : [usage(false)],
          ),
        );
      },
      writeResource: () => Promise.resolve({}),
    });
    assertEquals(calls, 2);
  };
  await Promise.all([execute("EXAMPLE_CALLER_A"), execute("EXAMPLE_CALLER_B")]);
});

Deno.test("documented Analytics metadata validates and is omitted from stored records", async () => {
  const result = await run(
    "enterprise",
    (input) =>
      Promise.resolve(Response.json({
        ...page(
          String(input).includes("cost_report")
            ? [cost(true, {
              list_amount: "125",
              requests: 2,
              speed: "standard",
              inference_geo: "global",
              claude_tag_user_id: "EXAMPLE_USER",
              slack_channel_id: null,
              rbac_group_id: null,
              claude_tag_category: null,
            })]
            : [
              usage(true, {
                speed: "standard",
                inference_geo: "global",
                claude_tag_user_id: "EXAMPLE_USER",
                slack_channel_id: null,
                rbac_group_id: null,
                claude_tag_category: null,
              }),
            ],
        ),
        organization_id: "EXAMPLE_ORGANIZATION",
      })),
  );
  assertEquals((result.costStatus as Json).state, "complete");
  assertEquals((result.usageStatus as Json).state, "complete");
  assertEquals(JSON.stringify(result).includes("EXAMPLE_USER"), false);
  assertEquals(JSON.stringify(result).includes("EXAMPLE_ORGANIZATION"), false);
});
