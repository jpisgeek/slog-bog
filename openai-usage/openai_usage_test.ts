import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { model } from "./openai_usage.ts";

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
// The `object` discriminator is what the API actually sends on every result
// row and what the endpoint schemas now require, so the fixtures carry it.
const usage = (overrides: Json = {}) => ({
  object: "organization.usage.completions.result",
  input_tokens: 10,
  output_tokens: 5,
  input_cached_tokens: 2,
  num_model_requests: 1,
  project_id: "proj_example",
  model: "gpt-example",
  ...overrides,
});
const cost = (overrides: Json = {}) => ({
  object: "organization.costs.result",
  amount: { value: 1.25, currency: "usd" },
  project_id: "proj_example",
  line_item: "example",
  ...overrides,
});

async function run(fetchImpl: typeof fetch) {
  const written: Json[] = [];
  // Transport is injected per call, not installed on the module. The exported
  // setter this replaced shipped in the published package, so any importer
  // could capture a live Authorization header. See ModelContext.fetch.
  await model.methods.collect.execute({ startTime: 1, endTime: 3 }, {
    globalArgs: {
      apiKey: "secret-admin-key",
      timeoutMs: 100,
    },
    fetch: fetchImpl,
    signal: new AbortController().signal,
    writeResource: (_spec: string, _name: string, data: Json) => {
      written.push(data);
      return Promise.resolve({});
    },
  });
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
  const hangingFetch: typeof fetch = (_input, init) =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener(
        "abort",
        () => reject(init.signal?.reason),
      );
    });
  let written = false;
  const pending = model.methods.collect.execute({ startTime: 1, endTime: 3 }, {
    globalArgs: {
      apiKey: "secret-admin-key",
      timeoutMs: 1000,
    },
    fetch: hangingFetch,
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
  try {
    await model.methods.collect.execute({
      startTime: 1e15,
      endTime: 1e15 + 1,
    }, {
      globalArgs: { apiKey: "secret-admin-key", timeoutMs: 100 },
      fetch: () => Promise.resolve(Response.json(page([]))),
      signal: new AbortController().signal,
      writeResource: () => Promise.resolve({}),
    });
    throw new Error("expected rejection");
  } catch (error) {
    assertStringIncludes(
      (error as Error).message,
      "startTime and endTime must be representable Unix seconds",
    );
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

// Review finding 2 (2026-08-30): pagination was read as `has_more === true`,
// so a page that never stated its own completeness — key missing, or the
// string "true" — ended the loop AND reported the dimension complete. The
// operator saw an authoritative total built from page one alone.
Deno.test("a page with no has_more flag is invalid, never silently complete", async () => {
  const withoutFlag = page([usage()], true, "next");
  delete (withoutFlag as Json).has_more;
  const result = await run((input) =>
    Promise.resolve(Response.json(
      String(input).includes("/costs?") ? page([cost()]) : withoutFlag,
    ))
  );
  assertEquals((result.usageStatus as Json).state, "unavailable");
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
  assertEquals((result.costStatus as Json).state, "complete");
});

Deno.test("a non-boolean has_more is a protocol violation, not a false", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(
      String(input).includes("/costs?")
        ? page([cost()])
        : { ...page([usage()]), has_more: "true" },
    ))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
});

// has_more: true with no cursor is the same lie from the other side: the page
// claims more data exists and gives no way to reach it.
Deno.test("has_more without a next_page cursor stays partial, not complete", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(
      String(input).includes("/costs?")
        ? page([cost()])
        : page([usage()], true, null),
    ))
  );
  assertEquals((result.usageStatus as Json).state, "partial");
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
});

/**
 * A fetch stub that HONOURS `init.redirect`, the way a real user agent does.
 *
 * The stubs above ignore init entirely, so a redirect test built on one would
 * pass whether or not the source sets a redirect policy at all. This one
 * re-issues the request against the redirect target under "follow" — and the
 * target answers with a perfectly healthy page on purpose, so a regression
 * shows up as a suspiciously complete result rather than hiding behind some
 * unrelated failure.
 */
function redirectingFetch(
  seen: { url: string; auth: string | null }[],
): typeof fetch {
  const impl = (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = String(input instanceof Request ? input.url : input);
    seen.push({
      url,
      auth: new Headers(init?.headers).get("authorization"),
    });
    if (url.startsWith("https://api.openai.com")) {
      const location = url.replace(
        "https://api.openai.com",
        "https://usage-mirror.example.net",
      );
      const mode = init?.redirect ?? "follow";
      if (mode === "error") {
        return Promise.reject(new TypeError("redirect not allowed"));
      }
      if (mode === "manual") {
        return Promise.resolve(
          new Response(null, { status: 302, headers: { location } }),
        );
      }
      return impl(location, init);
    }
    return Promise.resolve(Response.json(page([usage()])));
  };
  return impl as typeof fetch;
}

// Review finding 4 (2026-08-30): fetch defaulted to redirect: "follow", so a
// 302 would have re-sent the Admin API key to whatever host OpenAI's answer
// named — the credential walks off the official origin without the operator
// ever seeing a request to that host.
Deno.test("a redirect off the official origin is refused and the key never leaves it", async () => {
  const seen: { url: string; auth: string | null }[] = [];
  const result = await run(redirectingFetch(seen));
  assertEquals(
    seen.some((call) => !call.url.startsWith("https://api.openai.com")),
    false,
    `a request left the official origin: ${
      seen.map((call) => call.url).join(", ")
    }`,
  );
  assertEquals(
    seen.some((call) =>
      call.auth !== null && !call.url.startsWith("https://api.openai.com")
    ),
    false,
    "the Authorization header was carried off the official origin",
  );
  assertEquals((result.usageStatus as Json).state, "unavailable");
  assertEquals((result.usageStatus as Json).errorKind, "http-error");
  assertStringIncludes(
    (result.usageStatus as Json).message as string,
    "redirect",
  );
  assertEquals(result.usage, null);
  assertEquals(result.costs, null);
});

// The refusal message is ours. The Location header is remote-supplied text and
// must not reach a stored field an operator reads as fact.
Deno.test("the refusal names the redirect but never the redirect target", async () => {
  const result = await run(redirectingFetch([]));
  assertEquals(
    JSON.stringify(result).includes("usage-mirror.example.net"),
    false,
  );
});

// Review finding 3 (2026-08-30): an explicit null counter was folded into 0,
// so a value OpenAI answered wrongly for a field its contract declares a plain
// integer was published as a token count this extension made up.
Deno.test("a null cached-token counter is a violation, not an absent zero", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost()]
        : [usage({ input_cached_tokens: null })],
    )))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
});

// Same finding, identifier side: a wrongly typed project_id used to flatten to
// null, which is exactly how a legitimately ungrouped row reads — so the row's
// tokens were pooled into the unattributed bucket with nothing to show for it.
Deno.test("a non-string project identifier invalidates usage instead of reading as ungrouped", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost()]
        : [usage({ project_id: 42 })],
    )))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
  assertEquals((result.costStatus as Json).state, "complete");
});

Deno.test("a non-string cost line item invalidates costs instead of reading as ungrouped", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost({ line_item: { name: "example" } })]
        : [usage()],
    )))
  );
  assertEquals((result.costStatus as Json).errorKind, "invalid-response");
  assertEquals(result.costs, null);
  assertEquals((result.usageStatus as Json).state, "complete");
});

// The tightening above must not swallow the null OpenAI legitimately sends for
// a dimension a row was not grouped by. SnapshotSchema declares identifiers
// nullable precisely because that null is real data.
Deno.test("null identifiers stay legal and keep the dimension complete", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost({ project_id: null, line_item: null })]
        : [usage({ project_id: null, model: null })],
    )))
  );
  assertEquals((result.usageStatus as Json).state, "complete");
  assertEquals(
    ((result.usage as Json).breakdowns as Json[])[0].projectId,
    null,
  );
  assertEquals((result.costStatus as Json).state, "complete");
  assertEquals(
    ((result.costs as Json).breakdowns as Json[])[0].lineItem,
    null,
  );
});

// A null amount is not the absent amount CostsResult permits. Dropping it
// would lower the reported spend under a status that still reads "partial by
// design" rather than "OpenAI answered wrongly".
Deno.test("a null cost amount invalidates costs rather than quietly lowering the total", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?") ? [cost({ amount: null })] : [usage()],
    )))
  );
  assertEquals((result.costStatus as Json).errorKind, "invalid-response");
  assertEquals(result.costs, null);
});

// Review finding 1 (2026-08-30, hash 13a3c726): result rows were
// `z.record(z.string(), z.unknown())` inside a passthrough bucket, so any
// field OpenAI sent survived unvalidated into the aggregation step. An
// unmodelled key is an unvalidated key: the row must not parse, and nothing
// from it may reach stored data.
Deno.test("an unknown field in a usage row is rejected, not passed through", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost()]
        : [usage({ unexpected_field: "attacker supplied text" })],
    )))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
  assertEquals(
    JSON.stringify(result).includes("attacker supplied text"),
    false,
    "an unvalidated field reached the stored snapshot",
  );
  assertEquals((result.costStatus as Json).state, "complete");
});

Deno.test("an unknown field in a cost row is rejected, not passed through", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost({ unexpected_field: "attacker supplied text" })]
        : [usage()],
    )))
  );
  assertEquals((result.costStatus as Json).errorKind, "invalid-response");
  assertEquals(result.costs, null);
  assertEquals(
    JSON.stringify(result).includes("attacker supplied text"),
    false,
    "an unvalidated field reached the stored snapshot",
  );
});

// The same rule one level up: a bucket or a page envelope carrying a field
// this version does not model is a response we have not fully understood.
Deno.test("an unknown field on a bucket is rejected", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(
      String(input).includes("/costs?") ? page([cost()]) : {
        ...page([usage()]),
        data: [{ ...bucket([usage()]), unexpected_field: "surprise" }],
      },
    ))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
});

// The discriminator is the field that says which shape a row claims to be.
// Unchecked, nothing downstream could tell a completions result from anything
// else that happened to carry an input_tokens key.
Deno.test("a result row with no object discriminator is rejected", async () => {
  const withoutDiscriminator = usage();
  delete (withoutDiscriminator as Json).object;
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?") ? [cost()] : [withoutDiscriminator],
    )))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
});

// Each endpoint is read against its own schema, so one endpoint answering with
// the other's body cannot be aggregated as if it were the dimension asked for.
Deno.test("a cost row served from the usage endpoint is rejected", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?") ? [cost()] : [cost()],
    )))
  );
  assertEquals((result.usageStatus as Json).errorKind, "invalid-response");
  assertEquals(result.usage, null);
  assertEquals((result.costStatus as Json).state, "complete");
});

// The strictness above must not reject a legitimate live response. Every
// optional field OpenAI documents on these result objects has to parse, and
// the totals must still come only from the fields this extension aggregates.
Deno.test("documented optional result fields are accepted, not treated as unknown", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?")
        ? [cost({ organization_id: "org-example" })]
        : [usage({
          input_audio_tokens: 3,
          output_audio_tokens: 4,
          user_id: null,
          api_key_id: null,
          batch: false,
          service_tier: "default",
        })],
    )))
  );
  assertEquals((result.usageStatus as Json).state, "complete");
  assertEquals((result.costStatus as Json).state, "complete");
  assertEquals((result.usage as Json).inputTokens, 10);
  assertEquals((result.usage as Json).cachedInputTokens, 2);
  assertEquals(((result.costs as Json).totals as Json[])[0].value, 1.25);
});

// Review finding 1 (2026-08-30): the row schema accepted `input_audio_tokens`
// and `output_audio_tokens` and then dropped them. OpenAI counts audio
// separately from text, so an audio-heavy organization got a snapshot that
// called itself complete while its token totals were missing every audio token
// it was billed for — an understated total wearing an exact-coverage label.
Deno.test("audio tokens are persisted and aggregated, not silently dropped", async () => {
  const result = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?") ? [cost()] : [
        usage({ input_audio_tokens: 300, output_audio_tokens: 400 }),
        usage({ input_audio_tokens: 30, output_audio_tokens: 40 }),
      ],
    )))
  );
  const usageSnapshot = result.usage as Json;
  assertEquals((result.usageStatus as Json).state, "complete");
  assertEquals(usageSnapshot.inputAudioTokens, 330);
  assertEquals(usageSnapshot.outputAudioTokens, 440);
  const breakdowns = usageSnapshot.breakdowns as Json[];
  assertEquals(breakdowns[0].inputAudioTokens, 300);
  assertEquals(breakdowns[1].outputAudioTokens, 40);
  // A row that carries no audio at all still reports zero rather than absent.
  const textOnly = await run((input) =>
    Promise.resolve(Response.json(page(
      String(input).includes("/costs?") ? [cost()] : [usage()],
    )))
  );
  assertEquals((textOnly.usage as Json).inputAudioTokens, 0);
  assertEquals((textOnly.usage as Json).outputAudioTokens, 0);
});

Deno.test("endless unique pagination stops with visible partial coverage", async () => {
  let calls = 0;
  const result = await run(() => {
    calls++;
    if (calls > 1001) throw new Error("pagination guard did not terminate");
    return Promise.resolve(
      Response.json({
        object: "page",
        data: [],
        has_more: true,
        next_page: `EXAMPLE_PAGE_${calls}`,
      }),
    );
  });
  assertEquals(calls, 1000);
  assertEquals((result.usageStatus as Json).state, "partial");
  assertEquals((result.costStatus as Json).state, "partial");
  assertEquals((result.usageStatus as Json).pagesRead, 500);
});
