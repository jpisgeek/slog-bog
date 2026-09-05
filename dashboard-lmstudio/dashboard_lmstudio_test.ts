import { assertEquals } from "jsr:@std/assert@1";
import { normalize } from "./dashboard_lmstudio.ts";

type Json = Record<string, unknown>;

Deno.test("short unlabelled diagnostic values cannot escape pattern redaction", async () => {
  const secret = "example-short-value";
  const result = await normalize(endpoint(
    "health",
    health({
      httpStatus: 500,
      errorKind: "http_error",
      error: secret,
    }),
  ));
  assertEquals(JSON.stringify(result).includes(secret), false);
  assertEquals(result.sections[0].sensitivity.redacted, true);
  assertEquals(result.sections[0].exceptions.length > 0, true);
});

Deno.test("repository failures become coverage gaps without exposing their messages", async () => {
  const ctx = endpoint("health", health());
  ctx.dataRepository.getContent = () =>
    Promise.reject(new Error("example-private-diagnostic"));
  const result = await normalize(ctx);
  assertEquals(result.sections[0].state, "partial");
  assertEquals(
    JSON.stringify(result).includes("example-private-diagnostic"),
    false,
  );
});

Deno.test("unknown collector fields and negative timing are rejected as invalid records", async () => {
  for (
    const value of [
      health({ unexpected: "example-private-value" }),
      health({ latencyMs: -1 }),
    ]
  ) {
    const result = await normalize(endpoint("health", value));
    assertEquals(result.sections[0].state, "partial");
    assertEquals(
      JSON.stringify(result).includes("example-private-value"),
      false,
    );
  }
});
const checkedAt = "2026-08-25T20:00:00.000Z";

function context(
  modelType: string,
  methodName: string,
  record: Json | null,
  overrides: Json = {},
) {
  const bytes = record === null
    ? null
    : new TextEncoder().encode(JSON.stringify(record));
  return {
    scope: "method" as const,
    modelType: { toString: () => modelType },
    modelId: "synthetic-model-id",
    definition: { name: "synthetic-inference", version: 1 },
    methodName,
    methodArgs: {},
    executionStatus: "succeeded" as const,
    dataHandles: record === null
      ? []
      : [{ name: `synthetic-${methodName}`, specName: methodName, version: 1 }],
    dataRepository: {
      getContent: () => Promise.resolve(bytes),
    },
    ...overrides,
  };
}

const endpoint = (method: string, record: Json | null, overrides: Json = {}) =>
  context("@jpisgeek/lmstudio/endpoint", method, record, overrides);
const probe = (method: string, record: Json | null, overrides: Json = {}) =>
  context("@jpisgeek/lmstudio/probe", method, record, overrides);
const daemon = (record: Json | null, overrides: Json = {}) =>
  context("@jpisgeek/lmstudio/daemon", "observe", record, overrides);

function health(overrides: Json = {}): Json {
  return {
    reachable: true,
    authorized: true,
    httpStatus: 200,
    latencyMs: 12,
    errorKind: "",
    error: "",
    checkedAt,
    ...overrides,
  };
}

function completion(overrides: Json = {}): Json {
  return {
    model: "example/chat",
    latencyMs: 125,
    httpStatus: 200,
    finishReason: "stop",
    promptTokens: 10,
    completionTokens: 5,
    totalTokens: 15,
    reasoningTokens: 0,
    reasoningChars: 0,
    contentChars: 20,
    emptyContentWithReasoning: false,
    contextExhausted: false,
    maxTokensHit: false,
    errorKind: "",
    error: "",
    checkedAt,
    ...overrides,
  };
}

Deno.test("published report contains the canonical contract verbatim", async () => {
  const entry = await Deno.readTextFile(
    new URL("./dashboard_lmstudio.ts", import.meta.url),
  );
  const canonical = await Deno.readTextFile(
    new URL("../dashboard-contract/dashboard_bundle.ts", import.meta.url),
  );
  const inlined = entry.split("// BEGIN INLINED DASHBOARD CONTRACT V1\n")[1]
    .split("// END INLINED DASHBOARD CONTRACT V1")[0].trim();
  assertEquals(inlined, canonical.trim());
});

Deno.test("healthy endpoint keeps reachability and authorization distinct", async () => {
  const bundle = await normalize(endpoint("health", health()));
  assertEquals(bundle.state, "healthy");
  assertEquals(
    bundle.sections[0].facts.find((f) => f.id === "reachable")?.value,
    true,
  );
  assertEquals(
    bundle.sections[0].facts.find((f) => f.id === "authorized")?.value,
    true,
  );
  assertEquals(bundle.sections[0].metrics[0].unit, "milliseconds");
});

Deno.test("endpoint down and token rejected are different states", async () => {
  const down = await normalize(endpoint(
    "health",
    health({
      reachable: false,
      authorized: false,
      httpStatus: 0,
      errorKind: "unreachable",
      error: "could not reach endpoint",
    }),
  ));
  assertEquals(down.state, "critical");
  assertEquals(down.sections[0].exceptions[0].headline, "Endpoint unreachable");

  const rejected = await normalize(endpoint(
    "health",
    health({
      authorized: false,
      httpStatus: 401,
      errorKind: "unauthorized",
      error: "endpoint reachable but rejected the API token",
    }),
  ));
  assertEquals(rejected.state, "critical");
  assertEquals(rejected.sections[0].state, "unauthorized");
  assertEquals(
    rejected.sections[0].facts.find((f) => f.id === "reachable")?.value,
    true,
  );
});

Deno.test("failed unauthorized probe remains unauthorized without a resource", async () => {
  const bundle = await normalize(probe("completion", null, {
    executionStatus: "failed",
    errorMessage: "UNAUTHORIZED: endpoint rejected the API token (HTTP 401)",
  }));
  assertEquals(bundle.sections[0].state, "unauthorized");
  assertEquals(bundle.sections[0].freshness.state, "unknown");
});

Deno.test("available models are inventory and an empty list is degraded", async () => {
  const loaded = await normalize(endpoint("models", {
    modelIds: ["example/chat", "example/embed"],
    modelCount: 2,
    syncedAt: checkedAt,
  }));
  assertEquals(loaded.state, "healthy");
  assertEquals(loaded.sections[0].metrics[0].value, 2);

  const empty = await normalize(endpoint("models", {
    modelIds: [],
    modelCount: 0,
    syncedAt: checkedAt,
  }));
  assertEquals(empty.state, "degraded");
});

Deno.test("remote daemon loaded inventory is exact but not accounting", async () => {
  const bundle = await normalize(daemon({
    cliAvailable: true,
    daemonRunning: true,
    status: "running",
    loadedModelCount: 1,
    loadedModels: [{
      identifier: "example/chat",
      type: "llm",
      architecture: "example",
    }],
    observedAt: checkedAt,
    errorKind: "",
    error: "",
  }));
  assertEquals(bundle.state, "healthy");
  assertEquals(bundle.sections[0].coverage.kind, "exact");
  assertEquals(bundle.sections[0].metrics[0].value, 1);
  assertEquals(bundle.extensions["jpisgeek/local-inference"], {
    accountingScope: "not-applicable",
    aggregateAccounting: false,
  });
});

Deno.test("remote daemon empty, unreachable, and missing CLI stay distinct", async () => {
  const base = {
    cliAvailable: true,
    daemonRunning: true,
    status: "running",
    loadedModelCount: 0,
    loadedModels: [],
    observedAt: checkedAt,
    errorKind: "",
    error: "",
  };
  assertEquals((await normalize(daemon(base))).state, "degraded");

  const unreachable = await normalize(daemon({
    ...base,
    daemonRunning: false,
    status: "unknown",
    errorKind: "unreachable",
    error: "The remote LM Studio daemon could not be reached",
  }));
  assertEquals(unreachable.state, "critical");
  assertEquals(unreachable.sections[0].metrics[0].availability, "unknown");

  const unsupported = await normalize(daemon({
    ...base,
    cliAvailable: false,
    daemonRunning: false,
    status: "unknown",
    errorKind: "cli-unavailable",
    error: "The lms CLI is not installed or executable",
  }));
  assertEquals(unsupported.sections[0].state, "unsupported");
});

Deno.test("embedding dimension is observed only when known", async () => {
  const known = await normalize(probe("embedding", {
    model: "example/embed",
    servesEmbeddings: true,
    measuredDimension: 768,
    dimensionKnown: true,
    latencyMs: 20,
    httpStatus: 200,
    errorKind: "",
    error: "",
    checkedAt,
  }));
  assertEquals(known.state, "healthy");
  assertEquals(known.sections[0].metrics[0].value, 768);

  const unknown = await normalize(probe("embedding", {
    model: "example/chat",
    servesEmbeddings: false,
    measuredDimension: 0,
    dimensionKnown: false,
    latencyMs: 20,
    httpStatus: 200,
    errorKind: "empty_response",
    error: "no vector",
    checkedAt,
  }));
  assertEquals(unknown.sections[0].metrics[0].availability, "unknown");
  assertEquals("value" in unknown.sections[0].metrics[0], false);
});

Deno.test("completion token metrics are explicitly single-request coverage", async () => {
  const bundle = await normalize(probe("completion", completion()));
  const section = bundle.sections[0];
  assertEquals(bundle.state, "healthy");
  assertEquals(section.coverage.kind, "observed-traffic");
  assertEquals(section.coverage.notes?.includes("not runtime-wide"), true);
  assertEquals(
    section.metrics.find((m) => m.id === "prompt-tokens")?.unit,
    "tokens",
  );
  assertEquals(bundle.extensions["jpisgeek/local-inference"], {
    accountingScope: "single-request",
    aggregateAccounting: false,
  });
});

Deno.test("context exhaustion and output-token cap remain distinct", async () => {
  const contextLimit = await normalize(probe(
    "completion",
    completion({
      finishReason: "length",
      contextExhausted: true,
    }),
  ));
  assertEquals(contextLimit.state, "degraded");
  assertEquals(
    contextLimit.sections[0].exceptions[0].headline,
    "Context window exhausted",
  );

  const outputLimit = await normalize(probe(
    "completion",
    completion({
      finishReason: "length",
      maxTokensHit: true,
    }),
  ));
  assertEquals(
    outputLimit.sections[0].exceptions[0].headline,
    "Output-token cap reached",
  );
});

Deno.test("reasoning-only empty output is visible", async () => {
  const bundle = await normalize(probe(
    "completion",
    completion({
      completionTokens: 8,
      totalTokens: 18,
      reasoningTokens: 8,
      reasoningChars: 100,
      contentChars: 0,
      emptyContentWithReasoning: true,
    }),
  ));
  assertEquals(bundle.state, "degraded");
  assertEquals(
    bundle.sections[0].exceptions[0].headline,
    "Reasoning consumed the response budget",
  );
});

Deno.test("failed request token zeros become unavailable instead of measured zero", async () => {
  const bundle = await normalize(probe(
    "completion",
    completion({
      httpStatus: 503,
      finishReason: "",
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      errorKind: "http_error",
      error: "HTTP 503",
    }),
  ));
  const prompt = bundle.sections[0].metrics.find((m) =>
    m.id === "prompt-tokens"
  )!;
  assertEquals(prompt.availability, "unknown");
  assertEquals("value" in prompt, false);
  assertEquals(
    bundle.sections[0].facts.find((f) => f.id === "context-exhausted")?.value,
    null,
  );
});

Deno.test("successful request without usage remains partial and unknown", async () => {
  const bundle = await normalize(probe(
    "completion",
    completion({
      promptTokens: null,
      completionTokens: null,
      totalTokens: null,
      reasoningTokens: null,
      contextExhausted: null,
      maxTokensHit: null,
    }),
  ));
  assertEquals(bundle.sections[0].state, "partial");
  assertEquals(
    bundle.sections[0].metrics.find((metric) => metric.id === "prompt-tokens")
      ?.availability,
    "unknown",
  );
  assertEquals(
    bundle.sections[0].exceptions.some((item) =>
      item.id.startsWith("lmstudio:completion:usage-unavailable:")
    ),
    true,
  );
});

Deno.test("partial and truncated capability checks never become healthy", async () => {
  const partial = await normalize(probe("capabilities", {
    model: "example/chat",
    emitsReasoning: true,
    honorsResponseFormat: false,
    wrapsInCodeFences: false,
    checksCompleted: 1,
    reasoningCheckTruncated: false,
    formatCheckTruncated: false,
    fenceCheckTruncated: false,
    latencyMs: 50,
    errorKind: "timeout",
    error: "timed out",
    checkedAt,
  }));
  assertEquals(partial.state, "critical");
  assertEquals(partial.sections[0].completeness.state, "partial");
  assertEquals(
    partial.sections[0].facts.find((f) => f.id === "honors-response-format")
      ?.value,
    null,
  );

  const truncated = await normalize(probe("capabilities", {
    model: "example/chat",
    emitsReasoning: false,
    honorsResponseFormat: true,
    wrapsInCodeFences: false,
    checksCompleted: 3,
    reasoningCheckTruncated: true,
    formatCheckTruncated: false,
    fenceCheckTruncated: false,
    latencyMs: 50,
    errorKind: "",
    error: "",
    checkedAt,
  }));
  assertEquals(truncated.state, "degraded");
});

Deno.test("malformed source records degrade visibly without echoing payloads", async () => {
  const bundle = await normalize(probe("completion", {
    model: "example/chat",
    promptTokens: "not-a-number",
    privatePayload: "must-not-survive",
  }));
  assertEquals(bundle.state, "partial");
  assertEquals(
    bundle.sections[0].exceptions[0].headline,
    "Probe record rejected",
  );
  assertEquals(JSON.stringify(bundle).includes("must-not-survive"), false);
});

// The caps are asserted as properties, not as literal strings, so the tests
// keep meaning if the limits are retuned. They must stay in step with the
// MAX_* constants in dashboard_lmstudio.ts.
const MAX_LISTED_ITEMS = 200;
const MAX_FACT_TEXT = 256;
const MAX_FREE_TEXT = 2048;
const MARKER = " [truncated]";

function reasonOf(bundle: Awaited<ReturnType<typeof normalize>>, id: string) {
  const metric = bundle.sections[0].metrics.find((m) => m.id === id)!;
  assertEquals(metric.availability, "unknown");
  return (metric as { reason: string }).reason;
}

Deno.test("absent reasoning tokens on a successful completion do not blame a failure", async () => {
  // A plain non-reasoning chat model returns prompt/completion/total and omits
  // reasoning_tokens. Before the fix this metric reused the request-failure
  // reason, so a healthy section claimed the request never completed.
  const bundle = await normalize(probe(
    "completion",
    completion({ reasoningTokens: null }),
  ));
  const section = bundle.sections[0];

  // The request plainly succeeded: nothing about it is partial or unavailable.
  assertEquals(section.state, "healthy");
  assertEquals(section.completeness.state, "exact");
  assertEquals(
    section.exceptions.some((item) =>
      item.id.startsWith("lmstudio:completion:usage-unavailable:")
    ),
    false,
  );
  assertEquals(
    section.metrics.find((m) => m.id === "prompt-tokens")?.availability,
    "observed",
  );

  // The reasoning metric is unknown, but for its own reason: the model did not
  // report the counter, not that the request failed.
  const reason = reasonOf(bundle, "reasoning-tokens");
  assertEquals(reason.includes("did not complete"), false);
  assertEquals(reason.includes("reasoning"), true);
});

Deno.test("a failed completion still attributes null reasoning tokens to the failure", async () => {
  // The failure reason stays reserved for failures: when the request itself
  // did not complete, every token metric must tell that same story.
  const bundle = await normalize(probe(
    "completion",
    completion({
      httpStatus: 503,
      finishReason: "",
      promptTokens: null,
      completionTokens: null,
      totalTokens: null,
      reasoningTokens: null,
      errorKind: "http_error",
      error: "HTTP 503",
    }),
  ));
  assertEquals(
    reasonOf(bundle, "reasoning-tokens"),
    reasonOf(bundle, "prompt-tokens"),
  );
  assertEquals(reasonOf(bundle, "reasoning-tokens").includes("request"), true);
});

Deno.test("a huge model inventory is truncated, still counted exactly, and marked partial", async () => {
  const modelIds = Array.from({ length: 5000 }, (_, i) => `example/chat-${i}`);
  const bundle = await normalize(endpoint("models", {
    modelIds,
    modelCount: modelIds.length,
    syncedAt: checkedAt,
  }));
  const section = bundle.sections[0];

  // Fact fan-out is bounded: without the cap this section emitted one Fact per
  // id, which the renderer turns into one table row per id.
  assertEquals(section.facts.length, MAX_LISTED_ITEMS);
  // The count itself is still exact — only the enumeration was cut.
  assertEquals(
    section.metrics.find((m) => m.id === "available-models")?.value,
    5000,
  );
  assertEquals(section.completeness.state, "partial");
  assertEquals(bundle.state, "partial");
  assertEquals(
    section.exceptions.some((item) =>
      item.id.startsWith("lmstudio:models:truncated:")
    ),
    true,
  );
  // Truncation is never silent: the reason names what was dropped.
  assertEquals(
    (section.completeness as { reason: string }).reason.includes("truncated"),
    true,
  );
});

Deno.test("an oversized model id cannot grow a fact without bound", async () => {
  const bundle = await normalize(endpoint("models", {
    modelIds: ["x".repeat(100_000)],
    modelCount: 1,
    syncedAt: checkedAt,
  }));
  const fact = bundle.sections[0].facts[0];
  assertEquals(typeof fact.value, "string");
  assertEquals((fact.value as string).length, MAX_FACT_TEXT + MARKER.length);
  assertEquals((fact.value as string).endsWith(MARKER), true);
});

Deno.test("a huge loaded-model inventory truncates the same way", async () => {
  const loadedModels = Array.from({ length: 1000 }, (_, i) => ({
    identifier: `example/chat-${i}`,
    type: "llm",
    architecture: "example",
  }));
  const bundle = await normalize(daemon({
    cliAvailable: true,
    daemonRunning: true,
    status: "running",
    loadedModelCount: loadedModels.length,
    loadedModels,
    observedAt: checkedAt,
    errorKind: "",
    error: "",
  }));
  const section = bundle.sections[0];
  // One daemon-running fact plus at most the cap of loaded-model facts.
  assertEquals(section.facts.length, MAX_LISTED_ITEMS + 1);
  assertEquals(
    section.metrics.find((m) => m.id === "loaded-models")?.value,
    1000,
  );
  assertEquals(section.completeness.state, "partial");
  assertEquals(
    section.exceptions.some((item) =>
      item.id.startsWith("lmstudio:daemon:truncated:")
    ),
    true,
  );
});

Deno.test("very large collector errors cannot reach summaries or details", async () => {
  // Sized under MAX_RECORD_BYTES on purpose: past that the record is refused
  // before it is parsed at all (see the oversized-record test), and this test
  // is about the clamp that applies to a record the report did accept.
  const huge = "E".repeat(500_000);
  const bound = MAX_FREE_TEXT + MARKER.length;

  const failedCompletion = await normalize(probe(
    "completion",
    completion({
      httpStatus: 500,
      finishReason: "",
      promptTokens: null,
      completionTokens: null,
      totalTokens: null,
      reasoningTokens: null,
      errorKind: "http_error",
      error: huge,
    }),
  ));
  assertEquals(failedCompletion.sections[0].summary.length <= bound, true);
  assertEquals(
    failedCompletion.sections[0].exceptions[0].detail.length <= bound,
    true,
  );

  const unhealthy = await normalize(endpoint(
    "health",
    health({
      reachable: false,
      authorized: false,
      httpStatus: 0,
      errorKind: "unreachable",
      error: huge,
    }),
  ));
  assertEquals(
    unhealthy.sections[0].exceptions[0].detail.length <= bound,
    true,
  );

  const brokenDaemon = await normalize(daemon({
    cliAvailable: true,
    daemonRunning: false,
    status: "unknown",
    loadedModelCount: 0,
    loadedModels: [],
    observedAt: checkedAt,
    errorKind: "command-failed",
    error: huge,
  }));
  assertEquals(brokenDaemon.sections[0].summary.length <= bound, true);
});

Deno.test("an unbounded errorKind cannot grow or forge an exception id", async () => {
  // errorKind is a free-form string in HealthSchema and reaches the exception
  // id, which the contract does not length-check. Unknown kinds are named by a
  // hash of the whole value, so length is bounded and the raw text — including
  // any `:` that would re-split the id into different fields — never appears.
  const bundle = await normalize(endpoint(
    "health",
    health({
      reachable: true,
      authorized: false,
      httpStatus: 500,
      errorKind: "k".repeat(50_000),
      error: "",
    }),
  ));
  const id = bundle.sections[0].exceptions[0].id;
  assertEquals(id.startsWith("lmstudio:health:unclassified-"), true);
  assertEquals(id.length < 200, true);
  assertEquals(id.includes("kkkk"), false);

  // Two kinds sharing a long prefix used to truncate onto one id, which put
  // two different conditions under one identity and one suppression.
  const other = await normalize(endpoint(
    "health",
    health({
      reachable: true,
      authorized: false,
      httpStatus: 500,
      errorKind: `${"k".repeat(50_000)}-different`,
      error: "",
    }),
  ));
  assertEquals(other.sections[0].exceptions[0].id === id, false);

  // A kind carrying the id's own delimiter cannot add fields to the id.
  const injected = await normalize(endpoint(
    "health",
    health({
      reachable: true,
      authorized: false,
      httpStatus: 500,
      errorKind: "unauthorized:lmstudio:health:forged",
      error: "",
    }),
  ));
  assertEquals(injected.sections[0].exceptions[0].id.split(":").length, 4);
});

Deno.test("an oversized completion model name cannot grow the summary or a fact", async () => {
  const bundle = await normalize(probe(
    "completion",
    completion({ model: "m".repeat(100_000) }),
  ));
  const section = bundle.sections[0];
  assertEquals(section.summary.length < 400, true);
  const model = section.facts.find((f) => f.id === "model")!;
  assertEquals((model.value as string).length, MAX_FACT_TEXT + MARKER.length);
});

// ---------------------------------------------------------------------------
// Review findings 1, 3, 4 and 5 (GPT-5 Codex, 2026-08-30, all severity block).
// ---------------------------------------------------------------------------

/** Bundle ids for a set of distinct sources, for the collision tests. */
async function idsFor(
  contexts: Array<Parameters<typeof normalize>[0]>,
): Promise<string[]> {
  const ids: string[] = [];
  for (const ctx of contexts) ids.push((await normalize(ctx)).id);
  return ids;
}

Deno.test("two different sources cannot produce the same bundle identity", async () => {
  // The bundle and section ids were fixed strings per method, so every LM
  // Studio endpoint in a fleet published `lmstudio-health`. Downstream keys
  // history on that id, so the second endpoint's record silently overwrote the
  // first one's and an operator watched whichever probe ran last.
  const distinct = [
    endpoint("health", health()),
    // A second model definition, pointing at a different endpoint.
    endpoint("health", health(), { definition: { name: "other", version: 1 } }),
    // The same definition, a different model instance.
    endpoint("health", health(), { modelId: "other-model-id" }),
    // A different method on the same source.
    endpoint("models", {
      modelIds: ["example/chat"],
      modelCount: 1,
      syncedAt: checkedAt,
    }),
    // The same method, a different model under probe.
    probe("completion", completion()),
    probe("completion", completion({ model: "example/other" })),
  ];
  const ids = await idsFor(distinct);
  assertEquals(new Set(ids).size, ids.length);

  // The same source twice is the same identity: history has to stay continuous
  // across runs, which is why the id cannot simply be made unique at random.
  const [first, second] = await idsFor([
    endpoint("health", health()),
    endpoint("health", health({ latencyMs: 99 })),
  ]);
  assertEquals(first, second);
});

Deno.test("identity cannot be collided by moving characters between fields", async () => {
  // Length-prefixed encoding is what stops ("ab","c") and ("a","bc") hashing
  // to one identity: without it those parts concatenate to the same bytes.
  const [a, b] = await idsFor([
    endpoint("health", health(), {
      definition: { name: "ab", version: 1 },
      modelId: "c",
    }),
    endpoint("health", health(), {
      definition: { name: "a", version: 1 },
      modelId: "bc",
    }),
  ]);
  assertEquals(a === b, false);
});

Deno.test("credentials, URLs, hosts and paths are removed from collector errors", async () => {
  const bundle = await normalize(probe(
    "completion",
    completion({
      httpStatus: 502,
      finishReason: "",
      promptTokens: null,
      completionTokens: null,
      totalTokens: null,
      reasoningTokens: null,
      errorKind: "http_error",
      error:
        "POST https://user:hunter2@inference.example.test:1234/v1/chat?api_key=sk-abcdefghijklmnop failed; authorization: Bearer sk-abcdefghijklmnop; model file /srv/example-user/.cache/lmstudio/models/chat.gguf; upstream 203.0.113.50:1234",
    }),
  ));
  const section = bundle.sections[0];
  const published = JSON.stringify(bundle);

  // Nothing that grants access or names infrastructure survives.
  for (
    const leaked of [
      "hunter2",
      "sk-abcdefghijklmnop",
      "inference.example.test",
      "/srv/example-user",
      "203.0.113.50",
    ]
  ) {
    assertEquals(published.includes(leaked), false);
  }
  // The observation itself survives: this is redaction, not deletion.
  assertEquals(section.summary.includes("redacted"), true);

  // And the bundle says so, instead of claiming it published raw text.
  assertEquals(section.sensitivity.redacted, true);
  assertEquals(section.sensitivity.fields.includes("error"), true);
  assertEquals(bundle.sensitivity.redacted, true);
});

// Written through fromCharCode rather than as literals so that this file stays
// free of the very bytes it is asserting about: a control character committed
// into a test fixture drives the terminal of whoever greps the repo, and the
// identifier scanner refuses any file carrying one.
const ESC = String.fromCharCode(0x1b);
const BIDI_OVERRIDE = String.fromCharCode(0x202e);
const BIDI_POP = String.fromCharCode(0x202c);
const ZERO_WIDTH_SPACE = String.fromCharCode(0x200b);

Deno.test("control and direction-formatting characters never reach stored text", async () => {
  const bundle = await normalize(endpoint(
    "health",
    health({
      reachable: false,
      authorized: false,
      httpStatus: 0,
      errorKind: "unreachable",
      // The ESC sequence rewrites the terminal title of whoever cats the
      // stored bundle; the bidi override makes two different messages render
      // alike; the zero-width space hides a hostname from the redaction pass.
      error: `probe${ESC}]0;PWNED failed ${BIDI_OVERRIDE}for${BIDI_POP} ` +
        `host${ZERO_WIDTH_SPACE}name.example.test`,
    }),
  ));
  const detail = bundle.sections[0].exceptions[0].detail;
  for (const char of detail) {
    const code = char.codePointAt(0)!;
    assertEquals(code >= 0x20 && code !== 0x7f, true);
  }
  for (const hidden of [BIDI_OVERRIDE, BIDI_POP, ZERO_WIDTH_SPACE]) {
    assertEquals(detail.includes(hidden), false);
  }
  // The zero-width space did not smuggle the hostname past redaction.
  assertEquals(detail.includes("name.example.test"), false);
});

Deno.test("a clean record distinguishes unchanged observations from omitted producer identifiers", async () => {
  // The flag has to mean something: a record with nothing to remove must not
  // claim a redaction pass fired on it.
  const bundle = await normalize(endpoint("health", health()));
  assertEquals(bundle.sections[0].sensitivity.redacted, false);
  assertEquals(bundle.sensitivity.redacted, true);
  assertEquals(bundle.producer.modelName, "lmstudio-observation");
  assertEquals(bundle.producer.modelId, undefined);
});

Deno.test("a successful-looking record with a failed HTTP status is rejected", async () => {
  // errorKind "" was the only success test, so a 500 whose kind the collector
  // never set was published as a healthy endpoint.
  const bundle = await normalize(endpoint(
    "health",
    health({ httpStatus: 500 }),
  ));
  assertEquals(bundle.sections[0].state, "partial");
  assertEquals(
    bundle.sections[0].exceptions[0].headline,
    "Probe record rejected",
  );

  const outOfRange = await normalize(endpoint(
    "health",
    health({ httpStatus: 99_999 }),
  ));
  assertEquals(outOfRange.sections[0].state, "partial");

  // The same contradiction on a completion: observed token metrics for a
  // request that answered 503.
  const failed = await normalize(probe(
    "completion",
    completion({ httpStatus: 503 }),
  ));
  assertEquals(failed.sections[0].state, "partial");
  assertEquals(failed.sections[0].metrics.length, 0);
});

Deno.test("an unreachable endpoint cannot also report a status or authorization", async () => {
  const bundle = await normalize(endpoint(
    "health",
    health({
      reachable: false,
      authorized: true,
      httpStatus: 200,
      errorKind: "unreachable",
      error: "could not reach endpoint",
    }),
  ));
  assertEquals(bundle.sections[0].state, "partial");
});

Deno.test("a daemon that is not running cannot report loaded models", async () => {
  const bundle = await normalize(daemon({
    cliAvailable: true,
    daemonRunning: false,
    status: "not-running",
    loadedModelCount: 2,
    loadedModels: [
      { identifier: "example/chat", type: "llm", architecture: "example" },
      { identifier: "example/embed", type: "llm", architecture: "example" },
    ],
    observedAt: checkedAt,
    errorKind: "",
    error: "",
  }));
  assertEquals(bundle.sections[0].state, "partial");

  // A stopped runtime with an empty inventory is not healthy either.
  const stopped = await normalize(daemon({
    cliAvailable: true,
    daemonRunning: false,
    status: "not-running",
    loadedModelCount: 0,
    loadedModels: [],
    observedAt: checkedAt,
    errorKind: "command-failed",
    error: "lms ps reported the runtime is not running",
  }));
  assertEquals(stopped.sections[0].state === "healthy", false);
});

Deno.test("an embedding capability cannot be claimed from a failed exchange", async () => {
  const bundle = await normalize(probe("embedding", {
    model: "example/embed",
    servesEmbeddings: true,
    measuredDimension: 768,
    dimensionKnown: true,
    latencyMs: 20,
    httpStatus: 500,
    errorKind: "",
    error: "",
    checkedAt,
  }));
  assertEquals(bundle.sections[0].state, "partial");
  assertEquals(
    bundle.sections[0].exceptions[0].headline,
    "Probe record rejected",
  );
});

Deno.test("a capability finding cannot come from a check that never ran", async () => {
  const bundle = await normalize(probe("capabilities", {
    model: "example/chat",
    emitsReasoning: true,
    honorsResponseFormat: true,
    wrapsInCodeFences: false,
    checksCompleted: 0,
    reasoningCheckTruncated: false,
    formatCheckTruncated: false,
    fenceCheckTruncated: false,
    latencyMs: 50,
    errorKind: "timeout",
    error: "timed out",
    checkedAt,
  }));
  assertEquals(bundle.sections[0].state, "partial");
});

Deno.test("an oversized resource is refused before it is decoded or parsed", async () => {
  // The expansion caps run after parsing, so they bound the output and not the
  // work: a hostile inventory cost a full decode, parse and schema walk before
  // anything was ever truncated.
  const modelIds = Array.from(
    { length: 60_000 },
    (_, i) => `example/chat-${i}-${"x".repeat(20)}`,
  );
  const record = { modelIds, modelCount: modelIds.length, syncedAt: checkedAt };
  const bytes = new TextEncoder().encode(JSON.stringify(record));
  assertEquals(bytes.byteLength > 1024 * 1024, true);

  let reads = 0;
  const bundle = await normalize({
    ...endpoint("models", record),
    dataRepository: {
      getContent: () => {
        reads++;
        return Promise.resolve(bytes);
      },
    },
  });
  const section = bundle.sections[0];

  // The resource is read once and then refused: nothing from inside it reaches
  // a fact, a metric, or any other part of the bundle.
  assertEquals(reads, 1);
  assertEquals(section.state, "partial");
  assertEquals(section.facts.length, 0);
  assertEquals(JSON.stringify(bundle).includes("example/chat-0"), false);
  assertEquals(
    section.exceptions[0].headline,
    "Probe record too large to parse",
  );
  // The refusal names the size, which is all that is known about a record
  // nothing decoded.
  assertEquals(section.exceptions[0].detail.includes("bytes"), true);
});

Deno.test("reasoning tokens alone are evidence of reasoning-only output", async () => {
  // The collector raises emptyContentWithReasoning when a model reports
  // reasoning usage without emitting any reasoning text, so the invariant that
  // demands evidence must accept the token counter as evidence. Requiring
  // reasoning characters would reject a record the collector legitimately
  // writes, and a rejected record is an observation lost.
  const bundle = await normalize(probe(
    "completion",
    completion({
      completionTokens: 8,
      totalTokens: 18,
      reasoningTokens: 8,
      reasoningChars: 0,
      contentChars: 0,
      emptyContentWithReasoning: true,
    }),
  ));
  assertEquals(bundle.state, "degraded");
  assertEquals(
    bundle.sections[0].exceptions[0].headline,
    "Reasoning consumed the response budget",
  );
});

Deno.test("one source keeps one identity whether its record is usable or not", async () => {
  // The family is part of the identity, so the failure path and the success
  // path have to agree on it. When the daemon builder hard-coded "daemon" and
  // the rejection path derived "observe" from the method name, a flapping
  // source split its history into two half-series.
  const good = await normalize(daemon({
    cliAvailable: true,
    daemonRunning: true,
    status: "running",
    loadedModelCount: 1,
    loadedModels: [{
      identifier: "example/chat",
      type: "llm",
      architecture: "example",
    }],
    observedAt: checkedAt,
    errorKind: "",
    error: "",
  }));
  const rejected = await normalize(daemon({ nothing: "usable" }));
  assertEquals(rejected.sections[0].state, "partial");
  assertEquals(good.id, rejected.id);
});

// ---------------------------------------------------------------------------
// Second-round review findings 1–4 (GPT-5, 2026-08-30, all severity block).
// ---------------------------------------------------------------------------

Deno.test("unlabelled keys, mail addresses, MACs, bare IPv6 and undotted hosts are removed", async () => {
  // Finding 1. The first redaction pass only recognised a credential when it
  // was introduced by `:` or `=`, only recognised an address when it was
  // dotted or bracketed, and did not recognise a mail address or a hardware
  // address at all. Every form below is one an LM Studio or proxy error prints
  // routinely, and each one was published verbatim.
  const bundle = await normalize(endpoint(
    "health",
    health({
      reachable: false,
      authorized: false,
      httpStatus: 0,
      errorKind: "unreachable",
      error: "API key sk-abcdefghijklmnopqrst rejected for ops@example.test; " +
        "host example-node unreachable at 2001:db8::1 (mac aa:bb:cc:dd:ee:ff); " +
        "retry via anvil:1234 with UjBhZGRlZERlcGxveW1lbnRLZXkxMjM0NQ",
    }),
  ));
  const published = JSON.stringify(bundle);
  for (
    const leaked of [
      "sk-abcdefghijklmnopqrst",
      "ops@example.test",
      "2001:db8::1",
      "aa:bb:cc:dd:ee:ff",
      "example-node",
      "UjBhZGRlZERlcGxveW1lbnRLZXkxMjM0NQ",
    ]
  ) {
    assertEquals(published.includes(leaked), false);
  }
  // Still an observation, and still declared as a redacted one.
  assertEquals(
    bundle.sections[0].exceptions[0].detail.includes("redacted"),
    true,
  );
  assertEquals(bundle.sensitivity.redacted, true);
});

Deno.test("the ledger reports screening and truncation, not only pattern hits", async () => {
  // Finding 2. `redacted` was measured against the already-screened, already-
  // clamped text, so a value whose ESC sequence was stripped or whose length
  // was cut came back false and the sensitivity block told an operator the
  // stored string was exactly what the endpoint sent.
  const screened = await normalize(endpoint(
    "health",
    health({
      reachable: false,
      authorized: false,
      httpStatus: 0,
      errorKind: "unreachable",
      // No credential, no host, no path: nothing a redaction pattern matches.
      error: `probe${ESC}]0;PWNED aborted`,
    }),
  ));
  assertEquals(screened.sections[0].sensitivity.redacted, true);
  assertEquals(screened.sections[0].sensitivity.fields.includes("error"), true);

  const truncated = await normalize(endpoint(
    "health",
    health({
      reachable: false,
      authorized: false,
      httpStatus: 0,
      errorKind: "unreachable",
      error: "e".repeat(5_000),
    }),
  ));
  assertEquals(truncated.sections[0].sensitivity.redacted, true);
});

Deno.test("configured model definition names and ids are screened before publication", async () => {
  // Finding 3. The producer block republished ctx.definition.name and
  // ctx.modelId untouched while the section beside it screened every
  // equivalent string. A definition named after the host it points at, or one
  // carrying a key pasted into the wrong field, went straight into the bundle.
  const bundle = await normalize(endpoint("health", health(), {
    definition: {
      name: "inference.anvil.example.test key sk-abcdefghijklmnop",
      version: 1,
    },
    modelId: "/srv/example-user/lmstudio/models/id",
  }));
  const published = JSON.stringify(bundle);
  for (
    const leaked of [
      "inference.anvil.example.test",
      "sk-abcdefghijklmnop",
      "/srv/example-user",
    ]
  ) {
    assertEquals(published.includes(leaked), false);
  }
  assertEquals(bundle.sensitivity.redacted, true);
  assertEquals(bundle.sensitivity.fields.includes("producer.modelName"), true);
  assertEquals(bundle.sensitivity.fields.includes("producer.modelId"), true);
});

Deno.test("resource identity is a truncated SHA-256 of the length-prefixed tuple", async () => {
  // Finding 4. Identity was a 64-bit FNV-1a, a hash-table function: an
  // attacker controlling a definition name or a probed model name can search
  // ~2^32 candidates for a second tuple landing on the same id and overwrite
  // another source's history. This recomputes the id independently, through
  // the runtime's own SHA-256, over the exact tuple the report hashes.
  const parts = [
    "@jpisgeek/lmstudio/endpoint",
    "synthetic-inference",
    "synthetic-model-id",
    "health",
    "health",
    "",
  ];
  const raw = parts.map((part) => `${part.length}:${part}`).join("");
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw)),
  );
  const hex = [...digest.slice(0, 16)]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
  const bundle = await normalize(endpoint("health", health()));
  assertEquals(bundle.id, `lmstudio-health-${hex}`);
  // 128 bits of it, which is the width the permanence of the id needs.
  assertEquals(hex.length, 32);
});
