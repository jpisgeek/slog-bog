import { assertEquals } from "jsr:@std/assert@1";
import { normalize } from "./dashboard_lmstudio.ts";

type Json = Record<string, unknown>;
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
      item.id === "lmstudio:completion:usage-unavailable"
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
      item.id === "lmstudio:completion:usage-unavailable"
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
    section.exceptions.some((item) => item.id === "lmstudio:models:truncated"),
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
    section.exceptions.some((item) => item.id === "lmstudio:daemon:truncated"),
    true,
  );
});

Deno.test("multi-megabyte collector errors cannot reach summaries or details", async () => {
  const huge = "E".repeat(2_000_000);
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
  assertEquals(failedCompletion.sections[0].summary.length, bound);
  assertEquals(failedCompletion.sections[0].exceptions[0].detail.length, bound);

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
  assertEquals(unhealthy.sections[0].exceptions[0].detail.length, bound);

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
  assertEquals(brokenDaemon.sections[0].summary.length, bound);
});

Deno.test("an unbounded errorKind cannot grow an exception id", async () => {
  // errorKind is a free-form string in HealthSchema; it is spliced into the
  // exception id, which the contract does not length-check.
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
  assertEquals(id.startsWith("lmstudio:health:"), true);
  assertEquals(id.length < 200, true);
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
