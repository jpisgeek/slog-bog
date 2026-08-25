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
