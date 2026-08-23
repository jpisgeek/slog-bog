/**
 * Tests for @jpisgeek/lmstudio (both the endpoint and probe models).
 *
 * Exported surface only — not in the manifest, so it does not move the
 * content hash the security review is bound to.
 *
 * The security case here is `baseUrl`: it is logged and can reach stored error
 * text, so embedded userinfo would leak a credential that `redact()` (which
 * only knows the bearer token) would never catch. The behavioural case is the
 * extension's whole reason for existing — an absent measurement must never be
 * indistinguishable from a measured zero.
 */
import { assertEquals } from "jsr:@std/assert@1";
import { model as endpoint } from "./lmstudio_endpoint.ts";
import { model as probe } from "./lmstudio_probe.ts";

const OK = {
  baseUrl: "https://inference.example.com/v1",
  apiToken: "sk-example-not-real",
};

// ---------------------------------------------------------------------------
// baseUrl on BOTH models (they are configured independently)
// ---------------------------------------------------------------------------

for (const [label, m] of [["endpoint", endpoint], ["probe", probe]] as const) {
  Deno.test(`${label}: baseUrl accepts http(s)`, () => {
    for (
      const baseUrl of [
        "https://inference.example.com/v1",
        "http://inference.example.com:1234/v1",
      ]
    ) {
      assertEquals(
        m.globalArguments.safeParse({ ...OK, baseUrl }).success,
        true,
        `expected ok: ${baseUrl}`,
      );
    }
  });

  Deno.test(`${label}: baseUrl rejects embedded credentials`, () => {
    for (
      const baseUrl of [
        "https://user:pass@inference.example.com/v1",
        "https://user@inference.example.com/v1",
      ]
    ) {
      assertEquals(
        m.globalArguments.safeParse({ ...OK, baseUrl }).success,
        false,
        `CREDENTIAL LEAK — accepted: ${baseUrl}`,
      );
    }
  });

  Deno.test(`${label}: baseUrl rejects non-http schemes`, () => {
    for (const baseUrl of ["file:///etc/passwd", "ftp://x.example.com"]) {
      assertEquals(
        m.globalArguments.safeParse({ ...OK, baseUrl }).success,
        false,
        `accepted: ${baseUrl}`,
      );
    }
  });

  Deno.test(`${label}: apiToken is required`, () => {
    assertEquals(
      m.globalArguments.safeParse({ baseUrl: OK.baseUrl }).success,
      false,
    );
  });
}

// ---------------------------------------------------------------------------
// "unknown" must never read as a measured value
// ---------------------------------------------------------------------------

Deno.test("embeddingProbe: dimensionKnown separates unknown from a real zero", () => {
  const base = {
    model: "example/embed",
    servesEmbeddings: false,
    measuredDimension: 0,
    dimensionKnown: false,
    latencyMs: 12,
    httpStatus: 200,
    errorKind: "empty_response",
    error: "no vector",
    checkedAt: new Date(0).toISOString(),
  };
  assertEquals(
    probe.resources.embeddingProbe.schema.safeParse(base).success,
    true,
  );
  const { dimensionKnown: _drop, ...without } = base;
  assertEquals(
    probe.resources.embeddingProbe.schema.safeParse(without).success,
    false,
    "dimensionKnown must be mandatory — 0 alone is ambiguous",
  );
});

Deno.test("capabilityProbe: checksCompleted is bounded 0..3", () => {
  const base = {
    model: "example/chat",
    emitsReasoning: false,
    honorsResponseFormat: false,
    wrapsInCodeFences: false,
    checksCompleted: 3,
    reasoningCheckTruncated: false,
    formatCheckTruncated: false,
    fenceCheckTruncated: false,
    latencyMs: 10,
    errorKind: "",
    error: "",
    checkedAt: new Date(0).toISOString(),
  };
  assertEquals(
    probe.resources.capabilityProbe.schema.safeParse(base).success,
    true,
  );
  for (const bad of [-1, 4, 1.5]) {
    assertEquals(
      probe.resources.capabilityProbe.schema.safeParse({
        ...base,
        checksCompleted: bad,
      }).success,
      false,
      `checksCompleted ${bad} must be rejected`,
    );
  }
});

Deno.test("completionProbe: reasoning-budget and context flags are mandatory", () => {
  const base = {
    model: "example/chat",
    latencyMs: 1,
    httpStatus: 200,
    finishReason: "length",
    promptTokens: 1,
    completionTokens: 2,
    totalTokens: 3,
    reasoningTokens: 2,
    reasoningChars: 40,
    contentChars: 0,
    emptyContentWithReasoning: true,
    contextExhausted: false,
    maxTokensHit: true,
    errorKind: "",
    error: "",
    checkedAt: new Date(0).toISOString(),
  };
  assertEquals(
    probe.resources.completionProbe.schema.safeParse(base).success,
    true,
  );
  const { emptyContentWithReasoning: _drop, ...without } = base;
  assertEquals(
    probe.resources.completionProbe.schema.safeParse(without).success,
    false,
  );
});

Deno.test("health: reachable and authorized are independent booleans", () => {
  // "up but rejecting the token" must be representable distinctly from "down".
  const upButUnauthorized = {
    reachable: true,
    authorized: false,
    httpStatus: 401,
    latencyMs: 8,
    errorKind: "unauthorized",
    error: "rejected",
    checkedAt: new Date(0).toISOString(),
  };
  const down = {
    reachable: false,
    authorized: false,
    httpStatus: 0,
    latencyMs: 0,
    errorKind: "unreachable",
    error: "refused",
    checkedAt: new Date(0).toISOString(),
  };
  for (const r of [upButUnauthorized, down]) {
    assertEquals(endpoint.resources.health.schema.safeParse(r).success, true);
  }
});

Deno.test("the package exposes exactly the documented method set", () => {
  assertEquals(Object.keys(endpoint.methods).sort(), ["health", "models"]);
  assertEquals(Object.keys(probe.methods).sort(), [
    "capabilities",
    "completion",
    "embedding",
  ]);
});

Deno.test("the two model types are distinct", () => {
  assertEquals(endpoint.type, "@jpisgeek/lmstudio/endpoint");
  assertEquals(probe.type, "@jpisgeek/lmstudio/probe");
});
