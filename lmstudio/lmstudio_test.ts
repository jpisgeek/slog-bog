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
import {
  MAX_OUTPUT_BYTES,
  model as daemon,
  runCommandForTest,
  setCommandRunnerForTest,
} from "./lmstudio_daemon.ts";

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

  Deno.test(`${label}: baseUrl rejects query strings and fragments`, () => {
    for (
      const baseUrl of [
        "https://inference.example.com/v1?token=private",
        "https://inference.example.com/v1#private",
        "https://inference.example.com/v1?",
        "https://inference.example.com/v1#",
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

Deno.test("completionProbe: absent usage remains unknown rather than zero", () => {
  const parsed = probe.resources.completionProbe.schema.safeParse({
    model: "example/chat",
    latencyMs: 1,
    httpStatus: 200,
    finishReason: "stop",
    promptTokens: null,
    completionTokens: null,
    totalTokens: null,
    reasoningTokens: null,
    reasoningChars: 0,
    contentChars: 2,
    emptyContentWithReasoning: false,
    contextExhausted: null,
    maxTokensHit: null,
    errorKind: "",
    error: "",
    checkedAt: new Date(0).toISOString(),
  });
  assertEquals(parsed.success, true);
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

Deno.test("published models migrate existing arguments without mutation", () => {
  for (const model of [endpoint, probe]) {
    assertEquals(model.version, "2026.08.25.1");
    assertEquals(model.upgrades.at(-1)?.toVersion, model.version);
    const old = { ...OK, timeoutSec: 30 };
    assertEquals(model.upgrades.at(-1)?.upgradeAttributes(old), old);
  }
  assertEquals(daemon.version, "2026.08.25.1");
  assertEquals("upgrades" in daemon, false);
});

Deno.test("completion rejects a malformed 2xx envelope", async () => {
  const originalFetch = globalThis.fetch;
  let written: Record<string, unknown> | undefined;
  globalThis.fetch = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          choices: [{ finish_reason: "stop" }],
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
  try {
    await probe.methods.completion.execute({
      model: "example/chat",
      prompt: "hello",
      maxTokens: 8,
      temperature: 0,
    }, {
      globalArgs: OK,
      signal: new AbortController().signal,
      logger: { info: () => {}, warning: () => {} },
      writeResource: (
        _spec: string,
        _name: string,
        value: Record<string, unknown>,
      ) => {
        written = value;
        return Promise.resolve({ name: "completion" });
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assertEquals(written?.errorKind, "malformed_response");
  assertEquals(written?.promptTokens, null);
  assertEquals(written?.completionTokens, null);
  assertEquals(written?.totalTokens, null);
});

Deno.test("completion rejects an empty finish reason", async () => {
  const originalFetch = globalThis.fetch;
  let written: Record<string, unknown> | undefined;
  globalThis.fetch = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          choices: [{ finish_reason: "", message: { content: "ok" } }],
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
  try {
    await probe.methods.completion.execute({
      model: "example/chat",
      prompt: "hello",
      maxTokens: 8,
      temperature: 0,
    }, {
      globalArgs: OK,
      signal: new AbortController().signal,
      logger: { info: () => {}, warning: () => {} },
      writeResource: (
        _spec: string,
        _name: string,
        value: Record<string, unknown>,
      ) => {
        written = value;
        return Promise.resolve({ name: "completion" });
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assertEquals(written?.errorKind, "malformed_response");
  assertEquals(written?.promptTokens, null);
});

async function runDaemon(
  runner: Parameters<typeof setCommandRunnerForTest>[0],
  signal: AbortSignal = new AbortController().signal,
) {
  setCommandRunnerForTest(runner);
  let written: unknown;
  try {
    await daemon.methods.observe.execute({}, {
      globalArgs: {
        lmsBinary: "lms",
        host: "inference.example.com",
        timeoutMs: 100,
      },
      signal,
      writeResource: (_spec: string, _name: string, value: unknown) => {
        written = value;
        return Promise.resolve({ name: "daemon" });
      },
    });
    return written as Record<string, unknown>;
  } finally {
    setCommandRunnerForTest();
  }
}

Deno.test("daemon: remote lms ps records loaded models", async () => {
  let argv: string[] = [];
  const value = await runDaemon((_binary, args) => {
    argv = args;
    return Promise.resolve({
      success: true,
      code: 0,
      stdout: JSON.stringify([{
        identifier: "example/chat",
        type: "llm",
        architecture: "example",
        path: "/private/path-is-not-retained",
      }]),
      stderr: "",
    });
  });
  assertEquals(argv, [
    "ps",
    "--host",
    "inference.example.com",
    "--json",
  ]);
  assertEquals(value.loadedModelCount, 1);
  assertEquals(value.daemonRunning, true);
  assertEquals(JSON.stringify(value).includes("private/path"), false);
});

Deno.test("daemon: local headless deployment does not invent a host", async () => {
  setCommandRunnerForTest((_binary, args) => {
    assertEquals(args, ["ps", "--json"]);
    return Promise.resolve({
      success: true,
      code: 0,
      stdout: "[]",
      stderr: "",
    });
  });
  try {
    await daemon.methods.observe.execute({}, {
      globalArgs: { lmsBinary: "lms", timeoutMs: 100 },
      signal: new AbortController().signal,
      writeResource: () => Promise.resolve({ name: "daemon" }),
    });
  } finally {
    setCommandRunnerForTest();
  }
});

Deno.test("daemon: successful empty list is measured zero", async () => {
  const value = await runDaemon(() =>
    Promise.resolve({ success: true, code: 0, stdout: "[]", stderr: "" })
  );
  assertEquals(value.loadedModelCount, 0);
  assertEquals(value.errorKind, "");
});

Deno.test("daemon: unreachable and malformed output remain explicit", async () => {
  const unreachable = await runDaemon(() =>
    Promise.resolve({
      success: false,
      code: 1,
      stdout: "",
      stderr: "connection refused at private-host",
    })
  );
  assertEquals(unreachable.errorKind, "unreachable");
  assertEquals(JSON.stringify(unreachable).includes("private-host"), false);

  const malformed = await runDaemon(() =>
    Promise.resolve({ success: true, code: 0, stdout: "{}", stderr: "" })
  );
  assertEquals(malformed.errorKind, "invalid-response");
});

Deno.test("daemon: caller cancellation throws and writes nothing", async () => {
  const controller = new AbortController();
  controller.abort(new DOMException("cancelled", "AbortError"));
  let threw = false;
  try {
    await runDaemon(
      () => Promise.reject(controller.signal.reason),
      controller.signal,
    );
  } catch {
    threw = true;
  }
  assertEquals(threw, true);
});

Deno.test("daemon: missing CLI and timeout are not false zeroes", async () => {
  const missing = await runDaemon(() =>
    Promise.reject(new Deno.errors.NotFound("missing executable"))
  );
  assertEquals(missing.cliAvailable, false);
  assertEquals(missing.errorKind, "cli-unavailable");

  const timedOut = await runDaemon((_binary, _args, signal) =>
    new Promise((_resolve, reject) => {
      signal.addEventListener(
        "abort",
        () => reject(new DOMException("timed out", "AbortError")),
        { once: true },
      );
    })
  );
  assertEquals(timedOut.errorKind, "timeout");
  assertEquals(timedOut.loadedModelCount, 0);
  assertEquals(timedOut.daemonRunning, false);
});

Deno.test("daemon model supports local headless and safe remote hosts", () => {
  assertEquals(daemon.globalArguments.safeParse({}).success, true);
  assertEquals(
    daemon.globalArguments.safeParse({ host: "inference.example.com" }).success,
    true,
  );
  assertEquals(
    daemon.globalArguments.safeParse({ host: "--help" }).success,
    false,
  );
  assertEquals(daemon.type, "@jpisgeek/lmstudio/daemon");
});

// ---------------------------------------------------------------------------
// The real subprocess runner. Every test above substitutes commandRunner, so
// the one function that actually spawns a process had no coverage at all --
// which is how it kept an unbounded `await child.output()` behind a SIGTERM
// that a child is free to ignore.
// ---------------------------------------------------------------------------

Deno.test("daemon runner: a SIGTERM-ignoring child is escalated to SIGKILL", async () => {
  const controller = new AbortController();
  // Ignores SIGTERM and spins in-process: no grandchild, so nothing but the
  // shell itself holds the pipes. The iteration count is a backstop -- if the
  // escalation regresses this fails in seconds instead of hanging the suite
  // forever, which is exactly what the old runner did to a live workflow.
  const running = runCommandForTest("/bin/sh", [
    "-c",
    "trap '' TERM; n=0; while [ $n -lt 40000000 ]; do n=$((n+1)); done",
  ], controller.signal);
  await new Promise((resolve) => setTimeout(resolve, 150));
  controller.abort();

  let guard: ReturnType<typeof setTimeout> | undefined;
  const outcome = await Promise.race([
    running.then(() => "exited" as const),
    new Promise<"still running">((resolve) => {
      guard = setTimeout(() => resolve("still running"), 8000);
    }),
  ]);
  clearTimeout(guard);
  assertEquals(
    outcome,
    "exited",
    "aborting must actually stop the child -- SIGTERM alone never does when " +
      "the child ignores it",
  );
  const result = await running;
  assertEquals(result.success, false);
});

Deno.test("daemon runner: output past the cap is truncated, never reported as success", async () => {
  const controller = new AbortController();
  // ~8 MB of stdout, well past the cap. The old runner buffered all of it
  // before anything got the chance to look at the size.
  const result = await runCommandForTest("/bin/sh", [
    "-c",
    "yes 0123456789012345678901234567890123456789 | head -n 200000",
  ], controller.signal);
  assertEquals(
    result.stdout.length <= MAX_OUTPUT_BYTES,
    true,
    `stdout was ${result.stdout.length} bytes, cap is ${MAX_OUTPUT_BYTES}`,
  );
  assertEquals(
    result.success,
    false,
    "a truncated answer must fail, not be returned as though it were whole",
  );
});

// ---------------------------------------------------------------------------
// `lms ps` output is remote-controlled text in --host mode. The daemon
// resource calls itself "sanitized", so hostile or unbounded model metadata
// must fail closed rather than being stored for 30 days.
// ---------------------------------------------------------------------------

const HOSTILE_IDENTIFIERS: [string, string, string][] = [
  ["terminal escape", "qwen\u001b]0;PWNED\u0007-7b", "PWNED"],
  ["bidi override", "qwen\u202egnp.exe-7b", "gnp.exe"],
  ["zero width", "qwen\u200b-7b", "\u200b"],
  ["unpaired surrogate", "qwen\ud800-7b", "\ud800"],
  ["over long name", `qwen-${"a".repeat(400)}`, "a".repeat(400)],
];

for (const [label, identifier, marker] of HOSTILE_IDENTIFIERS) {
  Deno.test(`daemon: a model identifier with a ${label} fails closed`, async () => {
    const value = await runDaemon(() =>
      Promise.resolve({
        success: true,
        code: 0,
        stdout: JSON.stringify([{
          identifier,
          type: "llm",
          architecture: "example",
        }]),
        stderr: "",
      })
    );
    assertEquals(value.errorKind, "invalid-response");
    assertEquals(value.loadedModelCount, 0);
    assertEquals(
      JSON.stringify(value).includes(marker),
      false,
      `unscreened identifier reached stored data: ${label}`,
    );

    // Asserted against the resource schema as well, not just the parse path:
    // a bound that lives only in parseModels() is one refactor away from
    // being silently gone.
    assertEquals(
      daemon.resources.daemon.schema.safeParse({
        cliAvailable: true,
        daemonRunning: true,
        status: "running",
        loadedModelCount: 1,
        loadedModels: [{ identifier, type: "llm", architecture: "example" }],
        observedAt: new Date(0).toISOString(),
        errorKind: "",
        error: "",
      }).success,
      false,
      `resource schema accepted a ${label} identifier`,
    );
  });
}

Deno.test("daemon: an unbounded model list fails closed", async () => {
  const models = Array.from({ length: 600 }, (_unused, i) => ({
    identifier: `example/model-${i}`,
    type: "llm",
    architecture: "example",
  }));
  const value = await runDaemon(() =>
    Promise.resolve({
      success: true,
      code: 0,
      stdout: JSON.stringify(models),
      stderr: "",
    })
  );
  assertEquals(value.errorKind, "invalid-response");
  assertEquals(value.loadedModelCount, 0);
  assertEquals(
    daemon.resources.daemon.schema.safeParse({
      cliAvailable: true,
      daemonRunning: true,
      status: "running",
      loadedModelCount: models.length,
      loadedModels: models,
      observedAt: new Date(0).toISOString(),
      errorKind: "",
      error: "",
    }).success,
    false,
    "resource schema accepted an unbounded loadedModels array",
  );
});

// ---------------------------------------------------------------------------
// A transient refusal is not a capability finding. embedding() used to
// relabel EVERY non-2xx as no_embedding_capability and store it for ever.
// ---------------------------------------------------------------------------

async function runEmbedding(queue: (() => Response)[]) {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  let written: Record<string, unknown> | undefined;
  globalThis.fetch = () => {
    calls++;
    const next = queue.shift();
    if (!next) return Promise.reject(new Error("unexpected extra request"));
    return Promise.resolve(next());
  };
  try {
    await probe.methods.embedding.execute({
      model: "example/embed",
      input: "swamp lmstudio probe",
    }, {
      globalArgs: OK,
      signal: new AbortController().signal,
      logger: { info: () => {}, warning: () => {} },
      writeResource: (
        _spec: string,
        _name: string,
        value: Record<string, unknown>,
      ) => {
        written = value;
        return Promise.resolve({ name: "embedding" });
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  return { written: written as Record<string, unknown>, calls };
}

// retry-after: 0 keeps the bounded backoff from putting a real second into
// every one of these tests.
const rateLimited = () =>
  new Response("slow down", {
    status: 429,
    headers: { "retry-after": "0" },
  });

Deno.test("embedding: a persistent rate limit is not stored as a missing capability", async () => {
  const { written, calls } = await runEmbedding([rateLimited, rateLimited]);
  assertEquals(calls, 2, "429 must get the same bounded retry completion gets");
  assertEquals(
    written.errorKind,
    "rate_limited",
    "a 429 stored as no_embedding_capability is a transient condition " +
      "recorded for ever as a capability finding",
  );
  assertEquals(written.servesEmbeddings, false);
  assertEquals(written.dimensionKnown, false);
});

Deno.test("embedding: a server fault is not stored as a missing capability", async () => {
  const { written, calls } = await runEmbedding([
    () => new Response("upstream exploded", { status: 502 }),
  ]);
  assertEquals(calls, 1);
  assertEquals(written.errorKind, "server_error");
  assertEquals(written.dimensionKnown, false);
});

Deno.test("embedding: a transient 503 is retried before anything is recorded", async () => {
  const { written, calls } = await runEmbedding([
    () =>
      new Response("loading another model", {
        status: 503,
        headers: { "retry-after": "0" },
      }),
    () =>
      new Response(JSON.stringify({ data: [{ embedding: [0.1, 0.2, 0.3] }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  ]);
  assertEquals(calls, 2, "the embedding probe must retry 503 like completion");
  assertEquals(written.errorKind, "");
  assertEquals(written.servesEmbeddings, true);
  assertEquals(written.measuredDimension, 3);
  assertEquals(written.dimensionKnown, true);
});

Deno.test("embedding: a generic 4xx is still labelled no_embedding_capability", async () => {
  // The deliberate behaviour this probe exists for: chat keeps working while
  // the endpoint refuses embeddings. Scoping the relabel must not lose it.
  const { written, calls } = await runEmbedding([
    () =>
      new Response("no embedding model is currently loaded", { status: 400 }),
  ]);
  assertEquals(calls, 1);
  assertEquals(written.errorKind, "no_embedding_capability");
  assertEquals(written.servesEmbeddings, false);
});
