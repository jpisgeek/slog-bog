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
  // Extended, not replaced: `success: false` was the only signal overflow
  // had, which left observe() unable to tell it from a non-zero exit. The
  // flag is what lets overflow reach `invalid-response` instead of being
  // keyword-scanned into `unreachable`.
  assertEquals(
    result.truncated,
    true,
    "overflow must be reported explicitly, not inferred from success alone",
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

// ---------------------------------------------------------------------------
// Shared fixtures for the gate-fix tests below.
//
// Built from code points rather than string escapes so the hostile characters
// are unambiguous in the source, and so a copy/paste of this file cannot
// silently lose them.
// ---------------------------------------------------------------------------

const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);
const ZWSP = String.fromCharCode(0x200b);
const RLO = String.fromCharCode(0x202e);
/** The terminal-title escape sequence, the canonical instance of the class. */
const TITLE_ESCAPE = `${ESC}]0;PWNED${BEL}`;

/** True when a string still carries anything that can drive or hide terminal output. */
function hasScreenableChar(value: string): boolean {
  for (const ch of value) {
    const cp = ch.codePointAt(0)!;
    if (cp <= 0x1f) return true;
    if (cp >= 0x7f && cp <= 0x9f) return true;
    if (cp >= 0x200b && cp <= 0x200f) return true;
    if (cp >= 0x202a && cp <= 0x202e) return true;
    if (cp >= 0x2066 && cp <= 0x2069) return true;
    if (cp === 0xfeff) return true;
    if (cp >= 0xd800 && cp <= 0xdfff) return true;
  }
  return false;
}

function jsonResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "application/json" },
  });
}

function chatBody(content: string, finishReason = "stop"): string {
  return JSON.stringify({
    choices: [{ finish_reason: finishReason, message: { content } }],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
  });
}

/** A response whose body stream fails partway through, the way a cancelled or timed-out read does. */
function failingBody(
  reason: unknown,
  onPull?: () => void,
  status = 200,
): Response {
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      onPull?.();
      controller.error(reason);
    },
  });
  return new Response(stream, {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A response body larger than the reader's byte cap. */
function oversizedBody(status = 200): Response {
  const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
  let sent = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= 8) {
        controller.close();
        return;
      }
      sent++;
      controller.enqueue(chunk);
    },
  });
  return new Response(stream, {
    status,
    headers: { "content-type": "application/json" },
  });
}

interface RunOutcome {
  written?: Record<string, unknown>;
  name?: string;
  thrown?: Error;
  calls: number;
}

/** Drive one probe or endpoint method against a queue of stubbed responses. */
async function runMethod(
  // Each method's execute() is typed to its own zod-inferred argument shape,
  // so the seam that drives all five of them is deliberately untyped here.
  // deno-lint-ignore no-explicit-any
  execute: (args: any, ctx: any) => Promise<unknown>,
  args: Record<string, unknown>,
  queue: (() => Response)[],
  signal: AbortSignal = new AbortController().signal,
): Promise<RunOutcome> {
  const originalFetch = globalThis.fetch;
  const outcome: RunOutcome = { calls: 0 };
  globalThis.fetch = () => {
    outcome.calls++;
    const next = queue.shift();
    if (!next) return Promise.reject(new Error("unexpected extra request"));
    return Promise.resolve(next());
  };
  try {
    await execute(args, {
      globalArgs: OK,
      signal,
      logger: { info: () => {}, warning: () => {} },
      writeResource: (
        _spec: string,
        name: string,
        value: Record<string, unknown>,
      ) => {
        outcome.written = value;
        outcome.name = name;
        return Promise.resolve({ name });
      },
    });
  } catch (e) {
    outcome.thrown = e as Error;
  } finally {
    globalThis.fetch = originalFetch;
  }
  return outcome;
}

// ---------------------------------------------------------------------------
// A cancelled or timed-out BODY read is not an observation about the endpoint.
//
// The request-level distinction was already made in classifyFetchError(), but
// everything after the response headers arrived went through
// `.text().catch(() => "")` or a bare `.json()`. A caller who cancelled a
// millisecond after the headers landed got "HTTP 500: " or, worse, a stored
// `malformed_response` -- a permanent finding about an endpoint nobody
// finished looking at.
// ---------------------------------------------------------------------------

Deno.test("completion: cancellation during the body read throws, never records malformed_response", async () => {
  const controller = new AbortController();
  const outcome = await runMethod(
    probe.methods.completion.execute,
    { model: "example/chat", prompt: "hello", maxTokens: 8, temperature: 0 },
    [() =>
      failingBody(
        new DOMException("aborted", "AbortError"),
        () => controller.abort(),
      )],
    controller.signal,
  );
  assertEquals(
    outcome.written,
    undefined,
    "a cancelled run must not leave an infinite-lifetime probe result behind",
  );
  assertEquals(outcome.thrown?.message.startsWith("CANCELLED:"), true);
});

Deno.test("completion: a timeout during the body read is a timeout, not a malformed body", async () => {
  const outcome = await runMethod(
    probe.methods.completion.execute,
    { model: "example/chat", prompt: "hello", maxTokens: 8, temperature: 0 },
    [() => failingBody(new DOMException("timed out", "TimeoutError"))],
  );
  assertEquals(
    outcome.written?.errorKind,
    "timeout",
    "a deadline that fires mid-body used to be stored as malformed_response",
  );
});

Deno.test("health: cancellation after the response headers arrive writes nothing", async () => {
  const controller = new AbortController();
  const outcome = await runMethod(
    endpoint.methods.health.execute,
    {},
    [() => {
      // Headers arrived, so fetch() resolves and the catch block never runs;
      // the caller pulls the plug immediately afterwards.
      controller.abort();
      return jsonResponse(JSON.stringify({ data: [] }));
    }],
    controller.signal,
  );
  assertEquals(
    outcome.written,
    undefined,
    "a cancelled run must not record reachable/latency for the endpoint",
  );
  assertEquals(outcome.thrown?.message.startsWith("CANCELLED:"), true);
});

Deno.test("models: cancellation after the model list parses writes nothing", async () => {
  const controller = new AbortController();
  const outcome = await runMethod(
    endpoint.methods.models.execute,
    {},
    [() => {
      controller.abort();
      return jsonResponse(JSON.stringify({ data: [{ id: "example/chat" }] }));
    }],
    controller.signal,
  );
  assertEquals(outcome.written, undefined);
  assertEquals(outcome.thrown?.message.startsWith("CANCELLED:"), true);
});

// ---------------------------------------------------------------------------
// Untrusted response bodies reach stored `error` fields whose lifetime is
// `infinite`. redact() only ever knew about the bearer token.
// ---------------------------------------------------------------------------

Deno.test("embedding: a hostile error body is screened and bounded before it is stored", async () => {
  const hostile = `${TITLE_ESCAPE} no embedding model ${RLO}${ZWSP}` +
    "z".repeat(5000);
  const outcome = await runMethod(
    probe.methods.embedding.execute,
    { model: "example/embed", input: "swamp lmstudio probe" },
    [() => new Response(hostile, { status: 400 })],
  );
  const stored = String(outcome.written?.error ?? "");
  assertEquals(
    hasScreenableChar(stored),
    false,
    "an endpoint error body reached stored data still able to drive a terminal",
  );
  assertEquals(
    stored.length <= 400,
    true,
    `stored error was ${stored.length} chars -- remote text must be bounded`,
  );
  // The deliberate half of the trade: the endpoint's own words survive, so
  // the probe stays diagnosable. Only its ability to be unbounded or to
  // control a terminal is removed.
  assertEquals(stored.includes("no embedding model"), true);
});

Deno.test("completion: the bearer token never survives an echoed error body", async () => {
  const outcome = await runMethod(
    probe.methods.completion.execute,
    { model: "example/chat", prompt: "hello", maxTokens: 8, temperature: 0 },
    [() =>
      new Response(`upstream echoed Authorization: Bearer ${OK.apiToken}`, {
        status: 500,
      })],
  );
  const stored = String(outcome.written?.error ?? "");
  assertEquals(stored.includes(OK.apiToken), false, "TOKEN LEAK into error");
  assertEquals(stored.includes("[REDACTED]"), true);
});

Deno.test("models: a hostile error body is screened before it reaches the thrown error", async () => {
  const outcome = await runMethod(
    endpoint.methods.models.execute,
    {},
    [() => new Response(`${TITLE_ESCAPE}gateway exploded`, { status: 502 })],
  );
  const message = outcome.thrown?.message ?? "";
  assertEquals(message.startsWith("HTTP_ERROR:"), true);
  assertEquals(
    hasScreenableChar(message),
    false,
    "a thrown error is exactly the string that ends up in a log",
  );
});

// ---------------------------------------------------------------------------
// Response bodies had no byte bound at all. A request timeout limits how long
// a hostile endpoint may stream, not how much it may hand over in that time.
// ---------------------------------------------------------------------------

Deno.test("models: an oversized 2xx body is refused, never parsed", async () => {
  const outcome = await runMethod(
    endpoint.methods.models.execute,
    {},
    [() => oversizedBody()],
  );
  assertEquals(outcome.written, undefined);
  assertEquals(outcome.thrown?.message.startsWith("MALFORMED_RESPONSE:"), true);
  assertEquals(outcome.thrown?.message.includes("cap"), true);
});

Deno.test("completion: an oversized 2xx body is refused, never parsed", async () => {
  const outcome = await runMethod(
    probe.methods.completion.execute,
    { model: "example/chat", prompt: "hello", maxTokens: 8, temperature: 0 },
    [() => oversizedBody()],
  );
  assertEquals(outcome.written?.errorKind, "malformed_response");
  assertEquals(String(outcome.written?.error).includes("cap"), true);
});

Deno.test("embedding: an oversized 2xx body is refused, never parsed", async () => {
  const outcome = await runMethod(
    probe.methods.embedding.execute,
    { model: "example/embed", input: "swamp lmstudio probe" },
    [() => oversizedBody()],
  );
  assertEquals(outcome.written?.errorKind, "malformed_response");
  assertEquals(
    outcome.written?.dimensionKnown,
    false,
    "an unread body must never leave a measured dimension behind",
  );
});

// ---------------------------------------------------------------------------
// Model ids are remote-controlled text, and they end up in an
// infinite-lifetime resource, in a tag, in a log line, and in a storage path.
// ---------------------------------------------------------------------------

Deno.test("models: a hostile model id fails closed instead of being stored", async () => {
  const hostile = `qwen${TITLE_ESCAPE}-7b`;
  const outcome = await runMethod(
    endpoint.methods.models.execute,
    {},
    [() => jsonResponse(JSON.stringify({ data: [{ id: hostile }] }))],
  );
  assertEquals(outcome.written, undefined, "unscreened id reached stored data");
  assertEquals(outcome.thrown?.message.startsWith("MALFORMED_RESPONSE:"), true);
  assertEquals(
    hasScreenableChar(outcome.thrown?.message ?? ""),
    false,
    "the rejected id must not be echoed into the error that reports it",
  );

  // Asserted against the resource schema as well, not just the parse path: a
  // bound that lives only in extractModelIds() is one refactor from gone.
  assertEquals(
    endpoint.resources.models.schema.safeParse({
      modelIds: [hostile],
      modelCount: 1,
      syncedAt: new Date(0).toISOString(),
    }).success,
    false,
    "resource schema accepted an unscreened model id",
  );
});

Deno.test("models: an over-long model id fails closed", async () => {
  const long = "q".repeat(400);
  const outcome = await runMethod(
    endpoint.methods.models.execute,
    {},
    [() => jsonResponse(JSON.stringify({ data: [{ id: long }] }))],
  );
  assertEquals(outcome.written, undefined);
  assertEquals(outcome.thrown?.message.startsWith("MALFORMED_RESPONSE:"), true);
  assertEquals(
    endpoint.resources.models.schema.safeParse({
      modelIds: [long],
      modelCount: 1,
      syncedAt: new Date(0).toISOString(),
    }).success,
    false,
  );
});

Deno.test("models: an unbounded model list fails closed", async () => {
  const ids = Array.from({ length: 2000 }, (_u, i) => ({ id: `m-${i}` }));
  const outcome = await runMethod(
    endpoint.methods.models.execute,
    {},
    [() => jsonResponse(JSON.stringify({ data: ids }))],
  );
  assertEquals(outcome.written, undefined);
  assertEquals(outcome.thrown?.message.startsWith("MALFORMED_RESPONSE:"), true);
  assertEquals(
    endpoint.resources.models.schema.safeParse({
      modelIds: ids.map((e) => e.id),
      modelCount: ids.length,
      syncedAt: new Date(0).toISOString(),
    }).success,
    false,
    "resource schema accepted an unbounded modelIds array",
  );
});

Deno.test("probe arguments reject a hostile or over-long model id", () => {
  for (
    const [label, bad] of [
      ["terminal escape", `qwen${TITLE_ESCAPE}-7b`],
      ["bidi override", `qwen${RLO}gnp.exe-7b`],
      ["zero width", `qwen${ZWSP}-7b`],
      ["over long", "q".repeat(400)],
    ] as const
  ) {
    for (
      const args of [
        probe.methods.embedding.arguments,
        probe.methods.completion.arguments,
        probe.methods.capabilities.arguments,
      ]
    ) {
      assertEquals(
        args.safeParse({ model: bad, prompt: "hi" }).success,
        false,
        `accepted a model id with a ${label}`,
      );
    }
  }
});

// ---------------------------------------------------------------------------
// The 2xx envelope was cast, not validated. `null`, `[]`, and `7` all parse.
// ---------------------------------------------------------------------------

Deno.test("completion: a 2xx body that is not a JSON object is malformed, not a crash", async () => {
  for (const body of ["null", "[]", "7", '"hello"']) {
    const outcome = await runMethod(
      probe.methods.completion.execute,
      { model: "example/chat", prompt: "hello", maxTokens: 8, temperature: 0 },
      [() => jsonResponse(body)],
    );
    assertEquals(
      outcome.thrown,
      undefined,
      `a 2xx body of ${body} escaped as an unhandled exception`,
    );
    assertEquals(outcome.written?.errorKind, "malformed_response");
  }
});

Deno.test("embedding: a 2xx body with no data[] is malformed, not an empty response", async () => {
  for (const body of ["{}", "null", '{"data":"nope"}']) {
    const outcome = await runMethod(
      probe.methods.embedding.execute,
      { model: "example/embed", input: "swamp lmstudio probe" },
      [() => jsonResponse(body)],
    );
    assertEquals(
      outcome.written?.errorKind,
      "malformed_response",
      `${body} was scored as empty_response -- claiming the endpoint answered ` +
        "the embedding question when it never did",
    );
    assertEquals(outcome.written?.dimensionKnown, false);
  }
});

Deno.test("embedding: a well-formed envelope with no vector is still empty_response", async () => {
  // The deliberate distinction must survive the malformed_response split: the
  // endpoint DID answer, and the answer carried no vector.
  const outcome = await runMethod(
    probe.methods.embedding.execute,
    { model: "example/embed", input: "swamp lmstudio probe" },
    [() => jsonResponse('{"data":[]}')],
  );
  assertEquals(outcome.written?.errorKind, "empty_response");
  assertEquals(outcome.written?.dimensionKnown, false);
});

Deno.test("models: a 2xx body that is not an OpenAI envelope throws the documented kind", async () => {
  for (const body of ["null", "[]", '{"models":[]}', '{"data":[{}]}']) {
    const outcome = await runMethod(
      endpoint.methods.models.execute,
      {},
      [() => jsonResponse(body)],
    );
    assertEquals(
      outcome.thrown?.message.startsWith("MALFORMED_RESPONSE:"),
      true,
      `${body} threw outside the taxonomy the README Caveats promise: ` +
        outcome.thrown?.message,
    );
  }
});

// ---------------------------------------------------------------------------
// Instance names ARE storage paths.
// ---------------------------------------------------------------------------

Deno.test("probe instance names stay unique and path-safe for ids that slugify alike", async () => {
  const vector = () =>
    jsonResponse(JSON.stringify({ data: [{ embedding: [0.1, 0.2] }] }));
  const names = new Set<string>();
  const ids = [
    "qwen/qwen3-4b",
    "qwen-qwen3-4b",
    `vendor/${"a".repeat(120)}/one`,
    `vendor/${"a".repeat(120)}/two`,
  ];
  for (const model of ids) {
    const outcome = await runMethod(
      probe.methods.embedding.execute,
      { model, input: "swamp lmstudio probe" },
      [vector],
    );
    const name = outcome.name!;
    assertEquals(
      name.length <= 120,
      true,
      `instance name was ${name.length} chars -- it is a path component`,
    );
    names.add(name);
  }
  assertEquals(
    names.size,
    ids.length,
    "two distinct model ids collided onto one instance name, so one probe " +
      "result silently overwrote another",
  );
});

// ---------------------------------------------------------------------------
// honorsResponseFormat must mean the model returned a JSON OBJECT.
// ---------------------------------------------------------------------------

async function runCapabilities(formatReply: string) {
  return await runMethod(
    probe.methods.capabilities.execute,
    { model: "example/chat", maxTokens: 32 },
    [
      () => jsonResponse(chatBody("17 * 24 = 408")),
      () => jsonResponse(chatBody(formatReply)),
      () => jsonResponse(chatBody("OK")),
    ],
  );
}

Deno.test("capabilities: a non-object JSON reply is not a honoured response_format", async () => {
  for (const reply of ["[1,2]", "null", "42", '"ok"']) {
    const outcome = await runCapabilities(reply);
    assertEquals(outcome.written?.checksCompleted, 3);
    assertEquals(
      outcome.written?.honorsResponseFormat,
      false,
      `${reply} recorded a capability the model never demonstrated`,
    );
  }
});

Deno.test("capabilities: a JSON object still honours the format, extra keys and all", async () => {
  // Deliberately not an exact match against {"ok":true}: honouring
  // json_object mode and following the prose instruction are two different
  // findings, and this flag is named for the first one.
  for (const reply of ['{"ok": true}', '{"ok": true, "note": "sure"}', "{}"]) {
    const outcome = await runCapabilities(reply);
    assertEquals(outcome.written?.honorsResponseFormat, true, reply);
  }
});

// ---------------------------------------------------------------------------
// Daemon: absent measurements, and overflow classification.
// ---------------------------------------------------------------------------

Deno.test("daemon: a model type the daemon never reported stays null, not an empty string", async () => {
  const value = await runDaemon(() =>
    Promise.resolve({
      success: true,
      code: 0,
      stdout: JSON.stringify([{ identifier: "example/chat" }]),
      stderr: "",
    })
  );
  const loaded = (value.loadedModels as Record<string, unknown>[])[0];
  assertEquals(
    loaded.type,
    null,
    'an absent type stored as "" is indistinguishable from a measured one',
  );
  assertEquals(loaded.architecture, null);
  assertEquals(value.errorKind, "");

  // The resource schema must refuse the empty string too, or the ambiguity
  // comes straight back the next time something writes this shape by hand.
  assertEquals(
    daemon.resources.daemon.schema.safeParse({
      cliAvailable: true,
      daemonRunning: true,
      status: "running",
      loadedModelCount: 1,
      loadedModels: [{
        identifier: "example/chat",
        type: "",
        architecture: "",
      }],
      observedAt: new Date(0).toISOString(),
      errorKind: "",
      error: "",
    }).success,
    false,
    'resource schema accepted "" as a measured type',
  );
});

Deno.test("daemon: an overflowing ps payload is invalid-response, never unreachable", async () => {
  // The captured megabyte is remote-controlled text; the keyword scan that
  // produces `unreachable` must never see it. "network" here is the trap.
  const value = await runDaemon(() =>
    Promise.resolve({
      success: false,
      truncated: true,
      code: 0,
      stdout: "[{...network...",
      stderr: "",
    })
  );
  assertEquals(
    value.errorKind,
    "invalid-response",
    "an oversized answer was recorded as a measurement about the host",
  );
  assertEquals(value.loadedModelCount, 0);
  assertEquals(value.daemonRunning, false);
});

Deno.test("daemon: a truncated payload that happens to parse is still refused", async () => {
  const value = await runDaemon(() =>
    Promise.resolve({
      success: true,
      truncated: true,
      code: 0,
      stdout: "[]",
      stderr: "",
    })
  );
  assertEquals(
    value.errorKind,
    "invalid-response",
    "a prefix that parses is a wrong answer, not a whole one",
  );
});
