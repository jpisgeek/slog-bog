/**
 * Operational probes against an OpenAI-compatible inference endpoint
 * (LM Studio, or anything else that speaks the same `/v1` surface).
 *
 * This is the part that encodes facts learned the hard way rather than what
 * the API contract promises:
 *
 *   embedding    A configured vector dimension that disagrees with what the
 *                model actually returns silently corrupts a vector index.
 *                The dimension must never be assumed from a model's name or
 *                reputation -- it is measured here, from the real response.
 *                Also: an endpoint with no embedding model loaded returns an
 *                error while chat completions keep working fine. That is a
 *                classic silent failure, so "does this endpoint serve
 *                embeddings at all" is recorded as its own fact.
 *
 *   completion   Some reasoning models can burn the entire completion token
 *                budget on reasoning_content before emitting any `content`
 *                at all, finishing with finish_reason: "length" and an empty
 *                answer. Without instrumentation that looks exactly like a
 *                model that ignored its instructions -- the wrong diagnosis.
 *                reasoningTokens / reasoningChars / emptyContentWithReasoning
 *                exist so that failure mode is nameable instead of guessed
 *                at. contextExhausted is a heuristic, not a direct fact --
 *                see the comment in completion() for why, and its limit.
 *
 *   capabilities A short battery against one model: does it emit reasoning
 *                unprompted, does it honour a requested response_format,
 *                does it wrap output in markdown fences even when told not
 *                to. Fencing is recorded as a formatting habit, not scored
 *                as a failure -- plenty of correct answers arrive fenced.
 *
 * No local/default endpoint anywhere in this file: `baseUrl` is required
 * config with no default, because this extension is meant for the public
 * swamp registry and must not assume a private network.
 *
 * All three probes throw a distinct UNAUTHORIZED error on a 401/403,
 * instead of writing it as data, matching endpoint.models(). A bad token is
 * a configuration fault, not a measurement -- left as data it would be
 * indistinguishable from a genuine finding (e.g. "no embedding model
 * loaded" leaves measuredDimension absent for the same reason a bad token
 * does), and only one of those is actually about the endpoint. Caller
 * cancellation (workflow abort, not the request timeout) throws for the
 * same reason: a cancelled probe never observed the endpoint at all, so
 * recording it as errorKind "timeout" would be indistinguishable from a
 * genuinely slow endpoint. Every other failure -- unreachable, timeout,
 * http_error, model_not_found, no_embedding_capability, empty_response,
 * malformed_response -- stays non-throwing: those are genuine observations
 * about endpoint state, not our own misconfiguration.
 *
 * `apiToken` must never be read from an environment variable: env values
 * persist into `.swamp/data/`, which would leak the token into stored state.
 * Source it from a vault expression instead, e.g.
 * `${{ vault.get('myvault', 'ExampleService/API Key') }}`.
 */
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  baseUrl: z
    .string()
    .min(1)
    .refine((v) => {
      try {
        const u = new URL(v);
        // http(s) only, and no embedded credentials: baseUrl is logged and can
        // appear in stored error text, so `https://user:pass@host` would leak.
        // The only credential is apiToken.
        return (u.protocol === "http:" || u.protocol === "https:") &&
          u.username === "" && u.password === "";
      } catch {
        return false;
      }
    }, {
      message:
        "baseUrl must be a valid http(s) URL with no embedded credentials " +
        "(user:pass@host); pass the token via apiToken.",
    })
    .describe(
      "Base URL of the OpenAI-compatible inference endpoint, including any " +
        "path prefix the server expects (typically ending in /v1), e.g. " +
        "https://inference.example.com/v1. Required -- this extension ships " +
        "no default endpoint. http:// is accepted for endpoints reachable " +
        "only over an already-encrypted transport (e.g. a WireGuard tunnel), " +
        "but the bearer token travels in cleartext over the connection " +
        "itself -- prefer https:// whenever the endpoint terminates TLS.",
    ),
  apiToken: z
    .string()
    .min(1)
    .meta({ sensitive: true })
    .describe(
      "Bearer token for the endpoint. Source it from a vault expression, " +
        "e.g. ${{ vault.get('myvault', 'ExampleService/API Key') }} -- " +
        "never hardcode it and never read it from an environment variable.",
    ),
  timeoutSec: z
    .number()
    .int()
    .positive()
    .default(30)
    .describe("HTTP timeout in seconds for every request this model makes."),
});

const EmbeddingArgsSchema = z.object({
  model: z
    .string()
    .min(1)
    .describe(
      "Model id to request embeddings from, as reported by the endpoint's " +
        "/v1/models list.",
    ),
  input: z
    .string()
    .min(1)
    .default("swamp lmstudio probe")
    .describe(
      "Short text sent as the embedding input. The default is enough to " +
        "measure vector dimension; override only to test content-specific " +
        "behavior.",
    ),
});

const CompletionArgsSchema = z.object({
  model: z.string().min(1).describe(
    "Model id to send the chat completion to.",
  ),
  prompt: z
    .string()
    .min(1)
    .describe(
      "Caller-supplied prompt. No default -- the point of this probe is " +
        "testing a real prompt against a real model, not a canned string.",
    ),
  maxTokens: z
    .number()
    .int()
    .positive()
    .default(512)
    .describe(
      "max_tokens sent with the request. Also used, alongside " +
        "finish_reason, to distinguish a completion that hit this cap from " +
        "one that hit the model's context window -- see contextExhausted.",
    ),
  temperature: z
    .number()
    .min(0)
    .max(2)
    .default(0)
    .describe("Sampling temperature. Defaults to 0 for reproducible probes."),
});

const CapabilitiesArgsSchema = z.object({
  model: z.string().min(1).describe(
    "Model id to run the capability battery against.",
  ),
  maxTokens: z
    .number()
    .int()
    .positive()
    .default(256)
    .describe("max_tokens applied to each battery call."),
});

const EmbeddingProbeSchema = z.object({
  model: z.string(),
  servesEmbeddings: z.boolean(),
  measuredDimension: z.number(),
  /**
   * False when no vector was returned at all (error, or a 200 with an empty
   * payload). Without this, the sentinel 0 in measuredDimension reads as a
   * real -- and alarming -- zero-length vector instead of "unknown".
   */
  dimensionKnown: z.boolean(),
  latencyMs: z.number(),
  httpStatus: z.number(),
  /** "" | "model_not_found" | "no_embedding_capability" | "empty_response" | "malformed_response" | "unreachable" | "timeout" | "http_error" -- "unauthorized" and cancellation are never stored here; both throw instead (see chatCompletion/embedding). */
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.string(),
});

const CompletionProbeSchema = z.object({
  model: z.string(),
  latencyMs: z.number(),
  httpStatus: z.number(),
  finishReason: z.string(),
  promptTokens: z.number(),
  completionTokens: z.number(),
  totalTokens: z.number(),
  reasoningTokens: z.number(),
  reasoningChars: z.number(),
  contentChars: z.number(),
  /**
   * True when content came back empty while the model demonstrably spent
   * its budget on reasoning_content / reasoning_tokens. Without this flag a
   * reasoning model that exhausted its budget thinking looks identical to a
   * model that just ignored the prompt.
   */
  emptyContentWithReasoning: z.boolean(),
  /**
   * Heuristic: true when finish_reason is "length" but completionTokens
   * came in under the maxTokens actually requested -- i.e. something other
   * than the requested cap forced the stop, almost always the model's
   * context window. See the comment in completion() for why this is an
   * inference rather than a fact read directly from the API.
   */
  contextExhausted: z.boolean(),
  /** True when finish_reason is "length" and the requested cap was reached. */
  maxTokensHit: z.boolean(),
  /** "" | "model_not_found" | "malformed_response" | "unreachable" | "timeout" | "http_error" -- "unauthorized" and cancellation are never stored here; both throw instead (see chatCompletion). */
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.string(),
});

const CapabilityProbeSchema = z.object({
  model: z.string(),
  emitsReasoning: z.boolean(),
  honorsResponseFormat: z.boolean(),
  /** A formatting habit, not a content failure -- recorded either way. */
  wrapsInCodeFences: z.boolean(),
  /**
   * How many of the 3 battery checks (reasoning, response_format, code
   * fences) actually ran to completion, in order. A rerun that fails partway
   * through writes the same aggregate shape as a rerun that completed --
   * without this, `emitsReasoning: false` on a failed battery is
   * indistinguishable from `emitsReasoning: false` because a complete battery
   * genuinely found no reasoning. Only the first `checksCompleted` boolean
   * fields (in the order above) reflect a real measurement; the rest are
   * left at their default `false` and must not be read as findings.
   */
  checksCompleted: z.number().int().min(0).max(3),
  /** True when max_tokens was reached before the reasoning check finished -- a truncated reply, not a genuine "no reasoning" finding. Only meaningful when checksCompleted >= 1. */
  reasoningCheckTruncated: z.boolean(),
  /** Same as reasoningCheckTruncated, for the response_format check. Only meaningful when checksCompleted >= 2. */
  formatCheckTruncated: z.boolean(),
  /** Same as reasoningCheckTruncated, for the code-fence check. Only meaningful when checksCompleted >= 3. */
  fenceCheckTruncated: z.boolean(),
  latencyMs: z.number(),
  /** "" | "model_not_found" | "malformed_response" | "unreachable" | "timeout" | "http_error" -- "unauthorized" and cancellation are never stored here; both throw instead (see chatCompletion). */
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.string(),
});

function normalizeBase(raw: string): string {
  return raw.replace(/\/+$/, "");
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(
    /^-+|-+$/g,
    "",
  ) || "unnamed";
}

/**
 * Build a filesystem-safe, collision-resistant instance name from a
 * caller-supplied model id. Instance names map directly to storage paths on
 * disk, but model ids routinely contain characters `slug()` normalizes away
 * -- e.g. `qwen/qwen3-4b` -- so two distinct ids (`foo/bar` and `foo-bar`)
 * can slugify to the same string and silently overwrite each other's
 * resource on every subsequent run. `slug()` stays in the name for
 * readability in `swamp data list`; the hash suffix, derived from the full
 * un-normalized id, is what actually guarantees uniqueness. The same model
 * id always hashes to the same suffix, so reruns against the same model
 * still overwrite the same instance -- this only separates ids that were
 * never the same to begin with.
 */
async function instanceName(prefix: string, modelId: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(modelId),
  );
  const hash = Array.from(new Uint8Array(digest).slice(0, 4))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${prefix}-${slug(modelId)}-${hash}`;
}

/** Strip the API token from any string before it can land in stored data. */
function redact(text: string, token: string): string {
  if (!token) return text;
  return text.split(token).join("[REDACTED]");
}

/**
 * fetch() throws before any HTTP response exists for DNS failure, connection
 * refused, TLS failure, our own request-timeout firing, or the caller's own
 * AbortSignal firing (workflow cancellation). All three surface as the same
 * DOMException shape out of fetch(), so `callerSignal` -- the caller's raw
 * signal, checked directly rather than inferred from the thrown error's
 * `name` -- is what actually tells a cancellation apart from a timeout.
 * Collapsing the two would mean cancelling a run and the endpoint genuinely
 * timing out produce identical stored evidence, which is exactly the
 * ambiguity this extension exists to prevent elsewhere.
 */
function classifyFetchError(
  e: unknown,
  callerSignal?: AbortSignal,
): { kind: string; message: string } {
  if (callerSignal?.aborted) {
    return {
      kind: "cancelled",
      message:
        "request was cancelled by the caller before the endpoint responded",
    };
  }
  const err = e as { name?: string; message?: string };
  if (err?.name === "TimeoutError" || err?.name === "AbortError") {
    return {
      kind: "timeout",
      message: "request timed out before the endpoint responded",
    };
  }
  return {
    kind: "unreachable",
    message: `could not reach endpoint: ${err?.message ?? String(e)}`,
  };
}

/** Statuses worth one bounded retry: rate-limited or momentarily overloaded. */
const RETRYABLE_STATUS = new Set([429, 503]);
/** Upper bound on how long a single retry will wait, regardless of what the
 * endpoint's Retry-After header asks for -- this is a diagnostic probe, not
 * a production client, so it should not stall a workflow run for minutes on
 * an adversarial or misconfigured Retry-After value. */
const MAX_RETRY_DELAY_MS = 5000;
/** Backoff used when the endpoint sends 429/503 without a Retry-After header. */
const DEFAULT_RETRY_DELAY_MS = 1000;

/** Read Retry-After as either delay-seconds or an HTTP-date, per RFC 9110 §10.2.3. */
function parseRetryAfterMs(response: Response): number | undefined {
  const header = response.headers.get("retry-after");
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const when = Date.parse(header);
  if (!Number.isNaN(when)) return Math.max(0, when - Date.now());
  return undefined;
}

/** Delay that resolves early -- without throwing -- if `signal` aborts while waiting. */
function abortableDelay(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Classify an HTTP-level (response received, but non-2xx) failure. `bodyText`
 * must already be redacted by the caller before it reaches here.
 */
function classifyHttpError(
  status: number,
  bodyText: string,
): { kind: string; message: string } {
  if (status === 401 || status === 403) {
    return {
      kind: "unauthorized",
      message: `endpoint rejected the API token (HTTP ${status})`,
    };
  }
  if (status === 404) {
    return {
      kind: "model_not_found",
      message: "HTTP 404 -- model id not recognized by this endpoint",
    };
  }
  const lower = bodyText.toLowerCase();
  if (
    status === 400 && lower.includes("model") &&
    (lower.includes("not found") || lower.includes("does not exist") ||
      lower.includes("unknown model"))
  ) {
    return {
      kind: "model_not_found",
      message: `endpoint reports the model id is not recognized: ${
        bodyText.slice(0, 160)
      }`,
    };
  }
  return {
    kind: "http_error",
    message: `HTTP ${status}: ${bodyText.slice(0, 160)}`,
  };
}

interface ChatResult {
  ok: boolean;
  httpStatus: number;
  errorKind: string;
  error: string;
  content: string;
  reasoningContent: string;
  finishReason: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  reasoningTokens: number;
  latencyMs: number;
}

/**
 * POST /v1/chat/completions, shared by completion() and capabilities().
 *
 * `signal` is the caller's raw cancellation signal (not yet combined with
 * the per-attempt timeout) -- it is what classifyFetchError() uses to tell
 * "the caller cancelled this run" apart from "this attempt timed out", and
 * what the 429/503 backoff wait below checks so a cancelled run doesn't sit
 * in a sleep() no one is waiting on anymore.
 */
async function chatCompletion(
  base: string,
  token: string,
  timeoutMs: number,
  signal: AbortSignal,
  body: Record<string, unknown>,
): Promise<ChatResult> {
  const started = performance.now();
  const result: ChatResult = {
    ok: false,
    httpStatus: 0,
    errorKind: "",
    error: "",
    content: "",
    reasoningContent: "",
    finishReason: "",
    promptTokens: 0,
    completionTokens: 0,
    totalTokens: 0,
    reasoningTokens: 0,
    latencyMs: 0,
  };

  const maxAttempts = 2;
  let response: Response | undefined;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      response = await fetch(`${base}/chat/completions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
        signal: AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]),
      });
    } catch (e) {
      const c = classifyFetchError(e, signal);
      result.latencyMs = Math.round(performance.now() - started);
      if (c.kind === "cancelled") {
        // Not an observation about the endpoint -- the caller pulled the
        // plug. Thrown (same distinction as the UNAUTHORIZED branch below)
        // so a cancelled run does not persist a "timeout" or "unreachable"
        // finding that never actually happened.
        throw new Error(`CANCELLED: ${c.message}`);
      }
      result.errorKind = c.kind;
      result.error = c.message;
      return result;
    }

    // Rate-limited or momentarily overloaded: worth one bounded retry,
    // honouring Retry-After when the endpoint sends one, capped so an
    // adversarial or misconfigured header can't stall the run for minutes.
    if (RETRYABLE_STATUS.has(response.status) && attempt < maxAttempts) {
      const delayMs = Math.min(
        parseRetryAfterMs(response) ?? DEFAULT_RETRY_DELAY_MS,
        MAX_RETRY_DELAY_MS,
      );
      await response.body?.cancel().catch(() => {});
      await abortableDelay(delayMs, signal);
      if (signal.aborted) {
        throw new Error(
          "CANCELLED: request was cancelled while waiting to retry after " +
            `a HTTP ${response.status} response`,
        );
      }
      continue;
    }
    break;
  }

  // The loop always assigns `response` (it either returns, throws, or falls
  // through with a response) before reaching here.
  const finalResponse = response!;
  result.httpStatus = finalResponse.status;
  result.latencyMs = Math.round(performance.now() - started);

  if (!finalResponse.ok) {
    const bodyText = await finalResponse.text().catch(() => "");
    // Redaction point: strip the token from any echoed error body -- a
    // misconfigured proxy's error page could in principle include request
    // headers -- before it is classified or stored.
    const safeBody = redact(bodyText, token);
    const c = classifyHttpError(finalResponse.status, safeBody);
    if (c.kind === "unauthorized") {
      // A bad token is a configuration fault, not a measurement, so it is
      // thrown rather than written as data -- same distinction as
      // endpoint.models(). If this landed as an errorKind on the resource,
      // a workflow could assert against a probe that never actually probed
      // anything: measuredDimension absent because the endpoint refused us
      // looks identical to absent because the model serves no embeddings.
      // Those need different operator actions, and only one of them is a
      // finding about the endpoint.
      //
      // Redaction point: run the message through redact() again even
      // though safeBody above is already scrubbed -- an exception string is
      // exactly the kind of thing that ends up in a log, so the token must
      // never reach it by any path.
      throw new Error(`UNAUTHORIZED: ${redact(c.message, token)}`);
    }
    result.errorKind = c.kind;
    result.error = c.message;
    return result;
  }

  let json: Record<string, unknown>;
  try {
    json = await finalResponse.json() as Record<string, unknown>;
  } catch (e) {
    // A malformed 2xx body used to be swallowed by `.catch(() => ({}))` and
    // scored as `ok: true` with every field empty -- indistinguishable from
    // a real completion that happened to say nothing. Recorded as data, not
    // thrown: an endpoint returning HTTP 200 with a broken body is a fact
    // about the endpoint, not a configuration fault on our end.
    result.errorKind = "malformed_response";
    result.error = `endpoint returned HTTP ${finalResponse.status} but the ` +
      `body was not valid JSON: ${e instanceof Error ? e.message : String(e)}`;
    return result;
  }

  const choices = Array.isArray(json.choices) ? json.choices : [];
  if (choices.length === 0) {
    // Same failure mode, different shape: valid JSON, but not a chat
    // completion envelope (missing/empty choices[]). Left as `ok: true`
    // this would read as "the model replied with empty content", not "the
    // endpoint sent something that isn't a completion".
    result.errorKind = "malformed_response";
    result.error = `endpoint returned HTTP ${finalResponse.status} with a ` +
      "2xx JSON body but no choices[] entry -- not a valid chat completion " +
      "envelope";
    return result;
  }

  const choice = choices[0] as Record<string, unknown>;
  const message = (choice.message ?? {}) as Record<string, unknown>;
  const usage = (json.usage ?? {}) as Record<string, unknown>;
  const usageDetails = (usage.completion_tokens_details ?? {}) as Record<
    string,
    unknown
  >;

  result.ok = true;
  result.content = typeof message.content === "string" ? message.content : "";
  result.reasoningContent = typeof message.reasoning_content === "string"
    ? message.reasoning_content
    : "";
  result.finishReason = String(choice.finish_reason ?? "");
  result.promptTokens = Number(usage.prompt_tokens ?? 0);
  result.completionTokens = Number(usage.completion_tokens ?? 0);
  result.totalTokens = Number(usage.total_tokens ?? 0);
  result.reasoningTokens = Number(usageDetails.reasoning_tokens ?? 0);
  return result;
}

async function embedding(
  args: z.infer<typeof EmbeddingArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
) {
  const a = EmbeddingArgsSchema.parse(args);
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const base = normalizeBase(g.baseUrl);
  const timeoutMs = g.timeoutSec * 1000;

  ctx.logger.info("probing embeddings for {model}", { model: a.model });

  let servesEmbeddings = false;
  let measuredDimension = 0;
  let dimensionKnown = false;
  let httpStatus = 0;
  let errorKind = "";
  let error = "";

  const started = performance.now();
  let response: Response | undefined;
  try {
    response = await fetch(`${base}/embeddings`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${g.apiToken}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ model: a.model, input: a.input }),
      signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(timeoutMs)]),
    });
  } catch (e) {
    const c = classifyFetchError(e, ctx.signal);
    // Cancellation is the caller pulling the plug, not an endpoint
    // observation -- thrown rather than folded into errorKind so it isn't
    // stored as a "timeout" or "unreachable" finding that never happened.
    if (c.kind === "cancelled") {
      throw new Error(`CANCELLED: ${c.message}`);
    }
    errorKind = c.kind;
    error = c.message;
  }

  if (response) {
    httpStatus = response.status;
    if (response.ok) {
      let json: Record<string, unknown>;
      try {
        json = await response.json() as Record<string, unknown>;
      } catch (e) {
        // A malformed 2xx body used to be swallowed by `.catch(() => ({}))`
        // and scored identically to "endpoint returned 200 with no vector" --
        // recorded here as its own kind so a broken JSON body isn't
        // misread as a genuine "no embedding capability" finding.
        errorKind = "malformed_response";
        error = `endpoint returned HTTP ${response.status} but the body ` +
          `was not valid JSON: ${e instanceof Error ? e.message : String(e)}`;
        json = {};
      }
      const data = Array.isArray(json.data) ? json.data : [];
      const first = (data[0] ?? {}) as Record<string, unknown>;
      const vector = Array.isArray(first.embedding) ? first.embedding : [];
      // Measured, never assumed: a configured dimension that disagrees with
      // what the model actually returns corrupts a vector index. This is
      // read from the real response, not derived from the model's name or
      // reputation.
      measuredDimension = vector.length;
      dimensionKnown = vector.length > 0;
      servesEmbeddings = dimensionKnown;
      if (!dimensionKnown && !errorKind) {
        errorKind = "empty_response";
        error = "endpoint returned HTTP 200 but no embedding vector -- treat " +
          "dimension as unknown, not zero";
      }
    } else {
      const bodyText = await response.text().catch(() => "");
      // Redaction point: strip the token before any response body reaches a
      // classification or a stored error message.
      const safeBody = redact(bodyText, g.apiToken);
      const c = classifyHttpError(response.status, safeBody);
      if (c.kind === "unauthorized") {
        // A bad token is a configuration fault, not a measurement, so it is
        // thrown rather than written as data -- same distinction as
        // endpoint.models(). Left as data, this would be indistinguishable
        // from a genuine "no embedding model loaded" finding: both leave
        // measuredDimension absent, but only one of them is a fact about
        // the endpoint.
        //
        // Redaction point: run the message through redact() again even
        // though safeBody above is already scrubbed -- an exception string
        // is exactly the kind of thing that ends up in a log.
        throw new Error(`UNAUTHORIZED: ${redact(c.message, g.apiToken)}`);
      }
      // A generic error here -- distinct from an explicit unauthorized or
      // model-not-found response -- is the classic silent failure this
      // probe exists to catch: chat still works, but no embedding model is
      // loaded. Re-labelled so that failure mode is nameable rather than a
      // bare "http_error".
      if (c.kind === "http_error") {
        errorKind = "no_embedding_capability";
        error = `endpoint likely has no embedding model loaded: ${c.message}`;
      } else {
        errorKind = c.kind;
        error = c.message;
      }
    }
  }

  const latencyMs = Math.round(performance.now() - started);
  const name = await instanceName("embedding", a.model);
  const handle = await ctx.writeResource("embeddingProbe", name, {
    model: a.model,
    servesEmbeddings,
    measuredDimension,
    dimensionKnown,
    latencyMs,
    httpStatus,
    errorKind,
    error,
    checkedAt: new Date().toISOString(),
  }, {
    tags: {
      model: a.model,
      servesEmbeddings: String(servesEmbeddings),
      dimensionKnown: String(dimensionKnown),
      errorKind,
    },
  });

  if (errorKind) {
    ctx.logger.warning("embedding probe against {model} failed: {kind}", {
      model: a.model,
      kind: errorKind,
    });
  } else {
    ctx.logger.info(
      "embedding probe: servesEmbeddings={serves} dimension={dim} ({known})",
      {
        serves: servesEmbeddings,
        dim: measuredDimension,
        known: dimensionKnown ? "measured" : "unknown",
      },
    );
  }

  return { dataHandles: [handle] };
}

async function completion(
  args: z.infer<typeof CompletionArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
) {
  const a = CompletionArgsSchema.parse(args);
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const base = normalizeBase(g.baseUrl);
  const timeoutMs = g.timeoutSec * 1000;

  ctx.logger.info("probing completion for {model}", { model: a.model });

  const result = await chatCompletion(
    base,
    g.apiToken,
    timeoutMs,
    ctx.signal,
    {
      model: a.model,
      messages: [{ role: "user", content: a.prompt }],
      max_tokens: a.maxTokens,
      temperature: a.temperature,
    },
  );

  const reasoningChars = result.reasoningContent.length;
  const contentChars = result.content.length;
  // Some models spend the entire completion budget on reasoning_content
  // before emitting any content, finishing with finish_reason: "length" and
  // an empty answer. Without this flag that looks exactly like a model that
  // ignored its instructions.
  const emptyContentWithReasoning = result.ok && contentChars === 0 &&
    (reasoningChars > 0 || result.reasoningTokens > 0);

  // contextExhausted is a heuristic, not a fact read directly from the API.
  // An OpenAI-compatible /v1/models listing does not reliably expose a
  // model's context length, so there is no generic way to compare
  // prompt_tokens + completion_tokens against a hard limit for an arbitrary
  // endpoint. Instead: if finish_reason is "length" but completionTokens
  // came in under the maxTokens actually requested, something other than
  // the requested cap forced the stop -- in practice, almost always the
  // context window. If generation ran all the way to the requested cap,
  // that is a genuine max_tokens cutoff, not context exhaustion. This is an
  // inference from one call's usage numbers, not a guarantee; an endpoint
  // that exposes real context-length metadata would let this be tightened.
  const hitLength = result.ok && result.finishReason === "length";
  const maxTokensHit = hitLength && result.completionTokens >= a.maxTokens;
  const contextExhausted = hitLength && result.completionTokens < a.maxTokens;

  const name = await instanceName("completion", a.model);
  const handle = await ctx.writeResource("completionProbe", name, {
    model: a.model,
    latencyMs: result.latencyMs,
    httpStatus: result.httpStatus,
    finishReason: result.finishReason,
    promptTokens: result.promptTokens,
    completionTokens: result.completionTokens,
    totalTokens: result.totalTokens,
    reasoningTokens: result.reasoningTokens,
    reasoningChars,
    contentChars,
    emptyContentWithReasoning,
    contextExhausted,
    maxTokensHit,
    errorKind: result.errorKind,
    error: result.error,
    checkedAt: new Date().toISOString(),
  }, {
    tags: {
      model: a.model,
      finishReason: result.finishReason,
      emptyContentWithReasoning: String(emptyContentWithReasoning),
      contextExhausted: String(contextExhausted),
      errorKind: result.errorKind,
    },
  });

  if (result.errorKind) {
    ctx.logger.warning("completion probe against {model} failed: {kind}", {
      model: a.model,
      kind: result.errorKind,
    });
  } else {
    ctx.logger.info(
      "completion probe: finishReason={fr} contextExhausted={ce} emptyContentWithReasoning={ecwr}",
      {
        fr: result.finishReason,
        ce: contextExhausted,
        ecwr: emptyContentWithReasoning,
      },
    );
  }

  return { dataHandles: [handle] };
}

async function capabilities(
  args: z.infer<typeof CapabilitiesArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
) {
  const a = CapabilitiesArgsSchema.parse(args);
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const base = normalizeBase(g.baseUrl);
  const timeoutMs = g.timeoutSec * 1000;

  ctx.logger.info("running capability battery for {model}", {
    model: a.model,
  });

  let emitsReasoning = false;
  let honorsResponseFormat = false;
  let wrapsInCodeFences = false;
  let reasoningCheckTruncated = false;
  let formatCheckTruncated = false;
  let fenceCheckTruncated = false;
  // How many of the 3 checks actually completed. This is what lets a reader
  // -- and a rerun -- tell "the battery ran and found nothing" apart from
  // "the battery stopped partway through", which would otherwise both look
  // like the same all-false aggregate with one errorKind. Without it, a
  // transient failure on a rerun silently overwrites a previously complete,
  // genuine result with a partial one that reads identically to a battery
  // that ran clean and found every capability absent.
  let checksCompleted = 0;
  let errorKind = "";
  let error = "";
  const started = performance.now();

  // Check 1: does the model emit reasoning content on a question that
  // invites it, unprompted?
  const reasoningCheck = await chatCompletion(
    base,
    g.apiToken,
    timeoutMs,
    ctx.signal,
    {
      model: a.model,
      messages: [{ role: "user", content: "What is 17 * 24? Show your work." }],
      max_tokens: a.maxTokens,
      temperature: 0,
    },
  );

  if (!reasoningCheck.ok) {
    errorKind = reasoningCheck.errorKind;
    error = reasoningCheck.error;
  } else {
    checksCompleted = 1;
    emitsReasoning = reasoningCheck.reasoningContent.length > 0 ||
      reasoningCheck.reasoningTokens > 0;
    // A response cut off at max_tokens before finishing its answer is a
    // truncated reply, not a measurement that reasoning is absent -- without
    // this flag the two are indistinguishable in the stored result.
    reasoningCheckTruncated = reasoningCheck.finishReason === "length";

    // Check 2: does the model honour a requested structured output format?
    const formatCheck = await chatCompletion(
      base,
      g.apiToken,
      timeoutMs,
      ctx.signal,
      {
        model: a.model,
        messages: [{
          role: "user",
          content:
            'Reply with only this JSON object, nothing else: {"ok": true}',
        }],
        max_tokens: a.maxTokens,
        temperature: 0,
        response_format: { type: "json_object" },
      },
    );

    if (!formatCheck.ok) {
      errorKind = formatCheck.errorKind;
      error = formatCheck.error;
    } else {
      checksCompleted = 2;
      formatCheckTruncated = formatCheck.finishReason === "length";
      try {
        JSON.parse(formatCheck.content.trim());
        honorsResponseFormat = true;
      } catch {
        honorsResponseFormat = false;
      }

      // Check 3: does it wrap output in markdown code fences even when told
      // not to? A formatting habit, not a content failure -- recorded
      // either way, never used to fail the probe.
      const fenceCheck = await chatCompletion(
        base,
        g.apiToken,
        timeoutMs,
        ctx.signal,
        {
          model: a.model,
          messages: [{
            role: "user",
            content:
              "Reply with exactly the word OK. Do not use markdown, do not use code fences.",
          }],
          max_tokens: a.maxTokens,
          temperature: 0,
        },
      );

      if (!fenceCheck.ok) {
        errorKind = fenceCheck.errorKind;
        error = fenceCheck.error;
      } else {
        checksCompleted = 3;
        fenceCheckTruncated = fenceCheck.finishReason === "length";
        wrapsInCodeFences = fenceCheck.content.includes("```");
      }
    }
  }

  const latencyMs = Math.round(performance.now() - started);
  const name = await instanceName("capabilities", a.model);
  const handle = await ctx.writeResource("capabilityProbe", name, {
    model: a.model,
    emitsReasoning,
    honorsResponseFormat,
    wrapsInCodeFences,
    checksCompleted,
    reasoningCheckTruncated,
    formatCheckTruncated,
    fenceCheckTruncated,
    latencyMs,
    errorKind,
    error,
    checkedAt: new Date().toISOString(),
  }, {
    tags: {
      model: a.model,
      emitsReasoning: String(emitsReasoning),
      honorsResponseFormat: String(honorsResponseFormat),
      wrapsInCodeFences: String(wrapsInCodeFences),
      checksCompleted: String(checksCompleted),
      errorKind,
    },
  });

  if (errorKind) {
    ctx.logger.warning(
      "capability battery for {model} stopped after {n}/3 checks: {kind}",
      { model: a.model, n: checksCompleted, kind: errorKind },
    );
  } else {
    ctx.logger.info(
      "capability battery for {model}: reasoning={r} responseFormat={f} codeFences={c}",
      {
        model: a.model,
        r: emitsReasoning,
        f: honorsResponseFormat,
        c: wrapsInCodeFences,
      },
    );
  }

  return { dataHandles: [handle] };
}

/**
 * Operational probe model for an OpenAI-compatible inference endpoint:
 * `embedding` measures real vector dimension, `completion` runs one chat
 * completion with reasoning/context-exhaustion diagnostics, `capabilities`
 * runs a short battery against one model. See the module doc above for the
 * failure modes each method exists to catch.
 */
export const model = {
  type: "@jpisgeek/lmstudio/probe",
  version: "2026.08.23.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    embeddingProbe: {
      description:
        "Measured (never assumed) embedding vector dimension for one " +
        "model, plus whether the endpoint serves embeddings at all. A " +
        "generic error on this endpoint while chat still works is " +
        "labelled no_embedding_capability rather than a bare http_error, " +
        "and a malformed 2xx body is labelled malformed_response rather " +
        "than scored as a zero-length vector.",
      schema: EmbeddingProbeSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    completionProbe: {
      description:
        "One chat completion probe, with reasoningTokens/reasoningChars, " +
        "emptyContentWithReasoning, and a heuristic contextExhausted flag " +
        "that distinguishes a context-window stop from a genuine " +
        "max_tokens cutoff -- see the schema comment for the heuristic's " +
        "limits.",
      schema: CompletionProbeSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    capabilityProbe: {
      description:
        "A short 3-call battery against one model: unprompted reasoning, " +
        "honouring a requested response_format, and markdown code-fence " +
        "wrapping. Fencing is recorded as a habit, never scored as a " +
        "failure. checksCompleted and the per-check *Truncated flags let a " +
        "reader tell a battery that ran clean and found a capability " +
        "absent apart from one that stopped partway through or was capped " +
        "by max_tokens before it could answer -- see the schema comments.",
      schema: CapabilityProbeSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
  },

  methods: {
    embedding: {
      description:
        "POST /v1/embeddings with a short input and record the MEASURED " +
        "vector dimension plus whether the endpoint serves embeddings at " +
        "all. Never assumes dimension from the model's name or reputation. " +
        "A 401/403 throws a distinct UNAUTHORIZED error rather than being " +
        "written as data -- a bad token is a configuration fault, not a " +
        "measurement of the endpoint. Caller cancellation throws too, " +
        "rather than being recorded as a timeout.",
      arguments: EmbeddingArgsSchema,
      execute: embedding,
    },
    completion: {
      description:
        "POST /v1/chat/completions with a caller-supplied prompt. Records " +
        "latency, finish_reason, and token usage, plus reasoning-specific " +
        "and context-exhaustion diagnostics that a plain OpenAI client " +
        "would not surface. A 401/403 throws a distinct UNAUTHORIZED " +
        "error rather than being written as data, as does caller " +
        "cancellation. 429/503 responses get one bounded, Retry-After-" +
        "aware retry before being recorded.",
      arguments: CompletionArgsSchema,
      execute: completion,
    },
    capabilities: {
      description:
        "Run a short battery against one model and summarise whether it " +
        "emits reasoning, honours a requested response_format, and wraps " +
        "output in markdown code fences. A 401/403 on any battery call " +
        "throws a distinct UNAUTHORIZED error rather than being written " +
        "as data, as does caller cancellation. A battery that stops " +
        "partway through records how many of the 3 checks completed " +
        "(checksCompleted) so a partial result is never indistinguishable " +
        "from a complete one that found the remaining capabilities absent.",
      arguments: CapabilitiesArgsSchema,
      execute: capabilities,
    },
  },
};
