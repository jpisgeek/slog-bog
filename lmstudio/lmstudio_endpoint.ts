/**
 * Identity and reachability of an OpenAI-compatible inference endpoint
 * (LM Studio, or anything else that speaks the same `/v1` surface).
 *
 * Deliberately generic: no vendor-specific defaults, no assumed local
 * network. This extension is written for the public swamp registry, so
 * `baseUrl` is required config with no default -- point it at whatever
 * gateway, tunnel, or reverse proxy fronts the real inference host. Do not
 * add a same-machine or private-network default here even for convenience.
 * A registry-published extension with a private default is a footgun for
 * every consumer who is not on this network, and it fails the publish-time
 * boundary check.
 *
 * `models` and `health` answer two different operator questions and are kept
 * separate on purpose:
 *   models = what is actually loaded right now, and did the token work.
 *   health = is the endpoint even reachable, independent of what it serves.
 * A host that is up but rejects the token, and a host that is simply down,
 * require different fixes and must not collapse into one "failed" bucket.
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
      if (v.includes("?") || v.includes("#")) return false;
      try {
        const u = new URL(v);
        // http(s) only, and no embedded credentials: baseUrl is logged and can
        // appear in stored error text, so `https://user:pass@host` would leak.
        // The only credential is apiToken.
        return (u.protocol === "http:" || u.protocol === "https:") &&
          u.username === "" && u.password === "" && u.search === "" &&
          u.hash === "";
      } catch {
        return false;
      }
    }, {
      message:
        "baseUrl must be a valid http(s) URL with no userinfo, query, or " +
        "fragment; pass the token via apiToken.",
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

const ModelsArgsSchema = z.object({});
const HealthArgsSchema = z.object({});

const ModelsSchema = z.object({
  modelIds: z.array(z.string()),
  modelCount: z.number(),
  syncedAt: z.string(),
});

const HealthSchema = z.object({
  reachable: z.boolean(),
  authorized: z.boolean(),
  httpStatus: z.number(),
  latencyMs: z.number(),
  /** "" | "unauthorized" | "http_error" | "unreachable" | "timeout" */
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.string(),
});

function normalizeBase(raw: string): string {
  return raw.replace(/\/+$/, "");
}

/** Strip the API token from any string before it can land in stored data. */
function redact(text: string, token: string): string {
  if (!token) return text;
  return text.split(token).join("[REDACTED]");
}

/**
 * Strip userinfo and query string before a URL is safe to log. Either can
 * carry credentials (basic-auth userinfo, an API key as a query param on a
 * gateway/reverse proxy) that the token-only redact() pass would never catch,
 * since it only knows about the bearer token.
 */
function safeUrlForLog(raw: string): string {
  try {
    const u = new URL(raw);
    u.username = "";
    u.password = "";
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch {
    return "[unparseable URL]";
  }
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
    message: "could not reach endpoint",
  };
}

function extractModelIds(payload: unknown): string[] {
  if (payload && typeof payload === "object") {
    const data = (payload as Record<string, unknown>).data;
    if (Array.isArray(data)) {
      const ids: string[] = [];
      for (const entry of data) {
        if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
          throw new Error("invalid model entry");
        }
        const id = (entry as Record<string, unknown>).id;
        if (typeof id !== "string" || !id) {
          throw new Error("model entry is missing a string id");
        }
        ids.push(id);
      }
      return ids;
    }
  }
  throw new Error(
    "Unexpected /models response shape -- expected an OpenAI-style " +
      "{ data: [{ id, ... }, ...] } envelope.",
  );
}

async function models(
  _args: z.infer<typeof ModelsArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const base = normalizeBase(g.baseUrl);
  const timeoutMs = g.timeoutSec * 1000;

  ctx.logger.info("listing models from {url}", {
    url: safeUrlForLog(`${base}/models`),
  });

  let response: Response;
  try {
    response = await fetch(`${base}/models`, {
      redirect: "error",
      headers: {
        Authorization: `Bearer ${g.apiToken}`,
        Accept: "application/json",
      },
      signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(timeoutMs)]),
    });
  } catch (e) {
    const c = classifyFetchError(e, ctx.signal);
    throw new Error(
      `${c.kind.toUpperCase()}: ${c.message} (${
        safeUrlForLog(`${base}/models`)
      })`,
    );
  }

  // Auth is validated, not just present: a wrong token returns 401 exactly
  // like a missing one on OpenAI-compatible servers. Surfaced as a distinct,
  // named failure rather than falling through to the generic HTTP-error
  // branch below, because "bad token" and "endpoint broken" call for
  // different operator actions.
  if (response.status === 401 || response.status === 403) {
    // Drain the body before throwing so the underlying connection can be
    // reused instead of held open until GC.
    await response.body?.cancel().catch(() => {});
    throw new Error(
      `UNAUTHORIZED: ${
        safeUrlForLog(`${base}/models`)
      } rejected the API token (HTTP ${response.status}). ` +
        "A wrong token behaves exactly like a missing one on this endpoint -- " +
        "verify the token value itself, not just that one was sent.",
    );
  }

  if (!response.ok) {
    const bodyText = await response.text().catch(() => "");
    // Redaction point: strip the token before any response body -- which
    // could in principle echo request headers back on a misconfigured
    // proxy's error page -- reaches an error message.
    const safeBody = redact(bodyText, g.apiToken).slice(0, 200);
    throw new Error(
      `HTTP_ERROR: ${
        safeUrlForLog(`${base}/models`)
      } returned HTTP ${response.status}. ${safeBody}`,
    );
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    // An unannotated JSON.parse failure here would surface as a bare
    // "Unexpected token < in JSON at position 0" with no indication of what
    // was being fetched or that the HTTP status was actually a 2xx --
    // annotated so the operator knows the endpoint claimed success but sent
    // a body that isn't the OpenAI-style envelope this extension expects.
    throw new Error(
      `MALFORMED_RESPONSE: ${
        safeUrlForLog(`${base}/models`)
      } returned HTTP ${response.status} ` +
        "but the body was not valid JSON",
    );
  }

  const ids = extractModelIds(payload);

  const handle = await ctx.writeResource("models", "models", {
    modelIds: ids,
    modelCount: ids.length,
    syncedAt: new Date().toISOString(),
  }, { tags: { modelCount: String(ids.length) } });

  ctx.logger.info("{n} model(s) served", { n: ids.length });

  return { dataHandles: [handle] };
}

async function health(
  _args: z.infer<typeof HealthArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const base = normalizeBase(g.baseUrl);
  const timeoutMs = g.timeoutSec * 1000;

  ctx.logger.info("checking health of {url}", {
    url: safeUrlForLog(`${base}/models`),
  });

  let reachable = false;
  let authorized = false;
  let httpStatus = 0;
  let errorKind = "";
  let error = "";

  const started = performance.now();
  try {
    // /models doubles as the health probe: it is cheap, and it exercises
    // auth the same way every other call does.
    const response = await fetch(`${base}/models`, {
      redirect: "error",
      headers: {
        Authorization: `Bearer ${g.apiToken}`,
        Accept: "application/json",
      },
      signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(timeoutMs)]),
    });
    // Getting any HTTP response at all -- even a 401 or 500 -- means the
    // host is reachable. Reachability and authorization are recorded
    // separately so "down" and "up but rejecting us" never look the same.
    reachable = true;
    httpStatus = response.status;
    if (response.status === 401 || response.status === 403) {
      errorKind = "unauthorized";
      error = "endpoint reachable but rejected the API token";
    } else if (!response.ok) {
      errorKind = "http_error";
      error = `endpoint returned HTTP ${response.status}`;
    } else {
      authorized = true;
    }
    // health() only needs the status line. An unconsumed body on any of the
    // branches above delays connection reuse and can retain the response
    // until garbage collection -- drained here regardless of which branch
    // ran.
    await response.body?.cancel().catch(() => {});
  } catch (e) {
    const c = classifyFetchError(e, ctx.signal);
    // Cancellation is not an observation about the endpoint -- it is the
    // caller pulling the plug. Recording it as errorKind "timeout" (the old
    // behaviour) would make a cancelled run and a genuinely slow endpoint
    // produce identical stored evidence, so it is rethrown instead of
    // written as data. Every other failure here -- unreachable, timeout,
    // http_error -- is a normal state for a homelab/dev endpoint and stays
    // non-throwing.
    if (c.kind === "cancelled") {
      throw new Error(`CANCELLED: ${c.message}`);
    }
    errorKind = c.kind;
    error = c.message;
  }
  const latencyMs = Math.round(performance.now() - started);

  const handle = await ctx.writeResource("health", "health", {
    reachable,
    authorized,
    httpStatus,
    latencyMs,
    errorKind,
    error,
    checkedAt: new Date().toISOString(),
  }, {
    tags: {
      reachable: String(reachable),
      authorized: String(authorized),
      errorKind,
    },
  });

  ctx.logger.info(
    "health: reachable={reachable} authorized={authorized} status={status} latency={ms}ms",
    { reachable, authorized, status: httpStatus, ms: latencyMs },
  );

  return { dataHandles: [handle] };
}

/**
 * Identity and reachability model for an OpenAI-compatible inference
 * endpoint: `models` lists what is actually loaded and validates the token,
 * `health` checks reachability independent of what the endpoint serves. See
 * the module doc above for why the two are kept separate.
 */
export const model = {
  type: "@jpisgeek/lmstudio/endpoint",
  version: "2026.08.25.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [{
    toVersion: "2026.08.25.1",
    description: "Tighten endpoint validation with no argument schema changes",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }],

  resources: {
    models: {
      description:
        "Every model id currently served by /v1/models, plus a count. A " +
        "401/403 on this call is thrown as a distinct UNAUTHORIZED error " +
        "rather than written as data -- a bad token is a config problem, " +
        "not an operational fact worth recording as a normal result.",
      schema: ModelsSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    health: {
      description:
        "Reachability and auth as two independent booleans, with HTTP " +
        "status and latency recorded separately, so 'host is down' and " +
        "'host is up but rejects the token' never collapse into one " +
        "generic failure. An unreachable, unauthorized, or slow endpoint is " +
        "recorded as data, not thrown -- the one exception is caller " +
        "cancellation, which throws rather than being written as a " +
        "misleading 'timeout' observation.",
      schema: HealthSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  methods: {
    models: {
      description:
        "GET /v1/models and record every served model id and a count. " +
        "A wrong token surfaces as a distinct UNAUTHORIZED error, not a " +
        "generic failure -- an OpenAI-compatible 401 looks identical " +
        "whether the token is wrong or absent.",
      arguments: ModelsArgsSchema,
      execute: models,
    },
    health: {
      description:
        "Reachability plus auth check against /v1/models, recording HTTP " +
        "status and latency separately so 'unreachable' and 'unauthorized' " +
        "are distinguishable. Writes a result for any endpoint-side " +
        "outcome; throws only if the caller cancels the run.",
      arguments: HealthArgsSchema,
      execute: health,
    },
  },
};
