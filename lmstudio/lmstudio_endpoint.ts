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

/**
 * Every model id in `/v1/models` is remote-controlled text: the endpoint at
 * the far end of `baseUrl` decides what it contains. A bare `z.string()`
 * accepts a megabyte-long id and accepts `qwen<ESC>]0;PWNED<BEL>-7b`, both of
 * which then land verbatim in an `infinite`-lifetime resource, in a tag, and
 * in the log line -- and the escape sequence rewrites the terminal of whoever
 * runs `swamp data list` afterwards.
 *
 * Bounded and screened, matching the RemoteText pattern lmstudio_daemon.ts
 * already applies to `lms ps --json` output for exactly the same class of
 * string. Kept local rather than imported: each extension ships only the
 * files in its own manifest.
 */
const RemoteText = (max: number, min = 0) =>
  z
    .string()
    .min(min)
    .max(max)
    // deno-lint-ignore no-control-regex
    .refine((v) => !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(v), {
      message: "value must not contain control or line-separator characters",
    })
    // Bidi and zero-width characters reorder or hide displayed text, so two
    // distinct model identifiers can render identically to an operator.
    .refine(
      (v) => !/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(v),
      {
        message:
          "value must not contain zero-width or direction-formatting characters",
      },
    )
    // Lone surrogates survive JSON.parse as \ud800-style escapes and decode to
    // the same replacement character, which again makes distinct values look
    // identical.
    .refine((v) => {
      for (const ch of v) {
        const cp = ch.codePointAt(0)!;
        if (cp >= 0xd800 && cp <= 0xdfff) return false;
      }
      return true;
    }, { message: "value must not contain unpaired surrogate code units" });

/** Longest model id this extension will store. */
const MAX_MODEL_ID_CHARS = 256;
/**
 * A ceiling on how many model ids one `/v1/models` response may contribute.
 * A real endpoint serves tens; anything at this scale is a broken or hostile
 * server, and an `infinite`-lifetime resource is the wrong place to discover
 * that. Refused outright (MALFORMED_RESPONSE) rather than truncated: a cut
 * list stored as a measurement is a wrong answer, not a failed one.
 */
const MAX_MODEL_IDS = 1024;

const ModelsSchema = z.object({
  modelIds: z.array(RemoteText(MAX_MODEL_ID_CHARS, 1)).max(MAX_MODEL_IDS),
  modelCount: z.number(),
  syncedAt: z.string(),
});

/**
 * `authorized` and `httpStatus` are tri-state on purpose, and null is the
 * point of them.
 *
 * They used to be a plain boolean and a plain number seeded with `false` and
 * `0`. That made "the endpoint refused this token" and "nothing about
 * authorization was ever determined" the same stored record: a 500, a
 * timeout, and a refused connection all wrote `authorized: false`, which
 * reads as a positive finding about the token, and `httpStatus: 0`, which
 * reads as a status code because it is typed as one. An operator (or a
 * dashboard) chasing `authorized == false` across an `infinite`-lifetime
 * resource cannot tell those apart, and the fix for a rejected token is
 * nothing like the fix for an unreachable host -- which is the whole reason
 * this model keeps reachability and authorization in separate fields to
 * begin with.
 *
 *   authorized: true   an accepted (2xx) response came back
 *                      false  an explicit 401/403
 *                      null   never determined
 *   httpStatus: number an HTTP response actually arrived and said this
 *                      null   no HTTP response exists
 *
 * The cross-field rules below are what make the old ambiguous record
 * unrepresentable rather than merely discouraged: a writer that regresses to
 * `false`/`0` fails validation instead of quietly storing a false negative.
 */
const HealthSchema = z.object({
  reachable: z.boolean(),
  authorized: z.boolean().nullable(),
  httpStatus: z.number().nullable(),
  latencyMs: z.number(),
  /** "" | "unauthorized" | "http_error" | "unreachable" | "timeout" */
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.string(),
}).superRefine((v, ctx) => {
  // No HTTP exchange happened, so there is no status to report and nothing
  // could have accepted or refused the token.
  if (!v.reachable && (v.httpStatus !== null || v.authorized !== null)) {
    ctx.addIssue({
      code: "custom",
      message:
        "an unreachable endpoint has no HTTP status and no authorization " +
        "result: both must be null, never false/0",
      path: ["reachable"],
    });
  }
  // The converse: reachability is only ever set from a response arriving.
  if (v.reachable && v.httpStatus === null) {
    ctx.addIssue({
      code: "custom",
      message: "a reachable endpoint must record the HTTP status it returned",
      path: ["httpStatus"],
    });
  }
  // true only after an accepted response.
  if (
    v.authorized === true &&
    !(v.httpStatus !== null && v.httpStatus >= 200 && v.httpStatus <= 299)
  ) {
    ctx.addIssue({
      code: "custom",
      message: "authorized may only be true for a 2xx response",
      path: ["authorized"],
    });
  }
  // false only for an explicit refusal.
  if (v.authorized === false && v.httpStatus !== 401 && v.httpStatus !== 403) {
    ctx.addIssue({
      code: "custom",
      message:
        "authorized may only be false for an explicit 401/403; anything " +
        "else that failed left authorization undetermined (null)",
      path: ["authorized"],
    });
  }
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
 * Remove everything from a remote-controlled string that can drive a
 * terminal, hide or reorder displayed text, or decode ambiguously.
 *
 * Split out of safeRemoteText() because the order of the three passes --
 * screen, redact, clamp -- is load-bearing, and each of them now runs over
 * the whole string.
 *
 * Screening runs FIRST because redaction is a literal substring match. An
 * endpoint that echoes the token back with a zero-width space wedged into the
 * middle of it does not match the configured token, so a redact-first pass
 * left it alone -- and the zero-width strip that ran afterwards reassembled
 * the credential intact inside the stored `error`.
 */
function screenRemoteText(text: string): string {
  return text
    // deno-lint-ignore no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ")
    .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "")
    .replace(/[\ud800-\udbff](?![\udc00-\udfff])/g, "\ufffd")
    .replace(/(^|[^\ud800-\udbff])([\udc00-\udfff])/g, "$1\ufffd")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * The one cut this function cannot move is the byte cap inside
 * readBodyCapped(): the body is already severed at MAX_RESPONSE_BYTES before
 * any of this runs, and that cut can land inside an echoed token, leaving a
 * genuine prefix of the credential at the very end of the text where split()
 * cannot match it. Collapsing whitespace then pulls that tail forward, so
 * "it is 256 KiB in, nobody will ever read that far" is not an argument.
 *
 * Applied only to a read that actually hit the cap: the tail of a complete
 * body is complete, and running this unconditionally would clip real error
 * text that merely happens to end with the token's first character.
 */
function stripTrailingTokenPrefix(text: string, token: string): string {
  if (!token) return text;
  const longest = Math.min(token.length - 1, text.length);
  for (let n = longest; n > 0; n--) {
    if (token.startsWith(text.slice(text.length - n))) {
      return `${text.slice(0, text.length - n)}[REDACTED]`;
    }
  }
  return text;
}

/**
 * Strip every form of the token from already-screened text.
 *
 * The screened spelling of the token is removed as well as the configured
 * one: screening collapses whitespace and drops zero-width characters, so a
 * token containing either no longer matches its own configured spelling by
 * the time this runs.
 */
function redactAll(text: string, token: string, truncated: boolean): string {
  let out = redact(text, token);
  const screenedToken = screenRemoteText(token);
  const alsoScreened = screenedToken !== "" && screenedToken !== token;
  if (alsoScreened) out = redact(out, screenedToken);
  if (truncated) {
    out = stripTrailingTokenPrefix(out, token);
    if (alsoScreened) out = stripTrailingTokenPrefix(out, screenedToken);
  }
  return out;
}

/**
 * True when remote-controlled text carries the configured token in either of
 * the two spellings redactAll() knows about.
 *
 * The screened spelling is checked as well as the configured one for the same
 * reason redaction checks it: screenRemoteText() collapses whitespace and
 * drops zero-width characters, so a token containing either no longer matches
 * its own configured spelling once the text around it has been screened.
 */
function containsToken(text: string, token: string): boolean {
  if (!token) return false;
  if (text.includes(token)) return true;
  const screened = screenRemoteText(token);
  return screened !== "" && screened !== token && text.includes(screened);
}

/**
 * Cut screened text to `max` characters without severing a surrogate pair.
 *
 * `slice()` cuts by UTF-16 code unit, so a cut landing between the two halves
 * of an astral character leaves a lone surrogate at the end of the kept text
 * -- recreating, after the screen, exactly what screenRemoteText() replaced a
 * moment earlier, in a string this extension documents as screened. Because
 * screening already replaced every unpaired surrogate, a high surrogate at
 * the boundary is necessarily the first half of a real pair, so backing the
 * cut up by one code unit is all that is needed.
 */
function clampText(text: string, max: number): string {
  if (text.length <= max) return text;
  const boundary = text.charCodeAt(max - 1);
  const cut = boundary >= 0xd800 && boundary <= 0xdbff ? max - 1 : max;
  return `${text.slice(0, cut)}...`;
}

/**
 * Screen a remote-controlled string before it reaches a log line, a thrown
 * error, or a stored resource.
 *
 * redact() alone was not enough. It strips the bearer token and nothing else,
 * so the endpoint's own error body reached every thrown message carrying
 * whatever the far end chose to put in it: an ESC]0;...BEL sequence that
 * rewrites the terminal title of whoever runs `swamp data list` afterwards, a
 * bidi override that makes two different messages render identically, lone
 * surrogates, and an unbounded length.
 *
 * The snippet is screened and bounded rather than dropped. Replacing it with
 * a canned "HTTP 400" would make this extension undiagnosable for the exact
 * cases it exists to diagnose -- "no embedding model is currently loaded" and
 * "model ... does not exist" are the endpoint telling you what is wrong, and
 * classifyHttpError() in lmstudio_probe.ts reads that same text to separate
 * model_not_found from a generic http_error. What is removed is the ability
 * of that text to be unbounded or to drive a terminal. The residual trade --
 * an endpoint that echoes your request inside its own error body can put part
 * of it in `error` -- is stated in the README Security section rather than
 * papered over.
 *
 * The clamp happens LAST, and that ordering is the whole fix for a real leak.
 * The old shape was `redact(text.slice(0, 4096), token)`: it cut the body
 * first and searched only the cut for the token, so a token longer than 4096
 * characters echoed at the start of a response was split by the slice, no
 * longer matched `split(token)`, and rode through with its first 4096
 * characters intact -- of which the first `max` were then written into an
 * `infinite`-lifetime resource and into a thrown message. Nothing is cut here
 * until every occurrence of the credential is already gone from the complete
 * response, which readBodyCapped() has already bounded to
 * MAX_RESPONSE_BYTES.
 *
 * `truncated` reports that the read hit that byte cap -- the one cut this
 * function did not make; see stripTrailingTokenPrefix().
 */
function safeRemoteText(
  text: string,
  token: string,
  max: number,
  truncated = false,
): string {
  const safe = redactAll(screenRemoteText(text), token, truncated);
  return clampText(safe, max);
}

/**
 * Hard cap on how many bytes of any HTTP response body this model will
 * buffer. `response.text()` and `response.json()` have no bound at all: the
 * request timeout limits how long a hostile endpoint may stream, not how much
 * it may hand over in that time, so a slow multi-gigabyte body fits inside a
 * 30-second deadline and exhausts memory. Same reasoning, and the same shape,
 * as MAX_OUTPUT_BYTES in lmstudio_daemon.ts.
 */
const MAX_RESPONSE_BYTES = 256 * 1024;
/** Longest screened endpoint-body snippet that may reach an error string. */
const MAX_ERROR_SNIPPET = 200;

/**
 * A body read fails for the same three reasons a fetch does, and they must
 * stay apart for the same reason: the caller cancelled, our deadline fired,
 * or the connection died mid-body.
 */
function classifyBodyError(
  e: unknown,
  callerSignal?: AbortSignal,
): { kind: string; message: string } {
  const c = classifyFetchError(e, callerSignal);
  if (c.kind === "cancelled") {
    return {
      kind: "cancelled",
      message:
        "request was cancelled by the caller while the response body was " +
        "being read",
    };
  }
  if (c.kind === "timeout") {
    return {
      kind: "timeout",
      message: "request timed out while the response body was being read",
    };
  }
  return {
    kind: "unreachable",
    message: "connection failed while the response body was being read",
  };
}

/**
 * Read a response body under a byte cap, keeping a failed read classifiable.
 *
 * `await response.text().catch(() => "")` -- the old shape -- did two wrong
 * things at once. It let an unbounded body through, and it turned a
 * cancellation or a timeout that landed after the response headers into an
 * empty string, which then read as "the endpoint returned HTTP 500 with an
 * empty body" or as a malformed JSON payload. A cancelled run recorded as an
 * observation about the endpoint is precisely the ambiguity this extension
 * exists to prevent.
 */
async function readBodyCapped(
  response: Response,
  callerSignal?: AbortSignal,
): Promise<
  { text: string; truncated: boolean; failed?: undefined } | {
    text?: undefined;
    truncated?: undefined;
    failed: { kind: string; message: string };
  }
> {
  const body = response.body;
  if (!body) return { text: "", truncated: false };
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      if (total + value.byteLength >= MAX_RESPONSE_BYTES) {
        chunks.push(value.subarray(0, MAX_RESPONSE_BYTES - total));
        total = MAX_RESPONSE_BYTES;
        truncated = true;
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } catch (e) {
    return { failed: classifyBodyError(e, callerSignal) };
  } finally {
    // Cancel rather than drain: draining a runaway body to be polite is the
    // same unbounded read the cap exists to prevent.
    await reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    buf.set(chunk, at);
    at += chunk.byteLength;
  }
  return { text: new TextDecoder().decode(buf), truncated };
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

/**
 * Pull the model ids out of a `/v1/models` payload, or fail closed.
 *
 * Two things this used to get wrong, both of which the README asserted were
 * already handled:
 *
 * 1. Every throw here was untagged ("Unexpected /models response shape --",
 *    "invalid model entry"), so a 2xx body that is not an OpenAI envelope
 *    escaped the documented UNAUTHORIZED / UNREACHABLE / TIMEOUT /
 *    HTTP_ERROR / MALFORMED_RESPONSE / CANCELLED taxonomy the Caveats
 *    section promises. A caller matching on that taxonomy silently missed
 *    the case.
 * 2. Ids were accepted as bare strings of any length and any content, then
 *    written to an `infinite`-lifetime resource, put in a tag, and logged.
 *    A hostile or broken endpoint could park a megabyte of terminal escape
 *    sequences there permanently. Screened through RemoteText, and the list
 *    length is capped, both refused outright rather than truncated: a cut
 *    list stored as a measurement is a wrong answer, not a failed one.
 */
function extractModelIds(
  payload: unknown,
  url: string,
  token: string,
): string[] {
  const shapeError = (why: string) =>
    new Error(
      `MALFORMED_RESPONSE: ${url} returned a 2xx body that is not an ` +
        `OpenAI-style { data: [{ id, ... }, ...] } envelope -- ${why}`,
    );

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw shapeError("the body is not a JSON object");
  }
  const data = (payload as Record<string, unknown>).data;
  if (!Array.isArray(data)) {
    throw shapeError("no data[] array");
  }
  if (data.length > MAX_MODEL_IDS) {
    throw shapeError(
      `data[] holds ${data.length} entries, more than the ${MAX_MODEL_IDS} ` +
        "this extension will store",
    );
  }
  const ids: string[] = [];
  for (const entry of data) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw shapeError("a data[] entry is not an object");
    }
    const id = (entry as Record<string, unknown>).id;
    if (typeof id !== "string" || !id) {
      throw shapeError("a data[] entry is missing a string id");
    }
    const screened = RemoteText(MAX_MODEL_ID_CHARS, 1).safeParse(id);
    if (!screened.success) {
      // Never echo the offending id: it is exactly the value that failed the
      // control/bidi screen, so putting it in the error message would carry
      // the escape sequence into the log this error is bound for.
      throw shapeError(
        `a data[] entry has an unusable model id (${
          screened.error.issues[0]?.message ?? "rejected"
        })`,
      );
    }
    // The screen above says nothing about a well-formed id that happens to BE
    // the credential. `/v1/models` is answered by the far end, so a hostile or
    // compromised endpoint can reply `{ data: [{ id: "<your bearer token>" }] }`
    // and the token is then written verbatim into an `infinite`-lifetime
    // resource, put in a tag, and logged -- the one path in this file where
    // remote text is stored without going through redactAll() first, because
    // an id is a measurement rather than a message. Refused, not redacted:
    // "[REDACTED]" stored as a served model id is a wrong answer, and the
    // whole list is suspect once the endpoint is playing this game.
    if (containsToken(screened.data, token)) {
      // The offending id is never echoed: it is the credential.
      throw shapeError(
        "a data[] entry returns the configured API token as a model id",
      );
    }
    ids.push(screened.data);
  }
  return ids;
}

async function models(
  _args: z.infer<typeof ModelsArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const base = normalizeBase(g.baseUrl);
  const timeoutMs = g.timeoutSec * 1000;
  const url = safeUrlForLog(`${base}/models`);

  ctx.logger.info("listing models from {url}", { url });

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
      `${c.kind.toUpperCase()}: ${c.message} (${url})`,
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
      `UNAUTHORIZED: ${url} rejected the API token ` +
        `(HTTP ${response.status}). ` +
        "A wrong token behaves exactly like a missing one on this endpoint -- " +
        "verify the token value itself, not just that one was sent.",
    );
  }

  if (!response.ok) {
    const body = await readBodyCapped(response, ctx.signal);
    if (body.failed) {
      // A cancellation or timeout that landed after the headers arrived is
      // not "the endpoint returned HTTP 500 with an empty body", which is
      // what the old `.catch(() => "")` turned it into. Each keeps its own
      // tag from the documented taxonomy.
      throw new Error(
        `${body.failed.kind.toUpperCase()}: ${body.failed.message} (${url})`,
      );
    }
    // Redaction and screening point: the token is stripped, and the
    // endpoint's own body -- which could in principle echo request headers
    // back on a misconfigured proxy's error page, or carry terminal control
    // sequences -- is bounded and screened before it reaches an error.
    const safeBody = safeRemoteText(
      body.text,
      g.apiToken,
      MAX_ERROR_SNIPPET,
      body.truncated,
    );
    throw new Error(
      `HTTP_ERROR: ${url} returned HTTP ${response.status}. ${safeBody}`,
    );
  }

  const body = await readBodyCapped(response, ctx.signal);
  if (body.failed) {
    throw new Error(
      `${body.failed.kind.toUpperCase()}: ${body.failed.message} (${url})`,
    );
  }
  if (body.truncated) {
    // Parsing the first MAX_RESPONSE_BYTES of a longer body would either
    // fail as broken JSON or, worse, succeed on a prefix that happens to be
    // valid and be stored as though it were the whole model list.
    throw new Error(
      `MALFORMED_RESPONSE: ${url} returned HTTP ${response.status} with a ` +
        `body over the ${MAX_RESPONSE_BYTES}-byte cap this extension reads`,
    );
  }

  let payload: unknown;
  try {
    payload = JSON.parse(body.text);
  } catch {
    // An unannotated JSON.parse failure here would surface as a bare
    // "Unexpected token < in JSON at position 0" with no indication of what
    // was being fetched or that the HTTP status was actually a 2xx --
    // annotated so the operator knows the endpoint claimed success but sent
    // a body that isn't the OpenAI-style envelope this extension expects.
    // The parser's own message is dropped rather than included: V8 embeds a
    // snippet of the offending body in it, which would route remote text
    // around the screening every other body path goes through.
    throw new Error(
      `MALFORMED_RESPONSE: ${url} returned HTTP ${response.status} ` +
        "but the body was not valid JSON",
    );
  }

  const ids = extractModelIds(payload, url, g.apiToken);

  // Cancellation that landed while the body was being parsed is the caller
  // pulling the plug, not a measurement. Checked before the write so a
  // cancelled run never leaves a resource behind claiming it observed the
  // endpoint.
  if (ctx.signal?.aborted) {
    throw new Error(
      "CANCELLED: request was cancelled by the caller before the model list " +
        "could be recorded",
    );
  }

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
  // Seeded null, not false/0: before the request has been made, nothing about
  // authorization has been determined and no HTTP status exists. `false` here
  // was a claim the endpoint rejected the token, made before the endpoint had
  // been asked anything -- and every path that never reached a 401/403 (a
  // 500, a timeout, a refused connection) shipped that claim to an
  // infinite-lifetime resource unchanged. See HealthSchema.
  let authorized: boolean | null = null;
  let httpStatus: number | null = null;
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
      // The only place `false` is earned: the endpoint was asked and said no.
      authorized = false;
      errorKind = "unauthorized";
      error = "endpoint reachable but rejected the API token";
    } else if (!response.ok) {
      // A 500, a 404, a gateway's 502 -- the endpoint never got as far as
      // ruling on the token, so authorization stays null. Recording `false`
      // here (the old behaviour) was a fabricated finding about the
      // credential in a resource that is never garbage-collected.
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

  // The catch above only sees a cancellation that fired while fetch() was
  // still in flight. Once the response headers have arrived fetch() resolves
  // normally, so a caller who cancelled a millisecond later fell straight
  // through to the write below and left a health record -- reachable, a
  // status, a latency -- for a run that was abandoned. Same rule as the
  // catch: cancellation is the caller pulling the plug, never an observation
  // about the endpoint, so it throws rather than being written as data.
  if (ctx.signal?.aborted) {
    throw new Error(
      "CANCELLED: request was cancelled by the caller before the health " +
        "check could be recorded",
    );
  }

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
      // Tags are strings, so the tri-state has to be spelled out rather than
      // stringified: `String(null)` is "null", which reads as a value someone
      // set. A tag search for authorized=false must return only endpoints
      // that actually refused the token.
      authorized: authorized === null ? "unknown" : String(authorized),
      errorKind,
    },
  });

  ctx.logger.info(
    "health: reachable={reachable} authorized={authorized} status={status} latency={ms}ms",
    {
      reachable,
      authorized: authorized === null ? "unknown" : String(authorized),
      status: httpStatus === null ? "none" : String(httpStatus),
      ms: latencyMs,
    },
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
  version: "2026.09.05.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [{
    toVersion: "2026.08.25.1",
    description: "Tighten endpoint validation with no argument schema changes",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.09.05.1",
    description:
      "Security hardening without renaming arguments or changing destinations; existing values are preserved and must pass current validation",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }],

  resources: {
    models: {
      description:
        "Every model id currently served by /v1/models, plus a count. A " +
        "401/403 on this call is thrown as a distinct UNAUTHORIZED error " +
        "rather than written as data -- a bad token is a config problem, " +
        "not an operational fact worth recording as a normal result. Model " +
        "ids are remote-controlled text, so they are length-bounded and " +
        "screened for control, bidi, and zero-width characters, and an " +
        "oversized list or an unscreenable id is refused as " +
        "MALFORMED_RESPONSE rather than stored.",
      schema: ModelsSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    health: {
      description:
        "Reachability and auth recorded independently, with HTTP status and " +
        "latency separate, so 'host is down' and 'host is up but rejects " +
        "the token' never collapse into one generic failure. `authorized` " +
        "is true only after a 2xx, false only for an explicit 401/403, and " +
        "null whenever authorization was never determined -- a 500, a " +
        "timeout, or a refused connection leaves it null rather than " +
        "claiming the token was rejected. `httpStatus` is null when no HTTP " +
        "response arrived at all, never 0. An unreachable, unauthorized, or " +
        "slow endpoint is recorded as data, not thrown -- the one exception " +
        "is caller cancellation, which throws rather than being written as " +
        "a misleading 'timeout' observation.",
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
