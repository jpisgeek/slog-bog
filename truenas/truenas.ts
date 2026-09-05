/**
 * TrueNAS SCALE inventory and health, over JSON-RPC 2.0 on a WebSocket.
 *
 * Built in-house rather than pulling a community extension: this model holds a
 * TrueNAS API key at runtime, and the decision was to keep that inside code we
 * control. It is deliberately narrow. Read-only discovery of the things a
 * homelab baseline actually needs. It does not manage datasets, shares, or
 * services.
 *
 * Speaks JSON-RPC 2.0 over WebSocket at /api/current. It originally used REST
 * v2.0, but TrueNAS raised a RESTAPIUsage alert -- triggered by this very model
 * -- warning that the REST API is removed in 26.04. Ported 2026-08-21. One
 * connection is opened per discover: authenticate once with the API key, issue
 * every query over it, close.
 *
 * Verified against TrueNAS SCALE 25.10.6 (Goldeye).
 *
 * If this fails with "tcp connect error" / "No route to host" from a macOS
 * scheduler while the same call works from a shell, suspect macOS Local
 * Network privacy rather than anything in this file: same-subnet access is
 * gated, cross-subnet and internet access is not, and a launchd-spawned
 * runtime does not inherit a Terminal's grant.
 *
 * Certificates are collected because of a real finding: TrueNAS raised a
 * CertificateIsExpiring alert, it was dismissed in the UI, and the certificate
 * still did not renew. Dismissed alerts are invisible inside TrueNAS but the
 * underlying expiry keeps advancing, so expiry is tracked here independently
 * of alert state.
 */
import { z } from "npm:zod@4";
import WsWebSocket from "npm:ws@8.21.0";

/**
 * Shortest `apiKey` this model will accept, and the same floor redactKey()
 * refuses to match below. The two numbers are one constant on purpose: while
 * the argument schema accepted `.min(1)` and redaction skipped anything under
 * eight characters, there was a band of accepted keys that could never be
 * redacted -- a hostile or merely chatty host could echo such a key back in
 * an error message and this model would write it straight to a swamp log,
 * while the README promised the key is never logged. Closing the band at the
 * argument boundary is the fix: a value too short to be redactable is too
 * short to open a connection with.
 */
const MIN_API_KEY_CHARS = 8;

/**
 * Longest `apiKey` this model will accept, and the reason the schema also
 * pins the key to printable non-space ASCII.
 *
 * Both bounds exist for redaction, not for tidiness. redactKey() strips the
 * key as a literal substring, so anything that can make the configured key
 * and its echoed form differ is a hole:
 *
 *   - No maximum meant a key could be longer than the text safeRemoteText()
 *     was willing to look at, so the echo of it was a prefix the literal
 *     match never found. TrueNAS key material is 64 characters; 128 leaves
 *     bounded room for its numeric ID and hyphen prefix.
 *   - No charset meant a key could itself contain a zero-width or bidi
 *     character. screenRemote() deletes those, so the SCREENED key could be
 *     shorter than MIN_API_KEY_CHARS -- and redactKey() skips a key that
 *     short, while the raw literal no longer appears in the screened text.
 *     A key of "abc<ZWSP>de<ZWSP>fg" passed the length floor and was then
 *     redactable in neither form.
 *
 * With the charset pinned, screenRemote(apiKey) === apiKey for every key this
 * model accepts, so there is no second form for redaction to miss.
 */
const MAX_API_KEY_CHARS = 128;
/** TrueNAS raw keys are `{positive id}-{64 alphanumeric characters}`. */
const TRUE_NAS_API_KEY_PATTERN = /^[1-9][0-9]*-[A-Za-z0-9]{64}$/;

const GlobalArgsSchema = z.object({
  baseUrl: z
    .string()
    .min(1)
    .meta({ sensitive: true })
    .describe(
      "Base URL of the TrueNAS host, e.g. https://nas.example.com. Prefer " +
        "the DNS name over an IP so TLS verification actually succeeds. The " +
        "WebSocket URL is rebuilt from this (https -> wss, /api/current). " +
        "A non-default port is allowed; credentials, paths, query strings " +
        "and fragments are rejected.",
    ),
  apiKey: z
    .string()
    .min(
      MIN_API_KEY_CHARS,
      {
        message:
          `apiKey must be at least ${MIN_API_KEY_CHARS} characters. Shorter ` +
          `values are refused before a socket opens rather than accepted: ` +
          `redactKey() cannot strip a value that short out of remote text ` +
          `without shredding every diagnostic message, so a short key would ` +
          `be a credential this model is unable to keep out of its own logs. ` +
          `A TrueNAS raw key includes 64 characters of key material; a ` +
          `one-character value is ` +
          `a misconfigured vault lookup, not a credential worth connecting ` +
          `with.`,
      },
    )
    .max(MAX_API_KEY_CHARS, {
      message:
        `apiKey must be at most ${MAX_API_KEY_CHARS} characters. TrueNAS ` +
        `raw keys carry exactly 64 characters of key material; a longer value ` +
        `is a misconfigured lookup, ` +
        `and an unbounded one cannot be guaranteed redactable out of the ` +
        `remote text this model logs.`,
    })
    .regex(/^[\x21-\x7e]+$/, {
      message:
        `apiKey must be printable ASCII with no spaces. A key containing a ` +
        `zero-width, bidi or control character is altered by the screening ` +
        `that runs over remote text, so neither its raw nor its screened ` +
        `form is reliably redactable -- the key would be a credential this ` +
        `model cannot keep out of its own logs.`,
    })
    .regex(TRUE_NAS_API_KEY_PATTERN, {
      message:
        `apiKey must use TrueNAS raw-key format: a positive numeric key ID, ` +
        `a hyphen, and exactly 64 alphanumeric key-material characters. ` +
        `Other spellings can collide with numeric, percentage, or date ` +
        `values that do not cross the string-redaction boundary.`,
    })
    .meta({ sensitive: true })
    .describe(
      "TrueNAS API key; source it from a vault expression. Must be " +
        `${MIN_API_KEY_CHARS}-${MAX_API_KEY_CHARS} characters of printable ` +
        "ASCII using TrueNAS raw-key format `{id}-{64 alphanumerics}` -- " +
        "other values are rejected before connecting because they can " +
        "collide with non-string remote primitives.",
    ),
  allowInsecureHttp: z
    .boolean()
    .default(false)
    .describe(
      "Allow baseUrl to use http://, which becomes an unencrypted ws:// " +
        "connection carrying the API key in cleartext on every call. Off " +
        "by default; only set this for a trusted loopback/VPN path where " +
        "TLS genuinely cannot be terminated on the TrueNAS host.",
    ),
  allowedHosts: z
    .array(z.string().min(1))
    .default([])
    .meta({ sensitive: true })
    .describe(
      "Optional pin: exact hosts the API key may be sent to, e.g. " +
        "['nas.example.com', 'nas.example.com:8443']. When non-empty the " +
        "host derived from baseUrl must match one entry exactly or the run " +
        "fails before a socket is opened. Entries are bare hosts or " +
        "host:port; a bare host pins only the scheme's default port, so every " +
        "non-default port must be explicit. No scheme, path or wildcard. Set " +
        "this whenever baseUrl comes from anywhere but a literal in your " +
        "workflow file.",
    ),
  timeoutSec: z.number().int().positive().default(20),
  certWarnDays: z
    .number()
    .int()
    .positive()
    .default(30)
    .describe("Certificates expiring within this many days are flagged"),
});

/** Longest remote string that may reach a log line or an error message. */
const MAX_REMOTE_CHARS = 200;

/**
 * Longest remote string that may be *stored* in a resource field. Alert
 * `formatted` is the one field here whose whole value is remote prose, and
 * these resources have `lifetime: "infinite"`, so an unbounded value is
 * unbounded forever. TrueNAS alert text runs to a line or two; 4,096 Unicode
 * code points keeps every real alert intact and refuses pathological input.
 */
const MAX_STORED_REMOTE_CHARS = 4096;

/**
 * Ceilings on the *raw* payload, applied before a message is assembled or
 * parsed and before a single byte of it is slugged, hashed, counted or
 * written.
 *
 * Bounding remote text at the point it reaches a log or a field (safe()) was
 * never the whole job, because several things happen to a raw string BEFORE
 * that: it is length-prefixed into an identity tuple, SHA-256'd, slugged, and
 * `loadavg` is written as-is with no safe() anywhere near it. A host that
 * answers `disk.query` with 200,000 rows, each carrying a 50 MB `identifier`,
 * costs this model a hash over every one of them and a datastore record per
 * row with `lifetime: "infinite"` -- the truncation that follows is far too
 * late to matter. Nothing here bounded that; `z.array(RawPoolSchema)` accepts
 * an array of any length and `z.string()` a string of any size.
 *
 * The numbers are set where a real TrueNAS cannot reach them and a hostile
 * one is stopped early: a 4 MB JSON message is orders of magnitude above any
 * real `alert.list`; 5,000 rows is more disks than a SCALE box supports; a
 * kilobyte is ~16x the longest real disk identifier. Alert prose gets its own,
 * larger ceiling because it is genuinely free text and is truncated (not
 * rejected) for storage -- refusing a whole run over a wordy alert would be
 * the model failing at the job it exists to do.
 */
const MAX_FRAME_BYTES = 4_000_000;
const MAX_ROWS = 5_000;
const MAX_RAW_FIELD_CHARS = 1_024;
const MAX_RAW_TEXT_CHARS = 65_536;
/** TrueNAS reports three load averages. Eight is slack, not a guess. */
const MAX_LOADAVG_ENTRIES = 8;
const MAX_REMOTE_BYTES = Number.MAX_SAFE_INTEGER;
const MAX_REMOTE_CORES = 1_000_000;
const MAX_REMOTE_UPTIME_SECONDS = 100 * 366 * 24 * 60 * 60;
const MAX_REMOTE_LOAD_AVERAGE = 1_000_000;

/**
 * Reject an oversized raw collection before a schema can visit its elements.
 * A `.max()` on `z.array()` is still retained as a contract backstop, but Zod
 * validates elements while collecting issues; it is therefore too late to be
 * the CPU/memory boundary for a hostile over-limit response.
 */
function assertRawArrayLength(
  value: unknown,
  label: string,
  max: number,
): void {
  if (Array.isArray(value) && value.length > max) {
    throw new Error(
      `TrueNAS ${label} returned more than ${max} entries; refused before ` +
        "element validation",
    );
  }
}

/** A remote number must be meaningful before it becomes a known reading. */
const boundedNonnegativeNumber = (
  field: string,
  max: number,
  integer = false,
) =>
  z.number().refine(
    (n) =>
      Number.isFinite(n) && n >= 0 && n <= max &&
      (!integer || Number.isSafeInteger(n)),
    {
      message:
        `${field} must be a finite, nonnegative${integer ? " integer" : ""} ` +
        `no greater than ${max}`,
    },
  );

/**
 * Strip the configured API key out of any remote-supplied text.
 *
 * This is defensive, not theoretical: `auth.login_with_api_key` takes the key
 * as its ONLY argument, and middlewared's own error prose habitually echoes
 * the argument that failed validation. Nothing in the JSON-RPC contract stops
 * a host -- a real one with a bad day, or one an operator was misdirected to
 * -- from putting the key back in `error.message`, which this model then puts
 * in a thrown Error that swamp logs. The README claims the key is never
 * logged; before this, that claim depended on the far end's discretion.
 *
 * The length floor matters. A one- or two-character `apiKey` (a test fixture,
 * a misconfigured vault lookup returning a stray char) would otherwise match
 * everywhere and shred every message into [REDACTED]. TrueNAS raw key material
 * is 64 characters; anything under 8 cannot be one, and mangling diagnostics
 * to protect a value that is not a credential is a worse trade.
 *
 * The floor is no longer a hole, though, which it was: GlobalArgsSchema now
 * refuses an `apiKey` shorter than MIN_API_KEY_CHARS, so no key this model
 * ever puts on a socket can land in the skipped band. The guard stays because
 * this function is also called with the *screened* form of the key (see
 * safeRemoteText), which screening can shorten, and `"".split("")` would
 * otherwise redact every character of every message.
 */
function redactKey(text: string, apiKey: string): string {
  if (apiKey.length < MIN_API_KEY_CHARS) return text;
  return text.split(apiKey).join("[REDACTED]");
}

/**
 * Neutralise the characters that let remote text act on whatever renders it.
 *
 * Remote strings from this socket do not only reach errors and logs; alert
 * `formatted`, `klass` and `level`, disk models and serials, pool names and
 * certificate CNs are all written into stored resources and, for several of
 * them, into resource TAGS -- which are how a workflow selects records. An
 * ESC]0;...BEL in an alert message rewrites the terminal title of whoever
 * runs `swamp data list`; a bidi override makes two different pool names
 * render identically to the person reading the gate output; a lone surrogate
 * is not valid UTF-8 and can fail a serializer downstream. None of that is
 * about the *length* of the text, which is why bounding it was not enough.
 */
function screenRemote(s: string): string {
  return s
    // Delete rather than replace: an inserted control/format character must
    // normalize back to the key it split so the following redaction sees it.
    .replace(
      /[\p{Cc}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu,
      "",
    )
    .replace(/[\ud800-\udbff](?![\udc00-\udfff])/g, "�")
    .replace(/(^|[^\ud800-\udbff])([\udc00-\udfff])/g, "$1�")
    .replace(/ {2,}/g, " ")
    .trim();
}

/** Every spelling of the API key that remote JSON prose can echo. */
function apiKeyForms(apiKey: string): string[] {
  return [
    ...new Set(
      [apiKey, screenRemote(apiKey)].flatMap((key) => [
        key,
        JSON.stringify(key).slice(1, -1),
      ]),
    ),
  ].filter((key) => key.length >= MIN_API_KEY_CHARS);
}

/** Escape one literal character for a dynamically-built regular expression. */
function regexLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Match one key character in either literal or valid JSON-escaped form. */
function jsonKeyCharacterPattern(character: string): string {
  const caseVariants = /[a-z]/.test(character)
    ? [character, character.toUpperCase()]
    : /[A-Z]/.test(character)
    ? [character, character.toLowerCase()]
    : [character];
  const forms = new Set<string>();
  for (const variant of caseVariants) {
    // Prefer the longer JSON short escapes before their literal character.
    if (variant === "\\") forms.add("\\\\\\\\");
    if (variant === '"') forms.add('\\\\"');
    if (variant === "/") forms.add("\\\\/");
    forms.add(regexLiteral(variant));

    const hex = variant.charCodeAt(0).toString(16).padStart(4, "0")
      .split("")
      .map((digit) =>
        /[a-f]/.test(digit) ? `[${digit}${digit.toUpperCase()}]` : digit
      )
      .join("");
    forms.add(`\\\\u${hex}`);
  }
  return `(?:${[...forms].join("|")})`;
}

/**
 * Match a key even when an arbitrary subset of its characters uses JSON
 * escapes. Enumerating strings cannot cover that space: a 64-character key
 * has 2^64 literal/`\\uXXXX` combinations. The key schema restricts input to
 * printable ASCII, so one exact pattern per character covers every valid JSON
 * spelling without decoding unrelated remote text. Each ASCII letter also
 * matches its other case: DNS and instance-name slugs case-fold text, so a
 * differently-cased echo is still a reversible credential spelling.
 */
function jsonEscapedApiKeyPattern(apiKey: string): RegExp {
  return new RegExp(
    Array.from(apiKey, jsonKeyCharacterPattern).join(""),
    "g",
  );
}

/** Raw/screened keys whose characters may each be JSON-escaped. */
function apiKeyPatternBases(apiKey: string): string[] {
  return [...new Set([apiKey, screenRemote(apiKey)])]
    .filter((key) => key.length >= MIN_API_KEY_CHARS);
}

/** Screen first so an invisible splitter cannot hide a reflected key. */
function containsApiKeyForm(value: string, apiKey: string): boolean {
  const screened = screenRemote(value);
  return apiKeyForms(apiKey).some((key) => screened.includes(key)) ||
    apiKeyPatternBases(apiKey).some((key) =>
      jsonEscapedApiKeyPattern(key).test(screened)
    );
}

/**
 * The single boundary every remote-supplied value crosses on its way into an
 * error, a log line, a stored field or a tag.
 *
 * Three separate defects lived on this path and they are fixed together
 * because they are one class, not three sites:
 *
 *   - Unbounded. The non-array guard pasted a whole `JSON.stringify(raw)`
 *     into a thrown error, so a hostile or merely broken host chose how much
 *     text went into swamp's logs.
 *   - Unredacted. See redactKey(): the API key could come back to us in the
 *     server's own error message and go straight out to a log.
 *   - Unscreened. See screenRemote(): control, bidi and zero-width characters
 *     reached logs, errors, stored fields and tags verbatim.
 *
 * It truncates rather than blanking. The leading text is what makes a failure
 * diagnosable -- "TrueNAS RPC failure: pool is busy" is the finding, and a
 * canned "RPC failure" would make this model undiagnosable for exactly the
 * cases it exists to diagnose. What is removed is the ability of that text to
 * be unbounded, to carry the key, or to drive a terminal.
 */
function safeRemoteText(
  value: unknown,
  apiKey: string,
  max = MAX_REMOTE_CHARS,
): string {
  let s: string;
  if (typeof value === "string") {
    s = value;
  } else {
    // Object diagnostics are attacker-controlled trees whose values and keys
    // may contain escaped or obfuscated credentials. Their type is the useful
    // fact; do not serialize their contents into a log-bound string at all.
    s = value === null
      ? "[null]"
      : Array.isArray(value)
      ? "[array]"
      : `[${typeof value}]`;
  }
  // SCREEN, REDACT, *THEN* TRUNCATE -- in that order, all three of them.
  //
  // Truncation used to run first (`s.slice(0, 65_536)`, to cap the regex
  // work), and that was a hole of its own: a key sitting across the cut lost
  // its tail, so the literal match found nothing and the surviving PREFIX of
  // the key went out as ordinary text. It is reachable with padding the far
  // end chooses -- 65,500 spaces then the key leaves 36 characters of it in
  // the slice, and screening then collapses the padding to nothing, so those
  // 36 characters are the entire returned string. Redaction now sees the
  // whole string, and only what survives redaction is truncated.
  //
  // The regex work is still bounded, just not here: the WebSocket client
  // enforces MAX_FRAME_BYTES while receiving the message, before this handler
  // sees or parses it.
  //
  // SCREEN FIRST, THEN REDACT. The order was the other way round and that was
  // the whole defect: redaction matched the key as a literal substring, so a
  // host echoing `abc<U+200B>def...` back at us matched nothing and passed
  // through untouched -- and then screening, running afterwards, DELETED the
  // zero-width character and handed the log line a perfectly intact API key.
  // The obfuscation only had to survive one function to be undone by the
  // next. Normalising first means redaction sees the same bytes the reader
  // will, and there is no later pass that can put the key back together.
  const screened = screenRemote(s);
  // Both forms of the key are stripped. The raw one covers a plain echo; the
  // screened one covers a key that screening itself would have altered (a key
  // is operator-supplied and nothing guarantees it is bare ASCII), where the
  // raw literal no longer appears in the normalised text.
  // A remote string may itself contain JSON-serialized text, where quotes and
  // backslashes in an echoed key are escaped. Cover that form too.
  let redacted = screened;
  for (const key of apiKeyForms(apiKey)) redacted = redactKey(redacted, key);
  for (const key of apiKeyPatternBases(apiKey)) {
    redacted = redacted.replace(jsonEscapedApiKeyPattern(key), "[REDACTED]");
  }
  const codePoints = Array.from(redacted);
  return codePoints.length <= max
    ? redacted
    : `${
      codePoints.slice(0, max).join("")
    }… (${codePoints.length} chars, truncated)`;
}

/** The `safe()` closure threaded through everything that touches remote text. */
type Safe = (value: unknown, max?: number) => string;

function safeOrUnknown(value: unknown, safe: Safe, max: number): string {
  if (value === null || value === undefined) return "UNKNOWN";
  return safe(value, max) || "UNKNOWN";
}

/**
 * Runtime validation of baseUrl. Deliberately NOT an object-level zod
 * refinement: swamp calls .partial() on globalArguments, and zod 4 refuses
 * that on an object carrying refinements -- a superRefine here made every
 * discover() fail before it connected.
 *
 * Returns the parsed URL so the caller builds the WebSocket URL from its
 * components instead of pasting strings onto the raw argument.
 */
function assertBaseUrl(
  baseUrl: string,
  apiKey: string,
  allowInsecureHttp: boolean,
  allowedHosts: string[],
): URL {
  if (!/^https?:\/\//i.test(baseUrl)) {
    throw new Error("baseUrl must start with http:// or https://");
  }
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    throw new Error("baseUrl is not a valid URL");
  }
  // Userinfo is a second credential channel in the WebSocket handshake. The
  // API key is the only supported credential and is sent in the RPC body.
  if (u.username !== "" || u.password !== "") {
    throw new Error(
      "baseUrl must not embed credentials (user:pass@host); the API key is " +
        "the only credential and is sent via apiKey.",
    );
  }
  // `baseUrl` is marked sensitive because it is resolved operator input, but
  // that alone cannot stop a key embedded in a hostname from entering DNS or
  // a socket address. Refuse every spelling the remote-text boundary knows
  // how to reconstruct; authentication belongs only in the RPC body.
  if (
    [baseUrl, u.href, u.host, u.hostname].some((component) =>
      containsApiKeyForm(component, apiKey)
    )
  ) {
    throw new Error(
      "baseUrl must not contain API key material; authentication is sent " +
        "only in the JSON-RPC body",
    );
  }
  if (u.protocol === "http:" && !allowInsecureHttp) {
    throw new Error(
      "baseUrl uses http://, which becomes an unencrypted ws:// connection " +
        "carrying the API key in cleartext. Use https://, or set " +
        "allowInsecureHttp: true to override (not recommended).",
    );
  }
  // The endpoint is fixed at /api/current. Accepting an arbitrary path creates
  // a second place to put bearer material, while a query string or fragment
  // cannot mean anything to the JSON-RPC endpoint. Refuse all three before a
  // URL component reaches DNS, a socket, or a diagnostic.
  if (u.pathname !== "/" || u.search !== "" || u.hash !== "") {
    throw new Error(
      "baseUrl must not carry a path, query string or fragment. It addresses " +
        "the fixed TrueNAS JSON-RPC endpoint at /api/current and nothing else.",
    );
  }
  assertHostAllowed(u, allowedHosts);
  return u;
}

/**
 * Enforce the `allowedHosts` pin: the API key may only be put on a socket to
 * a host the operator named here, and the check runs before any socket opens.
 *
 * WHY THIS IS A PIN AND NOT A MANDATORY ALLOWLIST -- the deliberate trade.
 *
 * The security review asked for an allowlist that is always required. When
 * `baseUrl` is a literal in the workflow file, that allowlist is a second
 * copy of the same literal, written by the same hand at the same moment, and
 * a typo goes into both copies -- so it cannot catch the mistake it exists to
 * catch, while it can and does break every working configuration on upgrade.
 * That is ceremony, not a control.
 *
 * Where it IS a real control is the case the review is actually describing:
 * `baseUrl` resolved from a vault expression, a datastore value, or a
 * workflow variable, where the host is not visible in the file at all. There
 * the pin is an independent literal and the only thing standing between a
 * changed upstream value and a live API key leaving for a new destination.
 * So it is offered, enforced without exception once set, and the README says
 * plainly to set it whenever `baseUrl` is not a literal.
 *
 * Entries are validated rather than merely compared. A pin written as
 * `https://nas.example.com/` or `*.example.com` would never match anything,
 * so it would silently deny every run -- or worse, in an earlier draft that
 * skipped unmatched-but-malformed entries, silently allow every run. A pin
 * that cannot work is a configuration error and says so at parse time.
 */
function assertHostAllowed(u: URL, allowedHosts: string[]): void {
  if (allowedHosts.length === 0) return;
  const seen = allowedHosts.map((raw, i) => {
    const entry = raw.trim().toLowerCase();
    if (
      !/^[a-z0-9._~\-]+(:\d{1,5})?$|^\[[0-9a-f:.]+\](:\d{1,5})?$/.test(entry)
    ) {
      throw new Error(
        `allowedHosts[${i}] is not a bare host or host:port. Write ` +
          `"nas.example.com" or "nas.example.com:8443" (IPv6 in brackets); ` +
          `a scheme, a path, or a wildcard never matches anything and would ` +
          `silently break every run.`,
      );
    }
    return entry;
  });
  // Compare effective destinations, including the port. URL normalizes an
  // explicitly-spelled default port away, so put it back before comparing.
  // A bare host means exactly the scheme default -- never every service on
  // that hostname. Non-default ports must be independently explicit.
  const defaultPort = u.protocol === "https:" || u.protocol === "wss:"
    ? "443"
    : "80";
  const destination = `${u.hostname.toLowerCase()}:${u.port || defaultPort}`;
  const hasPort = (e: string) =>
    e.startsWith("[") ? /\]:\d+$/.test(e) : e.includes(":");
  const ok = seen.some((e) =>
    (hasPort(e) ? e : `${e}:${defaultPort}`) === destination
  );
  if (!ok) {
    throw new Error(
      "baseUrl destination is not in allowedHosts. The API key is not sent " +
        "to a destination that was not pinned, and a bare host pin covers " +
        "only the scheme's default port.",
    );
  }
}

/**
 * Verify the socket we ended up on is still the socket we vetted, before the
 * API key is put on it.
 *
 * Everything else in this file checks `baseUrl` -- the destination we ASKED
 * for. Nothing checked the destination we GOT. The WebSocket API exposes no
 * redirect policy: there is no `redirect: "error"` the way `fetch` has one,
 * no per-hop callback, and RFC 6455 leaves following 3xx during the opening
 * handshake up to the client. So "we validated the URL string" was the whole
 * of the argument that the key could not be sent somewhere else, and a URL
 * string is not a destination. A host that answers `https://nas.example.com`
 * with a redirect to another host -- or to `ws://` -- would have had the key
 * delivered there, past a pin that had already passed and a TLS requirement
 * that had already been satisfied by the first hop.
 *
 * The redirect itself is refused one layer down, and that is the load-bearing
 * part: the pinned WebSocket client is constructed with followRedirects false.
 * No redirect is ever taken, so there is no hop for a credential to be carried
 * to. The suite proves that configuration against a real local server that
 * answers the handshake with a 302 to a second origin and asserts the second
 * origin is never contacted.
 *
 * This function is the check on top of that. The socket must name its own
 * destination -- `ws.url`, with no fallback to the URL we asked for, so a
 * client that cannot say where it landed is refused rather than assumed
 * correct -- and that destination must still carry the scheme approved for
 * this run and the exact host `assertBaseUrl` cleared, `allowedHosts` pin
 * included. It costs a string compare on a path where the alternative is
 * sending a live credential to an address nobody approved.
 */
function assertConnectedDestination(
  connectedUrl: string,
  requestedWsUrl: string,
  allowedHosts: string[],
): void {
  let got: URL, want: URL;
  try {
    got = new URL(connectedUrl);
    want = new URL(requestedWsUrl);
  } catch {
    throw new Error(
      `the connected WebSocket reports an unparseable URL; the API key is ` +
        `not sent to a destination that cannot be checked`,
    );
  }
  if (got.protocol !== want.protocol) {
    throw new Error(
      `the connection transport differs from the one approved for this run. ` +
        `A transport downgrade after the handshake ` +
        `would put the API key on the wire in cleartext; refused.`,
    );
  }
  if (got.host.toLowerCase() !== want.host.toLowerCase()) {
    throw new Error(
      `the connection landed on a different host than the one checked before ` +
        `connecting. A redirect cannot move the API key to another host; ` +
        `refused.`,
    );
  }
  // And the pin again, against the arrived-at host rather than the asked-for
  // one. Redundant while the two match, which is the point: an allowlist that
  // is only ever evaluated against a value nobody re-verified is an allowlist
  // on paper.
  assertHostAllowed(got, allowedHosts);
}

const DiscoverArgsSchema = z.object({});

/**
 * Sentinel written in place of a numeric TrueNAS did not report.
 *
 * Every one of these fields used to be backfilled with `?? 0`, which is the
 * certificate `daysRemaining` mistake wearing a different hat: 0 is a
 * *legitimate* value for all of them. An empty pool really does have 0 bytes
 * allocated; a box that just came up really does have near-0 uptime. So a CEL
 * gate could not tell "TrueNAS did not say" from "TrueNAS said zero", and a
 * pool whose `allocated`/`free` came back null was written sizeBytes: 0,
 * usedPercent: 0 -- a capacity gate read that as plenty of room, on a pool it
 * knew nothing about.
 *
 * -1 is impossible for every field it stands in for, so a consumer that never
 * reads the companion `*Known` flag still sees an obviously-wrong number
 * rather than a reassuring one. The flag is the supported way to ask; the
 * sentinel is the safety net under consumers that forget, exactly as
 * `expiryKnown` sits over `daysRemaining: -9999`.
 */
const UNKNOWN_NUMBER = -1;

const knownOrUnknownInteger = (max: number) =>
  z.number().refine(
    (n) =>
      n === UNKNOWN_NUMBER ||
      (Number.isSafeInteger(n) && n >= 0 && n <= max),
    { message: `must be ${UNKNOWN_NUMBER} or an integer from 0 to ${max}` },
  );
const knownOrUnknownPercent = z.number().refine(
  (n) => n === UNKNOWN_NUMBER || (Number.isFinite(n) && n >= 0 && n <= 100),
  { message: `must be ${UNKNOWN_NUMBER} or a percentage from 0 to 100` },
);
const nonnegativeCount = z.number().refine(
  (n) => Number.isSafeInteger(n) && n >= 0 && n <= MAX_ROWS,
  { message: `must be an integer from 0 to ${MAX_ROWS}` },
);
const GenerationIdSchema = z.string().uuid();

const SystemSchema = z.object({
  generationId: GenerationIdSchema,
  hostname: z.string(),
  version: z.string(),
  model: z.string(),
  cores: knownOrUnknownInteger(MAX_REMOTE_CORES),
  physmemBytes: knownOrUnknownInteger(MAX_REMOTE_BYTES),
  uptimeSeconds: knownOrUnknownInteger(MAX_REMOTE_UPTIME_SECONDS),
  loadavg: z.array(
    boundedNonnegativeNumber(
      "system loadavg entry",
      MAX_REMOTE_LOAD_AVERAGE,
    ),
  ).max(MAX_LOADAVG_ENTRIES),
  /**
   * False when TrueNAS omitted any of `cores`, `physmem` or `uptime_seconds`;
   * those three are then UNKNOWN_NUMBER. Check this before comparing them --
   * `uptimeSeconds` in particular, since a backfilled 0 makes a "rebooted in
   * the last five minutes" gate fire on every single run.
   */
  metricsKnown: z.boolean(),
});

const PoolSchema = z.object({
  generationId: GenerationIdSchema,
  name: z.string(),
  status: z.string(),
  healthy: z.boolean(),
  allocatedBytes: knownOrUnknownInteger(MAX_REMOTE_BYTES),
  freeBytes: knownOrUnknownInteger(MAX_REMOTE_BYTES),
  sizeBytes: knownOrUnknownInteger(MAX_REMOTE_BYTES),
  usedPercent: knownOrUnknownPercent,
  fragmentationPercent: knownOrUnknownPercent,
  /**
   * False when TrueNAS reported no `allocated`/`free` for this pool;
   * `allocatedBytes`, `freeBytes`, `sizeBytes` and `usedPercent` are then all
   * UNKNOWN_NUMBER. Consumers must check this before gating on capacity.
   */
  capacityKnown: z.boolean(),
});

const DiskSchema = z.object({
  generationId: GenerationIdSchema,
  name: z.string(),
  serial: z.string(),
  model: z.string(),
  sizeBytes: knownOrUnknownInteger(MAX_REMOTE_BYTES),
  type: z.string(),
  pool: z.string(),
  /** False when TrueNAS reported no `size`; `sizeBytes` is UNKNOWN_NUMBER. */
  sizeKnown: z.boolean(),
  /**
   * True when TrueNAS actually answered the pool-membership question, whether
   * the answer was a pool name or "this disk is in no pool".
   *
   * `pool` used to be `d.pool ?? ""` with the tag `d.pool ?? "none"`, which
   * made two completely different facts render identically: a disk genuinely
   * outside every pool, and a run where the `extra: { pools: true }` join was
   * not honoured at all. In the second case EVERY disk reads "none", so an
   * "orphaned disk" gate fires across the whole array while a "which disks
   * back tank" gate silently returns nothing. When this is false the `pool`
   * field is "" and the tag reads "unknown", never "none".
   */
  poolKnown: z.boolean(),
});

const AlertSchema = z.object({
  generationId: GenerationIdSchema,
  id: z.string(),
  klass: z.string(),
  level: z.string(),
  formatted: z.string(),
  dismissed: z.boolean(),
  /**
   * True when the alert is real but hidden from the TrueNAS UI because
   * somebody dismissed it. These are the dangerous ones.
   */
  silenced: z.boolean(),
  /**
   * False when TrueNAS sent this alert with a null, blank, or screened-empty
   * `klass`, `level` or `formatted` -- the three fields that ARE the alert.
   *
   * Those nulls used to be written as `""`, which is the most dangerous
   * backfill in this file. An alert record with `level: ""` exists, counts
   * toward `summary.alerts`, and matches no `level == "CRITICAL"` gate
   * anywhere, so a box in a genuinely critical state reports as a box with
   * an alert nobody wrote a rule for -- and the operator's severity gate,
   * the whole point of collecting alerts, stays green through it. The value
   * is not invented here: unknown class and level read "UNKNOWN", this flag
   * says so structurally, `summary.alertsContentUnknown` counts them, and
   * `summary.discoveryDegraded` goes true for the run so a workflow that
   * only reads the roll-up still sees it.
   */
  contentKnown: z.boolean(),
});

const CertificateSchema = z.object({
  generationId: GenerationIdSchema,
  name: z.string(),
  commonName: z.string(),
  notAfter: z.string(),
  daysRemaining: z.number(),
  /**
   * False for objects with no expiry at all, a CSR for instance. Without
   * this, the sentinel daysRemaining reads as a real (and alarming) number.
   * Consumers must check this before comparing daysRemaining.
   */
  expiryKnown: z.boolean(),
  expiringSoon: z.boolean(),
  expired: z.boolean(),
});

const SummarySchema = z.object({
  generationId: GenerationIdSchema,
  generationComplete: z.boolean(),
  hostname: z.string(),
  version: z.string(),
  pools: nonnegativeCount,
  poolsUnhealthy: nonnegativeCount,
  /**
   * Pools whose capacity TrueNAS did not report this run. Counted here for the
   * same reason `certificatesWithoutExpiry` is: a workflow that gates on the
   * summary alone would otherwise have no way to see that the capacity numbers
   * underneath it are absent rather than low.
   */
  poolsCapacityUnknown: nonnegativeCount,
  disks: nonnegativeCount,
  alerts: nonnegativeCount,
  alertsSilenced: nonnegativeCount,
  /**
   * Alerts this run whose class, level or text TrueNAS did not supply. Same
   * reason `poolsCapacityUnknown` is here: a workflow gating on the roll-up
   * alone would otherwise have no way to see that some of the alerts counted
   * above carry nothing a severity gate can match. Non-zero also sets
   * `discoveryDegraded`.
   */
  alertsContentUnknown: nonnegativeCount,
  certificates: nonnegativeCount,
  certificatesExpiringSoon: nonnegativeCount,
  certificatesExpired: nonnegativeCount,
  certificatesWithoutExpiry: nonnegativeCount,
  /**
   * True when `pool.query` came back as a well-formed EMPTY array. A NAS with
   * no pools is not a steady state; this is what a pool still importing after
   * a reboot, or failing to import at all, looks like from here.
   */
  poolsReportedEmpty: z.boolean(),
  /** Same, for `disk.query`. A NAS with no disks has no steady state at all. */
  disksReportedEmpty: z.boolean(),
  /**
   * The one field a workflow can gate on to refuse the whole roll-up.
   *
   * The summary used to report `pools: 0, poolsUnhealthy: 0` for an empty
   * response and say nothing else, which reads exactly like a clean bill of
   * health: zero pools, none of them unhealthy. The prune protection already
   * kept the underlying records, but it only WARNED when it had stale records
   * to keep -- so on a first run, where nothing stale exists, the run was
   * completely silent about having discovered nothing.
   *
   * This does not fail the run. Alerts and certificates come off the same
   * connection and are still valid, and an import window is transient, so
   * throwing away a good certificate-expiry reading to punish a missing pool
   * list is the wrong trade. The flag makes the incompleteness explicit and
   * lets the consumer decide; the run also warns unconditionally now.
   *
   * It also covers `alertsContentUnknown`, for the same reason and with the
   * same trade: an alert that arrived without a class or a level is invisible
   * to every severity gate, and one such alert must not be able to hide
   * behind five good ones in a roll-up that otherwise looks clean.
   */
  discoveryDegraded: z.boolean(),
  syncedAt: z.string(),
});

const RESOURCE_SCHEMAS = {
  system: SystemSchema,
  pool: PoolSchema,
  disk: DiskSchema,
  alert: AlertSchema,
  certificate: CertificateSchema,
  summary: SummarySchema,
} as const;

type PlannedWrite = {
  kind: keyof typeof RESOURCE_SCHEMAS;
  name: string;
  fields: Record<string, unknown>;
  tags: Record<string, string>;
};

/** Refuse a plan that would collide or defer data validation until a write. */
function assertPlanWritable(planned: PlannedWrite[]): void {
  const seen = new Map<PlannedWrite["kind"], Set<string>>();
  for (const write of planned) {
    RESOURCE_SCHEMAS[write.kind].parse(write.fields);
    const names = seen.get(write.kind) ?? new Set<string>();
    if (names.has(write.name)) {
      throw new Error(
        `TrueNAS returned duplicate ${write.kind} identity ${write.name}; ` +
          "the run is refused before one row can overwrite another",
      );
    }
    names.add(write.name);
    seen.set(write.kind, names);
  }
}

/**
 * Raw TrueNAS response shapes for the fields this model actually reads.
 *
 * These validate an untrusted third-party payload. Unlike the resource
 * schemas above (which gate CEL and must be exact), a TrueNAS release that
 * ADDS a field must not break discovery, so `.strict()` is wrong here: a
 * point release that enriches `disk.query` would take the whole model down.
 *
 * They used to carry `.passthrough()`, defended as "extra fields we don't use
 * are expected and harmless". The first half of that is right and the second
 * half was the mistake. `.passthrough()` does not merely *accept* undeclared
 * keys, it RETAINS them on the parsed object -- so every raw record carried
 * an unbounded, entirely unvalidated blob of remote data through the rest of
 * discover(), one `...spread` away from being written into an
 * infinite-lifetime resource by a future edit that looked harmless. Zod's
 * default `strip` accepts exactly the same payloads and drops the undeclared
 * keys at the parse boundary, so nothing past this line can reach them by
 * accident. Forward compatibility was never the thing `.passthrough()` bought;
 * strip gives that for free and retention was pure downside.
 *
 * What each schema still asserts is that the fields the model RELIES on are
 * present and typed as expected, so contract drift throws here instead of the
 * mapping code silently writing placeholder 0/""/[] values as if they were
 * real data.
 */
/**
 * Every raw string this model reads, with a ceiling on it.
 *
 * Written as one helper rather than `.max()` sprinkled per field so a new
 * field cannot be added without a bound: the bound is what `rawString` means.
 * The message names the field and the limit because an operator hitting this
 * is looking at either a genuinely pathological payload or a host that is not
 * TrueNAS, and both are worth being able to tell apart from a network fault.
 */
function hasOnlyPairedSurrogates(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (i + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        return false;
      }
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

const rawString = (field: string, max = MAX_RAW_FIELD_CHARS) =>
  z.string().max(max, {
    message:
      `${field} exceeds ${max} characters. A TrueNAS payload does not carry ` +
      `a value that size; the run is refused before it is hashed into an ` +
      `instance name or written to an infinite-lifetime record.`,
  }).refine(hasOnlyPairedSurrogates, {
    message:
      `${field} contains an unpaired UTF-16 surrogate; it cannot be hashed ` +
      "into an injective resource identity",
  });

type IdentityCandidate = readonly [source: string, value: unknown];
type IdentityPart = Readonly<{
  source: string;
  type: "number" | "string";
  value: string;
}>;

/** Preserve field provenance and primitive type while selecting identities.
 * Invisible-only text is blank after remote screening. */
function identityPart([source, value]: IdentityCandidate):
  | IdentityPart
  | undefined {
  if (typeof value === "number") {
    return { source, type: "number", value: String(value) };
  }
  if (typeof value === "string" && screenRemote(value) !== "") {
    return { source, type: "string", value };
  }
  return undefined;
}

function identityParts(...candidates: IdentityCandidate[]): IdentityPart[] {
  return candidates.map(identityPart).filter(
    (part): part is IdentityPart => part !== undefined,
  );
}

function firstNonBlankIdentity(
  ...candidates: IdentityCandidate[]
): IdentityPart | undefined {
  return identityParts(...candidates)[0];
}

/** Same ceiling logic for an id that TrueNAS may send as a string or number. */
const rawId = (field: string) =>
  z.union([
    rawString(field, 256),
    boundedNonnegativeNumber(field, Number.MAX_SAFE_INTEGER, true),
  ]);

const RawSystemSchema = z.object({
  hostname: rawString("system.info hostname"),
  version: rawString("system.info version"),
  model: rawString("system.info model").nullable().optional(),
  cores: boundedNonnegativeNumber(
    "system.info cores",
    MAX_REMOTE_CORES,
    true,
  ).nullable().optional(),
  physmem: boundedNonnegativeNumber(
    "system.info physmem",
    MAX_REMOTE_BYTES,
    true,
  ).nullable().optional(),
  uptime_seconds: boundedNonnegativeNumber(
    "system.info uptime_seconds",
    MAX_REMOTE_UPTIME_SECONDS,
    true,
  ).nullable().optional(),
  // `model` stays optional on purpose and is NOT part of the class fixed
  // below: its backfill is the literal string "unknown", which names itself
  // as a placeholder. The defect being fixed elsewhere is a backfill that a
  // consumer cannot tell from data, and "unknown" is not one.
  // Bounded because this array is the one field written to a resource with no
  // safe() between the wire and the record -- an array is not a string, so the
  // remote-text boundary never saw it. A host answering with a million-element
  // loadavg would have had every element stored, forever.
  loadavg: z
    .array(boundedNonnegativeNumber(
      "system.info loadavg entry",
      MAX_REMOTE_LOAD_AVERAGE,
    ))
    .max(MAX_LOADAVG_ENTRIES, {
      message:
        `system.info loadavg has more than ${MAX_LOADAVG_ENTRIES} entries; ` +
        `TrueNAS reports three, and this array is stored verbatim`,
    })
    .nullable()
    .optional(),
});

const RawPoolSchema = z.object({
  name: rawString("pool.query name"),
  id: rawId("pool.query id").optional(),
  status: rawString("pool.query status").nullable().optional(),
  healthy: z.boolean().nullable().optional(),
  allocated: boundedNonnegativeNumber(
    "pool.query allocated",
    MAX_REMOTE_BYTES,
    true,
  ).nullable().optional(),
  free: boundedNonnegativeNumber(
    "pool.query free",
    MAX_REMOTE_BYTES,
    true,
  ).nullable().optional(),
  // Confirmed against TrueNAS API v25.10: "Percentage of pool fragmentation
  // as a string, or null if not available."
  fragmentation: z
    .union([
      rawString("pool.query fragmentation", 64),
      boundedNonnegativeNumber("pool.query fragmentation", 100),
    ])
    .nullable()
    .optional(),
}).refine(
  (p) => firstNonBlankIdentity(["name", p.name], ["id", p.id]) !== undefined,
  {
    message:
      "pool.query row has neither a usable `name` nor `id`; the pool cannot " +
      "be given a stable resource identity",
  },
).refine(
  // Presence, not truthiness -- the same shape as the certificate expiry
  // check below, for the same reason.
  //
  // `status` and `healthy` are core `pool.query` fields, not `extra`-gated
  // ones, so their KEYS are always present on a host whose contract has not
  // drifted. While they were merely optional, a rename made `Boolean(
  // undefined)` false for every pool on the box: `poolsUnhealthy` equalled
  // `pools` on every run, forever, and `status` read "UNKNOWN" -- which looks
  // like a real ZFS status string rather than like a parse failure. A
  // permanent, box-wide false degrade is not a safe failure mode; it trains
  // an operator to ignore the one signal pools exist to give.
  (p) => p.status !== undefined && p.healthy !== undefined,
  {
    message:
      "pool.query row is missing `status` and/or `healthy`; the TrueNAS pool " +
      "contract has changed and pool health can no longer be read",
  },
);

/**
 * The refinements on the three schemas below exist because every field in
 * them was optional, which made the contract this block claims a no-op for
 * them: `.parse()` could not fail, so a renamed field fell through to the
 * `?? ""` defaults in the mapping code and was written as if it were real
 * data. Each refinement asserts only the *identity or date* fields the model
 * genuinely cannot work without, so a rename throws while a merely enriched
 * payload still passes.
 */
const RawDiskSchema = z.object({
  devname: rawString("disk.query devname").nullable().optional(),
  identifier: rawString("disk.query identifier").nullable().optional(),
  serial: rawString("disk.query serial").nullable().optional(),
  model: rawString("disk.query model").nullable().optional(),
  size: boundedNonnegativeNumber(
    "disk.query size",
    MAX_REMOTE_BYTES,
    true,
  ).nullable().optional(),
  type: rawString("disk.query type").nullable().optional(),
  // Only populated when disk.query is called with extra.pools: true, and the
  // absent-vs-null distinction is load-bearing -- see `poolKnown` on
  // DiskSchema. Left optional rather than required precisely BECAUSE the
  // model can now represent "not answered" honestly: making it required
  // would take a whole NAS's discovery down over a join that has a correct
  // non-fatal reading.
  pool: rawString("disk.query pool").nullable().optional(),
}).refine(
  // A blank preferred identifier must not mask a usable devname, and with
  // neither one there is no stable identity. Response position is never an
  // identity: it changes whenever the enumeration order does.
  (d) =>
    firstNonBlankIdentity(
      ["identifier", d.identifier],
      ["devname", d.devname],
    ) !== undefined,
  {
    message:
      "disk.query row has neither `identifier` nor `devname`; the TrueNAS " +
      "disk contract has changed and disks can no longer be identified",
  },
);

const RawAlertSchema = z.object({
  uuid: rawString("alert.list uuid").optional(),
  id: rawId("alert.list id").optional(),
  key: rawString("alert.list key").optional(),
  klass: rawString("alert.list klass").nullable().optional(),
  level: rawString("alert.list level").nullable().optional(),
  // The one genuinely free-text field, so it gets the wide ceiling: it is
  // truncated for storage rather than rejected, and failing a whole discovery
  // because one alert was wordy would break the model's actual job.
  formatted: rawString("alert.list formatted", MAX_RAW_TEXT_CHARS)
    .nullable()
    .optional(),
  dismissed: z.boolean(),
}).refine(
  // Same stable-identity rule as disks. A blank uuid must not mask a usable id
  // or key, and response position is never used as an identity.
  (a) =>
    firstNonBlankIdentity(
      ["uuid", a.uuid],
      ["id", a.id],
      ["key", a.key],
    ) !== undefined,
  {
    message:
      "alert.list row has none of `uuid`, `id`, `key`; the TrueNAS alert " +
      "contract has changed and alerts can no longer be identified",
  },
).refine(
  // Presence again. `klass`, `level` and `formatted` are the entire content
  // of an alert -- the class it belongs to, how bad it is, and what it says.
  // Backfilled to "" they produce a record that exists, counts toward
  // `summary.alerts`, and matches no `klass ==` or `level ==` gate anywhere,
  // so a box full of CRITICAL alerts reports as a box full of alerts nobody
  // wrote a rule for. A missing KEY is contract drift and throws here.
  // Present-and-null is still accepted, because a null is a real (if
  // unhelpful) answer rather than a changed contract -- but it is no longer
  // silently written as "": it reads "UNKNOWN", sets `contentKnown: false`,
  // counts into `summary.alertsContentUnknown` and degrades the run. See
  // AlertSchema.contentKnown.
  (a) =>
    a.klass !== undefined && a.level !== undefined && a.formatted !== undefined,
  {
    message:
      "alert.list row is missing `klass`, `level` and/or `formatted`; the " +
      "TrueNAS alert contract has changed and alert severity can no longer " +
      "be read",
  },
);

const RawCertificateSchema = z.object({
  id: rawId("certificate.query id").optional(),
  name: rawString("certificate.query name").nullable().optional(),
  common: rawString("certificate.query common").nullable().optional(),
  common_name: rawString("certificate.query common_name").nullable().optional(),
  until: z.unknown().optional(),
  not_after: z.unknown().optional(),
}).refine(
  // A certificate MUST arrive with something stable to be named by. Without
  // this, `String(c.id ?? c.name ?? "")` was "" for a row carrying neither,
  // instanceName() fell back to `idx<n>` -- the row's POSITION in the
  // response -- and the position of a certificate is not a property of the
  // certificate. TrueNAS does not promise an order, so two rows swapping
  // places renames both records: each inherits the other's stored history,
  // and the run that reports one fewer certificate prunes a record that
  // belongs to a certificate still on the box. Expiry history is the entire
  // reason certificates are collected here (see the module header), and a
  // history that silently changes owner is worse than none.
  (c) => firstNonBlankIdentity(["id", c.id], ["name", c.name]) !== undefined,
  {
    message:
      "certificate.query row has neither a usable `id` nor a `name`; there " +
      "is no stable identifier to name its record by, and naming it by its " +
      "position in the response would move history between certificates " +
      "whenever TrueNAS reorders them",
  },
).refine(
  // Presence, not truthiness: `until: null` is a legitimate payload -- a CSR
  // has no expiry, which is exactly what expiryKnown:false exists to record
  // -- so requiring a non-null value here would reject valid data. What must
  // never pass silently is the key being GONE, because toIso(undefined) is
  // "" and every certificate would then be written notAfter:"",
  // expiryKnown:false, daysRemaining:-9999. summary.certificatesWithoutExpiry
  // would quietly equal certs.length on every run, including for a cert two
  // days from lapsing -- the precise failure certificates are collected to
  // catch (see the module header).
  (c) => c.until !== undefined || c.not_after !== undefined,
  {
    message: "certificate.query row has neither `until` nor `not_after`; the " +
      "TrueNAS certificate contract has changed and expiry can no longer " +
      "be read",
  },
);

/**
 * Unambiguous encoding of an identity tuple: each field is prefixed with its
 * own length, so no content inside a field can be mistaken for the boundary
 * between two fields.
 *
 * This replaces `identity.join(U+001F)`. A separator-based encoding is only
 * injective while the separator cannot occur inside a field, and NOTHING
 * enforced that: every one of these fields is remote text straight out of a
 * TrueNAS payload, so a disk `identifier` or an alert `klass` containing a
 * Unit Separator collapsed two different identity tuples onto one digest --
 * and a digest collision here means two different objects sharing one
 * `infinite`-lifetime record, each run overwriting the other's state.
 * (Screening the fields instead would be worse: mapping U+001F to a space
 * makes DIFFERENT identities encode identically, which is the same bug.)
 * Length prefixes need no such assumption; ["a","b c"] and ["a b","c"] encode
 * as "1:a3:b c" and "3:a b1:c" whatever the fields contain.
 */
function encodeIdentity(identity: string[]): string {
  return identity.map((s) => `${s.length}:${s}`).join("");
}

/** Longest readable half of an instance name. The name is a storage path
 * component, so it is bounded well inside the ext4/APFS 255-byte limit. */
const MAX_SLUG_CHARS = 48;

/**
 * SHA-256 over the encoded identity, truncated to 128 bits and hex-encoded.
 *
 * This was a 32-bit FNV-1a. 32 bits gives a ~50% chance of some collision
 * across roughly 77,000 distinct identities, and the readable half of the
 * name cannot break a tie because it is truncated to MAX_SLUG_CHARS and is
 * not injective anyway (`foo/bar` and `foo-bar` both slug to `foo-bar`). A
 * collision means two disks, or two alerts, silently sharing one record.
 * 128 bits is not a number of buckets anything collides in.
 *
 * "Non-cryptographic is fine, this is not security sensitive" was the old
 * justification and it does not hold: the inputs are attacker-influencable
 * remote strings, and FNV-1a is trivially invertible to a chosen digest, so
 * a hostile payload could aim one object's record at another's on purpose.
 *
 * Widening the digest RENAMES every stored instance. The run after this
 * change writes new records and prunes the old ones, exactly as documented in
 * the README, and history under the old names is lost once. That is a
 * one-time cost paid deliberately; it is the same trade the `cert-` prefix
 * comment declines to pay for a cosmetic rename, and is worth paying here
 * because the alternative is silent record merging.
 */
async function shortHash(input: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(digest).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Resource instance names must be stable and filesystem-safe. */
function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(
    /^-+|-+$/g,
    "",
  ) || "unnamed";
}

/**
 * Build a collision-safe, filesystem-safe instance name. `slug()` alone is
 * not injective -- distinct raw identifiers can slug to the same string
 * (`foo/bar` and `foo-bar` both become `foo-bar`), and a fully missing
 * identifier always slugs to the literal string "unnamed" for every record
 * that has one. Every name here therefore also carries a short hash of the
 * *raw*, pre-slug identity fields together with each field's provenance and
 * primitive type. A numeric `id: 1`, string `id: "1"`, and `uuid: "1"` must
 * not collapse merely because their readable values match.
 *
 * Identity fields must be stable across polls (real IDs, not mutable state
 * like a formatted message or a status string) -- otherwise the instance
 * name would change every time the underlying data changes, breaking
 * garbage collection and history for what is still the same resource.
 *
 * The readable half goes through `safe` first, and that is not decoration.
 * Every identity field here is remote text -- a pool name, a disk identifier,
 * an alert class, a certificate CN -- and nothing stops a hostile or merely
 * misdirected host from naming a pool after the API key it was just sent. The
 * slug of that name is a persistent record name in the datastore, where no
 * later redaction pass reaches it. Prune logs intentionally omit stored names.
 * Screening and key detection therefore run BEFORE either the label or digest
 * is built, in that order, exactly as safeRemoteText() does everywhere else.
 * If any identity contains a raw, JSON-escaped, or invisibly split form of the
 * key, the run aborts before writes. Non-secret identities still hash their raw
 * typed/provenanced values, so screening cannot merge two records.
 */
async function instanceName(
  prefix: string,
  apiKey: string,
  safe: Safe,
  ...identity: IdentityPart[]
): Promise<string> {
  for (const part of identity) {
    if (containsApiKeyForm(part.value, apiKey)) {
      throw new Error(
        "TrueNAS returned API key material in a resource identity; refused " +
          "before hashing or writing it",
      );
    }
  }
  // Length-prefixed rather than separator-joined; see encodeIdentity(). The
  // previous separators (a raw NUL, then U+001F) both assumed that byte could
  // not occur inside an identifier, and nothing enforced it -- every field
  // here is remote text off a TrueNAS payload.
  const raw = encodeIdentity(
    identity.flatMap((part) => [part.source, part.type, part.value]),
  );
  // Build the readable label from EVERY non-empty identity field, not just the
  // first. Taking only the first makes the visible part non-discriminating
  // wherever a caller passes a shared scope ahead of the object identifier:
  // every object in that scope then differs only in an opaque hash, defeating
  // the reason this name has a readable part.
  // Capped so an unusually long identity cannot produce an unbounded name.
  // The hash still covers the full raw identity, so uniqueness never depends on
  // what survives truncation.
  const parts = identity.map((part) => slug(safe(part.value)))
    .filter((s) => s !== "");
  const label =
    (parts.length ? parts.join("-").slice(0, MAX_SLUG_CHARS) : "").replace(
      /-+$/,
      "",
    ) || "unnamed";
  const name = `${prefix}-${label}-${await shortHash(raw)}`;
  assertNoApiKeyInGeneratedName(name, apiKey);
  return name;
}

/** Final invariant after slug case-folding and digest assembly. */
function assertNoApiKeyInGeneratedName(name: string, apiKey: string): void {
  if (containsApiKeyForm(name, apiKey)) {
    throw new Error(
      "generated resource identity contains API key material; refused before " +
        "writing it",
    );
  }
}

/**
 * TrueNAS reports pool fragmentation as a nullable percentage, sometimes with
 * a trailing "%".
 *
 * ABSENT still means 0, and that is argued, not overlooked. Unlike a missing
 * capacity or a missing certificate expiry, 0% fragmentation is not itself an
 * alarming value, so no gate can be lulled by it -- the worst a consumer does
 * is see a healthy fragmentation figure for a pool that reported none.
 *
 * MALFORMED is a completely different fact and used to be folded into the
 * same 0. `Number("busy")` is NaN, `Number.isFinite(NaN)` is false, and the
 * old line answered 0 -- so `fragmentation: "ERROR"`, or a future release
 * changing the field to an object, or a value of 4e9, all reported as a
 * pristine pool. That is contract drift or a hostile payload wearing the
 * exact disguise this model exists to strip off, so it throws. Bounds too:
 * a percentage outside 0-100 is not a percentage.
 */
function parsePercent(
  value: string | number | null | undefined,
  safe: Safe,
): number {
  if (value === null || value === undefined) return 0;
  let n: number;
  if (typeof value === "number") {
    n = value;
  } else {
    const text = value.trim();
    // Number("") is 0, Number("0x10") is 16, and Number("1e2") is 100.
    // None is a decimal percentage spelling from TrueNAS. Validate the whole
    // string before conversion so whitespace and parser conveniences cannot
    // turn malformed remote input into a healthy measurement.
    if (!/^(?:\d+(?:\.\d+)?|\.\d+)%?$/.test(text)) {
      throw new Error(
        `pool.query returned a fragmentation value that is not a 0-100 ` +
          `percentage: ${safe(value, 64)}`,
      );
    }
    n = Number(text.replace(/%$/, ""));
  }
  if (!Number.isFinite(n) || n < 0 || n > 100) {
    throw new Error(
      `pool.query returned a fragmentation value that is not a 0-100 ` +
        `percentage: ${safe(value, 64)}`,
    );
  }
  return n;
}

function daysUntil(iso: string): number {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return Number.NaN;
  return Math.floor((then - Date.now()) / 86_400_000);
}

/**
 * Normalize a TrueNAS expiry field to an ISO string, or null when the record
 * legitimately has no expiry.
 *
 * The three-way distinction is the whole point, and the old `toIso` collapsed
 * it to two. It returned "" for anything it could not read -- an unparseable
 * date string, a `{ $date: ... }` wrapper of an unexpected shape, a boolean,
 * a number out of Date range -- and the caller turned "" into
 * `expiryKnown: false`, which is the SAME state a CSR produces. So "we could
 * not read this certificate's expiry" and "this object has no expiry, by
 * design" were indistinguishable, on the one field this model was written to
 * watch (see the module header: a dismissed CertificateIsExpiring alert is
 * why certificates are collected at all).
 *
 *   - absent / null / empty string -> null, a real "no expiry" (a CSR).
 *   - a bounded value this function can turn into a date -> canonical ISO.
 *   - anything else -> throw. Present but unreadable is drift, not absence.
 */
function toIsoOrNull(value: unknown, safe: Safe): string | null {
  const fail = () =>
    new Error(
      `certificate.query returned an expiry this model cannot read: ` +
        `${safe(value, 64)}. Present-but-unreadable is contract drift; it is ` +
        `not reported as "no expiry", because a CSR reports that legitimately.`,
    );
  const fromEpoch = (ms: number): string => {
    if (!Number.isFinite(ms)) throw fail();
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) throw fail();
    return d.toISOString();
  };
  const fromText = (text: string): string | null => {
    if (text.length > MAX_RAW_FIELD_CHARS) throw fail();
    if (text.trim() === "") return null;
    const ms = Date.parse(text);
    if (Number.isNaN(ms)) throw fail();
    // Date.parse accepts trailing comments and, on V8, even NUL-suffixed
    // text. Store only the date it parsed, never the remote input around it.
    return fromEpoch(ms);
  };
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return fromText(value);
  if (typeof value === "number") return fromEpoch(value);
  if (typeof value === "object") {
    const d = (value as Record<string, unknown>)["$date"];
    if (typeof d === "number") return fromEpoch(d);
    if (typeof d === "string") return fromText(d);
  }
  throw fail();
}

/**
 * Resolve TrueNAS's old/new certificate expiry aliases without letting a
 * preferred null mask a valid fallback. Every present field is parsed: an
 * unreadable alias is contract drift even when its peer is valid, and two
 * different valid instants are a conflict rather than an arbitrary choice.
 */
function resolveCertificateExpiry(
  until: unknown,
  notAfter: unknown,
  safe: Safe,
): string | null {
  const parsed = [until, notAfter]
    .filter((value) => value !== undefined)
    .map((value) => toIsoOrNull(value, safe));
  const known = parsed.filter((value): value is string => value !== null);
  if (new Set(known).size > 1) {
    throw new Error(
      "certificate.query returned conflicting `until` and `not_after` " +
        "expiry values; refused before writing either one",
    );
  }
  return known[0] ?? null;
}

/**
 * `auth.login_with_api_key` is deprecated and scheduled for removal in
 * TrueNAS 27. `auth.login_ex` with the API_KEY_PLAIN mechanism is the
 * replacement, but it also requires a `username`, which this model does not
 * currently collect. Rather than ship an auth path that has never been run
 * against a real host, support is capped explicitly and the limit is stated
 * wherever an operator can actually hit it.
 *
 * That last part was the defect. The hint used to live *only* in the
 * post-connect warning below, which runs after `system.info` -- i.e. only on a
 * run where authentication already succeeded. On the host the hint exists for,
 * the one where the call is gone, auth is what fails, `system.info` never runs
 * and the warning never printed. The operator got a bare RPC error and no
 * explanation. So the hint is now attached to the auth failure itself
 * (AUTH_REMOVAL_HINT, used in discover()), and this warning covers the other
 * case: a 27+ host where the deprecated call still happens to work, which is a
 * heads-up rather than a diagnosis.
 */
const AUTH_REMOVAL_HINT =
  "If this host is TrueNAS 27 or newer, auth.login_with_api_key has been " +
  "removed: this model has not moved to auth.login_ex, which additionally " +
  "requires a username it does not collect.";

function warnIfVersionUnsupported(
  version: string,
  logger: { warning: (msg: string, props?: Record<string, unknown>) => void },
  safe: Safe,
): void {
  const m = version.match(/(\d{2,4})\.(\d{1,2})\.(\d{1,2})/);
  if (!m) return;
  const major = Number(m[1]);
  if (Number.isFinite(major) && major >= 27) {
    logger.warning(
      "TrueNAS reports version {version}; auth.login_with_api_key is " +
        "scheduled for removal starting with 27. It still worked this run, " +
        "but this model has not moved to auth.login_ex, so a later upgrade " +
        "will break discovery.",
      // Remote free text; bound it like every other remote string that
      // reaches a log line.
      { version: safe(version, 64) },
    );
  }
}

/**
 * A single inbound frame, after validation.
 *
 * `notification` covers a well-formed frame with no id: middlewared pushes
 * `collection_update` events down the same socket, and those correlate to
 * nothing we sent. They are dropped silently -- flagging them would turn a
 * normal TrueNAS behaviour into a warning on every run.
 */
type RpcFrame =
  | { kind: "notification" }
  | { kind: "result"; id: number; result: unknown }
  | { kind: "error"; id: number; message: string }
  | { kind: "invalid"; id?: number; detail: string };

/**
 * Validate an inbound JSON-RPC frame before anything correlates on it.
 *
 * The old code did `msg = JSON.parse(...)` and immediately asserted the
 * result was a `Record<string, unknown>`, then `const id = msg.id as number`.
 * Every one of the following was a real outcome of that:
 *
 *   - A frame of `null`, or a bare number/string/array. `msg.id` on `null`
 *     throws a TypeError inside `ws.onmessage`, which is not inside any
 *     try/catch and not attached to any promise, so it escapes as an
 *     unhandled error while the pending call sits waiting for its timeout.
 *   - A STRING id. `#pending` is keyed by number, so `get("3")` misses, the
 *     reply is dropped on the floor, and the call fails the full timeoutSec
 *     later reporting "timed out waiting for pool.query" -- a diagnosis
 *     pointing at the network for what is a protocol mismatch.
 *   - `error: 0` or `error: ""`. `if (msg.error)` is false for both, so the
 *     frame took the SUCCESS branch and resolved the call with
 *     `result: undefined`. For `auth.login_with_api_key` that lands on
 *     `authed !== true` and reports a revoked API key; for `pool.query` it
 *     lands on the non-array guard. Both blame the wrong thing.
 *   - `error` present as a string or array. `e.message` is then undefined and
 *     the error reads "TrueNAS RPC failure: [undefined]", which says nothing
 *     at all.
 *   - Neither `result` nor `error`. Silently resolved with undefined.
 *
 * Anything that fails validation is reported as such -- rejecting the pending
 * call immediately when the id is usable, so the caller gets the protocol
 * fault instead of a timeout that misdescribes it.
 */
function classifyFrame(raw: unknown, safe: Safe): RpcFrame {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    const what = raw === null
      ? "null"
      : Array.isArray(raw)
      ? "an array"
      : `a ${typeof raw}`;
    return {
      kind: "invalid",
      detail: `frame is ${what}, not a JSON-RPC object`,
    };
  }
  const m = raw as Record<string, unknown>;
  if (m.jsonrpc !== "2.0") {
    return {
      kind: "invalid",
      id: typeof m.id === "number" && Number.isSafeInteger(m.id)
        ? m.id
        : undefined,
      detail: `frame declares jsonrpc ${safe(m.jsonrpc, 32)}, not "2.0"`,
    };
  }
  if (!("id" in m)) {
    if (
      "result" in m || "error" in m || typeof m.method !== "string" ||
      m.method.trim() === ""
    ) {
      return {
        kind: "invalid",
        detail:
          "frame without an id is not a JSON-RPC notification with a method",
      };
    }
    if (
      "params" in m &&
      (m.params === null || typeof m.params !== "object")
    ) {
      return {
        kind: "invalid",
        detail: "notification params is neither an array nor an object",
      };
    }
    return { kind: "notification" };
  }
  if (m.id === null) {
    return {
      kind: "invalid",
      detail: "frame id is null; this client sends integer ids",
    };
  }
  if (typeof m.id !== "number" || !Number.isSafeInteger(m.id)) {
    return {
      kind: "invalid",
      detail: `frame id is ${safe(m.id, 32)} (${typeof m.id}), not the ` +
        `integer this client sends; the reply cannot be matched to a call`,
    };
  }
  const id = m.id;
  if ("method" in m || "params" in m) {
    return {
      kind: "invalid",
      id,
      detail: "response frame also carries notification members",
    };
  }
  const hasResult = "result" in m;
  // Presence, not truthiness or value. `error: 0` and `error: null` are both
  // invalid error members, and neither can make a simultaneous result valid.
  const hasError = "error" in m;
  if (hasError && hasResult) {
    return {
      kind: "invalid",
      id,
      detail: "frame carries both result and error",
    };
  }
  if (hasError) {
    const e = m.error;
    if (e === null || typeof e !== "object" || Array.isArray(e)) {
      return {
        kind: "invalid",
        id,
        detail: `error member is ${safe(e, 32)} (${typeof e}), not an object`,
      };
    }
    const eo = e as Record<string, unknown>;
    if (typeof eo.code !== "number" || !Number.isSafeInteger(eo.code)) {
      return {
        kind: "invalid",
        id,
        detail: `error.code is ${safe(eo.code, 32)}, not an integer`,
      };
    }
    if (typeof eo.message !== "string") {
      return {
        kind: "invalid",
        id,
        detail: `error.message is ${typeof eo.message}, not a string`,
      };
    }
    return { kind: "error", id, message: eo.message };
  }
  if (!hasResult) {
    return {
      kind: "invalid",
      id,
      detail: "frame carries neither a result nor an error member",
    };
  }
  return { kind: "result", id, result: m.result };
}

/** The WebSocket surface this client needs, shared by the bounded production
 * client and the in-memory test transport. */
interface RpcSocket {
  url: string;
  onopen: (() => void) | null;
  onerror: ((event: unknown) => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onclose: (() => void) | null;
  send(data: string): void;
  close(): void;
}

type OpenWebSocket = (url: string) => RpcSocket;

/**
 * The browser-compatible WebSocket API exposes a complete message only after
 * the runtime has assembled it, so an `onmessage` length check is too late to
 * be a memory bound. `ws` enforces maxPayload while receiving fragments and
 * defines the limit in bytes. Compression and redirects are disabled so the
 * bound and the destination both remain literal.
 */
const openBoundedWebSocket: OpenWebSocket = (url) =>
  new WsWebSocket(url, {
    followRedirects: false,
    maxPayload: MAX_FRAME_BYTES,
    perMessageDeflate: false,
  }) as unknown as RpcSocket;

/** Return only structured, locally defined WebSocket diagnostics. Runtime
 * prose may echo the full URL, whose path is operator input and may contain a
 * credential unrelated to apiKey. */
function webSocketFailure(
  event: unknown,
  phase: "connect" | "message",
): string {
  const error = event && typeof event === "object"
    ? (event as { error?: unknown }).error
    : undefined;
  const code = error && typeof error === "object"
    ? (error as { code?: unknown }).code
    : undefined;
  if (code === "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH") {
    return `TrueNAS WebSocket message exceeded the ${MAX_FRAME_BYTES}-byte limit`;
  }
  const safeCode = typeof code === "string" && /^[A-Z0-9_]+$/.test(code)
    ? ` (${code})`
    : "";
  return phase === "connect"
    ? `TrueNAS WebSocket connection failed${safeCode}`
    : `TrueNAS WebSocket protocol failure${safeCode}`;
}

function throwIfAborted(signal: AbortSignal, phase: string): void {
  if (signal.aborted) throw new Error(`aborted ${phase}`);
}

/**
 * Minimal JSON-RPC 2.0 client over one WebSocket. TrueNAS keys responses by
 * request id, so calls are correlated through a pending-map rather than
 * assuming ordered replies.
 */
class TrueNasRpc {
  #ws: RpcSocket;
  #signal: AbortSignal;
  #onProtocolError: (detail: string) => void;
  #safe: Safe;
  #id = 0;
  #pending = new Map<
    number,
    {
      method: string;
      resolve: (v: unknown) => void;
      reject: (e: Error) => void;
    }
  >();
  #closed = false;

  private constructor(
    ws: RpcSocket,
    signal: AbortSignal,
    onProtocolError: (detail: string) => void,
    safe: Safe,
  ) {
    this.#ws = ws;
    this.#signal = signal;
    this.#onProtocolError = onProtocolError;
    this.#safe = safe;
    ws.onmessage = (ev) => {
      // maxPayload has already bounded the assembled message in bytes. This
      // check is about protocol type, not size: binary is refused rather than
      // stringified into "[object Blob]" and misreported as malformed JSON.
      if (typeof ev.data !== "string") {
        this.#failAll(
          `TrueNAS sent a non-text WebSocket frame; this client speaks ` +
            `JSON-RPC text frames only`,
        );
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(ev.data as string);
      } catch (e) {
        this.#failAll(
          `malformed frame: ${this.#safe((e as Error).message)}`,
        );
        return;
      }
      const frame = classifyFrame(parsed, this.#safe);
      if (frame.kind === "notification") return;
      if (frame.kind === "invalid") {
        // Fail the waiting call rather than letting it run out its timeout
        // and report a network problem for a protocol one. With no usable
        // id there is nothing to fail, so it is logged and dropped.
        const waiter = frame.id !== undefined
          ? this.#pending.get(frame.id)
          : undefined;
        if (waiter && frame.id !== undefined) {
          this.#pending.delete(frame.id);
          waiter.reject(
            new Error(
              `TrueNAS sent an invalid JSON-RPC frame: ${frame.detail}`,
            ),
          );
        } else {
          this.#failAll(
            `TrueNAS sent an invalid JSON-RPC frame: ${frame.detail}`,
          );
        }
        return;
      }
      const waiter = this.#pending.get(frame.id);
      if (!waiter) {
        this.#failAll(
          "TrueNAS sent a JSON-RPC response for an unknown or duplicate " +
            "request id",
        );
        return;
      }
      this.#pending.delete(frame.id);
      if (frame.kind === "error") {
        waiter.reject(
          new Error(
            waiter.method === "auth.login_with_api_key"
              // Authentication takes the key as its only argument. Remote
              // prose can echo a partial, escaped, or transformed key that no
              // literal redactor can enumerate, so none of that prose crosses
              // the error boundary. The numeric code is also omitted: a
              // number- or date-shaped misconfiguration must not escape the
              // string-only credential boundary through a primitive field.
              ? "TrueNAS RPC authentication failed"
              : `TrueNAS RPC failure: ${this.#safe(frame.message)}`,
          ),
        );
      } else {
        waiter.resolve(frame.result);
      }
    };
    ws.onclose = () => {
      this.#closed = true;
      for (const [, w] of this.#pending) {
        w.reject(new Error("connection closed before reply"));
      }
      this.#pending.clear();
    };
    ws.onerror = (event) => this.#failAll(webSocketFailure(event, "message"));
  }

  /**
   * Abandon the connection: every waiting call is rejected with the same
   * reason and the socket is closed.
   *
   * Used for faults that are not attributable to one request id -- an
   * over-limit message is refused by the receiver and a non-text frame is
   * refused before parsing, so neither has an id to blame. Dropping such a
   * fault silently would leave every call to
   * die of its own timeout and report "timed out waiting for pool.query",
   * which points at the network for what is a host refusing to speak the
   * protocol.
   */
  #failAll(detail: string): void {
    this.#onProtocolError(detail);
    this.#closed = true;
    for (const [, w] of this.#pending) w.reject(new Error(detail));
    this.#pending.clear();
    this.close();
  }

  /**
   * @param assertDestination Re-checks the socket's OWN reported URL at open
   *   time, before the caller is handed a connection it can authenticate on.
   *   See assertConnectedDestination() for what this is defending against.
   */
  static connect(
    wsUrl: string,
    timeoutMs: number,
    signal: AbortSignal,
    safe: Safe,
    openWebSocket: OpenWebSocket,
    onProtocolError: (detail: string) => void = () => {},
    assertDestination: (connectedUrl: string) => void = () => {},
  ): Promise<TrueNasRpc> {
    return new Promise((resolve, reject) => {
      // An AbortSignal that is ALREADY aborted before we get here never fires
      // another "abort" event, so the listener registered below would never
      // run. The old code therefore opened the socket for a run that had
      // already been cancelled -- and the very first thing discover() does on
      // a connected socket is send auth.login_with_api_key, i.e. it put the
      // plaintext API key on the wire for work nobody was waiting for, then
      // reported the eventual hang as "timed out connecting" rather than
      // "aborted". Check the flag before anything else, socket included.
      if (signal.aborted) {
        reject(new Error("aborted before connecting"));
        return;
      }
      let settled = false;
      let ws: RpcSocket;
      try {
        ws = openWebSocket(wsUrl);
      } catch {
        reject(new Error("cannot open TrueNAS WebSocket"));
        return;
      }
      const cleanup = () => {
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        ws.onopen = null;
      };
      const failOnce = (err: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        // `ws` emits an error when close() aborts a handshake that has not
        // opened yet. Removing the handler first turns that expected cleanup
        // event into an uncaught EventEmitter error. Keep a sink until close
        // completes; a successful connection immediately replaces this with
        // the runtime protocol handler in the TrueNasRpc constructor.
        ws.onerror = () => {};
        ws.onclose = () => {
          ws.onerror = null;
          ws.onclose = null;
        };
        try {
          ws.close();
        } catch { /* already closing */ }
        reject(err);
      };
      const timer = setTimeout(() => {
        failOnce(new Error("timed out connecting to TrueNAS WebSocket"));
      }, timeoutMs);
      const onAbort = () => failOnce(new Error("aborted"));
      signal.addEventListener("abort", onAbort, { once: true });
      ws.onopen = () => {
        if (settled) {
          // A late open arriving after we already failed this connection
          // (timeout, abort, or a prior error event) -- close it rather
          // than leaving an authenticated-capable socket open and
          // unreferenced.
          try {
            ws.close();
          } catch { /* already closing */ }
          return;
        }
        // The scheme and host checks that ran over `baseUrl` describe where
        // we ASKED to go. This one is about where we actually arrived, and it
        // runs before the caller can send anything -- the first thing
        // discover() does with a resolved connection is put the API key on
        // it, so any check that happens after resolve() happens after the
        // credential has already left.
        try {
          // `ws.url`, with no `|| wsUrl` behind it. That fallback substituted
          // the destination we WANTED for the one the socket reported, so a
          // socket that named no destination at all passed a check about
          // where it had landed -- the check failing open on exactly the
          // runtime it could not vouch for. A socket that cannot say where it
          // is does not get the API key.
          assertDestination(ws.url);
        } catch (e) {
          failOnce(e as Error);
          return;
        }
        settled = true;
        cleanup();
        resolve(new TrueNasRpc(ws, signal, onProtocolError, safe));
      };
      ws.onerror = (ev) => {
        failOnce(new Error(webSocketFailure(ev, "connect")));
      };
    });
  }

  call(method: string, params: unknown[], timeoutMs: number): Promise<unknown> {
    if (this.#closed) return Promise.reject(new Error("connection closed"));
    // Same reason as connect(): addEventListener("abort", ...) on a signal
    // that has already aborted never fires, so the old code fell straight
    // through to #ws.send() and wrote the request -- for the auth call, the
    // API key itself -- to a socket belonging to a cancelled run, then sat
    // there for the full timeout waiting on a reply nobody wanted. The abort
    // can land between connect() resolving and this call starting, so the
    // guard has to be here as well, not only in connect().
    if (this.#signal.aborted) {
      return Promise.reject(new Error(`aborted before sending ${method}`));
    }
    const id = ++this.#id;
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(new Error(`aborted waiting for ${method}`));
      };
      const settle = () => {
        clearTimeout(timer);
        this.#signal.removeEventListener("abort", onAbort);
      };
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        this.#signal.removeEventListener("abort", onAbort);
        reject(new Error(`timed out waiting for ${method}`));
      }, timeoutMs);
      this.#pending.set(id, {
        method,
        resolve: (v) => {
          settle();
          resolve(v);
        },
        reject: (e) => {
          settle();
          reject(e);
        },
      });
      this.#signal.addEventListener("abort", onAbort, { once: true });
      this.#ws.send(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    });
  }

  close() {
    try {
      this.#ws.close();
    } catch { /* already closing */ }
  }
}

type DiscoverContext = {
  signal: AbortSignal;
  globalArgs: Record<string, unknown>;
  modelType: string;
  modelId: string;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
    warning: (msg: string, props?: Record<string, unknown>) => void;
  };
  // deno-lint-ignore no-explicit-any
  writeResource: (...a: any[]) => Promise<any>;
  dataRepository: {
    findAllForModel: (
      t: string,
      id: string,
    ) => Promise<Array<{ name: string }>>;
    delete: (t: string, id: string, name: string) => Promise<void>;
  };
};

async function discoverWithSocket(
  _args: unknown,
  ctx: DiscoverContext,
  openWebSocket: OpenWebSocket,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  // One boundary for every remote-supplied string in this run: bounded,
  // key-redacted, control/bidi screened. Built here because it needs the key,
  // and threaded rather than duplicated so no site can be missed.
  const safe: Safe = (value, max) => safeRemoteText(value, g.apiKey, max);
  const base = assertBaseUrl(
    g.baseUrl,
    g.apiKey,
    g.allowInsecureHttp,
    g.allowedHosts,
  );
  // Built from the parsed URL's components, not by pasting "/api/current"
  // onto the raw argument. The old concatenation swapped the scheme with a
  // regex and appended blindly, so anything after the host that was not a
  // plain path (a query string, a fragment) ended up in front of the path
  // segment it was supposed to precede. assertBaseUrl now rejects those, and
  // rebuilding here means the endpoint path is correct by construction rather
  // than by the argument happening to be well shaped.
  const wsScheme = base.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${wsScheme}//${base.host}/api/current`;
  const timeoutMs = g.timeoutSec * 1000;

  // The resolved URL is sensitive operator input. It is validated above but
  // never copied into logs or errors; authentication belongs only in the RPC
  // body and the local diagnostic is sufficient.
  ctx.logger.info("connecting to TrueNAS");

  const rpc = await TrueNasRpc.connect(
    wsUrl,
    timeoutMs,
    ctx.signal,
    safe,
    openWebSocket,
    (detail) =>
      ctx.logger.warning("TrueNAS RPC protocol issue: {detail}", { detail }),
    // Checked again once the socket is open, against where it says it landed
    // rather than where we aimed it. assertBaseUrl ran on a string; this runs
    // on the connection the key is about to be sent over.
    (connected) => assertConnectedDestination(connected, wsUrl, g.allowedHosts),
  );

  let sysRaw: unknown, poolsRaw: unknown, disksRaw: unknown;
  let alertsRaw: unknown, certsRaw: unknown;
  try {
    // Both auth failure paths carry AUTH_REMOVAL_HINT. The version warning
    // further down only runs after system.info, so it is unreachable on a host
    // where auth.login_with_api_key has been removed -- which is the single
    // case the hint was written for. See the comment on AUTH_REMOVAL_HINT.
    let authed: unknown;
    try {
      authed = await rpc.call(
        "auth.login_with_api_key",
        [g.apiKey],
        timeoutMs,
      );
    } catch (e) {
      const err = e as Error;
      // Not on a cancellation. An aborted run failed for a reason that has
      // nothing to do with the deprecated call, and pointing an operator at
      // TrueNAS 27 when they hit Ctrl-C is worse than saying nothing.
      if (ctx.signal.aborted) throw err;
      throw new Error(`${err.message} ${AUTH_REMOVAL_HINT}`);
    }
    if (authed !== true) {
      throw new Error(
        `TrueNAS rejected the API key. Check it has not been revoked. ${AUTH_REMOVAL_HINT}`,
      );
    }

    // One call per object type over the single authenticated connection.
    // disk.query needs extra.pools: true -- pool joining defaults to false,
    // and without it every disk's `pool` field comes back empty.
    [sysRaw, poolsRaw, disksRaw, alertsRaw, certsRaw] = await Promise.all([
      rpc.call("system.info", [], timeoutMs),
      rpc.call("pool.query", [], timeoutMs),
      rpc.call("disk.query", [[], { extra: { pools: true } }], timeoutMs),
      rpc.call("alert.list", [], timeoutMs),
      rpc.call("certificate.query", [], timeoutMs),
    ]);
  } finally {
    rpc.close();
  }

  throwIfAborted(ctx.signal, "after collecting responses");

  // ---- validate every response before writing or pruning anything --------
  // A malformed non-array result used to be silently treated as an empty
  // list, which would then prune every existing resource of that kind on
  // the next step. Throw instead: partial-but-wrong data must never look
  // like "nothing exists any more."
  for (
    const [label, raw] of [
      ["pool.query", poolsRaw],
      ["disk.query", disksRaw],
      ["alert.list", alertsRaw],
      ["certificate.query", certsRaw],
    ] as const
  ) {
    if (!Array.isArray(raw)) {
      // The type is the diagnostic fact; the payload is a bounded preview.
      // This used to stringify the entire unexpected response into the
      // message, which put an unbounded amount of remote text -- hostnames,
      // share paths, alert prose -- into whatever log caught the throw.
      throw new Error(
        `TrueNAS ${label} returned a non-array result (${typeof raw}): ${
          safe(raw)
        }`,
      );
    }
  }

  // Enforce collection ceilings BEFORE Zod can traverse every element and
  // accumulate one issue per bad row. The schema maxima below remain as a
  // second contract check, not as the resource-exhaustion boundary.
  if (
    sysRaw !== null && typeof sysRaw === "object" && !Array.isArray(sysRaw)
  ) {
    assertRawArrayLength(
      (sysRaw as Record<string, unknown>).loadavg,
      "system.info loadavg",
      MAX_LOADAVG_ENTRIES,
    );
  }
  for (
    const [label, raw] of [
      ["pool.query", poolsRaw],
      ["disk.query", disksRaw],
      ["alert.list", alertsRaw],
      ["certificate.query", certsRaw],
    ] as const
  ) {
    assertRawArrayLength(raw, label, MAX_ROWS);
  }

  // Everything downstream is per-row work the far end would otherwise choose
  // the amount of: a SHA-256, an instance name, and a permanent record.
  const rows = <T extends z.ZodType>(schema: T, label: string) =>
    z.array(schema).max(MAX_ROWS, {
      message:
        `TrueNAS ${label} returned more than ${MAX_ROWS} rows; that is not a ` +
        `NAS inventory, and each row costs a hashed identity and a permanent ` +
        `record`,
    });

  const sys = RawSystemSchema.parse(sysRaw ?? {});
  const pools = rows(RawPoolSchema, "pool.query").parse(poolsRaw);
  const disks = rows(RawDiskSchema, "disk.query").parse(disksRaw);
  const alerts = rows(RawAlertSchema, "alert.list").parse(alertsRaw);
  const certs = rows(RawCertificateSchema, "certificate.query").parse(certsRaw);

  warnIfVersionUnsupported(sys.version, ctx.logger, safe);

  /**
   * Every write this run intends to make, built in full before any of them
   * happens.
   *
   * The README and the method description both promise all-or-nothing, and
   * the code did not deliver it: `system` was written, then pools, then
   * disks, and only somewhere in the middle of that did parsePercent() or
   * toIsoOrNull() get a chance to throw on a value they refuse to guess at.
   * A host whose fifth certificate carried an unreadable expiry left behind a
   * `system` record, a summary-less set of pools and disks, and no summary --
   * a datastore holding half of one run and half of the previous one, with
   * nothing marking which half was which. Deriving everything first and
   * writing second makes the guarantee structural: the last thing that can
   * throw now happens before the first thing that can persist.
   */
  const planned: PlannedWrite[] = [];
  const generationId = crypto.randomUUID();
  throwIfAborted(ctx.signal, "before planning resources");

  // ---- system -------------------------------------------------------------
  // `?? 0` here wrote a real-looking number for a field TrueNAS never sent.
  // uptimeSeconds was the sharp one: 0 is the value a box that just rebooted
  // reports, so a "rebooted recently" gate fired on every run where the field
  // was simply absent. UNKNOWN_NUMBER + metricsKnown separates the two.
  const metricsKnown = sys.cores != null && sys.physmem != null &&
    sys.uptime_seconds != null;
  const hostname = safeOrUnknown(sys.hostname, safe, 128);
  const version = safeOrUnknown(sys.version, safe, 64);
  const systemModel = safeOrUnknown(sys.model, safe, 128);
  planned.push({
    kind: "system",
    name: "system",
    fields: {
      generationId,
      hostname,
      version,
      model: systemModel,
      cores: sys.cores ?? UNKNOWN_NUMBER,
      physmemBytes: sys.physmem ?? UNKNOWN_NUMBER,
      uptimeSeconds: sys.uptime_seconds ?? UNKNOWN_NUMBER,
      // An absent loadavg stays []. Unlike a number, an empty array is not
      // mistakable for a reading: there is no element to compare against.
      loadavg: sys.loadavg ?? [],
      metricsKnown,
    },
    tags: {
      generationId,
      // A tag is a selector, so a bidi override or an ESC sequence in a
      // hostname is worse here than in a field: it changes what the operator
      // believes they are selecting.
      hostname,
      metricsKnown: String(metricsKnown),
    },
  });

  // ---- pools --------------------------------------------------------------
  let poolsUnhealthy = 0;
  let poolsCapacityUnknown = 0;
  for (const p of pools) {
    throwIfAborted(ctx.signal, "while planning pools");
    // The worst instance of the `?? 0` class. A pool reporting neither
    // `allocated` nor `free` was written sizeBytes: 0, usedPercent: 0, and
    // `usedPercent > 90` then read as "plenty of room" on a pool whose fill
    // level was in fact unknown. Both fields are needed for either number to
    // mean anything, so they are known together or not at all.
    const capacityKnown = p.allocated != null && p.free != null;
    if (!capacityKnown) poolsCapacityUnknown++;
    const allocated = capacityKnown ? p.allocated! : UNKNOWN_NUMBER;
    const free = capacityKnown ? p.free! : UNKNOWN_NUMBER;
    const size = capacityKnown ? allocated + free : UNKNOWN_NUMBER;
    // `healthy: null` (the key is present -- RawPoolSchema now requires that
    // much -- but carries no value) is treated as NOT healthy on purpose. For
    // capacity, guessing benign is the danger, so an unknown capacity gets a
    // sentinel; for a HEALTH field the safe direction is inverted. An
    // unreadable health is not a healthy pool, and erring toward "unhealthy"
    // produces a visible alert an operator resolves, where erring toward
    // "healthy" produces silence over a degraded array.
    const healthy = p.healthy === true;
    if (!healthy) poolsUnhealthy++;
    const poolName = safeOrUnknown(p.name, safe, 128);
    const poolStatus = safeOrUnknown(p.status, safe, 64);
    const poolIdentity = identityParts(["name", p.name], ["id", p.id]);
    const name = await instanceName(
      "pool",
      g.apiKey,
      safe,
      ...poolIdentity,
    );
    planned.push({
      kind: "pool",
      name,
      fields: {
        generationId,
        name: poolName,
        status: poolStatus,
        healthy,
        allocatedBytes: allocated,
        freeBytes: free,
        sizeBytes: size,
        usedPercent: !capacityKnown
          ? UNKNOWN_NUMBER
          : size > 0
          ? Math.round((allocated / size) * 1000) / 10
          : 0,
        // parsePercent still defaults an ABSENT fragmentation to 0, and that
        // stays: unlike capacity, 0% fragmentation is not itself an alarming
        // value, so a gate reading it cannot be lulled the way a capacity
        // gate could. Argued rather than swept in with the rest of the class.
        // A MALFORMED or out-of-range fragmentation is a different fact and
        // now throws rather than reporting the same reassuring 0. It throws
        // during PLANNING, before anything is written, which is what makes
        // that throw all-or-nothing rather than mid-write.
        fragmentationPercent: parsePercent(p.fragmentation ?? null, safe),
        capacityKnown,
      },
      tags: {
        generationId,
        healthy: String(healthy),
        status: poolStatus,
        capacityKnown: String(capacityKnown),
      },
    });
  }

  // ---- disks --------------------------------------------------------------
  for (const d of disks) {
    throwIfAborted(ctx.signal, "while planning disks");
    // Same class as the pool capacity above: a disk whose `size` TrueNAS did
    // not report was written sizeBytes: 0, which reads as a real (and absurd)
    // capacity rather than as an absent one.
    const sizeKnown = d.size != null;
    // Absent key vs. present-and-null, kept apart. `d.pool ?? "none"` said
    // "this disk belongs to no pool" for both, and only one of them means
    // that: the other means the extra.pools join did not happen, in which
    // case EVERY disk on the box claims to be orphaned. See `poolKnown`.
    const normalizedPool = d.pool === undefined
      ? undefined
      : d.pool === null
      ? null
      : safe(d.pool, 128) || undefined;
    const poolKnown = normalizedPool !== undefined;
    const rawId = firstNonBlankIdentity(
      ["identifier", d.identifier],
      ["devname", d.devname],
    )!;
    const diskIdentity = [rawId, ...identityParts(["serial", d.serial])];
    const name = await instanceName(
      "disk",
      g.apiKey,
      safe,
      ...diskIdentity,
    );
    planned.push({
      kind: "disk",
      name,
      fields: {
        generationId,
        name: safeOrUnknown(d.devname, safe, 128),
        serial: safeOrUnknown(d.serial, safe, 128),
        model: safeOrUnknown(d.model, safe, 128),
        sizeBytes: sizeKnown ? d.size! : UNKNOWN_NUMBER,
        type: safeOrUnknown(d.type, safe, 64),
        pool: typeof normalizedPool === "string" ? normalizedPool : "",
        sizeKnown,
        poolKnown,
      },
      tags: {
        generationId,
        pool: !poolKnown
          ? "unknown"
          : normalizedPool === null
          ? "none"
          : normalizedPool,
        type: safeOrUnknown(d.type, safe, 64),
        sizeKnown: String(sizeKnown),
        poolKnown: String(poolKnown),
      },
    });
  }

  // ---- alerts -------------------------------------------------------------
  let silenced = 0;
  let alertsContentUnknown = 0;
  for (const a of alerts) {
    throwIfAborted(ctx.signal, "while planning alerts");
    const dismissed = a.dismissed;
    if (dismissed) silenced++;
    // A null or screened-empty `klass`, `level` or `formatted` is the alert
    // arriving without the thing that makes it an alert. It used to be written
    // as "", which is
    // indistinguishable from an ordinary field a gate happens not to match --
    // so a CRITICAL condition could sit in the datastore, be counted in
    // `summary.alerts`, and be matched by no severity gate on the box. The
    // value is not fabricated: class and level read the self-naming
    // "UNKNOWN" (the same convention as pool status), `contentKnown` says so
    // in a field a CEL gate can read, and the run is marked degraded. Null is
    // accepted rather than thrown on because one uninformative alert must not
    // cost the operator their pool health and certificate expiry, which came
    // off the same connection and are fine.
    const klass = a.klass == null ? "" : safe(a.klass, 128);
    const level = a.level == null ? "" : safe(a.level, 64);
    const formatted = a.formatted == null
      ? ""
      : safe(a.formatted, MAX_STORED_REMOTE_CHARS);
    const contentKnown = klass !== "" && level !== "" && formatted !== "";
    if (!contentKnown) alertsContentUnknown++;
    const rawId = firstNonBlankIdentity(
      ["uuid", a.uuid],
      ["id", a.id],
      ["key", a.key],
    )!;
    const alertIdentity = [rawId, ...identityParts(["klass", a.klass])];
    const name = await instanceName(
      "alert",
      g.apiKey,
      safe,
      ...alertIdentity,
    );
    planned.push({
      kind: "alert",
      name,
      fields: {
        generationId,
        id: safe(rawId.value, 128),
        klass: klass || "UNKNOWN",
        level: level || "UNKNOWN",
        // The one stored field that is entirely remote prose. Kept in full
        // (up to 4,096 code points) rather than dropped -- an alert you cannot
        // read is an alert you cannot act on, and the disclosure this carries
        // is stated in the README Security section rather than papered over.
        // What is removed is the ability of that prose to be unbounded in an
        // infinite-lifetime record, to carry the API key back to us, or to
        // drive the terminal of whoever runs `swamp data list`.
        //
        // A null stays "" here rather than becoming "UNKNOWN": unlike class
        // and level this field is not a selector, and inventing prose that
        // reads like the alert's own text would be worse than an empty one.
        // `contentKnown` is what says the text is missing.
        formatted,
        dismissed,
        // A dismissed alert is hidden in the TrueNAS UI but the condition
        // behind it is still true. Surface it rather than inherit the
        // dismissal.
        silenced: dismissed,
        contentKnown,
      },
      tags: {
        generationId,
        // "UNKNOWN" in a tag, not "": a selector that matches every alert
        // whose level TrueNAS omitted is useful; one that reads as an empty
        // string is how they went unnoticed.
        level: level || "UNKNOWN",
        klass: klass || "UNKNOWN",
        silenced: String(dismissed),
        contentKnown: String(contentKnown),
      },
    });
  }

  // ---- certificates -------------------------------------------------------
  let expiringSoon = 0, expired = 0, withoutExpiry = 0;
  for (const c of certs) {
    throwIfAborted(ctx.signal, "while planning certificates");
    // Parse both aliases. A null/blank `until` must not mask a valid
    // `not_after`, and two different valid values are contract drift rather
    // than a choice this model is entitled to make.
    const notAfter = resolveCertificateExpiry(c.until, c.not_after, safe);
    const days = notAfter === null ? Number.NaN : daysUntil(notAfter);
    const isExpired = Number.isFinite(days) && days < 0;
    const soon = Number.isFinite(days) && days >= 0 && days <= g.certWarnDays;
    if (isExpired) expired++;
    if (soon) expiringSoon++;
    if (!Number.isFinite(days)) withoutExpiry++;
    // RawCertificateSchema now refuses a row with neither a usable `id` nor a
    // `name`, and firstNonBlankIdentity prevents a blank id from masking a
    // usable name, so this is a real identifier rather than possibly "". That is
    // what removed the `idx<n>` fallback the other kinds still carry: a
    // certificate named by its POSITION in the response gets a different
    // record every time TrueNAS reorders the list, which moves expiry history
    // between certificates and prunes records for certificates still on the
    // box. There is no benign reading of that, and unlike a disk there is no
    // partial identity worth keeping, so the row is refused upstream instead.
    const rawId = firstNonBlankIdentity(["id", c.id], ["name", c.name])!;
    // Prefix is `cert-` while the resource kind is `certificate`. Reviewed and
    // kept: the instance name is the record's identity in the datastore, so
    // renaming the prefix orphans every stored certificate record -- the next
    // run prunes all of them and writes new ones, losing their history -- to
    // buy nothing but a tidier spelling. The prefix is documented in the
    // README instead. (Note the prune protection above keys on `pool-`/`disk-`
    // for the same reason: prefixes here are load-bearing, not cosmetic.)
    const commonName = firstNonBlankIdentity(
      ["common", c.common],
      ["common_name", c.common_name],
    );
    const certificateIdentity = [rawId, ...(commonName ? [commonName] : [])];
    const name = await instanceName(
      "cert",
      g.apiKey,
      safe,
      ...certificateIdentity,
    );
    planned.push({
      kind: "certificate",
      name,
      fields: {
        generationId,
        name: safeOrUnknown(c.name, safe, 128),
        commonName: safeOrUnknown(commonName?.value, safe, 253),
        notAfter: notAfter ?? "",
        daysRemaining: Number.isFinite(days) ? days : -9999,
        expiryKnown: Number.isFinite(days),
        expiringSoon: soon,
        expired: isExpired,
      },
      tags: {
        generationId,
        expiringSoon: String(soon),
        expired: String(isExpired),
        expiryKnown: String(Number.isFinite(days)),
      },
    });
  }

  // ---- summary ------------------------------------------------------------
  // An empty pool.query or disk.query is reported as such, unconditionally,
  // instead of rolling up as "0 pools, 0 of them unhealthy" -- which is what
  // a perfectly healthy NAS with nothing wrong also looks like. See
  // SummarySchema.discoveryDegraded for why this flags rather than throws.
  const poolsReportedEmpty = pools.length === 0;
  const disksReportedEmpty = disks.length === 0;
  const inventoryReportedEmpty = poolsReportedEmpty || disksReportedEmpty;
  // Alerts that carry no class or level degrade the run for the same reason
  // an empty pool list does: the roll-up otherwise reads clean while a fact
  // the gates are written against is missing underneath it.
  const discoveryDegraded = inventoryReportedEmpty || alertsContentUnknown > 0;
  throwIfAborted(ctx.signal, "before planning summary");
  planned.push({
    kind: "summary",
    name: "summary",
    fields: {
      generationId,
      generationComplete: true,
      hostname,
      version,
      pools: pools.length,
      poolsUnhealthy,
      poolsCapacityUnknown,
      disks: disks.length,
      alerts: alerts.length,
      alertsSilenced: silenced,
      alertsContentUnknown,
      certificates: certs.length,
      certificatesExpiringSoon: expiringSoon,
      certificatesExpired: expired,
      certificatesWithoutExpiry: withoutExpiry,
      poolsReportedEmpty,
      disksReportedEmpty,
      discoveryDegraded,
      syncedAt: new Date().toISOString(),
    },
    tags: {
      generationId,
      generationComplete: "true",
      poolsUnhealthy: String(poolsUnhealthy),
      poolsCapacityUnknown: String(poolsCapacityUnknown),
      alertsContentUnknown: String(alertsContentUnknown),
      certsExpiring: String(expiringSoon),
      discoveryDegraded: String(discoveryDegraded),
    },
  });

  // ---- write --------------------------------------------------------------
  // Nothing above this line touched the datastore. Every response has been
  // parsed, every derived value computed, every instance name hashed, every
  // output checked against its resource schema, and every duplicate derived
  // identity rejected. Nothing that remains can fail on the DATA.
  //
  // It can still fail on the DATASTORE, and that is not the same thing. Each
  // record is its own writeResource() call, there is no transaction to enrol
  // them in, and a datastore that dies on the fourth of nine calls leaves
  // three records from this generation next to five from the last one. The
  // README used to call this "all or nothing" and that was simply not true.
  //
  // What is true, and is now structural: before any resource or prune, write
  // `summary.generationComplete:false` with the same generationId carried by
  // every planned record. Only after every write and delete succeeds is that
  // summary replaced with `generationComplete:true`. A datastore failure can
  // still leave mixed records, but it cannot leave the previous healthy
  // summary looking current; the incomplete marker and IDs identify exactly
  // which records belong to the interrupted generation.
  throwIfAborted(ctx.signal, "before writing resources");
  assertPlanWritable(planned);
  const handles = [];
  const live = new Set(planned.map((w) => w.name));
  const commit = planned.find((w) => w.kind === "summary");
  if (!commit) {
    throw new Error("internal error: TrueNAS generation has no summary");
  }
  await ctx.writeResource(
    commit.kind,
    commit.name,
    { ...commit.fields, generationComplete: false },
    { tags: { ...commit.tags, generationComplete: "false" } },
  );
  for (const w of planned) {
    if (w.kind === "summary") continue;
    throwIfAborted(ctx.signal, "while writing resources");
    handles.push(
      await ctx.writeResource(w.kind, w.name, w.fields, { tags: w.tags }),
    );
  }

  // Prune anything the box no longer reports, resolved alerts especially.
  // This uses dataRepository.findAllForModel/delete directly rather than
  // context.readResource because readResource addresses one named instance.
  // There is no "list every stored instance for this model" call in the
  // readResource surface, and bulk stale-resource pruning genuinely needs
  // one. Bulk stale-resource pruning therefore uses the repository surface.
  //
  // A kind that came back COMPLETELY empty is not evidence that the kind is
  // gone, and the validation above cannot tell the two apart: `[]` is a
  // well-formed array, so it passes and no name of that kind enters `live`.
  // pool.query answers `[]` while ZFS is still importing after a reboot or
  // update, and while a pool is failing to import at all; disk.query
  // answering `[]` has no legitimate steady state on a NAS. The old code
  // took that single empty response as authoritative and hard-deleted every
  // stored pool-*/disk-* record in one pass, during exactly the window a
  // pool is missing. Protect those two prefixes when the kind is empty but
  // the datastore still holds records for it. Alerts and certificates are deliberately
  // NOT protected: an empty alert list is the normal healthy state and a
  // resolved alert must be pruned or it is reported forever.
  const protectedPrefixes: string[] = [];
  if (poolsReportedEmpty) protectedPrefixes.push("pool-");
  if (disksReportedEmpty) protectedPrefixes.push("disk-");

  throwIfAborted(ctx.signal, "before finding stale resources");
  const existing = await ctx.dataRepository.findAllForModel(
    ctx.modelType,
    ctx.modelId,
  );
  throwIfAborted(ctx.signal, "after finding stale resources");
  let keptStale = 0;
  for (const rec of existing) {
    throwIfAborted(ctx.signal, "while pruning stale resources");
    if (live.has(rec.name)) continue;
    if (protectedPrefixes.some((p) => rec.name.startsWith(p))) {
      keptStale++;
      continue;
    }
    await ctx.dataRepository.delete(ctx.modelType, ctx.modelId, rec.name);
    // A datastore name may be legacy, injected, or derived under older rules.
    // The delete itself still needs the exact name; the log does not.
    ctx.logger.info("pruned one stale TrueNAS resource");
  }

  // Complete the marker only after every record and prune succeeded. This is
  // the only part of the write path whose ORDER is a guarantee.
  throwIfAborted(ctx.signal, "before committing summary");
  handles.push(
    await ctx.writeResource(commit.kind, commit.name, commit.fields, {
      tags: commit.tags,
    }),
  );
  // Warned on the EMPTY RESPONSE, not on having kept something. The old
  // `if (keptStale > 0)` made the warning conditional on prior state, so the
  // single run where it matters most -- a first run, or the first run after a
  // datastore reset, where no stale record exists to keep -- discovered
  // nothing and said nothing at all, and the summary underneath it read as a
  // clean bill of health. The kept-record sentence is now the part that is
  // conditional.
  // Gated on the EMPTY INVENTORY specifically, not on discoveryDegraded,
  // which now has a second cause: this sentence is entirely about pools and
  // disks and would be a misdiagnosis if it fired for an alert that arrived
  // without a level.
  if (inventoryReportedEmpty) {
    ctx.logger.warning(
      "TrueNAS reported {pools} pool(s) and {disks} disk(s). An empty pool " +
        "or disk list is not a steady state on a NAS: it is what a pool " +
        "still importing (or failing to import) after a reboot looks like. " +
        "summary.discoveryDegraded is true for this run, so gate on that " +
        "rather than on the counts. Kept {kept} existing record(s) rather " +
        "than deleting them. Once any object of that kind is reported again, " +
        "records that really did go away are pruned on that run; if the last " +
        "pool or disk was genuinely removed, delete the stale record by hand.",
      { pools: pools.length, disks: disks.length, kept: keptStale },
    );
  }
  // Said out loud rather than left to the flag. An alert with no class or
  // level is the one kind of record whose absence of content is invisible
  // exactly where it matters -- in a severity gate, which simply does not
  // match it and reports nothing wrong.
  if (alertsContentUnknown > 0) {
    ctx.logger.warning(
      "TrueNAS sent {count} alert(s) with no class, level or text. Their " +
        "class and level read UNKNOWN and `contentKnown` is false on those " +
        "records: a severity gate cannot match them, so they are counted in " +
        "summary.alertsContentUnknown and this run is flagged " +
        "discoveryDegraded rather than rolled up as if every alert were " +
        "readable.",
      { count: alertsContentUnknown },
    );
  }

  ctx.logger.info(
    "discovered {pools} pool(s), {disks} disk(s), {alerts} alert(s) " +
      "({silenced} silenced), {certs} certificate(s)",
    {
      pools: pools.length,
      disks: disks.length,
      alerts: alerts.length,
      silenced,
      certs: certs.length,
    },
  );

  return { dataHandles: handles };
}

/** The public model path always uses the byte-bounded client. Tests instrument
 * a non-exported copy of the constructor expression for their in-memory
 * transport; no runtime input can replace this factory. */
const discover = (_args: unknown, ctx: DiscoverContext) =>
  discoverWithSocket(_args, ctx, openBoundedWebSocket);

/**
 * Test-only surface. Not part of the model contract, not addressed by any
 * workflow, and not referenced anywhere inside this file.
 *
 * It exists because several of the properties this module now guarantees are
 * invisible from `model` alone -- that the raw schemas STRIP undeclared keys
 * instead of retaining them, that two identity tuples differing only by a
 * control character get different digests, that a malformed JSON-RPC frame is
 * classified rather than cast. A fix nobody can observe is a fix that ships
 * dead, which has happened in this repo often enough to be the rule these
 * exports exist to break.
 */
export const __testOnly = {
  assertConnectedDestination,
  assertNoApiKeyInGeneratedName,
  RawSystemSchema,
  RawPoolSchema,
  RawDiskSchema,
  RawAlertSchema,
  RawCertificateSchema,
  classifyFrame,
  encodeIdentity,
  identityPart,
  instanceName,
  parsePercent,
  safeRemoteText,
  toIsoOrNull,
};

/**
 * The `@jpisgeek/truenas` model definition: a single `discover` method
 * producing five read-only resource types (system, pool, disk, alert,
 * certificate) plus a `summary` roll-up. See the module header above for
 * the JSON-RPC migration story and why certificate expiry is tracked
 * independently of TrueNAS's own alert state, which a dismissal can hide.
 */
export const model = {
  type: "@jpisgeek/truenas",
  version: "2026.09.05.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    system: {
      description:
        "Host identity, version, CPU, memory, uptime, load. `metricsKnown` " +
        "is false when TrueNAS omitted cores/memory/uptime; those read -1 " +
        "rather than 0 so an absent uptime cannot look like a fresh reboot.",
      schema: SystemSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    pool: {
      description: "One record per ZFS pool with status, health, capacity, " +
        "fragmentation. Check `capacityKnown` before gating on capacity: " +
        "when TrueNAS reports no allocated/free the four capacity fields are " +
        "-1, not 0, so an unknown pool cannot read as an empty one.",
      schema: PoolSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    disk: {
      description:
        "One record per physical disk and its pool membership. Missing " +
        "name, serial, model, or type reads `UNKNOWN`. `sizeKnown` " +
        "is false when TrueNAS reported no size; `sizeBytes` is then -1. " +
        "`poolKnown` is false when TrueNAS did not answer the pool-membership " +
        "question at all or answered with screened-empty text, which is a " +
        "different fact from a disk that is in no pool; the tag reads " +
        "`unknown` there, never `none`.",
      schema: DiskSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    alert: {
      description:
        "One record per active TrueNAS alert. `silenced` marks alerts that " +
        "were dismissed in the UI. Still true, just no longer visible there. " +
        "`contentKnown` is false when TrueNAS sent no usable class, level " +
        "or text: " +
        "class and level then read `UNKNOWN` rather than an empty string, " +
        "because an alert no severity gate can match must not look like an " +
        "ordinary one.",
      schema: AlertSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    certificate: {
      description:
        "One record per certificate with days remaining; missing name/commonName " +
        "reads `UNKNOWN`. Tracked independently of TrueNAS alert state so a " +
        "dismissed expiry warning cannot hide a cert that is about to lapse.",
      schema: CertificateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    summary: {
      description: "Single roll-up of the most recent discover. Require " +
        "`generationComplete` and consume only records carrying its " +
        "`generationId`; then gate on `discoveryDegraded` before trusting " +
        "the counts. It is true when " +
        "pool.query or disk.query came back empty, which is what an " +
        "importing pool looks like and is indistinguishable from a healthy " +
        "box by the counts alone, and true when any alert arrived without " +
        "usable class, level or text (`alertsContentUnknown`).",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  methods: {
    discover: {
      description:
        "Read-only sweep of system info, pools, disks, alerts, and " +
        "certificates in one pass. Writes one resource per object plus a " +
        "summary, and prunes objects the box no longer reports. The five " +
        "sub-fetches are issued together; every response is parsed, every " +
        "derived value computed, every resource schema checked, and every " +
        "duplicate identity rejected before the first write. Any failure " +
        "therefore aborts with nothing written or pruned. The writes " +
        "themselves are not a transaction -- the datastore offers none -- " +
        "so `summary.generationComplete:false` is written before any " +
        "resource or prune. Every record carries that summary's " +
        "`generationId`; only after all writes and deletes succeed is the " +
        "summary replaced with `generationComplete:true`.",
      arguments: DiscoverArgsSchema,
      execute: discover,
    },
  },
};
