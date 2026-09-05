/**
 * Proton Pass vault provider for swamp.
 *
 * Secrets stay in Proton Pass. This provider shells out to the official
 * `pass-cli` on demand and copies no secret into swamp's own storage, into
 * this repository, or into any file: it writes no files and caches no value
 * between calls. That is a claim about THIS extension, not about the host --
 * `pass-cli` keeps its own local database and has ordinary filesystem access,
 * and the earlier wording ("nothing is ever copied onto disk") promised
 * something no caller of a subprocess is in a position to guarantee.
 * `${{ vault.get('<your-vault>', '<YOUR_ITEM>') }}` resolves live at run time.
 *
 * Secret key forms accepted by `get()` (placeholders, not real item names).
 * The split is at the FIRST slash, which the examples below used to
 * contradict:
 *   "<item>"                     -> that item, field = defaultField
 *   "<item>/<field>"             -> that item, that field
 *
 * An item title containing a slash therefore cannot be addressed at all.
 * Everything after the first slash is the field name, slashes included, so
 * "<item>/a/b" asks for a field literally named "a/b".
 *
 * READ-ONLY, AND TITLE-ONLY. Two surfaces were removed rather than hardened.
 * `put()` accounted for 10 of 39 review blocks across six rounds, every one a
 * way for a non-idempotent write to be misreported; `pass://SHARE_ID/ITEM_ID`
 * accounted for 14, because it carried a second identity scheme that had to be
 * parsed, grammar-checked, canonicalised, share-bound and liveness-checked
 * separately from the one the item listing already provides. Adding validation
 * to either kept adding surface for the next reviewer to read. Removing them
 * is the only change in this file that made the thing smaller.
 *
 * The cost is real and is not hidden: titles can be edited in the Proton Pass
 * UI and item IDs cannot, so renaming an item breaks any key that names it.
 * There is no longer a stable-across-rename address.
 */
import { z } from "npm:zod@4";

/**
 * Characters that must never reach a diagnostic string.
 *
 * Cc  C0/C1 controls -- NUL truncates a log line at the consumer, CR/LF start
 *     a NEW one, and ESC opens a terminal control sequence.
 * Cf  format controls -- U+202E RIGHT-TO-LEFT OVERRIDE reverses the display of
 *     everything after it, so a key can be made to render as a different key.
 * Zl/Zp  U+2028/U+2029, line and paragraph separators: a second way to end a
 *     line that plain \n filtering misses.
 *
 * Why this matters here specifically: every failure in this file interpolates
 * operator-supplied text (secret key, item title, field name, vault name) into
 * an exception, and those exceptions land verbatim in swamp run logs and run
 * reports. A key of `Item\n2026-01-01 12:00:00 INFO vault.get ok` therefore
 * writes a SECOND, forged line into the run log that reads exactly like a real
 * one -- a log-forgery primitive handed to whoever can name a secret key. An
 * ESC sequence in the same position can clear the operator's terminal or
 * rewrite lines already printed above it.
 */
const CONTROL_CHARS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/**
 * Longest secret key this provider will even look at.
 *
 * Not a message bound -- those exist separately -- but an ALGORITHM bound. The
 * separator-collision check walks every slash in the key and folds and scans
 * the whole inventory at each one, so key length multiplies inventory size.
 * A Proton title has a practical limit far below this; anything longer is not
 * a title someone typed.
 */
const MAX_SECRET_KEY = 1024;

/**
 * Reject control characters in a configured value.
 *
 * Config is validated once, at provider construction, so a malformed vault
 * config fails loudly at load rather than at the first secret lookup -- and
 * `vaultName` in particular is interpolated into nearly every error this file
 * raises.
 */
const plainText = (label: string) =>
  z.string()
    // A blank or whitespace-only value is not a value. Accepting one let an
    // empty `binary` select an undefined program and an empty `vaultName`
    // address an undefined vault -- both of which then failed somewhere far
    // from the configuration that caused them, or worse, silently resolved to
    // a default. Refuse at the boundary where the name is still attached.
    .refine((v) => v.trim().length > 0, {
      message: `${label} must not be empty or whitespace-only`,
    })
    .refine((s) => !CONTROL_CHARS.test(s), {
      message:
        `${label} must not contain control characters (newlines, NUL, or terminal ` +
        `escapes): it is interpolated into errors that are written to swamp run ` +
        `logs and reports, where a newline forges a log line.`,
    });

// strictObject, not object: a non-strict schema STRIPS unknown keys, so a
// misspelled `binary` (or `binaray`, `Binary`, `bin`) vanished silently and
// the provider fell back to resolving `pass-cli` off PATH -- i.e. a typo in a
// security-sensitive setting quietly selected a different program than the
// operator configured. Unknown keys are now a configuration error.
/** The one executable name the standard install-location fallback applies to. */
const DEFAULT_BINARY = "pass-cli";

/**
 * The one grammar every Proton id is held to, wherever it arrives from.
 *
 * `=` may only PAD, and only at the end: `/^[A-Za-z0-9_=-]+$/` accepted `A=B`
 * and `A====`, which are not base64url at all, so two spellings that a decoder
 * would treat as one value could be checked as two different ids.
 *
 * THE LENGTH RULE IS ENFORCED. This comment said the opposite for several
 * rounds, arguing that a canonical LENGTH would be specific to Proton and not
 * safely knowable. That was true when it was written and stopped being true
 * when the real CLI was run: every id a real vault returns is 86 base64url
 * characters plus `==`, correctly padded, with zero pad bits. What actually
 * went wrong the first time was the FIXTURES -- short invented ids like `ID1`
 * -- not the rule.
 */
/** Base64url alphabet used to validate canonical identifier padding bits. */
export const B64URL =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Length of the base64url BODY of every id pass-cli 2.3.2 emits -- item, share
 * and vault alike -- excluding the two `=` of padding. 86 characters is 64
 * encoded bytes.
 */
const PROTON_ID_BODY_LENGTH = 86;

/** Validate the observed identifier length, alphabet and pad bits; return its unpadded form. */
export function canonicalId(raw: string): string | undefined {
  const body = raw.replace(/=+$/, "");
  const pad = raw.length - body.length;
  if (body === "") return undefined;
  if (!/^[A-Za-z0-9_-]+$/.test(body)) return undefined;
  const rem = body.length % 4;
  // A LENGTH RULE, at last, and on evidence rather than assumption. I refused
  // to add one twice, on the grounds that Proton ids might be random strings
  // over the base64url alphabet rather than encodings of bytes -- and the
  // first attempt did refuse `ID1` and took 27 tests down with it. That was
  // the FIXTURES being unreal, not the rule being wrong: every id a real vault
  // returns is 88 characters, 86 of base64url plus `==`, with correct padding
  // and zero pad bits. The README has claimed base64url throughout; the code
  // only now means it.
  //
  // THE OBSERVED LENGTH, enforced. Documenting "86 base64url characters plus
  // `==`" while accepting `TQ==` meant malformed identity data crossed the
  // fail-closed boundary wearing a valid-looking shape -- and an id is the
  // thing every binding in this file compares.
  //
  // The trade is stated in the README and it is real: this is an OBSERVATION
  // of pass-cli 2.3.2, not a promise Proton has made. A build issuing ids of
  // another length refuses every lookup here rather than resolving a wrong
  // one. That is the fail-closed stance this file takes everywhere else, and
  // the failure is loud, immediate, and says exactly what to change.
  if (body.length !== PROTON_ID_BODY_LENGTH) return undefined;
  // No `rem === 1` check: with the length fixed at 86, `rem` is always 2, so
  // the impossible-remainder case cannot arise. It was live until the length
  // rule landed, and a mutation audit reported it UNGUARDED the moment it
  // stopped being reachable.
  // Padding, when present at all, must be the amount this length needs.
  if (pad !== 0 && pad !== (rem === 0 ? 0 : 4 - rem)) return undefined;
  // A final character carrying bits a decoder would discard is a SECOND
  // spelling of a value that already has one, and two spellings that decode
  // alike are exactly what canonicalisation exists to collapse.
  if (rem !== 0) {
    const unused = rem === 2 ? 4 : 2;
    if ((B64URL.indexOf(body[body.length - 1]) & ((1 << unused) - 1)) !== 0) {
      return undefined;
    }
  }
  return body;
}

const ConfigSchema = z.strictObject({
  vaultName: plainText("vaultName")
    .describe("Proton Pass vault to read from, e.g. '<your-vault>'"),
  defaultField: plainText("defaultField")
    .default("password")
    .describe("Item field used when the secret key names no field"),
  timeoutSec: z
    .number()
    .int()
    .positive()
    .max(300)
    .default(30)
    .describe(
      "How long any single pass-cli call may take, in whole seconds, 1 to " +
        "300. It reaches Proton's servers, so an unbounded call can hang for " +
        "as long as the network allows. The range is enforced by the schema " +
        "and was previously enforced without being stated anywhere.",
    ),
  binary: plainText("binary")
    // REFUSED AT LOAD, not at first use. resolveBinary rejects a relative path
    // and a non-sanctioned bare name, but it runs on the first lookup -- so a
    // config this provider considers malformed was accepted at construction
    // and only complained about later, while the source claimed configuration
    // errors fail at load. Same rule, moved to where the claim says it is.
    .refine(
      (v) => v === DEFAULT_BINARY || v.startsWith("/"),
      `must be the bare name '${DEFAULT_BINARY}' or an absolute path`,
    )
    .default(DEFAULT_BINARY)
    .describe(
      "pass-cli executable. Left as a bare name it is resolved against PATH " +
        "and then a list of known install locations, because non-login " +
        "contexts (ssh, launchd, cron, a daemon) often lack Homebrew's bin " +
        "directory on PATH.",
    ),
});

/**
 * Longest run of caller- or CLI-derived text this provider will put into an
 * exception.
 *
 * Every string interpolated into an error here is bounded, not just the one
 * that was noticed first: secret keys, item titles, field names and the
 * configured vault name are all attacker- or operator-supplied and all land in
 * the same place -- swamp run logs and reports. An unbounded one turns a
 * failed lookup into a log-flooding primitive, and bounding a single call site
 * only moves which string does it.
 *
 * WHAT THIS DOES NOT DO, deliberately: it does not redact. Secret KEYS, item
 * titles and the vault name stay legible in errors. Review raised replacing
 * them with opaque correlation ids; that was declined and the reasoning is
 * here rather than in a commit message. These identifiers are the operator's
 * own input -- already sitting in the model definition that asked for the
 * secret -- so the log gains nothing it did not already have, while a
 * correlation id costs the one thing a secrets provider must give up on
 * failure: which lookup failed. `Secret 'x/y' not found in vault 'z'` is
 * actionable; `lookup 4f2a failed` sends the operator hunting for a mapping
 * table that does not exist. The secret VALUE is a different matter and is
 * never interpolated anywhere in this file.
 */
const MAX_ERROR_TEXT = 120;

/**
 * Render control characters as visible escapes.
 *
 * Bounding a string is not the same as making it safe to write down. A
 * 30-character key is well under MAX_ERROR_TEXT and can still contain CR/LF
 * (a forged run-log line), NUL (a truncated one at whatever reads the log),
 * ESC (a terminal control sequence that rewrites lines already printed), or
 * U+202E (which reverses how everything after it renders, so the key shown to
 * the operator is not the key that was asked for). `clip()` used to hand all
 * of that through unchanged.
 *
 * Escaping rather than stripping: the operator must still be able to tell that
 * their key had a stray newline in it, and two different keys must not collapse
 * to the same rendering.
 */
function escapeControl(s: string): string {
  return s.replace(new RegExp(CONTROL_CHARS, "gu"), (c) => {
    const code = c.codePointAt(0)!;
    return code <= 0xff
      ? `\\x${code.toString(16).padStart(2, "0")}`
      : `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

/**
 * Bound one interpolated string, and neutralise anything in it that could
 * corrupt or forge the log line it lands in. Never applied to the secret
 * VALUE, which is never interpolated at all.
 *
 * Escape FIRST, then bound: escaping expands (one byte becomes four), so
 * bounding first would let a 120-character run of ESCs become a 480-character
 * message fragment. The reported length is the ORIGINAL length, which is the
 * number the operator recognises.
 */
export function clip(s: string, max = MAX_ERROR_TEXT): string {
  const safe = escapeControl(s);
  return safe.length <= max
    ? safe
    : `${safe.slice(0, max)}...(${s.length} chars)`;
}

/**
 * Refuse a caller-supplied locator that carries control characters.
 *
 * `clip()` above makes such a string SAFE TO PRINT; this makes it never worth
 * printing. A secret key with a newline in it cannot address a real Proton
 * Pass item -- item titles do not contain them -- so it is a mistake at best
 * and an attempt to write a chosen line into the run log at worst. Refusing at
 * the entry point also means the CLI is never invoked with it, and the refusal
 * itself is escaped, so the refusal cannot be the forged line either.
 */
/**
 * The ONLY variables pass-cli is given.
 *
 * Both spawns used to inherit swamp's entire environment. That environment is
 * shared with every other extension in the run, so it can hold API tokens for
 * unrelated providers, proxy and TLS overrides that redirect or downgrade
 * traffic, and whatever the operator exported into the shell that launched
 * swamp -- all handed to an executable this provider already documents as
 * only as trustworthy as the PATH it was found on. A substituted `pass-cli`
 * did not need to exfiltrate anything: it was passed the credentials on
 * arrival.
 *
 * Each name earns its place. PATH so the CLI can find its own helpers, HOME
 * because pass-cli keeps its config there and macOS resolves the login
 * Keychain through it, USER/LOGNAME for the same OS integration, TMPDIR for
 * scratch space, the LANG/LC_* trio so output encoding is not locale-mangled,
 * and the XDG and D-Bus names because that is how a Linux session exposes its
 * secret store. SSH_AUTH_SOCK is deliberately ABSENT: it is a live credential
 * channel and nothing here needs it.
 */
const ENV_ALLOWLIST = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_RUNTIME_DIR",
  "DBUS_SESSION_BUS_ADDRESS",
] as const;

/**
 * Is this VALUE fit to pass on, given what the name is for?
 *
 * Allowlisting the names was half the job. A name on the list still carried
 * whatever the surrounding environment put in it, and several of these names
 * are instructions rather than data: the path-valued ones redirect where
 * pass-cli looks for its own config and helpers, and
 * `DBUS_SESSION_BUS_ADDRESS` selects a TRANSPORT -- `unix:` is a local socket,
 * but the same variable accepts `tcp:host=...`, which would point the secret
 * store at somewhere else entirely with no TLS in sight.
 *
 * A value that fails its rule is DROPPED rather than corrected. The child then
 * behaves as it would with the variable unset, which is a state it already has
 * to handle, and this provider does not get into the business of repairing
 * someone's environment.
 */
function envValueIsUsable(name: string, value: string): boolean {
  // Control characters make no sense in any of these and are how one variable
  // becomes two on the far side of something that splits on newlines.
  if (CONTROL_CHARS.test(value)) return false;
  if (value.length > 4096) return false;
  switch (name) {
    // Directory-valued: an absolute path or nothing.
    case "HOME":
    case "TMPDIR":
    case "XDG_CONFIG_HOME":
    case "XDG_DATA_HOME":
    case "XDG_RUNTIME_DIR":
      return value.startsWith("/");
    // A LOCAL socket only. The resolution walk already refuses relative PATH
    // entries; this is the same rule for the other variable that names where
    // something is reached.
    case "DBUS_SESSION_BUS_ADDRESS":
      // A D-BUS ADDRESS IS A SEMICOLON-SEPARATED LIST, and a client is free to
      // use any element of it. `startsWith("unix:")` therefore passed
      // `unix:path=/ok;tcp:host=example,port=1` -- a local socket with a
      // cleartext TCP fallback welded on behind it. Every element must be a
      // unix socket, or the variable is not passed at all.
      return value.split(";").every((part) => part.startsWith("unix:"));
    default:
      return true;
  }
}

function childEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const name of ENV_ALLOWLIST) {
    let value: string | undefined;
    try {
      value = Deno.env.get(name);
    } catch {
      // A narrower --allow-env than this list is a legitimate way to run the
      // provider, and it should tighten the child's environment rather than
      // fail the lookup outright.
      continue;
    }
    if (value === undefined) continue;
    if (!envValueIsUsable(name, value)) continue;
    if (name === "PATH") {
      // THE CHILD GETS THE SAME RULE THE WALK DOES. Resolution skips relative
      // and empty PATH entries, and then handed the raw PATH to the child --
      // so `.` or an empty component could still select an executable from the
      // working directory, just one step further out, if pass-cli invokes a
      // helper. An entry we would not resolve through is not an entry we pass
      // on.
      const safe = value.split(":").filter((d) => d.startsWith("/"));
      if (safe.length === 0) continue;
      env[name] = safe.join(":");
      continue;
    }
    env[name] = value;
  }
  return env;
}

/**
 * Bound the key before anything reads it.
 *
 * The separator-collision check visits every slash and the control-character
 * check scans the whole string, so caller-chosen length drives caller-chosen
 * cost. This runs before either.
 */
function rejectOversizedKey(secretKey: string): void {
  if (secretKey.length <= MAX_SECRET_KEY) return;
  throw new Error(
    `Secret key is too long: this provider accepts at most ` +
      `${MAX_SECRET_KEY} characters, and an item title cannot usefully be ` +
      `longer than that.`,
  );
}

function rejectControlChars(what: string, s: string): void {
  if (!CONTROL_CHARS.test(s)) return;
  throw new Error(
    `${what} '${clip(s)}' contains a control character. Newlines, NUL and ` +
      `terminal escapes are refused here because this string is written to ` +
      `swamp run logs and reports, where they forge or corrupt log lines.`,
  );
}

/**
 * Resolve the pass-cli binary. A bare name is tried on PATH first, then at the
 * usual install prefixes. An explicit path is used as given.
 *
 * TRUST NOTE (deliberate, documented in README "Security"): whichever
 * executable answers `--version` first is the one that receives item titles,
 * vault names. Nothing here verifies ownership, signature
 * or digest, so a `pass-cli` planted earlier on PATH -- or a `binary:` path
 * pointed somewhere wrong -- is trusted. Verifying it would mean pinning a
 * digest per platform and per CLI release, which breaks on every upgrade of a
 * tool this provider does not ship. The operator's lever is `binary:` set to
 * an absolute path on a directory they control.
 */
const CANDIDATE_PATHS = [
  "/opt/homebrew/bin/pass-cli",
  "/usr/local/bin/pass-cli",
  "/home/linuxbrew/.linuxbrew/bin/pass-cli",
];
// Resolution is per call. A module cache would let one caller's environment
// choose the executable for a later provider instance with a different PATH.
const PROBE_TIMEOUT_MS = 5_000;

/** Thrown when the caller's signal aborted. Distinguishable from a timeout. */
class CancelledError extends Error {}

/**
 * Hard ceilings on what pass-cli may return in one call.
 *
 * `.output()` buffers both streams to completion with no limit, so the child
 * chose how much memory this process allocated. The per-call deadline did not
 * help: a program can emit gigabytes well inside 30 seconds, and a broken or
 * substituted CLI writing in a loop would take the whole swamp run down with
 * it, not just this lookup.
 *
 * A vault item and a vault listing are small. 4 MiB of stdout is already far
 * past anything legitimate, and 64 KiB of stderr past any real diagnostic.
 */
const MAX_STDOUT_BYTES = 4 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;

/** Thrown when the child exceeded a stream ceiling; carries no CLI text. */
class OversizedResponse extends Error {}

/**
 * Read a stream up to `limit` bytes, then stop.
 *
 * On overflow the bytes read so far are DISCARDED rather than returned
 * truncated: a half-read JSON document is a different document, and this
 * provider's whole posture is that an unreadable response is refused rather
 * than mined. The reader is cancelled so a child still writing gets EPIPE
 * instead of blocking on a full pipe forever.
 */
async function readCapped(
  stream: ReadableStream<Uint8Array>,
  limit: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        throw new OversizedResponse("stream exceeded its ceiling");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  // Backed by an explicit ArrayBuffer: Deno.CommandOutput's fields are
  // Uint8Array<ArrayBuffer>, and the default constructor widens to
  // ArrayBufferLike, which does not satisfy it.
  const out = new Uint8Array(new ArrayBuffer(total));
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

/**
 * `candidates` is a parameter, and this function is exported, for ONE reason:
 * the not-found path is otherwise untestable on any machine that actually has
 * pass-cli installed. Probing the real prefixes there resolves to the
 * operator's real CLI -- so the test would both miss the branch it is aiming
 * at and invoke a live credential tool. Production callers never pass it.
 */
export async function resolveBinary(
  configured: string,
  signal?: AbortSignal,
  candidates: readonly string[] = CANDIDATE_PATHS,
): Promise<string> {
  // CANCELLATION BEFORE ANYTHING ELSE, configuration included. A caller that
  // has already given up is told so rather than handed a complaint about a
  // `binary` value that was never going to be reached. This check has moved
  // twice: it sat after the bare-name refusal, then after the relative-path
  // refusal, and both times a cancelled call reported a configuration error.
  if (signal?.aborted) {
    throw new CancelledError("cancelled before pass-cli was located");
  }
  // An explicit path must be ABSOLUTE. `./pass-cli` and `../pass-cli` used to
  // be honoured verbatim, which resolves against whatever directory the swamp
  // process happens to be in -- so the same config selected a different
  // executable depending on the caller's cwd, and a writable working
  // directory became a way to choose the program that receives secret
  // locators. The README already tells operators to use an
  // absolute path; this makes the code agree with it.
  if (configured.includes("/")) {
    if (!configured.startsWith("/")) {
      throw new Error(
        "The 'binary' setting must be either the bare name 'pass-cli' or an " +
          "absolute path. A relative path is refused because it resolves " +
          "against the working directory of whatever process swamp happens " +
          "to run under.",
      );
    }
    return configured;
  }
  // Computed BEFORE the probe, because the refusal below has to happen before
  // the probe rather than after it.
  const usingDefaultPaths = candidates.length === CANDIDATE_PATHS.length &&
    candidates.every((c, i) => c === CANDIDATE_PATHS[i]);
  // A BARE NAME MUST BE THE SANCTIONED ONE. Any other bare name was probed on
  // PATH and then, when that failed, walked down the pass-cli install
  // prefixes -- so a configured `my-pass-cli` that is not on PATH silently ran
  // the standard pass-cli instead: a different program than the one named,
  // chosen without saying so. The README documents exactly two accepted
  // forms, and this is the code agreeing with it.
  if (configured !== DEFAULT_BINARY && usingDefaultPaths) {
    throw new Error(
      `The 'binary' setting must be either the bare name '${DEFAULT_BINARY}' ` +
        `or an absolute path. Another bare name is refused because it is ` +
        `resolved against PATH and then against the standard install ` +
        `prefixes, which means a name that is not on PATH would silently run ` +
        `a different program than the one configured.`,
    );
  }

  // Resolution is inside the caller's cancellation scope AND inside the
  // configured deadline -- run() passes the COMBINED signal, not just the
  // caller's. Probing walks up to four executables at 5s each, so with only
  // the caller's signal wired in, resolution could run 20s past a
  // `timeoutSec: 1` that the operator set precisely to bound this call, and a
  // caller that had already given up still waited out the whole walk.
  //
  // This function cannot tell WHICH source fired -- an AbortSignal.any() does
  // not say -- so it reports the generic CancelledError and run(), which holds
  // both sources, re-decides cancellation vs timeout from them.
  if (signal?.aborted) {
    throw new CancelledError("cancelled before pass-cli was located");
  }

  // Bounded. These probes ran before any timeout existed, so a hung or
  // wedged executable could block a secret lookup forever while the
  // documented per-call bound sat unused a few lines below.
  const probe = async (bin: string): Promise<boolean> => {
    const deadline = AbortSignal.timeout(PROBE_TIMEOUT_MS);
    try {
      const out = await new Deno.Command(bin, {
        args: ["--version"],
        stdin: "null",
        stdout: "null",
        stderr: "null",
        clearEnv: true,
        env: childEnv(),
        signal: signal ? AbortSignal.any([signal, deadline]) : deadline,
      }).output();
      return out.success;
    } catch {
      return false;
    }
  };

  // AN ABSOLUTE PATH, NOT A NAME. Probing the bare name proved that some
  // `pass-cli` on PATH answered `--version`, then cached the NAME -- so every
  // later call re-resolved PATH with no probe at all, and the executable that
  // passed the check need not be the executable that receives the secret. A
  // PATH entry changing between the two, or a directory earlier on PATH
  // becoming writable, is enough to separate them. Resolve to a path once,
  // probe that path, and hand that same path to every later call.
  // GUARDED like every other environment read in this file. `Deno.env.get`
  // throws a permission error when --allow-env is narrower than this name, and
  // that error is Deno's, not ours: unbounded, unescaped, and thrown from
  // outside every message discipline here. It also aborted resolution
  // entirely, so a perfectly good executable at a standard install prefix was
  // never tried. A PATH we cannot read is an empty PATH.
  let pathValue = "";
  try {
    pathValue = Deno.env.get("PATH") ?? "";
  } catch { /* narrower --allow-env than PATH: fall through to the prefixes */ }
  for (const dir of pathValue.split(":")) {
    // A RELATIVE PATH ENTRY IS SKIPPED. `PATH=.` produced `./pass-cli`, which
    // resolves against whatever directory swamp happens to run in -- exactly
    // the substitution the absolute-path rule above exists to refuse, arriving
    // by a different door. The invariant is that what this function returns is
    // absolute; entries that cannot satisfy it do not get a vote.
    if (!dir.startsWith("/")) continue;
    const abs = `${dir}/${configured}`;
    if (await probe(abs)) {
      return abs;
    }
    if (signal?.aborted) {
      throw new CancelledError("cancelled while locating pass-cli");
    }
  }
  // CANCELLATION FIRST. A caller who gave up must be told that, not told the
  // binary was missing -- the probe above returns false on abort, so without
  // this the abort was reported as a resolution failure and sent whoever read
  // the log after the wrong problem.
  if (signal?.aborted) {
    throw new CancelledError("cancelled while locating pass-cli");
  }
  // The DEFAULT list is a list of places `pass-cli` is normally installed.
  // Walking it for a different configured name meant an operator who named a
  // specific executable, and whose executable was missing, silently got the
  // standard pass-cli instead -- secret locators going to a
  // program they did not choose.
  //
  // Gated on the default list rather than on the name alone: a caller that
  // supplies its own candidates has stated where that name may live, and
  // honouring them is not substitution. Only the built-in pass-cli locations
  // are refused to a non-pass-cli name.
  // The post-probe copy of this guard is GONE. It refused a non-default bare
  // name only once the PATH probe had already failed, so a hostile name that
  // WAS on PATH was probed, accepted and returned before the guard ran -- the
  // check happened on the one path where it no longer mattered. It now runs
  // above, before any probe.
  for (const candidate of candidates) {
    // Re-checked between probes: a cancellation that arrives mid-walk should
    // stop the walk, not be reported as "could not find the binary" after
    // three more 5s probes have run to completion.
    if (signal?.aborted) {
      throw new CancelledError("cancelled while locating pass-cli");
    }
    if (await probe(candidate)) {
      return candidate;
    }
  }
  if (signal?.aborted) {
    throw new CancelledError("cancelled while locating pass-cli");
  }
  // NO PATHS IN THIS MESSAGE. `configured` is whatever the operator put in
  // `binary:` -- frequently an absolute path under their home directory or a
  // private tooling tree -- and it would be published into swamp run logs and
  // reports, which are read by people who have no business learning the
  // layout of that host. The candidate list is equally a set of local
  // filesystem paths. The operator does not need them echoed: they wrote the
  // config, and the README lists the prefixes that are searched.
  throw new Error(
    "Could not find the Proton Pass CLI. It is not on the PATH this process " +
      "sees and it is not at any of the install prefixes this provider " +
      "searches (see the README). Install it (brew install proton-pass-cli), " +
      "or set 'binary' on the vault config to an absolute path.",
  );
}

/**
 * Decide what an aborted `Deno.Command` means.
 *
 * CALLER CANCELLATION WINS. The old order asked `deadline.aborted` first, so
 * a run that hit both -- the common case, since a caller giving up and a slow
 * Proton call are the same incident -- was reported as "pass-cli did not
 * answer within Ns". That sends whoever reads the log to look at Proton's
 * availability when in fact swamp itself pulled the plug. Cancellation is the
 * more specific fact and the one the operator can act on.
 */
export function classifyAbort(
  callerAborted: boolean,
  deadlineAborted: boolean,
): "cancelled" | "timeout" | "exec-failed" {
  if (callerAborted) return "cancelled";
  if (deadlineAborted) return "timeout";
  return "exec-failed";
}

/**
 * Run pass-cli and return stdout.
 *
 * No shell is used, and every untrusted value travels joined to its option as
 * `--option=value` -- the two are different problems, and only the second
 * stops a value beginning with `-` being read as a flag by pass-cli itself.
 *
 * Every call here is a READ. The write path and the indeterminate-outcome
 * machinery it needed are gone, and so is the doc comment that used to sit
 * here describing them.
 */
async function run(
  configured: string,
  args: string[],
  opts: {
    timeoutSec?: number;
    signal?: AbortSignal;
  } = {},
): Promise<string> {
  // Bounded, and cancellable. pass-cli talks to Proton's servers, so a call
  // can hang on the network for as long as the transport allows -- and with
  // no signal wired through, a caller that had already given up was still
  // waited on. A secret lookup that never returns stalls whatever asked for
  // it, and this provider sits in the path of model runs that have their own
  // deadlines. The deadline is armed BEFORE binary resolution AND handed to
  // it, so resolution is bounded by it rather than merely measured against it
  // after the fact.
  const timeoutSec = opts.timeoutSec ?? 30;
  const deadline = AbortSignal.timeout(timeoutSec * 1000);
  const signal = opts.signal
    ? AbortSignal.any([opts.signal, deadline])
    : deadline;

  let bin: string;
  try {
    // The COMBINED signal, not opts.signal. Resolution probes up to four
    // executables at 5s each; handed only the caller's signal it ran to
    // completion after the configured deadline had already expired, so
    // `timeoutSec` bounded the pass-cli call but not the work in front of it.
    bin = await resolveBinary(configured, signal);
  } catch (cause) {
    // resolveBinary only knows "the signal fired". Which one fired is a fact
    // only this scope holds, and getting it wrong reports a blown deadline as
    // "the caller cancelled" -- sending whoever reads the log to look at
    // swamp's scheduling instead of at their own timeoutSec.
    if (cause instanceof CancelledError) {
      if (
        classifyAbort(opts.signal?.aborted ?? false, deadline.aborted) ===
          "timeout"
      ) {
        throw new Error(`pass-cli was not located within ${timeoutSec}s`);
      }
      throw cause;
    }
    // No `cause` attached, here or below: a Deno spawn rejection embeds the
    // executable path in its own message, and console.error / structured
    // loggers print the whole cause chain. Attaching it would republish
    // exactly the path these messages are careful not to name.
    if (deadline.aborted) {
      throw new Error(`pass-cli was not located within ${timeoutSec}s`);
    }
    throw cause;
  }

  // BEFORE SPAWNING. The abort check used to sit after `child.status`, which
  // stopped the RETURN but not the INVOCATION -- so a caller who had given up
  // still caused pass-cli to be run, and was then told the call was cancelled.
  // The only place to notice an abort without having already acted on it is
  // before the process exists.
  if (opts.signal?.aborted) {
    throw new CancelledError("cancelled before pass-cli was invoked");
  }
  if (deadline.aborted) {
    throw new Error(`pass-cli did not answer within ${timeoutSec}s`);
  }

  let out: Deno.CommandOutput | undefined;
  try {
    const child = new Deno.Command(bin, {
      args,
      // "null" unless something is being sent: an interactive prompt must
      // never block the call, and a closed stdin is what guarantees that.
      stdin: "null", // never let it block on an interactive prompt
      stdout: "piped",
      stderr: "piped",
      clearEnv: true,
      env: childEnv(),
      signal,
    }).spawn();
    let stdoutBytes: Uint8Array<ArrayBuffer>;
    let stderrBytes: Uint8Array<ArrayBuffer>;
    try {
      [stdoutBytes, stderrBytes] = await Promise.all([
        readCapped(child.stdout, MAX_STDOUT_BYTES),
        readCapped(child.stderr, MAX_STDERR_BYTES),
      ]);
    } catch (e) {
      // Overflow: stop the child before awaiting it, or the await blocks on a
      // process still writing into a pipe nobody is draining.
      try {
        child.kill("SIGKILL");
      } catch { /* already gone */ }
      await child.status.catch(() => {});
      // NOT COVERED BY A TEST, and marked as such rather than left to look
      // proven. Reaching it needs an overflow to be raised while an abort is
      // ALREADY set, and the abort terminates the child -- so the flood that
      // would cross the ceiling stops the moment the condition it needs
      // becomes true. Two attempts failed for that reason, one racing a caller
      // signal and one racing the deadline; both passed with this guard
      // removed. The mutation audit reports it UNGUARDED, which is accurate.
      //
      // CANCELLATION OUTRANKS THE OVERFLOW REFUSAL. A caller who gave up, or a
      // deadline that expired, is why the pipe stopped being drained -- so
      // reporting "pass-cli returned more output than this provider will read"
      // blames the remote for our own stop. The same cancellation-first rule
      // the resolution path follows, applied to the one path that skipped it:
      // this refusal is rethrown past the classifier below, so without the
      // check here nothing downstream can reclassify it.
      if (
        (opts.signal?.aborted ?? false) || deadline.aborted
      ) {
        switch (
          classifyAbort(opts.signal?.aborted ?? false, deadline.aborted)
        ) {
          case "cancelled":
            throw new CancelledError("cancelled while reading pass-cli output");
          case "timeout":
            throw new Error(`pass-cli did not answer within ${timeoutSec}s`);
        }
      }
      if (e instanceof OversizedResponse) {
        throw new UnreadableResponse(
          "pass-cli returned more output than this provider will read; " +
            "refusing it rather than parsing a partial response",
        );
      }
      throw e;
    }
    const status = await child.status;
    out = {
      success: status.success,
      code: status.code,
      signal: status.signal,
      stdout: stdoutBytes,
      stderr: stderrBytes,
    };
  } catch (spawnError) {
    // An overflow refusal is a real answer about the response and must not be
    // reclassified below as "the binary would not run".
    if (spawnError instanceof UnreadableResponse) throw spawnError;
    // The rejection itself is deliberately DROPPED rather than kept as an
    // error `cause`: Deno quotes the executable path in it, and that path is
    // the operator's own filesystem layout. `out === undefined` carries the
    // only fact needed below -- that the binary would not run at all.
    out = undefined;
  }

  // An abort does NOT necessarily reject. Deno terminates the child and hands
  // back a perfectly ordinary CommandOutput carrying the signal's exit code --
  // so a cancelled or timed-out call fell through to the CLI classifier below
  // and came back as `pass-cli failed: unclassified (exit 143)`. That reads as
  // though Proton misbehaved when in fact we killed the process. Decide from
  // the signals, which are true in the rejecting and non-rejecting case alike.
  // The abort signals are consulted even when the child SUCCEEDED. Moving from
  // .output() to spawn()+capped reads changed the failure shape: .output()
  // rejected on an already-aborted signal, whereas a spawned child can run to
  // completion and hand back a perfectly good CommandOutput. Without this, a
  // cancelled call returned the secret it was cancelled to prevent -- which is
  // precisely what "a caller signal reaches the pass-cli process" exists to
  // catch, and it caught it.
  const aborted = (opts.signal?.aborted ?? false) || deadline.aborted;
  // ABORT WINS OVER A SUCCESSFUL RESULT. Every call this provider makes is a
  // read, so a cancelled one must not hand back the secret it was cancelled to
  // prevent -- there is no non-idempotent write left for which that rule would
  // be the wrong one.
  if (out === undefined || !out.success || aborted) {
    switch (classifyAbort(opts.signal?.aborted ?? false, deadline.aborted)) {
      case "cancelled":
        throw new CancelledError("cancelled before pass-cli answered");
      case "timeout":
        throw new Error(`pass-cli did not answer within ${timeoutSec}s`);
      case "exec-failed":
        // Only a REJECTION with nothing aborted means the binary would not
        // run. A non-zero exit is pass-cli's own verdict, and it is classified
        // further down rather than here.
        if (out === undefined) {
          // The path is NOT named. `bin` is either the operator's configured
          // `binary:` value -- often an absolute path inside their home
          // directory or a private tooling tree -- or the install prefix it
          // resolved to, and this string is written to swamp run logs and
          // reports. "Which executable did swamp try" is answered by the
          // config the operator already holds; a run report is the wrong
          // place to disclose the layout of the host. `cause` is dropped for
          // the same reason: Deno's spawn rejection quotes the path, and a
          // logger that prints the cause chain would publish it anyway.
          throw new Error(
            "Could not execute the configured pass-cli binary. Is the Proton " +
              "Pass CLI installed (brew install proton-pass-cli), and is " +
              "'binary' on the vault config pointing at it?",
          );
        }
        break;
    }
  }

  if (out === undefined) {
    // Unreachable, and narrowed rather than asserted. "confirmed" is the only
    // verdict that skips the block above, and it is only produced when the
    // child succeeded, so `out` is defined on every path that reaches here.
    // The compiler cannot follow that through the verdict, and a real refusal
    // is worth more than a `!` that would silently be wrong if the reasoning
    // above ever stopped holding.
    throw new UnreadableResponse("pass-cli produced no output to read");
  }

  // macOS keeps the pass-cli database key in the login Keychain, which a
  // non-GUI session cannot reach. Say so plainly rather than surfacing a raw
  // -25308.
  const stderrPeek = new TextDecoder().decode(out.stderr);
  if (/User interaction is not allowed|-25308/.test(stderrPeek)) {
    throw new Error(
      "pass-cli cannot reach the macOS login Keychain from this context " +
        "(errSecInteractionNotAllowed). It works from a GUI login session " +
        "or a LaunchAgent in that session, but not over plain ssh, from a " +
        "LaunchDaemon, or from cron.",
    );
  }

  // FATAL. The lossy default rewrote every invalid byte to U+FFFD, so a
  // malformed response could be repaired into well-formed JSON on the way in
  // -- silently altering a title, an id, or the secret itself, and then
  // parsing cleanly. A response that is not valid UTF-8 is a broken response,
  // not one to guess at. stderr below stays lossy on purpose: it is only ever
  // pattern-matched for classification and never becomes a value.
  let stdout: string;
  try {
    stdout = new TextDecoder("utf-8", { fatal: true }).decode(out.stdout);
  } catch {
    throw new UnreadableResponse(
      "pass-cli returned bytes that are not valid UTF-8",
    );
  }
  const stderr = new TextDecoder().decode(out.stderr).trim();

  // pass-cli reports some failures with exit 0, on stdout AND on stderr, so
  // neither the code nor one stream decides this alone. Only stdout was
  // examined, so a process that exited cleanly with an `Error:` on stderr --
  // and whatever happened to be on stdout, valid or stale -- was read as
  // healthy and mined for a secret.
  if (!out.success || /^Error:/m.test(stdout) || /^Error:/m.test(stderr)) {
    // NEVER put raw stdout into an error: for `item view` it is the whole
    // item -- secret included -- and an exception string ends up in run
    // logs and reports. Only the `Error:` lines from stdout are read, and
    // even those are read only to classify.
    const stdoutErrors = stdout
      .split("\n")
      .filter((l) => /^Error:/.test(l))
      .join(" ")
      .trim();
    // Classify, do not forward. stderr is pass-cli's, not ours: it can echo
    // the arguments it was given -- which include vault and item names -- and
    // whatever the server said. The verdict is enough to act on; the text is
    // not ours to publish into a run log.
    const detail = classifyCliFailure(stderr, stdoutErrors, out.code);
    // Surface the actionable case rather than a raw CLI dump.
    if (detail === "session-not-usable") {
      throw new Error(
        `Proton Pass session is not usable: ${detail}. ` +
          `Run 'pass-cli login' (or attach a personal access token for ` +
          `unattended runs).`,
      );
    }
    throw new Error(`pass-cli failed: ${detail}`);
  }
  return stdout;
}

/**
 * Reduce a pass-cli failure to a fixed verdict.
 *
 * The matching reads the full text; only the verdict escapes. Exception
 * strings from this provider land in swamp run logs and reports, and the
 * whole reason this extension was a publish blocker at its first review was
 * output reaching an error path -- forwarding stderr verbatim is the same
 * mistake with a different source.
 *
 * The README's Security section lists this exact set. A verdict added here
 * without being added there is caught by the doc/code test.
 */
export const CLI_VERDICTS = [
  "session-not-usable",
  "vault-not-found",
  "item-not-found",
  "field-not-found",
  "permission-denied",
  "network-failure",
  "unclassified",
] as const;

/** Map CLI output to a fixed failure category without returning raw remote text. */
export function classifyCliFailure(
  stderr: string,
  stdoutErrors: string,
  code: number,
): string {
  const text = `${stderr}\n${stdoutErrors}`;
  const patterns: [RegExp, string][] = [
    // ANCHORED TO PHRASES, not to bare words. `session` and `token` matched
    // anywhere in any CLI text, so an item genuinely called "Session Token" --
    // or any field error mentioning either word -- was reported as an
    // authentication failure, sending the operator to re-login over a missing
    // field. The words are far too common in a password manager's own output
    // to carry a verdict on their own.
    [
      /not logged in|session (expired|invalid|not usable)|no active session|unauthor|invalid token|token (expired|invalid)/i,
      "session-not-usable",
    ],
    // Vault before item: "vault X not found" contains "not found", so the
    // generic rule matched first and mislabelled a missing VAULT as a missing
    // ITEM -- which sends whoever is debugging to look for the wrong thing.
    [/vault .*not found|unknown vault|no such vault/i, "vault-not-found"],
    // Specific before generic, and this ordering is the whole correctness of
    // the table. "field does not exist" contains "does not exist", so with the
    // generic rule first the field-not-found verdict was UNREACHABLE -- a
    // missing field was reported as a missing item, sending whoever is
    // debugging to look for the wrong thing. Same class as the vault/item pair
    // above, which had already been fixed once; the field case was missed.
    // Any new pattern goes above every pattern its text could also match.
    [/field .*(not found|does not exist)|no such field/i, "field-not-found"],
    [/not found|no such item|does not exist/i, "item-not-found"],
    [/permission|denied|forbidden/i, "permission-denied"],
    [
      /network|timed? ?out|connection|dns|resolve|could not reach|unreachable/i,
      "network-failure",
    ],
  ];
  for (const [re, verdict] of patterns) if (re.test(text)) return verdict;
  // Only the exit code, which is a small integer, joins the fixed word.
  // The exit code is appended deliberately, and it is the ONLY thing in any
  // verdict that varies: a small integer produced by the process, never text
  // from pass-cli or from Proton. Without it "unclassified" is unactionable.
  // Documented in the README rather than quietly widening the closed set.
  return `unclassified (exit ${code})`;
}

// ---------------------------------------------------------------------------
// Response schemas.
//
// These schemas ARE the contract with pass-cli. Every location this provider
// reads a secret or an inventory row from is named below; nothing else in a
// response is looked at, and a document that matches none of them is refused
// rather than mined.
//
// What this replaces: a recursive walk that searched EVERY nested object for a
// key matching the requested field name and returned the first string it hit.
// On any response shape the CLI had not been pinned to -- a wrapper carrying
// share metadata, a diagnostics blob, an error envelope that happens to nest a
// `password` -- that walk would return an unrelated string AS THE SECRET, with
// nothing to show it had. Depth-bounding narrowed the blast radius; it did not
// make the search exact. Naming the locations does.
// ---------------------------------------------------------------------------

/**
 * The `content` wrapper keys Proton uses for a custom field's value, and the
 * ONLY keys a value is ever read from.
 *
 * What this closes: the old reader returned the FIRST string it iterated past
 * inside `content`, whatever the key was called. Proton's own serialisation
 * puts a label beside the value for some field types, and a CLI build or an
 * error envelope this provider has not been pinned to can put anything there.
 * For `{"Label":"EXAMPLE_LABEL","Hidden":"EXAMPLE_SECRET_VALUE"}` the old code returned
 * `"EXAMPLE_LABEL"` AS THE SECRET, and nothing in the response, the logs or the
 * return value showed that it had. Key order in a JSON object is the
 * serialiser's choice, so which string won was not even stable.
 */
const CONTENT_WRAPPERS = ["Hidden", "Text", "Totp"] as const;

/**
 * Item-body properties that may hold a value directly, and the only names read
 * from the item body or its `login` block.
 *
 * What this closes: the old reader did `body[field]` and `body.login[field]`
 * with `field` taken from the CALLER'S key, against a schema whose catchall
 * accepted every object. Any top-level string in any response could therefore
 * be returned as the secret by asking for it by name --
 * `vault.get('proton', 'Item/shareId')` handed back the share id, and a
 * response carrying a `sessionToken` or an `error` string handed those back
 * just as readily. A CUSTOM field never lives here: it lives in `fields[]`,
 * which is looked up by name below. So the set of directly-readable properties
 * is the login item's own value slots and nothing else.
 */
const ITEM_VALUE_KEYS = [
  "password",
  "username",
  "email",
  // `totp_uri`, not `totp`. The real Login block spells it with the suffix,
  // so the old spelling named a slot that never existed in any response.
  "totp_uri",
  "note",
] as const;
type ItemValueKey = typeof ITEM_VALUE_KEYS[number];
const isValueKey = (f: string): f is ItemValueKey =>
  (ITEM_VALUE_KEYS as readonly string[]).includes(f);

const optionalString = z.string().optional();

/**
 * A field entry. Proton serialises custom fields as `{name, content:{...}}`
 * and some CLI versions as flat `{name, value}`. `type` is metadata that rides
 * along on some builds; it is never read as a value.
 *
 * STRICT: an entry carrying a key this provider has never seen is not a field
 * entry it understands, and "I do not understand this" must not resolve to a
 * secret. `content` is still typed loosely here because the REFUSAL for an
 * unrecognised wrapper belongs at read time, not parse time -- see
 * contentValue(). Refusing at parse time would fail a lookup of `password`
 * because some unrelated `note` field used a wrapper key we have not met.
 */
/**
 * One entry of `content.extra_fields` -- what Proton calls a custom field.
 *
 * The `{name, content:{Hidden|Text|Totp}}` shape here was already right. Only
 * its LOCATION was wrong: this provider looked for a top-level `fields[]`,
 * which no pass-cli response has ever carried.
 */
const CliFieldSchema = z.strictObject({
  name: z.string(),
  type: z.string().optional(),
  value: optionalString,
  content: z.record(z.string(), z.unknown()).optional(),
});

/**
 * `item.content` -- the part of an item that holds anything readable.
 *
 * `content.content` is a TAGGED UNION keyed by item type: `{"Login": {...}}`,
 * `{"Note": {...}}`, `{"CreditCard": {...}}`, and so on. Real values are
 * observed for Login, Identity, CreditCard, Alias, Note and Custom. It is left
 * as an open record rather than enumerated: the variants are Proton's to add,
 * the single-key rule below is what makes reading one unambiguous, and pinning
 * the list would refuse a whole item type the day one is introduced.
 */
const CliItemContentSchema = z.strictObject({
  title: optionalString,
  note: optionalString,
  // TYPED, NOT BOUND, and the difference is the point. A wrong-typed value
  // now fails the parse instead of being silently ignored -- the confusion
  // this file has produced four times. But there is nothing to bind it TO: a
  // real `item_uuid` is 8 characters where the item id is 88, so it is a
  // different identifier, and no expectation the caller supplies constrains
  // it. Recognised so a real response parses; never read as a value; and this
  // comment exists so the next reader does not mistake that for an oversight.
  item_uuid: z.string().optional(),
  content: z.record(z.string(), z.unknown()).optional(),
  extra_fields: z.array(CliFieldSchema).optional(),
});

/**
 * The body of an item, as a real `item view --output json` actually emits it.
 *
 * What this replaces was fiction. It expected `password` and `login.password`
 * at the top level and a top-level `fields[]`; the real response nests the
 * value two containers down, at `content.content.Login.password`, and puts
 * custom fields in `content.extra_fields`. Nothing here could ever have
 * resolved a secret, and 94 tests agreed it worked because every fixture was
 * written from the same misunderstanding.
 *
 * Still an EXPLICIT key list with no catchall, and still fail-closed: a
 * response this provider cannot fully account for is refused rather than
 * mined. The difference is that the keys are now the vendor's.
 */
const CliItemBodySchema = z.strictObject({
  content: CliItemContentSchema.optional(),
  // metadata: recognised so a real response parses, read only for binding
  id: z.unknown().optional(),
  share_id: z.unknown().optional(),
  vault_id: z.unknown().optional(),
  state: z.unknown().optional(),
  // TYPED to what a real response carries. These were `z.unknown()`, which
  // accepted any shape at all while the README promised wrong-typed values are
  // refused -- and "recognised so the parse succeeds" quietly became "anything
  // goes here".
  flags: z.array(z.unknown()).optional(),
  create_time: z.string().optional(),
  modify_time: z.string().optional(),
  // `last_use_time`, `revision` and `aliasEmail` are GONE. No pass-cli
  // response observed carries them; they were added defensively for keys
  // nobody has seen, which contradicts the fail-closed rule this schema is
  // built on -- a build that grows a key should fail loudly and have this
  // provider updated, not be quietly pre-accepted with an unchecked type.
  item_type: z.unknown().optional(),
});

/**
 * The envelope. `attachments` sits beside `item` in every real response and
 * has to be recognised or the strict parse refuses the whole document.
 *
 * The BARE-ARRAY variant is gone. This provider used to accept a naked
 * `[{name,value}]` as a response, which carried no item identity at all and so
 * silently bypassed every id, share and liveness check -- and no pass-cli
 * emits it. Removing a surface is the only kind of change here that reduces
 * what a reviewer has to reason about.
 */
const CliWrappedItemSchema = z.strictObject({
  item: CliItemBodySchema,
  attachments: z.array(z.unknown()).optional(),
});

type CliItemBody = z.infer<typeof CliItemBodySchema>;

/**
 * A response this provider refuses to read: unrecognised, ambiguous, or
 * structurally incomplete. Its own type so the refusals stay together and
 * greppable, and so it is obvious at every throw site that the message is
 * fixed text -- none of these is ever built out of the response itself, which
 * for `item view` is the whole item, secret included.
 */
class UnreadableResponse extends Error {}

/**
 * `JSON.parse` keeps the LAST of two identically named keys and discards the
 * first, silently and before any schema can object. Every strict schema in
 * this file therefore validated a document that had already been edited:
 * `{"state":"Trashed","state":"Active"}` reached the liveness check as
 * unambiguously Active, and a second `"password"` overwrote the first with no
 * trace that either the ambiguity refusal or the trash refusal had anything
 * to rule on. The duplicate has to be caught in the TEXT, because by the time
 * there is an object it is already gone.
 *
 * Scanned rather than re-implemented: the value still comes from
 * `JSON.parse`, and this walk only decides whether the text was honest about
 * it. Keys are compared after unescaping, so `"a"` and `"\u0061"` collide.
 */
function parseJsonStrict(text: string): unknown {
  const value = JSON.parse(text);
  // Objects hold their seen keys; arrays hold null, since positions cannot
  // collide. The stack mirrors nesting so sibling objects do not share a set.
  const stack: Array<Set<string> | null> = [];
  let expectKey = false;
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      const start = i;
      i++;
      while (i < text.length) {
        if (text[i] === "\\") {
          i += 2;
          continue;
        }
        if (text[i] === '"') break;
        i++;
      }
      const raw = text.slice(start, i + 1);
      i++;
      if (expectKey) {
        const key = JSON.parse(raw) as string;
        // `__proto__` NEVER REACHES THE SCHEMA. Zod's strict object cannot
        // refuse it: the runtime discards the key while building the object,
        // so an unaccounted key vanishes before any key-count or catchall
        // check runs -- the one key that defeats "no unrecognised keys" by
        // never being there to recognise. Refused in the TEXT, which is the
        // only place it still exists.
        if (key === "__proto__") {
          throw new UnreadableResponse(
            "pass-cli returned an object naming a reserved key",
          );
        }
        const top = stack[stack.length - 1];
        if (top) {
          if (top.has(key)) {
            throw new UnreadableResponse(
              "pass-cli returned an object naming the same key twice",
            );
          }
          top.add(key);
        }
        expectKey = false;
      }
      continue;
    }
    if (c === "{") {
      stack.push(new Set());
      expectKey = true;
      i++;
      continue;
    }
    if (c === "[") {
      stack.push(null);
      expectKey = false;
      i++;
      continue;
    }
    if (c === "}" || c === "]") {
      stack.pop();
      expectKey = false;
      i++;
      continue;
    }
    if (c === ",") {
      expectKey = stack[stack.length - 1] instanceof Set;
      i++;
      continue;
    }
    i++;
  }
  return value;
}

/**
 * The value inside a field's `content` wrapper, or undefined if it holds none.
 *
 * Refuses instead of guessing when the wrapper is not one of the three
 * documented keys, when two of them are populated (which of the two is the
 * value?), or when the documented key holds something that is not a string.
 * A secret is not a thing to pick out of a bag by feel.
 */
function contentValue(
  content: Record<string, unknown> | undefined,
): string | undefined {
  if (content === undefined) return undefined;
  const unrecognised = Object.keys(content).filter(
    (k) => !(CONTENT_WRAPPERS as readonly string[]).includes(k),
  );
  if (unrecognised.length > 0) {
    // The offending key name is NOT quoted: it is CLI-supplied text and this
    // message reaches run logs. The shape is the fault, not its contents.
    throw new UnreadableResponse(
      "a field whose content wrapper this provider does not recognise",
    );
  }
  const present = CONTENT_WRAPPERS.filter((k) => content[k] !== undefined);
  if (present.length === 0) return undefined;
  if (present.length > 1) {
    throw new UnreadableResponse(
      "a field whose content carries more than one candidate value",
    );
  }
  const v = content[present[0]];
  if (typeof v !== "string") {
    throw new UnreadableResponse(
      "a field whose content is not a string",
    );
  }
  return v;
}

/**
 * Every value the documented field array holds for `field`. A list, not a
 * first hit: duplicates are an ambiguity to refuse, and returning the first
 * one is how a decoy entry planted before the real one wins.
 */
function fromFieldArray(
  fields: z.infer<typeof CliFieldSchema>[],
  field: string,
): string[] {
  const found: string[] = [];
  // Count NAME matches, not values. `new Set()` downstream collapsed two
  // entries carrying the SAME value into one candidate, and an entry with no
  // value at all never reached it, so a planted duplicate either tied the
  // real one or hid behind it and the documented refusal never fired.
  // Duplicated names are ambiguous because they are duplicated, whatever they
  // hold.
  // FOLDED, exactly as item titles are. Two custom fields whose names render
  // identically -- NFC versus NFD, a trailing space, a variation selector --
  // were two different names here, so each matched one request, the duplicate
  // refusal never fired, and the caller got a confidently wrong value. That is
  // the same defect the title fold exists to prevent, one level down, and it
  // went unfixed for four rounds while the titles above it were hardened
  // twice.
  //
  // DETECTION FOLDS; SELECTION IS EXACT -- the same two-step the title path
  // uses, and stated here because writing the fold without the exact check is
  // precisely the bug that shipped in the title path and took two rounds to
  // find. Folding alone WIDENS the match: a request differing from the stored
  // name by composition or a trailing space would select a field it never
  // named. The fold decides ambiguity; the raw comparison decides identity.
  const wanted = foldTitleForDuplicates(field);
  let matches = 0;
  let exact = 0;
  for (const f of fields) {
    if (foldTitleForDuplicates(f.name) !== wanted) continue;
    matches++;
    if (f.name !== field) continue;
    exact++;
    const direct = f.value;
    const wrapped = contentValue(f.content);
    if (direct !== undefined && wrapped !== undefined && direct !== wrapped) {
      throw new UnreadableResponse(
        "a field carrying two different values at once",
      );
    }
    // Same empty-is-absent rule the typed slots use. Applied to one and not
    // the other, an empty CUSTOM field came back as a successful credential
    // while an empty typed slot refused -- one rule, stated twice, disagreeing.
    const v = presentValue(direct ?? wrapped);
    if (v !== undefined) found.push(v);
  }
  if (matches > 1) {
    throw new UnreadableResponse(
      "more than one field carries this name; refusing to choose between them",
    );
  }
  // One field RENDERS as the requested name but is not it, byte for byte.
  // Refusing beats returning a secret from a field the key never named.
  if (matches === 1 && exact === 0) {
    throw new UnreadableResponse(
      "a field renders the same as the requested name but is not that name",
    );
  }
  return found;
}

/**
 * True when a parsed body is actually an ITEM and not merely an object that
 * happened to survive the key check -- `{}`, or a list row like
 * `{"id":"…","title":"…"}`, parses fine and holds no value at all. A response
 * with no container and no value slot is structurally incomplete, and reading
 * "field not present" out of it would tell the operator their field name is
 * wrong when in fact the response was not an item.
 */
function isItemBody(body: CliItemBody): boolean {
  return body.content !== undefined;
}

/**
 * The single typed block inside `content.content`.
 *
 * Real responses tag it by item type -- `{"Login":{...}}`, `{"Note":{...}}` --
 * so exactly one key is expected. Zero means there is nothing to read; more
 * than one means the response does not say what kind of item this is, and
 * picking a variant would be choosing which of two answers to hand back.
 */
/**
 * `{"Login": {...}}` and `"item_type": "login"` are the same fact written
 * twice, in two spellings. Normalising the tag lets them be compared, so a
 * response whose type block disagrees with its own declared type is refused
 * rather than read.
 */
function normaliseVariantTag(tag: string): string {
  return tag.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function variantBlock(
  content: NonNullable<CliItemBody["content"]>,
): Record<string, unknown> | undefined {
  const c = content.content;
  // ABSENT IS REFUSED, not tolerated. Returning undefined here let the callers
  // carry on: a note or a custom field could still be read out of a response
  // that never said what kind of item it described. "Structurally incomplete"
  // was already the documented refusal for a body with no content container;
  // a content container with no type block is the same claim one level down.
  if (c === undefined) {
    throw new UnreadableResponse(
      "an item whose content names no item type at all",
    );
  }
  const keys = Object.keys(c);
  // A key that NAMES SOMETHING. "Exactly one key" says how many there are, not
  // that the one is an item type -- so a blank tag, or one carrying control
  // characters, satisfied the count and then had a secret read out of it. The
  // real tags are `Login`, `Note`, `CreditCard` and their kind: a letter
  // followed by letters or digits, which is what a type name looks like in
  // every response observed.
  if (keys.length === 1 && !/^[A-Za-z][A-Za-z0-9]*$/.test(keys[0])) {
    throw new UnreadableResponse(
      "an item whose content type is not a recognisable type name",
    );
  }
  if (keys.length !== 1) {
    throw new UnreadableResponse(
      "an item whose content does not name exactly one item type",
    );
  }
  const inner = c[keys[0]];
  if (inner === null || typeof inner !== "object" || Array.isArray(inner)) {
    throw new UnreadableResponse(
      "an item whose content block is not an object",
    );
  }
  return inner as Record<string, unknown>;
}

/**
 * pass-cli emits "" for a slot that is simply unset -- an item with no email
 * carries `"email": ""`. Returning that as a secret would hand a caller an
 * empty credential and report success, so an empty slot counts as ABSENT and
 * the ordinary "field not present" refusal applies.
 */
function presentValue(v: unknown): string | undefined {
  if (v === undefined) return undefined;
  // `null` is PRESENT-AND-UNSET, which is a different thing from absent and is
  // handled by the caller: it counts toward ambiguity so a null typed slot
  // plus a custom field of the same name is refused rather than silently
  // resolved to the other one, but it yields no value.
  if (v === null) return undefined;
  // PRESENT-BUT-WRONG-TYPE IS NOT ABSENT, here as everywhere else in this
  // file. Folding a number or an object into "absent" reported a malformed
  // response as a missing field, which sends the operator to check their field
  // name when the response was the problem.
  if (typeof v !== "string") {
    throw new UnreadableResponse("a value slot that is not a string");
  }
  return v === "" ? undefined : v;
}

/**
 * Pull a secret value out of `item view --output json`, reading only the
 * documented locations. See the schema block above for what changed and why.
 */
/**
 * Is this body the item that was actually asked for, and is it live?
 *
 * `item view` was invoked with `--item-id`, and the response was then mined
 * for the field WITHOUT ever checking that the item it describes is the one
 * addressed. `id` and `state` sat in the schema as `z.unknown()`, present but
 * unread, so a CLI that answered with a different item -- or with one already
 * in the trash -- had its value returned as though it were the requested
 * secret. The listing was checked for liveness a moment earlier; the response
 * itself never was, and those are two different claims.
 *
 * SCOPE, stated plainly. This binds against a CONFUSED CLI: one that resolves
 * the wrong item, or serves a trashed one from cache. It does not bind
 * against a HOSTILE one, which can echo whatever id it was handed -- that
 * remains operator-decision "the provider trusts whichever executable it
 * found", and no check on the far side of that boundary can fix it. Values
 * are verified WHEN PRESENT rather than required, because older builds omit
 * them and refusing there would break working setups over a field that has
 * never been guaranteed.
 */
function bindToRequestedItem(
  body: CliItemBody,
  expectedId: string | undefined,
  expectedShareId?: string,
  expectedTitle?: string,
  expectedVaultId?: string,
  expectedItemType?: string,
): void {
  // THE TITLE IS PART OF THE IDENTITY TOO. Resolution reads the listing, picks
  // a title, and then views the item BY ID -- two calls, with a gap. Rename
  // the item in the Proton Pass UI inside that gap and the id still resolves,
  // so the secret comes back under a title that no longer names it.
  // `content.title` was parsed and then never compared, exactly as `id` and
  // `state` were before it.
  //
  // Compared raw, like selection: the fold decides ambiguity, never identity.
  // No type check here, unlike `id`, `share_id` and `state`. Those are
  // `z.unknown()` in the schema so a wrong-typed value reaches this function;
  // `content.title` is `z.string().optional()`, so a non-string title has
  // already failed the parse and this branch could never fire. A mutation
  // audit reported the check UNGUARDED, which is what an unreachable guard
  // looks like from the outside.
  const actual = body.content?.title;
  if (expectedTitle !== undefined && actual !== undefined) {
    if (actual !== expectedTitle) {
      throw new UnreadableResponse(
        "the item it returned is titled differently than the one requested",
      );
    }
  }
  // PRESENT-BUT-WRONG-TYPE IS NOT ABSENT. Reading these as
  // `typeof x === "string" && ...` meant a numeric id, or a state of
  // `{"trashed":true}`, skipped the check entirely and read exactly like an
  // older CLI that omits the field -- so the one shape a confused or hostile
  // response would actually take was the one shape that bypassed both checks.
  // Absent stays tolerated, because older builds genuinely omit these.
  const state = body.state;
  if (state !== undefined) {
    if (typeof state !== "string") {
      throw new UnreadableResponse(
        "an item state that is not a string",
      );
    }
    if (!isActiveState(state)) {
      throw new UnreadableResponse(
        "the item it returned is in the trash",
      );
    }
  }
  // ONE RULE, APPLIED THREE TIMES. These were three hand-written checks that
  // drifted apart the moment they were written separately: the share
  // expectation was validated as canonical and the vault one was not, and a
  // response id was checked only when the listing happened to supply an
  // expectation to compare it against -- so a malformed id in the response
  // passed unexamined whenever the listing had omitted its own.
  //
  // Both halves matter and they are different questions. A response identity
  // must be a CANONICAL id whenever it is present at all, because
  // `canonicalId` returns undefined for anything malformed and two different
  // malformed ids therefore compare EQUAL -- the binding passing precisely
  // when the identity is unreadable. And an expectation must itself be
  // canonical before anything can be compared to it, for the same reason.
  // WHAT THE VAULT COMPARISON ACTUALLY PROVES. `expectedVaultId` comes from
  // the item listing, so comparing it to the item view establishes that TWO
  // RESPONSES AGREE -- not that either describes an item in the configured
  // vault. Vault scope is enforced by `--vault-name=` on every call, by
  // pass-cli, and this check does not add to it. It is kept because a confused
  // CLI whose two answers disagree is worth catching, and it is described
  // honestly here rather than left to read as a membership proof.
  //
  // ITEM TYPE, bound like the ids. It was parsed from both the listing and the
  // body and read by neither, so a response describing a different KIND of
  // item than the row it was resolved from went unnoticed -- the fifth field
  // to be accepted and ignored here, after state, id, title and vault_id.
  //
  // The response also states its type twice: `item_type` and the tag on
  // `content.content`. Two spellings of one fact that disagree is a response
  // that does not know what it is describing.
  const bodyType = body.item_type;
  if (bodyType !== undefined && typeof bodyType !== "string") {
    throw new UnreadableResponse("an item type that is not a string");
  }
  // The type is stated in up to THREE places -- the listing row, the body's
  // `item_type`, and the tag on `content.content` -- and any two of them that
  // are present must agree. Nesting the tag comparison inside "the body
  // declared a type" meant a body that simply omitted `item_type` skipped it
  // entirely, so an arbitrary single variant could supply a known field and be
  // returned as the credential while the listing declared another kind.
  // Whichever pair happens to be available is the pair that gets checked.
  const tag = body.content?.content === undefined
    ? undefined
    : Object.keys(body.content.content)[0];
  const claims: [string, string | undefined][] = [
    ["listed", expectedItemType],
    ["declared", typeof bodyType === "string" ? bodyType : undefined],
    ["content block", tag],
  ];
  const stated = claims.filter(([, v]) => v !== undefined) as [
    string,
    string,
  ][];
  for (let i = 1; i < stated.length; i++) {
    if (
      normaliseVariantTag(stated[i][1]) !== normaliseVariantTag(stated[0][1])
    ) {
      throw new UnreadableResponse(
        `an item whose ${stated[i][0]} type disagrees with its ` +
          `${stated[0][0]} type`,
      );
    }
  }
  const identities: [string, unknown, string | undefined][] = [
    ["item id", body.id, expectedId],
    ["share id", body.share_id, expectedShareId],
    ["vault id", body.vault_id, expectedVaultId],
  ];
  for (const [what, actualRaw, expected] of identities) {
    if (expected !== undefined && canonicalId(expected) === undefined) {
      throw new UnreadableResponse(
        `the item listing gave a ${what} that is not a canonical Proton id`,
      );
    }
    if (actualRaw === undefined) continue;
    if (typeof actualRaw !== "string") {
      throw new UnreadableResponse(`a ${what} that is not a string`);
    }
    const actualId = canonicalId(actualRaw);
    if (actualId === undefined) {
      throw new UnreadableResponse(
        `a ${what} that is not a canonical Proton id`,
      );
    }
    if (expected !== undefined && actualId !== canonicalId(expected)) {
      throw new UnreadableResponse(
        `the item it returned has a different ${what} than the one requested`,
      );
    }
  }
}

function extractValue(
  stdout: string,
  field: string,
  expectedId?: string,
  expectedShareId?: string,
  expectedTitle?: string,
  expectedVaultId?: string,
  expectedItemType?: string,
): string {
  const trimmed = stdout.trim();
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(trimmed);
  } catch (e) {
    // A duplicate-key refusal is a real answer ABOUT the document, not a
    // failure to read it. Swallowing it here reported honest JSON as "not
    // JSON", which sends whoever reads the log after the wrong problem.
    if (e instanceof UnreadableResponse) throw e;
    // Previously: `if (trimmed) return trimmed` -- any non-JSON output at all
    // was handed back AS THE SECRET. A usage message, a warning banner, a
    // partially written line, all became values, and a caller would have
    // authenticated with them. This provider always asks for --output json,
    // so non-JSON here is a broken response, not an alternate format.
    // The length is GONE. It was derived from untrusted output, so it leaked a
    // measurement of a response that for `item view` is the whole item -- and
    // it was never a byte count either, only a UTF-16 code-unit count wearing
    // the label. A fixed string says the same useful thing.
    throw new UnreadableResponse(
      "pass-cli returned output that is not JSON",
    );
  }

  // ONE recognised response shape: the `{item, attachments}` envelope a real
  // `item view --output json` emits. The bare-body and bare-field-array
  // variants are gone; neither exists, and the array carried no identity at
  // all, so accepting it bypassed every check below.
  const candidates: string[] = [];
  const wrapped = CliWrappedItemSchema.safeParse(parsed);
  const body = wrapped.success ? wrapped.data.item : undefined;
  // Refuse rather than search. The payload is the item, so it may not be
  // described any further than "unrecognised" -- and a body with no content
  // container is not an item either.
  if (!body || !isItemBody(body)) {
    throw new UnreadableResponse(
      "pass-cli returned an item shape this provider does not recognise",
    );
  }
  // Identity BEFORE value. Reading the field first and checking afterwards
  // would already have pulled the secret out of the wrong item.
  bindToRequestedItem(
    body,
    expectedId,
    expectedShareId,
    expectedTitle,
    expectedVaultId,
    expectedItemType,
  );
  const content = body.content!;
  // A CUSTOM field, by name, from where Proton actually keeps them.
  // STRUCTURE FIRST, FOR EVERY READ. `variantBlock` refuses a response that
  // names zero or several item types, or whose type block is not an object --
  // and it used to be called only when the requested field was a value slot,
  // so a CUSTOM field lookup skipped the structural check entirely and could
  // return a secret out of a document this provider had refused to recognise.
  // The check is about the RESPONSE, not about which field was asked for.
  const block = variantBlock(content);
  candidates.push(...fromFieldArray(content.extra_fields ?? [], field));
  // Only the closed set of value slots is readable by name. An arbitrary
  // caller-named key is NOT looked up -- that is what turned any string in any
  // response into a secret on request.
  // A slot that is PRESENT AND NULL is a claim on the name even though it
  // yields nothing. Counting only the slots that produced a value meant a null
  // typed `password` alongside a custom field called `password` resolved
  // quietly to the custom field -- two locations claiming one name, which is
  // the ambiguity this whole function refuses everywhere else.
  let nullClaims = 0;
  if (isValueKey(field)) {
    // `note` is the item's own note, one level above the typed block.
    if (field === "note") {
      if (content.note === null) nullClaims++;
      const own = presentValue(content.note);
      if (own !== undefined) candidates.push(own);
    }
    if (block !== undefined) {
      if (block[field] === null) nullClaims++;
      const slot = presentValue(block[field]);
      if (slot !== undefined) candidates.push(slot);
    }
  }
  if (nullClaims > 0 && candidates.length > 0) {
    throw new UnreadableResponse(
      "this field is claimed in more than one place and one of them is unset; " +
        "refusing to choose between them",
    );
  }

  // Ambiguity is refused, not resolved by precedence. Two documented
  // locations disagreeing about one field means the response does not say
  // what the secret is, and picking the first one is picking whichever a
  // planted entry could be made to occupy.
  const distinct = [...new Set(candidates)];
  if (distinct.length > 1) {
    throw new UnreadableResponse(
      "pass-cli returned more than one value for this field; refusing to " +
        "choose between them",
    );
  }
  const found: string | undefined = distinct[0];

  if (found === undefined) {
    throw new Error(
      `Field '${clip(field)}' not present in the item. Check the field name ` +
        `in Proton Pass, or address it explicitly as 'ITEM_TITLE/FIELD'.`,
    );
  }
  return found;
}

/**
 * One row of `pass-cli item list --output json`, reduced to what matters here.
 *
 * `id` is OPTIONAL and stays optional all the way to the caller. It used to be
 * defaulted to `""`, which typechecked fine and then silently disabled the
 * exact-address step in get(): the falsy id fell through to `--item-title`,
 * the very selector this provider refuses to trust because it picks one of
 * several same-titled items -- trashed ones included -- without saying which.
 * A missing id is now a fact get() can fail closed on.
 */
export type PassItem = {
  id?: string;
  shareId?: string;
  vaultId?: string;
  itemType?: string;
  title: string;
  active: boolean;
};

// Strict, like the item body above: a row carries exactly the keys named here
// -- the nine a real `item list` emits, plus `name` as a tolerated alias for
// `title` -- and nothing else, and the wrapper carries `items` and nothing
// else. It said "these four keys" for several rounds after the real key set
// was discovered and written in immediately below it. The catchall that
// used to sit here made ANY array of objects a valid inventory and any
// envelope with an `items` key a valid listing -- an error or paginated
// response was read as a complete vault rather than refused.
const CliListRowSchema = z.strictObject({
  // read
  id: z.string().optional(),
  title: z.string().optional(),
  state: z.string().optional(),
  share_id: z.string().optional(),
  // recognised, never read. These were MISSING, and the schema is strict, so
  // every row a real pass-cli emits failed to parse and every list() and
  // get() against a real vault died with "unrecognised shape". The suite
  // stayed green throughout because every fixture was a shape invented here
  // rather than captured from the CLI.
  vault_id: z.string().optional(),
  flags: z.array(z.unknown()).optional(),
  create_time: z.string().optional(),
  modify_time: z.string().optional(),
  // TYPED, so the parse refuses a wrong-typed value instead of the reader
  // converting it to "absent" and disabling the check that depends on it.
  // That conversion is the fourth appearance of one confusion in this file --
  // after `if (rec.id)`, `typeof x === "string" &&`, and `|| undefined` --
  // and every time it turned malformed input into missing input.
  item_type: z.string().optional(),
  // tolerated alias, kept because the title/name conflict refusal below is
  // cheap and a future or older build may use it
  name: z.string().optional(),
});

const CliListArraySchema = z.array(CliListRowSchema);
const CliListWrappedSchema = z.strictObject({ items: CliListArraySchema });

/**
 * Is this row live? `Active` and `Trashed` are the only states this provider
 * knows how to act on, and a third one is refused.
 *
 * The test was `state.toLowerCase() === "active"`, which quietly filed every
 * unrecognised state under TRASHED. That does not fail closed, it fails
 * WRONG: a live item whose state this provider cannot read vanishes from the
 * inventory, and a vanished row is how the duplicate-title refusal in get()
 * stops seeing the duplicate. Two live items sharing a title, one of them in
 * a state added by a later pass-cli, resolved to one item and returned its
 * password -- the exact "which secret did I just read" ambiguity the rest of
 * this file exists to refuse.
 *
 * ABSENT state is still live: older builds omit the field entirely and that
 * trade is documented in the README. Only a state that is PRESENT and
 * unrecognised is an error. The value itself is not interpolated -- no CLI
 * text is forwarded verbatim from any error path in this file.
 */
function isActiveState(state: string | undefined): boolean {
  if (state === undefined) return true;
  // EXACT, not case-folded. The README documents a strict two-value enum, and
  // `aCtIvE` is not a value pass-cli emits -- accepting it meant a response
  // that differs from the documented shape was read as live rather than
  // refused, which is the opposite of what the strictness is for.
  if (state === "Active") return true;
  if (state === "Trashed") return false;
  throw new Error(
    "pass-cli item list reported an item state this provider does not " +
      "recognise; refusing to guess whether the item is live or trashed",
  );
}

/**
 * Fold a title to the form used for DUPLICATE DETECTION only.
 *
 * Selection still requires an exact match; this exists purely to answer "could
 * the operator have meant a different item?" Two titles that fold together are
 * treated as ambiguous and refused, never silently resolved.
 *
 * Why: `get()` compared titles with `===`, so two items whose titles RENDER
 * IDENTICALLY were two different titles. Each matched exactly one item, the
 * `items.length > 1` refusal never fired, and the caller got a confidently
 * wrong secret. Demonstrated with NFC vs NFD `EXAMPLE-CAFÉ`, a trailing space,
 * and a U+FE0E variation selector -- none of which an operator can see in
 * `list()` output. Note the title/name check elsewhere in this file uses
 * `!==` on raw strings and therefore already fails closed on the same input;
 * the two sites disagreed about what identity means.
 *
 * NFC collapses the composed/decomposed pair. Trimming collapses the
 * whitespace pair. Stripping variation selectors collapses the VS pair.
 *
 * NOT closed by this: confusables across scripts, e.g. Cyrillic U+0430 in
 * `EXAMPLE-А-KEY` against Latin `A`. Catching those needs Unicode's confusables
 * table, which is large, versioned, and not worth vendoring into a credential
 * provider. It is disclosed in the README rather than silently left as a gap.
 */
export function foldTitleForDuplicates(title: string): string {
  return title
    .normalize("NFC")
    .replace(/[\uFE00-\uFE0F]/gu, "")
    // VS17-VS256 live in the supplementary plane and the BMP class above
    // cannot express them. Without this range a title differing only by
    // U+E0100 folded to a DIFFERENT identity, so the duplicate refusal never
    // fired on it -- the exact hole the BMP range was added to close.
    .replace(/[\u{E0100}-\u{E01EF}]/gu, "")
    .trim();
}

/**
 * Parse the item list, and record whether each item is live or in the trash.
 *
 * `state` has been sitting in this response all along and nothing read it, so
 * a trashed item was indistinguishable from a live one: it appeared in
 * `list-keys` as an available key, and `item view --item-title` would happily
 * resolve to it. Deleting a secret in Proton Pass therefore did not stop swamp
 * from handing out its value -- which is the opposite of what deleting a
 * secret is for.
 *
 * The human-readable fallback is NOT parsed -- it was removed, because its
 * `(state=...)` suffix could not be told apart from a title that genuinely
 * ends that way. Only `--output json` is read.
 *
 * EVERY nonblank row must parse and blank output is refused. Skipping
 * unparsed rows made a partially-read listing indistinguishable from a
 * complete one, and a short inventory is how `get` concludes a key is absent
 * when it is not and how a duplicate-title check misses the duplicate.
 * Likewise blank output: `--output json` answers an empty vault with `[]`,
 * never with nothing, so silence is a broken call and not "you have no
 * secrets" -- a fact callers act on.
 */
export /**
 * `/` is both a legal character in a Proton item title and this provider's
 * locator separator, and the escape hatch that used to resolve the collision
 * -- addressing the item by `pass://` URI -- is gone.
 *
 * So the collision is now refused at both ends rather than silently resolved.
 * `list()` must not offer a title it cannot address, and `get()` must not
 * quietly read field `B` of item `A` when the vault holds an item genuinely
 * called `A/B`. Whichever way that guess went, it would return SOME secret,
 * and the caller could not tell which.
 */
function titleIsAddressable(title: string): boolean {
  return !title.includes("/");
}

/** Parse a complete JSON inventory, validating rows and preserving their activity state. */
export function parseItems(stdout: string): PassItem[] {
  const trimmed = stdout.trim();
  if (!trimmed) {
    throw new Error("pass-cli item list returned no output");
  }
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(trimmed);
  } catch (e) {
    // A duplicate-key refusal is a real answer ABOUT the document, not a
    // failure to read it. Swallowing it here reported honest JSON as "not
    // JSON", which sends whoever reads the log after the wrong problem.
    if (e instanceof UnreadableResponse) throw e;
    // The human-readable fallback is GONE, and its ambiguity is why. Its rows
    // ended with an optional `(state=Trashed)` suffix, so an item whose TITLE
    // ends that way was indistinguishable from state metadata -- a live secret
    // could be read as trashed, or a trashed one as live, and the caller is
    // deciding whether a credential is still valid on that answer. Embedded
    // newlines in a title likewise became extra rows.
    //
    // No escaping scheme was worth inventing: this provider always passes
    // `--output json`, so non-JSON here is a broken response, not an alternate
    // format. extractValue() already applies exactly this rule to item bodies;
    // the list parser was the last place still guessing.
    throw new Error(
      `pass-cli item list returned output that is not JSON; this provider ` +
        `requests --output json and does not parse the human-readable ` +
        `format, which cannot express a title unambiguously`,
    );
  }

  const shape = CliListArraySchema.safeParse(parsed);
  const wrapped = shape.success
    ? undefined
    : CliListWrappedSchema.safeParse(parsed);
  const rows = shape.success
    ? shape.data
    : wrapped?.success
    ? wrapped.data.items
    : undefined;
  // An unrecognised shape is a broken response, not an empty vault. Returning
  // [] made "pass-cli answered with something we cannot read" and "you have
  // no secrets" the same answer -- and the second is a fact a caller may act
  // on, including by concluding a key is absent.
  if (!rows) {
    throw new Error("pass-cli item list returned an unrecognised shape");
  }
  const out: PassItem[] = [];
  const seenIds = new Set<string>();
  for (const rec of rows) {
    // `title ?? name` PICKED when a row carried both and they disagreed, and
    // the picked one is what get() matches against -- so a row could present
    // one identity to the duplicate check and another to the operator reading
    // the vault. Two names is not a row with a title; it is a row whose
    // identity is unknown. Refuse rather than choose.
    if (
      typeof rec.title === "string" && typeof rec.name === "string" &&
      rec.title !== rec.name
    ) {
      throw new Error(
        "pass-cli item list contained a row whose title and name disagree; " +
          "refusing to choose an identity for it",
      );
    }
    const title = rec.title ?? rec.name;
    // A row without a title used to be SKIPPED, which quietly shortened the
    // inventory -- and a shortened inventory is how `get` concludes a key is
    // absent when it is not, and how `list` under-reports. Refuse instead.
    if (typeof title !== "string") {
      throw new Error("pass-cli item list contained a row with no title");
    }
    // Blank and control-bearing names are refused for the same reason the
    // config strings are: an empty title matches nothing legitimately and a
    // control character forges a line in the run log this text reaches.
    if (title.trim().length === 0 || CONTROL_CHARS.test(title)) {
      throw new Error(
        "pass-cli item list contained a row with a blank or control-bearing " +
          "title",
      );
    }
    // Duplicate ids made the inventory order-dependent: URI liveness resolves
    // with .find(), so an active and a trashed row sharing an id authorised or
    // refused according to which the CLI happened to list first. An id that
    // does not identify one row is not an id.
    // PRESENT-AND-EMPTY IS NOT MISSING. `if (rec.id)` treated "" as absent, so
    // an empty id skipped canonical validation entirely and was then written
    // out as `undefined` -- malformed data laundered into "this row simply has
    // no id", which list() advertises and get() cannot address.
    if (rec.id !== undefined) {
      // CANONICAL, because that is what the binding compares. Tracking raw
      // spellings let `X` and `X==` pass the duplicate refusal as two rows and
      // then authorise as one, making active-versus-trashed selection depend
      // on listing order -- the exact ambiguity this refusal exists to stop.
      const key = rec.id === "" ? undefined : canonicalId(rec.id);
      if (key === undefined) {
        throw new Error(
          "pass-cli item list contained a row whose id is not a canonical " +
            "Proton id; refusing to use it as an address",
        );
      }
      if (seenIds.has(key)) {
        throw new Error(
          "pass-cli item list contained more than one row with the same id; " +
            "refusing to resolve it by listing order",
        );
      }
      seenIds.add(key);
    }
    // Absent state is treated as ACTIVE: older pass-cli builds omit the field
    // entirely, and hiding every secret from them would be worse than the bug
    // this fixes. Documented in the README as a trade this provider makes.
    // A state that is present but unrecognised is refused -- see
    // isActiveState.
    out.push({
      shareId: rec.share_id,
      // Carried so it can be COMPARED. It was parsed from both the listing and
      // the item body and then discarded by both, so a confused CLI could
      // answer with an item from another vault and nothing would notice --
      // the same "parsed but never read" shape as `state`, `id` and `title`
      // before it. That is four fields now; the pattern is the finding.
      vaultId: rec.vault_id,
      itemType: rec.item_type,
      // `|| undefined` was the other half of the same laundering: an empty id
      // became an absent one on the way out, so nothing downstream could tell
      // a row that carried no id from a row that carried a broken one. An
      // empty id is refused above; this is now a plain pass-through.
      id: rec.id,
      title,
      active: isActiveState(rec.state),
    });
  }
  return out;
}

/** Where a secret key points, once parsed. */
/**
 * Where a secret key points, once parsed.
 *
 * ONE FORM. `pass://SHARE_ID/ITEM_ID` addressing is gone: across six review
 * rounds it produced 14 of 39 blocks -- more than any other surface in this
 * file -- because it carried a second identity scheme that had to be parsed,
 * grammar-checked, canonicalised, bound to a share, and liveness-checked
 * separately from the one the listing already provides. A title resolves to
 * exactly one live item and is then addressed by that item's id, which is the
 * same guarantee by a shorter road. Items renamed in the Proton Pass UI now
 * break their key: that is the cost, and it is stated in the README.
 */
type Located = { kind: "title"; field: string; title: string };

/**
 * The `@jpisgeek/proton-pass` vault provider definition: `get` resolves a
 * secret live through pass-cli (title or title/field) and `list` returns item
 * titles. There is no `put`: this provider does not write. See the module
 * header for the key forms and what removing writes cost.
 *
 * Each method takes an optional trailing AbortSignal. swamp may or may not
 * supply one; when it does, cancellation reaches binary resolution and the
 * pass-cli process rather than being noticed only after both have finished.
 */
export const vault = {
  type: "@jpisgeek/proton-pass",
  name: "Proton Pass",
  description:
    "Reads secrets from Proton Pass via the official pass-cli. Secrets are " +
    "never copied into swamp storage by this provider. Every get() is a " +
    "live lookup.",
  configSchema: ConfigSchema,
  createProvider: (name: string, config: Record<string, unknown>) => {
    // ZOD'S ERROR IS NOT OUR ERROR. `.parse()` throws a ZodError whose message
    // quotes the offending input -- including UNKNOWN KEY NAMES, which come
    // from the caller's model definition. Every other message in this file is
    // length-bounded and control-character-escaped before it reaches a run
    // log; this one walked straight past all of it, so a pathological config
    // key could flood or forge log lines exactly as a pathological secret key
    // once could. The details are dropped rather than clipped: a config error
    // is the operator's own file, which they are holding.
    let cfg: z.infer<typeof ConfigSchema>;
    try {
      cfg = ConfigSchema.parse(config);
    } catch {
      throw new Error(
        "The Proton Pass vault config is not valid. Check 'vaultName', " +
          "'defaultField', 'binary' and 'timeoutSec' against the README: " +
          "unknown keys are refused, and the details are withheld here " +
          "because they would quote your model definition into the run log.",
      );
    }

    /** Split a secret key into the pass-cli locator plus the field to read. */
    const locate = (secretKey: string): Located => {
      rejectOversizedKey(secretKey);
      // CASE-INSENSITIVE. URI schemes are case-insensitive by RFC 3986, so
      // `PASS://S/I` is the same address `pass://` names -- and it fell
      // through this check into title/field parsing, where it resolved as
      // field `/S/I` of an item titled `PASS:`. A reserved prefix that is only
      // reserved in one spelling is not reserved.
      if (secretKey.toLowerCase().startsWith("pass://")) {
        // Refused, not parsed. Everything this form needed -- a second id
        // grammar, share binding, its own liveness path, canonicalisation --
        // is gone with it.
        throw new Error(
          `Secret '${clip(secretKey)}' uses the pass:// URI form, which this ` +
            `provider no longer accepts. Address the item by its title, or ` +
            `'TITLE/FIELD' for a custom field.`,
        );
      }
      const slash = secretKey.indexOf("/");
      const title = slash === -1 ? secretKey : secretKey.slice(0, slash);
      // AMBIGUOUS BY CONSTRUCTION. `A/B` means field `B` of item `A`, and it
      // also spells an item genuinely titled `A/B`. get() cannot serve both,
      // and whichever it picked would return SOME secret with no way for the
      // caller to tell which. The vault decides whether the ambiguity is real:
      // the refusal fires only when an item with the whole key as its title
      // actually exists. Checked in get() against the live listing, below.
      const field = slash === -1
        ? cfg.defaultField
        : secretKey.slice(slash + 1);
      // Same rule the URI form now applies: `Item/` resolved to a field named
      // "" and returned whatever was stored under it. The other locator
      // components were already refused when blank; the field half was not.
      if (field.trim().length === 0) {
        throw new Error(
          `Secret '${clip(secretKey)}' names a blank field. Give a field ` +
            `name, or omit the trailing '/' to use the configured default.`,
        );
      }
      return { kind: "title", field, title };
    };

    // Same joined form as the view call below: `cfg.vaultName` is operator
    // input and may begin with `-`, which pass-cli's option parser would read
    // as a flag if it arrived as its own argv entry.
    const listArgs = [
      "item",
      "list",
      `--vault-name=${cfg.vaultName}`,
      "--output",
      "json",
    ];

    return {
      get: async (
        secretKey: string,
        signal?: AbortSignal,
      ): Promise<string> => {
        // BEFORE anything else, and before pass-cli is invoked at all. The
        // key is interpolated into every failure this method can raise, and
        // those land in swamp run logs and run reports: a key of
        // `Item\n2026-01-01 00:00:00 INFO vault.get ok` would write a second,
        // forged line into the log that reads like a real one. Item titles do
        // not contain control characters, so nothing legitimate is refused.
        // LENGTH FIRST, before anything scans the key. `rejectControlChars`
        // runs a regex over the whole string and `locate` lowercases it; both
        // did their work before the bound that exists to stop caller-chosen
        // input driving caller-chosen cost. A limit checked after the work it
        // limits is decoration.
        rejectOversizedKey(secretKey);
        rejectControlChars("Secret key", secretKey);
        const located = locate(secretKey);
        const runOpts = { timeoutSec: cfg.timeoutSec, signal };

        // Resolve to exactly one LIVE item, and address it by ID.
        //
        // `--item-title` lets pass-cli choose when several items share a
        // name, and it will choose a trashed one just as readily as a live
        // one. Real vaults do accumulate duplicate titles, so "which secret
        // did I just read" had no reliable answer. Nothing about that
        // was visible: the wrong value simply came back. `--item-title` is
        // now never sent; if an exact address cannot be formed, the lookup
        // fails instead of degrading to it.
        //
        // A title pinned in a config is
        // the address form MOST likely to outlive the item it names, so
        // exempting it would put the biggest hole in exactly the guarantee
        // this provider makes.
        const title = located.title;
        const all = parseItems(await run(cfg.binary, listArgs, runOpts));
        // THE VAULT DECIDES WHETHER THE AMBIGUITY IS REAL. `A/B` is both
        // "field B of item A" and a legal title in its own right. Refuse only
        // when an active item is actually titled with the whole key -- at that
        // point the key names two different secrets and neither reading is
        // safe. When no such item exists there is nothing to be ambiguous
        // with, and the ordinary title/field split stands.
        // FOLDED ONCE, not once per slash. This loop used to normalise and
        // scan the entire inventory at every split point, so cost was
        // key-length times inventory-size on data the caller chose. The
        // inventory is folded a single time into a set and each split point is
        // then one lookup.
        const activeFolded = new Set(
          all.filter((i) => i.active).map((i) =>
            foldTitleForDuplicates(i.title)
          ),
        );
        // EVERY SPLIT POINT, not just the whole key. The split is taken at
        // the FIRST slash, so `A/B/C` reads as field `B/C` of item `A` -- but
        // an active item titled `A/B` makes field `C` of `A/B` an equally
        // good reading, and an item titled `A/B/C` makes the whole key a
        // title. Checking only the whole key caught the last of those and
        // missed every one in between, which is worse than not checking:
        // multi-slash keys looked guarded.
        for (let cut = title.length; cut <= secretKey.length; cut++) {
          if (cut !== secretKey.length && secretKey[cut] !== "/") continue;
          const alternative = secretKey.slice(0, cut);
          if (alternative === title) continue;
          // FOLDED, like every other title comparison here. Byte equality
          // meant a slash-bearing title differing from the key only by
          // composition, a trailing space or a variation selector slipped past
          // the ambiguity refusal -- and then get() resolved the OTHER reading
          // and returned a secret from an item nobody named. Detection folds;
          // this check is detection.
          if (!activeFolded.has(foldTitleForDuplicates(alternative))) continue;
          throw new Error(
            `Secret '${clip(secretKey)}' is ambiguous in Proton Pass vault ` +
              `'${clip(cfg.vaultName)}': an active item is titled ` +
              `'${clip(alternative)}', so this key also reads as a field of ` +
              `that item, as well as the field '${clip(located.field)}' of ` +
              `item '${clip(title)}'. '/' is both a legal title character ` +
              `and this provider's field separator, so no key names one of ` +
              `them unambiguously. Rename the item.`,
          );
        }
        // Detection folds; selection does not. Anything that could be the
        // requested title counts toward ambiguity, so a fold collision is
        // refused below rather than resolved by exact match.
        const wanted = foldTitleForDuplicates(title);
        const items = all.filter(
          (i) => i.active && foldTitleForDuplicates(i.title) === wanted,
        );
        if (items.length === 0) {
          throw new Error(
            `Secret '${clip(secretKey)}' not found in Proton Pass vault ` +
              `'${clip(cfg.vaultName)}': no active item titled ` +
              `'${clip(title)}' (a trashed item with that title is not ` +
              `used).`,
          );
        }
        if (items.length > 1) {
          throw new Error(
            `Secret '${clip(secretKey)}' is ambiguous in Proton Pass vault ` +
              `'${clip(cfg.vaultName)}': ${items.length} active items have ` +
              `titles indistinguishable from '${clip(title)}'. They may not ` +
              `look different -- Unicode composition, a trailing space or a ` +
              `variation selector all render the same. Refusing to guess ` +
              `which one you meant. Remove or rename the duplicates: with ` +
              `URI addressing gone there is no key that names one of several ` +
              `same-titled items.`,
          );
        }
        const only = items[0];
        // SELECTION IS EXACT. The filter above folds so that anything which
        // could be the requested title counts toward ambiguity -- that is
        // what stops two identical-looking items from matching one each.
        // But folding widened the match, and nothing narrowed it back, so a
        // request that differed from the stored title by composition, a
        // trailing space or a variation selector selected an item it never
        // named. The comment here claimed selection was exact for two
        // rounds while no code performed the comparison.
        if (only.title !== title) {
          throw new Error(
            `Secret '${clip(secretKey)}' not found in Proton Pass vault ` +
              `'${clip(cfg.vaultName)}': an active item RENDERS the same ` +
              `as '${clip(title)}' but is not byte-for-byte that title ` +
              `(Unicode composition, a trailing space or a variation ` +
              `selector all render alike). Refusing to hand back a secret ` +
              `from an item the key did not name: copy the title from ` +
              `list().`,
          );
        }
        // Fail closed. A row the listing gave no id for cannot be addressed
        // exactly, and the old fallback -- send `--item-title` anyway -- is
        // precisely the selector three paragraphs of this file exist to
        // avoid. "We could not tell which item" is a safe answer; handing
        // back a value from an item nobody chose is not.
        if (!only.id) {
          throw new Error(
            `Secret '${clip(secretKey)}' matched an item in Proton Pass ` +
              `vault '${clip(cfg.vaultName)}' that pass-cli listed without ` +
              `an id, so it cannot be addressed exactly. Refusing to fall ` +
              `back to --item-title, which picks one of several same-titled ` +
              `items without saying which. Upgrade pass-cli.`,
          );
        }
        // No id check here. parseItems() now refuses a non-canonical id
        // for the whole listing, before any row reaches this point -- it has
        // to, because duplicate detection compares canonical forms and
        // cannot canonicalise what it will not validate. Two checks of the
        // same rule, one of them unreachable, is worse than one: a mutation
        // audit reported this one GUARDED when deleting it changed nothing.
        // `const`, and declared where they are known. These were `let`
        // declarations hoisted above two branches that had to agree about what
        // identity means -- the hoisting was the shape of the disagreement.
        // With one locator form there is one place they can be set.
        // `--option=value`, NOT `--option value`. Vault names and item ids
        // both come from outside this file, and either can begin with `-`.
        // Passed as a separate argv entry, pass-cli's own option parser is
        // free to read it as a flag rather than as the value it belongs to --
        // avoiding a shell prevents shell injection, not argument injection.
        // The joined form has no second reading.
        const resolved = [
          `--vault-name=${cfg.vaultName}`,
          `--item-id=${only.id}`,
        ];
        const expectedId = only.id;
        // The row carries its share, so a title lookup binds the WHOLE
        // address, not just the item half.
        const expectedShareId = only.shareId;

        // NOTE: deliberately no --field. pass-cli's own field resolution
        // rejects custom field names ("Field does not exist: password"),
        // so pull the whole item and pick the field out here instead.
        const stdout = await run(cfg.binary, [
          "item",
          "view",
          ...resolved,
          "--output",
          "json",
        ], runOpts);
        // NOT COVERED BY A TEST. Reaching it needs the abort to land in the
        // gap between run() resolving and this line -- and an abort that
        // arrives any earlier is caught by run() itself, which passes the
        // signal to the child. Every attempt to time it hit the earlier
        // check instead, and the mutation audit reports this UNGUARDED,
        // which is accurate. Third branch in this file argued for rather
        // than demonstrated, and labelled like the other two.
        //
        // ABORT AFTER THE AWAIT, TOO. run() checks the signal before
        // spawning and again around the child, but a caller can abort while
        // this continuation is queued -- between run() resolving and the
        // value being handed back. Without this, the secret a caller
        // cancelled to prevent is returned anyway, which is exactly what
        // threading the signal into pass-cli exists to stop.
        if (signal?.aborted) {
          throw new CancelledError("cancelled before the secret was read");
        }
        try {
          return extractValue(
            stdout,
            located.field,
            expectedId,
            expectedShareId,
            only.title,
            only.vaultId,
            only.itemType,
          );
        } catch (cause) {
          // No CancelledError rethrow here: the abort recheck was MOVED
          // above this try rather than guarded inside it, so a cancellation
          // can no longer reach this catch to be reclassified. Structure
          // instead of a guard, and one less unreachable branch.
          throw new Error(
            `Secret '${clip(secretKey)}' not readable from Proton Pass vault ` +
              `'${clip(cfg.vaultName)}': ${(cause as Error).message}`,
          );
        }
      },

      /**
       * Live item titles, deduplicated, trashed items excluded.
       *
       * Titles containing `/` are omitted: they cannot be addressed by any key
       * this provider accepts, and offering one would hand back a string that
       * resolves to a different item's field.
       */
      list: async (signal?: AbortSignal): Promise<string[]> => {
        const stdout = await run(cfg.binary, listArgs, {
          timeoutSec: cfg.timeoutSec,
          signal,
        });
        // Live items only. A trashed secret is one the operator deleted, and
        // listing it as available is how a dead credential keeps getting
        // handed out. Duplicate titles are collapsed -- `get` is where
        // ambiguity is refused, and it is refused there rather than here so
        // the message can say which key is at fault.
        const seen = new Set<string>();
        const out: string[] = [];
        for (const it of parseItems(stdout)) {
          if (!it.active) continue;
          // A title containing `/` cannot be addressed by any key this
          // provider accepts, and offering it would hand the caller a string
          // that resolves to a DIFFERENT item's field. Listing it as available
          // is the lie; omitting it is merely incomplete.
          if (!titleIsAddressable(it.title)) continue;
          if (seen.has(it.title)) continue;
          seen.add(it.title);
          out.push(it.title);
        }
        // Same rule as get(): a caller who aborted while this continuation
        // was queued gets the cancellation, not the inventory.
        if (signal?.aborted) {
          throw new CancelledError("cancelled before the listing was read");
        }
        return out;
      },

      getName: (): string => name,
    };
  },
};
