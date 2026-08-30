/**
 * Proton Pass vault provider for swamp.
 *
 * Secrets stay in Proton Pass. This provider shells out to the official
 * `pass-cli` on demand, so nothing is ever copied into swamp's own storage,
 * into this repository, or onto disk. `${{ vault.get('myvault', 'KEY') }}`
 * resolves live at run time.
 *
 * Secret key forms accepted by `get()` (placeholders, not real item names).
 * The split is at the FIRST slash, which the examples below used to
 * contradict:
 *   "<item>"                     -> that item, field = defaultField
 *   "<item>/<field>"             -> that item, that field
 *   "pass://SHARE_ID/ITEM_ID"        -> stable URI, field = defaultField
 *   "pass://SHARE_ID/ITEM_ID/FIELD"  -> stable URI, that field
 *
 * An item title containing a slash therefore cannot be addressed by title at
 * all -- use the URI form for those. Everything after the first slash is the
 * field name, slashes included, so "<item>/a/b" asks for a field literally
 * named "a/b", and "pass://SHARE/ITEM/a/b" does the same.
 *
 * `put()` accepts BARE TITLES ONLY. It is deliberately narrower than `get()`
 * -- see the rejection sites in put() for what a qualified key used to do.
 *
 * Prefer the URI form for anything long-lived: titles can be edited in the
 * Proton Pass UI, item IDs cannot.
 */
import { z } from "npm:zod@4";

const ConfigSchema = z.object({
  vaultName: z
    .string()
    .describe("Proton Pass vault to read from, e.g. '<your-vault>'"),
  defaultField: z
    .string()
    .default("password")
    .describe("Item field used when the secret key names no field"),
  timeoutSec: z
    .number()
    .int()
    .positive()
    .max(300)
    .default(30)
    .describe(
      "How long any single pass-cli call may take. It reaches Proton's " +
        "servers, so an unbounded call can hang for as long as the network " +
        "allows.",
    ),
  binary: z
    .string()
    .default("pass-cli")
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

/** Bound one interpolated string. Never applied to the secret VALUE, which is
 * never interpolated at all. */
export function clip(s: string, max = MAX_ERROR_TEXT): string {
  return s.length <= max ? s : `${s.slice(0, max)}...(${s.length} chars)`;
}

/**
 * Resolve the pass-cli binary. A bare name is tried on PATH first, then at the
 * usual install prefixes. An explicit path is used as given.
 *
 * TRUST NOTE (deliberate, documented in README "Security"): whichever
 * executable answers `--version` first is the one that receives item titles,
 * vault names and `put()` values. Nothing here verifies ownership, signature
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
// Keyed by the configured name. A bare "pass-cli" and a bare "pass-cli-beta"
// are different programs, and one global slot meant whichever resolved FIRST
// won for every provider afterwards -- so a second vault configured with a
// different binary would silently send its secret lookups through the first
// one's executable.
const resolvedBinary = new Map<string, string>();

/** A --version probe should answer instantly; anything slower is wedged. */
const PROBE_TIMEOUT_MS = 5_000;

/** Thrown when the caller's signal aborted. Distinguishable from a timeout. */
class CancelledError extends Error {}

async function resolveBinary(
  configured: string,
  signal?: AbortSignal,
): Promise<string> {
  if (configured.includes("/")) return configured;
  const cached = resolvedBinary.get(configured);
  if (cached) return cached;

  // Resolution is inside the caller's cancellation scope, not before it.
  // Probing walks up to four executables at 5s each, and with the signal
  // stopping at run()'s Deno.Command a caller that had already given up still
  // waited out the whole walk -- the exact stall the signal exists to prevent.
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
        signal: signal ? AbortSignal.any([signal, deadline]) : deadline,
      }).output();
      return out.success;
    } catch {
      return false;
    }
  };

  if (await probe(configured)) {
    resolvedBinary.set(configured, configured);
    return configured;
  }
  for (const candidate of CANDIDATE_PATHS) {
    // Re-checked between probes: a cancellation that arrives mid-walk should
    // stop the walk, not be reported as "could not find the binary" after
    // three more 5s probes have run to completion.
    if (signal?.aborted) {
      throw new CancelledError("cancelled while locating pass-cli");
    }
    if (await probe(candidate)) {
      resolvedBinary.set(configured, candidate);
      return candidate;
    }
  }
  if (signal?.aborted) {
    throw new CancelledError("cancelled while locating pass-cli");
  }
  throw new Error(
    `Could not find '${clip(configured)}' on PATH or at ${
      CANDIDATE_PATHS.join(", ")
    }. Install the Proton Pass CLI (brew install proton-pass-cli), or set ` +
      `'binary' on the vault config to an absolute path.`,
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

/** Run pass-cli and return stdout. Never uses a shell, so no argv injection. */
async function run(
  configured: string,
  args: string[],
  opts: { timeoutSec?: number; signal?: AbortSignal } = {},
): Promise<string> {
  // Bounded, and cancellable. pass-cli talks to Proton's servers, so a call
  // can hang on the network for as long as the transport allows -- and with
  // no signal wired through, a caller that had already given up was still
  // waited on. A secret lookup that never returns stalls whatever asked for
  // it, and this provider sits in the path of model runs that have their own
  // deadlines. The deadline is armed BEFORE binary resolution so that
  // resolution counts against it too.
  const timeoutSec = opts.timeoutSec ?? 30;
  const deadline = AbortSignal.timeout(timeoutSec * 1000);
  const signal = opts.signal
    ? AbortSignal.any([opts.signal, deadline])
    : deadline;

  let bin: string;
  try {
    bin = await resolveBinary(configured, opts.signal);
  } catch (cause) {
    if (cause instanceof CancelledError) throw cause;
    if (deadline.aborted) {
      throw new Error(
        `pass-cli was not located within ${timeoutSec}s`,
        { cause },
      );
    }
    throw cause;
  }

  let out: Deno.CommandOutput | undefined;
  let cause: unknown;
  try {
    out = await new Deno.Command(bin, {
      args,
      stdin: "null", // never let it block on an interactive prompt
      stdout: "piped",
      stderr: "piped",
      signal,
    }).output();
  } catch (e) {
    cause = e;
  }

  // An abort does NOT necessarily reject. Deno terminates the child and hands
  // back a perfectly ordinary CommandOutput carrying the signal's exit code --
  // so a cancelled or timed-out call fell through to the CLI classifier below
  // and came back as `pass-cli failed: unclassified (exit 143)`. That reads as
  // though Proton misbehaved when in fact we killed the process. Decide from
  // the signals, which are true in the rejecting and non-rejecting case alike.
  if (out === undefined || !out.success) {
    switch (classifyAbort(opts.signal?.aborted ?? false, deadline.aborted)) {
      case "cancelled":
        throw new CancelledError("cancelled before pass-cli answered", {
          cause,
        });
      case "timeout":
        throw new Error(
          `pass-cli did not answer within ${timeoutSec}s`,
          { cause },
        );
      case "exec-failed":
        // Only a REJECTION with nothing aborted means the binary would not
        // run. A non-zero exit is pass-cli's own verdict, and it is classified
        // further down rather than here.
        if (out === undefined) {
          throw new Error(
            `Could not execute '${clip(bin)}'. Is the Proton Pass CLI ` +
              `installed (brew install proton-pass-cli)?`,
            { cause },
          );
        }
        break;
    }
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

  const stdout = new TextDecoder().decode(out.stdout);
  const stderr = new TextDecoder().decode(out.stderr).trim();

  // pass-cli reports some failures on stdout with exit 0, so check both.
  if (!out.success || /^Error:/m.test(stdout)) {
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

export function classifyCliFailure(
  stderr: string,
  stdoutErrors: string,
  code: number,
): string {
  const text = `${stderr}\n${stdoutErrors}`;
  const patterns: [RegExp, string][] = [
    [/not logged in|session|unauthor|token/i, "session-not-usable"],
    // Vault before item: "vault X not found" contains "not found", so the
    // generic rule matched first and mislabelled a missing VAULT as a missing
    // ITEM -- which sends whoever is debugging to look for the wrong thing.
    [/vault .*not found|unknown vault|no such vault/i, "vault-not-found"],
    [/not found|no such item|does not exist/i, "item-not-found"],
    [/field does not exist/i, "field-not-found"],
    [/permission|denied|forbidden/i, "permission-denied"],
    [
      /network|timed? ?out|connection|dns|resolve|could not reach|unreachable/i,
      "network-failure",
    ],
  ];
  for (const [re, verdict] of patterns) if (re.test(text)) return verdict;
  // Only the exit code, which is a small integer, joins the fixed word.
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
 * A field entry. Proton serialises custom fields as `{name, content:{...}}`
 * and some CLI versions as flat `{name, value}`. Both are documented here;
 * `content` values stay `unknown` because the wrapper key varies
 * (`Hidden`/`Text`/`Totp`) and a new one should not fail the whole parse.
 */
const CliFieldSchema = z.object({
  name: z.string(),
  value: z.string().optional(),
  content: z.record(z.string(), z.unknown()).optional(),
});

/**
 * The body of an item. `fields` and `login` are the documented containers;
 * the catchall keeps top-level item properties readable (`{"password": "..."}`
 * is a shape the CLI emits) without making every nested object searchable.
 */
const CliItemBodySchema = z.object({
  fields: z.array(CliFieldSchema).optional(),
  login: z.record(z.string(), z.unknown()).optional(),
}).catchall(z.unknown());

const CliFieldArraySchema = z.array(CliFieldSchema);
const CliWrappedItemSchema = z.object({ item: CliItemBodySchema });

const asString = (v: unknown): string | undefined =>
  typeof v === "string" ? v : undefined;

/** First string inside a `content` wrapper, whatever the wrapper key is. */
function fromContent(content: Record<string, unknown> | undefined) {
  if (!content) return undefined;
  for (const v of Object.values(content)) {
    const s = asString(v);
    if (s !== undefined) return s;
  }
  return undefined;
}

/** Look up one field in a documented field array. No recursion. */
function fromFieldArray(
  fields: z.infer<typeof CliFieldArraySchema>,
  field: string,
): string | undefined {
  for (const f of fields) {
    if (f.name !== field) continue;
    return asString(f.value) ?? fromContent(f.content);
  }
  return undefined;
}

/**
 * Pull a secret value out of `item view --output json`, reading only the
 * documented locations. See the schema block above for what changed and why.
 */
function extractValue(stdout: string, field: string): string {
  const trimmed = stdout.trim();
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    // Previously: `if (trimmed) return trimmed` -- any non-JSON output at all
    // was handed back AS THE SECRET. A usage message, a warning banner, a
    // partially written line, all became values, and a caller would have
    // authenticated with them. This provider always asks for --output json,
    // so non-JSON here is a broken response, not an alternate format.
    throw new Error(
      `pass-cli returned ${trimmed.length} byte(s) that are not JSON`,
    );
  }

  let found: string | undefined;
  const asFieldArray = CliFieldArraySchema.safeParse(parsed);
  if (asFieldArray.success) {
    found = fromFieldArray(asFieldArray.data, field);
  } else {
    const wrapped = CliWrappedItemSchema.safeParse(parsed);
    const bare = CliItemBodySchema.safeParse(parsed);
    const body = wrapped.success
      ? wrapped.data.item
      : bare.success
      ? bare.data
      : undefined;
    if (!body) {
      // Refuse rather than search. The payload is the item, so it may not be
      // described any further than "unrecognised".
      throw new Error(
        "pass-cli returned an item shape this provider does not recognise",
      );
    }
    found = fromFieldArray(body.fields ?? [], field) ??
      asString(body[field]) ??
      asString(body.login?.[field]);
  }

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
export type PassItem = { id?: string; title: string; active: boolean };

const CliListRowSchema = z.object({
  id: z.string().optional(),
  title: z.string().optional(),
  name: z.string().optional(),
  state: z.string().optional(),
}).catchall(z.unknown());

const CliListArraySchema = z.array(CliListRowSchema);
const CliListWrappedSchema = z.object({ items: CliListArraySchema });

/** `- [id]: Title (state=Trashed)` -- the human-readable fallback row. */
const TEXT_ROW = /^-\s*\[([^\]]*)\]:\s*(.+?)(?:\s*\(state=([A-Za-z]+)\))?\s*$/;

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
 * The human-readable fallback is parsed too, because it carries the same fact
 * in a different shape. Previously the `(state=...)` suffix was left glued to
 * the title, producing key names no lookup could ever match.
 *
 * EVERY nonblank row must parse and blank output is refused. Skipping
 * unparsed rows made a partially-read listing indistinguishable from a
 * complete one, and a short inventory is how `get` concludes a key is absent
 * when it is not and how a duplicate-title check misses the duplicate.
 * Likewise blank output: `--output json` answers an empty vault with `[]`,
 * never with nothing, so silence is a broken call and not "you have no
 * secrets" -- a fact callers act on.
 */
export function parseItems(stdout: string): PassItem[] {
  const trimmed = stdout.trim();
  if (!trimmed) {
    throw new Error("pass-cli item list returned no output");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    const out: PassItem[] = [];
    for (const raw of trimmed.split("\n")) {
      const line = raw.trim();
      if (!line) continue;
      const m = TEXT_ROW.exec(line);
      if (!m) {
        throw new Error("pass-cli item list output was not recognisable");
      }
      out.push({
        id: m[1] || undefined,
        title: m[2].trim(),
        active: (m[3] ?? "Active").toLowerCase() === "active",
      });
    }
    return out;
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
  for (const rec of rows) {
    const title = rec.title ?? rec.name;
    // A row without a title used to be SKIPPED, which quietly shortened the
    // inventory -- and a shortened inventory is how `get` concludes a key is
    // absent when it is not, and how `list` under-reports. Refuse instead.
    if (typeof title !== "string") {
      throw new Error("pass-cli item list contained a row with no title");
    }
    // Absent state is treated as ACTIVE: older pass-cli builds omit the field
    // entirely, and hiding every secret from them would be worse than the bug
    // this fixes. Documented in the README as a trade this provider makes.
    const state = rec.state ?? "Active";
    out.push({
      id: rec.id || undefined,
      title,
      active: state.toLowerCase() === "active",
    });
  }
  return out;
}

/** Where a secret key points, once parsed. */
type Located =
  | { kind: "uri"; args: string[]; field: string; id: string }
  | { kind: "title"; field: string; title: string };

/**
 * The `@jpisgeek/proton-pass` vault provider definition: `get` resolves a
 * secret live through pass-cli (title, title/field, or pass:// URI), `put`
 * creates a login item from a BARE TITLE only, `list` returns item titles.
 * See the module header for the key forms and the caveats on `put`.
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
    "never copied into swamp storage. Every get() is a live lookup.",
  configSchema: ConfigSchema,
  createProvider: (name: string, config: Record<string, unknown>) => {
    const cfg = ConfigSchema.parse(config);

    /** Split a secret key into the pass-cli locator plus the field to read. */
    const locate = (secretKey: string): Located => {
      if (secretKey.startsWith("pass://")) {
        // pass://SHARE_ID/ITEM_ID[/FIELD]. Naming one item removes the
        // AMBIGUITY problem but not the DELETION one, so hand back the item
        // id and let get() confirm it is still live. A stable URI pinned in a
        // config is the address form most likely to outlive the item it
        // names, so exempting it would put the biggest hole in exactly the
        // guarantee this provider makes.
        const parts = secretKey.slice("pass://".length).split("/");
        // A URI missing either half used to fall through with no id and no
        // title, which meant the raw key went to pass-cli as its own locator
        // and whatever the CLI made of it came back unchecked -- no liveness
        // check, no ambiguity check. A malformed address is refused here.
        if (parts.length < 2 || !parts[0] || !parts[1]) {
          throw new Error(
            `Secret '${clip(secretKey)}' is not a usable pass:// URI: the ` +
              `form is 'pass://SHARE_ID/ITEM_ID' or ` +
              `'pass://SHARE_ID/ITEM_ID/FIELD'.`,
          );
        }
        // Everything after the item id is the field name, slashes included --
        // the same rule the title form uses, rather than "the last segment".
        const field = parts.length > 2
          ? parts.slice(2).join("/")
          : cfg.defaultField;
        return { kind: "uri", args: [secretKey], field, id: parts[1] };
      }
      const slash = secretKey.indexOf("/");
      const title = slash === -1 ? secretKey : secretKey.slice(0, slash);
      const field = slash === -1
        ? cfg.defaultField
        : secretKey.slice(slash + 1);
      return { kind: "title", field, title };
    };

    const listArgs = [
      "item",
      "list",
      "--vault-name",
      cfg.vaultName,
      "--output",
      "json",
    ];

    return {
      get: async (
        secretKey: string,
        signal?: AbortSignal,
      ): Promise<string> => {
        const located = locate(secretKey);
        const runOpts = { timeoutSec: cfg.timeoutSec, signal };

        // Resolve to exactly one LIVE item, and address it by ID.
        //
        // `--item-title` lets pass-cli choose when several items share a
        // name, and it will choose a trashed one just as readily as a live
        // one. This vault genuinely holds duplicate titles -- the `put` below
        // creates a new item every call rather than updating -- so "which
        // secret did I just read" had no reliable answer. Nothing about that
        // was visible: the wrong value simply came back. `--item-title` is
        // now never sent; if an exact address cannot be formed, the lookup
        // fails instead of degrading to it.
        //
        // pass:// URIs are checked too. A stable URI pinned in a config is
        // the address form MOST likely to outlive the item it names, so
        // exempting it would put the biggest hole in exactly the guarantee
        // this provider makes.
        let resolved: string[];
        if (located.kind === "uri") {
          const item = parseItems(await run(cfg.binary, listArgs, runOpts))
            .find((i) => i.id === located.id);
          if (item && !item.active) {
            throw new Error(
              `Secret '${clip(secretKey)}' refers to a trashed item in ` +
                `Proton Pass vault '${clip(cfg.vaultName)}'. Restore it, or ` +
                `name a live item.`,
            );
          }
          // An id absent from this listing is left alone: a pass:// URI can
          // address a different vault, and refusing there would break a
          // locator that works.
          resolved = located.args;
        } else {
          const title = located.title;
          const items = parseItems(await run(cfg.binary, listArgs, runOpts))
            .filter((i) => i.active && i.title === title);
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
                `'${clip(cfg.vaultName)}': ${items.length} active items are ` +
                `titled '${clip(title)}'. Refusing to guess which one you ` +
                `meant -- remove the duplicates, or address one by its ` +
                `pass:// URI.`,
            );
          }
          const only = items[0];
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
                `items without saying which. Upgrade pass-cli, or address the ` +
                `item by its pass:// URI.`,
            );
          }
          resolved = ["--vault-name", cfg.vaultName, "--item-id", only.id];
        }

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
        try {
          return extractValue(stdout, located.field);
        } catch (cause) {
          throw new Error(
            `Secret '${clip(secretKey)}' not readable from Proton Pass vault ` +
              `'${clip(cfg.vaultName)}': ${(cause as Error).message}`,
          );
        }
      },

      /**
       * Creates a NEW login item each call (pass-cli has no update-in-place
       * here), so repeated puts of the same key produce duplicates. The value
       * is passed as an argument to pass-cli, which is visible in the process
       * list to other local users for the duration of the call. Do not use
       * `put` on a shared multi-user host. Prefer creating items in the
       * Proton Pass UI and reading them with `get`.
       *
       * BARE TITLES ONLY -- see the rejections below.
       */
      put: async (
        secretKey: string,
        secretValue: string,
        signal?: AbortSignal,
      ): Promise<void> => {
        // `item create login` can set exactly one secret slot: --password.
        // put() therefore cannot honour the key forms get() accepts, and it
        // used to pretend otherwise by silently truncating them:
        //
        //   put("Item/field")  wrote the value to the PASSWORD of an item
        //                      titled "Item"; get("Item/field") then asked for
        //                      a field named "field" and did not find it. The
        //                      write reported success and the read never
        //                      worked -- a secret stored where nothing looks.
        //   put("pass://S/I")  split at the first slash and created an item
        //                      literally titled "pass:".
        //
        // Refusing is the honest half of the round-trip. Implementing the
        // other semantics would mean pass-cli growing a custom-field write
        // flag, which it has not.
        if (secretKey.startsWith("pass://")) {
          throw new Error(
            `put() cannot write to a pass:// URI ('${clip(secretKey)}'): a ` +
              `URI names an item that already exists, and pass-cli creates a ` +
              `new item rather than updating one. Create the item in the ` +
              `Proton Pass UI and read it with get().`,
          );
        }
        if (secretKey.includes("/")) {
          throw new Error(
            `put() accepts a bare item title only, not '${clip(secretKey)}': ` +
              `pass-cli's 'item create login' writes the password field and ` +
              `nothing else, so a key naming a field would be stored ` +
              `somewhere get('${clip(secretKey)}') would never look.`,
          );
        }
        // The same round-trip requirement from the other direction: get() with
        // no field reads `defaultField`, and put() can only ever write
        // `password`. Configure them apart and a put/get pair silently fails
        // to round-trip, which is the class of bug the checks above close.
        if (cfg.defaultField !== "password") {
          throw new Error(
            `put() writes the 'password' field, but this vault's ` +
              `defaultField is '${clip(cfg.defaultField)}', so ` +
              `get('${clip(secretKey)}') would not read back what put() ` +
              `wrote. Set defaultField to 'password', or create items in the ` +
              `Proton Pass UI.`,
          );
        }
        await run(cfg.binary, [
          "item",
          "create",
          "login",
          "--vault-name",
          cfg.vaultName,
          "--title",
          secretKey,
          "--password",
          secretValue,
        ], { timeoutSec: cfg.timeoutSec, signal });
      },

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
          if (seen.has(it.title)) continue;
          seen.add(it.title);
          out.push(it.title);
        }
        return out;
      },

      getName: (): string => name,
    };
  },
};
