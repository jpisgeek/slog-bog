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
 * named "a/b".
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
 * Resolve the pass-cli binary. A bare name is tried on PATH first, then at the
 * usual install prefixes. An explicit path is used as given.
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

async function resolveBinary(configured: string): Promise<string> {
  if (configured.includes("/")) return configured;
  const cached = resolvedBinary.get(configured);
  if (cached) return cached;

  // Bounded. These probes ran before any timeout existed, so a hung or
  // wedged executable could block a secret lookup forever while the
  // documented per-call bound sat unused a few lines below.
  const probe = async (bin: string): Promise<boolean> => {
    try {
      const out = await new Deno.Command(bin, {
        args: ["--version"],
        stdin: "null",
        stdout: "null",
        stderr: "null",
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
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
    if (await probe(candidate)) {
      resolvedBinary.set(configured, candidate);
      return candidate;
    }
  }
  throw new Error(
    `Could not find '${configured}' on PATH or at ${
      CANDIDATE_PATHS.join(", ")
    }. Install the Proton Pass CLI (brew install proton-pass-cli), or set ` +
      `'binary' on the vault config to an absolute path.`,
  );
}

/** Run pass-cli and return stdout. Never uses a shell, so no argv injection. */
async function run(
  configured: string,
  args: string[],
  opts: { timeoutSec?: number; signal?: AbortSignal } = {},
): Promise<string> {
  const bin = await resolveBinary(configured);
  let out: Deno.CommandOutput;
  // Bounded, and cancellable. pass-cli talks to Proton's servers, so a call
  // can hang on the network for as long as the transport allows -- and with
  // no signal wired through, a caller that had already given up was still
  // waited on. A secret lookup that never returns stalls whatever asked for
  // it, and this provider sits in the path of model runs that have their own
  // deadlines.
  const deadline = AbortSignal.timeout((opts.timeoutSec ?? 30) * 1000);
  const signal = opts.signal
    ? AbortSignal.any([opts.signal, deadline])
    : deadline;
  try {
    out = await new Deno.Command(bin, {
      args,
      stdin: "null", // never let it block on an interactive prompt
      stdout: "piped",
      stderr: "piped",
      signal,
    }).output();
  } catch (cause) {
    if (deadline.aborted) {
      throw new Error(
        `pass-cli did not answer within ${opts.timeoutSec ?? 30}s`,
        { cause },
      );
    }
    if (opts.signal?.aborted) {
      throw new Error("cancelled before pass-cli answered", { cause });
    }
    throw new Error(
      `Could not execute '${bin}'. Is the Proton Pass CLI installed ` +
        `(brew install proton-pass-cli)?`,
      { cause },
    );
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
    // logs and reports. Only the `Error:` lines from stdout are surfaced.
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
 */
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
  return `unclassified (exit ${code})`;
}

/**
 * Pull a secret value out of `item view --output json`. The CLI has shifted
 * this shape between releases, so probe the plausible locations rather than
 * pinning to one and breaking on upgrade.
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

  // Depth-bounded, and it prefers a shallow match. The recursion walks EVERY
  // nested object looking for the field name, so on an unexpected response
  // shape it could return an unrelated string that merely shared a key --
  // handing back the wrong value as a secret, silently. Bounding the depth
  // does not make the search exact, but it stops it wandering arbitrarily far
  // from the item it was asked about.
  const MAX_DEPTH = 6;
  const seen = new Set<unknown>();
  const search = (node: unknown, depth = 0): string | undefined => {
    if (depth > MAX_DEPTH) return undefined;
    if (typeof node === "string") return undefined;
    if (node === null || typeof node !== "object") return undefined;
    if (seen.has(node)) return undefined;
    seen.add(node);

    if (Array.isArray(node)) {
      for (const entry of node) {
        // Custom fields serialize as {name, value} pairs.
        if (entry && typeof entry === "object" && !Array.isArray(entry)) {
          const rec = entry as Record<string, unknown>;
          if (rec.name === field) {
            // Flat shape: {name, value}
            if (typeof rec.value === "string") return rec.value;
            // Proton shape: {name, content: {Hidden|Text|Totp: value}}
            const content = rec.content;
            if (content && typeof content === "object") {
              for (
                const v of Object.values(content as Record<string, unknown>)
              ) {
                if (typeof v === "string") return v;
              }
            }
          }
        }
        const hit = search(entry, depth + 1);
        if (hit !== undefined) return hit;
      }
      return undefined;
    }

    const rec = node as Record<string, unknown>;
    if (typeof rec[field] === "string") return rec[field] as string;
    for (const value of Object.values(rec)) {
      const hit = search(value, depth + 1);
      if (hit !== undefined) return hit;
    }
    return undefined;
  };

  const found = search(parsed);
  if (found === undefined) {
    throw new Error(
      `Field '${field}' not present in the item. Check the field name in ` +
        `Proton Pass, or address it explicitly as 'ITEM_TITLE/FIELD'.`,
    );
  }
  return found;
}

/**
 * One row of `pass-cli item list --output json`, reduced to what matters here.
 */
export type PassItem = { id: string; title: string; active: boolean };

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
 * in a different shape: `- [id]: Title (state=Trashed)`. Previously that
 * suffix was left glued to the title, producing key names no lookup could
 * ever match.
 */
export function parseItems(stdout: string): PassItem[] {
  const trimmed = stdout.trim();
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    const out: PassItem[] = [];
    let sawAnyLine = false;
    for (const line of trimmed.split("\n")) {
      if (line.trim()) sawAnyLine = true;
      const m = /^-\s*\[([^\]]*)\]:\s*(.+?)(?:\s*\(state=([A-Za-z]+)\))?\s*$/
        .exec(line.trim());
      if (!m) continue;
      out.push({
        id: m[1],
        title: m[2].trim(),
        active: (m[3] ?? "Active").toLowerCase() === "active",
      });
    }
    // Text that parsed as neither JSON nor a single recognisable row is a
    // broken response. Returning [] made it indistinguishable from a vault
    // that is genuinely empty, and the second is a fact a caller acts on.
    if (out.length === 0 && sawAnyLine) {
      throw new Error("pass-cli item list output was not recognisable");
    }
    return out;
  }
  const rows = Array.isArray(parsed)
    ? parsed
    : (parsed as Record<string, unknown>)?.items;
  // An unrecognised shape is a broken response, not an empty vault. Returning
  // [] made "pass-cli answered with something we cannot read" and "you have
  // no secrets" the same answer -- and the second is a fact a caller may act
  // on, including by concluding a key is absent.
  if (!Array.isArray(rows)) {
    throw new Error("pass-cli item list returned an unrecognised shape");
  }
  const out: PassItem[] = [];
  for (const r of rows) {
    if (typeof r !== "object" || r === null || Array.isArray(r)) {
      throw new Error("pass-cli item list contained a non-object row");
    }
    const rec = r as Record<string, unknown>;
    const title = (rec.title ?? rec.name) as string | undefined;
    // A row without a title used to be SKIPPED, which quietly shortened the
    // inventory -- and a shortened inventory is how `get` concludes a key is
    // absent when it is not, and how `list` under-reports. Refuse instead.
    if (typeof title !== "string") {
      throw new Error("pass-cli item list contained a row with no title");
    }
    // Absent state is treated as ACTIVE: older pass-cli builds omit the field
    // entirely, and hiding every secret from them would be worse than the bug
    // this fixes.
    const state = typeof rec.state === "string" ? rec.state : "Active";
    out.push({
      id: typeof rec.id === "string" ? rec.id : "",
      title,
      active: state.toLowerCase() === "active",
    });
  }
  return out;
}

/**
 * The `@jpisgeek/proton-pass` vault provider definition: `get` resolves a
 * secret live through pass-cli (title, title/field, or pass:// URI), `put`
 * creates a login item, `list` returns item titles. See the module header
 * for the key forms and the caveats on `put`.
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
    const locate = (secretKey: string) => {
      if (secretKey.startsWith("pass://")) {
        const field = secretKey.split("/").length > 4
          ? secretKey.split("/").pop()!
          : cfg.defaultField;
        // pass://SHARE_ID/ITEM_ID[/FIELD]. Naming one item removes the
        // AMBIGUITY problem but not the DELETION one, so hand back the item
        // id and let get() confirm it is still live. A stable URI pinned in a
        // config is the address form most likely to outlive the item it
        // names, so exempting it would put the biggest hole in exactly the
        // guarantee this provider makes.
        const parts = secretKey.slice("pass://".length).split("/");
        return {
          args: [secretKey],
          field,
          title: undefined,
          id: parts.length >= 2 && parts[1] ? parts[1] : undefined,
        };
      }
      const slash = secretKey.indexOf("/");
      const title = slash === -1 ? secretKey : secretKey.slice(0, slash);
      const field = slash === -1
        ? cfg.defaultField
        : secretKey.slice(slash + 1);
      return {
        args: ["--vault-name", cfg.vaultName, "--item-title", title],
        field,
        title,
        id: undefined,
      };
    };

    return {
      get: async (secretKey: string): Promise<string> => {
        const { args, field, title, id } = locate(secretKey);

        // Resolve the title to exactly one LIVE item, and address it by ID.
        //
        // `--item-title` lets pass-cli choose when several items share a
        // name, and it will choose a trashed one just as readily as a live
        // one. This vault genuinely holds duplicate titles -- the `put` below
        // creates a new item every call rather than updating -- so "which
        // secret did I just read" had no reliable answer. Nothing about that
        // was visible: the wrong value simply came back.
        //
        // pass:// URIs are checked too. A stable URI pinned in a config is
        // the address form MOST likely to outlive the item it names, so
        // exempting it would put the biggest hole in exactly the guarantee
        // this provider makes.
        let resolved = args;
        if (id !== undefined) {
          const item = parseItems(
            await run(cfg.binary, [
              "item",
              "list",
              "--vault-name",
              cfg.vaultName,
              "--output",
              "json",
            ], { timeoutSec: cfg.timeoutSec }),
          ).find((i) => i.id === id);
          if (item && !item.active) {
            throw new Error(
              `Secret '${secretKey}' refers to a trashed item in Proton Pass ` +
                `vault '${cfg.vaultName}'. Restore it, or name a live item.`,
            );
          }
          // An id absent from this listing is left alone: a pass:// URI can
          // address a different vault, and refusing there would break a
          // locator that works.
        } else if (title !== undefined) {
          const items = parseItems(
            await run(cfg.binary, [
              "item",
              "list",
              "--vault-name",
              cfg.vaultName,
              "--output",
              "json",
            ], { timeoutSec: cfg.timeoutSec }),
          ).filter((i) => i.active && i.title === title);
          if (items.length === 0) {
            throw new Error(
              `Secret '${secretKey}' not found in Proton Pass vault ` +
                `'${cfg.vaultName}': no active item titled '${title}' ` +
                `(a trashed item with that title is not used).`,
            );
          }
          if (items.length > 1) {
            throw new Error(
              `Secret '${secretKey}' is ambiguous in Proton Pass vault ` +
                `'${cfg.vaultName}': ${items.length} active items are titled ` +
                `'${title}'. Refusing to guess which one you meant -- remove ` +
                `the duplicates, or address one by its pass:// URI.`,
            );
          }
          if (items[0].id) {
            resolved = [
              "--vault-name",
              cfg.vaultName,
              "--item-id",
              items[0].id,
            ];
          }
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
        ], { timeoutSec: cfg.timeoutSec });
        try {
          return extractValue(stdout, field);
        } catch (cause) {
          throw new Error(
            `Secret '${secretKey}' not readable from Proton Pass vault ` +
              `'${cfg.vaultName}': ${(cause as Error).message}`,
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
       */
      put: async (secretKey: string, secretValue: string): Promise<void> => {
        const slash = secretKey.indexOf("/");
        const title = slash === -1 ? secretKey : secretKey.slice(0, slash);
        await run(cfg.binary, [
          "item",
          "create",
          "login",
          "--vault-name",
          cfg.vaultName,
          "--title",
          title,
          "--password",
          secretValue,
        ], { timeoutSec: cfg.timeoutSec });
      },

      list: async (): Promise<string[]> => {
        const stdout = await run(cfg.binary, [
          "item",
          "list",
          "--vault-name",
          cfg.vaultName,
          "--output",
          "json",
        ], { timeoutSec: cfg.timeoutSec });
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
