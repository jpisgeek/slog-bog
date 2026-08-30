/**
 * Proton Pass vault provider for swamp.
 *
 * Secrets stay in Proton Pass. This provider shells out to the official
 * `pass-cli` on demand, so nothing is ever copied into swamp's own storage,
 * into this repository, or onto disk. `${{ vault.get('myvault', 'KEY') }}`
 * resolves live at run time.
 *
 * Secret key forms accepted by `get()` (placeholders, not real item names):
 *   "Example Service/API Key"          -> item titled so, field = defaultField
 *   "Example Service/API Key/password" -> explicit field on that item
 *   "pass://SHARE_ID/ITEM_ID/FIELD"    -> stable URI, survives item renames
 *
 * Prefer the URI form for anything long-lived: titles can be edited in the
 * Proton Pass UI, item IDs cannot.
 */
import { z } from "npm:zod@4";

const ConfigSchema = z.object({
  vaultName: z
    .string()
    .describe("Proton Pass vault to read from, e.g. 'homelab'"),
  defaultField: z
    .string()
    .default("password")
    .describe("Item field used when the secret key names no field"),
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
let resolvedBinary: string | null = null;

async function resolveBinary(configured: string): Promise<string> {
  if (configured.includes("/")) return configured;
  if (resolvedBinary) return resolvedBinary;

  const probe = async (bin: string): Promise<boolean> => {
    try {
      const out = await new Deno.Command(bin, {
        args: ["--version"],
        stdin: "null",
        stdout: "null",
        stderr: "null",
      }).output();
      return out.success;
    } catch {
      return false;
    }
  };

  if (await probe(configured)) {
    resolvedBinary = configured;
    return configured;
  }
  for (const candidate of CANDIDATE_PATHS) {
    if (await probe(candidate)) {
      resolvedBinary = candidate;
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
async function run(configured: string, args: string[]): Promise<string> {
  const bin = await resolveBinary(configured);
  let out: Deno.CommandOutput;
  try {
    out = await new Deno.Command(bin, {
      args,
      stdin: "null", // never let it block on an interactive prompt
      stdout: "piped",
      stderr: "piped",
    }).output();
  } catch (cause) {
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
    const detail = stderr || stdoutErrors ||
      `exit ${out.code} (stdout withheld: it may contain item contents)`;
    // Surface the actionable case rather than a raw CLI dump.
    if (/not logged in|session|unauthor/i.test(detail)) {
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
    // --field on a non-JSON build prints the bare value.
    if (trimmed) return trimmed;
    throw new Error("pass-cli returned no value");
  }

  const seen = new Set<unknown>();
  const search = (node: unknown): string | undefined => {
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
        const hit = search(entry);
        if (hit !== undefined) return hit;
      }
      return undefined;
    }

    const rec = node as Record<string, unknown>;
    if (typeof rec[field] === "string") return rec[field] as string;
    for (const value of Object.values(rec)) {
      const hit = search(value);
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
    for (const line of trimmed.split("\n")) {
      const m = /^-\s*\[([^\]]*)\]:\s*(.+?)(?:\s*\(state=([A-Za-z]+)\))?\s*$/
        .exec(line.trim());
      if (!m) continue;
      out.push({
        id: m[1],
        title: m[2].trim(),
        active: (m[3] ?? "Active").toLowerCase() === "active",
      });
    }
    return out;
  }
  const rows = Array.isArray(parsed)
    ? parsed
    : (parsed as Record<string, unknown>)?.items;
  if (!Array.isArray(rows)) return [];
  const out: PassItem[] = [];
  for (const r of rows) {
    const rec = r as Record<string, unknown>;
    const title = (rec.title ?? rec.name) as string | undefined;
    if (typeof title !== "string") continue;
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
        // A pass:// URI names one item already; nothing to disambiguate.
        return { args: [secretKey], field, title: undefined };
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
      };
    };

    return {
      get: async (secretKey: string): Promise<string> => {
        const { args, field, title } = locate(secretKey);

        // Resolve the title to exactly one LIVE item, and address it by ID.
        //
        // `--item-title` lets pass-cli choose when several items share a
        // name, and it will choose a trashed one just as readily as a live
        // one. This vault genuinely holds duplicate titles -- the `put` below
        // creates a new item every call rather than updating -- so "which
        // secret did I just read" had no reliable answer. Nothing about that
        // was visible: the wrong value simply came back.
        //
        // Skipped for pass:// URIs, which already name a specific item.
        let resolved = args;
        if (title !== undefined) {
          const items = parseItems(
            await run(cfg.binary, [
              "item",
              "list",
              "--vault-name",
              cfg.vaultName,
              "--output",
              "json",
            ]),
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
        ]);
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
        ]);
      },

      list: async (): Promise<string[]> => {
        const stdout = await run(cfg.binary, [
          "item",
          "list",
          "--vault-name",
          cfg.vaultName,
          "--output",
          "json",
        ]);
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
