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
        return { args: [secretKey], field };
      }
      const slash = secretKey.indexOf("/");
      const title = slash === -1 ? secretKey : secretKey.slice(0, slash);
      const field = slash === -1
        ? cfg.defaultField
        : secretKey.slice(slash + 1);
      return {
        args: ["--vault-name", cfg.vaultName, "--item-title", title],
        field,
      };
    };

    return {
      get: async (secretKey: string): Promise<string> => {
        const { args, field } = locate(secretKey);
        // NOTE: deliberately no --field. pass-cli's own field resolution
        // rejects custom field names ("Field does not exist: password"),
        // so pull the whole item and pick the field out here instead.
        const stdout = await run(cfg.binary, [
          "item",
          "view",
          ...args,
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
        let parsed: unknown;
        try {
          parsed = JSON.parse(stdout.trim());
        } catch {
          // Fall back to the human format: "- [id]: Title"
          return stdout
            .split("\n")
            .map((line) => line.replace(/^-\s*\[[^\]]*\]:\s*/, "").trim())
            .filter(Boolean);
        }
        const rows = Array.isArray(parsed)
          ? parsed
          : (parsed as Record<string, unknown>)?.items;
        if (!Array.isArray(rows)) return [];
        return rows
          .map((r) => {
            const rec = r as Record<string, unknown>;
            return (rec.title ?? rec.name) as string | undefined;
          })
          .filter((t): t is string => typeof t === "string");
      },

      getName: (): string => name,
    };
  },
};
