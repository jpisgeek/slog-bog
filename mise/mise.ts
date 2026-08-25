/**
 * mise toolchain drift across a fleet.
 *
 * mise already installs tools and pins versions, and it does that well. This
 * model installs nothing, upgrades nothing, and trusts nothing. It walks the
 * fleet, asks each host what it is actually running, and writes down where
 * that disagrees with what the host's own config asked for.
 *
 * The distinction the whole model is built around: a host that did not answer
 * is not a host with nothing to report. mise is routinely absent from a
 * non-login shell's PATH, and an empty tool list from a host that never ran
 * mise reads exactly like a host that is perfectly clean. So every failure to
 * measure is recorded as a failure to measure, never as a zero.
 */
import { z } from "npm:zod@4";

/**
 * Absolute path, and only characters that cannot change the meaning of the
 * single-quoted remote command they are interpolated into. No quote, no
 * semicolon, no dollar, no backtick, no whitespace.
 */
const SAFE_ABS_PATH = /^\/[A-Za-z0-9._/-]*$/;
/** Same character class, but a bare command name like `mise` is also fine. */
const SAFE_BIN_PATH = /^[A-Za-z0-9._/-]+$/;

const SshSchema = z.object({
  // host/user become the positional `user@host` argument to ssh. A value
  // starting with "-" would be read as an ssh option (-oProxyCommand=...).
  host: z.string().min(1).refine((v) => !v.startsWith("-"), {
    message: "ssh.host must not start with '-'",
  }),
  user: z.string().min(1).refine((v) => !v.startsWith("-"), {
    message: "ssh.user must not start with '-'",
  }),
  port: z.number().int().positive().default(22),
});

export const NodeSchema = z.object({
  name: z.string().min(1).describe("Label for this host in the written data"),
  ssh: SshSchema.optional().describe(
    "Reach this host over SSH. Omit for the machine swamp is running on.",
  ),
  dir: z
    .string()
    .refine(
      (v) => SAFE_ABS_PATH.test(v) && !v.split("/").includes(".."),
      {
        message:
          "dir must be an absolute path made of [A-Za-z0-9._/-] with no '..' " +
          "segment. It is interpolated into the remote command, so a value " +
          "that could change that command's meaning is refused rather than " +
          "stripped: a half-repaired path that silently measures the wrong " +
          "directory is worse than a config error.",
      },
    )
    .optional()
    .describe(
      "Which directory's config to evaluate. mise config is directory-scoped, " +
        "so without this the question has no fixed answer. Defaults to the " +
        "swamp working directory locally and the login directory over SSH.",
    ),
  misePath: z
    .string()
    .refine((v) => SAFE_BIN_PATH.test(v) && !v.startsWith("-"), {
      message:
        "misePath must match [A-Za-z0-9._/-] and must not start with '-'",
    })
    .default("mise")
    .describe(
      "Path to the mise binary. Worth setting for SSH hosts: a non-login " +
        "shell often has no ~/.local/bin on PATH, and mise lives there.",
    ),
});

export const GlobalArgsSchema = z.object({
  nodes: z
    .array(NodeSchema)
    .min(1)
    .refine(
      (ns) => new Set(ns.map((n) => n.name)).size === ns.length,
      { message: "Duplicate node name: each node needs its own label" },
    ),
  timeoutSec: z.number().int().positive().default(15),
  maxConcurrency: z
    .number()
    .int()
    .positive()
    .default(8)
    .describe(
      "How many hosts to poll at once. A long nodes list otherwise spawns an " +
        "unbounded pile of ssh processes at the same time.",
    ),
  expect: z
    .record(z.string(), z.string())
    .default({})
    .describe(
      "Optional fleet-wide expectation, e.g. {node: '22'}. A version matches " +
        "when its dot-separated segments start with these, so '22' accepts " +
        "22.23.2 but '22.2' does not. Omit it and each host is judged only " +
        "against its own config.",
    ),
});

export type Drift =
  | "notinstalled"
  | "notactive"
  | "notineffect"
  | "outdated"
  | "expected"
  | "unmeasured";

export type ToolEntry = { installed: boolean; active: boolean };

/**
 * Does `resolved` satisfy the `expect` value? Compared segment by segment, so
 * "22" accepts 22.23.2 while "22.2" does not. A plain string prefix would
 * quietly accept 22.23.2 for an operator who asked for the 22.2 line, which is
 * the sort of near-miss nobody notices until a build breaks.
 */
export function satisfiesExpect(expected: string, resolved: string): boolean {
  const want = expected.split(".");
  const got = resolved.split(".");
  if (want.length > got.length) return false;
  return want.every((seg, i) => seg === got[i]);
}

/**
 * Drift for a single tool the current config asked for. Install state is
 * mutually exclusive (a tool cannot be both missing and merely inactive), so
 * those two are an either/or. Outdated and expect are independent judgements
 * layered on top.
 */
export function classifyTool(
  entry: ToolEntry,
  opts: { outdated: boolean; expectFail: boolean },
): Drift[] {
  const drift: Drift[] = [];
  if (!entry.installed) drift.push("notinstalled");
  else if (!entry.active) drift.push("notactive");
  if (opts.outdated) drift.push("outdated");
  if (opts.expectFail) drift.push("expected");
  return drift;
}

/** The read-only invocations this model ever makes. */
export const SUB_LS = ["ls", "--current", "--json"];
export const SUB_CONFIG = ["config", "ls", "--json"];
export const SUB_OUTDATED = ["outdated", "--json"];
export const SUB_VERSION = ["--version"];
export const SUB_TRUST = ["trust", "--show"];

/**
 * Local argv. Handed straight to Deno.Command, which does not go through a
 * shell, so nothing here can be reinterpreted no matter what dir holds.
 */
export function localArgs(dir: string | undefined, sub: string[]): string[] {
  return dir ? ["-C", dir, ...sub] : [...sub];
}

/**
 * Two operator-supplied values reach this string: `misePath` unquoted at the
 * start and `dir` single-quoted in the -C flag. Each is safe only because its
 * schema regex forbids every shell metacharacter. The quoting around dir is
 * sufficient rather than merely hopeful because the schema has already refused
 * any value containing a quote. Loosening either SAFE_BIN_PATH or
 * SAFE_ABS_PATH breaks the command without changing its text.
 */
export function remoteCommand(
  misePath: string,
  dir: string | undefined,
  sub: string[],
): string {
  const parts = [misePath];
  if (dir) parts.push("-C", `'${dir}'`);
  parts.push(...sub);
  return parts.join(" ");
}

/**
 * BatchMode=yes so an unknown host key or a password prompt fails closed
 * instead of hanging a sweep forever. ConnectTimeout is capped at ten seconds
 * because a switched-off host should not consume the whole per-node budget
 * before the command even starts.
 */
export function sshArgs(
  ssh: { host: string; user: string; port: number },
  timeoutSec: number,
  remote: string,
): string[] {
  return [
    "-o",
    "BatchMode=yes",
    "-o",
    `ConnectTimeout=${Math.min(timeoutSec, 10)}`,
    "-p",
    String(ssh.port),
    `${ssh.user}@${ssh.host}`,
    remote,
  ];
}

/**
 * A shell that cannot find mise says so in one of two shapes, and the exit
 * code alone is not enough because some invocations return 126 or 1 instead
 * of the conventional 127.
 *
 * The two phrases are not equally safe to match. "command not found" is
 * shell phrasing and mise never emits it about itself, so it can be matched
 * anywhere in stderr. "No such file or directory" is an ordinary os error
 * string, and mise is a Rust binary whose own io failures render it for an
 * unreadable config or a broken shim. Those hosts ran mise and hit a real
 * problem, so matching that phrase loosely would file a measured failure as
 * "never measured", inverting the one distinction this model is built on.
 * It is therefore only accepted behind a shell prefix.
 */
const CMD_NOT_FOUND_RE = /command not found/i;
const SHELL_NO_SUCH_FILE_RE =
  /(?:^|\n)[^\n]*sh: [^\n]*No such file or directory/i;

export function classifyFailure(
  code: number,
  stderr: string,
): "notfound" | "failed" {
  if (code === 127) return "notfound";
  if (CMD_NOT_FOUND_RE.test(stderr)) return "notfound";
  if (SHELL_NO_SUCH_FILE_RE.test(stderr)) return "notfound";
  return "failed";
}

export type RunResult =
  | { ok: true; stdout: string }
  | { ok: false; kind: "notfound" | "failed"; error: string };

export type ParsedNode = z.infer<typeof NodeSchema>;

/**
 * Run one read-only mise subcommand against one node.
 *
 * Only stderr is quoted back into the error. mise prints config contents on
 * stdout, and error strings end up in swamp run logs and reports, so stdout
 * stays out of them.
 */
export async function runMise(
  node: ParsedNode,
  sub: string[],
  timeoutSec: number,
  signal: AbortSignal,
): Promise<RunResult> {
  const bin = node.misePath ?? "mise";
  const cmd = node.ssh
    ? new Deno.Command("ssh", {
      args: sshArgs(
        node.ssh,
        timeoutSec,
        remoteCommand(bin, node.dir, sub),
      ),
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
      signal: AbortSignal.any([
        signal,
        AbortSignal.timeout((timeoutSec + 10) * 1000),
      ]),
    })
    : new Deno.Command(bin, {
      args: localArgs(node.dir, sub),
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
      signal: AbortSignal.any([
        signal,
        AbortSignal.timeout((timeoutSec + 10) * 1000),
      ]),
    });

  try {
    const out = await cmd.output();
    const stderr = new TextDecoder().decode(out.stderr).trim();
    if (!out.success) {
      return {
        ok: false,
        kind: classifyFailure(out.code, stderr),
        error: stderr.slice(0, 160) || `exit ${out.code}`,
      };
    }
    return { ok: true, stdout: new TextDecoder().decode(out.stdout) };
  } catch (e) {
    // Deno throws NotFound when the local binary itself is absent, which is
    // the same fact as a shell's 127 and must classify the same way.
    const msg = (e as Error).message;
    return {
      ok: false,
      kind: e instanceof Deno.errors.NotFound
        ? "notfound"
        : classifyFailure(-1, msg),
      error: msg.slice(0, 160),
    };
  }
}

export type ToolRow = {
  tool: string;
  requestedVersion: string | null;
  resolvedVersion: string | null;
  installPath: string | null;
  sourceType: string | null;
  sourcePath: string | null;
  installed: boolean;
  active: boolean;
  outdated: boolean;
  latestVersion: string | null;
  drift: Drift[];
};

/** JSON.parse that yields a fallback instead of throwing mid-sweep. */
function parseJson<T>(raw: string, fallback: T): T {
  try {
    const v = JSON.parse(raw);
    return v == null ? fallback : v as T;
  } catch {
    return fallback;
  }
}

const str = (v: unknown): string | null =>
  typeof v === "string" && v !== "" ? v : null;

/**
 * `mise ls --current --json` is keyed by tool name, each holding an array of
 * entries. Only the first entry per tool is the one the config selected, so
 * that is the row. Anything shaped unexpectedly is skipped rather than cast:
 * this data crosses a process boundary and nothing validates it upstream.
 */
export function parseLsCurrent(json: string): ToolRow[] {
  const obj = parseJson<Record<string, unknown>>(json, {});
  const rows: ToolRow[] = [];
  for (const [tool, entries] of Object.entries(obj)) {
    if (!Array.isArray(entries) || entries.length === 0) continue;
    const e = entries[0] as Record<string, unknown>;
    if (!e || typeof e !== "object") continue;
    const source = (e.source ?? {}) as Record<string, unknown>;
    rows.push({
      tool,
      requestedVersion: str(e.requested_version),
      resolvedVersion: str(e.version),
      installPath: str(e.install_path),
      sourceType: str(source.type),
      sourcePath: str(source.path),
      installed: e.installed === true,
      active: e.active === true,
      outdated: false,
      latestVersion: null,
      drift: [],
    });
  }
  return rows;
}

export function parseConfigLs(
  json: string,
): { path: string; tools: string[] }[] {
  const arr = parseJson<unknown[]>(json, []);
  if (!Array.isArray(arr)) return [];
  const out: { path: string; tools: string[] }[] = [];
  for (const raw of arr) {
    const c = raw as Record<string, unknown>;
    const path = str(c?.path);
    if (!path) continue;
    const tools = Array.isArray(c.tools) ? c.tools.map((t) => String(t)) : [];
    out.push({ path, tools });
  }
  return out;
}

/** Tool name to its latest version, for whatever mise reports as behind. */
export function parseOutdated(json: string): Record<string, string | null> {
  const obj = parseJson<Record<string, unknown>>(json, {});
  const out: Record<string, string | null> = {};
  for (const [tool, v] of Object.entries(obj)) {
    const rec = v as Record<string, unknown>;
    out[tool] = str(rec?.latest);
  }
  return out;
}

/**
 * `trust --show` has no JSON output, so this parses its "<path>: <status>"
 * lines. Recorded for context only. An untrusted plain [tools] config still
 * applies, so trust is never a drift trigger on its own.
 */
export function parseTrustShow(text: string): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const line of text.split("\n")) {
    const idx = line.lastIndexOf(": ");
    if (idx === -1) continue;
    const path = line.slice(0, idx).trim();
    const status = line.slice(idx + 2).trim();
    if (!path) continue;
    if (status === "trusted") out[path] = true;
    else if (status === "untrusted") out[path] = false;
  }
  return out;
}

/** Tools a config declares that never appeared in `ls --current`. */
export function notInEffect(declared: string[], present: string[]): string[] {
  const have = new Set(present);
  return declared.filter((t) => !have.has(t));
}

export const model = {
  type: "@jpisgeek/mise",
  version: "2026.08.24.1",
  globalArguments: GlobalArgsSchema,
  resources: {},
  methods: {},
};
