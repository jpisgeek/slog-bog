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
 *
 * The same rule holds one level down. A host that answers the tool list but
 * not the outdated probe is written as degraded, with the subcommands that
 * went quiet named on the record, because a drift count from a probe that
 * never ran is not a low count. It is no count at all.
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

/**
 * One host to sweep: how to reach it, which directory's config to evaluate,
 * and where the mise binary lives there. Every field that ends up
 * interpolated into a shell command (ssh.host, ssh.user, dir, misePath)
 * carries its own refinement, because this schema is the boundary where
 * operator-supplied fleet config turns into command text.
 */
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

/**
 * Everything an operator sets once for the whole sweep: which hosts to ask,
 * how long to wait on each, how many to ask concurrently, and an optional
 * fleet-wide version to hold every host to. Node names must be unique here
 * because a name is also the resource identity each sweep writes to. Two
 * hosts sharing a name would silently overwrite one another's record.
 */
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
        "22.23.2 but '22.2' does not. It can only police tools a host's own " +
        "config declares. A tool no config on that host mentions produces no " +
        "record for that host at all, so expect never flags it and its " +
        "absence is not visible in the drift counts. Omit it and each host " +
        "is judged only against its own config.",
    ),
});

/**
 * Every way a host's tools or config can diverge from what mise's own config
 * asked for, plus "unmeasured" for a host that could not be asked at all. A
 * flat list rather than one boolean per condition because a single tool can
 * carry more than one at once, installed but outdated and also failing the
 * fleet-wide expect, for instance.
 *
 * This array is the only source of truth. The Drift type and the zod enum
 * the resource schemas validate against are both derived from it, so a
 * misspelled class fails at write time instead of settling into the bog as
 * published data nobody can query for.
 */
const DRIFT_CLASSES = [
  "notinstalled",
  "notactive",
  "notineffect",
  "outdated",
  "expected",
  "unmeasured",
] as const;

/** One drift class, derived from DRIFT_CLASSES so the two cannot part ways. */
export type Drift = typeof DRIFT_CLASSES[number];

/** The same list as a zod enum, for the drift arrays the resources carry. */
const DriftEnum = z.enum(DRIFT_CLASSES);

/**
 * The only two facts classifyTool needs to place a tool on the
 * install/active axis. Kept separate from ToolRow so classification cannot
 * quietly grow a dependency on fields (versions, paths) that have nothing to
 * do with whether a tool is installed or active.
 */
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
/** Which config files are in scope and what each declares, so a piece of drift can be traced back to the file that caused it. */
export const SUB_CONFIG = ["config", "ls", "--json"];
/** Installed tools mise considers behind latest, the source for the "outdated" drift flag. */
export const SUB_OUTDATED = ["outdated", "--json"];
/** Confirms mise answered at all and records which build ran, for the node record's miseVersion field. */
export const SUB_VERSION = ["--version"];
/** Per-config trust state, recorded for context only. See parseTrustShow for why it never drives drift on its own. */
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
 * It is therefore only accepted behind a named shell at the start of a line,
 * optionally by way of the "line 1:" that bash adds. Matching any word ending
 * in "sh" was too loose by half: mise's own "failed to refresh: No such file
 * or directory" ends in "sh" and would have been filed as a missing binary.
 */
const CMD_NOT_FOUND_RE = /command not found/i;
const SHELL_NO_SUCH_FILE_RE =
  /(?:^|\n)(?:[^\s:]*\/)?(?:ash|bash|csh|dash|fish|ksh|sh|tcsh|zsh): (?:line \d+: )?[^\n]*No such file or directory/i;

/**
 * Turns an exit code and stderr into the two-way split the rest of the model
 * acts on. "notfound" means mise itself was absent, the honesty case: no
 * drift claim gets made. Anything else is "failed", a host that ran mise and
 * hit a real problem. See the regex comments above for how that split is
 * drawn.
 */
export function classifyFailure(
  code: number,
  stderr: string,
): "notfound" | "failed" {
  if (code === 127) return "notfound";
  if (CMD_NOT_FOUND_RE.test(stderr)) return "notfound";
  if (SHELL_NO_SUCH_FILE_RE.test(stderr)) return "notfound";
  return "failed";
}

/**
 * What runMise hands back: either the raw stdout of a successful call, or a
 * failure already classified into "notfound" versus "failed" so nothing
 * downstream has to re-inspect stderr to know which honesty case applies.
 */
export type RunResult =
  | { ok: true; stdout: string }
  | { ok: false; kind: "notfound" | "failed"; error: string };

/**
 * NodeSchema after zod has run: defaults (misePath, ssh.port) are filled in
 * and every refinement has already passed. runMise and its helpers take this
 * rather than the raw config type because they depend on those defaults
 * being present.
 */
export type ParsedNode = z.infer<typeof NodeSchema>;

/**
 * Run one read-only mise subcommand against one node.
 *
 * Only stderr is quoted back into the error. mise prints config contents on
 * stdout, and error strings end up in swamp run logs and reports, so stdout
 * stays out of them.
 *
 * Every host problem comes back as a RunResult. The one thing this throws is
 * the caller's own cancellation, which is not an observation about the host
 * at all and must never be written down as one.
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
    // Deno does not throw when a signal aborts a running command. It kills
    // the child and hands back success: false with SIGTERM, which is the
    // same shape as a host whose mise fell over on its own. So the caller's
    // signal is asked here, before anything gets classified, and the throw
    // goes straight back out through the catch below. Our own per-command
    // kill is composed into the same signal with AbortSignal.any and cannot
    // be told apart from the result, so only the caller's signal counts. A
    // host that ran out of time did fail to answer, and stays a failure.
    if (signal.aborted) {
      throw signal.reason ?? new Error("run cancelled by the caller");
    }
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
    // Cancellation leaves by this door, whether it was raised just above or
    // thrown by a spawn that never got off the ground. The caller pulling
    // the run away says nothing about this host, so it is never classified.
    if (signal.aborted) throw e;
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

/**
 * One tool's state as read out of `ls --current --json`, flattened from
 * mise's per-tool array-of-entries shape down to the single entry the
 * current config actually selects. `outdated`, `latestVersion`, and `drift`
 * start at their empty defaults here because parseLsCurrent only knows what
 * `ls --current` said. Those three fields are filled in later, once the
 * outdated and expect comparisons run.
 */
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

/**
 * What a subcommand promises at the top level. `ls --current` and `outdated`
 * are keyed by tool name, `config ls` is a list of files, and the two are not
 * interchangeable.
 */
type JsonShape = "object" | "array";

/**
 * Did this payload come back as the shape its subcommand promises?
 *
 * Two ways to get an answer that is not one. A remote login shell that prints
 * anything to stdout, a banner or a stray echo in ~/.bashrc, glues its own
 * text to the front of the output, and ssh reports the whole thing as exit 0.
 * Or the payload is valid JSON of the wrong top-level type.
 *
 * Both end in the same place, and it is the place this model exists to avoid.
 * The parsers below are total by design, so an array handed to the tool
 * parser yields no rows and an object handed to the config parser yields no
 * files. The payload evaporates into an empty result, and an empty result is
 * exactly what a host with nothing wrong looks like. So the shape is checked
 * here, before anything tolerant gets hold of it.
 *
 * A valid empty result of the right shape is not a failure. `{}` from
 * `ls --current` says the config in that directory declares no tools, and
 * that is a reading rather than the absence of one.
 */
function isJsonPayload(raw: string, shape: JsonShape): boolean {
  try {
    const v = JSON.parse(raw);
    if (v === null || typeof v !== "object") return false;
    return shape === "array" ? Array.isArray(v) : !Array.isArray(v);
  } catch {
    return false;
  }
}

/**
 * The stdout of a run that both succeeded and answered in the promised shape,
 * or null when any part of that failed. From a consumer's side those are one
 * fact: the probe did not answer, so nothing may be claimed from it.
 */
function jsonStdout(r: RunResult, shape: JsonShape): string | null {
  return r.ok && isJsonPayload(r.stdout, shape) ? r.stdout : null;
}

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

/**
 * `config ls --json` lists every mise config file in scope and the tools
 * each one declares. Malformed entries are skipped rather than thrown on,
 * the same choice parseLsCurrent makes, because this data also crosses a
 * process boundary and nothing upstream guarantees its shape.
 */
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

const NodeStateSchema = z.object({
  name: z.string(),
  /**
   * Did mise actually run here? Everything downstream depends on this being
   * separate from the counts. A host that did not answer has null counts, not
   * zero ones, because zero is a measurement and this is the absence of one.
   */
  measured: z.boolean(),
  /**
   * mise answered, but at least one of the follow-up subcommands did not.
   * The drift counts on a degraded node are a floor rather than a total: the
   * outdated probe has to reach an upstream registry, and a host busy enough
   * to time it out still reports every tool it has. Read this before reading
   * a zero as good news.
   */
  degraded: z.boolean(),
  /** Which subcommands went unanswered: "config", "outdated", "trust", "version". */
  failedSubcommands: z.array(z.string()),
  /**
   * How an unmeasured host failed. "notfound" when mise itself was absent,
   * "failed" when mise ran and hit a real problem, and "unparseable" when the
   * host exited zero and handed back something other than the JSON that
   * subcommand promises, usually a login shell printing over the top of the
   * answer. null on a host that answered. Each wants a different errand, and
   * a not-found host in particular wants misePath set rather than a look at
   * the network.
   */
  failureKind: z.string().nullable(),
  transport: z.string(),
  error: z.string().nullable(),
  miseVersion: z.string().nullable(),
  /** The directory the reading came from. null means wherever an ssh login lands. */
  dir: z.string().nullable(),
  configCount: z.number().nullable(),
  toolCount: z.number().nullable(),
  drift: z.array(DriftEnum),
});

const ToolStateSchema = z.object({
  node: z.string(),
  tool: z.string(),
  requestedVersion: z.string().nullable(),
  resolvedVersion: z.string().nullable(),
  installPath: z.string().nullable(),
  sourceType: z.string().nullable(),
  sourcePath: z.string().nullable(),
  installed: z.boolean(),
  active: z.boolean(),
  outdated: z.boolean(),
  latestVersion: z.string().nullable(),
  drift: z.array(DriftEnum),
});

const ConfigStateSchema = z.object({
  node: z.string(),
  path: z.string(),
  trusted: z.boolean().nullable(),
  toolsDeclared: z.array(z.string()),
  toolsInEffect: z.array(z.string()),
  toolsNotInEffect: z.array(z.string()),
});

const SummarySchema = z.object({
  nodes: z.number(),
  nodesMeasured: z.number(),
  nodesUnmeasured: z.number(),
  /**
   * Measured hosts where a follow-up subcommand went unanswered. While this
   * is above zero, every drift total below is a floor rather than a count of
   * everything out there. A sweep that could not run the outdated probe on
   * half the fleet still reports the outdated it found, and no more.
   */
  nodesDegraded: z.number(),
  tools: z.number(),
  notinstalled: z.number(),
  notactive: z.number(),
  configsNotInEffect: z.number(),
  outdated: z.number(),
  expected: z.number(),
  sweptAt: z.string(),
});

/**
 * The leading sixty-four bits of SHA-256, as sixteen lowercase hex
 * characters.
 *
 * Tool names and config paths arrive from remote hosts, and slugPart
 * collapses punctuation runs, so a host can vary punctuation invisibly to the
 * readable half of a name and go hunting for a hash that lands on another
 * host's record. Against a short non-cryptographic hash that hunt is a
 * feasible search. Against a truncated SHA-256 it is not, because there is no
 * shortcut from a target digest back to an input.
 *
 * `crypto.subtle` is a global Web API, so this stays true to a dependency
 * list that is deliberately empty. It is async, which is the only reason
 * resourceName is.
 */
async function shortHash(s: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(s),
  );
  return Array.from(new Uint8Array(digest).subarray(0, 8))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Hash input for a resource name. Each part is prefixed with its own length,
 * so the encoding is reversible and two different identities can never
 * produce the same string. Concatenating the parts directly would not manage
 * that: node "a!" with tool "b" and node "a" with tool "!b" both concatenate
 * to "a!b" and both flatten to "a-b", which is one resource name for two
 * different things, and the second sweep would quietly overwrite the first.
 */
function identityKey(parts: string[]): string {
  return parts.map((p) => `${p.length}:${p}`).join("");
}

/**
 * Resource name built to resist collision. Normalising alone is not
 * injective: node
 * "nas-01" with tool "go" and node "nas" with tool "01-go" flatten to the
 * same string, and the second write would quietly overwrite the first. mise
 * also keys backend-prefixed tools like "npm:prettier" and
 * "go:github.com/x/y", so a raw name can carry a path separator straight
 * into a resource name. The hash is taken over the raw parts, length-prefixed
 * so two different identities stay two different inputs however alike they
 * look once flattened, and it is collision-resistant, so two different
 * inputs stay two different names even when a host is choosing its tool
 * names to make them collide.
 */
async function resourceName(
  prefix: string,
  ...parts: string[]
): Promise<string> {
  const flat = parts.map(slugPart).join("-");
  return `${prefix}-${flat || "id"}-${await shortHash(identityKey(parts))}`;
}

/**
 * One identity part, flattened for the readable half of a resource name. A
 * part that flattens away to nothing becomes "x" rather than disappearing, so
 * every part keeps its position and the node name is always the first segment
 * after the prefix. That is what lets nodePrefix name a host's whole run of
 * resources without knowing which tools it had.
 */
function slugPart(p: string): string {
  const s = p
    .replace(/[^a-zA-Z0-9]+/g, "-")
    .toLowerCase()
    .replace(/^-+|-+$/g, "");
  return s === "" ? "x" : s;
}

/**
 * The leading text every tool or config resource name for one host shares.
 * The prune uses it to leave a host's stored rows alone when this sweep could
 * not measure that host. One node name that slugs to a prefix of another's
 * covers both, which errs towards keeping records rather than deleting them.
 */
function nodePrefix(prefix: string, node: string): string {
  return `${prefix}-${slugPart(node)}-`;
}

/**
 * Where a local sweep actually looks. Null when the runtime will not say,
 * which records the same "we do not know" the ssh case does rather than
 * writing down a directory nobody read.
 */
function currentDir(): string | null {
  try {
    return Deno.cwd();
  } catch {
    return null;
  }
}

/**
 * The `@jpisgeek/mise` model definition: a single `discover` method that
 * sweeps every configured node and records node, tool, and config state as
 * separate resources, so a report can filter or diff at whichever
 * granularity the drift showed up at. See the module header above for why an
 * unmeasured host is written down as unmeasured rather than folded into a
 * zero count.
 */
export const model = {
  type: "@jpisgeek/mise",
  version: "2026.08.24.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    node: {
      description:
        "One record per host: whether mise answered at all, whether it " +
        "answered in full, which directory the reading came from, and how " +
        "much drift was found there. A null dir means an ssh node with no " +
        "dir set, where the reading comes from wherever the login lands.",
      schema: NodeStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    tool: {
      description:
        "One record per tool per host: what the config asked for, what the " +
        "host resolved it to, and whether it is installed, active, or behind.",
      schema: ToolStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    config: {
      description:
        "One record per mise config file in scope, with the tools it " +
        "declares and the tools that never took effect.",
      schema: ConfigStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    summary: {
      description: "Fleet totals for the most recent sweep.",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },
  methods: {
    discover: {
      description:
        "Ask every configured host what toolchain it is running and write " +
        "down where that disagrees with its own config. Read-only: nothing " +
        "is installed, upgraded, or trusted. A full sweep deletes every " +
        "stored record it did not write this time, which includes the node " +
        "record of a host dropped from the config, not only departed tool " +
        "and config rows. A single-node run never deletes anything, and " +
        "neither does a host that came back unmeasured or only part " +
        "measured, which keeps its stored rows rather than having them read " +
        "as gone.",
      arguments: z.object({
        node: z.string().optional().describe("Limit the sweep to one node"),
      }),
      // deno-lint-ignore no-explicit-any
      execute: async (args: { node?: string }, ctx: any) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const targets = args.node
          ? g.nodes.filter((n) => n.name === args.node)
          : g.nodes;
        if (targets.length === 0) {
          throw new Error(
            `No node named '${args.node}'. Known: ${
              g.nodes.map((n) => n.name).join(", ")
            }`,
          );
        }

        ctx.logger.info("sweeping {n} host(s) for mise state", {
          n: targets.length,
        });

        const handles = [];
        const nodeStates: z.infer<typeof NodeStateSchema>[] = [];
        const toolStates: z.infer<typeof ToolStateSchema>[] = [];
        const configStates: z.infer<typeof ConfigStateSchema>[] = [];

        // Bounded concurrency: a long nodes list otherwise spawns an
        // unbounded pile of ssh processes at once.
        const queue = [...targets];
        const worker = async () => {
          for (;;) {
            // A cancelled run stops taking hosts off the queue. Churning
            // through the rest of the fleet only to throw the results away
            // wastes ssh connections on a run nobody is waiting for.
            if (ctx.signal.aborted) return;
            const node = queue.shift();
            if (!node) return;
            const transport = node.ssh ? "ssh" : "local";
            // What was measured, not what the operator typed. Left as the
            // raw input, two sweeps run from different working directories
            // would judge different configs and both record dir: null.
            const dir = node.dir ?? (node.ssh ? null : currentDir());
            try {
              const run = (sub: string[]) =>
                runMise(node, sub, g.timeoutSec, ctx.signal);

              const ls = await run(SUB_LS);
              // Two ways to learn nothing, and they take the same exit.
              // mise never ran, or mise exited zero without the tool object
              // it promises, whether a shell printed over the answer or the
              // payload came back as some other shape entirely. Parsed on
              // the tolerant path the second one writes a clean host with no
              // tools.
              const lsJson = jsonStdout(ls, "object");
              if (lsJson === null) {
                const kind = ls.ok ? "unparseable" : ls.kind;
                const err = ls.ok
                  ? "mise exited zero without the JSON object it promises"
                  : ls.error;
                // The honesty case. Counts stay null so that "we could not
                // ask" never reads downstream as "there was nothing to find".
                ctx.logger.warning(
                  "{name} unmeasured ({kind}): {err}",
                  { name: node.name, kind, err },
                );
                nodeStates.push({
                  name: node.name,
                  measured: false,
                  // Not part measured, not measured at all. The unmeasured
                  // drift record below carries that whole fact on its own.
                  degraded: false,
                  failedSubcommands: [],
                  failureKind: kind,
                  transport,
                  error: err,
                  miseVersion: null,
                  dir,
                  configCount: null,
                  toolCount: null,
                  drift: ["unmeasured"],
                });
                continue;
              }

              const rows = parseLsCurrent(lsJson);
              const ver = await run(SUB_VERSION);
              const cfg = await run(SUB_CONFIG);
              const outd = await run(SUB_OUTDATED);
              const trust = await run(SUB_TRUST);

              // A subcommand that never answered leaves a hole in the
              // reading, and the empty object it falls back to is shaped
              // exactly like good news. `outdated` is the one that has to
              // reach upstream registries, so on a busy host it is the one
              // that times out, and a drift sweep reporting no drift because
              // its drift probe timed out is the single thing this model
              // exists to prevent. Every hole is named here instead.
              //
              // The two JSON probes are held to their promised shape as
              // well as to the exit code, and the shapes differ: config ls
              // lists files, outdated is keyed by tool. `trust --show` and
              // `--version` are plain text with no shape to fail, so an exit
              // code is all there is to judge them on.
              const cfgJson = jsonStdout(cfg, "array");
              const outdJson = jsonStdout(outd, "object");
              const failed: string[] = [];
              if (cfgJson === null) failed.push("config");
              if (outdJson === null) failed.push("outdated");
              if (!trust.ok) failed.push("trust");
              if (!ver.ok) failed.push("version");
              if (failed.length > 0) {
                ctx.logger.warning(
                  "{name} answered in part, no reading from: {subs}",
                  { name: node.name, subs: failed.join(", ") },
                );
              }

              const outdated = outdJson === null ? {} : parseOutdated(outdJson);
              const configs = cfgJson === null ? [] : parseConfigLs(cfgJson);
              const trusted = trust.ok ? parseTrustShow(trust.stdout) : {};

              const nodeDrift = new Set<Drift>();
              for (const r of rows) {
                // Tool names are keys off a remote host's JSON, so every
                // lookup by one is guarded. A tool called "constructor" or
                // "__proto__" otherwise reads a function off the prototype
                // chain, which passes an undefined check and then lands in a
                // field typed string.
                const expected = Object.hasOwn(g.expect, r.tool)
                  ? g.expect[r.tool]
                  : undefined;
                const expectFail = expected !== undefined &&
                  r.resolvedVersion !== null &&
                  !satisfiesExpect(expected, r.resolvedVersion);
                const isOutdated = Object.hasOwn(outdated, r.tool);
                const drift = classifyTool(r, {
                  outdated: isOutdated,
                  expectFail,
                });
                for (const d of drift) nodeDrift.add(d);
                toolStates.push({
                  node: node.name,
                  tool: r.tool,
                  requestedVersion: r.requestedVersion,
                  resolvedVersion: r.resolvedVersion,
                  installPath: r.installPath,
                  sourceType: r.sourceType,
                  sourcePath: r.sourcePath,
                  installed: r.installed,
                  active: r.active,
                  outdated: isOutdated,
                  latestVersion: isOutdated ? outdated[r.tool] : null,
                  drift,
                });
              }

              // Config paths come off the same remote JSON as tool names and
              // need the same guard: parseConfigLs asks only for a non-empty
              // string, so "__proto__" reaches this lookup.
              const trustOf = (p: string): boolean | null =>
                Object.hasOwn(trusted, p) ? trusted[p] : null;
              const present = rows.map((r) => r.tool);
              for (const c of configs) {
                const missing = notInEffect(c.tools, present);
                if (missing.length > 0) nodeDrift.add("notineffect");
                configStates.push({
                  node: node.name,
                  path: c.path,
                  // trust --show reports the directory, config ls the file,
                  // so a miss here is unknown rather than false.
                  trusted: trustOf(c.path) ??
                    trustOf(c.path.replace(/\/[^/]+$/, "")),
                  toolsDeclared: c.tools,
                  toolsInEffect: c.tools.filter((t) => present.includes(t)),
                  toolsNotInEffect: missing,
                });
              }

              nodeStates.push({
                name: node.name,
                measured: true,
                degraded: failed.length > 0,
                failedSubcommands: failed,
                failureKind: null,
                transport,
                // A degraded host is not a clean host, so it does not get to
                // report a null error while quietly missing a reading.
                error: failed.length > 0
                  ? `part measured, no answer from: ${failed.join(", ")}`
                  : null,
                miseVersion: ver.ok
                  ? (ver.stdout.trim().split(" ")[0] || null)
                  : null,
                dir,
                // Zero configs is a measurement. No answer from config ls is
                // the absence of one, and null is how that is written down.
                configCount: cfgJson === null ? null : configs.length,
                toolCount: rows.length,
                drift: [...nodeDrift],
              });
            } catch (e) {
              // Cancellation is the caller taking the run away, not a fact
              // about this host. It is the one throw that is allowed back
              // out, so no record is invented for a host that was never
              // given the chance to answer.
              if (ctx.signal.aborted) throw e;
              // Every other unexpected throw stays with the host it came
              // from. The workers run under Promise.all, so an escaping
              // error would take the whole sweep with it and nothing at all
              // would be written, including for every host that answered.
              const msg = (e as Error)?.message ?? String(e);
              // Record first, log second. The logger is the one thing in here
              // that reaches outside this model, so it is also the one thing
              // that can throw on the way out and take the record with it.
              nodeStates.push({
                name: node.name,
                measured: false,
                degraded: false,
                failedSubcommands: [],
                // Nothing here says mise was absent. The sweep broke.
                failureKind: "failed",
                transport,
                error: msg.slice(0, 160),
                miseVersion: null,
                dir,
                configCount: null,
                toolCount: null,
                drift: ["unmeasured"],
              });
              ctx.logger.warning(
                "{name} threw mid-sweep, recorded unmeasured: {err}",
                { name: node.name, err: msg },
              );
            }
          }
        };
        await Promise.all(
          Array.from(
            { length: Math.min(g.maxConcurrency, targets.length) },
            worker,
          ),
        );

        // The single choke point. Every write below this line happens after
        // the whole fleet has been asked, so a run cancelled at any point up
        // to here leaves the last good sweep exactly as it was. Writing now
        // would replace it with a partial fleet, or with failure records for
        // hosts that were never given a chance to answer.
        if (ctx.signal.aborted) {
          throw ctx.signal.reason ??
            new Error("sweep cancelled before anything was written");
        }

        // Every name written this sweep, and the names that must survive the
        // prune anyway. A host that could not be measured, or that answered
        // only in part, says nothing about which of its tools and configs
        // still exist, so its stored rows are held rather than read as gone.
        const live = new Set<string>();
        const protectedPrefixes: string[] = [];

        for (const n of nodeStates) {
          const name = await resourceName("node", n.name);
          live.add(name);
          if (!n.measured || n.degraded) {
            protectedPrefixes.push(
              nodePrefix("tool", n.name),
              nodePrefix("config", n.name),
            );
          }
          handles.push(
            await ctx.writeResource(
              "node",
              name,
              n,
              {
                tags: {
                  measured: String(n.measured),
                  degraded: String(n.degraded),
                  transport: n.transport,
                },
              },
            ),
          );
        }
        // A tool row cannot say on its own that its host answered in part,
        // and it writes outdated: false when the outdated probe never ran.
        // The host's degraded flag rides along as a tag so a query over rows
        // alone cannot read a partial sweep as a clean one.
        const degradedNodes = new Set(
          nodeStates.filter((n) => n.degraded).map((n) => n.name),
        );
        for (const t of toolStates) {
          const name = await resourceName("tool", t.node, t.tool);
          live.add(name);
          handles.push(
            await ctx.writeResource(
              "tool",
              name,
              t,
              {
                tags: {
                  node: t.node,
                  tool: t.tool,
                  drift: t.drift.join(","),
                  degraded: String(degradedNodes.has(t.node)),
                },
              },
            ),
          );
        }
        for (const c of configStates) {
          const name = await resourceName("config", c.node, c.path);
          live.add(name);
          handles.push(
            await ctx.writeResource(
              "config",
              name,
              c,
              { tags: { node: c.node } },
            ),
          );
        }

        const count = (d: Drift) =>
          toolStates.filter((t) => t.drift.includes(d)).length;
        const degradedCount = nodeStates.filter((n) => n.degraded).length;
        handles.push(
          await ctx.writeResource("summary", "summary", {
            nodes: nodeStates.length,
            nodesMeasured: nodeStates.filter((n) => n.measured).length,
            nodesUnmeasured: nodeStates.filter((n) => !n.measured).length,
            nodesDegraded: degradedCount,
            tools: toolStates.length,
            notinstalled: count("notinstalled"),
            notactive: count("notactive"),
            configsNotInEffect: configStates.filter((c) =>
              c.toolsNotInEffect.length > 0
            ).length,
            outdated: count("outdated"),
            expected: count("expected"),
            sweptAt: new Date().toISOString(),
          }, {
            tags: {
              nodes: String(nodeStates.length),
              nodesDegraded: String(degradedCount),
            },
          }),
        );
        live.add("summary");

        // Prune only on a full sweep. A single-node run legitimately sees one
        // host's worth of resources, so it deletes nothing. Without this the
        // summary and a stale tool row end up as two published views of the
        // same fact that permanently disagree: remove a tool from a config
        // and the summary says notinstalled is zero while last sweep's row
        // still carries the drift.
        if (!args.node) {
          const existing = await ctx.dataRepository.findAllForModel(
            ctx.modelType,
            ctx.modelId,
          );
          for (const rec of existing as { name: string }[]) {
            if (live.has(rec.name)) continue;
            if (protectedPrefixes.some((p) => rec.name.startsWith(p))) continue;
            await ctx.deleteResource(rec.name);
            ctx.logger.info("pruned {name}", { name: rec.name });
          }
        }

        return { dataHandles: handles };
      },
    },
  },
};
