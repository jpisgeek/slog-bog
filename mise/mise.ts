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

/**
 * The basename `misePath` is allowed to have.
 *
 * The charset rule alone let `misePath` name any executable on the box --
 * `/bin/sh` satisfied it -- which sits badly next to a model that advertises
 * itself as read-only. The subcommands are fixed and none of them does damage
 * under a different binary, so this is not a live exploit; it is a guarantee
 * the schema was not actually keeping. It keeps it now. The point of the
 * argument is to say WHERE mise is when it is not on the PATH, and every
 * legitimate answer to that is named mise. Exactly mise, or mise.exe: the
 * first form of this allowed any extension, so mise.sh and mise.evil both
 * passed a rule documented as "the basename must be mise".
 */
const MISE_BASENAME = /(?:^|\/)mise(?:\.exe)?$/;
/**
 * Make process-controlled text printable before it reaches data, tags, or
 * logs. Escaping instead of dropping the byte keeps two hostile names from
 * collapsing into one identity and leaves a visible record of what the host
 * actually returned. The resulting text is plain ASCII at every control-byte
 * position, including ESC, so a terminal never gets a sequence to act on.
 */
/**
 * Characters that must never reach a resource field, tag, log parameter, or
 * resource name as themselves.
 *
 * This was C0 and C1 only, which is the terminal-safety half of the problem
 * and not the display-integrity half. Unicode format characters -- the
 * bidirectional overrides U+202A..U+202E and isolates U+2066..U+2069, the
 * marks U+200E/U+200F/U+061C, and the zero-width joiners -- are not control
 * bytes and pass that filter untouched. They can visually reverse or hide
 * parts of a string, so a tool named with an embedded override renders as a
 * different tool than the one stored, in a resource name a human then reads
 * to decide something. Nothing in a mise tool name, version, or path has a
 * legitimate use for them.
 *
 * Matched by Unicode general category rather than a list of code points:
 * Cc (control), Cf (format, which is where the bidi and zero-width characters
 * live), and Zl/Zp (line and paragraph separators). A list would need
 * revisiting every time Unicode adds a member; the categories do not.
 */
/**
 * Ceilings on remote input.
 *
 * Everything below crosses a process boundary from a host this model does not
 * control, and none of it had a bound. A compromised or simply broken host
 * could return output until the collector ran out of memory, or a tool name
 * long enough to make a resource name unusable. The limits are far above any
 * legitimate value -- mise's own output for a large fleet host is kilobytes,
 * not megabytes -- so they never truncate real data; they exist so the worst
 * case is bounded rather than unbounded.
 */
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_SLUG_CHARS = 64;
const MAX_DETAIL_CHARS = 160;
/**
 * The longest a single remote value may be.
 *
 * The output cap stops a host filling memory; it did not stop one putting a
 * four-megabyte tool name into a resource field and its tags, because only
 * the readable half of the resource NAME was capped. A value longer than this
 * is not a tool name, a version or a path -- filesystem paths top out around
 * 4096 bytes on Linux and the rest are far shorter -- so it is refused rather
 * than truncated. Truncating would store a different string under the same
 * identity and call it the measurement.
 */
const MAX_VALUE_CHARS = 4096;

/**
 * Read one process stream, stopping at the ceiling instead of after it.
 *
 * The first version of this bound decoded whatever `Deno.Command.output()`
 * had already buffered, which is not a bound at all: output() reads the child
 * to completion first, so a host emitting gigabytes exhausted memory before
 * the check ever ran. The limit has to be enforced where the bytes arrive.
 *
 * Truncation is reported rather than papered over. A JSON payload cut short
 * fails to parse and is already handled as an unreadable answer, and a cut
 * stderr still classifies. Returning the first few megabytes as though they
 * were the whole answer is the one behaviour that would turn a hostile host
 * into a wrong measurement rather than a failed one.
 */
async function readCapped(
  stream: ReadableStream<Uint8Array>,
  cap: number,
  onOverflow?: () => void,
): Promise<{ text: string; truncated: boolean }> {
  const decoder = new TextDecoder();
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (total + value.byteLength > cap) {
        chunks.push(value.subarray(0, cap - total));
        truncated = true;
        // Kill the child HERE, not after both streams settle. Waiting on
        // Promise.all meant this stream stopped reading while the other one
        // sat waiting for an EOF that only arrives when the child exits --
        // which a runaway producer never does. The cap fired and the sweep
        // still hung until the deadline, so the bound existed and bought
        // nothing.
        onOverflow?.();
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    // Cancel rather than drain. Draining a hostile stream to be polite is
    // the same unbounded read this exists to prevent.
    await reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
  let at = 0;
  for (const c of chunks) {
    buf.set(c, at);
    at += c.byteLength;
  }
  const text = decoder.decode(buf);
  return {
    text: truncated
      ? text + "\n[truncated: output exceeded the size limit]"
      : text,
    truncated,
  };
}

/**
 * Spawn and collect, with both streams capped and the child killed the moment
 * either one runs over. Same result shape as `Deno.Command.output()`, minus
 * the unbounded buffering.
 */
async function cappedOutput(
  cmd: Deno.Command,
): Promise<{ success: boolean; code: number; stdout: string; stderr: string }> {
  const child = cmd.spawn();
  let killed = false;
  const kill = () => {
    if (killed) return;
    killed = true;
    // The answer is already unusable, so there is nothing to gain by letting
    // the child keep producing -- and everything to lose, because the other
    // stream cannot reach EOF until it exits. Killing may race a process
    // that has already exited, which is not an error worth reporting.
    try {
      child.kill("SIGKILL");
    } catch { /* already gone */ }
  };
  const [o, e] = await Promise.all([
    readCapped(child.stdout, MAX_OUTPUT_BYTES, kill),
    readCapped(child.stderr, MAX_OUTPUT_BYTES, kill),
  ]);
  const status = await child.status;
  return {
    success: status.success && !o.truncated && !e.truncated,
    code: status.code,
    stdout: o.text,
    stderr: e.text,
  };
}

const UNSAFE_TEXT_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

function printableRemoteText(value: string): string {
  let printable = "";
  // Iterate by code point, not code unit: charCodeAt(0) on an astral
  // character returns its high surrogate, which is not the character.
  for (const char of value) {
    if (UNSAFE_TEXT_RE.test(char)) {
      const cp = char.codePointAt(0) ?? 0;
      printable += `\\u${cp.toString(16).padStart(4, "0")}`;
    } else if (char === "\\") {
      // The escape has to escape its own introducer or it is not injective,
      // and this one is used to build resource NAMES. A tool whose name
      // contains a real newline and a tool literally named "\\u000a" both
      // rendered as the same string, so they shared a resource name and an
      // identity hash: one silently overwrote the other, and the datastore
      // reported one tool where there were two. Doubling the backslash makes
      // the mapping reversible, so distinct inputs stay distinct.
      printable += "\\\\";
    } else {
      printable += char;
    }
  }
  return printable;
}

/**
 * Reduce arbitrary remote text to a fixed, safe code.
 *
 * This used to return a printable 160-character excerpt of stderr. Escaping
 * control bytes and truncating does not sanitise: remote stderr routinely
 * carries credential-bearing URLs, tokens in query strings, private hostnames,
 * account names and home-directory paths, and any of those fit in 160
 * characters. That text was written into resources AND logs, so one unlucky
 * failure published infrastructure detail into the datastore permanently.
 *
 * Classification needs to READ stderr; nothing needs to STORE it. The matching
 * still runs against the full text and only the verdict escapes.
 */
export type RemoteErrorCode =
  | "binary-missing"
  | "permission-denied"
  | "host-key-unknown"
  | "connection-failed"
  | "config-error"
  | "timed-out"
  | "nonzero-exit"
  | "unclassified";

const ERROR_PATTERNS: [RegExp, RemoteErrorCode][] = [
  [
    /host key verification failed|remote host identification/i,
    "host-key-unknown",
  ],
  [/command not found|no such file or directory/i, "binary-missing"],
  [
    /permission denied|access denied|operation not permitted/i,
    "permission-denied",
  ],
  [
    /connection (refused|closed|timed out)|could not resolve|network is unreachable|no route to host/i,
    "connection-failed",
  ],
  [/timed out|timeout/i, "timed-out"],
  [/toml|parse error|invalid config/i, "config-error"],
];

/**
 * Classify remote failure text into one of a closed set of codes. Never
 * returns any part of the input. Order matters: the most specific patterns
 * are tried first, because "connection timed out" is a connection failure
 * rather than our deadline expiring.
 */
export function remoteErrorCode(value: string): RemoteErrorCode {
  for (const [re, code] of ERROR_PATTERNS) if (re.test(value)) return code;
  return "unclassified";
}

const SshSchema = z.object({
  // host/user become the positional `user@host` argument to ssh. A value
  // starting with "-" would be read as an ssh option (-oProxyCommand=...).
  // Refusing a leading dash stops either being read as an option. These
  // charsets are the rest of the answer: neither reaches a shell here, but
  // both are interpolated into a destination that ssh itself parses, and an
  // `@` or a `:` inside one silently changes which host is contacted. Held
  // to what a hostname and a username can actually contain.
  host: z.string().min(1).max(253).regex(/^[A-Za-z0-9]([A-Za-z0-9._-]*)$/, {
    message: "ssh.host must be a hostname: letters, digits, dot, dash, " +
      "underscore, and must not start with '-'",
  }),
  user: z.string().min(1).max(64).regex(/^[A-Za-z0-9_][A-Za-z0-9._-]*$/, {
    message: "ssh.user must be a username: letters, digits, dot, dash, " +
      "underscore, and must not start with '-'",
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
/**
 * A host label: non-empty, and printable all the way through.
 *
 * Hoisted so the `node` method argument is held to the same rule as the
 * config value it is compared against. It was a bare string, which made it
 * the one place in this model where unprintable text reached a message --
 * by arriving from the caller rather than from a host, and so missing every
 * filter aimed at hosts.
 */
const NodeLabelSchema = z
  .string()
  .min(1)
  .max(MAX_SLUG_CHARS)
  .refine((v) => printableRemoteText(v) === v, {
    message: "name must not contain terminal control characters",
  })
  // Screened the same way a host's strings are. A label is operator config
  // rather than remote input, which is why it was exempt -- but it is the
  // single most widely published value this model handles: it reaches
  // resource data, resource names, tags on every row, and log lines, and
  // none of the host-facing screening ever saw it. Refused at parse time
  // rather than dropped, because unlike a host's answer this is something
  // the operator can simply rewrite, and a silently renamed node would
  // scatter its history across two identities.
  .refine((v) => safeRemoteString(v) !== null, {
    message: "name must not look like a credential or a URL carrying one",
  });

export const NodeSchema = z.object({
  name: NodeLabelSchema
    .describe("Label for this host in the written data"),
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
    .refine(
      (v) =>
        SAFE_BIN_PATH.test(v) && !v.startsWith("-") && MISE_BASENAME.test(v),
      {
        message:
          "misePath must match [A-Za-z0-9._/-], must not start with '-', " +
          "and must name a mise binary",
      },
    )
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
  errorDetail: z
    .boolean()
    .default(false)
    .describe(
      "Store a bounded excerpt of an UNMEASURED host's own error text " +
        "alongside the classification code, for diagnosis. Only the probe " +
        "that decides whether a host was measured at all carries text here: " +
        "a host that answered and then had a follow-up probe fail is " +
        "degraded, and names the probe in failedSubcommands rather than " +
        "storing its text. OFF by default, and it " +
        "should stay off wherever the datastore is not fully trusted: host " +
        "error text routinely carries credential-bearing URLs, tokens, " +
        "private hostnames and home paths, and resource data is durable and " +
        "readable. The trade is real -- with this off a novel failure " +
        "classifies as 'unclassified' and you lose the detail that would " +
        "explain it. Turn it on for a private fleet whose datastore you own " +
        "and need to debug; leave it off for anything shared. The " +
        "classification code is written either way; this only adds a second " +
        "field beside it.",
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
export type ToolEntry = {
  installed: boolean;
  active: boolean;
  /**
   * The version mise resolved, or null when it did not report one. Part of
   * the classification input rather than a display field: an installed and
   * active tool with no version is a hole, and every version-dependent
   * judgement passes silently on it.
   */
  resolvedVersion: string | null;
};

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
  opts: { outdated: boolean | null; expectFail: boolean },
): Drift[] {
  const drift: Drift[] = [];
  if (!entry.installed) drift.push("notinstalled");
  else if (!entry.active) drift.push("notactive");
  // An installed, active tool with no resolved version is a hole, not a
  // clean row. Every version-dependent judgement below silently passes on
  // it: an `expect` rule cannot fail a version it does not have, so the
  // tool came back with no drift at all and read as healthy. Absence again,
  // wearing the shape of a pass.
  else if (entry.resolvedVersion === null) drift.push("unmeasured");
  // null is "we could not ask", which is a different fact from "not behind".
  // It earns `unmeasured` rather than silently contributing nothing, so a
  // failed outdated probe is visible in the drift set instead of looking
  // exactly like a clean result.
  if (opts.outdated === null) drift.push("unmeasured");
  else if (opts.outdated) drift.push("outdated");
  if (opts.expectFail) drift.push("expected");
  return drift;
}

/** The read-only invocations this model ever makes. */
export const SUB_LS = ["ls", "--current", "--json"];
/** Which config files are in scope and what each declares, so a piece of drift can be traced back to the file that caused it. */
export const SUB_CONFIG = ["config", "ls", "--json"];
/** Installed tools mise considers behind latest, the source for the "outdated" drift flag. */
export const SUB_OUTDATED = ["outdated", "--json"];
/**
 * The version mise reported, or null if it did not report one.
 *
 * `mise version` prints "2025.1.0 macos-arm64 (...)", so the first token is
 * the version. Anything that is not version-shaped is a host printing over
 * the answer, and null is how that gets said -- which in turn marks the node
 * degraded rather than letting a banner stand in for a version.
 */
export function parseVersion(stdout: string): string | null {
  const first = printableRemoteText(stdout.trim()).split(/\s+/)[0] ?? "";
  // Anchored at both ends. Unanchored, "1evil" matched its leading digit and
  // was accepted as a version, which is exactly the banner case this check
  // exists to catch -- and being accepted, it kept the host off the degraded
  // list. mise versions are calendar-style dotted numbers, optionally with a
  // pre-release suffix, and nothing else is a version this model will report.
  return /^v?\d+(\.\d+){0,3}(-[0-9A-Za-z.]+)?$/.test(first) ? first : null;
}

/**
 * Confirms mise answered at all and records which build ran, for the node
 * record's miseVersion field.
 *
 * The `version` SUBCOMMAND, not the `--version` flag. Every invocation this
 * model makes is prefixed with `-C <dir>` whenever a node sets `dir`, and
 * `mise -C <dir> --version` is not a form mise accepts: it prints its full
 * help to stdout and exits 1. That read as a failed probe, so every node with
 * `dir` set -- the configuration this model's own documentation recommends --
 * came back permanently degraded with `version` in failedSubcommands and a
 * null miseVersion, which in turn nulled `outdated` and `configsNotInEffect`
 * on the summary. `mise -C <dir> version` prints the same string the flag
 * does and exits 0. Note this was the only SUB_* that was a top-level flag
 * rather than a subcommand; keep it that way.
 */
export const SUB_VERSION = ["version"];
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
    // BatchMode alone does NOT guarantee an unknown host key fails closed:
    // it disables the interactive prompt, but ambient ssh_config can still
    // set StrictHostKeyChecking=no or accept-new, in which case ssh trusts a
    // key it has never seen and connects anyway. Passing the policy on the
    // command line beats any config file, so the guarantee is ours rather
    // than the operator's environment's.
    "-o",
    "StrictHostKeyChecking=yes",
    // Same reasoning, applied to what this connection hands the remote host
    // rather than what it trusts about it. ssh inherits ambient config, so a
    // ForwardAgent in the operator's ~/.ssh/config -- a perfectly ordinary
    // thing to have there for hosts you use interactively -- would expose
    // the authentication agent to every host this model sweeps. An agent
    // socket on a remote box can sign for the key it holds, which for a
    // fleet key is every host that trusts it. A read-only inventory probe
    // has no business offering that, so all four forwardings are refused on
    // the command line where no config file can put them back.
    // ProxyCommand and LocalCommand are the two ambient directives that run
    // a shell command, and ssh expands %h and %u into them -- so an operator
    // config written for interactive use turns every value in this model's
    // node list into shell input on the local machine. Same class as the
    // forwardings below, and the same answer: state it on the command line,
    // where no config file can put it back.
    // Multiplexing has to be off, and this is the sharpest of the ambient
    // problems: with a ControlMaster socket already open, ssh hands the
    // session to the existing connection and every option below is simply
    // not consulted. The strict host-key policy this model insists on would
    // be bypassed by a connection someone opened earlier under a weaker one.
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
    // SendEnv is deliberately NOT set here. `-o SendEnv=-*` looks like it
    // clears the list and does not: command-line options are read before
    // config files, and SendEnv accumulates, so a `SendEnv AWS_*` in the
    // operator's config is added afterwards and survives. Verified against
    // ssh -G rather than assumed. Shipping the option anyway would put a
    // guarantee in the argv that the argv does not keep, which is worse than
    // the gap. The residual is documented in the README instead: it needs a
    // SendEnv or SetEnv in the operator's own config AND a matching
    // AcceptEnv on the target, and `-F /dev/null` would close it only by
    // discarding the per-host IdentityFile and ProxyJump settings a real
    // fleet depends on.
    "-o",
    "ProxyCommand=none",
    "-o",
    "PermitLocalCommand=no",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    "-o",
    "ForwardX11Trusted=no",
    "-o",
    "ClearAllForwardings=yes",
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
  | {
    ok: false;
    kind: "notfound" | "failed";
    /** Closed-set classification code. Always safe to store. */
    error: string;
    /**
     * A bounded printable excerpt of the host's own text. Carried so the
     * caller CAN store it when errorDetail is enabled, and simply dropped
     * when it is not. Kept off `error` so the safe field can never
     * accidentally become the unsafe one.
     */
    detail?: string;
  };

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
  // Our own deadline gets its own controller rather than being folded into the
  // caller's signal with AbortSignal.any. Composed that way the two are
  // indistinguishable afterwards, so a host that merely took too long was
  // reported as a generic remote failure -- a classification that says
  // something about the host when the truth was about us.
  const deadline = new AbortController();
  const timer = setTimeout(
    () => deadline.abort(new Error("deadline")),
    (timeoutSec + 10) * 1000,
  );
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
      signal: AbortSignal.any([signal, deadline.signal]),
    })
    : new Deno.Command(bin, {
      args: localArgs(node.dir, sub),
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
      signal: AbortSignal.any([signal, deadline.signal]),
    });

  try {
    const out = await cappedOutput(cmd);
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
    // Our own deadline, not the caller's cancellation. Keeping the two signals
    // apart is the whole point: a host that merely ran out of time is a fact
    // about the host, and folding it into the caller's signal made it
    // indistinguishable from a generic remote failure.
    if (deadline.signal.aborted) {
      return { ok: false, kind: "failed", error: "timed-out" };
    }
    const stderr = out.stderr.trim();
    if (!out.success) {
      return {
        ok: false,
        kind: classifyFailure(out.code, stderr),
        error: stderr ? remoteErrorCode(stderr) : "nonzero-exit",
        detail: safeDetail(stderr),
      };
    }
    return { ok: true, stdout: out.stdout };
  } catch (e) {
    // Cancellation leaves by this door, whether it was raised just above or
    // thrown by a spawn that never got off the ground. The caller pulling
    // the run away says nothing about this host, so it is never classified.
    if (signal.aborted) throw e;
    if (deadline.signal.aborted) {
      return { ok: false, kind: "failed", error: "timed-out" };
    }
    // Deno throws NotFound when the local binary itself is absent, which is
    // the same fact as a shell's 127 and must classify the same way.
    const msg = (e as Error).message;
    return {
      ok: false,
      kind: e instanceof Deno.errors.NotFound
        ? "notfound"
        : classifyFailure(-1, msg),
      error: e instanceof Deno.errors.NotFound
        ? "binary-missing"
        : remoteErrorCode(msg),
      detail: safeDetail(msg),
    };
  } finally {
    // A long-lived process running many probes would otherwise accumulate one
    // live timer per call until each fired.
    clearTimeout(timer);
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
  /** null until the outdated probe answers -- and stays null if it failed. */
  outdated: boolean | null;
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
/**
 * JSON.parse, narrowed rather than asserted.
 *
 * The generic form of this took a type parameter and returned `v as T`, which
 * is a promise the caller makes about a remote host's output rather than
 * anything checked. `parseJson<Record<string, unknown>>` on an array returned
 * the array, and Object.entries over it produced rows keyed "0", "1", "2".
 * These two return null on the wrong shape so the caller has to say what that
 * means, which for every caller here is "the host did not answer".
 */
function parseJsonObject(raw: string): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(raw);
    return typeof v === "object" && v !== null && !Array.isArray(v)
      ? v as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function parseJsonArray(raw: string): unknown[] | null {
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

const str = (v: unknown): string | null =>
  typeof v === "string" && v !== "" && v.length <= MAX_VALUE_CHARS
    ? printableRemoteText(v)
    : null;

/**
 * Values that must never be persisted, however they arrive.
 *
 * These strings come off a remote host and are written into resource data and
 * into resource NAMES, both of which are durable and readable. A tool source
 * path or install path can legitimately be a URL, and a URL can legitimately
 * carry userinfo or a token in its query -- at which point publishing it is
 * publishing a credential.
 */
/**
 * The names a credential is written down under, with an optional prefix.
 *
 * The prefix alternative is the point: `\b(token)` does not match inside
 * GITHUB_TOKEN, because underscore is a word character, so every
 * environment-variable-shaped name walked past the rule that was supposed to
 * catch it. Shared between the field filter and the free-text one so the two
 * cannot drift apart again, which they already did once.
 */
const CREDENTIAL_KEYWORDS =
  "(?:[A-Za-z0-9]+[_-])*(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|secret|password|passwd|passphrase|pwd|credential|client[_-]?secret|session|session[_-]?id|sessionid|cookie|set[_-]?cookie|auth|pat|sig|signature)(?:[_-][A-Za-z0-9]+)*";

const CREDENTIAL_SHAPES: RegExp[] = [
  // Auth material inline. This required twelve characters and knew only
  // about bearer, while the free-text filter had already been widened to
  // every scheme and no minimum -- so the stricter rule guarded error prose
  // and the looser one guarded the fields that are actually published. What
  // follows an auth scheme is a credential however short it is, and Basic
  // is the one most likely to appear in a source URL.
  // The negative lookahead is for the free-text path, which replaces the
  // credential with this placeholder before the whole-string check runs.
  // Without it the check matches its own output and throws away the
  // surrounding sentence, which is the part worth keeping.
  /\b(?:bearer|basic|digest|negotiate|authorization)\s+(?!\[withheld\])\S+/i,
  // A private key body. Matched on BEGIN and PRIVATE KEY separately rather
  // than as one run of text, because the previous single pattern missed a
  // header whose internal spacing had been changed or wrapped.
  /-----BEGIN[\s\S]{0,40}PRIVATE\s*KEY/i,
  // A secret-looking assignment anywhere, not only after a URL separator.
  // The previous form required ? & or # in front, so a bare `token=...` in
  // a path or an error sentence passed untouched.
  // The keyword may carry a prefix. `\b(token)` does not match inside
  // GITHUB_TOKEN, because underscore is a word character, so every
  // environment-variable-shaped name -- the commonest way a secret is
  // actually written down -- walked past this rule untouched.
  new RegExp(
    `\\b${CREDENTIAL_KEYWORDS}\\s*[=:]\\s*(?!\\[withheld\\])\\S`,
    "i",
  ),
  // A long unbroken high-entropy-looking run: the shape of a bare key sitting
  // on its own with nothing around it to name it. Deliberately conservative
  // about length so ordinary hashes in paths -- a nix store path, a git sha
  // -- are not caught, and deliberately requiring mixed case and digits so
  // hex digests and lowercase words are not.
  /(?=[A-Za-z0-9_-]{40,})(?=[A-Za-z0-9_-]*[a-z])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{40,}/,
];

/**
 * Anything that looks like it could be a URL, anywhere in the value.
 *
 * This was anchored at the start, so a URL wrapped in punctuation or sitting
 * inside a longer string -- `(https://u@host/x)`, or a source field that
 * names a path and then a URL -- never reached the URL rule at all. It is
 * unanchored now and the match is extracted before parsing, so the rule
 * applies wherever the URL happens to be.
 *
 * Deliberately loose: the cost of testing something that is not a URL is one
 * failed parse, and the cost of missing one is publishing a credential.
 */
const URLISH_RE = /[a-z][a-z0-9+.-]*:\/\/[^\s]+/gi;

/**
 * Locations that carry userinfo without a scheme in front of them.
 *
 * The URL rule only ever saw `scheme://`, and two extremely ordinary forms
 * are not written that way. scp-style git remotes -- `user@host:path`, which
 * is how most git sources are actually written and so how a mise tool source
 * is likely to arrive -- and scheme-relative URLs, `//user@host/path`. Both
 * put an account name, and sometimes a password, in front of a private
 * hostname, and both went into stored data untouched while the README said
 * credential-bearing URLs are withheld.
 *
 * Matched by shape rather than parsed, because neither form is something
 * `new URL()` will accept.
 */
const USERINFO_NO_SCHEME: RegExp[] = [
  // scp-style: user@host:path, with an optional :password. Requires a
  // colon-path after the host so an ordinary email address in an error
  // sentence is not mistaken for a location. The host alternative includes
  // the bracketed IPv6 form, which the first version of this did not. A
  // literal address in a source location is nearly always an internal one,
  // and userinfo in front of a bracketed address slipped through with
  // username, password and address intact. The shape is described rather
  // than written out: an example address here trips the identifier scanner
  // that guards this repo, which is the scanner doing its job.
  /(?:^|[\s(<'"])[A-Za-z0-9._~%-]+(?::[^\s@]*)?@(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):[^\s]/,
  // scheme-relative with userinfo, same two host forms
  /(?:^|[\s(<'"])\/\/[A-Za-z0-9._~%-]+(?::[^\s@]*)?@(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)/,
];

/**
 * Does this URL carry anything beyond the location of a thing?
 *
 * The previous version matched two regexes: userinfo in its user-and-password
 * form, and a query parameter whose NAME was on a list. Both are the wrong
 * shape of test. A username with no password is still an account name; a
 * signing parameter nobody thought to list still signs; and a list of secret
 * parameter names is a list that is wrong the moment a registry invents a new
 * one. So the rule is inverted: a source or install URL legitimately needs a
 * scheme, a host and a path, and nothing else. Any username, any password,
 * any query, any fragment means this is not just a location, and a value that
 * is not just a location does not get persisted.
 */
function urlCarriesMoreThanLocation(value: string): boolean {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    // Fail closed. This returned false -- "carries nothing extra" -- which
    // meant anything URL-shaped that would not parse skipped the check
    // entirely. `https://user:pass@` has no host, so it does not parse, and
    // it went into stored data with its credentials intact while the README
    // said credential-bearing URLs are withheld. A value that announces
    // itself as a URL and then cannot be read as one is not a value this
    // model can vouch for, so it is treated as carrying more than a
    // location. Only strings matched by URLISH_RE reach here, so an
    // ordinary path or version is unaffected.
    return true;
  }
  return u.username !== "" || u.password !== "" ||
    u.search !== "" || u.hash !== "";
}

/**
 * A remote string that is safe to persist, or null.
 *
 * Omits rather than redacts. A redacted value invites the reader to believe
 * the rest of the field is intact, and a partially-scrubbed URL is still a
 * hostname and a path. Absence is honest and the resource schema already
 * allows null for every one of these fields.
 */
export function safeRemoteString(v: unknown): string | null {
  const s = str(v);
  if (s === null) return null;
  // Every URL-shaped run in the value, not just one anchored at the start.
  // Trailing punctuation is trimmed before parsing so `(https://u@h/x)`
  // is judged as the URL it contains rather than failing to parse and
  // passing.
  for (const m of s.matchAll(URLISH_RE)) {
    const candidate = m[0].replace(/[)\]}>.,;'"]+$/, "");
    if (urlCarriesMoreThanLocation(candidate)) return null;
  }
  // The schemeless forms, which new URL() will not parse and the rule above
  // therefore never saw.
  for (const re of USERINFO_NO_SCHEME) if (re.test(s)) return null;
  for (const re of CREDENTIAL_SHAPES) if (re.test(s)) return null;
  return s;
}

/**
 * A bounded, screened excerpt of a host's own error text.
 *
 * This is the value behind the opt-in `errorDetail` argument, and it is the
 * one place this model stores text it did not choose the shape of. Free text
 * cannot be validated the way a field can, so it gets three passes: control
 * and format characters escaped, credential-shaped tokens removed rather than
 * redacted, and a hard length bound.
 *
 * Screening is per whitespace-separated token because the interesting case is
 * a URL or a key sitting inside a sentence -- "failed to fetch <url>" should
 * keep the sentence and lose the URL. A token that screens out is dropped
 * entirely; the marker says a token was there without saying what it was.
 */
function safeDetail(text: string): string | undefined {
  const printable = printableRemoteText(text).trim();
  if (printable === "") return undefined;
  // Whole-string pass first, before tokenizing. `password = swordfish` is
  // three whitespace-separated tokens and no single one of them is an
  // assignment, so per-token screening walked straight past it. Here the
  // assignment and whatever follows it are replaced together.
  const deassigned = printable
    .replace(
      // To end of line, not to the first space. A passphrase may contain
      // spaces, and stopping at the first one withheld its opening word and
      // published the rest -- worse than withholding nothing, because it
      // reads as though the screening worked.
      new RegExp(`\\b(${CREDENTIAL_KEYWORDS})\\s*[=:].*`, "gi"),
      "$1=[withheld]",
    )
    // Same reason, different shape. `Bearer abc123` is two whitespace-
    // separated tokens and neither is a credential on its own -- the scheme
    // word is a word and the token is an opaque string with nothing about it
    // to match. Only the pair means anything, so the pair is matched here,
    // with no minimum length: what follows an auth scheme is a credential
    // however short it is.
    .replace(
      /\b(bearer|basic|digest|negotiate|authorization)\s+\S+/gi,
      "$1 [withheld]",
    );
  // Whole-string shapes before tokenizing, because some of them span
  // whitespace and no single token carries them. A PEM header is five words:
  // tokenized, not one of them is a private key, so the marker this model
  // has screened for from the start never matched inside error text at all.
  for (const re of CREDENTIAL_SHAPES) {
    if (re.test(deassigned)) return "[withheld: unscreenable error text]";
  }
  const kept = deassigned
    .split(/(\s+)/)
    .map((tok) =>
      (/\s/.test(tok) || safeRemoteString(tok) !== null) ? tok : "[withheld]"
    )
    .join("");
  return kept.slice(0, MAX_DETAIL_CHARS);
}

/**
 * A count of entries a parser refused.
 *
 * Every parser below skips entries it cannot vouch for, which is correct --
 * a malformed row is not a measurement. What was wrong was skipping them
 * silently: a host that answered with fifty tools and forty malformed rows
 * produced ten clean rows and a node record that claimed to be fully
 * measured. The reader could not tell a thin host from a broken answer.
 *
 * A sink is optional so the parsers stay callable on their own, and it is a
 * mutable object rather than a changed return type so the counting is
 * additive across the several parsers that feed one node's reading.
 */
export interface DropSink {
  dropped: number;
  /**
   * Tool names whose outdated entry was dropped.
   *
   * The count alone was not enough here. `outdated` is read by asking whether
   * a tool is a key in the map, so a tool whose entry was malformed fell out
   * of the map and came back as "not outdated" -- absence read as health, the
   * exact failure this model exists to prevent, one level below where it was
   * already being prevented. A name in this set means "nobody measured this
   * tool", which classifies as unmeasured rather than current.
   */
  unmeasuredTools?: Set<string>;
}

function noteDrop(sink: DropSink | undefined): void {
  if (sink) sink.dropped += 1;
}

/**
 * A remote string safe to use as a KEY, or null.
 *
 * Same screening as safeRemoteString, applied to the values that become tool
 * names, config paths and tags. Screening only the value fields was half a
 * job: a key is written into resource names and into tags, which are the most
 * visible and most queried surface of the whole record, and nothing stopped a
 * tool name from being a URL carrying userinfo. A key cannot be nulled the way
 * a field can -- there is nothing left to hang the row on -- so an unsafe key
 * drops the entry and counts it.
 */
export function safeRemoteKey(v: unknown, sink?: DropSink): string | null {
  const s = safeRemoteString(v);
  if (s === null) noteDrop(sink);
  return s;
}

/**
 * Response shapes, validated rather than cast.
 *
 * Known fields are type-checked strictly: a `version` that arrives as a number
 * or an `installed` that arrives as the string "true" is a malformed response,
 * not something to coerce. `e.installed === true` silently read every one of
 * those as false.
 *
 * Unknown fields are tolerated but not kept, which is zod's default and is
 * what was wanted all along. mise adds fields between releases, and failing
 * the whole probe on an upstream addition would turn every mise upgrade into
 * an outage of this collector -- a worse and far more likely failure than the
 * one strictness prevents. These schemas carried `.loose()` on the belief
 * that it was needed for that tolerance. It was not: the default already
 * accepts an unrecognized field without complaint. All `.loose()` added was
 * PASSTHROUGH, so unvalidated remote data rode along inside a parsed object
 * that read as validated -- the one thing nobody wanted. Dropping it keeps
 * the compatibility and loses the passthrough.
 */
/**
 * One entry of `mise ls --current --json`.
 *
 * `installed` and `active` are required, because they are the measurement.
 * They were optional, and `e.installed === true` read a missing field as
 * false -- so `{}` parsed cleanly into a row saying the tool is present in
 * the config, not installed, not active, with null versions, and nothing
 * anywhere said the host had not actually answered. An entry that does not
 * carry both is not a reading and is dropped and counted.
 *
 * The version and path fields stay optional because mise genuinely omits
 * them: a tool declared but never installed has no install path and no
 * resolved version, and that absence is itself the measurement.
 */
const LsEntrySchema = z.object({
  version: z.string().optional(),
  requested_version: z.string().optional(),
  install_path: z.string().optional(),
  installed: z.boolean(),
  active: z.boolean(),
  source: z.object({
    type: z.string().optional(),
    path: z.string().optional(),
  }).optional(),
});

/**
 * One row of `mise config ls --json`.
 *
 * `tools` is required on purpose. It was optional, and a missing `tools`
 * became `[]` -- a config that declares nothing, which is a measurement, when
 * what actually happened is that the host did not say. That is the same
 * mistake as reading a failed outdated probe as "everything is current", one
 * level down. An entry without it is dropped and counted.
 */
const ConfigEntrySchema = z.object({
  path: z.string(),
  tools: z.array(z.string()),
});

/**
 * The one field the prune reads off a stored record. Validated because the
 * loop that reads it deletes.
 */
const StoredRecordSchema = z.object({
  // Printable, not merely non-empty. This name is read back out of the
  // datastore and written straight into a log line, so it is remote-shaped
  // text arriving by a route none of the host-facing filters cover -- a
  // record written by an older version, or by anything else sharing the
  // store, could put control and format characters into log output.
  name: z.string().min(1).refine((v) => printableRemoteText(v) === v),
});

const OutdatedEntrySchema = z.object({
  latest: z.string().optional(),
});

/**
 * `mise ls --current --json` is keyed by tool name, each holding an array of
 * entries. Only the first entry per tool is the one the config selected, so
 * that is the row. Anything shaped unexpectedly is skipped rather than cast:
 * this data crosses a process boundary and nothing validates it upstream.
 */
export function parseLsCurrent(json: string, sink?: DropSink): ToolRow[] {
  const obj = parseJsonObject(json);
  if (obj === null) return [];
  const rows: ToolRow[] = [];
  for (const [tool, entries] of Object.entries(obj)) {
    if (!Array.isArray(entries) || entries.length === 0) {
      noteDrop(sink);
      continue;
    }
    // Validated, not cast. `entries[0] as Record<string, unknown>` accepted a
    // number, a string, or null and then read properties off it, which is how
    // a malformed response became a row of nulls that looked measured.
    const parsed = LsEntrySchema.safeParse(entries[0]);
    if (!parsed.success) {
      noteDrop(sink);
      continue;
    }
    const name = safeRemoteKey(tool, sink);
    if (name === null) continue;
    const e = parsed.data;
    const source = e.source ?? {};
    rows.push({
      tool: name,
      requestedVersion: safeRemoteString(e.requested_version),
      resolvedVersion: safeRemoteString(e.version),
      installPath: safeRemoteString(e.install_path),
      sourceType: safeRemoteString(source.type),
      // Source and install paths are the most likely of these to be a URL,
      // and therefore the most likely to carry userinfo or a token.
      sourcePath: safeRemoteString(source.path),
      installed: e.installed === true,
      active: e.active === true,
      outdated: null,
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
  sink?: DropSink,
): { path: string; tools: string[] }[] {
  const arr = parseJsonArray(json);
  if (arr === null) return [];
  const out: { path: string; tools: string[] }[] = [];
  const seen = new Set<string>();
  for (const raw of arr) {
    // Validated, not cast. The cast let a number or null through and then
    // read `.path` off it, which is undefined rather than an error.
    const parsed = ConfigEntrySchema.safeParse(raw);
    if (!parsed.success) {
      noteDrop(sink);
      continue;
    }
    const path = safeRemoteKey(parsed.data.path, sink);
    if (path === null) continue;
    // A repeated path is two rows that will be written under one resource
    // name, so the second silently overwrites the first while both are
    // counted in the summary -- contradictory data and a total that does
    // not match it. The first wins and the repeat is counted as a drop,
    // which marks the host degraded and says the reading is partial.
    if (seen.has(path)) {
      noteDrop(sink);
      continue;
    }
    seen.add(path);
    // A declared tool name becomes a tag, so it is screened the same way. A
    // dropped name is counted: the config still parsed, but the list of what
    // it declares is now short, and a short list reads as "declares less".
    const tools: string[] = [];
    for (const t of parsed.data.tools) {
      const name = safeRemoteKey(t, sink);
      if (name !== null) tools.push(name);
    }
    out.push({ path, tools });
  }
  return out;
}

/**
 * Tool name to its latest version, for whatever mise reports as behind.
 *
 * The accumulator is built with no prototype, because every key in it is a
 * tool name a remote host chose. On a plain object, a lookup that misses
 * walks up to Object.prototype and hands back a function for "constructor"
 * or "toString", which is how a remote tool name gets something other than a
 * version out of a map typed as versions. With no prototype there is nowhere
 * for a lookup to walk, so anything read back is something this parser put
 * there. Callers still use Object.hasOwn, and now they are not the only
 * thing standing in the way.
 */
export function parseOutdated(
  json: string,
  sink?: DropSink,
): Record<string, string | null> {
  const obj = parseJsonObject(json);
  if (obj === null) return Object.create(null);
  const out: Record<string, string | null> = Object.create(null);
  for (const [tool, v] of Object.entries(obj)) {
    const parsed = OutdatedEntrySchema.safeParse(v);
    if (!parsed.success) {
      noteDrop(sink);
      // The value was malformed, but the key still names a real tool, and
      // that name is what stops its row reading as current.
      const named = safeRemoteString(tool);
      if (named !== null) sink?.unmeasuredTools?.add(named);
      continue;
    }
    const name = safeRemoteKey(tool, sink);
    if (name === null) continue;
    out[name] = safeRemoteString(parsed.data.latest);
  }
  return out;
}

/**
 * `trust --show` has no JSON output, so this parses its "<path>: <status>"
 * lines. Recorded for context only. An untrusted plain [tools] config still
 * applies, so trust is never a drift trigger on its own.
 */
export function parseTrustShow(
  text: string,
  sink?: DropSink,
): Record<string, boolean> {
  // No prototype here either. These keys are config paths from the same
  // remote host, so a lookup that misses must come back empty rather than
  // walking up to Object.prototype and finding a function.
  const out: Record<string, boolean> = Object.create(null);
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    const idx = line.lastIndexOf(": ");
    if (idx === -1) {
      noteDrop(sink);
      continue;
    }
    const path = safeRemoteKey(line.slice(0, idx).trim(), sink);
    const status = line.slice(idx + 2).trim();
    if (path === null) continue;
    if (status === "trusted") out[path] = true;
    else if (status === "untrusted") out[path] = false;
    // Any other status is a line this parser does not understand, which is
    // the same kind of hole as a malformed row.
    else noteDrop(sink);
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
   * mise answered, but at least one of the follow-up subcommands did not, or
   * some of what it did answer was unreadable.
   * The drift counts on a degraded node are a floor rather than a total: the
   * outdated probe has to reach an upstream registry, and a host busy enough
   * to time it out still reports every tool it has. Read this before reading
   * a zero as good news.
   */
  degraded: z.boolean(),
  /** Which subcommands went unanswered: "config", "outdated", "trust", "version". */
  failedSubcommands: z.array(z.string()),
  /**
   * How many entries this host's answers contained that no parser would
   * vouch for: malformed rows, unreadable trust lines, and names that
   * screened as credential-shaped. Non-zero means the counts below are a
   * floor, and it is why such a host is degraded rather than clean. Null on
   * a host that was never measured, because nothing was parsed to drop.
   */
  droppedEntries: z.number().nullable(),
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
  /** Always a closed-set classification code, never host text. */
  error: z.string().nullable(),
  /**
   * A bounded excerpt of the host's own error text, present only when the
   * errorDetail global argument is enabled. Null otherwise, and null on
   * success. Split from `error` on purpose: one field is always safe to read
   * and to publish, the other is opt-in and is not.
   */
  errorDetail: z.string().nullable(),
  miseVersion: z.string().nullable(),
  /**
   * The directory the reading came from. null has two causes: an ssh node
   * with no dir set, where the reading comes from wherever the login lands,
   * and a local node whose working directory could not be read, which
   * happens when the directory swamp started in has since been deleted.
   */
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
  /**
   * null means NOT MEASURED, not "up to date". The outdated probe can fail on
   * its own while ls succeeds, and reporting false in that case presents an
   * unknown as a healthy value -- the one direction a drift report must never
   * round in.
   */
  outdated: z.boolean().nullable(),
  latestVersion: z.string().nullable(),
  drift: z.array(DriftEnum),
});

const ConfigStateSchema = z.object({
  node: z.string(),
  /**
   * Whether the host this config came from answered in full.
   *
   * A config row could look complete after unsafe or malformed declared-tool
   * names were dropped: the node was marked degraded, but nothing on the row
   * itself said so, and an empty `toolsNotInEffect` on a partial reading is
   * indistinguishable from a config fully in effect. Tool rows already
   * carried this; config rows now do too, in the data and as a tag.
   */
  degraded: z.boolean(),
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
  /**
   * Every total below rests on the ls probe. Null when any host went
   * unmeasured, because a fleet where nobody answered reporting `tools: 0`
   * is an incomplete sweep wearing the shape of a healthy one.
   */
  tools: z.number().nullable(),
  notinstalled: z.number().nullable(),
  notactive: z.number().nullable(),
  /**
   * Null when any host's config probe went unanswered. Zero is a fleet with
   * no config drift; null is a fleet where some of it went unmeasured, and
   * publishing the second as the first is the whole failure this model
   * exists to prevent.
   */
  configsNotInEffect: z.number().nullable(),
  /** Null when any host's outdated probe went unanswered. See configsNotInEffect. */
  outdated: z.number().nullable(),
  expected: z.number().nullable(),
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
/**
 * Identity digest for a resource name.
 *
 * This was the first 8 bytes of SHA-256. 64 bits is not a collision-resistant
 * identity when part of the input is remote-controlled: a birthday search over
 * tool names or paths is ~2^32 work offline, which is minutes, and a collision
 * means two different tools resolve to the same resource name and one silently
 * overwrites the other. The length-prefixed encoding below makes distinct
 * identities distinct as INPUTS; truncating the digest threw that guarantee
 * away at the last step.
 *
 * 32 bytes is 2^128 collision resistance and costs 48 more characters in a
 * name nothing reads by eye.
 */
async function shortHash(s: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(s),
  );
  return Array.from(new Uint8Array(digest))
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
 * injective: node "builder-01" with tool "go" and node "builder" with tool
 * "01-go" flatten to the same string, and the second write would quietly
 * overwrite the first. mise
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
  const flat = parts.map(slugPart).join(PART_SEP);
  return `${prefix}-${flat || "id"}-${await shortHash(identityKey(parts))}`;
}

/**
 * One identity part, flattened for the readable half of a resource name. A
 * part that flattens away to nothing becomes "x" rather than disappearing, so
 * every part keeps its position and the node name is always the first segment
 * after the prefix. That is what lets nodePrefix name a host's whole run of
 * resources without knowing which tools it had.
 */
/**
 * What separates the node component of a resource name from the tool or
 * config component.
 *
 * A single dash was ambiguous, and no amount of care at the reading end could
 * fix it: slugs contain dashes, so `tool-web-server-ruby-<hash>` is node
 * `web` with tool `server-ruby` and node `web-server` with tool `ruby`, and
 * the hash covers the pair rather than either half. That ambiguity was worked
 * around twice -- longest-match, then hold-on-disagreement -- and both were
 * heuristics standing in for a fact the name did not carry.
 *
 * A double dash carries it. slugPart collapses every run of non-alphanumeric
 * characters to ONE dash, so no slug can contain `--`, so the first `--`
 * after the prefix is always the real boundary. Existing records keep their
 * old single-dash names and are pruned on the next full sweep, which is the
 * documented behaviour for a record this sweep did not write.
 */
const PART_SEP = "--";

function slugPart(p: string): string {
  const s = p
    .replace(/[^a-zA-Z0-9]+/g, "-")
    .toLowerCase()
    .replace(/^-+|-+$/g, "");
  // Bounded because the input is remote. A host returning a megabyte-long
  // tool name would otherwise put a megabyte-long readable half into a
  // resource NAME, which is an identifier that gets stored, indexed and
  // displayed. Identity is unaffected: the full value is still hashed, so
  // truncating the readable half cannot merge two distinct identities.
  const capped = s.length > MAX_SLUG_CHARS ? s.slice(0, MAX_SLUG_CHARS) : s;
  return capped === "" ? "x" : capped;
}

/**
 * The leading text every tool or config resource name for one host shares.
 * The prune uses it to leave a host's stored rows alone when this sweep could
 * not measure that host. One node name that slugs to a prefix of another's
 * covers both, which errs towards keeping records rather than deleting them.
 */
function nodePrefix(prefix: string, node: string): string {
  return `${prefix}-${slugPart(node)}${PART_SEP}`;
}

/**
 * Does an unmeasured host's hold cover this stored record?
 *
 * A record is named `tool-<node-slug>-<tool-slug>-<hash>`, and both slugs may
 * contain the separator, so `tool-web-` is a prefix of a record belonging to
 * a node called web AND of one belonging to web-server. Testing the held
 * prefixes alone therefore let an unmeasured `web` hold `web-server`'s stale
 * rows indefinitely, leaving stored data that contradicts the current sweep.
 *
 * The ambiguity is resolved by comparing against every configured node rather
 * than only the held ones: the longest prefix that matches names the node the
 * record actually belongs to, because a longer node slug is a more specific
 * claim on the same string. Only that node's state decides. A record matching
 * no configured node belongs to a host that has left the config, which is
 * exactly what the prune is for.
 */
function holdsRecord(prefixHeld: Map<string, boolean>, name: string): boolean {
  // Unambiguous now: PART_SEP cannot occur inside a slug, so at most one
  // configured node prefix can match a given name. The multi-match branch
  // below is kept for records written before the separator changed, which
  // still carry the old ambiguous single-dash form.
  const matches: boolean[] = [];
  for (const [prefix, isHeld] of prefixHeld) {
    if (name.startsWith(prefix)) matches.push(isHeld);
  }
  if (matches.length === 0) return false;
  // Ambiguity only matters when it changes the answer. A record matching
  // several node prefixes cannot be attributed to one of them -- the hash
  // covers the node-and-tool pair, not the node, so nothing in the name
  // breaks the tie -- but if every candidate agrees, the attribution does
  // not need to be resolved to know what to do. Holding unconditionally
  // meant a record whose every candidate node was measured stayed forever,
  // contradicting the documented promise that a full sweep deletes what it
  // did not write.
  //
  // Only a genuine disagreement is held, and it is held rather than guessed
  // because keeping a stale row is recoverable by the next sweep that can
  // attribute it, and deleting a live one is not.
  return matches.some((held) => held);
}

/**
 * Where a local sweep actually looks. Null when the runtime will not say,
 * which records the same "we do not know" the ssh case does rather than
 * writing down a directory nobody read.
 */
function currentDir(): string | null {
  try {
    return printableRemoteText(Deno.cwd());
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
  version: "2026.08.28.3",
  globalArguments: GlobalArgsSchema,
  /**
   * Nothing to transform, and the reasons are worth stating rather than
   * assuming, because "no-op" can mean two different things.
   *
   * One field has been added since 2026.08.24.1: `errorDetail`, which carries
   * `.default(false)`. An instance stored without it parses and comes back
   * off by default, which is the safe direction for the one argument that
   * persists host text, so there is no attribute to write.
   *
   * The rest of the changes are narrowings of validation on arguments that
   * already existed -- misePath must now name mise, ssh.host and ssh.user
   * are held to hostname and username charsets, and a node label is screened
   * the way a host's strings are. An upgrade function cannot help there, and
   * should not try: a config that used to parse and now does not is a config
   * this model refuses rather than repairs, which is the same rule it applies
   * to `dir` and `misePath` everywhere else. A half-fixed value that measures
   * the wrong thing silently is worse than a loud config error.
   *
   * So this exists to move `typeVersion` on existing instances, which is what
   * it is for. Targeting 2026.08.28.2 rather than .1 on purpose: instances
   * are filtered on `toVersion > typeVersion`, so an entry naming a version
   * already installed would never run, and this one reaches instances sitting
   * at both 2026.08.24.1 and 2026.08.28.1.
   */
  upgrades: [
    {
      toVersion: "2026.08.28.2",
      description:
        "Security hardening; no globalArguments migration. errorDetail was " +
        "added with a default, and the other changes tighten validation on " +
        "existing arguments rather than reshaping them.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.08.28.3",
      description:
        "Probes `mise version` instead of the `--version` flag, which mise " +
        "refuses behind the `-C <dir>` every node with `dir` set carries. No " +
        "globalArguments change: an existing config is already correct and " +
        "needs no edit. Stored records are not migrated either -- the stale " +
        "`degraded` rows and null miseVersion clear on the next full sweep, " +
        "which rewrites them from a probe that now answers.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    node: {
      description:
        "One record per host: whether mise answered at all, whether it " +
        "answered in full, which directory the reading came from, and how " +
        "much drift was found there. A null dir is either an ssh node with " +
        "no dir set, where the reading comes from wherever the login lands, " +
        "or a local node whose working directory could not be read.",
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
        "as gone, and which does not rewrite the fleet summary from one " +
        "host's worth of data.",
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
          // Names neither the value asked for nor the fleet. Echoing the
          // argument put caller-controlled text into an error that gets
          // logged, and listing every configured label turned one wrong
          // guess into a directory of the fleet. The operator has the node
          // list already; nobody else should get it from a typo.
          throw new Error(
            `No node by that name is configured (${g.nodes.length} known).`,
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
                const err = ls.ok ? "unparseable-output" : ls.error;
                const detail = ls.ok ? undefined : ls.detail;
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
                  droppedEntries: null,
                  failedSubcommands: [],
                  failureKind: kind,
                  transport,
                  error: err,
                  // Opt-in only. With errorDetail off, a novel failure is
                  // just its code, which is the safe default.
                  errorDetail: g.errorDetail ? (detail ?? null) : null,
                  miseVersion: null,
                  dir,
                  configCount: null,
                  toolCount: null,
                  drift: ["unmeasured"],
                });
                continue;
              }

              // One sink for the whole node: every parser adds to it, so a
              // host that answers badly in several places is degraded once
              // with a total, rather than per-parser.
              const drops: DropSink = {
                dropped: 0,
                unmeasuredTools: new Set<string>(),
              };
              const rows = parseLsCurrent(lsJson, drops);
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
              // `version` are plain text with no JSON shape to fail, so
              // they are judged on whether the text itself parsed.
              const cfgJson = jsonStdout(cfg, "array");
              const outdJson = jsonStdout(outd, "object");

              // null, not {}. An empty map is indistinguishable from "every
              // tool is current", which is exactly the wrong reading when the
              // probe failed.
              const outdated = outdJson === null
                ? null
                : parseOutdated(outdJson, drops);
              const configs = cfgJson === null
                ? []
                : parseConfigLs(cfgJson, drops);
              const trusted = trust.ok
                ? parseTrustShow(trust.stdout, drops)
                : {};

              // A zero exit is not an answer. These two checks used to stop
              // at the exit code, so a login shell that printed a banner over
              // the top of the answer and exited zero passed -- and produced
              // a node record with a null version and an empty trust map that
              // read as measured. Judge the text too: a version line has to
              // be version-shaped, and trust output is either genuinely empty
              // or lines this parser understood.
              const miseVersion = ver.ok ? parseVersion(ver.stdout) : null;
              const trustReadable = !trust.ok ||
                trust.stdout.trim() === "" ||
                Object.keys(trusted).length > 0;

              const failed: string[] = [];
              if (cfgJson === null) failed.push("config");
              if (outdJson === null) failed.push("outdated");
              if (!trust.ok || !trustReadable) failed.push("trust");
              if (!ver.ok || miseVersion === null) failed.push("version");
              if (failed.length > 0) {
                ctx.logger.warning(
                  "{name} answered in part, no reading from: {subs}",
                  { name: node.name, subs: failed.join(", ") },
                );
              }
              // Computed once here, where both the failed-probe list and
              // the drop count are final, so the node record and every
              // config row it produces cannot disagree about it.
              const nodeDegraded = failed.length > 0 || drops.dropped > 0;

              if (drops.dropped > 0) {
                ctx.logger.warning(
                  "{name} returned {n} entries no parser would accept; " +
                    "its counts are a floor",
                  { name: node.name, n: String(drops.dropped) },
                );
              }

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
                // Three states, not two. The probe failed for everyone
                // (null), the probe failed for this tool alone (null), or
                // the probe answered (a boolean).
                const isOutdated = outdated === null ||
                    drops.unmeasuredTools?.has(r.tool)
                  ? null
                  : Object.hasOwn(outdated, r.tool);
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
                  latestVersion: isOutdated && outdated !== null
                    ? outdated[r.tool]
                    : null,
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
                  degraded: nodeDegraded,
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
                degraded: nodeDegraded,
                droppedEntries: drops.dropped,
                failedSubcommands: failed,
                failureKind: null,
                transport,
                // A degraded host is not a clean host, so it does not get to
                // report a null error while quietly missing a reading.
                error: failed.length > 0
                  // A code, not a sentence. `error` is documented as a
                  // closed set, and this path was writing prose into it --
                  // which is exactly the field a reader is told they can
                  // match on. Which subcommands went quiet is already on
                  // the record, in failedSubcommands, where it belongs.
                  ? "partially-measured"
                  : null,
                // Names our own subcommands, not host text: nothing extra
                // to withhold.
                errorDetail: null,
                miseVersion,
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
              const msg = remoteErrorCode(
                (e as Error)?.message ?? String(e),
              );
              // Record first, log second. The logger is the one thing in here
              // that reaches outside this model, so it is also the one thing
              // that can throw on the way out and take the record with it.
              nodeStates.push({
                name: node.name,
                measured: false,
                degraded: false,
                droppedEntries: null,
                failedSubcommands: [],
                // Nothing here says mise was absent. The sweep broke.
                failureKind: "failed",
                transport,
                error: msg,
                // Through the same screening as every other stored excerpt.
                // This path built its own printable-and-truncate inline and
                // so was the one place a credential-bearing token could be
                // stored whole, which is the sort of thing an inline
                // reimplementation is always eventually for.
                errorDetail: g.errorDetail
                  ? (safeDetail((e as Error)?.message ?? String(e)) ?? null)
                  : null,
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
        // Prefix -> may this prefix's rows be pruned. Every configured node
        // gets an entry, not only the protected ones, because deciding which
        // node a stored name belongs to needs the whole field to compare
        // against. See holdsRecord below.
        const prefixHeld = new Map<string, boolean>();
        const legacyHeld = new Map<string, boolean>();

        for (const n of nodeStates) {
          const name = await resourceName("node", n.name);
          live.add(name);
          // OR, not overwrite. Distinct node labels can slug to the same
          // prefix -- "web server" and "web-server" both become web-server,
          // and so does anything past the slug's length cap -- so setting
          // the entry let whichever node came last decide for all of them.
          // That could delete a failed host's retained rows or keep a
          // measured host's departed ones. Holding when ANY colliding node
          // is held errs toward keeping data, which is the recoverable
          // direction.
          const held = !n.measured || n.degraded;
          for (
            const p of [
              nodePrefix("tool", n.name),
              nodePrefix("config", n.name),
            ]
          ) {
            prefixHeld.set(p, (prefixHeld.get(p) ?? false) || held);
          }
          // The pre-PART_SEP forms, kept in their own map. Records written
          // before the separator changed match none of the new prefixes, so
          // a full sweep would delete an unmeasured host's legacy rows --
          // breaking the retention guarantee precisely during the migration,
          // when there is most to lose. They cannot go in the map above:
          // `tool-web-` is a prefix of `tool-web-server--ruby-...` too, and
          // mixing them would hand back the ambiguity PART_SEP removed. A
          // name is matched against one map or the other by its own shape.
          for (
            const p of [
              `tool-${slugPart(n.name)}-`,
              `config-${slugPart(n.name)}-`,
            ]
          ) {
            legacyHeld.set(p, (legacyHeld.get(p) ?? false) || held);
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
              // The same degraded flag tool rows carry. A config row could
              // look complete after unsafe or malformed declared-tool names
              // were dropped: the host is marked degraded, but nothing on
              // the config row said so, and an empty toolsNotInEffect on a
              // partial reading is indistinguishable from a config fully in
              // effect.
              {
                tags: {
                  node: c.node,
                  degraded: String(degradedNodes.has(c.node)),
                },
              },
            ),
          );
        }

        // The summary is a fleet record under a fixed name, so only a sweep
        // of the whole fleet may write it. A targeted run is a diagnostic
        // that touches the host it names and nothing else, the same reason
        // it prunes nothing. One host's totals filed under a fleet name read
        // as the fleet, and only `nodes: 1` would hint otherwise. Leaving the
        // standing record alone keeps its own sweptAt on show, which says how
        // old it is plainly enough.
        if (!args.node) {
          const count = (d: Drift) =>
            toolStates.filter((t) => t.drift.includes(d)).length;
          const degradedCount = nodeStates.filter((n) => n.degraded).length;
          // A count is only a count if everything that feeds it answered.
          // The model refuses to write zero for a host whose probe failed,
          // and then the summary added those refusals up into a fleet zero
          // and published it as good news -- the same mistake one level up.
          // A total whose inputs are incomplete is null here, which is the
          // word this model already uses for "nobody measured that".
          const anyFailed = (sub: string) =>
            nodeStates.some((n) =>
              !n.measured || n.failedSubcommands.includes(sub)
            );
          const outdatedComplete = !anyFailed("outdated");
          // Drops count here as well as probe failures. Config entries that
          // no parser would accept are missing configs, so a fleet total of
          // zero computed across them says "no config drift" about configs
          // nobody read.
          const configComplete = !anyFailed("config") &&
            nodeStates.every((n) => (n.droppedEntries ?? 0) === 0);
          // Every tool-derived total rests on the ls probe, so a host that
          // never answered at all takes all of them with it. The first pass
          // at this only covered outdated and config, which left the sweep
          // able to report `tools: 0, notinstalled: 0` for a fleet where
          // nobody answered -- an incomplete sweep wearing the shape of a
          // healthy one, which is the exact failure this whole model is
          // built around not committing.
          // A host that answered but whose answer contained entries no
          // parser would accept is not a host that was fully measured, so
          // its totals cannot be added into a fleet total either.
          const toolsComplete = nodeStates.every((n) =>
            n.measured && (n.droppedEntries ?? 0) === 0
          );
          const num = (ok: boolean, v: number) => ok ? v : null;
          handles.push(
            await ctx.writeResource("summary", "summary", {
              nodes: nodeStates.length,
              nodesMeasured: nodeStates.filter((n) => n.measured).length,
              nodesUnmeasured: nodeStates.filter((n) => !n.measured).length,
              nodesDegraded: degradedCount,
              tools: num(toolsComplete, toolStates.length),
              notinstalled: num(toolsComplete, count("notinstalled")),
              notactive: num(toolsComplete, count("notactive")),
              configsNotInEffect: num(
                configComplete,
                configStates.filter((c) => c.toolsNotInEffect.length > 0)
                  .length,
              ),
              outdated: num(
                toolsComplete && outdatedComplete,
                count("outdated"),
              ),
              // An expectation that was never evaluated is not an
              // expectation that passed. A tool with no resolved version
              // classifies as unmeasured and its `expect` rule is skipped,
              // so counting `expected` across it reported zero failures
              // where there had been zero checks.
              expected: num(
                toolsComplete && count("unmeasured") === 0,
                count("expected"),
              ),
              sweptAt: new Date().toISOString(),
            }, {
              tags: {
                nodes: String(nodeStates.length),
                nodesDegraded: String(degradedCount),
              },
            }),
          );
          live.add("summary");
        }

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
          // Validated, not cast. This loop deletes, so what it reads has to
          // be checked: `existing as {name: string}[]` on a repository that
          // returned anything else produced records whose `name` was
          // undefined, and `undefined.startsWith` throws mid-prune, after
          // some deletions and before the rest.
          for (const raw of existing) {
            const rec = StoredRecordSchema.safeParse(raw);
            if (!rec.success) {
              ctx.logger.warning(
                "skipped a stored record with no readable name during prune",
              );
              continue;
            }
            if (live.has(rec.data.name)) continue;
            // Matched against one map or the other by the record's own
            // shape, never both.
            const byShape = rec.data.name.includes(PART_SEP)
              ? prefixHeld
              : legacyHeld;
            if (holdsRecord(byShape, rec.data.name)) continue;
            await ctx.deleteResource(rec.data.name);
            // Screened before it is logged, not merely checked for
            // printability. This name came out of the datastore rather than
            // off a host, so nothing upstream vouches for it: a record
            // written by an older version of this model, or by anything else
            // sharing the store, can carry a credential or an infrastructure
            // identifier in its name, and the prune would have copied it
            // verbatim into a log line.
            ctx.logger.info("pruned {name}", {
              name: safeRemoteString(rec.data.name) ?? "<withheld>",
            });
          }
        }

        return { dataHandles: handles };
      },
    },
  },
};
