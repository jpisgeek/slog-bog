/**
 * Drive a Paseo daemon from swamp: agents, terminals, scripts, schedules, and
 * pending permission requests.
 *
 * Paseo runs AI coding agents and workspace terminals on a machine and exposes
 * them over a local daemon. This model wraps that daemon's CLI so a workflow
 * can launch an agent with a named provider and model, watch it, answer its
 * permission prompts, and read what it did -- without a human at that
 * machine's keyboard.
 *
 * Two things this model refuses to do, both deliberate:
 *
 * It will not accept a daemon target with a password in it. Paseo's own
 * `--host` accepts `tcp://host:port?ssl=true&password=secret`, and an argument
 * is the worst possible place for a secret: argv is what a runner logs, what a
 * crash dump carries, and what `ps` shows to every other user on the box.
 * `host` here is the address only, and the password arrives separately at call
 * time from wherever the caller resolves secrets. Stored data records the
 * address with any query string stripped, so a secret cannot reach the
 * datastore even if a future caller passes one.
 *
 * It will not run a destructive method without being told the target twice.
 * Deleting an agent or a schedule takes the id AND a `confirm` that has to
 * equal it. Ids reach this model from stored data through CEL, so a
 * mis-scoped expression is a plausible way to delete the wrong thing, and a
 * second field that has to agree is cheap insurance against it.
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Screening: values that become argv
// ---------------------------------------------------------------------------

/**
 * Characters a daemon address may contain. Deliberately narrow: hostnames,
 * IPv4 literals, and a port. No userinfo (`@`), no query string, no scheme --
 * `tcp://` and `ssl=` are added by this model, not by the caller, so there is
 * no form in which a caller can smuggle a credential through this field.
 */
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]*)(:[0-9]{1,5})?$/;

/** Refuses a value that would be read as a flag rather than an operand. */
export function assertPositional(value: string, what: string): string {
  if (value.startsWith("-")) {
    throw new Error(
      `${what} must not begin with '-': the CLI reads a leading dash as an ` +
        `option, so an id like '--all' would widen a scoped command to ` +
        `everything. Refused rather than escaped.`,
    );
  }
  if (value.length === 0) throw new Error(`${what} must not be empty`);
  return value;
}

/**
 * The daemon address, validated.
 *
 * Rejects anything carrying `password=`, `@`, or a scheme, naming the reason.
 * The check is on the raw string rather than a parsed URL on purpose: a parser
 * that normalises is a parser that can be tricked into normalising a secret
 * into a place this function no longer inspects.
 */
export function parseHostTarget(host: string): string {
  const lowered = host.toLowerCase();
  if (lowered.includes("password")) {
    throw new Error(
      "host must not contain a password. Paseo accepts " +
        "tcp://host:port?ssl=true&password=... but argv is logged, dumped, " +
        "and visible in the process table. Pass the address here and supply " +
        "the secret at call time instead.",
    );
  }
  if (host.includes("@")) {
    throw new Error("host must not contain userinfo ('@')");
  }
  if (host.includes("://")) {
    throw new Error(
      "host must be 'address' or 'address:port' without a scheme; " +
        "tcp:// and ssl=true are supplied by this model",
    );
  }
  if (!HOST_RE.test(host)) {
    throw new Error(
      `host ${JSON.stringify(host)} is not an address[:port]. Allowed: ` +
        `letters, digits, dot, hyphen, optional :port.`,
    );
  }
  return host;
}

/**
 * The `--host` argv pair, or nothing.
 *
 * With a password the address becomes a tcp:// URL, because that is the only
 * form Paseo accepts a password in. That string is built here, used once, and
 * never returned to a caller that stores things -- see `redactHost`, which is
 * what the resource records.
 */
export function hostArgs(host?: string, password?: string): string[] {
  if (!host) return [];
  const addr = parseHostTarget(host);
  if (!password) return ["--host", addr];
  const [h, p] = addr.split(":");
  const port = p ?? "6767";
  return [
    "--host",
    `tcp://${h}:${port}?ssl=true&password=${encodeURIComponent(password)}`,
  ];
}

/** What a resource is allowed to say about the daemon it talked to. */
export function redactHost(host?: string): string {
  if (!host) return "local";
  const noQuery = host.split("?")[0];
  return noQuery.replace(/^tcp:\/\//, "");
}

/**
 * A destructive method's second opinion.
 *
 * Compared exactly, not case-folded and not trimmed. An id that differs from
 * its confirmation only by case or whitespace is a caller that built one of
 * them by a different route than it thinks, which is the situation this guard
 * exists to catch rather than to smooth over.
 */
export function assertConfirmed(
  id: string,
  confirm: string,
  what: string,
): string {
  const target = assertPositional(id, `${what} id`);
  if (confirm !== target) {
    throw new Error(
      `refusing to ${what}: confirm ${JSON.stringify(confirm)} does not ` +
        `equal id ${JSON.stringify(target)}. Both must name the same target.`,
    );
  }
  return target;
}

// ---------------------------------------------------------------------------
// argv builders -- pure, so every one of them is testable without a daemon
// ---------------------------------------------------------------------------

/** Repeated `--flag k=v` pairs, sorted so argv is stable across runs. */
export function pairFlags(
  flag: string,
  pairs?: Record<string, string>,
): string[] {
  if (!pairs) return [];
  return Object.keys(pairs).sort().flatMap((k) => {
    if (k.includes("=")) {
      throw new Error(`${flag} key must not contain '=': ${k}`);
    }
    return [flag, `${k}=${pairs[k]}`];
  });
}

/** Optional `--flag value`, omitted entirely when the value is absent. */
function opt(flag: string, value?: string | number): string[] {
  return value === undefined || value === "" ? [] : [flag, String(value)];
}

export interface AgentRunOpts {
  prompt: string;
  title?: string;
  provider?: string;
  model?: string;
  mode?: string;
  thinking?: string;
  workspace?: string;
  cwd?: string;
  newWorkspace?: "local" | "worktree";
  newBranch?: string;
  base?: string;
  branch?: string;
  waitTimeout?: string;
  env?: Record<string, string>;
  labels?: Record<string, string>;
  background?: boolean;
}

/**
 * `paseo agent run`.
 *
 * The prompt is a trailing operand and is screened like any other: a prompt
 * beginning with a dash would be read as an option and the agent would run
 * with no task at all, which fails in a way that looks like the agent simply
 * did nothing.
 */
export function agentRunArgs(o: AgentRunOpts): string[] {
  const args = ["agent", "run"];
  args.push(
    ...opt("--title", o.title),
    ...opt("--provider", o.provider),
    ...opt("--model", o.model),
    ...opt("--mode", o.mode),
    ...opt("--thinking", o.thinking),
    ...opt("--workspace", o.workspace),
    ...opt("--cwd", o.cwd),
    ...opt("--new-workspace", o.newWorkspace),
    ...opt("--new-branch", o.newBranch),
    ...opt("--base", o.base),
    ...opt("--branch", o.branch),
    ...opt("--wait-timeout", o.waitTimeout),
    ...pairFlags("--env", o.env),
    ...pairFlags("--label", o.labels),
  );
  if (o.background) args.push("--background");
  args.push("--json", assertPositional(o.prompt, "prompt"));
  return args;
}

export function agentLsArgs(
  opts?: { all?: boolean; global?: boolean; labels?: Record<string, string> },
): string[] {
  const args = ["agent", "ls"];
  if (opts?.all) args.push("--all");
  if (opts?.global) args.push("--global");
  args.push(...pairFlags("--label", opts?.labels), "--json");
  return args;
}

export function agentInspectArgs(id: string): string[] {
  return ["agent", "inspect", assertPositional(id, "agent id"), "--json"];
}

export function agentSendArgs(id: string, prompt: string): string[] {
  return [
    "send",
    assertPositional(id, "agent id"),
    "--json",
    assertPositional(prompt, "prompt"),
  ];
}

export function agentStopArgs(id: string): string[] {
  return ["agent", "stop", assertPositional(id, "agent id"), "--json"];
}

export function agentWaitArgs(id: string, timeout?: string): string[] {
  return [
    "wait",
    assertPositional(id, "agent id"),
    ...opt("--timeout", timeout),
    "--json",
  ];
}

export function agentLogsArgs(id: string): string[] {
  return ["logs", assertPositional(id, "agent id"), "--json"];
}

/** Destructive: takes the id twice. */
export function agentDeleteArgs(id: string, confirm: string): string[] {
  return [
    "agent",
    "delete",
    assertConfirmed(id, confirm, "delete agent"),
    "--json",
  ];
}

export function agentArchiveArgs(id: string, confirm: string): string[] {
  return ["archive", assertConfirmed(id, confirm, "archive agent"), "--json"];
}

// --- terminals -------------------------------------------------------------

export function terminalLsArgs(): string[] {
  return ["terminal", "ls", "--json"];
}

export function terminalCreateArgs(
  o?: { cwd?: string; name?: string },
): string[] {
  return [
    "terminal",
    "create",
    ...opt("--cwd", o?.cwd),
    ...opt("--name", o?.name),
    "--json",
  ];
}

export function terminalCaptureArgs(id: string): string[] {
  return ["terminal", "capture", assertPositional(id, "terminal id"), "--json"];
}

/**
 * `paseo terminal send-keys`.
 *
 * Keys are separate operands rather than one joined string, so a key sequence
 * containing a space is not silently re-split by the CLI into two.
 */
export function terminalSendKeysArgs(id: string, keys: string[]): string[] {
  if (keys.length === 0) throw new Error("send-keys needs at least one key");
  return [
    "terminal",
    "send-keys",
    assertPositional(id, "terminal id"),
    ...keys.map((k, i) => assertPositional(k, `key[${i}]`)),
  ];
}

export function terminalKillArgs(id: string, confirm: string): string[] {
  return [
    "terminal",
    "kill",
    assertConfirmed(id, confirm, "kill terminal"),
    "--json",
  ];
}

// --- scripts ---------------------------------------------------------------

export function scriptLsArgs(): string[] {
  return ["script", "ls", "--json"];
}

export function scriptStartArgs(name: string): string[] {
  return ["script", "start", assertPositional(name, "script name"), "--json"];
}

export function scriptStopArgs(name: string): string[] {
  return ["script", "stop", assertPositional(name, "script name"), "--json"];
}

// --- schedules -------------------------------------------------------------

export function scheduleLsArgs(): string[] {
  return ["schedule", "ls", "--json"];
}

export function scheduleInspectArgs(id: string): string[] {
  return ["schedule", "inspect", assertPositional(id, "schedule id"), "--json"];
}

export function schedulePauseArgs(id: string): string[] {
  return ["schedule", "pause", assertPositional(id, "schedule id"), "--json"];
}

export function scheduleResumeArgs(id: string): string[] {
  return ["schedule", "resume", assertPositional(id, "schedule id"), "--json"];
}

export function scheduleRunOnceArgs(id: string): string[] {
  return [
    "schedule",
    "run-once",
    assertPositional(id, "schedule id"),
    "--json",
  ];
}

export function scheduleDeleteArgs(id: string, confirm: string): string[] {
  return [
    "schedule",
    "delete",
    assertConfirmed(id, confirm, "delete schedule"),
    "--json",
  ];
}

// --- permission requests ---------------------------------------------------

export function permitLsArgs(): string[] {
  return ["permit", "ls", "--json"];
}

export function permitAllowArgs(agent: string, reqId?: string): string[] {
  return [
    "permit",
    "allow",
    assertPositional(agent, "agent id"),
    ...(reqId ? [assertPositional(reqId, "request id")] : []),
    "--json",
  ];
}

export function permitDenyArgs(agent: string, reqId?: string): string[] {
  return [
    "permit",
    "deny",
    assertPositional(agent, "agent id"),
    ...(reqId ? [assertPositional(reqId, "request id")] : []),
    "--json",
  ];
}

// --- daemon ----------------------------------------------------------------

export function daemonStatusArgs(): string[] {
  return ["daemon", "status", "--json"];
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const PairsSchema = z.record(
  z.string().min(1).max(128).regex(/^[A-Za-z_][A-Za-z0-9_.-]*$/, {
    message: "key must be a plain identifier",
  }),
  z.string().max(4096),
);

export const GlobalArgsSchema = z.object({
  binary: z
    .string()
    .min(1)
    .max(1024)
    .regex(/^[A-Za-z0-9._/-]+$/, {
      message: "binary must match [A-Za-z0-9._/-] and not start with '-'",
    })
    .refine((v) => !v.startsWith("-"), {
      message: "binary must not start with '-'",
    })
    .refine((v) => v.split("/").pop() === "paseo", {
      message: "binary's basename must be exactly 'paseo'",
    })
    .default("paseo")
    .describe(
      "Path to the paseo CLI. The basename must be 'paseo': the charset rule " +
        "alone would let this name any executable on the box, which is a " +
        "guarantee this model advertises and would not otherwise keep.",
    ),
  host: z
    .string()
    .min(1)
    .max(261)
    .optional()
    .describe(
      "Daemon address as 'address' or 'address:port'. No scheme, no userinfo, " +
        "and no password -- see the module docs. Omit for the local daemon.",
    ),
  timeoutSec: z.number().int().positive().max(3600).default(120),
});

export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// I/O -- the only impure part, kept deliberately thin
// ---------------------------------------------------------------------------

/** Bounded so a runaway daemon cannot exhaust memory through this model. */
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

async function readCapped(
  stream: ReadableStream<Uint8Array> | null,
): Promise<string> {
  if (!stream) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const c of stream) {
    total += c.byteLength;
    if (total > MAX_OUTPUT_BYTES) break;
    chunks.push(c);
  }
  return new TextDecoder().decode(
    chunks.reduce((acc, c) => {
      const out = new Uint8Array(acc.length + c.length);
      out.set(acc);
      out.set(c, acc.length);
      return out;
    }, new Uint8Array()),
  );
}

export interface RunResult {
  ok: boolean;
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Spawn paseo. No shell anywhere, so nothing in argv is re-interpreted.
 *
 * The error names the binary and subcommand only. An earlier draft pasted the
 * whole argv into the message, which would have put any `--env KEY=value` pair
 * -- and, if a future caller ever passes one, a daemon password -- into
 * something that gets logged and stored.
 */
export async function run(
  binary: string,
  args: string[],
  timeoutSec: number,
  signal?: AbortSignal,
): Promise<RunResult> {
  const deadline = AbortSignal.timeout(timeoutSec * 1000);
  const composite = signal ? AbortSignal.any([signal, deadline]) : deadline;
  try {
    const child = new Deno.Command(binary, {
      args,
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
      signal: composite,
    }).spawn();
    const [stdout, stderr, status] = await Promise.all([
      readCapped(child.stdout),
      readCapped(child.stderr),
      child.status,
    ]);
    return { ok: status.success, code: status.code, stdout, stderr };
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) {
      throw new Error(
        `could not execute '${binary}' (${args[0] ?? "?"}): not found. ` +
          `Install the Paseo CLI or set 'binary' to its absolute path.`,
      );
    }
    throw new Error(
      `'${binary} ${args[0] ?? "?"}' failed to run: ${(e as Error).name}`,
    );
  }
}

/** Paseo's --json output, or a named failure. Never returns half a reading. */
export function parseJson(res: RunResult, what: string): unknown {
  if (!res.ok) {
    const first = res.stderr.trim().split("\n")[0] ?? "";
    throw new Error(
      `${what} failed (exit ${res.code}): ${first.slice(0, 200)}`,
    );
  }
  const text = res.stdout.trim();
  if (text === "") return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(
      `${what} exited 0 but did not return JSON. A login banner or a prompt ` +
        `printed over the answer is the usual cause; the repair belongs on ` +
        `the host rather than in a looser parser here.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Resource shapes
// ---------------------------------------------------------------------------

const AgentSchema = z.object({
  id: z.string(),
  title: z.string().nullable(),
  status: z.string().nullable(),
  provider: z.string().nullable(),
  model: z.string().nullable(),
  workspace: z.string().nullable(),
  daemon: z.string(),
});

const TerminalSchema = z.object({
  id: z.string(),
  name: z.string().nullable(),
  cwd: z.string().nullable(),
  daemon: z.string(),
});

const SummarySchema = z.object({
  daemon: z.string(),
  agents: z.number().int().nullable(),
  terminals: z.number().int().nullable(),
  schedules: z.number().int().nullable(),
  scripts: z.number().int().nullable(),
  observedAt: z.string(),
});

/** Pull a list out of paseo's --json, which wraps some collections and not others. */
export function coerceList(v: unknown, key: string): Record<string, unknown>[] {
  if (Array.isArray(v)) return v as Record<string, unknown>[];
  if (v && typeof v === "object") {
    const inner = (v as Record<string, unknown>)[key];
    if (Array.isArray(inner)) return inner as Record<string, unknown>[];
  }
  return [];
}

/** First present key, else null -- paseo names ids differently per collection. */
export function pick(
  o: Record<string, unknown>,
  ...keys: string[]
): string | null {
  for (const k of keys) {
    const v = o[k];
    if (typeof v === "string" && v !== "") return v;
    if (typeof v === "number") return String(v);
  }
  return null;
}

/** Stable, collision-resistant resource suffix for an opaque id. */
export async function idHash(value: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(buf)).map((b) =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

export const model = {
  type: "@jpisgeek/paseo",
  version: "2026.08.29.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [],
  resources: {
    agent: {
      description:
        "One record per Paseo agent the daemon reported: its id, title, " +
        "status, provider and model, and which daemon answered. Titles and " +
        "workspace paths are operator-supplied and can name projects.",
      schema: AgentSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    terminal: {
      description:
        "One record per workspace terminal: id, name, and working directory. " +
        "The cwd is a real path on the daemon's machine.",
      schema: TerminalSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    summary: {
      description:
        "Counts for the most recent observation. A count is null rather than " +
        "zero when its listing did not answer, because zero is a daemon with " +
        "nothing running and null is a daemon that was never read.",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },
  methods: {},
};
