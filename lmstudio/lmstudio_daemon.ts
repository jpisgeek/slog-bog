/** Observe an LM Studio headless daemon through the supported `lms` CLI. */
import { z } from "npm:zod@4";

/**
 * The transport check on `--host`, and the reason remote mode is loopback-only.
 *
 * `lms ps --host <host>` talks to the far end over plain HTTP: the CLI offers
 * no TLS option, no certificate to verify, and no way for this extension to
 * establish one on its behalf. Naming a remote host directly therefore puts
 * the daemon exchange -- the host's loaded model inventory, and whatever the
 * far end sends back -- on the wire in cleartext, on a link this code cannot
 * see. The only remote configuration whose confidentiality can actually be
 * asserted is one where the encryption is somebody else's job and already
 * terminated locally: a WireGuard interface, an `ssh -L` forward, an stunnel
 * listener. All of those present as a loopback address, and everything else
 * is refused at config-parse time rather than silently downgraded.
 *
 * Accepts the bare host, `host:port`, and the bracketed IPv6 form.
 */
function isLoopbackHost(value: string): boolean {
  let host = value;
  if (host.startsWith("[")) {
    // [::1] or [::1]:1234 -- the brackets exist precisely so the colons
    // inside the address are not read as a port separator.
    const end = host.indexOf("]");
    host = end === -1 ? host.slice(1) : host.slice(1, end);
  } else if ((host.match(/:/g) ?? []).length === 1) {
    // Exactly one colon is host:port. More than one is a bare IPv6 literal,
    // which has no port to strip.
    host = host.slice(0, host.indexOf(":"));
  }
  host = host.toLowerCase();
  if (host === "localhost" || host === "::1" || host === "0:0:0:0:0:0:0:1") {
    return true;
  }
  const octets = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!octets) return false;
  const parts = octets.slice(1).map(Number);
  // The whole 127.0.0.0/8 block supports distinct local tunnel endpoints.
  return parts.every((o) => o <= 255) && parts[0] === 127;
}

const GlobalArgsSchema = z.object({
  lmsBinary: z.string().min(1).default("lms").describe(
    "LM Studio CLI executable path or name",
  ),
  timeoutMs: z.number().int().positive().default(15_000).describe(
    "Maximum time for each lms command",
  ),
  host: z.string().min(1).refine(
    (value) => !/\s/.test(value) && !value.startsWith("-"),
    {
      message: "host must not contain whitespace or begin with a hyphen",
    },
  ).refine(isLoopbackHost, {
    message:
      "host must be a loopback address (localhost, 127.0.0.0/8, or ::1), " +
      "optionally with a port: `lms --host` speaks cleartext HTTP, so a " +
      "remote daemon must be reached through the local end of an encrypted " +
      "tunnel (WireGuard, an ssh -L forward, stunnel) rather than named " +
      "directly",
  }).optional().describe(
    "Optional remote LM Studio host accepted by lms ps --host. Must be a loopback address, with or without a port: lms speaks cleartext, so remote daemons are reached by pointing this at the local end of an encrypted tunnel. Omit when running this model beside llmster",
  ),
});

const ObserveArgsSchema = z.object({});

/**
 * Every field below is remote-controlled text: it comes out of `lms ps --json`,
 * which in `--host` mode is whatever the far end chose to send. A bare
 * `z.string()` accepts a megabyte-long identifier and accepts
 * `qwen<ESC>]0;PWNED<BEL>-7b`, both of which then land verbatim in a 30-day
 * resource that repeated observe runs compound -- and the escape sequence
 * rewrites the terminal of whoever lists that data later. The resource calls
 * itself "sanitized"; without a bound and a charset screen it was not.
 *
 * Bounded and screened, matching the RemoteText pattern the hyperv model
 * already uses for the same class of string. Kept local rather than imported:
 * each extension ships only the files in its own manifest.
 */
const RemoteText = (max: number, min = 0) =>
  z
    .string()
    .min(min)
    .max(max)
    // deno-lint-ignore no-control-regex
    .refine((v) => !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(v), {
      message: "value must not contain control or line-separator characters",
    })
    // Bidi and zero-width characters reorder or hide displayed text, so two
    // distinct model identifiers can render identically to an operator.
    .refine(
      (v) => !/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(v),
      {
        message:
          "value must not contain zero-width or direction-formatting characters",
      },
    )
    // Lone surrogates survive JSON.parse as \ud800-style escapes and decode to
    // the same replacement character, which again makes distinct values look
    // identical.
    .refine((v) => {
      for (const ch of v) {
        const cp = ch.codePointAt(0)!;
        if (cp >= 0xd800 && cp <= 0xdfff) return false;
      }
      return true;
    }, { message: "value must not contain unpaired surrogate code units" });

/**
 * A ceiling on how many loaded models one observation may record. LM Studio
 * loads models into memory, so a real host reports single digits; anything at
 * this scale is a broken or hostile daemon, and storing it unbounded grows the
 * datastore every 30 days for as long as the model keeps running. Refused
 * outright (errorKind "invalid-response") rather than silently truncated: a cut
 * list stored as a measurement is a wrong answer, not a failed one.
 */
const MAX_LOADED_MODELS = 512;

/**
 * `type` and `architecture` are nullable because `lms ps --json` does not
 * always send them, and the resource description promises that missing
 * measurements remain explicit.
 *
 * They used to be `RemoteText(64)` / `RemoteText(128)` with a min of 0, fed
 * by a helper that returned `""` for an absent key. An absent field and a
 * daemon that genuinely reported an empty string were therefore stored
 * identically, and both read as a measured value -- the exact
 * absent-versus-measured collapse this package exists to prevent everywhere
 * else (dimensionKnown, checksCompleted, the nullable token counts). `null`
 * now means "the daemon did not tell us"; a string is always something the
 * daemon actually said.
 */
const LoadedModelSchema = z.object({
  identifier: RemoteText(256, 1),
  type: RemoteText(64, 1).nullable(),
  architecture: RemoteText(128, 1).nullable(),
});

const DaemonSchema = z.object({
  cliAvailable: z.boolean(),
  daemonRunning: z.boolean(),
  status: z.enum(["running", "not-running", "unknown"]),
  loadedModelCount: z.number().int().nonnegative(),
  loadedModels: z.array(LoadedModelSchema).max(MAX_LOADED_MODELS),
  observedAt: z.iso.datetime(),
  errorKind: z.enum([
    "",
    "cli-unavailable",
    "unreachable",
    "timeout",
    "command-failed",
    "invalid-response",
  ]),
  error: z.string(),
}).superRefine((value, ctx) => {
  if (value.loadedModelCount !== value.loadedModels.length) {
    ctx.addIssue({
      code: "custom",
      message: "loadedModelCount must match loadedModels length",
      path: ["loadedModelCount"],
    });
  }
});

interface CommandResult {
  success: boolean;
  code: number;
  stdout: string;
  stderr: string;
  /**
   * True when either stream hit MAX_OUTPUT_BYTES and the answer we hold is a
   * prefix of what the CLI was sending.
   *
   * Overflow used to be expressed only by flipping `success` to false, which
   * meant observe() could not tell it apart from a non-zero exit: it fell
   * into the `!success` branch, ran the connect/refused/network keyword scan
   * over up to two megabytes of remote-controlled text, and recorded
   * `unreachable` or `command-failed`. Both the README and the resource
   * description promise an oversized payload is refused as
   * `invalid-response`. Carried explicitly so that promise is kept by the
   * code and not just by the docs.
   *
   * Optional so the CommandRunner test seam stays source-compatible: a runner
   * that never truncates simply omits it.
   */
  truncated?: boolean;
}

export type CommandRunner = (
  binary: string,
  args: string[],
  signal: AbortSignal,
) => Promise<CommandResult>;

/**
 * Per-stream byte cap on `lms` output. `lms ps --json` lists the handful of
 * models a host has in memory, so a megabyte is already orders of magnitude
 * more than a truthful answer needs -- and in `--host` mode the far end
 * decides how much it sends.
 *
 * Exported for the tests, which assert the cap actually holds.
 */
export const MAX_OUTPUT_BYTES = 1024 * 1024;
/** How long a child gets to honour SIGTERM before it is SIGKILLed. */
const SIGTERM_GRACE_MS = 1_000;
/**
 * How long after the SIGKILL we still wait for the pipes to drain before
 * abandoning the child entirely. SIGKILL cannot be caught, but a grandchild
 * that inherited stdout keeps the pipe open after its parent is gone, and a
 * read on that pipe never reaches EOF.
 */
const REAP_GRACE_MS = 1_000;

/**
 * Read one stream with a hard byte cap, killing the child at the point of
 * overflow rather than after both streams settle -- stderr cannot reach EOF
 * while the process is still producing on stdout, so waiting for both would
 * reintroduce the hang the cap exists to prevent.
 *
 * `stop` is the give-up signal: it releases this loop so the caller's timers
 * and the child can be cleaned up instead of leaking a pending read.
 */
async function readCapped(
  stream: ReadableStream<Uint8Array>,
  onOverflow: () => void,
  stop: AbortSignal,
): Promise<{ text: string; truncated: boolean }> {
  const reader = stream.getReader();
  const stopped = new Promise<ReadableStreamReadResult<Uint8Array>>(
    (resolve) => {
      const done = () => resolve({ done: true, value: undefined });
      if (stop.aborted) done();
      else stop.addEventListener("abort", done, { once: true });
    },
  );
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), stopped]);
      if (done || !value) break;
      if (total + value.byteLength > MAX_OUTPUT_BYTES) {
        chunks.push(value.subarray(0, MAX_OUTPUT_BYTES - total));
        total = MAX_OUTPUT_BYTES;
        truncated = true;
        onOverflow();
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    // Cancel rather than drain: draining a runaway stream to be polite is the
    // same unbounded read the cap exists to prevent.
    await reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    buf.set(chunk, at);
    at += chunk.byteLength;
  }
  return { text: new TextDecoder().decode(buf), truncated };
}

/**
 * The complete list of environment variables `lms` is allowed to inherit.
 *
 * Two, both load-bearing for the CLI and neither of them secret-carrying:
 * PATH, because a bare `lms` (and the node/electron helpers it re-execs) is
 * resolved through it and a cleared environment would otherwise leave the
 * child unable to find its own runtime; HOME, because `lms` keeps its client
 * state under `~/.lmstudio` and without it writes to, or fails at, the wrong
 * place. Anything added here is another value handed to an operator-chosen
 * executable, so add only with a stated reason.
 */
const LMS_ENV_ALLOWLIST = ["PATH", "HOME"] as const;

/** Build the child environment from the allowlist, and nothing else. */
function lmsChildEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of LMS_ENV_ALLOWLIST) {
    let value: string | undefined;
    try {
      value = Deno.env.get(key);
    } catch {
      // Reading env needs a permission this model does not require. Not having
      // PATH is a worse `lms` invocation, not a reason to refuse to spawn --
      // and it is never a reason to fall back to inheriting everything.
      value = undefined;
    }
    if (value) env[key] = value;
  }
  return env;
}

/**
 * Spawn `lms` and collect its output under two hard bounds: bytes, and time.
 *
 * The previous version had neither. It sent SIGTERM on abort and then went
 * back to awaiting `child.output()` unconditionally -- so `timeoutMs` bounded
 * nothing. `lms` is an Electron/Node binary that defers exit while a request
 * is outstanding, so `lms ps --host <remote> --json` blocked on a network read
 * after a partition would take the SIGTERM, ignore it, and leave observe()
 * wedged forever: no error, no resource written, and a workflow run that never
 * returns. `output()` also buffered whatever the far end sent, so the timeout
 * bounded how long it ran, not how much it could hand over in that time.
 *
 * Now: SIGTERM, escalate to the uncatchable SIGKILL after a grace period, and
 * give up on the child outright a grace period after that -- a deadline that
 * does not depend on the child's signal handling at all, because a grandchild
 * holding the inherited pipe can outlive the process we killed.
 */
const defaultRunner: CommandRunner = async (binary, args, signal) => {
  const child = new Deno.Command(binary, {
    args,
    // The child gets a built environment, never the inherited one. Deno.Command
    // hands the spawned process the entire parent environment by default, and
    // `lmsBinary` is operator-configured -- so whatever the swamp runtime is
    // holding in env at that moment (other extensions' tokens, CI secrets, a
    // vault password passed in by the host) was being handed to an arbitrary
    // executable that has no use for any of it. `clearEnv` is what makes that
    // impossible rather than merely unlikely; the allowlist below is what
    // keeps `lms` working.
    clearEnv: true,
    env: lmsChildEnv(),
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();

  const kill = (sig: Deno.Signal) => {
    try {
      child.kill(sig);
    } catch {
      // The child may already have exited.
    }
  };

  let escalation: ReturnType<typeof setTimeout> | undefined;
  let deadline: ReturnType<typeof setTimeout> | undefined;
  const stop = new AbortController();
  let abandon: () => void = () => {};
  const abandoned = new Promise<never>((_resolve, reject) => {
    abandon = () => {
      // Release the readers first so the collect() below can settle instead of
      // leaving a read pending on a pipe nothing will ever close.
      stop.abort();
      reject(
        new DOMException(
          "the lms CLI did not exit after SIGTERM and SIGKILL",
          "TimeoutError",
        ),
      );
    };
  });

  const abort = () => {
    kill("SIGTERM");
    escalation = setTimeout(() => kill("SIGKILL"), SIGTERM_GRACE_MS);
    deadline = setTimeout(abandon, SIGTERM_GRACE_MS + REAP_GRACE_MS);
  };
  signal.addEventListener("abort", abort, { once: true });
  // addEventListener never fires for a signal that aborted before it was
  // attached, so a caller who cancelled before we spawned would otherwise get
  // the unbounded wait all over again.
  if (signal.aborted) abort();

  const overflow = () => kill("SIGKILL");
  const collect = (async () => {
    const [out, err, status] = await Promise.all([
      readCapped(child.stdout, overflow, stop.signal),
      readCapped(child.stderr, overflow, stop.signal),
      child.status,
    ]);
    return { out, err, status };
  })();

  try {
    const { out, err, status } = await Promise.race([collect, abandoned]);
    return {
      // Truncated output is never reported as success. A JSON payload cut at
      // the cap fails to parse and is already handled as invalid-response;
      // returning the first megabyte as though it were the whole answer is the
      // one behaviour that turns a runaway daemon into a wrong measurement
      // rather than a failed one.
      success: status.success && !out.truncated && !err.truncated,
      truncated: out.truncated || err.truncated,
      code: status.code,
      stdout: out.text,
      stderr: err.text,
    };
  } finally {
    signal.removeEventListener("abort", abort);
    clearTimeout(escalation);
    clearTimeout(deadline);
    // On the give-up path collect() is still in flight; stop.abort() has
    // already released it, so this just reaps it rather than leaking the ops.
    stop.abort();
    await collect.catch(() => {});
  }
};

/**
 * The real subprocess runner, exposed so the tests can exercise it directly.
 * Every other daemon test substitutes `commandRunner`, which left the one
 * function that actually spawns a process -- and the one that used to hang
 * forever -- with no coverage at all.
 */
export const runCommandForTest: CommandRunner = defaultRunner;

function safeError(
  kind: z.infer<typeof DaemonSchema>["errorKind"],
  code?: number,
) {
  switch (kind) {
    case "cli-unavailable":
      return "The lms CLI is not installed or executable";
    case "unreachable":
      return "The remote LM Studio daemon could not be reached";
    case "timeout":
      return "The lms CLI did not respond before the configured timeout";
    case "invalid-response":
      return "The lms CLI returned JSON that did not match the supported contract";
    case "command-failed":
      return `The lms CLI failed${code === undefined ? "" : ` (exit ${code})`}`;
    default:
      return "";
  }
}

/**
 * First key that carries a non-empty string, or `null` for "the daemon did
 * not report this".
 *
 * The old version returned `""` for both cases, which is what let an absent
 * `type` be stored as though it had been measured. An empty string from the
 * daemon is treated as absent too: it carries no more information than the
 * missing key, and failing the whole observation over it would turn a
 * cosmetic gap in one model entry into `invalid-response` for the entire
 * host.
 */
function optionalString(
  record: Record<string, unknown>,
  ...keys: string[]
): string | null {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value !== "") return value;
  }
  return null;
}

function parseModels(payload: unknown): z.infer<typeof LoadedModelSchema>[] {
  const entries = Array.isArray(payload)
    ? payload
    : payload && typeof payload === "object" &&
        Array.isArray((payload as Record<string, unknown>).models)
    ? (payload as Record<string, unknown>).models as unknown[]
    : null;
  if (!entries) throw new Error("missing model array");
  // Checked here as well as on the resource schema: observe() builds the
  // result object by hand, so an array cap that only lived on DaemonSchema
  // would not be enforced until something else re-parsed the stored value.
  if (entries.length > MAX_LOADED_MODELS) {
    throw new Error("model array exceeds the supported length");
  }
  return entries.map((entry) => {
    if (!entry || typeof entry !== "object") throw new Error("invalid model");
    const record = entry as Record<string, unknown>;
    return LoadedModelSchema.parse({
      // `?? ""` keeps identifier failing closed: it is the one field that is
      // required, and RemoteText(256, 1) rejects the empty string, so an
      // entry with no usable identifier still becomes invalid-response
      // rather than a nameless model in the stored list.
      identifier: optionalString(record, "identifier", "modelKey", "id") ?? "",
      type: optionalString(record, "type", "modelType"),
      architecture: optionalString(
        record,
        "architecture",
        "architectureName",
      ),
    });
  });
}

async function runJson(
  binary: string,
  args: string[],
  timeoutMs: number,
  callerSignal: AbortSignal,
  commandRunner: CommandRunner,
): Promise<CommandResult> {
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = AbortSignal.any([callerSignal, timeout]);
  try {
    const result = await commandRunner(binary, args, signal);
    if (callerSignal.aborted) throw callerSignal.reason;
    if (timeout.aborted) throw new DOMException("timed out", "TimeoutError");
    return result;
  } catch (error) {
    if (callerSignal.aborted) throw error;
    if (timeout.aborted) throw new DOMException("timed out", "TimeoutError");
    throw error;
  }
}

interface ObservationContext {
  globalArgs: unknown;
  signal: AbortSignal;
  /** Applies to this observation only; production uses the immutable runner. */
  commandRunner?: CommandRunner;
  writeResource(
    spec: string,
    name: string,
    value: z.infer<typeof DaemonSchema>,
    options?: { tags?: Record<string, string> },
  ): Promise<unknown>;
}

async function observe(
  _args: z.infer<typeof ObserveArgsSchema>,
  ctx: ObservationContext,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const observedAt = new Date().toISOString();
  let result: z.infer<typeof DaemonSchema>;
  try {
    // The normal headless deployment runs beside llmster. `--host` is added
    // only when the operator explicitly configures remote CLI mode.
    const hostArgs = g.host ? ["--host", g.host] : [];
    const psResult = await runJson(
      g.lmsBinary,
      ["ps", ...hostArgs, "--json"],
      g.timeoutMs,
      ctx.signal,
      ctx.commandRunner ?? defaultRunner,
    );
    if (psResult.truncated) {
      // Checked before the !success branch below, and never handed to the
      // keyword scan. An overflowing payload is remote-controlled text: the
      // word "network" appearing anywhere in the megabyte we captured used
      // to be enough to record the host as `unreachable`, which is a
      // measurement, and a wrong one. The CLI answered; the answer was too
      // large to be one, which is what `invalid-response` means.
      throw new SyntaxError("lms ps output exceeded the supported size");
    }
    if (!psResult.success) {
      const combined = `${psResult.stderr}\n${psResult.stdout}`;
      const kind = /connect|refused|unreachable|offline|network/i.test(combined)
        ? "unreachable"
        : "command-failed";
      result = {
        cliAvailable: true,
        daemonRunning: false,
        status: "unknown",
        loadedModelCount: 0,
        loadedModels: [],
        observedAt,
        errorKind: kind,
        error: safeError(kind, psResult.code),
      };
    } else {
      let loadedModels: z.infer<typeof LoadedModelSchema>[];
      try {
        loadedModels = parseModels(JSON.parse(psResult.stdout));
      } catch {
        throw new SyntaxError("invalid lms ps response");
      }
      result = {
        cliAvailable: true,
        daemonRunning: true,
        status: "running",
        loadedModelCount: loadedModels.length,
        loadedModels,
        observedAt,
        errorKind: "",
        error: "",
      };
    }
  } catch (error) {
    if (ctx.signal.aborted) throw error;
    const kind = error instanceof DOMException && error.name === "TimeoutError"
      ? "timeout"
      : error instanceof Deno.errors.NotFound
      ? "cli-unavailable"
      : error instanceof SyntaxError
      ? "invalid-response"
      : "command-failed";
    result = {
      cliAvailable: kind !== "cli-unavailable",
      daemonRunning: false,
      status: "unknown",
      loadedModelCount: 0,
      loadedModels: [],
      observedAt,
      errorKind: kind,
      error: safeError(kind),
    };
  }

  const handle = await ctx.writeResource("daemon", "daemon", result, {
    tags: {
      status: result.status,
      errorKind: result.errorKind,
      loadedModelCount: String(result.loadedModelCount),
    },
  });
  return { dataHandles: [handle] };
}

/** LM Studio headless-daemon and loaded-model observation. */
export const model = {
  type: "@jpisgeek/lmstudio/daemon",
  version: "2026.09.05.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [{
    toVersion: "2026.09.05.1",
    description:
      "Preserve daemon configuration while advancing its version; remote host values still require current loopback validation and are never silently redirected",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }],
  resources: {
    daemon: {
      description:
        "Sanitized daemon status and models currently loaded in memory; missing measurements remain explicit -- a model type or architecture the daemon did not report is null, never an empty string that reads as a measured value. Model identifiers are length-bounded and screened for control, bidi, and zero-width characters, and an unscreenable, oversized, or output-cap-overflowing ps payload is refused as invalid-response rather than stored or misread as an unreachable host.",
      schema: DaemonSchema,
      lifetime: "30d" as const,
      garbageCollection: 30,
    },
  },
  methods: {
    observe: {
      description:
        "List models loaded by LM Studio with lms ps --json, optionally adding --host for an explicitly configured remote runtime.",
      arguments: ObserveArgsSchema,
      execute: observe,
    },
  },
};
