/** Observe an LM Studio headless daemon through the supported `lms` CLI. */
import { z } from "npm:zod@4";

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
  ).optional().describe(
    "Optional remote LM Studio host accepted by lms ps --host; omit when running this model beside llmster",
  ),
});

const ObserveArgsSchema = z.object({});

const LoadedModelSchema = z.object({
  identifier: z.string().min(1),
  type: z.string(),
  architecture: z.string(),
});

const DaemonSchema = z.object({
  cliAvailable: z.boolean(),
  daemonRunning: z.boolean(),
  status: z.enum(["running", "not-running", "unknown"]),
  loadedModelCount: z.number().int().nonnegative(),
  loadedModels: z.array(LoadedModelSchema),
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
}

export type CommandRunner = (
  binary: string,
  args: string[],
  signal: AbortSignal,
) => Promise<CommandResult>;

const defaultRunner: CommandRunner = async (binary, args, signal) => {
  const child = new Deno.Command(binary, {
    args,
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const abort = () => {
    try {
      child.kill("SIGTERM");
    } catch {
      // The child may already have exited.
    }
  };
  signal.addEventListener("abort", abort, { once: true });
  try {
    const output = await child.output();
    return {
      success: output.success,
      code: output.code,
      stdout: new TextDecoder().decode(output.stdout),
      stderr: new TextDecoder().decode(output.stderr),
    };
  } finally {
    signal.removeEventListener("abort", abort);
  }
};

let commandRunner: CommandRunner = defaultRunner;

/** Test seam; production always uses an argv-only Deno.Command. */
export function setCommandRunnerForTest(runner?: CommandRunner): void {
  commandRunner = runner ?? defaultRunner;
}

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

function strings(record: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    if (typeof record[key] === "string") return record[key] as string;
  }
  return "";
}

function parseModels(payload: unknown): z.infer<typeof LoadedModelSchema>[] {
  const entries = Array.isArray(payload)
    ? payload
    : payload && typeof payload === "object" &&
        Array.isArray((payload as Record<string, unknown>).models)
    ? (payload as Record<string, unknown>).models as unknown[]
    : null;
  if (!entries) throw new Error("missing model array");
  return entries.map((entry) => {
    if (!entry || typeof entry !== "object") throw new Error("invalid model");
    const record = entry as Record<string, unknown>;
    return LoadedModelSchema.parse({
      identifier: strings(record, "identifier", "modelKey", "id"),
      type: strings(record, "type", "modelType"),
      architecture: strings(record, "architecture", "architectureName"),
    });
  });
}

async function runJson(
  binary: string,
  args: string[],
  timeoutMs: number,
  callerSignal: AbortSignal,
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

async function observe(
  _args: z.infer<typeof ObserveArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
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
    );
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
  version: "2026.08.25.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    daemon: {
      description:
        "Sanitized daemon status and models currently loaded in memory; missing measurements remain explicit.",
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
