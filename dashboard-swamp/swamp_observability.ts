/**
 * Read Swamp's documented operational interfaces into typed resources.
 *
 * This model invokes the Swamp binary directly with an argv array. It never
 * uses a shell, command/shell model, private database, or internal HTTP API.
 * Each interface is independent: one unavailable command is persisted as a
 * coverage gap while the remaining observations survive.
 */
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  repoDir: z.string().min(1).describe("Swamp repository to observe"),
  swampBinary: z.string().min(1).default("swamp").describe(
    "Swamp executable path or name",
  ),
  server: z.string().url().refine(
    (value) => {
      const url = new URL(value);
      return url.protocol === "https:" && !url.username && !url.password &&
        !url.search && !url.hash;
    },
    "server must use https and must not contain URL credentials, query parameters, or fragments",
  ).optional()
    .describe(
      "Optional HTTPS swamp serve URL without userinfo, query, or fragment; omit to observe the local repository",
    ),
  token: z.string().min(1).optional().meta({ sensitive: true }).describe(
    "Optional serve token; use a vault expression. Passed only in the child environment.",
  ),
  timeoutMs: z.number().int().positive().default(15_000),
});

const ObserveArgsSchema = z.object({});

const InterfaceNameSchema = z.enum([
  "run-history",
  "run-doctor",
  "workflow-history",
  "stored-reports",
  "serve-heartbeat",
]);

const ObservationSchema = z.object({
  interface: InterfaceNameSchema,
  available: z.boolean(),
  observedAt: z.iso.datetime(),
  errorKind: z.enum([
    "",
    "unsupported",
    "unauthorized",
    "timeout",
    "unreachable",
    "invalid-response",
    "command-failed",
  ]),
  error: z.string(),
  payload: z.json().nullable(),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;
type Observation = z.infer<typeof ObservationSchema>;

interface CommandResult {
  success: boolean;
  code: number;
  stdout: string;
  stderr: string;
}

export type CommandRunner = (
  binary: string,
  args: string[],
  options: { cwd: string; env: Record<string, string>; signal: AbortSignal },
) => Promise<CommandResult>;

const defaultRunner: CommandRunner = async (binary, args, options) => {
  const command = new Deno.Command(binary, {
    args,
    cwd: options.cwd,
    env: options.env,
    clearEnv: false,
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  });
  const child = command.spawn();
  const abort = () => {
    try {
      child.kill("SIGTERM");
    } catch {
      // The process may already have exited.
    }
  };
  options.signal.addEventListener("abort", abort, { once: true });
  try {
    const output = await child.output();
    return {
      success: output.success,
      code: output.code,
      stdout: new TextDecoder().decode(output.stdout),
      stderr: new TextDecoder().decode(output.stderr),
    };
  } finally {
    options.signal.removeEventListener("abort", abort);
  }
};

let commandRunner: CommandRunner = defaultRunner;

/** Test seam; production always uses the argv-only Deno.Command runner. */
export function setCommandRunnerForTest(runner?: CommandRunner): void {
  commandRunner = runner ?? defaultRunner;
}

function classifyFailure(text: string): Observation["errorKind"] {
  if (/unauthorized|forbidden|401|403|invalid token/i.test(text)) {
    return "unauthorized";
  }
  if (/timed out|timeout/i.test(text)) return "timeout";
  if (/connect|refused|unreachable|dns|network/i.test(text)) {
    return "unreachable";
  }
  return "command-failed";
}

function safeError(kind: Observation["errorKind"], code?: number): string {
  switch (kind) {
    case "unauthorized":
      return "Swamp rejected the configured serve credential";
    case "timeout":
      return "Swamp interface did not respond before the timeout";
    case "unreachable":
      return "Swamp interface could not be reached";
    case "invalid-response":
      return "Swamp returned invalid JSON for this interface";
    case "unsupported":
      return "This Swamp build exposes no public serve-heartbeat query";
    default:
      return `Swamp command failed${
        code === undefined ? "" : ` (exit ${code})`
      }`;
  }
}

async function query(
  g: GlobalArgs,
  name: Observation["interface"],
  args: string[],
  callerSignal: AbortSignal,
): Promise<Observation> {
  const observedAt = new Date().toISOString();
  const timeout = AbortSignal.timeout(g.timeoutMs);
  const signal = AbortSignal.any([callerSignal, timeout]);
  const remote = g.server ? ["--server", g.server] : [];
  try {
    const result = await commandRunner(
      g.swampBinary,
      [...args, ...remote, "--json"],
      {
        cwd: g.repoDir,
        env: g.token ? { SWAMP_SERVER_TOKEN: g.token } : {},
        signal,
      },
    );
    if (callerSignal.aborted) throw callerSignal.reason;
    if (!result.success) {
      const kind = timeout.aborted
        ? "timeout"
        : classifyFailure(`${result.stderr}\n${result.stdout}`);
      return {
        interface: name,
        available: false,
        observedAt,
        errorKind: kind,
        error: safeError(kind, result.code),
        payload: null,
      };
    }
    try {
      return {
        interface: name,
        available: true,
        observedAt,
        errorKind: "",
        error: "",
        payload: JSON.parse(result.stdout),
      };
    } catch {
      return {
        interface: name,
        available: false,
        observedAt,
        errorKind: "invalid-response",
        error: safeError("invalid-response"),
        payload: null,
      };
    }
  } catch (error) {
    if (callerSignal.aborted) throw error;
    const kind = timeout.aborted
      ? "timeout"
      : classifyFailure(error instanceof Error ? error.message : String(error));
    return {
      interface: name,
      available: false,
      observedAt,
      errorKind: kind,
      error: safeError(kind),
      payload: null,
    };
  }
}

async function observe(
  _args: z.infer<typeof ObserveArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const definitions = [
    ["run-history", ["run", "history", "--all"]],
    ["run-doctor", ["run", "doctor"]],
    ["workflow-history", ["workflow", "history", "search"]],
    ["stored-reports", ["report", "search"]],
  ] as const;

  const observations = await Promise.all(
    definitions.map(([name, args]) => query(g, name, [...args], ctx.signal)),
  );
  observations.push({
    interface: "serve-heartbeat",
    available: false,
    observedAt: new Date().toISOString(),
    errorKind: "unsupported",
    error: safeError("unsupported"),
    payload: null,
  });

  const dataHandles = [];
  for (const observation of observations) {
    dataHandles.push(
      await ctx.writeResource(
        "observation",
        `interface-${observation.interface}`,
        observation,
        {
          tags: {
            interface: observation.interface,
            available: String(observation.available),
          },
        },
      ),
    );
  }
  return { dataHandles };
}

/** Public Swamp operational-interface collector. */
export const model = {
  type: "@jpisgeek/swamp-observability",
  version: "2026.08.25.2",
  globalArguments: GlobalArgsSchema,
  resources: {
    observation: {
      description:
        "One verbatim JSON snapshot per documented Swamp operational interface; errors are sanitized and unavailable interfaces are retained explicitly.",
      schema: ObservationSchema,
      lifetime: "30d" as const,
      garbageCollection: 30,
    },
  },
  methods: {
    observe: {
      description:
        "Read run history, stale-run diagnostics, workflow history, and stored reports; record heartbeat coverage as unsupported when no public query exists.",
      arguments: ObserveArgsSchema,
      execute: observe,
    },
  },
};
