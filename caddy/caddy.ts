/** Systemd Caddy management through an existing Swamp SSH model. @module */
import { z } from "npm:zod@4";
import { driver } from "./driver.ts";

const Name = z.string().regex(/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/);
const Digest = z.string().regex(/^[a-f0-9]{64}$/);
const Global = z.object({
  sshModel: Name.describe(
    "Existing @swamp/ssh model; its own credentials remain authoritative",
  ),
  host: Name.describe("One exact host name in the SSH model"),
  configPath: z.string().regex(/^\/[a-zA-Z0-9_./-]+\/Caddyfile$/).default(
    "/etc/caddy/Caddyfile",
  ),
  caddyBinary: z.string().regex(/^\/[a-zA-Z0-9_./-]+$/).default(
    "/usr/bin/caddy",
  ),
  systemctlBinary: z.string().regex(/^\/[a-zA-Z0-9_./-]+$/).default(
    "/usr/bin/systemctl",
  ),
});
const Route = z.object({
  name: z.string().regex(/^[a-z][a-z0-9_]{0,31}$/),
  hostname: z.string().regex(/^[a-z0-9.-]+$/),
  wildcardDomain: z.string().regex(/^[a-z0-9.-]+$/),
  upstream: z.string().regex(
    /^(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}$/,
  ),
  allowedCidrs: z.array(z.string().regex(/^[0-9a-fA-F.:]+\/[0-9]{1,3}$/)).min(
    1,
  ),
  expectedSha256: Digest.describe(
    "Digest returned by inspect; refuses changes on drift",
  ),
});
const Result = z.object({
  requestId: z.string(),
  action: z.enum(["inspect", "plan", "apply"]),
  beforeSha256: Digest,
  afterSha256: Digest,
  changed: z.boolean(),
  validated: z.boolean(),
  serviceActive: z.boolean(),
  backupPath: z.string().nullable(),
  route: z.string().nullable(),
});
type Context = {
  globalArgs: unknown;
  signal: AbortSignal;
  logger: { info: (message: string) => void };
  writeResource: (
    spec: string,
    name: string,
    value: Record<string, unknown>,
  ) => Promise<unknown>;
};

async function cli(args: string[], signal: AbortSignal): Promise<unknown> {
  const p = await new Deno.Command("swamp", {
    args: [...args, "--json"],
    stdout: "piped",
    stderr: "piped",
    signal,
  }).output();
  if (!p.success) {
    throw new Error(
      "Swamp transport operation failed; inspect the SSH model method report. Raw diagnostics withheld.",
    );
  }
  return JSON.parse(new TextDecoder().decode(p.stdout));
}

async function execute(
  action: "inspect" | "plan" | "apply",
  args: unknown,
  ctx: Context,
) {
  const global = Global.parse(ctx.globalArgs);
  const route = action === "inspect" ? {} : Route.parse(args);
  ctx.logger.info("Running Caddy operation through the configured SSH model");
  const metadata = await cli(["model", "get", global.sshModel], ctx.signal) as {
    type?: string;
  };
  if (metadata.type !== "@swamp/ssh") {
    throw new Error("Transport model must be @swamp/ssh");
  }
  const requestId = crypto.randomUUID();
  const payload = { ...global, ...route, action, requestId };
  const script = driver + "\nprint(json.dumps(transaction(json.loads(" +
    JSON.stringify(JSON.stringify(payload)) + "))))\n";
  await cli([
    "model",
    "method",
    "run",
    global.sshModel,
    "script",
    "--input",
    "hosts=name:" + global.host,
    "--input",
    "interpreter=python3",
    "--input",
    "sudo=true",
    "--input",
    "timeoutSec=360",
    "--input",
    "script=" + script,
  ], ctx.signal);
  const data = await cli([
    "data",
    "get",
    global.sshModel,
    "run-script-" + global.host,
  ], ctx.signal) as { content?: { stdout?: string; exitCode?: number } };
  if (data.content?.exitCode !== 0 || typeof data.content.stdout !== "string") {
    throw new Error("SSH result is missing or failed");
  }
  const result = Result.parse(JSON.parse(data.content.stdout));
  if (result.requestId !== requestId || result.action !== action) {
    throw new Error(
      "SSH result was replaced by a concurrent operation; inspect before retrying",
    );
  }
  const handle = await ctx.writeResource("operation", action, result);
  ctx.logger.info("Caddy operation completed");
  return { dataHandles: [handle] };
}

/** Own Caddy extension: preserves the existing service, wildcard TLS and other routes. */
export const model = {
  type: "@jpisgeek/caddy",
  version: "2026.09.04.1",
  globalArguments: Global,
  resources: {
    operation: {
      description:
        "Correlated Caddy operation; no full configuration or credentials",
      schema: Result,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  methods: {
    inspect: {
      description: "Read the Caddyfile digest and active service state",
      arguments: z.object({}),
      execute: (args: unknown, ctx: Context) => execute("inspect", args, ctx),
    },
    plan: {
      description:
        "Render and validate one wildcard-host route without replacing live configuration",
      arguments: Route,
      execute: (args: unknown, ctx: Context) => execute("plan", args, ctx),
    },
    apply: {
      description:
        "Validate, privately back up, atomically replace and reload one route; roll back on reload failure",
      arguments: Route,
      execute: (args: unknown, ctx: Context) => execute("apply", args, ctx),
    },
  },
};
