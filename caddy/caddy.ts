/** Systemd Caddy management through an existing Swamp SSH model. @module */
import { z } from "npm:zod@4";
import { driver, hostSafety } from "./driver.ts";
import { helperMain } from "./helper.ts";

const Name = z.string().max(255).regex(/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/);
const Digest = z.string().regex(/^[a-f0-9]{64}$/);
const Empty = z.object({}).strict();

function nonUniversalClients(cidrs: string[]): boolean {
  try {
    for (const bits of [32, 128]) {
      const ranges = cidrs.filter((cidr) =>
        cidr.includes(":") === (bits === 128)
      )
        .map((cidr) => {
          const [address, prefix] = cidr.split("/");
          let value: bigint;
          if (bits === 32) {
            value = address.split(".").reduce(
              (n, byte) => (n << 8n) + BigInt(byte),
              0n,
            );
          } else {
            const normalized = new URL("http://[" + address + "]/")
              .hostname.slice(1, -1);
            const halves = normalized.split("::");
            const left = halves[0] ? halves[0].split(":") : [];
            const right = halves[1] ? halves[1].split(":") : [];
            const words = halves.length === 1 ? left : [
              ...left,
              ...Array(8 - left.length - right.length).fill("0"),
              ...right,
            ];
            value = words.reduce(
              (n, word) => (n << 16n) + BigInt("0x" + word),
              0n,
            );
          }
          const size = 1n << BigInt(bits - Number(prefix));
          const start = value & ~(size - 1n);
          return [start, start + size - 1n];
        }).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
      let end = -1n;
      for (const [start, stop] of ranges) {
        if (start > end + 1n) break;
        if (stop > end) end = stop;
      }
      if (end === (1n << BigInt(bits)) - 1n) return false;
    }
    return true;
  } catch {
    return false;
  }
}

const Global = z.object({
  sshModel: Name.describe(
    "Existing @swamp/ssh model; its own credentials remain authoritative",
  ),
  host: Name.describe("One exact host name in the SSH model"),
  helperPath: z.string().max(255).regex(
    /^\/(?:[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\/)*[a-zA-Z0-9_-][a-zA-Z0-9_.-]*$/,
  ).default(
    "/usr/local/sbin/swamp-caddy",
  ).describe(
    "Root-owned helper on the host; the only command the sudoers rule allows",
  ),
}).strict();
/** Exact identity and observed digest required to retire one owned route. */
export const Removal = z.object({
  name: z.string().regex(/^[a-z][a-z0-9_]{0,31}$/),
  hostname: z.string().max(253).regex(/^[a-z0-9.-]+$/),
  wildcardDomain: z.string().max(253).regex(/^[a-z0-9.-]+$/),
  expectedSha256: Digest.describe(
    "Digest returned by inspect; refuses changes on drift",
  ),
}).strict();
/** Bounded route configuration; verified HTTPS is the default backend transport. */
export const Route = Removal.extend({
  upstream: z.string().max(259).regex(
    /^(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}$/,
  ),
  upstreamScheme: z.enum(["http", "https"]).default("https").describe(
    "Verified HTTPS by default; cleartext HTTP requires explicit operator opt-in",
  ),
  upstreamCaFile: z.string().max(255).regex(
    /^\/etc\/caddy\/trust\/[a-zA-Z0-9_-]+\.pem$/,
  ).optional().describe(
    "Verified public CA PEM on the proxy; required for HTTPS backends",
  ),
  allowedCidrs: z.array(
    z.union([z.cidrv4().max(18), z.cidrv6().max(49)]).refine(
      (cidr) => Number(cidr.split("/")[1]) > 0,
      "Universal client networks are not supported",
    ),
  ).min(
    1,
  ).max(32).refine(
    nonUniversalClients,
    "Client networks must not collectively cover an entire address family",
  ),
}).refine(
  (route) =>
    route.upstreamScheme === "https"
      ? route.upstreamCaFile !== undefined
      : route.upstreamCaFile === undefined,
  { message: "HTTPS requires a scoped CA file; HTTP must not specify one" },
);
const Result = z.object({
  requestId: z.string().uuid(),
  action: z.enum(["inspect", "plan", "apply", "remove"]),
  beforeSha256: Digest,
  afterSha256: Digest,
  changed: z.boolean(),
  validated: z.boolean(),
  serviceActive: z.boolean(),
  backupPath: z.string().regex(
    /^\/etc\/caddy\/\.swamp-caddy-backups\/[a-f0-9]{64}-[a-f0-9]{32}\.Caddyfile$/,
  ).nullable(),
  route: z.string().max(4096).nullable(),
}).strict();
const Operation = Result.extend({
  transport: z.object({
    modelId: z.string().uuid(),
    host: Name,
    name: z.string().max(300),
    version: z.number().int().positive(),
  }).strict(),
});
const ChildResource = z.object({
  kind: z.literal("resource"),
  specName: z.literal("runResult"),
  name: z.string().max(300),
  version: z.number().int().positive(),
  size: z.number().int().nonnegative().max(131072),
  metadata: z.object({
    ownerDefinition: z.object({
      ownerType: z.literal("model-method"),
      ownerRef: z.string().uuid(),
    }),
  }),
  attributes: z.object({
    host: Name,
    method: z.literal("script"),
    exitCode: z.literal(0),
    signal: z.null(),
    error: z.undefined().optional(),
    stdout: z.string().max(16384),
  }),
});
type Definition = {
  definition: { id: string; name: string };
  type: { normalized: string };
};
type Context = {
  globalArgs: unknown;
  signal: AbortSignal;
  logger: { info: (message: string) => void };
  definitionRepository?: {
    findByNameGlobal: (name: string) => Promise<Definition | null>;
    findAllByIdGlobal?: (id: string) => Promise<Definition[]>;
  };
  runModel?: (request: {
    definition: string;
    method: string;
    arguments: Record<string, unknown>;
  }) => Promise<
    { ok: true; resources: unknown[] } | { ok: false; error: unknown }
  >;
  writeResource: (
    spec: string,
    name: string,
    value: Record<string, unknown>,
  ) => Promise<unknown>;
  createFileWriter?: (
    spec: string,
    name: string,
  ) => { writeText: (text: string) => Promise<unknown> };
};

function parseClosed<T extends z.ZodObject>(
  schema: T,
  value: unknown,
): z.output<T> {
  if (
    typeof value !== "object" || value === null ||
    Object.keys(value).some((key) => !Object.hasOwn(schema.shape, key))
  ) {
    throw new Error(
      "Caddy data contains unsupported fields or values; details withheld",
    );
  }
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new Error(
      "Caddy data contains unsupported fields or values; details withheld",
    );
  }
  return parsed.data;
}

function expectedRoute(route: z.infer<typeof Route>): string {
  const networks = route.allowedCidrs.map((cidr) => {
    const [address, prefix] = cidr.split("/");
    const canonical = address.includes(":")
      ? new URL("http://[" + address + "]/").hostname.slice(1, -1)
      : address;
    return canonical + "/" + Number(prefix);
  });
  const proxy = route.upstreamScheme === "https"
    ? [
      "        reverse_proxy https://" + route.upstream + " {",
      "            transport http {",
      "                tls_trust_pool file " + route.upstreamCaFile,
      "            }",
      "        }",
    ]
    : ["        reverse_proxy " + route.upstream];
  return [
    "    # BEGIN swamp-caddy " + route.name,
    "    @swamp_" + route.name + " host " + route.hostname,
    "    handle @swamp_" + route.name + " {",
    "        @outside_" + route.name + " not remote_ip " + networks.join(" "),
    "        respond @outside_" + route.name + ' "Forbidden" 403',
    ...proxy,
    "    }",
    "    # END swamp-caddy " + route.name,
    "",
  ].join("\n");
}

/** The helper's exact bytes: the transaction plus its root entry point. */
export const helperSource =
  "#!/usr/bin/python3\n# Generated from driver.ts + helper.ts; do not edit by hand. Install root-owned at /usr/local/sbin/swamp-caddy." +
  driver + helperMain;

/** Hex SHA-256 of the helper the host must carry. */
export async function helperDigest(): Promise<string> {
  const bytes = new TextEncoder().encode(helperSource);
  const hash = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(hash)).map((b) =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

/**
 * The unprivileged script the SSH model runs. It never elevates itself: it
 * checks that the installed helper is byte-identical to the one this
 * extension ships, then hands the payload to `sudo -n <helper>` on stdin.
 * `-n` makes a missing sudoers rule fail at once instead of prompting.
 */
export function wrapperScript(
  helperPath: string,
  expected: string,
  payload: unknown,
): string {
  return hostSafety + String.raw`
import hashlib,json,subprocess,sys
helper=${JSON.stringify(helperPath)}
expected=${JSON.stringify(expected)}
payload=json.loads(${JSON.stringify(JSON.stringify(payload))})
try:
    protected_path(helper,'executable')
    fd=os.open(helper,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as source:
        meta=os.fstat(source.fileno())
        if meta.st_uid!=0 or meta.st_mode & 0o022 or meta.st_size>65536:
            raise RuntimeError('Unsafe helper')
        data=source.read(65537)
    if len(data)>65536: raise RuntimeError('Oversized helper')
except (OSError,RuntimeError):
    print(json.dumps({'error':'helper must be a protected root-owned regular executable; install the emitted bytes'})); sys.exit(4)
if hashlib.sha256(data).hexdigest()!=expected:
    print(json.dumps({'error':'installed helper is not a pinned compatible version'})); sys.exit(4)
try:
    p=bounded_process(['/usr/bin/sudo','-n',helper],input=json.dumps(payload).encode(),timeout=330)
    out=p.stdout.decode()
except Exception:
    print(json.dumps({'error':'helper execution failed, exceeded its deadline or returned excessive output; inspect before retrying'})); sys.exit(5)
if not out.strip():
    print(json.dumps({'error':'helper produced no answer; sudo -n was probably refused (check /etc/sudoers.d/swamp-caddy)'})); sys.exit(p.returncode or 5)
sys.stdout.write(out); sys.exit(p.returncode)
`;
}

async function execute(
  action: "inspect" | "plan" | "apply" | "remove",
  args: unknown,
  ctx: Context,
) {
  const global = parseClosed(Global, ctx.globalArgs);
  if (action === "inspect") parseClosed(Empty, args);
  const route = action === "plan" || action === "apply"
    ? parseClosed(Route, args)
    : null;
  const removal = action === "remove" ? parseClosed(Removal, args) : null;
  const expected = route ? expectedRoute(route) : null;
  ctx.logger.info("Running Caddy operation through the configured SSH model");
  if (!ctx.definitionRepository?.findAllByIdGlobal || !ctx.runModel) {
    throw new Error("Native child model execution is required");
  }
  ctx.signal.throwIfAborted();
  const target = await ctx.definitionRepository.findByNameGlobal(
    global.sshModel,
  );
  if (
    !target || target.type.normalized !== "@swamp/ssh" ||
    target.definition.name !== global.sshModel ||
    !z.string().uuid().safeParse(target.definition.id).success
  ) {
    throw new Error(
      "Configured transport must resolve to an existing @swamp/ssh model",
    );
  }
  const identities = await ctx.definitionRepository.findAllByIdGlobal(
    target.definition.id,
  );
  if (
    identities.length !== 1 ||
    identities[0].type.normalized !== "@swamp/ssh" ||
    identities[0].definition.name !== global.sshModel ||
    identities[0].definition.id !== target.definition.id
  ) {
    throw new Error("Transport model identity is ambiguous");
  }
  // Native lookup tries names before UUIDs; a UUID-shaped model name must not
  // shadow the identity that was just resolved and checked.
  const shadow = await ctx.definitionRepository.findByNameGlobal(
    target.definition.id,
  );
  if (
    shadow && (
      shadow.definition.id !== target.definition.id ||
      shadow.definition.name !== global.sshModel ||
      shadow.type.normalized !== "@swamp/ssh"
    )
  ) throw new Error("Transport model identity is shadowed");
  const requestId = crypto.randomUUID();
  const payload = { ...route, ...removal, action, requestId };
  const script = wrapperScript(
    global.helperPath,
    await helperDigest(),
    payload,
  );
  ctx.signal.throwIfAborted();
  const invocation = await ctx.runModel({
    definition: target.definition.id,
    method: "script",
    arguments: {
      hosts: "name:" + global.host,
      script,
      interpreter: "python3",
      sudo: false,
      timeoutSec: 360,
      parallel: 1,
      captureOutput: true,
      okExitCodes: [0],
    },
  });
  ctx.signal.throwIfAborted();
  if (!invocation.ok || invocation.resources.length !== 1) {
    throw new Error(
      "Swamp transport operation failed; inspect the SSH model method report. Raw diagnostics withheld.",
    );
  }
  const checked = ChildResource.safeParse(invocation.resources[0]);
  if (
    !checked.success ||
    checked.data.name !== "run-script-" + global.host ||
    checked.data.metadata.ownerDefinition.ownerRef !== target.definition.id ||
    checked.data.attributes.host !== global.host
  ) {
    throw new Error(
      "SSH invocation returned invalid or mismatched resource evidence",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(checked.data.attributes.stdout);
  } catch {
    throw new Error("Helper answer was not JSON; inspect the SSH model record");
  }
  const failure = z.object({ error: z.string() }).safeParse(parsed);
  if (failure.success) {
    throw new Error(
      "Caddy helper refused; inspect the protected SSH model record. Raw diagnostics withheld.",
    );
  }
  const result = parseClosed(Result, parsed);
  if (result.requestId !== requestId || result.action !== action) {
    throw new Error(
      "Helper response does not match this request; inspect before retrying",
    );
  }
  if (
    result.route !== expected ||
    result.changed !== (result.beforeSha256 !== result.afterSha256) ||
    (action === "inspect"
      ? result.changed || result.validated || result.backupPath !== null
      : !result.validated || !result.serviceActive ||
        result.beforeSha256 !== (route ?? removal)?.expectedSha256 ||
        (action === "plan" || !result.changed
          ? result.backupPath !== null
          : result.backupPath === null || !result.backupPath.startsWith(
            "/etc/caddy/.swamp-caddy-backups/" + result.beforeSha256 + "-",
          )))
  ) {
    throw new Error(
      "Helper response contradicts the requested operation; details withheld",
    );
  }
  const handle = await ctx.writeResource("operation", action, {
    ...result,
    transport: {
      modelId: target.definition.id,
      host: global.host,
      name: checked.data.name,
      version: checked.data.version,
    },
  });
  ctx.logger.info("Caddy operation completed");
  return { dataHandles: [handle] };
}

/** Own Caddy extension: preserves the existing service, wildcard TLS and other routes. */
export const model = {
  type: "@jpisgeek/caddy",
  version: "2026.10.15.1",
  globalArguments: Global,
  upgrades: [
    {
      toVersion: "2026.09.21.1",
      description:
        "The transaction now runs as a root-owned helper on the host " +
        "(helperPath, default /usr/local/sbin/swamp-caddy) reached through " +
        "sudo -n, instead of the whole script under sudo. configPath, " +
        "caddyBinary and systemctlBinary are fixed inside the helper and are " +
        "no longer global arguments; existing values are dropped.",
      upgradeAttributes: (old: Record<string, unknown>) => {
        const next = { ...old };
        delete next.configPath;
        delete next.caddyBinary;
        delete next.systemctlBinary;
        return next;
      },
    },
    {
      toVersion: "2026.10.04.1",
      description:
        "Add method-scoped HTTPS backend trust; global arguments are unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => ({ ...old }),
    },
    {
      toVersion: "2026.10.06.1",
      description:
        "Add digest-gated removal of one exact managed route; global arguments are unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => ({ ...old }),
    },
    {
      toVersion: "2026.10.15.1",
      description:
        "Require native child execution and the newly pinned protected helper. " +
        "HTTPS now defaults on and requires upstreamCaFile; workflows using " +
        "cleartext backends must explicitly set upstreamScheme: http. " +
        "Every Caddyfile writer must honor the helper's lock. " +
        "Global arguments are unchanged; do not install a helper or change a workflow automatically.",
      upgradeAttributes: (old: Record<string, unknown>) => ({ ...old }),
    },
  ],
  resources: {
    operation: {
      description:
        "Correlated Caddy operation; no full configuration or credentials",
      schema: Operation,
      lifetime: "7d",
      garbageCollection: 20,
    },
    helperDigest: {
      description:
        "Digest and size of emitted helper bytes; not an inspection of a remote service",
      schema: z.object({ sha256: Digest, bytes: z.number().int().positive() })
        .strict(),
      lifetime: "7d",
      garbageCollection: 5,
    },
  },
  files: {
    helper: {
      description:
        "The exact root-owned helper to install on the host as helperPath; the extension refuses any other bytes there",
      contentType: "text/x-python",
      lifetime: "7d",
      garbageCollection: 5,
    },
  },
  // Installed Swamp validates merged globals first, then passes method-only
  // inputs to execute. Strip only at that adapter; parseClosed rejects every
  // unexpected execution input, and CLI admission rejects undeclared overrides.
  methods: {
    helper: {
      description:
        "Emit the helper's exact bytes and digest so an operator can install it root-owned on the host; nothing runs remotely",
      arguments: Empty.strip(),
      execute: async (args: unknown, ctx: Context) => {
        parseClosed(Empty, args);
        if (!ctx.createFileWriter) throw new Error("File output unavailable");
        const digest = await helperDigest();
        const file = await ctx.createFileWriter("helper", "swamp-caddy")
          .writeText(helperSource);
        const record = await ctx.writeResource(
          "helperDigest",
          "helper-digest",
          {
            sha256: digest,
            bytes: new TextEncoder().encode(helperSource).length,
          },
        );
        ctx.logger.info(
          "Helper emitted; install it at helperPath, root-owned, mode 0755",
        );
        return { dataHandles: [file, record] };
      },
    },
    inspect: {
      description: "Read the Caddyfile digest and active service state",
      arguments: Empty.strip(),
      execute: (args: unknown, ctx: Context) => execute("inspect", args, ctx),
    },
    plan: {
      description:
        "Render and validate one wildcard-host route without replacing live configuration",
      arguments: Route.strip(),
      execute: (args: unknown, ctx: Context) => execute("plan", args, ctx),
    },
    apply: {
      description:
        "Validate, privately back up, atomically replace and reload one route; roll back on reload failure",
      arguments: Route.strip(),
      execute: (args: unknown, ctx: Context) => execute("apply", args, ctx),
    },
    remove: {
      description:
        "Remove one exact managed route after a digest check, private backup and full validation; preserve every other route",
      arguments: Removal.strip(),
      execute: (args: unknown, ctx: Context) => execute("remove", args, ctx),
    },
  },
};
