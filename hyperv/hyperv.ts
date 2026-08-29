/**
 * Read the Hyper-V host, its VMs, and its virtual switches.
 *
 * Reached by SSH to the Windows OpenSSH server, running PowerShell there.
 * There is no REST or JSON-RPC surface for Hyper-V, so PowerShell is the API,
 * and SSH is how we get to it. Authentication is whatever identity the ambient
 * ssh-agent already holds, so no password or WinRM credential is accepted,
 * read, or stored by this model.
 *
 * Two things make the transport less fragile than it looks:
 *
 *   - Commands are sent with `-EncodedCommand`, base64 UTF-16LE. The Windows
 *     sshd's default shell is cmd.exe, so anything with a quote, pipe, or
 *     brace in it gets mangled twice before PowerShell ever sees it. Encoding
 *     removes every layer of quoting at once. This is not premature: a literal
 *     pipe in a remote command already truncated a script earlier in this
 *     repo's history and left a file half-written.
 *   - Output is parsed as JSON, and PowerShell is told to emit an array even
 *     for a single object. `ConvertTo-Json` on one item returns an object, on
 *     many an array; code that assumes one shape breaks the first time the
 *     count changes.
 *
 * Authentication is the ambient ssh-agent. Load an identity that the target
 * authorizes before running anything here; this model never handles key
 * material, never reads a key file, and never takes a password argument. If
 * no agent is reachable the ssh call fails, which is the intended outcome
 * rather than a fallback to something weaker.
 *
 * Collection is read-only; lifecycle methods mutate and are guarded.
 *
 * The guards are not ceremony. `delete` destroys a machine and its disks, and
 * `restoreCheckpoint` silently discards everything since the checkpoint was
 * taken -- a rollback that quietly throws away an hour of work is worse than
 * one that refuses. Both require the caller to name what they are destroying,
 * so a wrong vmName arriving from a workflow input fails rather than
 * succeeding against the wrong machine.
 *
 * Three serialisation traps live on this API, all the same shape: a value that
 * arrives as a .NET type rather than the thing it represents. VM `State` is an
 * enum number (a stopped VM is 3, not "Off"). `SecureBoot` is also an enum
 * number, where 0 means ON -- read as a boolean it reports the security
 * posture backwards. `CreationTime` arrives as `/Date(1234567890000)/`. Each
 * parses cleanly into something wrong, which is the dangerous kind, so all
 * three are resolved PowerShell-side rather than decoded here from a table
 * that drifts as Microsoft adds values.
 */
import { z } from "npm:zod@4";

/**
 * How to reach the host. `host` and `user` are required and deliberately have
 * no defaults: a default address is a way to act on the wrong machine, and on
 * Windows the login account is frequently not the fleet's usual one. Source
 * both from a vault expression so no machine identity lands in a tracked file.
 */
/**
 * A hostname, IPv4 literal, or bracketed IPv6 literal -- and nothing else.
 *
 * This string becomes half of an ssh destination argument, so the shapes it
 * must refuse are not hypothetical. `user@evil` in the host smuggles a second
 * userinfo section and ssh honours the LAST one, silently redirecting the
 * connection. A leading `-` is read by ssh as an option rather than a
 * destination. Whitespace and control characters split or truncate the
 * argument. None of these need a shell to be dangerous; ssh's own parser is
 * enough.
 */
const HOSTLIKE =
  /^(?:\[[0-9A-Fa-f:.]+\]|[0-9A-Za-z](?:[0-9A-Za-z-]*[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:[0-9A-Za-z-]*[0-9A-Za-z])?)*)$/;

/**
 * A login name. Deliberately narrower than what Windows will accept: the
 * point is to refuse `-oProxyCommand=...` and anything carrying `@`, a space,
 * or a control character, not to model every legal account name. A host whose
 * account does not fit this can be reached by an ssh_config Host block.
 */
const USERLIKE = /^[A-Za-z0-9._][A-Za-z0-9._-]*$/;

/**
 * A name that identifies exactly ONE object on the host.
 *
 * PowerShell's `-Name` parameters accept WILDCARDS. `Remove-VM -Name *`
 * selects every machine, and quoting does not help: the string is a perfectly
 * well-formed argument, it just means "all of them". This is what made the
 * confirmation guards insufficient rather than merely thin -- `confirmName`
 * equalling `vmName` is satisfied by passing `*` twice, and the model would
 * have confirmed the caller's intent to destroy the entire host.
 *
 * Control characters are refused in the same place, for a different reason.
 * Resource IDs are digested over parts joined by NUL, so a name allowed to
 * contain NUL could shift the boundary and make two different names produce
 * one ID -- the exact collision the digest exists to prevent.
 */
export const SafeName = z
  .string()
  .min(1)
  .max(128)
  .refine((v) => !/[*?\[\]]/.test(v), {
    message:
      "name must not contain PowerShell wildcards (* ? [ ]): they select " +
      "more than one object, and a confirmation that repeats a wildcard " +
      "confirms nothing",
  })
  // deno-lint-ignore no-control-regex
  .refine((v) => !/[\u0000-\u001f\u007f]/.test(v), {
    message: "name must not contain control characters",
  })
  .refine((v) => v.trim() === v && v.trim() !== "", {
    message: "name must not be blank or padded with whitespace",
  });

export const GlobalArgsSchema = z.object({
  host: z
    .string()
    .min(1)
    .max(253)
    .regex(
      HOSTLIKE,
      "host must be a bare hostname, IPv4 literal, or bracketed IPv6 " +
        "literal: no userinfo, scheme, port, whitespace, or leading dash",
    )
    .describe(
      "Address of the Hyper-V host's SSH server. Source it from a vault " +
        "expression so no machine identity lands in a tracked file.",
    )
    .meta({ sensitive: true }),
  user: z
    .string()
    .min(1)
    .max(64)
    .regex(
      USERLIKE,
      "user must be a plain login name: no @, whitespace, or leading dash",
    )
    .describe(
      "Login user for SSH. Also vault-sourced; on Windows this is frequently " +
        "an account whose name differs from the fleet default.",
    )
    .meta({ sensitive: true }),
  port: z.number().int().positive().max(65535).default(22),
  timeoutSec: z.number().int().positive().default(30),
});

const DiscoverArgsSchema = z.object({});

/**
 * The argument shape for the methods that only need to name a target:
 * `start`, and the read side of the checkpoint methods. Empty names are
 * rejected at the schema rather than passed to the host, where an empty
 * `-Name` would select nothing or, worse, everything.
 */
export const VmNameArgs = z.object({
  vmName: SafeName.describe("Name of the target virtual machine."),
});

/**
 * `stop`, whose danger is entirely in the `force` flag. A graceful stop needs
 * the guest's Shutdown integration service to answer; `force` does not, and
 * risks the guest filesystem exactly as pulling the plug would. It defaults
 * off and warns when set.
 */
export const StopArgsSchema = z.object({
  vmName: SafeName,
  force: z.boolean().default(false).describe(
    "Cut power instead of asking the guest to shut down. A graceful stop " +
      "needs the Shutdown integration service responding; force does not, " +
      "and risks the guest filesystem exactly as pulling the plug would.",
  ),
});

/**
 * `checkpoint`. The name must not already exist on the VM -- Hyper-V would
 * otherwise decide for itself what to do about the collision, and the caller
 * would not know which restore point they ended up with.
 */
export const CheckpointArgsSchema = z.object({
  vmName: SafeName,
  name: SafeName.describe(
    "Checkpoint name to create. Must not already exist on this VM: the " +
      "method refuses a duplicate rather than letting Hyper-V decide what to " +
      "do about the collision, because the caller would not then know which " +
      "restore point they ended up with.",
  ),
});

/**
 * `removeCheckpoint`, which is the mirror of `checkpoint` and therefore needs
 * the opposite precondition. It shared `CheckpointArgsSchema` until a review
 * pointed out that the published description then told callers of THIS method
 * that the name must not already exist -- the exact inverse of the truth. Two
 * verbs, two schemas.
 */
export const RemoveCheckpointArgsSchema = z.object({
  vmName: SafeName,
  name: SafeName.describe(
    "Checkpoint to remove. Must already exist on this VM; it is the " +
      "checkpoint that will be deleted.",
  ),
});

/**
 * `restoreCheckpoint`, which is the most dangerous read-shaped verb here.
 * Rolling back discards every change made since the checkpoint was taken, the
 * loss is silent -- Hyper-V neither warns nor offers an undo -- so
 * `confirmDiscardSince` must repeat the checkpoint name. A rollback that
 * quietly throws away an hour of work is worse than one that refuses.
 */
export const RestoreArgsSchema = z.object({
  vmName: SafeName,
  name: SafeName.describe("Checkpoint to roll back to."),
  confirmDiscardSince: SafeName.describe(
    "Must equal the checkpoint name. Restoring discards every change made " +
      "since it was taken, and that loss is silent -- Hyper-V does not warn " +
      "and there is no undo. Naming it again is the acknowledgement.",
  ),
});

/**
 * `delete`, guarded by making the caller say the name twice. `confirmName`
 * must equal `vmName` exactly, because a `vmName` arriving from a workflow
 * input is not something to take on trust and this verb removes the machine
 * and its checkpoints. `deleteDisks` is off by default so the VHDX files
 * survive: Hyper-V's own Remove-VM leaves them, and destroying them silently
 * would be a harsher default than the platform's.
 */
export const DeleteArgsSchema = z.object({
  vmName: SafeName,
  confirmName: SafeName.describe(
    "Must exactly equal vmName. Deleting removes the machine and its " +
      "checkpoints; a vmName arriving from a workflow input is not something " +
      "to take on trust.",
  ),
  confirmForcePowerOff: z.boolean().default(false).describe(
    "Required when the VM is RUNNING. Deleting a running machine cuts its " +
      "power -- there is no graceful shutdown in this path and the guest " +
      "filesystem takes the same risk as pulling the plug. Deletion of a " +
      "running VM is refused unless this is set, so the power-off is a " +
      "decision rather than a side effect of the delete.",
  ),
  deleteDisks: z.boolean().default(false).describe(
    "Also delete the VHDX files. Off by default: Hyper-V's own Remove-VM " +
      "leaves disks behind, and silently destroying them would be a harsher " +
      "default than the platform's own.",
  ),
});

const VmHostSchema = z.object({
  name: z.string(),
  logicalProcessorCount: z.number().int(),
  memoryCapacityBytes: z.number(),
  virtualMachinePath: z.string(),
  vmCount: z.number().int(),
  switchCount: z.number().int(),
});

const VmSchema = z.object({
  name: z.string(),
  /** Resolved name, e.g. Running / Off / Paused -- never the raw enum number. */
  state: z.string(),
  status: z.string(),
  generation: z.number().int().nullable(),
  cpuCount: z.number().int().nullable(),
  memoryAssignedBytes: z.number().nullable(),
  uptimeSeconds: z.number().nullable(),
});

const CheckpointSchema = z.object({
  vmName: z.string(),
  name: z.string(),
  /** Standard or Production. Production checkpoints use VSS in the guest. */
  checkpointType: z.string(),
  createdAt: z.string().nullable(),
  parentName: z.string().nullable(),
});

const VmSwitchSchema = z.object({
  name: z.string(),
  /** External / Internal / Private, resolved from the numeric SwitchType. */
  switchType: z.string(),
});

type Ctx = {
  signal: AbortSignal;
  globalArgs: Record<string, unknown>;
  modelType: string;
  modelId: string;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
    warning: (msg: string, props?: Record<string, unknown>) => void;
  };
  // deno-lint-ignore no-explicit-any
  writeResource: (...a: any[]) => Promise<any>;
};

/** base64 of the UTF-16LE bytes, which is what -EncodedCommand expects. */
export function encodeCommand(ps: string): string {
  const u16 = new Uint8Array(ps.length * 2);
  for (let i = 0; i < ps.length; i++) {
    const c = ps.charCodeAt(i);
    u16[i * 2] = c & 0xff;
    u16[i * 2 + 1] = c >> 8;
  }
  return btoa(String.fromCharCode(...u16));
}

async function runPowerShell(
  g: z.infer<typeof GlobalArgsSchema>,
  ps: string,
  signal: AbortSignal,
): Promise<string> {
  const out = await new Deno.Command("ssh", {
    args: [
      // Everything ssh will otherwise take from ambient config is pinned
      // here, because this model's guarantees have to be its own rather than
      // the environment's. StrictHostKeyChecking=yes refuses an unknown or
      // changed host key instead of trusting it -- a Hyper-V host that has
      // been replaced underneath you is exactly the case worth failing on.
      // ControlMaster/ControlPath matter more than they look: an already-open
      // multiplexed socket makes ssh reuse that connection and skip the host
      // key policy entirely, so a strict setting here would be decorative
      // without them. ProxyCommand and PermitLocalCommand both run local
      // programs, and forwarding hands this process's agent to the remote
      // host, where a socket signs for every key it holds.
      "-o",
      "BatchMode=yes",
      // BatchMode only suppresses PROMPTS. On its own ssh will still try
      // password and keyboard-interactive against a host that offers them,
      // and will still read default identity files. Public key only, so the
      // set of things that can authenticate is the set the caller configured.
      "-o",
      "PreferredAuthentications=publickey",
      "-o",
      "PasswordAuthentication=no",
      "-o",
      "KbdInteractiveAuthentication=no",
      "-o",
      "StrictHostKeyChecking=yes",
      "-o",
      "ControlMaster=no",
      "-o",
      "ControlPath=none",
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
      `ConnectTimeout=${Math.min(g.timeoutSec, 10)}`,
      "-p",
      String(g.port),
      // `--` so a destination can never be read as an option, belt to the
      // regex's braces.
      "--",
      `${g.user}@${g.host}`,
      `powershell -NoProfile -NonInteractive -EncodedCommand ${
        encodeCommand(ps)
      }`,
    ],
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
    signal: AbortSignal.any([
      signal,
      AbortSignal.timeout((g.timeoutSec + 10) * 1000),
    ]),
  }).output();

  const stdout = new TextDecoder().decode(out.stdout).trim();
  if (out.code !== 0) {
    const err = new TextDecoder().decode(out.stderr);
    throw new Error(
      `powershell over ssh failed (exit ${out.code}): ${classifyRemote(err)}`,
    );
  }
  return stdout;
}

/**
 * Turn remote stderr into one of a fixed set of verdicts, and let nothing
 * else out.
 *
 * The matching reads the full text; only the verdict escapes. That split is
 * the whole point: stderr from a Windows host routinely carries the hostname,
 * an account name, a filesystem path, a VM name, or whatever a failing cmdlet
 * decided to print, and this text was previously copied verbatim into thrown
 * errors -- which are written into resources AND logs, so one unlucky failure
 * publishes infrastructure detail into the datastore permanently.
 *
 * An unrecognised failure returns "unclassified" rather than a sample of the
 * text. Losing detail on rare failures is the price; the alternative leaks by
 * default and is only safe by luck.
 */
export function classifyRemote(stderr: string): string {
  const patterns: [RegExp, string][] = [
    [
      /host key verification failed|remote host identification/i,
      "host-key-refused",
    ],
    [
      /permission denied|access denied|authentication failed/i,
      "permission-denied",
    ],
    [
      /connection (refused|closed|timed out)|no route to host|network is unreachable/i,
      "connection-failed",
    ],
    [
      /could not resolve|name or service not known|nodename nor servname/i,
      "host-unresolved",
    ],
    [
      /is not recognized as|commandnotfound|term '.*' is not recognized/i,
      "powershell-or-cmdlet-missing",
    ],
    [
      /not authorized|requires elevation|access is denied/i,
      "insufficient-privilege",
    ],
  ];
  for (const [re, code] of patterns) if (re.test(stderr)) return code;
  return stderr.trim() ? "unclassified" : "no-stderr";
}

/** Parse JSON that may be a single object, an array, or empty. */
export function asArray(raw: string): Record<string, unknown>[] {
  if (!raw) return [];
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    // Deliberately no sample of `raw`. Malformed stdout is still remote
    // output and can carry the same infrastructure detail stderr does; the
    // byte count is enough to tell "empty" from "something came back wrong".
    throw new Error(
      `expected JSON from PowerShell, got ${raw.length} byte(s) that did not parse`,
    );
  }
  if (v === null) return [];
  return Array.isArray(v)
    ? v as Record<string, unknown>[]
    : [v as Record<string, unknown>];
}

/**
 * Collapse an untrusted remote name into something safe to put in a resource
 * ID, and say how much was lost.
 *
 * VM, checkpoint, and switch names come from the host and are chosen by
 * whoever runs it. They can hold spaces, slashes, unicode, or nothing at all.
 * A raw name in an ID is two problems: characters a datastore may not accept,
 * and -- worse -- ambiguity, because `a-b` and `a` + `b` collapse to the same
 * string once you join with a dash.
 */
export function slugPart(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || "unnamed";
}

/**
 * The separator between ID parts. Two dashes is unambiguous because
 * `slugPart` collapses every run of non-alphanumerics to a SINGLE dash, so a
 * doubled dash cannot occur inside a part and can only ever be the join.
 */
export const PART_SEP = "--";

/**
 * Build a resource ID that is scoped, collision-free, and readable.
 *
 * Three properties, each load-bearing. It is SCOPED by host, so the same VM
 * name on two Hyper-V hosts does not overwrite one record with the other --
 * the previous form omitted the host entirely. It is COLLISION-FREE because
 * the trailing digest is taken over the original parts with a delimiter that
 * cannot appear in them, so two different names cannot produce one ID even
 * after slugging flattens them. And it stays READABLE, because the slugs are
 * kept in front of the digest.
 */
export async function resourceId(
  kind: string,
  host: string,
  ...parts: string[]
): Promise<string> {
  const scoped = [host, ...parts];
  const digest = await sha256Hex(scoped.join("\u0000"));
  return [kind, ...scoped.map(slugPart)].join(PART_SEP) + "-" + digest;
}

/** Hex SHA-256 via Web Crypto, so no dependency is added for one hash. */
export async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The shapes PowerShell is expected to return, declared rather than assumed.
 *
 * These were previously read by casting -- `String(row.Name ?? "")`,
 * `num(row.MemoryCapacity) ?? 0` -- which cannot fail. A cmdlet that returned
 * nothing for a field produced an empty string or a zero, and a partially
 * collected host was then written down as a complete one. A host with 0 GB of
 * memory and a VM with an empty name are not plausible readings of reality;
 * they are the shape of a silent collection failure, and the schemas make
 * that failure loud.
 *
 * Unknown KEYS are tolerated on purpose. Windows adds properties between
 * builds, and a schema that rejects an unrecognised field turns a routine
 * platform update into a total collection outage on a host that is otherwise
 * answering correctly. What is NOT tolerated is a field this model reads
 * being absent or the wrong type -- that is the failure worth being loud
 * about, because it is the one that silently produces a plausible-looking
 * record. Values are typed; the object is open. (zod strips unknown keys by
 * default, so nothing unvalidated reaches a resource either way.)
 */
export const PsVmHostRow = z.object({
  Name: z.string().min(1),
  LogicalProcessorCount: z.number().int().nonnegative(),
  MemoryCapacity: z.number().nonnegative(),
  VirtualMachinePath: z.string().min(1),
});

export const PsVmRow = z.object({
  Name: z.string().min(1),
  State: z.string().min(1),
  Status: z.string(),
  Generation: z.number().int(),
  ProcessorCount: z.number().int().nonnegative(),
  MemoryAssigned: z.number().nonnegative(),
  // A .NET TimeSpan, serialised as an OBJECT carrying TotalSeconds -- not a
  // number and not a string. Typed, rather than left unknown and narrowed by
  // hand at the read, which is where a wrong assumption used to survive.
  Uptime: z.object({ TotalSeconds: z.number() }).nullable().optional(),
});

export const PsSwitchRow = z.object({
  Name: z.string().min(1),
  // The raw enum number. Kept numeric on purpose: SWITCH_TYPES maps it, and a
  // test asserts that map covers the enum rather than spot-checking it.
  SwitchType: z.number().int(),
});

/**
 * The discover response as a whole.
 *
 * `vms` and `switches` are REQUIRED. They were previously read as
 * `top.vms ?? []`, which turned a response that omitted the field entirely --
 * a truncated pipeline, a cmdlet that errored past $ErrorActionPreference --
 * into the confident claim that the host runs no virtual machines. An empty
 * array still means empty; a missing one now means broken.
 */
export const DiscoverEnvelope = z.object({
  host: PsVmHostRow,
  vms: z.array(PsVmRow),
  switches: z.array(PsSwitchRow),
});

/** The state probe. `state` must be present; only its VALUE may be null. */
/**
 * The disk-deletion envelope, and it is REQUIRED rather than defaulted.
 *
 * The proof used to be read as `top?.results ?? []`, which meant a truncated
 * or malformed response produced an empty result list, counted zero failures,
 * and logged that every disk had been removed. A deletion whose evidence went
 * missing is not a deletion that succeeded. `diskCount` is carried alongside
 * so the count can be reconciled: a host that reported four disks and
 * returned three results has not accounted for the fourth.
 */
export const DiskDeleteEnvelope = z.object({
  diskCount: z.number().int().nonnegative(),
  results: z.array(z.object({
    index: z.number().int().nonnegative(),
    removed: z.boolean(),
  })),
});

export const PsStateRow = z.object({
  state: z.string().nullable(),
});

export const PsCheckpointRow = z.object({
  VMName: z.string().min(1),
  Name: z.string().min(1),
  CheckpointType: z.string(),
  // Either the /Date(ms)/ form PowerShell emits or an ISO string, depending
  // on how it was serialised. Both are strings; anything else is a bug.
  CreationTime: z.string(),
  ParentSnapshotName: z.string().nullable().optional(),
});

/**
 * The checkpoint response. `checkpoints` is required for the same reason
 * `vms` is: removal and restore return this list as their proof, so a
 * response missing the field must not read as "none, therefore verified".
 */
export const CheckpointEnvelope = z.object({
  host: z.string().min(1),
  checkpoints: z.array(PsCheckpointRow),
});

/**
 * Parse one PowerShell row, and fail with the field path rather than the
 * value. A zod message would otherwise quote the offending input straight
 * into an error that gets written to a resource and a log.
 */
export function parseRow<T>(
  schema: z.ZodType<T>,
  row: unknown,
  what: string,
): T {
  const r = schema.safeParse(row);
  if (r.success) return r.data;
  const where = r.error.issues
    .map((i) => `${i.path.join(".") || "<root>"}: ${i.code}`)
    .join("; ");
  throw new Error(
    `${what} from the host did not match the expected shape (${where})`,
  );
}

/**
 * Virtual switch types, keyed by the number `Get-VMSwitch` actually returns.
 * Exported so the tests can assert the map covers the enum rather than
 * checking a couple of values by hand and missing one when Microsoft adds it.
 */
export const SWITCH_TYPES: Record<number, string> = {
  0: "Private",
  1: "Internal",
  2: "External",
};

/**
 * Narrow an unknown to a finite number, or null. PowerShell's JSON puts
 * nulls, strings, and occasionally NaN where a count belongs, and every one of
 * those coerces to something plausible if you let it. Null here means "not
 * measured", which the schemas distinguish from zero.
 */
export function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

async function discover(_args: unknown, ctx: Ctx) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const handles = [];

  // One round trip for all three collections. Each is wrapped in @() so a
  // single result still arrives as an array.
  const ps = `
$ErrorActionPreference='Stop'
# Progress records are written to stderr as CLIXML. Harmless on success, but
# it buries any real error message, so silence it rather than parse around it.
$ProgressPreference='SilentlyContinue'
$h = Get-VMHost | Select-Object Name,LogicalProcessorCount,MemoryCapacity,VirtualMachinePath
# State is an enum and serialises as its NUMBER, not its name -- a VM that is
# off arrives as 3. Resolve it PowerShell-side with ToString() rather than
# keeping an enum table here that drifts the moment Microsoft adds a state.
$vms = @(Get-VM | Select-Object Name,Status,Generation,ProcessorCount,MemoryAssigned,Uptime,@{n='State';e={$_.State.ToString()}})
$sw = @(Get-VMSwitch | Select-Object Name,SwitchType)
[pscustomobject]@{ host=$h; vms=$vms; switches=$sw } | ConvertTo-Json -Depth 5 -Compress
`.trim();

  const raw = await runPowerShell(g, ps, ctx.signal);
  const top = parseRow(
    DiscoverEnvelope,
    asArray(raw)[0],
    "discover envelope",
  );

  // Parsed, not cast. A field the host failed to return is an error here
  // rather than an empty string or a zero written down as fact -- and the
  // envelope above requires `vms` and `switches` to be PRESENT, so a response
  // that omits them fails instead of reading as "zero found".
  const hostRec = top.host;
  const vms = top.vms;
  const switches = top.switches;

  handles.push(
    await ctx.writeResource(
      "vmHost",
      await resourceId("vmhost", hostRec.Name),
      {
        name: hostRec.Name,
        logicalProcessorCount: hostRec.LogicalProcessorCount,
        memoryCapacityBytes: hostRec.MemoryCapacity,
        virtualMachinePath: hostRec.VirtualMachinePath,
        vmCount: vms.length,
        switchCount: switches.length,
      },
      { tags: { vmCount: String(vms.length) } },
    ),
  );

  for (const v of vms) {
    // Uptime arrives as a .NET TimeSpan, serialised as an object with
    // TotalSeconds -- not a number, and not a string.
    const up = v.Uptime as Record<string, unknown> | null | undefined;
    handles.push(
      await ctx.writeResource(
        "vm",
        await resourceId("vm", hostRec.Name, v.Name),
        {
          name: v.Name,
          state: v.State,
          status: v.Status,
          generation: v.Generation,
          cpuCount: v.ProcessorCount,
          memoryAssignedBytes: v.MemoryAssigned,
          uptimeSeconds: up ? num(up.TotalSeconds) : null,
        },
        { tags: { state: v.State } },
      ),
    );
  }

  for (const sw of switches) {
    handles.push(
      await ctx.writeResource(
        "vmSwitch",
        await resourceId("vmswitch", hostRec.Name, sw.Name),
        {
          name: sw.Name,
          switchType: SWITCH_TYPES[sw.SwitchType] ?? `Type${sw.SwitchType}`,
        },
      ),
    );
  }

  ctx.logger.info(
    `hyper-v: ${vms.length} VM(s), ${switches.length} switch(es) on ` +
      hostRec.Name,
  );
  return handles;
}

/** PowerShell serialises DateTime as /Date(epochMillis)/. Nothing else does. */
export function dotNetDate(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const m = /^\/Date\((-?\d+)\)\/$/.exec(v);
  if (m) {
    const n = Number(m[1]);
    if (!Number.isFinite(n)) return null;
    const d = new Date(n);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  // Already ISO-8601? Accept it. Anything else is not a timestamp, and the
  // old `return v` passed it straight through to a field documented as
  // ISO-8601 -- so a cmdlet returning "Unknown" was stored as if it were a
  // date, and every consumer downstream inherited that lie.
  const d = new Date(v);
  if (!Number.isNaN(d.getTime()) && /^\d{4}-\d{2}-\d{2}/.test(v)) {
    return d.toISOString();
  }
  return null;
}

/** Read one VM's state by name, or null when it does not exist. */
async function vmState(
  g: z.infer<typeof GlobalArgsSchema>,
  vmName: string,
  signal: AbortSignal,
): Promise<string | null> {
  // Handle ONLY the not-found case; let everything else fail.
  //
  // This ran under $ErrorActionPreference='SilentlyContinue', which turned
  // every Get-VM failure -- no permission, provider not loaded, WMI broken --
  // into `state: null`, i.e. "that VM does not exist". `delete` verifies
  // itself by asking this exact question, so a host that had stopped
  // answering would have confirmed a deletion that never happened. Now the
  // specific "not found" exception answers null and any other error
  // propagates.
  const ps = `
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
  $v = Get-VM -Name ${psQuote(vmName)} -ErrorAction Stop
  [pscustomobject]@{ state = $v.State.ToString() } | ConvertTo-Json -Compress
} catch [Microsoft.HyperV.PowerShell.VirtualizationOperationFailedException] {
  if ($_.Exception.Message -match 'not find|does not exist') { '{"state":null}' }
  else { throw }
} catch [System.Management.Automation.ItemNotFoundException] {
  '{"state":null}'
}`.trim();
  const raw = await runPowerShell(g, ps, signal);
  // Strict: `state` must be present, and only an explicit JSON null means
  // "no such VM". The old form returned null for a malformed response too,
  // which made a broken probe indistinguishable from an absent machine --
  // and `delete` verifies its own success by asking exactly this question.
  const o = parseRow(PsStateRow, asArray(raw)[0], "VM state probe");
  return o.state;
}

/**
 * Refuse a restore whose acknowledgement does not name the checkpoint.
 *
 * Extracted so the refusal is reachable without a live host. The check itself
 * is the safety property -- restoring discards every change made since the
 * checkpoint and Hyper-V keeps no undo point -- so it is exactly the logic
 * that must not be provable only by running it against a real machine.
 * Compared with `!==`, not case-folded or trimmed: a caller that cannot
 * reproduce the name exactly has not demonstrated it knows what it is
 * discarding.
 */
export function assertRestoreConfirmed(
  name: string,
  confirmDiscardSince: string,
): void {
  if (confirmDiscardSince !== name) {
    throw new Error(
      `refusing to restore: confirmDiscardSince ${
        JSON.stringify(confirmDiscardSince)
      } does not match the checkpoint ${JSON.stringify(name)}. ` +
        `Restoring discards everything since that checkpoint, silently.`,
    );
  }
}

/**
 * Refuse a delete whose confirmation does not equal the VM name. Same
 * reasoning as assertRestoreConfirmed: a vmName arriving from a workflow
 * input is not something to take on trust, and the refusal has to be testable
 * without destroying a machine to observe it.
 */
export function assertDeleteConfirmed(
  vmName: string,
  confirmName: string,
): void {
  if (confirmName !== vmName) {
    throw new Error(
      `refusing to delete: confirmName ${JSON.stringify(confirmName)} ` +
        `does not equal vmName ${JSON.stringify(vmName)}`,
    );
  }
}

/**
 * Single-quote a value for PowerShell. Doubling the quote is the documented
 * escape inside a single-quoted string, and single-quoted strings do not
 * interpolate -- so a VM name containing $( ) cannot become code.
 */
export function psQuote(v: string): string {
  return "'" + v.replace(/'/g, "''") + "'";
}

/**
 * Read a VM's checkpoints, and let a failed read fail.
 *
 * This query previously carried `-ErrorAction SilentlyContinue`, which made
 * "the query broke" and "this VM has no checkpoints" the same answer: an
 * empty array. That is not a cosmetic difference. `restoreCheckpoint` and
 * `removeCheckpoint` both return this list as their proof of what happened,
 * so a suppressed failure let a mutation report success while having verified
 * nothing at all. `$ErrorActionPreference='Stop'` now governs it -- a VM with
 * genuinely no checkpoints still returns empty, because that is not an error
 * in PowerShell, so the two cases are finally distinguishable.
 *
 * The host's own name comes back in the same round trip, because resource IDs
 * are scoped by host and paying a second connection for a string that is
 * already on the wire would be silly.
 */
async function listCheckpoints(
  g: z.infer<typeof GlobalArgsSchema>,
  vmName: string,
  signal: AbortSignal,
): Promise<{ hostName: string; rows: z.infer<typeof PsCheckpointRow>[] }> {
  const ps = `
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$h = (Get-VMHost).Name
$c = @(Get-VMSnapshot -VMName ${psQuote(vmName)} |
  Select-Object VMName,Name,CreationTime,ParentSnapshotName,
    @{n='CheckpointType';e={$_.SnapshotType.ToString()}})
[pscustomobject]@{ host=$h; checkpoints=$c } | ConvertTo-Json -Depth 4 -Compress`
    .trim();
  const top = parseRow(
    CheckpointEnvelope,
    asArray(await runPowerShell(g, ps, signal))[0],
    "checkpoint envelope",
  );
  return { hostName: top.host, rows: top.checkpoints };
}

async function collectCheckpoints(
  g: z.infer<typeof GlobalArgsSchema>,
  vmName: string,
  ctx: Ctx,
): Promise<unknown[]> {
  const { hostName, rows } = await listCheckpoints(g, vmName, ctx.signal);
  const handles = [];
  for (const c of rows) {
    handles.push(
      await ctx.writeResource(
        "checkpoint",
        await resourceId("checkpoint", hostName, c.VMName, c.Name),
        {
          vmName: c.VMName,
          name: c.Name,
          checkpointType: c.CheckpointType,
          createdAt: dotNetDate(c.CreationTime),
          parentName: c.ParentSnapshotName ?? null,
        },
        { tags: { vm: c.VMName } },
      ),
    );
  }
  return handles;
}

async function start(args: z.infer<typeof VmNameArgs>, ctx: Ctx) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const before = await vmState(g, args.vmName, ctx.signal);
  if (before === null) throw new Error(`no VM named ${args.vmName}`);
  if (before === "Running") {
    ctx.logger.info(`${args.vmName} already running`);
    return [];
  }
  await runPowerShell(
    g,
    `$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';Start-VM -Name ${
      psQuote(args.vmName)
    }`,
    ctx.signal,
  );
  const after = await vmState(g, args.vmName, ctx.signal);
  if (after !== "Running") {
    throw new Error(`start did not take: ${args.vmName} is ${after}`);
  }
  ctx.logger.info(`${args.vmName}: ${before} -> ${after}`);
  return [];
}

async function stop(args: z.infer<typeof StopArgsSchema>, ctx: Ctx) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const before = await vmState(g, args.vmName, ctx.signal);
  if (before === null) throw new Error(`no VM named ${args.vmName}`);
  if (before === "Off") {
    ctx.logger.info(`${args.vmName} already off`);
    return [];
  }
  if (args.force) {
    ctx.logger.warning(
      `${args.vmName}: forcing power off -- the guest filesystem is at the ` +
        `same risk as pulling the plug`,
    );
  }
  await runPowerShell(
    g,
    `$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';Stop-VM -Name ${
      psQuote(args.vmName)
    }${args.force ? " -TurnOff -Force" : " -Force"}`,
    ctx.signal,
  );
  const after = await vmState(g, args.vmName, ctx.signal);
  if (after !== "Off") throw new Error(`stop did not take: still ${after}`);
  ctx.logger.info(`${args.vmName}: ${before} -> ${after}`);
  return [];
}

async function checkpoint(
  args: z.infer<typeof CheckpointArgsSchema>,
  ctx: Ctx,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  if ((await vmState(g, args.vmName, ctx.signal)) === null) {
    throw new Error(`no VM named ${args.vmName}`);
  }
  // Refuse a duplicate BEFORE mutating. The uniqueness rule used to live only
  // in the argument's description, which meant Hyper-V decided what to do
  // about a collision and the caller never learned which restore point they
  // ended up holding.
  const before = await listCheckpoints(g, args.vmName, ctx.signal);
  if (before.rows.some((c) => c.Name === args.name)) {
    throw new Error(
      `${args.vmName} already has a checkpoint named ${args.name}; ` +
        `remove it first or choose another name`,
    );
  }

  await runPowerShell(
    g,
    `$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';Checkpoint-VM -Name ${
      psQuote(args.vmName)
    } -SnapshotName ${psQuote(args.name)}`,
    ctx.signal,
  );

  // Read back, and look for THIS checkpoint. The old check was
  // `handles.length > 0`, which any pre-existing checkpoint satisfied -- so a
  // creation that silently did nothing reported success on the strength of
  // someone else's restore point.
  const after = await listCheckpoints(g, args.vmName, ctx.signal);
  if (!after.rows.some((c) => c.Name === args.name)) {
    throw new Error(`checkpoint ${args.name} did not appear after creation`);
  }
  ctx.logger.info(`${args.vmName}: checkpoint ${args.name} created`);
  return await collectCheckpoints(g, args.vmName, ctx);
}

async function restoreCheckpoint(
  args: z.infer<typeof RestoreArgsSchema>,
  ctx: Ctx,
) {
  assertRestoreConfirmed(args.name, args.confirmDiscardSince);
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  if ((await vmState(g, args.vmName, ctx.signal)) === null) {
    throw new Error(`no VM named ${args.vmName}`);
  }
  await runPowerShell(
    g,
    `$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';Restore-VMSnapshot -VMName ${
      psQuote(args.vmName)
    } -Name ${psQuote(args.name)} -Confirm:$false`,
    ctx.signal,
  );
  ctx.logger.info(`${args.vmName}: restored to ${args.name}`);
  ctx.logger.warning(
    `${args.vmName}: everything since ${args.name} is gone. Hyper-V does not ` +
      `keep an undo point for this.`,
  );
  return await collectCheckpoints(g, args.vmName, ctx);
}

async function removeCheckpoint(
  args: z.infer<typeof RemoveCheckpointArgsSchema>,
  ctx: Ctx,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);

  // Removing something that was never there is not success, it is a caller
  // working from a stale picture -- and staying quiet about it invites the
  // next call to assume the rest of that picture holds.
  const before = await listCheckpoints(g, args.vmName, ctx.signal);
  if (!before.rows.some((c) => c.Name === args.name)) {
    throw new Error(
      `${args.vmName} has no checkpoint named ${args.name}`,
    );
  }

  await runPowerShell(
    g,
    `$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';Remove-VMSnapshot -VMName ${
      psQuote(args.vmName)
    } -Name ${psQuote(args.name)}`,
    ctx.signal,
  );

  // And confirm it actually went. Now that the query fails loudly instead of
  // returning empty, an absence here means absence rather than a broken read.
  const after = await listCheckpoints(g, args.vmName, ctx.signal);
  if (after.rows.some((c) => c.Name === args.name)) {
    throw new Error(
      `checkpoint ${args.name} is still present on ${args.vmName} after removal`,
    );
  }
  ctx.logger.info(`${args.vmName}: checkpoint ${args.name} removed`);
  return await collectCheckpoints(g, args.vmName, ctx);
}

async function deleteVm(args: z.infer<typeof DeleteArgsSchema>, ctx: Ctx) {
  assertDeleteConfirmed(args.vmName, args.confirmName);
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const before = await vmState(g, args.vmName, ctx.signal);
  if (before === null) throw new Error(`no VM named ${args.vmName}`);

  // Cutting power is its own decision. This path has no graceful shutdown --
  // Stop-VM -TurnOff is the plug, not a request to the guest -- so a caller
  // who only meant "remove this idle VM" should not silently get a hard power
  // cut on a machine that turned out to be running.
  if (before !== "Off" && !args.confirmForcePowerOff) {
    throw new Error(
      `${args.vmName} is ${before}. Deleting it cuts power with no graceful ` +
        `shutdown, risking the guest filesystem. Stop it first, or pass ` +
        `confirmForcePowerOff to accept that.`,
    );
  }

  // Disk removal reports per file. It used to run with -ErrorAction
  // SilentlyContinue while the method logged "disks removed" and threw the
  // result object away, so a disk that could not be deleted -- locked, in use,
  // on a disconnected volume -- was indistinguishable from one that was.
  const ps = `
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$name = ${psQuote(args.vmName)}
$disks = @(Get-VMHardDiskDrive -VMName $name | Select-Object -ExpandProperty Path)
if ((Get-VM -Name $name).State -ne 'Off') { Stop-VM -Name $name -TurnOff -Force }
Remove-VM -Name $name -Force
$results = @()
${
    args.deleteDisks
      ? `foreach ($d in $disks) {
  $ok = $false
  try { Remove-Item -LiteralPath $d -Force -ErrorAction Stop; $ok = $true } catch { $ok = $false }
  # Verify absence rather than trusting the call.
  if (Test-Path -LiteralPath $d) { $ok = $false }
  $results += [pscustomobject]@{ index = $results.Count; removed = $ok }
}`
      : ""
  }
[pscustomobject]@{ diskCount = $disks.Count; results = @($results) } | ConvertTo-Json -Depth 4 -Compress`
    .trim();
  const envelope = parseRow(
    DiskDeleteEnvelope,
    asArray(await runPowerShell(g, ps, ctx.signal))[0],
    "disk deletion envelope",
  );

  // Read back rather than trust the cmdlet.
  const after = await vmState(g, args.vmName, ctx.signal);
  if (after !== null) {
    throw new Error(
      `delete did not take: ${args.vmName} still present (${after})`,
    );
  }

  if (args.deleteDisks) {
    const results = envelope.results;
    // Reconcile before judging. Fewer results than disks means the loop did
    // not finish, and an all-`removed` list of the wrong length is not proof.
    if (results.length !== envelope.diskCount) {
      throw new Error(
        `${args.vmName} was deleted, but disk removal is unaccounted for: ` +
          `the host reported ${envelope.diskCount} disk(s) and returned ` +
          `${results.length} result(s)`,
      );
    }
    const failed = results.filter((r) => !r.removed).length;
    if (failed > 0) {
      // Positions, never paths: a disk path names a volume layout and often
      // the VM, and this message reaches logs and resources.
      throw new Error(
        `${args.vmName} was deleted, but ${failed} of ${results.length} ` +
          `disk(s) could not be removed and are still on disk ` +
          `(positions: ${
            results.filter((r) => !r.removed).map((r) => r.index).join(", ")
          })`,
      );
    }
    ctx.logger.info(
      `${args.vmName}: deleted, ${results.length} disk(s) removed and verified absent`,
    );
  } else {
    ctx.logger.info(`${args.vmName}: deleted (disks left in place)`);
  }
  return [];
}

/**
 * WHY CALLER-SUPPLIED NAMES STAY IN ERRORS AND LOGS -- a deliberate decision,
 * recorded here so it is reviewable rather than assumed.
 *
 * Messages like `no VM named web01` name infrastructure, and this model is
 * emphatic elsewhere about not doing that. The distinction is where the string
 * came from. Remote OUTPUT is screened hard: stderr is classified to a fixed
 * verdict, malformed stdout is reported as a byte count, and parse failures
 * name the field rather than the value -- because none of that was chosen by
 * the caller and all of it can carry things nobody asked for.
 *
 * A `vmName` is different. The caller typed it. It is already in the workflow
 * definition that invoked the method, and -- per the retention trade-off the
 * README states plainly -- it is already stored as a resource field, as a tag,
 * and in readable form inside the resource ID itself. Redacting it from the
 * error while writing it to the record beside that error protects nothing; it
 * only makes a destructive method impossible to diagnose. "delete refused"
 * without saying which machine is worse than useless when a workflow passes
 * the wrong input, which is precisely the failure the confirmation guards
 * exist to catch.
 *
 * The honest description is that this model treats caller-supplied names as
 * the operator's own data, and remote output as untrusted. Anyone unwilling to
 * accept the first half should not accept the resource records either, and
 * that is the operator-decision the README already asks them to make.
 */
/**
 * The model: read-only collection, plus lifecycle methods that mutate and are
 * guarded. Resource lifetimes are `infinite` with garbage collection rather
 * than a TTL, because a VM that stops being reported has usually been deleted
 * and that is worth keeping a record of, not expiring quietly.
 */
export const model = {
  type: "@jpisgeek/hyperv",
  version: "2026.08.29.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    vmHost: {
      description: "The Hyper-V host itself: capacity and where it keeps VMs.",
      schema: VmHostSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    vm: {
      description: "One record per virtual machine. Summary only -- no " +
        "device contents, no console credentials.",
      schema: VmSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    checkpoint: {
      description: "One record per checkpoint. createdAt is normalised to " +
        "ISO-8601 from the /Date(ms)/ form PowerShell emits.",
      schema: CheckpointSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    vmSwitch: {
      description: "One record per virtual switch, with its type resolved " +
        "from the numeric form PowerShell returns.",
      schema: VmSwitchSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },

  methods: {
    discover: {
      description: "Read-only sweep of the Hyper-V host, its VMs, and its " +
        "virtual switches. Writes one resource each and never mutates.",
      arguments: DiscoverArgsSchema,
      execute: discover,
    },
    start: {
      description: "Start a VM. No-op if already running; verifies by " +
        "reading the state back rather than trusting the cmdlet's exit.",
      arguments: VmNameArgs,
      execute: start,
    },
    stop: {
      description: "Stop a VM. Graceful by default, which needs the guest's " +
        "Shutdown integration service responding. force cuts power instead " +
        "and risks the guest filesystem; it warns when used.",
      arguments: StopArgsSchema,
      execute: stop,
    },
    checkpoint: {
      description: "Take a checkpoint. Verifies the checkpoint actually " +
        "appeared afterwards -- a zero exit is not proof it exists.",
      arguments: CheckpointArgsSchema,
      execute: checkpoint,
    },
    restoreCheckpoint: {
      description: "Roll a VM back to a checkpoint. DESTRUCTIVE: everything " +
        "since that checkpoint is discarded, silently and with no undo, so " +
        "confirmDiscardSince must repeat the checkpoint name.",
      arguments: RestoreArgsSchema,
      execute: restoreCheckpoint,
    },
    removeCheckpoint: {
      description: "Delete a checkpoint, merging its differencing disk. " +
        "Does not change the running state of the VM.",
      arguments: RemoveCheckpointArgsSchema,
      execute: removeCheckpoint,
    },
    delete: {
      description: "Delete a VM. DESTRUCTIVE: confirmName must exactly " +
        "equal vmName. Disks are LEFT IN PLACE unless deleteDisks is set, " +
        "matching Hyper-V's own default rather than being harsher than it.",
      arguments: DeleteArgsSchema,
      execute: deleteVm,
    },
  },
};
