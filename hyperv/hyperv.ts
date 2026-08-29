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
 * Authentication is public key only, and which key is offered is ssh's
 * decision, not this model's. An agent identity or an identity file named by
 * the caller's ssh configuration will both be used; this model handles no key
 * material and takes no password argument, and it narrows ssh to publickey so
 * a host offering passwords cannot be used as a fallback. It does not claim
 * to control which identities ssh loads -- that is listed as an operator
 * decision in the README rather than as a guarantee.
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
 * The refused set is wider than ASCII controls, and each addition earns its
 * place. C1 controls (U+0080-U+009F) are controls that survive a naive ASCII
 * check. U+2028 and U+2029 are line and paragraph separators, so a name
 * carrying one can forge an extra line in a log and make a record appear to
 * say something it does not. The bidi and zero-width family
 * (U+200B-U+200F, U+202A-U+202E, U+2066-U+2069, U+FEFF) can reorder or hide
 * text on display, so what an operator reads before confirming a deletion is
 * not what the string actually is -- which matters most in exactly the place
 * this model asks a human to compare two names.
 *
 * Control characters are refused for one more reason.
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
  .refine((v) => !/[\u0000-\u001f\u007f-\u009f]/.test(v), {
    message: "name must not contain control characters",
  })
  .refine((v) => !/[\u2028\u2029]/.test(v), {
    message: "name must not contain line or paragraph separators",
  })
  .refine(
    (v) => !/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(v),
    {
      message:
        "name must not contain zero-width or direction-formatting characters",
    },
  )
  .refine((v) => v.trim() === v && v.trim() !== "", {
    message: "name must not be blank or padded with whitespace",
  })
  .refine(
    (v) => {
      // Iterating a string yields whole code points, so any surrogate still
      // visible here is UNPAIRED. TextEncoder maps every one of them to the
      // same replacement character before hashing, and slugPart drops them
      // all -- so two different malformed names would produce one identical
      // resource ID, which is exactly the collision the digest exists to
      // prevent.
      for (const ch of v) {
        const cp = ch.codePointAt(0)!;
        if (cp >= 0xd800 && cp <= 0xdfff) return false;
      }
      return true;
    },
    { message: "name must not contain unpaired surrogate code units" },
  );

/**
 * A remote string that will be STORED but is not an identifier: status text,
 * a checkpoint type, a filesystem path. It cannot be held to SafeName -- a
 * path contains separators and a status contains spaces -- but it can be
 * bounded. Unbounded and unscreened, a broken or hostile host could write
 * control text or arbitrary bulk into a resource, and in one case into a
 * datastore TAG, which is a queryable index rather than an opaque blob.
 */
export const RemoteText = (max: number) =>
  z
    .string()
    .max(max)
    // deno-lint-ignore no-control-regex
    .refine((v) => !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(v), {
      message: "value must not contain control or line-separator characters",
    })
    // The same families SafeName refuses. They were added there and not here,
    // which left the gap open on the class of strings that is actually
    // remote-controlled -- including the queryable state tag. Bidi and
    // zero-width characters reorder or hide displayed text; unpaired
    // surrogates survive as replacement characters and make distinct values
    // look identical.
    .refine(
      (v) => !/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(v),
      {
        message:
          "value must not contain zero-width or direction-formatting characters",
      },
    )
    .refine((v) => {
      for (const ch of v) {
        const cp = ch.codePointAt(0)!;
        if (cp >= 0xd800 && cp <= 0xdfff) return false;
      }
      return true;
    }, { message: "value must not contain unpaired surrogate code units" });

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
  // Typed rather than `any`. This is the boundary that is supposed to
  // guarantee only validated values reach a resource, and a signature of
  // `(...a: any[]) => Promise<any>` guarantees nothing at all -- it would
  // accept the raw remote object just as happily as the parsed one.
  writeResource: (
    spec: string,
    id: string,
    attributes: Record<string, unknown>,
    options?: { tags?: Record<string, string> },
  ) => Promise<unknown>;
};

/**
 * The ssh argument vector, built in one place so it can be asserted by
 * property rather than by reading the call site.
 *
 * Everything ssh would otherwise take from ambient configuration is pinned
 * here, because this model's guarantees have to be its own rather than the
 * environment's -- and it carries a `delete` verb, so "connected somewhere
 * slightly different than you thought" is not a survivable failure mode.
 */
export function sshArgs(
  g: { host: string; user: string; port: number; timeoutSec: number },
  remote: string,
): string[] {
  return [
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
    // An ssh_config `Host` block can rewrite HostName, and canonicalisation
    // can rewrite it again -- so a host string this model validated can
    // still resolve to a different machine, which for a model with `delete`
    // in it is the whole ballgame. HostName is pinned to the validated
    // value and canonicalisation is off, so config may still supply
    // per-host settings but cannot change WHERE this connects.
    "-o",
    `HostName=${g.host}`,
    "-o",
    "CanonicalizeHostname=no",
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
    `powershell -NoProfile -NonInteractive -EncodedCommand ${remote}`,
  ];
}

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
  const timedOut = AbortSignal.timeout((g.timeoutSec + 10) * 1000);
  const cmd = new Deno.Command("ssh", {
    args: sshArgs(g, encodeCommand(ps)),
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
    signal: AbortSignal.any([signal, timedOut]),
  });

  // Read both streams with a hard byte cap instead of buffering to
  // completion. `.output()` accumulates whatever the far end sends, so a host
  // that is broken or hostile can exhaust this process's memory long before
  // the timeout has anything to say about it -- the timeout bounds how long
  // it runs, not how much it can hand over in that time.
  //
  // The child is killed at the point of overflow rather than after both
  // streams settle. Waiting for stderr to end cannot work when the process is
  // still producing: stderr does not reach EOF until the child exits, and the
  // child is exactly what is not exiting.
  const child = cmd.spawn();
  let killed = false;
  const kill = () => {
    if (killed) return;
    killed = true;
    try {
      child.kill("SIGKILL");
    } catch { /* already gone */ }
  };
  const [stdoutRaw, stderrRaw, status] = await Promise.all([
    readCapped(child.stdout, kill),
    readCapped(child.stderr, kill),
    child.status,
  ]);

  if (killed) {
    throw new Error(
      `powershell over ssh produced more than ${MAX_OUTPUT_BYTES} bytes and ` +
        `was terminated`,
    );
  }
  // Distinguish OUR abort from THEIR failure. Both arrive as a non-zero child
  // status, and reporting a caller cancellation or a local timeout as
  // "powershell over ssh failed" sends whoever is debugging to the wrong
  // machine entirely.
  if (signal.aborted) {
    throw new Error("cancelled before the remote command completed");
  }
  if (timedOut.aborted) {
    throw new Error(
      `timed out locally after ${g.timeoutSec + 10}s waiting for the host`,
    );
  }
  const stdout = new TextDecoder().decode(stdoutRaw).trim();
  if (status.code !== 0) {
    throw new Error(
      `powershell over ssh failed (exit ${status.code}): ${
        classifyRemote(new TextDecoder().decode(stderrRaw))
      }`,
    );
  }
  return stdout;
}

/** Nothing this model asks for is remotely this large. */
export const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

/**
 * Drain a stream up to the cap, calling `onOverflow` the moment it is passed.
 * Returns what was read so far so a caller can still classify a failure.
 */
async function readCapped(
  stream: ReadableStream<Uint8Array>,
  onOverflow: () => void,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_OUTPUT_BYTES) {
        onOverflow();
        break;
      }
      chunks.push(value);
    }
  } catch {
    // The stream dies when the child is killed; that is the expected path
    // after an overflow, not a separate failure to report.
  } finally {
    try {
      reader.releaseLock();
    } catch { /* already released */ }
  }
  const out = new Uint8Array(total > MAX_OUTPUT_BYTES ? 0 : total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
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
  // Narrowed, not asserted. A cast here would let a JSON array of numbers or
  // strings through as if it were a list of records, and every field read
  // downstream would then be undefined rather than an error.
  const rows = Array.isArray(v) ? v : [v];
  return rows.map((row, i) => {
    if (typeof row !== "object" || row === null || Array.isArray(row)) {
      throw new Error(
        `expected a JSON object at position ${i}, got ${
          row === null ? "null" : Array.isArray(row) ? "an array" : typeof row
        }`,
      );
    }
    return row as Record<string, unknown>;
  });
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
 * Three properties, each load-bearing. It is SCOPED by the CONFIGURED target
 * -- the address and port this model was pointed at -- so the same VM name on
 * two Hyper-V hosts does not overwrite one record with the other. Scoping by
 * the name the host REPORTS was the first attempt and is not sound: two
 * machines can answer to the same hostname (a rebuild, a clone, a naming
 * collision across sites), and then their VMs share IDs and silently
 * overwrite each other. The configured address is the thing the operator
 * actually distinguished when they wrote the model down. It is COLLISION-FREE because
 * the trailing digest is taken over the original parts with a delimiter that
 * cannot appear in them, so two different names cannot produce one ID even
 * after slugging flattens them. And it stays READABLE, because the slugs are
 * kept in front of the digest.
 */
export async function resourceId(
  target: string,
  kind: string,
  ...parts: string[]
): Promise<string> {
  const scoped = [target, ...parts];
  return [kind, ...scoped.map(slugPart)].join(PART_SEP) + "-" +
    await sha256Hex(frameParts(scoped));
}

/**
 * Frame parts so no input can forge a boundary, without using a byte that
 * inputs might contain.
 *
 * The first attempt joined with NUL, which is unambiguous only while every
 * part is guaranteed NUL-free. Caller-supplied names are, because `SafeName`
 * refuses control characters -- but names DISCOVERED on the host arrive from
 * PowerShell and were never held to that rule, so the guarantee did not
 * actually cover the inputs it needed to. Length-prefixing removes the
 * question: `["ab","c"]` frames as `2:ab1:c`, `["a","bc"]` as `1:a2:bc`, and
 * no choice of contents makes those collide, because the lengths are read
 * before the content rather than inferred from a delimiter inside it.
 *
 * It also takes a control character out of the published source, which the
 * identifier scan and any reader are entitled to be suspicious of.
 */
/**
 * Find the checkpoints a name would select ON THE HOST.
 *
 * PowerShell's `-Name` is CASE-INSENSITIVE. Comparing with `===` in
 * JavaScript therefore asked a different question from the one the host would
 * answer: a VM already holding "Nightly" passed a uniqueness precheck for
 * "nightly", and the subsequent Checkpoint-VM or Remove-VMSnapshot acted on
 * whichever one it matched. Ask the question the host will ask.
 */
export function matchCheckpoints<T extends { Name: string }>(
  rows: T[],
  name: string,
): T[] {
  const want = name.toLowerCase();
  return rows.filter((c) => c.Name.toLowerCase() === want);
}

export function frameParts(parts: string[]): string {
  return parts.map((p) => `${p.length}:${p}`).join("");
}

/**
 * The stable identity of the connection this model was pointed at: user, host
 * and port.
 *
 * Host and port because two Hyper-V endpoints can live behind one address.
 * The USER because two accounts on one host do not see the same thing --
 * Hyper-V shows an unprivileged account a subset -- so two configurations
 * differing only by account expose different inventories and must not
 * overwrite each other's records.
 */
export function targetKey(
  g: { host: string; user: string; port: number },
): string {
  return `${g.user}@${g.host}:${g.port}`;
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
  Name: SafeName,
  // Positive, not merely non-negative. The comment above claimed a host with
  // zero memory is not a plausible reading of reality; the schema accepted it
  // anyway, which is the gap between saying a thing and enforcing it. A
  // hypervisor with no processors or no memory is a failed query.
  LogicalProcessorCount: z.number().int().positive(),
  MemoryCapacity: z.number().positive(),
  VirtualMachinePath: RemoteText(4096).min(1),
});

export const PsVmRow = z.object({
  // Remote names feed resource IDs, so they are held to the same rule as
  // caller-supplied ones. A host that reports a VM named with a control
  // character is either broken or hostile, and either way its name should not
  // reach an identifier.
  Name: SafeName,
  State: RemoteText(64).min(1),
  Status: RemoteText(256),
  // Hyper-V has exactly two generations. Anything else is not a VM record.
  Generation: z.union([z.literal(1), z.literal(2)]),
  ProcessorCount: z.number().int().positive(),
  MemoryAssigned: z.number().nonnegative(),
  // A .NET TimeSpan, serialised as an OBJECT carrying TotalSeconds -- not a
  // number and not a string. Typed, rather than left unknown and narrowed by
  // hand at the read, which is where a wrong assumption used to survive.
  // Required. `optional()` let a response that omitted uptime entirely read
  // as "uptime unknown" rather than "this response is incomplete", which is
  // the same class of lie as a zeroed memory capacity.
  Uptime: z.object({ TotalSeconds: z.number() }).nullable(),
});

export const PsSwitchRow = z.object({
  Name: SafeName,
  // The raw enum number. Kept numeric on purpose: SWITCH_TYPES maps it, and a
  // test asserts that map covers the enum rather than spot-checking it.
  // Only the enum Hyper-V defines. Accepting any integer and inventing
  // `Type${n}` for the rest stored malformed data under a plausible-looking
  // label instead of rejecting it.
  SwitchType: z.number().int().refine((v) => v in SWITCH_TYPES, {
    message: "SwitchType must be a known Hyper-V switch type",
  }),
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

/**
 * The states Hyper-V reports. Remote strings are interpolated into logs and
 * errors, so the set they can come from is closed rather than "whatever the
 * host said" -- an unrecognised value is rendered as a fixed token instead of
 * echoed. Collection still stores the raw string; this governs what is
 * allowed to reach a message.
 */
export const KNOWN_VM_STATES = new Set([
  "Other",
  "Running",
  "Off",
  "Stopping",
  "Saved",
  "Paused",
  "Starting",
  "Reset",
  "Saving",
  "Pausing",
  "Resuming",
  "FastSaved",
  "FastSaving",
  "ForceShutdown",
  "ForceReboot",
  "Hibernated",
  "ComponentServicing",
  "RunningCritical",
  "OffCritical",
  "StoppingCritical",
  "SavedCritical",
  "PausedCritical",
  "StartingCritical",
  "ResetCritical",
  "SavingCritical",
  "PausingCritical",
  "ResumingCritical",
  "FastSavedCritical",
  "FastSavingCritical",
]);

/** Render a state for a human without letting the host choose the text. */
export function safeState(v: string | null): string {
  if (v === null) return "absent";
  return KNOWN_VM_STATES.has(v) ? v : "unrecognised-state";
}

export const PsStateRow = z.object({
  state: RemoteText(64).min(1).nullable(),
});

/** ISO-8601 as PowerShell emits it, anchored so a prefix cannot pass. */
export const ISO_DATE =
  /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/;

export const PsCheckpointRow = z.object({
  VMName: SafeName,
  Name: SafeName,
  CheckpointType: RemoteText(64),
  // Only the two forms PowerShell actually produces. Accepting any string and
  // letting dotNetDate return null for the rest meant a malformed timestamp
  // was written as "no creation time" -- a broken response wearing the shape
  // of missing data.
  // Shape AND value. `2026-13-45T99:99:99Z` matches the pattern and is not a
  // date; letting it through meant dotNetDate returned null and the record
  // said "no creation time" for a response that was actually malformed.
  CreationTime: z.string().refine((v) => dotNetDate(v) !== null, {
    message:
      "CreationTime must be a .NET /Date(ms)/ or ISO-8601 value that names a " +
      "real instant",
  }),
  // Required, nullable. A root checkpoint genuinely has no parent; a
  // response that omits the field has not told us either way.
  ParentSnapshotName: SafeName.nullable(),
});

/**
 * The checkpoint response. `checkpoints` is required for the same reason
 * `vms` is: removal and restore return this list as their proof, so a
 * response missing the field must not read as "none, therefore verified".
 */
export const CheckpointEnvelope = z.object({
  checkpoints: z.array(PsCheckpointRow),
});

/**
 * Take the single top-level object a call is supposed to return.
 *
 * `asArray(raw)[0]` accepted an array of any length and silently used the
 * first element, so a response carrying extra objects -- a stray Write-Output,
 * a cmdlet that emitted more than intended -- was treated as valid and the
 * remainder discarded unseen. One envelope means one.
 */
export function oneEnvelope(
  raw: string,
  what: string,
): Record<string, unknown> {
  const rows = asArray(raw);
  if (rows.length !== 1) {
    throw new Error(
      `${what}: expected exactly one top-level object from the host, got ${rows.length}`,
    );
  }
  return rows[0];
}

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
    oneEnvelope(raw, "discover"),
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
      await resourceId(targetKey(g), "vmhost", hostRec.Name),
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
    const up = v.Uptime;
    handles.push(
      await ctx.writeResource(
        "vm",
        await resourceId(targetKey(g), "vm", v.Name),
        {
          name: v.Name,
          state: v.State,
          status: v.Status,
          generation: v.Generation,
          cpuCount: v.ProcessorCount,
          memoryAssignedBytes: v.MemoryAssigned,
          uptimeSeconds: up ? up.TotalSeconds : null,
        },
        { tags: { state: v.State } },
      ),
    );
  }

  for (const sw of switches) {
    handles.push(
      await ctx.writeResource(
        "vmSwitch",
        await resourceId(targetKey(g), "vmswitch", sw.Name),
        {
          name: sw.Name,
          switchType: SWITCH_TYPES[sw.SwitchType],
        },
      ),
    );
  }

  // Counts only. The host name is remote-discovered rather than
  // caller-supplied, and it is already stored as a resource field and inside
  // the resource ID -- there is nothing a log line adds except one more place
  // it has to be scrubbed from later.
  ctx.logger.info(
    `hyper-v: ${vms.length} VM(s), ${switches.length} switch(es)`,
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
  // Already ISO-8601? Accept it. The schema now rejects anything that is
  // neither form before this is reached, so a null from here means the value
  // was structurally a date and still unrepresentable -- not that the host
  // sent something else entirely.
  if (ISO_DATE.test(v)) {
    const d = new Date(v);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
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
} catch {
  # ONE condition means absent, and it has to satisfy both halves: the error
  # must carry Hyper-V's own not-found identifier AND come from Get-VM. The
  # previous form also caught ItemNotFoundException outright, which any
  # provider, module or path failure can raise -- and the delete method proves
  # itself by asking this question, so a broken host would have confirmed a
  # deletion that never happened. Everything else propagates.
  $id = $_.FullyQualifiedErrorId
  $isMissing = ($id -like '*InvalidParameter*') -and ($id -like '*GetVM*')
  if (-not $isMissing) {
    $isMissing = ($id -like '*VirtualMachineNotFound*')
  }
  if ($isMissing) { '{"state":null}' } else { throw }
}`.trim();
  const raw = await runPowerShell(g, ps, signal);
  // Strict: `state` must be present, and only an explicit JSON null means
  // "no such VM". The old form returned null for a malformed response too,
  // which made a broken probe indistinguishable from an absent machine --
  // and `delete` verifies its own success by asking exactly this question.
  const o = parseRow(
    PsStateRow,
    oneEnvelope(raw, "VM state probe"),
    "VM state probe",
  );
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
 * PowerShell that resolves a VM name to exactly one machine, or refuses.
 *
 * Hyper-V matches names case-insensitively, so a host can legitimately hold
 * two VMs whose names differ only in case and a confirmed NAME is not a
 * confirmed TARGET. `delete` learned this first and the other verbs did not,
 * which left start, stop and the checkpoint methods acting on whichever match
 * the host picked. Every mutating verb now begins with this, and every one of
 * them then acts on `$vm` -- the resolved object -- rather than passing the
 * name a second time and inviting the host to resolve it again, differently.
 */
function resolveOneVm(vmName: string): string {
  return `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$hits = @(Get-VM -Name ${psQuote(vmName)} -ErrorAction SilentlyContinue)
if ($hits.Count -ne 1) {
  throw "expected exactly one VM matching the given name, found $($hits.Count)"
}
$vm = $hits[0]`;
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
 */
async function listCheckpoints(
  g: z.infer<typeof GlobalArgsSchema>,
  vmName: string,
  signal: AbortSignal,
): Promise<z.infer<typeof PsCheckpointRow>[]> {
  const ps = `${resolveOneVm(vmName)}
$c = @(Get-VMSnapshot -VM $vm |
  Select-Object VMName,Name,CreationTime,ParentSnapshotName,
    @{n='CheckpointType';e={$_.SnapshotType.ToString()}})
[pscustomobject]@{ checkpoints=$c } | ConvertTo-Json -Depth 4 -Compress`
    .trim();
  const top = parseRow(
    CheckpointEnvelope,
    oneEnvelope(await runPowerShell(g, ps, signal), "checkpoints"),
    "checkpoint envelope",
  );
  return top.checkpoints;
}

async function collectCheckpoints(
  g: z.infer<typeof GlobalArgsSchema>,
  vmName: string,
  ctx: Ctx,
): Promise<unknown[]> {
  const rows = await listCheckpoints(g, vmName, ctx.signal);
  const handles = [];
  for (const c of rows) {
    handles.push(
      await ctx.writeResource(
        "checkpoint",
        await resourceId(targetKey(g), "checkpoint", c.VMName, c.Name),
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
    `${resolveOneVm(args.vmName)}
Start-VM -VM $vm`,
    ctx.signal,
  );
  const after = await vmState(g, args.vmName, ctx.signal);
  if (after !== "Running") {
    throw new Error(
      `start did not take: ${args.vmName} is ${safeState(after)}`,
    );
  }
  ctx.logger.info(
    `${args.vmName}: ${safeState(before)} -> ${safeState(after)}`,
  );
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
    `${resolveOneVm(args.vmName)}
Stop-VM -VM $vm${args.force ? " -TurnOff -Force" : " -Force"}`,
    ctx.signal,
  );
  const after = await vmState(g, args.vmName, ctx.signal);
  if (after !== "Off") {
    throw new Error(`stop did not take: still ${safeState(after)}`);
  }
  ctx.logger.info(
    `${args.vmName}: ${safeState(before)} -> ${safeState(after)}`,
  );
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
  if (matchCheckpoints(before, args.name).length > 0) {
    throw new Error(
      `${args.vmName} already has a checkpoint named ${args.name}; ` +
        `remove it first or choose another name`,
    );
  }

  await runPowerShell(
    g,
    `${resolveOneVm(args.vmName)}
# Refuse a duplicate in the same call that creates, not one round trip earlier.
# Query through $vm, not by name again, and let a failed query FAIL. With
# SilentlyContinue a permission, provider or storage error came back as an
# empty list and was read as "no duplicate", after which this mutated anyway.
$existing = @(Get-VMSnapshot -VM $vm -Name ${
      psQuote(args.name)
    } -ErrorAction Stop)
if ($existing.Count -ne 0) {
  throw "a checkpoint with that name already exists on this VM"
}
Checkpoint-VM -VM $vm -SnapshotName ${psQuote(args.name)}`,
    ctx.signal,
  );

  // Read back, and look for THIS checkpoint. The old check was
  // `handles.length > 0`, which any pre-existing checkpoint satisfied -- so a
  // creation that silently did nothing reported success on the strength of
  // someone else's restore point.
  const after = await listCheckpoints(g, args.vmName, ctx.signal);
  if (matchCheckpoints(after, args.name).length !== 1) {
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

  // Restore is the least reversible verb here, so it gets the same
  // one-target requirement the other checkpoint methods have. Under
  // PowerShell's case-insensitive matching, "Nightly" and "nightly" are both
  // candidates; rolling back to whichever the host happened to pick would
  // discard a different span of work than the caller acknowledged.
  const candidates = matchCheckpoints(
    await listCheckpoints(g, args.vmName, ctx.signal),
    args.name,
  );
  if (candidates.length === 0) {
    throw new Error(`${args.vmName} has no checkpoint named ${args.name}`);
  }
  if (candidates.length > 1) {
    throw new Error(
      `${args.vmName} has ${candidates.length} checkpoints matching ` +
        `${args.name} case-insensitively; refusing to guess which span of ` +
        `work to discard`,
    );
  }
  await runPowerShell(
    g,
    `${resolveOneVm(args.vmName)}
# Uniqueness is settled HERE, in the call that mutates. Deciding it in an
# earlier round trip left a window in which a second case-variant checkpoint
# could appear, and Restore-VMSnapshot would then roll back to whichever it
# matched -- discarding a different span of work than was acknowledged.
$snaps = @(Get-VMSnapshot -VM $vm -Name ${psQuote(args.name)})
if ($snaps.Count -ne 1) {
  throw "expected exactly one checkpoint matching the given name, found $($snaps.Count)"
}
Restore-VMSnapshot -VMSnapshot $snaps[0] -Confirm:$false`,
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
  // Match the way the host will. Refusing an ambiguous target matters more
  // here than anywhere else: Remove-VMSnapshot would act on whichever one it
  // picked, and the caller confirmed a name, not a choice.
  const before = await listCheckpoints(g, args.vmName, ctx.signal);
  const targets = matchCheckpoints(before, args.name);
  if (targets.length === 0) {
    throw new Error(`${args.vmName} has no checkpoint named ${args.name}`);
  }
  if (targets.length > 1) {
    throw new Error(
      `${args.vmName} has ${targets.length} checkpoints matching ${args.name} ` +
        `case-insensitively; PowerShell would pick one and this will not ` +
        `choose for you`,
    );
  }

  await runPowerShell(
    g,
    `${resolveOneVm(args.vmName)}
# Same reason as restore: the check and the deletion have to be one operation.
$snaps = @(Get-VMSnapshot -VM $vm -Name ${psQuote(args.name)})
if ($snaps.Count -ne 1) {
  throw "expected exactly one checkpoint matching the given name, found $($snaps.Count)"
}
Remove-VMSnapshot -VMSnapshot $snaps[0]`,
    ctx.signal,
  );

  // And confirm it actually went. Now that the query fails loudly instead of
  // returning empty, an absence here means absence rather than a broken read.
  const after = await listCheckpoints(g, args.vmName, ctx.signal);
  if (matchCheckpoints(after, args.name).length > 0) {
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

  // A courtesy pre-check: it fails fast with a clear message before anything
  // is touched. It is NOT the guard -- a VM can start between this call and
  // the delete script, so the binding refusal lives inside that script, on
  // the host, using the state it sees at the moment it acts.
  if (before !== "Off" && !args.confirmForcePowerOff) {
    throw new Error(
      `${args.vmName} is ${
        safeState(before)
      }. Deleting it cuts power with no graceful ` +
        `shutdown, risking the guest filesystem. Stop it first, or pass ` +
        `confirmForcePowerOff to accept that.`,
    );
  }

  // Disk removal reports per file. It used to run with -ErrorAction
  // SilentlyContinue while the method logged "disks removed" and threw the
  // result object away, so a disk that could not be deleted -- locked, in use,
  // on a disconnected volume -- was indistinguishable from one that was.
  const ps = `${resolveOneVm(args.vmName)}
$name = $vm.Name
$allowForce = ${args.confirmForcePowerOff ? "$true" : "$false"}
$disks = @(Get-VMHardDiskDrive -VM $vm | Select-Object -ExpandProperty Path)
# A VHDX can be attached to more than one VM -- shared disks, differencing
# chains, or simply the same file added twice. Deleting this VM's disks would
# then destroy storage another machine is still using, and Remove-Item has no
# idea it is doing that. Collect every path attached to any OTHER VM and treat
# those as untouchable.
function Get-OtherDiskSet {
  # Normalise before comparing. Two spellings of one file -- a relative
  # segment, a trailing slash, different case on a case-insensitive volume --
  # are the same storage, and a plain string compare calls them different and
  # deletes one of them.
  $set = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  # Attached paths are not the whole story. A differencing disk names a
  # PARENT, and that parent is storage another VM depends on just as directly
  # -- deleting it destroys the child. Walk each chain to its root, with a
  # depth bound so a corrupt or circular chain cannot spin here forever.
  foreach ($p in @(Get-VM | Where-Object { $_.Name -ne $name } |
      Get-VMHardDiskDrive | Select-Object -ExpandProperty Path)) {
    $cur = $p
    $depth = 0
    while ($cur) {
      try { [void]$set.Add([System.IO.Path]::GetFullPath($cur)) } catch { [void]$set.Add($cur) }
      if ($depth -ge 32) {
        # A chain this long is either corrupt or something nobody intended.
        # Refusing is the only safe answer: continuing would mean deleting
        # from a set we know is incomplete.
        throw "differencing chain deeper than 32 links; refusing to judge disk ownership"
      }
      $next = $null
      try { $next = (Get-VHD -Path $cur -ErrorAction Stop).ParentPath }
      catch {
        # Fail CLOSED. A chain we cannot read is a chain we cannot clear, and
        # treating an unreadable parent as "no parent" is how a base disk
        # another VM depends on gets deleted.
        throw "cannot inspect a disk chain; refusing to judge disk ownership"
      }
      if (-not $next -or $next -eq $cur) { break }
      $cur = $next
      $depth++
    }
  }
  # The unary comma is load-bearing. A bare return lets PowerShell ENUMERATE
  # the HashSet on the way out, so the caller receives null, a bare string, or
  # an array depending on how many items it held -- and Contains() on an
  # array is case-SENSITIVE, which silently undoes the normalisation this
  # function exists for. Wrapping in a single-element array suppresses that.
  return ,$set
}
function Normalise-Path([string]$p) {
  try { return [System.IO.Path]::GetFullPath($p) } catch { return $p }
}
$othersDisks = Get-OtherDiskSet
$shared = @($disks | Where-Object { $othersDisks.Contains((Normalise-Path $_)) })
$state = $vm.State.ToString()
# The acknowledgement is enforced HERE, not only before the call. Checking
# state in one SSH round trip and powering off in a later one leaves a window
# where a VM starts in between -- and the old script then cut its power
# regardless of what the caller had agreed to. The host makes this decision
# with the state it has at that instant.
if ($state -ne 'Off') {
  if (-not $allowForce) {
    throw "refusing to delete a VM that is $state without confirmForcePowerOff"
  }
  Stop-VM -VM $vm -TurnOff -Force
}
# Order matters: once Remove-VM has run, the attachment information this
# check depends on no longer exists, so a shared disk would be undetectable
# at exactly the moment it is about to be deleted.
${
    args.deleteDisks
      ? `if ($shared.Count -gt 0) {
  throw "refusing to delete: $($shared.Count) of $($disks.Count) disk(s) are attached to another VM"
}`
      : ""
  }
Remove-VM -VM $vm -Force
$results = @()
${
    args.deleteDisks
      ? `# Re-check ownership immediately before each delete, not once up front. The
# earlier snapshot cannot be atomic -- another VM can attach a disk in the
# window -- so the window is made as small as this transport allows rather
# than pretended away. A disk that became shared since the snapshot is
# refused here and reported, not removed.
for ($i = 0; $i -lt $disks.Count; $i++) {
  $d = $disks[$i]
  $ok = $false
  # Per iteration, not once before the loop. A single snapshot ahead of the
  # loop is the same non-atomic check this was supposed to replace, just
  # slightly later -- and the window grows with every disk deleted.
  $current = Get-OtherDiskSet
  if ($current.Contains((Normalise-Path $d))) {
    $ok = $false
  } else {
    try { Remove-Item -LiteralPath $d -Force -ErrorAction Stop; $ok = $true } catch { $ok = $false }
    # Verify absence rather than trusting the call.
    if (Test-Path -LiteralPath $d) { $ok = $false }
  }
  $results += [pscustomobject]@{ index = $i; removed = $ok }
}`
      : ""
  }
[pscustomobject]@{ diskCount = $disks.Count; results = @($results) } | ConvertTo-Json -Depth 4 -Compress`
    .trim();
  const envelope = parseRow(
    DiskDeleteEnvelope,
    oneEnvelope(await runPowerShell(g, ps, ctx.signal), "disk deletion"),
    "disk deletion envelope",
  );

  // Read back rather than trust the cmdlet.
  const after = await vmState(g, args.vmName, ctx.signal);
  if (after !== null) {
    throw new Error(
      `delete did not take: ${args.vmName} still present (${safeState(after)})`,
    );
  }

  if (args.deleteDisks) {
    const results = envelope.results;
    // Reconcile before judging. Fewer results than disks means the loop did
    // not finish, and an all-`removed` list of the wrong length is not proof.
    // Count alone is not coverage: three results for three disks can still be
    // indices 0, 0, 1, leaving disk 2 unaccounted for while the totals agree.
    // Require exactly one result per index over 0..diskCount-1.
    const seen = new Set(results.map((r) => r.index));
    const covered = seen.size === envelope.diskCount &&
      results.length === envelope.diskCount &&
      [...Array(envelope.diskCount).keys()].every((i) => seen.has(i));
    if (!covered) {
      throw new Error(
        `${args.vmName} was deleted, but disk removal is unaccounted for: ` +
          `the host reported ${envelope.diskCount} disk(s) and returned ` +
          `${results.length} result(s) covering ${seen.size} distinct ` +
          `position(s)`,
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
 * Messages like `no VM named <your-vm-name>` name infrastructure, and this model is
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
