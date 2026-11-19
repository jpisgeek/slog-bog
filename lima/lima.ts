/**
 * Dedicated Linux VMs on macOS, driven through Lima.
 *
 * One model instance owns one Lima instance in one explicitly chosen Lima
 * home. The model renders the complete VM configuration itself, from pinned
 * inputs, rather than inheriting Lima's default template: no host home mount,
 * no SSH agent or X11 forwarding, no host public keys copied in, no proxy
 * environment propagated, and every guest port ignored unless it is listed.
 *
 * The rules the whole model is built around:
 *
 * - Ownership is a marker this model wrote, bound to its own identity and the
 *   instance directory it created. A Lima instance that merely shares the
 *   name is unmanaged, and nothing here will start, stop, reconfigure, or
 *   delete it.
 * - Drift is reported, never repaired. A plan whose hash differs from the one
 *   the instance was created with says `replacement-required` and stops.
 * - Nothing is deleted on a failure path. A create that dies half-way leaves
 *   what it made, with diagnostics, for a person to look at.
 * - `destroy` is its own door, with its own arguments, and it refuses a
 *   running instance, a wrong name, and a missing preservation decision.
 *
 * Process execution is argv only, with a scrubbed environment: LIMA_HOME, a
 * fixed PATH, and HOME. Output is capped, control characters are escaped
 * before anything reaches a resource or a log line, and no environment,
 * private key, or full argument vector is ever persisted.
 */
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Input rules
// ---------------------------------------------------------------------------

/** Absolute path made only of characters that cannot alter an argv element. */
const SAFE_ABS_PATH = /^\/[A-Za-z0-9._@/-]*$/;
/** A bare command name or a safe absolute path. */
const SAFE_BIN_PATH = /^[A-Za-z0-9._/-]+$/;
/** `limactl` exactly, wherever it lives. Nothing else runs under this model. */
const LIMACTL_BASENAME = /(?:^|\/)limactl$/;
/** Lima's own rule for instance names is looser; this one is deliberately tight. */
const INSTANCE_NAME = /^[a-z][a-z0-9-]{0,31}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SIZE = /^[1-9][0-9]{0,3}GiB$/;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const LOOPBACK = /^127\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}$/;

/** Output cap per stream. Lima's largest legitimate answer is kilobytes. */
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_DETAIL_CHARS = 200;
const MAX_ERROR_ENTRIES = 8;

/**
 * Host roots a mount may never sit at or under. The list is about what the
 * guest must not be handed, not about what the operator is allowed to type:
 * the home directory (keychains, ssh keys, the controller vault), the
 * system tree, external and network volumes, and the temp trees where other
 * processes leave sockets.
 */
export function deniedMountRoots(home: string | undefined): string[] {
  const roots = [
    "/",
    "/Volumes",
    "/private",
    "/System",
    "/Library",
    "/etc",
    "/var",
    "/dev",
    "/tmp",
  ];
  if (home && SAFE_ABS_PATH.test(home) && home !== "/") roots.push(home);
  return roots;
}

/** True when a mount location sits at or under a denied host root, or names a credential directory. */
export function mountIsDenied(
  location: string,
  home: string | undefined,
): boolean {
  for (const root of deniedMountRoots(home)) {
    if (root === "/") {
      if (location === "/") return true;
      continue;
    }
    if (
      location === root || location.startsWith(root + "/") ||
      root.startsWith(location + "/")
    ) return true;
  }
  return /\/\.(ssh|swamp|gnupg|aws|config)(\/|$)/.test(location);
}

function canonicalPath(p: string): boolean {
  return SAFE_ABS_PATH.test(p) && p !== "/" &&
    p.split("/").slice(1).every((part) =>
      part !== "" && part !== "." && part !== ".."
    );
}

const ImageSchema = z.object({
  location: z.string().url().refine((u) => {
    const parsed = new URL(u);
    // Query/fragment tokens and userinfo must never reach persistent config.
    return parsed.protocol === "https:" && !parsed.username &&
      !parsed.password &&
      !parsed.search && !parsed.hash && !u.includes("?") && !u.includes("#");
  }, {
    message: "image must be credential-free HTTPS without query or fragment",
  }),
  arch: z.enum(["aarch64", "x86_64"]),
  digest: z.string().regex(DIGEST, "digest must be sha256:<64 hex>"),
}).strict();

const MountSchema = z.object({
  location: z.string().regex(
    SAFE_ABS_PATH,
    "mount location must be a safe absolute path",
  )
    .refine(
      (p) => canonicalPath(p),
      {
        message: "mount location must be normalized",
      },
    )
    .refine((p) => !mountIsDenied(p, Deno.env.get("HOME")), {
      message:
        "mount location is under a denied host root (home, system, volumes, temp)",
    }),
  writable: z.boolean().default(false),
}).strict();

const PortForwardSchema = z.object({
  guestPort: z.number().int().min(1).max(65535),
  hostPort: z.number().int().min(1024).max(65535),
  hostIP: z.string().regex(LOOPBACK, "hostIP must be a loopback address")
    .default("127.0.0.1"),
}).strict();

const ProvisionSchema = z.object({
  mode: z.enum(["system", "user", "boot"]),
  file: z.string().regex(
    SAFE_ABS_PATH,
    "provision file must be a safe absolute path",
  ),
  sha256: z.string().regex(HEX64, "sha256 must be 64 hex characters"),
}).strict();

/** Operator inputs for one instance: identity, home, approved limactl, pinned image, sizes, and explicit mounts, forwards, and provisioning. */
const GlobalArgsObjectSchema = z.object({
  name: z.string().regex(
    INSTANCE_NAME,
    "name: lowercase letter first, then [a-z0-9-], max 32",
  )
    .describe("Lima instance name; also the ownership key"),
  limaHome: z.string().regex(
    SAFE_ABS_PATH,
    "limaHome must be a safe absolute path",
  )
    .refine((p) => canonicalPath(p), {
      message: "limaHome must be a normalized directory",
    })
    .describe(
      "Dedicated LIMA_HOME for this instance; never the default ~/.lima",
    ),
  limactlPath: z.string().regex(SAFE_BIN_PATH).regex(
    LIMACTL_BASENAME,
    "limactlPath must name limactl",
  )
    .default("limactl"),
  limaVersion: z.string().regex(VERSION).describe(
    "Exact approved limactl version, e.g. 2.2.0",
  ),
  arch: z.enum(["aarch64", "x86_64"]).default("aarch64"),
  vmType: z.literal("vz").default("vz").describe(
    "v1 supports the Virtualization.framework backend only",
  ),
  image: ImageSchema.describe("Pinned guest image; the digest is mandatory"),
  cpus: z.number().int().min(1).max(64),
  memory: z.string().regex(SIZE, "memory like 8GiB"),
  disk: z.string().regex(SIZE, "disk like 40GiB"),
  mounts: z.array(MountSchema).max(8).default([]),
  portForwards: z.array(PortForwardSchema).max(16).default([]),
  provision: z.array(ProvisionSchema).max(8).default([])
    .describe(
      "Reviewed credential-free provisioning scripts; full bodies persist in config artifacts",
    ),
  sshLocalPort: z.number().int().refine(
    (n) => n === 0 || (n >= 1024 && n <= 65535),
    {
      message: "sshLocalPort is 0 (random) or 1024-65535",
    },
  ).default(0),
  startTimeoutSec: z.number().int().min(30).max(3600).default(600),
  commandTimeoutSec: z.number().int().min(5).max(600).default(120),
  lockStaleSec: z.number().int().min(60).max(86400).default(1800).describe(
    "Deprecated compatibility input; lock age never permits takeover. OS locks release on process exit.",
  ),
}).strict();

/** Full validation stays at every method/check boundary; Swamp needs a partial-able structural schema. */
export const GlobalArgsSchema = GlobalArgsObjectSchema
  .refine((g) => {
    const home = Deno.env.get("HOME");
    return !home || (g.limaHome !== home && g.limaHome !== `${home}/.lima` &&
      !g.limaHome.startsWith(`${home}/.lima/`));
  }, {
    message: "limaHome must be dedicated, not HOME or the default Lima home",
  })
  .refine((g) => g.image.arch === g.arch, {
    message: "image.arch must equal arch",
  })
  .refine(
    (g) =>
      new Set(g.portForwards.map((p) => p.hostPort)).size ===
        g.portForwards.length,
    {
      message: "hostPort values must be unique",
    },
  )
  .refine(
    (g) => new Set(g.mounts.map((m) => m.location)).size === g.mounts.length,
    {
      message: "mount locations must be unique",
    },
  );

/** Parsed and defaulted global arguments. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Text hygiene
// ---------------------------------------------------------------------------

/**
 * Escape control, format, and separator characters so process output can be
 * stored and logged without a terminal or a reader acting on it.
 */
export function safeText(value: string, max = MAX_DETAIL_CHARS): string {
  const escaped = value.replace(
    /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu,
    (c) => "\\u" + c.codePointAt(0)!.toString(16).padStart(4, "0"),
  );
  return escaped.length > max ? escaped.slice(0, max) + "…" : escaped;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/** A rendered Lima configuration document, as plain JSON. */
export type Rendered = Record<string, unknown>;

/**
 * Canonical JSON: keys sorted at every level, no whitespace. Two renders of
 * the same inputs hash the same; a change anywhere hashes differently.
 */
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    return "{" + Object.keys(o).sort().map((k) =>
      JSON.stringify(k) + ":" + canonical(o[k])
    ).join(",") + "}";
  }
  return JSON.stringify(value);
}

/** Hex SHA-256 of a UTF-8 string; the config hash is this over the canonical render. */
export async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest)).map((b) =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

/**
 * The complete Lima configuration. Everything Lima would otherwise inherit
 * from its default template is stated here, so the rendered document is the
 * whole truth of what the guest gets.
 */
export function renderTemplate(g: GlobalArgs, scripts: string[]): Rendered {
  if (scripts.length !== g.provision.length) {
    throw new Error("one script body per provision entry");
  }
  const explicit = g.portForwards.map((p) => ({
    guestIP: "127.0.0.1",
    guestPort: p.guestPort,
    hostIP: p.hostIP,
    hostPort: p.hostPort,
    proto: "tcp",
  }));
  const rendered: Rendered = {
    minimumLimaVersion: "2.0.0",
    vmType: g.vmType,
    os: "Linux",
    arch: g.arch,
    images: [{
      location: g.image.location,
      arch: g.image.arch,
      digest: g.image.digest,
    }],
    cpus: g.cpus,
    memory: g.memory,
    disk: g.disk,
    mounts: g.mounts.map((m) => ({
      location: m.location,
      writable: m.writable,
    })),
    mountInotify: false,
    containerd: { system: false, user: false },
    ssh: {
      localPort: g.sshLocalPort,
      loadDotSSHPubKeys: false,
      forwardAgent: false,
      forwardX11: false,
      forwardX11Trusted: false,
    },
    // Explicit forwards first; the final rule swallows every other guest port.
    portForwards: [...explicit, { guestPortRange: [1, 65535], ignore: true }],
    hostResolver: { enabled: true, ipv6: false },
    propagateProxyEnv: false,
    upgradePackages: false,
    plain: false,
    nestedVirtualization: false,
    rosetta: { enabled: false, binfmt: false },
    provision: g.provision.map((p, i) => ({
      mode: p.mode,
      script: scripts[i],
    })),
  };
  if (g.mounts.length > 0) rendered.mountType = "virtiofs";
  return rendered;
}

/** Read each provisioning script and refuse any whose content hash moved. */
export async function loadProvisionScripts(g: GlobalArgs): Promise<string[]> {
  const out: string[] = [];
  for (const p of g.provision) {
    let text: string;
    try {
      text = await Deno.readTextFile(p.file);
    } catch {
      throw new Error(`provision script is unreadable: ${p.file}`);
    }
    const actual = await sha256Hex(text);
    if (actual !== p.sha256) {
      throw new Error(
        `provision script hash mismatch for ${p.file}: reviewed ${
          p.sha256.slice(0, 12)
        }…, found ${actual.slice(0, 12)}…`,
      );
    }
    out.push(text);
  }
  return out;
}

/** Top-level keys whose canonical form differs between two renders. */
export function diffKeys(a: Rendered, b: Rendered): string[] {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].filter((k) => canonical(a[k]) !== canonical(b[k])).sort();
}

// ---------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------

/** Outcome of one limactl invocation: stdout on success, a bounded classification otherwise. */
export type RunResult =
  | { ok: true; stdout: string; stderr: string }
  | {
    ok: false;
    kind: "notfound" | "timed-out" | "failed";
    code: number;
    detail: string;
  };

async function readCapped(
  stream: ReadableStream<Uint8Array>,
  cap: number,
  onOverflow: () => void,
  signal: AbortSignal,
) {
  const reader = stream.getReader();
  // A descendant can inherit a pipe even after limactl exits. Do not let that
  // pipe keep a cancelled call (and its mutation lock) alive indefinitely.
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancel, { once: true });
  if (signal.aborted) cancel();
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
        onOverflow();
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    signal.removeEventListener("abort", cancel);
    await reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
  let at = 0;
  for (const c of chunks) {
    buf.set(c, at);
    at += c.byteLength;
  }
  const text = new TextDecoder().decode(buf);
  return truncated ? text + "\n[truncated]" : text;
}

/** The only environment the child ever sees. */
export function childEnv(g: GlobalArgs): Record<string, string> {
  return {
    LIMA_HOME: g.limaHome,
    HOME: Deno.env.get("HOME") ?? "/",
    PATH: "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
    LANG: "C.UTF-8",
  };
}

/** The argv every invocation gets: TUI off, then the subcommand. */
export function limactlArgs(sub: string[]): string[] {
  return ["--tty=false", ...sub];
}

/** Run one limactl subcommand with argv only, a scrubbed environment, capped output, and a deadline. */
export async function runLimactl(
  g: GlobalArgs,
  sub: string[],
  signal: AbortSignal,
  timeoutSec = g.commandTimeoutSec,
): Promise<RunResult> {
  signal.throwIfAborted();
  const deadline = new AbortController();
  const termination = AbortSignal.any([signal, deadline.signal]);
  const timer = setTimeout(
    () => deadline.abort(new Error("deadline")),
    timeoutSec * 1000,
  );
  const cmd = new Deno.Command(g.limactlPath, {
    args: limactlArgs(sub),
    env: childEnv(g),
    clearEnv: true,
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  });
  try {
    const child = cmd.spawn();
    let escalation: ReturnType<typeof setTimeout> | undefined;
    let killed = false;
    const kill = () => {
      if (killed) return;
      killed = true;
      try {
        child.kill("SIGKILL");
      } catch { /* already gone */ }
    };
    const terminate = () => {
      try {
        child.kill("SIGTERM");
      } catch { /* already gone; inherited pipes still need cancelling */ }
      // Give the owned process a short cleanup window, then enforce the stop.
      // Await its status below before letting a mutation release its lock.
      escalation = setTimeout(kill, 250);
    };
    termination.addEventListener("abort", terminate, { once: true });
    if (termination.aborted) terminate();
    try {
      const [stdout, stderr, status] = await Promise.all([
        readCapped(child.stdout, MAX_OUTPUT_BYTES, kill, termination),
        readCapped(child.stderr, MAX_OUTPUT_BYTES, kill, termination),
        child.status,
      ]);
      signal.throwIfAborted();
      if (deadline.signal.aborted) {
        return {
          ok: false,
          kind: "timed-out",
          code: -1,
          detail: `no answer within ${timeoutSec}s`,
        };
      }
      if (!status.success) {
        return {
          ok: false,
          kind: "failed",
          code: status.code,
          detail: safeText(stderr.trim() || stdout.trim()),
        };
      }
      return { ok: true, stdout, stderr };
    } finally {
      clearTimeout(escalation);
      termination.removeEventListener("abort", terminate);
    }
  } catch (e) {
    signal.throwIfAborted();
    if (deadline.signal.aborted) {
      return {
        ok: false,
        kind: "timed-out",
        code: -1,
        detail: `no answer within ${timeoutSec}s`,
      };
    }
    if (e instanceof Deno.errors.NotFound) {
      return {
        ok: false,
        kind: "notfound",
        code: 127,
        detail: "limactl not found",
      };
    }
    return {
      ok: false,
      kind: "failed",
      code: -1,
      detail: safeText((e as Error).message),
    };
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Lima output parsing
// ---------------------------------------------------------------------------

/** Validate consumed host facts and discard unrelated Lima metadata; VM security config stays strict. */
export const LimaInfoSchema = z.object({
  version: z.string(),
  limaHome: z.string(),
  vmTypes: z.array(z.string()),
});

const ObservedForwardSchema = z.object({
  guestIP: z.string().optional(),
  guestPort: z.number().int().optional(),
  hostIP: z.string().optional(),
  hostPort: z.number().int().optional(),
  proto: z.string().optional(),
  ignore: z.boolean().optional(),
  guestPortRange: z.tuple([z.number().int(), z.number().int()]).optional(),
}).strict();
const ObservedConfigSchema = z.object({
  minimumLimaVersion: z.string().optional(),
  vmType: z.string().optional(),
  os: z.string().optional(),
  arch: z.string().optional(),
  cpus: z.number().optional(),
  memory: z.string().optional(),
  disk: z.string().optional(),
  images: z.array(ImageSchema).optional(),
  mounts: z.array(
    z.object({ location: z.string(), writable: z.boolean() }).strict(),
  ).optional(),
  mountType: z.string().optional(),
  mountInotify: z.boolean().optional(),
  containerd: z.object({ system: z.boolean(), user: z.boolean() }).strict()
    .optional(),
  ssh: z.object({
    localPort: z.number().int(),
    loadDotSSHPubKeys: z.boolean(),
    forwardAgent: z.boolean(),
    forwardX11: z.boolean(),
    forwardX11Trusted: z.boolean(),
  }).strict().optional(),
  portForwards: z.array(ObservedForwardSchema).optional(),
  hostResolver: z.object({ enabled: z.boolean(), ipv6: z.boolean() }).strict()
    .optional(),
  propagateProxyEnv: z.boolean().optional(),
  upgradePackages: z.boolean().optional(),
  plain: z.boolean().optional(),
  nestedVirtualization: z.boolean().optional(),
  rosetta: z.object({ enabled: z.boolean(), binfmt: z.boolean() }).strict()
    .optional(),
  provision: z.array(
    z.object({ mode: z.enum(["system", "user", "boot"]), script: z.string() })
      .strict(),
  ).optional(),
}).strict();

/** One strictly validated entry of limactl list. */
export const LimaInstanceSchema = z.object({
  name: z.string(),
  status: z.string(),
  dir: z.string(),
  vmType: z.string().optional(),
  arch: z.string().optional(),
  cpus: z.number().nonnegative().optional(),
  memory: z.number().nonnegative().optional(),
  disk: z.number().nonnegative().optional(),
  sshLocalPort: z.number().int().optional(),
  limaVersion: z.string().optional(),
  errors: z.array(z.string()).optional(),
  config: ObservedConfigSchema.optional(),
}).strict();

/** A parsed `limactl list` entry. */
export type LimaInstance = z.infer<typeof LimaInstanceSchema>;

/**
 * `limactl list --json` has printed one object per line and, in other
 * versions, one array. Both are accepted; anything else is malformed, and a
 * malformed answer is never treated as an empty home.
 */
export function parseList(stdout: string): LimaInstance[] | null {
  const text = stdout.trim();
  if (text === "") return [];
  let raw: unknown[];
  try {
    const whole = JSON.parse(text);
    raw = Array.isArray(whole) ? whole : [whole];
  } catch {
    try {
      raw = text.split("\n").filter((l) => l.trim() !== "").map((l) =>
        JSON.parse(l)
      );
    } catch {
      return null;
    }
  }
  const out: LimaInstance[] = [];
  for (const r of raw) {
    const parsed = LimaInstanceSchema.safeParse(r);
    if (!parsed.success) return null;
    out.push(parsed.data);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Ownership and locking
// ---------------------------------------------------------------------------

/** Normalize current runtime identities and legacy markers; unknown shapes fail closed. */
const ModelTypeSchema = z.union([
  z.string().min(1),
  z.object({ raw: z.string().optional(), normalized: z.string().min(1) })
    .strict().transform((type) => type.normalized),
]);

/** The ownership record written at create and required to match before any mutation. */
export const MarkerSchema = z.object({
  modelType: ModelTypeSchema,
  modelId: z.string(),
  definitionId: z.string(),
  name: z.string(),
  limaHome: z.string(),
  instanceDir: z.string(),
  configHash: z.string().regex(HEX64),
  imageDigest: z.string(),
  createdAt: z.string(),
}).strict();
/** A parsed ownership marker. */
export type Marker = z.infer<typeof MarkerSchema>;

/** Directory inside the Lima home that holds markers and locks. */
export function ownedDir(g: GlobalArgs): string {
  return `${g.limaHome}/.swamp-owned`;
}
/** Path of this instance's ownership marker. */
export function markerPath(g: GlobalArgs): string {
  return `${ownedDir(g)}/${g.name}.json`;
}
/** Path of this instance's lock file. */
export function lockPath(g: GlobalArgs): string {
  return `${ownedDir(g)}/${g.name}.lock`;
}

/** Read the marker: absent, valid, or malformed, each reported distinctly. */
export async function readMarker(
  g: GlobalArgs,
): Promise<Marker | null | "malformed"> {
  let text: string;
  try {
    text = await Deno.readTextFile(markerPath(g));
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) return null;
    return "malformed";
  }
  try {
    const parsed = MarkerSchema.safeParse(JSON.parse(text));
    return parsed.success ? parsed.data : "malformed";
  } catch {
    return "malformed";
  }
}

type Identity = { modelType: string; modelId: string; definitionId: string };

/**
 * Owned means: marker present, written by this model instance, for this
 * home and name, and pointing at the directory Lima reports. Any one of
 * those failing makes the instance unmanaged, not "probably ours".
 */
export function ownership(
  marker: Marker | null | "malformed",
  inst: LimaInstance | null,
  g: GlobalArgs,
  id: Identity,
): "missing" | "unmanaged" | "owned" | "orphan-marker" {
  if (!inst) {
    return marker && marker !== "malformed" ? "orphan-marker" : "missing";
  }
  if (!marker || marker === "malformed") return "unmanaged";
  const ok = marker.modelType === id.modelType &&
    marker.modelId === id.modelId && marker.definitionId === id.definitionId &&
    marker.name === g.name &&
    marker.limaHome === g.limaHome && marker.instanceDir === inst.dir;
  return ok ? "owned" : "unmanaged";
}

/**
 * Persistent lock inode with a nonblocking OS advisory lock. Closing the handle
 * (including process exit) releases exclusion; elapsed time never steals it.
 * Legacy create-only lock files are refused, not automatically deleted.
 */
export async function acquireLock(
  g: GlobalArgs,
  method: string,
  _log: Logger,
): Promise<() => Promise<void>> {
  await Deno.mkdir(ownedDir(g), { recursive: true, mode: 0o700 });
  const path = lockPath(g);
  let file: Deno.FsFile;
  try {
    file = await Deno.open(path, {
      read: true,
      write: true,
      createNew: true,
      mode: 0o600,
    });
  } catch (e) {
    if (!(e instanceof Deno.errors.AlreadyExists)) throw e;
    let protocol: unknown;
    try {
      protocol = JSON.parse(await Deno.readTextFile(path)).protocol;
    } catch {
      /* Missing or partially written metadata is never proof of a free lock. */
    }
    if (protocol !== "os-lock-v1") {
      throw new Error("legacy or unreadable lock; inspect before retrying");
    }
    file = await Deno.open(path, { read: true, write: true });
  }
  try {
    if (!await file.tryLock(true)) {
      throw new Error(
        `another run holds the lock for ${g.name}; inspect before retrying`,
      );
    }
    const body = new TextEncoder().encode(
      JSON.stringify({
        protocol: "os-lock-v1",
        method,
        pid: Deno.pid,
        at: new Date().toISOString(),
      }),
    );
    await file.truncate(0);
    let written = 0;
    while (written < body.length) {
      written += await file.write(body.subarray(written));
    }
    return () => {
      file.close();
      return Promise.resolve();
    };
  } catch (e) {
    file.close();
    throw e;
  }
}

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

type Logger = {
  info: (msg: string, props?: Record<string, unknown>) => void;
  warning: (msg: string, props?: Record<string, unknown>) => void;
};

/** Host observation: limactl state, versions, backend support, and unmet prerequisites. */
export const HostSchema = z.object({
  observedAt: z.string(),
  limactl: z.enum([
    "ok",
    "missing",
    "unsupported-version",
    "malformed",
    "failed",
  ]),
  limaVersion: z.string().nullable(),
  expectedLimaVersion: z.string(),
  vmTypeSupported: z.boolean().nullable(),
  limaHome: z.string(),
  hostOs: z.string(),
  hostArch: z.string(),
  instancesInHome: z.number().nullable(),
  prerequisites: z.array(z.string()),
});

/** Instance observation: ownership state, Lima status, sizes, and the hash it was created from. */
export const InstanceSchema = z.object({
  observedAt: z.string(),
  name: z.string(),
  limaHome: z.string(),
  state: z.enum(["missing", "unmanaged", "owned", "orphan-marker", "unknown"]),
  status: z.string().nullable(),
  dir: z.string().nullable(),
  vmType: z.string().nullable(),
  arch: z.string().nullable(),
  cpus: z.number().nullable(),
  memoryBytes: z.number().nullable(),
  diskBytes: z.number().nullable(),
  sshLocalPort: z.number().nullable(),
  limaVersion: z.string().nullable(),
  errors: z.array(z.string()),
  createdConfigHash: z.string().nullable(),
  lastAction: z.enum([
    "inspect",
    "plan",
    "create",
    "start",
    "verify",
    "stop",
    "destroy",
  ]),
  changed: z.boolean(),
});

/** Plan record: the config hash, the action it implies, drifted keys, and blockers. */
export const PlanSchema = z.object({
  renderedAt: z.string(),
  action: z.enum([
    "create",
    "noop",
    "replacement-required",
    "blocked-unmanaged",
    "blocked-prerequisites",
  ]),
  configHash: z.string(),
  imageDigest: z.string(),
  limaVersion: z.string(),
  observedState: z.string(),
  observedStatus: z.string().nullable(),
  validated: z.boolean(),
  diff: z.array(z.string()),
  prerequisites: z.array(z.string()),
});

/** Verification record: one named pass/fail per check against the running guest. */
export const VerificationSchema = z.object({
  observedAt: z.string(),
  pass: z.boolean(),
  checks: z.array(
    z.object({ name: z.string(), pass: z.boolean(), detail: z.string() }),
  ),
});

/** A host observation. */
export type HostState = z.infer<typeof HostSchema>;
/** An instance observation. */
export type InstanceState = z.infer<typeof InstanceSchema>;

/** Everything one observation pass learned, including the raw list entry and marker. */
export type Observation = {
  host: HostState;
  instance: InstanceState;
  raw: LimaInstance | null;
  marker: Marker | null | "malformed";
};

function hostArch(): string {
  return Deno.build.arch === "aarch64" ? "aarch64" : Deno.build.arch;
}

/** Observe host and instance without changing anything; failures become facts on the host record. */
export async function observe(
  g: GlobalArgs,
  id: Identity,
  signal: AbortSignal,
  lastAction: InstanceState["lastAction"],
): Promise<Observation> {
  const observedAt = new Date().toISOString();
  const prerequisites: string[] = [];
  const host: HostState = {
    observedAt,
    limactl: "ok",
    limaVersion: null,
    expectedLimaVersion: g.limaVersion,
    vmTypeSupported: null,
    limaHome: g.limaHome,
    hostOs: Deno.build.os,
    hostArch: hostArch(),
    instancesInHome: null,
    prerequisites,
  };
  const marker = await readMarker(g);
  const blank = (state: InstanceState["state"]): InstanceState => ({
    observedAt,
    name: g.name,
    limaHome: g.limaHome,
    state,
    status: null,
    dir: null,
    vmType: null,
    arch: null,
    cpus: null,
    memoryBytes: null,
    diskBytes: null,
    sshLocalPort: null,
    limaVersion: null,
    errors: [],
    createdConfigHash: marker && marker !== "malformed"
      ? marker.configHash
      : null,
    lastAction,
    changed: false,
  });
  if (Deno.build.os !== "darwin") {
    prerequisites.push(`host os is ${Deno.build.os}; Lima vz needs macOS`);
  }
  if (host.hostArch !== g.arch) {
    prerequisites.push(
      `host arch ${host.hostArch} does not match requested ${g.arch}`,
    );
  }
  if (marker === "malformed") {
    prerequisites.push("ownership marker is unreadable; inspect it by hand");
  }

  const info = await runLimactl(g, ["info"], signal);
  if (!info.ok) {
    host.limactl = info.kind === "notfound" ? "missing" : "failed";
    prerequisites.push(
      info.kind === "notfound"
        ? `limactl ${g.limaVersion} is not installed at ${g.limactlPath}`
        : `limactl info failed: ${info.detail}`,
    );
    return { host, instance: blank("unknown"), raw: null, marker };
  }
  let parsedInfo: z.infer<typeof LimaInfoSchema>;
  try {
    parsedInfo = LimaInfoSchema.parse(JSON.parse(info.stdout));
  } catch {
    host.limactl = "malformed";
    prerequisites.push(
      "limactl info returned something other than its JSON document",
    );
    return { host, instance: blank("unknown"), raw: null, marker };
  }
  host.limaVersion = safeText(parsedInfo.version, 40);
  host.vmTypeSupported = parsedInfo.vmTypes.includes(g.vmType);
  if (parsedInfo.version !== g.limaVersion) {
    host.limactl = "unsupported-version";
    prerequisites.push(
      `limactl is ${host.limaVersion}, approved version is ${g.limaVersion}`,
    );
  }
  if (!host.vmTypeSupported) {
    prerequisites.push(`vmType ${g.vmType} is not offered by this limactl`);
  }
  if (parsedInfo.limaHome !== g.limaHome) {
    prerequisites.push("limactl did not honour LIMA_HOME");
  }

  const list = await runLimactl(g, ["list", "--json"], signal);
  if (!list.ok) {
    host.limactl = host.limactl === "ok" ? "failed" : host.limactl;
    prerequisites.push(`limactl list failed: ${list.detail}`);
    return { host, instance: blank("unknown"), raw: null, marker };
  }
  const instances = parseList(list.stdout);
  if (instances === null) {
    host.limactl = host.limactl === "ok" ? "malformed" : host.limactl;
    prerequisites.push(
      "limactl list returned something this model cannot read",
    );
    return { host, instance: blank("unknown"), raw: null, marker };
  }
  host.instancesInHome = instances.length;
  const raw = instances.find((i) => i.name === g.name) ?? null;
  const state = ownership(marker, raw, g, id);
  const instance = blank(state);
  if (raw) {
    instance.status = safeText(raw.status, 40);
    instance.dir = safeText(raw.dir);
    instance.vmType = raw.vmType === undefined ? null : safeText(raw.vmType);
    instance.arch = raw.arch === undefined ? null : safeText(raw.arch);
    instance.cpus = raw.cpus ?? null;
    instance.memoryBytes = raw.memory ?? null;
    instance.diskBytes = raw.disk ?? null;
    instance.sshLocalPort = raw.sshLocalPort ?? null;
    instance.limaVersion = raw.limaVersion === undefined
      ? null
      : safeText(raw.limaVersion);
    instance.errors = (raw.errors ?? []).slice(0, MAX_ERROR_ENTRIES).map((e) =>
      safeText(e)
    );
  }
  return { host, instance, raw, marker };
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

type Ctx = {
  globalArgs: unknown;
  signal: AbortSignal;
  modelType: string | { raw?: string; normalized: string };
  modelId: string;
  definition: { id: string; name: string };
  logger: Logger;
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
    overrides?: { tags?: Record<string, string> },
  ) => Promise<{ name: string }>;
  createFileWriter: (
    spec: string,
    name: string,
  ) => { writeText: (t: string) => Promise<{ name: string }> };
};

function identity(ctx: Ctx): Identity {
  return {
    modelType: ModelTypeSchema.parse(ctx.modelType),
    modelId: ctx.modelId,
    definitionId: ctx.definition.id,
  };
}

async function persist(ctx: Ctx, g: GlobalArgs, obs: Observation) {
  const host = await ctx.writeResource("host", `host-${g.name}`, obs.host, {
    tags: { limactl: obs.host.limactl, name: g.name },
  });
  const instance = await ctx.writeResource(
    "instance",
    `instance-${g.name}`,
    obs.instance,
    {
      tags: {
        state: obs.instance.state,
        status: obs.instance.status ?? "none",
        name: g.name,
        changed: String(obs.instance.changed),
      },
    },
  );
  return [host, instance];
}

function requireHost(obs: Observation) {
  if (obs.host.limactl !== "ok" || obs.host.prerequisites.length > 0) {
    throw new Error(`host is not ready: ${obs.host.prerequisites.join("; ")}`);
  }
}

function requireOwned(obs: Observation, verb: string) {
  if (obs.instance.state !== "owned") {
    throw new Error(
      `refusing to ${verb}: instance is ${obs.instance.state}, not owned by this model`,
    );
  }
}

async function resolvedPath(path: string): Promise<string> {
  try {
    return await Deno.realPath(path);
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
    const cut = path.lastIndexOf("/");
    if (cut <= 0) throw new Error("path has no existing safe parent");
    return `${await resolvedPath(path.slice(0, cut))}/${path.slice(cut + 1)}`;
  }
}

/** Mandatory on every method and again under mutation locks; no optional-check bypass. */
export async function validatePaths(g: GlobalArgs): Promise<void> {
  const home = Deno.env.get("HOME");
  if (!home) {
    throw new Error(
      "HOME is required to establish the dedicated-home boundary",
    );
  }
  const realHome = await Deno.realPath(home);
  const realDefault = await resolvedPath(`${home}/.lima`);
  const real = await resolvedPath(g.limaHome);
  if (
    real !== g.limaHome || real === realHome || real === realDefault ||
    real.startsWith(realDefault + "/")
  ) {
    throw new Error(
      "limaHome must be canonical and dedicated, not a default-home alias",
    );
  }
  for (const mount of g.mounts) {
    const target = await Deno.realPath(mount.location);
    if (
      target !== mount.location || mountIsDenied(target, realHome) ||
      mountIsDenied(target, home)
    ) throw new Error("mount target is denied or aliased");
  }
}

/** Compare the complete supported config, not just selected port or mount numbers. */
export function configChecks(
  g: GlobalArgs,
  scripts: string[],
  config: unknown,
) {
  const parsed = ObservedConfigSchema.safeParse(config);
  const wanted = renderTemplate(g, scripts);
  const cfg = parsed.success ? parsed.data : null;
  const equal = (key: string) =>
    cfg !== null &&
    canonical((cfg as Record<string, unknown>)[key]) === canonical(wanted[key]);
  return [
    {
      name: "config-identity",
      pass: cfg !== null && canonical(cfg) === canonical(wanted),
      detail: "complete supported configuration must equal the approved render",
    },
    {
      name: "ssh-settings",
      pass: equal("ssh") && equal("propagateProxyEnv"),
      detail: "SSH and proxy settings must equal the approved render",
    },
    {
      name: "port-forwarding-policy",
      pass: equal("portForwards"),
      detail:
        "complete ordered forwards and catch-all must equal the approved render",
    },
    {
      name: "configured-mounts",
      pass: equal("mounts") && equal("mountType") && equal("mountInotify"),
      detail:
        "mount locations, permissions and backend must equal the approved render",
    },
  ];
}

async function requireStartConfig(g: GlobalArgs, obs: Observation) {
  const scripts = await loadProvisionScripts(g);
  const hash = await sha256Hex(canonical(renderTemplate(g, scripts)));
  if (
    !obs.marker || obs.marker === "malformed" ||
    obs.marker.configHash !== hash ||
    obs.marker.imageDigest !== g.image.digest ||
    !configChecks(g, scripts, obs.raw?.config).every((c) => c.pass)
  ) {
    throw new Error(
      "replacement-required: desired or observed configuration drift, or identity unavailable; run plan and inspect",
    );
  }
}

async function writeTemplate(
  g: GlobalArgs,
  rendered: Rendered,
): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const dir = await Deno.makeTempDir({ prefix: "swamp-lima-" });
  const path = `${dir}/${g.name}.yaml`;
  // JSON is YAML; Lima reads it as such, and it is what the hash was taken over.
  await Deno.writeTextFile(path, JSON.stringify(rendered, null, 2) + "\n", {
    mode: 0o600,
  });
  return {
    path,
    cleanup: async () =>
      await Deno.remove(dir, { recursive: true }).catch(() => {}),
  };
}

async function guestShell(
  g: GlobalArgs,
  script: string,
  signal: AbortSignal,
): Promise<RunResult> {
  return await runLimactl(g, ["shell", g.name, "sh", "-c", script], signal);
}

/** The @jpisgeek/lima model: inspect, plan, create, start, verify, stop, destroy. */
export const model = {
  type: "@jpisgeek/lima",
  version: "2026.11.19.1",
  globalArguments: GlobalArgsObjectSchema,
  resources: {
    host: {
      description:
        "What the Mac and its limactl offer: version, backend support, the dedicated home, and every unmet prerequisite.",
      schema: HostSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    instance: {
      description:
        "Observed state of the one instance this model may own: missing, unmanaged, owned, or unknown, with Lima's own status and sizes.",
      schema: InstanceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    plan: {
      description:
        "The rendered configuration's hash, the action it implies, the keys that drifted, and what still blocks it.",
      schema: PlanSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    verification: {
      description:
        "Isolation and identity checks against the running guest, each named with its own pass/fail.",
      schema: VerificationSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
  },
  files: {
    config: {
      description:
        "Complete rendered config including provisioning scripts. Only reviewed credential-free scripts are allowed; retained indefinitely (GC keeps 10 versions).",
      contentType: "application/json",
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  checks: {
    "dedicated-lima-home": {
      description:
        "limaHome must be a dedicated directory, never Lima's default home or the user's home.",
      labels: ["policy"],
      execute: async (ctx: { globalArgs: unknown }) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        const home = Deno.env.get("HOME");
        const errors: string[] = [];
        if (home && (g.limaHome === home || g.limaHome === `${home}/.lima`)) {
          errors.push(
            "limaHome is the default Lima home or the user home; choose a dedicated directory",
          );
        }
        return Promise.resolve(
          errors.length ? { pass: false, errors } : { pass: true },
        );
      },
    },
    "no-denied-mounts": {
      description:
        "No mount may expose the home directory, system tree, volumes, or temp trees to the guest.",
      labels: ["policy"],
      execute: async (ctx: { globalArgs: unknown }) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        const bad = g.mounts.filter((m) =>
          mountIsDenied(m.location, Deno.env.get("HOME"))
        ).map((m) => m.location);
        return Promise.resolve(
          bad.length
            ? { pass: false, errors: bad.map((b) => `denied mount: ${b}`) }
            : { pass: true },
        );
      },
    },
    "approved-limactl": {
      description:
        "The limactl on this host is the approved version and offers the requested backend.",
      labels: ["live"],
      execute: async (ctx: { globalArgs: unknown; signal?: AbortSignal }) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        const r = await runLimactl(
          g,
          ["info"],
          ctx.signal ?? new AbortController().signal,
        );
        if (!r.ok) {
          return {
            pass: false,
            errors: [
              r.kind === "notfound" ? "limactl is not installed" : r.detail,
            ],
          };
        }
        const parsed = LimaInfoSchema.safeParse((() => {
          try {
            return JSON.parse(r.stdout);
          } catch {
            return null;
          }
        })());
        if (!parsed.success) {
          return { pass: false, errors: ["limactl info was not readable"] };
        }
        const errors: string[] = [];
        if (parsed.data.version !== g.limaVersion) {
          errors.push(
            `limactl ${
              safeText(parsed.data.version, 40)
            } is not the approved ${g.limaVersion}`,
          );
        }
        if (!parsed.data.vmTypes.includes(g.vmType)) {
          errors.push(`backend ${g.vmType} unavailable`);
        }
        return errors.length ? { pass: false, errors } : { pass: true };
      },
    },
  },
  methods: {
    inspect: {
      description:
        "Read the host's Lima capabilities and this instance's observed state. Missing, unmanaged, and unreadable are recorded as different facts. Nothing is changed.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, ctx: Ctx) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        const obs = await observe(g, identity(ctx), ctx.signal, "inspect");
        return { dataHandles: await persist(ctx, g, obs) };
      },
    },
    plan: {
      description:
        "Render and validate the complete configuration, hash it, and say what applying it would mean: create, noop, replacement-required, or blocked. No VM is created.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, ctx: Ctx) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        const obs = await observe(g, identity(ctx), ctx.signal, "plan");
        const prerequisites = [...obs.host.prerequisites];
        let scripts: string[] = [];
        try {
          scripts = await loadProvisionScripts(g);
        } catch (e) {
          prerequisites.push((e as Error).message);
          scripts = g.provision.map(() => "");
        }
        const rendered = renderTemplate(g, scripts);
        const configHash = await sha256Hex(canonical(rendered));
        let validated = false;
        if (obs.host.limactl === "ok") {
          const tmp = await writeTemplate(g, rendered);
          try {
            const v = await runLimactl(g, ["validate", tmp.path], ctx.signal);
            validated = v.ok;
            if (!v.ok) {
              prerequisites.push(
                `limactl validate rejected the rendered config: ${v.detail}`,
              );
            }
          } finally {
            await tmp.cleanup();
          }
        }
        let action: z.infer<typeof PlanSchema>["action"];
        let diff: string[] = [];
        if (prerequisites.length > 0) action = "blocked-prerequisites";
        else if (obs.instance.state === "missing") action = "create";
        else if (
          obs.instance.state === "owned" && obs.marker &&
          obs.marker !== "malformed"
        ) {
          const actual = obs.raw?.config;
          if (
            obs.marker.configHash === configHash &&
            obs.marker.imageDigest === g.image.digest && actual &&
            canonical(actual) === canonical(rendered)
          ) action = "noop";
          else {
            action = "replacement-required";
            diff = actual
              ? diffKeys(actual, rendered)
              : ["(observed configuration unavailable)"];
            if (diff.length === 0) diff = ["(creation identity differs)"];
          }
        } else action = "blocked-unmanaged";
        const plan = {
          renderedAt: new Date().toISOString(),
          action,
          configHash,
          imageDigest: g.image.digest,
          limaVersion: g.limaVersion,
          observedState: obs.instance.state,
          observedStatus: obs.instance.status,
          validated,
          diff,
          prerequisites,
        };
        const handles = await persist(ctx, g, obs);
        handles.push(
          await ctx.writeResource("plan", `plan-${g.name}`, plan, {
            tags: { action, configHash: configHash.slice(0, 12), name: g.name },
          }),
        );
        handles.push(
          await ctx.createFileWriter(
            "config",
            `config-${g.name}-${configHash.slice(0, 12)}`,
          ).writeText(JSON.stringify(rendered, null, 2) + "\n"),
        );
        ctx.logger.info("plan for {name}: {action} ({hash})", {
          name: g.name,
          action,
          hash: configHash.slice(0, 12),
        });
        return { dataHandles: handles };
      },
    },
    create: {
      description:
        "Create the exact planned instance without booting it. Requires the reviewed config hash; refuses an existing instance whether owned or not, and never deletes what a failed create left behind.",
      arguments: z.object({
        configHash: z.string().regex(HEX64).describe(
          "The plan's configHash, as reviewed",
        ),
      }),
      execute: async (args: { configHash: string }, ctx: Ctx) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        const id = identity(ctx);
        const obs = await observe(g, id, ctx.signal, "create");
        requireHost(obs);
        if (obs.instance.state !== "missing") {
          throw new Error(
            `refusing to create: an instance named ${g.name} already exists in this home (${obs.instance.state})`,
          );
        }
        const scripts = await loadProvisionScripts(g);
        const rendered = renderTemplate(g, scripts);
        const configHash = await sha256Hex(canonical(rendered));
        if (configHash !== args.configHash) {
          throw new Error(
            `config hash ${
              configHash.slice(0, 12)
            }… does not match the reviewed ${
              args.configHash.slice(0, 12)
            }…; run plan again`,
          );
        }
        const release = await acquireLock(g, "create", ctx.logger);
        try {
          await validatePaths(g);
          const again = await observe(g, id, ctx.signal, "create");
          requireHost(again);
          if (again.instance.state !== "missing") {
            throw new Error(
              "instance appeared while acquiring the lock; inspect",
            );
          }
          const tmp = await writeTemplate(g, rendered);
          let r: RunResult;
          try {
            r = await runLimactl(
              g,
              ["create", "--name", g.name, tmp.path],
              ctx.signal,
              g.startTimeoutSec,
            );
          } finally {
            await tmp.cleanup();
          }
          if (!r.ok) {
            throw new Error(
              `limactl create failed (${r.kind}): ${r.detail}. Nothing was deleted; inspect the home by hand.`,
            );
          }
          const after = await observe(g, id, ctx.signal, "create");
          if (!after.raw) {
            throw new Error(
              "limactl create returned success but the instance is not listed; inspect",
            );
          }
          const marker: Marker = {
            modelType: id.modelType,
            modelId: id.modelId,
            definitionId: id.definitionId,
            name: g.name,
            limaHome: g.limaHome,
            instanceDir: after.raw.dir,
            configHash,
            imageDigest: g.image.digest,
            createdAt: new Date().toISOString(),
          };
          await Deno.mkdir(ownedDir(g), { recursive: true, mode: 0o700 });
          await Deno.writeTextFile(
            markerPath(g),
            JSON.stringify(marker, null, 2) + "\n",
            { mode: 0o600 },
          );
          const final = await observe(g, id, ctx.signal, "create");
          final.instance.changed = true;
          const handles = await persist(ctx, g, final);
          handles.push(
            await ctx.createFileWriter(
              "config",
              `config-${g.name}-${configHash.slice(0, 12)}`,
            ).writeText(JSON.stringify(rendered, null, 2) + "\n"),
          );
          ctx.logger.info("created {name} ({hash})", {
            name: g.name,
            hash: configHash.slice(0, 12),
          });
          return { dataHandles: handles };
        } finally {
          await release();
        }
      },
    },
    start: {
      description:
        "Start the owned instance and wait for Lima to report it running. Already running is a no-op.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, ctx: Ctx) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        const id = identity(ctx);
        const release = await acquireLock(g, "start", ctx.logger);
        try {
          await validatePaths(g);
          const obs = await observe(g, id, ctx.signal, "start");
          requireHost(obs);
          requireOwned(obs, "start");
          await requireStartConfig(g, obs);
          if (obs.instance.status === "Running") {
            return { dataHandles: await persist(ctx, g, obs) };
          }
          const r = await runLimactl(
            g,
            ["start", "--timeout", `${g.startTimeoutSec}s`, g.name],
            ctx.signal,
            g.startTimeoutSec + 30,
          );
          if (!r.ok) {
            throw new Error(`limactl start failed (${r.kind}): ${r.detail}`);
          }
          const after = await observe(g, id, ctx.signal, "start");
          if (after.instance.status !== "Running") {
            throw new Error(
              `instance is ${after.instance.status ?? "absent"} after start`,
            );
          }
          after.instance.changed = true;
          return { dataHandles: await persist(ctx, g, after) };
        } finally {
          await release();
        }
      },
    },
    verify: {
      description:
        "Check the running guest against the plan: config identity, guest OS and arch, actual mounts, port forwarding policy, SSH settings, and readiness. Each check is recorded separately.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, ctx: Ctx) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        const obs = await observe(g, identity(ctx), ctx.signal, "verify");
        requireHost(obs);
        requireOwned(obs, "verify");
        if (obs.instance.status !== "Running") {
          throw new Error(
            `verify needs a running instance; it is ${obs.instance.status}`,
          );
        }
        const checks: { name: string; pass: boolean; detail: string }[] = [];
        const scripts = await loadProvisionScripts(g);
        checks.push(...configChecks(g, scripts, obs.raw?.config));
        const guest = await guestShell(
          g,
          "uname -m; . /etc/os-release; echo \"$ID $VERSION_ID\"; findmnt -rn -o TARGET,FSTYPE -t virtiofs,9p,fuse.sshfs | tr '\\n' ';'; echo; systemctl is-system-running",
          ctx.signal,
        );
        if (!guest.ok && guest.kind !== "failed") {
          checks.push({
            name: "guest-reachable",
            pass: false,
            detail: guest.detail,
          });
        } else {
          const lines = (guest.ok ? guest.stdout : "").trim().split("\n");
          const [arch = "", os = "", mountsLine = "", ready = ""] = lines;
          checks.push({
            name: "guest-identity",
            pass: arch.trim() === g.arch && os.startsWith("ubuntu "),
            detail: safeText(`${arch.trim()} ${os.trim()}`),
          });
          const guestMounts = mountsLine.split(";").map((s) =>
            s.trim().split(/\s+/)[0]
          ).filter((s) => s !== "");
          checks.push({
            name: "guest-mounts",
            pass: canonical([...guestMounts].sort()) ===
              canonical(g.mounts.map((m) => m.location).sort()),
            detail: safeText(`guest=${JSON.stringify(guestMounts)}`),
          });
          checks.push({
            name: "guest-readiness",
            pass: ready.trim() === "running",
            detail: safeText(ready.trim() || "(no answer)"),
          });
        }
        const verification = {
          observedAt: new Date().toISOString(),
          pass: checks.every((c) => c.pass),
          checks,
        };
        const handles = await persist(ctx, g, obs);
        handles.push(
          await ctx.writeResource(
            "verification",
            `verification-${g.name}`,
            verification,
            { tags: { pass: String(verification.pass), name: g.name } },
          ),
        );
        return { dataHandles: handles };
      },
    },
    stop: {
      description:
        "Gracefully stop the owned instance. No force escalation; a stop that fails is reported, not retried harder.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, ctx: Ctx) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        const id = identity(ctx);
        const release = await acquireLock(g, "stop", ctx.logger);
        try {
          await validatePaths(g);
          const obs = await observe(g, id, ctx.signal, "stop");
          requireHost(obs);
          requireOwned(obs, "stop");
          if (obs.instance.status === "Stopped") {
            return { dataHandles: await persist(ctx, g, obs) };
          }
          const r = await runLimactl(
            g,
            ["stop", g.name],
            ctx.signal,
            g.startTimeoutSec,
          );
          if (!r.ok) {
            throw new Error(`limactl stop failed (${r.kind}): ${r.detail}`);
          }
          const after = await observe(g, id, ctx.signal, "stop");
          if (after.instance.status !== "Stopped") {
            throw new Error(
              `instance is ${after.instance.status ?? "absent"} after stop`,
            );
          }
          after.instance.changed = true;
          return { dataHandles: await persist(ctx, g, after) };
        } finally {
          await release();
        }
      },
    },
    destroy: {
      description:
        "Delete the owned, stopped instance and its disk. A separate door: the exact name must be typed, a preservation decision recorded, and the instance freshly inspected. Never a rollback step.",
      arguments: z.object({
        confirmName: z.string().describe("Must equal the instance name"),
        preservation: z.enum(["no-unique-data", "backup-verified"]).describe(
          "Why deleting the disk is acceptable",
        ),
        backupRef: z.string().max(200).optional().describe(
          "Where the verified backup lives; required with backup-verified",
        ),
      }),
      execute: async (
        args: { confirmName: string; preservation: string; backupRef?: string },
        ctx: Ctx,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        await validatePaths(g);
        if (args.confirmName !== g.name) {
          throw new Error("confirmName does not match the instance name");
        }
        if (
          args.preservation === "backup-verified" && !args.backupRef?.trim()
        ) throw new Error("backup-verified needs backupRef");
        const id = identity(ctx);
        const release = await acquireLock(g, "destroy", ctx.logger);
        try {
          await validatePaths(g);
          const obs = await observe(g, id, ctx.signal, "destroy");
          requireHost(obs);
          requireOwned(obs, "destroy");
          if (obs.instance.status !== "Stopped") {
            throw new Error(
              `destroy needs a stopped instance; it is ${obs.instance.status}`,
            );
          }
          const r = await runLimactl(
            g,
            ["delete", g.name],
            ctx.signal,
            g.startTimeoutSec,
          );
          if (!r.ok) {
            throw new Error(`limactl delete failed (${r.kind}): ${r.detail}`);
          }
          await Deno.remove(markerPath(g)).catch(() => {});
          const after = await observe(g, id, ctx.signal, "destroy");
          if (after.instance.state !== "missing") {
            throw new Error(
              `instance still ${after.instance.state} after delete; inspect`,
            );
          }
          after.instance.changed = true;
          ctx.logger.info("destroyed {name} ({preservation})", {
            name: g.name,
            preservation: args.preservation,
          });
          return { dataHandles: await persist(ctx, g, after) };
        } finally {
          await release();
        }
      },
    },
  },
};
