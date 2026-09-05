/**
 * Read Swamp's documented operational interfaces into typed resources.
 *
 * This model invokes the Swamp binary directly with an argv array. It never
 * uses a shell, command/shell model, private database, or internal HTTP API.
 * Each interface is independent: one unavailable command is persisted as a
 * coverage gap while the remaining observations survive.
 *
 * It observes the LOCAL repository only. It holds no credential and addresses
 * no remote host, so there is no destination for it to be redirected to and no
 * authentication for it to forward. See assertLocalOnly() for why the remote
 * mode was removed rather than guarded, and INHERITED_ENV for why the child is
 * given an isolated empty HOME rather than the operator's — a credential and a
 * remote server it could otherwise have recovered from ambient CLI
 * configuration.
 *
 * Nothing a command prints is stored as it arrived. Every successful response
 * is projected through a strict per-interface schema first, and the projection
 * keeps only counts, booleans, and status values drawn from a closed
 * vocabulary — never a byte of the response's own text.
 */
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  repoDir: z.string().min(1).describe("Swamp repository to observe"),
  swampBinary: z.string().min(1).default("swamp").describe(
    "Swamp executable: a bare program name resolved on PATH, or an absolute path. Relative paths are refused.",
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

/**
 * The complete vocabulary a stored status may be drawn from.
 *
 * This is an enum and not a pattern on purpose. The previous version stored
 * the response's own status text whenever it fit a 32-character shape, and 32
 * characters is room enough for a short API key, an internal host name, an
 * address, an account number, or the name of somebody's machine — all of which
 * would then sit in a 30-day resource and flow into the dashboard bundle. Any
 * character-class rule has the same hole, because the field's LENGTH and
 * ALPHABET were never what made it safe. Only a closed set is safe: a value
 * that is not one of these six is not shortened or escaped, it is replaced by
 * `unknown` and its text is dropped on the floor at the collection boundary.
 */
const StatusBucketSchema = z.enum([
  "active",
  "succeeded",
  "failed",
  "stale",
  "orphaned",
  "unknown",
]);

type StatusBucket = z.infer<typeof StatusBucketSchema>;

/**
 * Status vocabularies, matched whole rather than by substring.
 *
 * These were unanchored substring probes evaluated success-before-failure,
 * which laundered compound statuses into passes: "completed_with_errors" and
 * "unsuccessful" both matched /success|succeeded|completed|passed/ and were
 * counted as succeeded, so a run that failed inflated the success count and
 * left the section healthy. Whole-token matching cannot do that, and a status
 * this build does not recognize falls through to "unknown", which degrades the
 * section rather than quietly passing it.
 *
 * The matching lives here, at the collection boundary, because the mapping is
 * also the redaction: the report can only ever see the bucket, so there is no
 * later stage holding the original text.
 */
const STATUS_VOCABULARY: ReadonlyArray<[StatusBucket, RegExp]> = [
  // Failure is tested first so that any future overlap resolves pessimistically.
  [
    "failed",
    /^(failed|failure|failing|error|errored|errors|cancel|cancelled|canceled|cancelling|aborted|abort|timeout|timed[_ -]?out|unsuccessful|rejected|crashed|killed)$/,
  ],
  ["stale", /^(stale|stalled)$/],
  ["orphaned", /^(orphan|orphaned)$/],
  [
    "active",
    /^(running|active|queued|pending|starting|started|in[_ -]?progress|waiting|scheduled)$/,
  ],
  [
    "succeeded",
    /^(succeeded|success|successful|completed|complete|passed|pass|ok|done|finished)$/,
  ],
];

/**
 * Longest status text this model will even attempt to classify.
 *
 * Nothing in the vocabulary is close to this long, so a longer value cannot
 * match anything; refusing it up front keeps unbounded remote text out of the
 * regex engine entirely.
 */
const MAX_CLASSIFIABLE_STATUS_CHARS = 64;

/** Map one raw status string onto the closed vocabulary. */
function classifyStatus(status: string): StatusBucket {
  if (status.length > MAX_CLASSIFIABLE_STATUS_CHARS) return "unknown";
  for (const [bucket, pattern] of STATUS_VOCABULARY) {
    if (pattern.test(status)) return bucket;
  }
  return "unknown";
}

/**
 * A projected history, workflow or report record: the four facts the dashboard
 * actually reads, and no field that could carry anything else.
 *
 * `status` is present only when the response actually carried a status field,
 * so "this Swamp build exposes no status" stays distinguishable from "this
 * status was not one this build recognizes" (the `unknown` bucket). Neither
 * case retains the original text.
 *
 * `identified` deliberately records only THAT the response named the artifact,
 * never what it was called. Report and run names are identifying metadata, but
 * their presence is still load-bearing: it is what separates "no status field
 * on this build" from "this record is junk".
 */
const RecordSchema = z.object({
  status: StatusBucketSchema.optional(),
  stale: z.literal(true).optional(),
  orphaned: z.literal(true).optional(),
  identified: z.literal(true).optional(),
}).strict();

/**
 * A count is only a count when it is a nonnegative safe integer.
 *
 * `-1`, `1.5` and `1e308` are all JavaScript numbers, and a consumer that adds
 * them up reaches a reassuring total from a response that never described a
 * healthy system. Anything else invalidates the whole run-doctor snapshot
 * rather than being coerced.
 */
const CountSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

const RunsPayloadSchema = z.object({ runs: z.array(RecordSchema) }).strict();
const ResultsPayloadSchema = z.object({ results: z.array(RecordSchema) })
  .strict();
const DoctorPayloadSchema = z.object({
  totalTracked: CountSchema.optional(),
  active: CountSchema.optional(),
  stale: CountSchema.optional(),
  orphaned: CountSchema.optional(),
}).strict();

/** Everything this model is willing to persist from a successful command. */
const PayloadSchema = z.union([
  RunsPayloadSchema,
  ResultsPayloadSchema,
  DoctorPayloadSchema,
  z.null(),
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
    "oversized",
    "command-failed",
  ]),
  error: z.string(),
  payload: PayloadSchema,
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;
type Observation = z.infer<typeof ObservationSchema>;
type Json = Record<string, unknown>;

function isJson(value: unknown): value is Json {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const STATUS_KEYS = ["status", "state", "outcome"] as const;
const IDENTITY_KEYS = ["id", "name", "reportName", "dataName"] as const;

/**
 * Project one raw record down to the projected shape.
 *
 * A record that is not an object becomes `{}`: it is still counted, because
 * dropping it silently would shrink the population the dashboard reports on,
 * but nothing it contained survives. The report already treats a record with
 * neither a status nor an identity as malformed, so these placeholders arrive
 * as the coverage gap they are.
 */
function projectRecord(value: unknown): Json {
  if (!isJson(value)) return {};
  const projected: Json = {};
  for (const key of STATUS_KEYS) {
    const raw = value[key];
    if (typeof raw !== "string") continue;
    const status = raw.trim().toLowerCase();
    if (status === "") continue;
    // The response said something about status, so the field exists on this
    // build. What it said is classified and then discarded.
    projected.status = classifyStatus(status);
    break;
  }
  if (value.stale === true) projected.stale = true;
  if (value.orphaned === true) projected.orphaned = true;
  if (
    IDENTITY_KEYS.some((key) =>
      typeof value[key] === "string" && value[key].trim() !== ""
    )
  ) projected.identified = true;
  return projected;
}

/**
 * Project a list-shaped response, or null when it is not list-shaped at all.
 *
 * Null means "this response was not the documented shape", which the caller
 * records as `invalid-response` — an explicit coverage gap. It is never an
 * empty list, because an empty list is a real and different answer.
 */
function projectRecords(payload: unknown, key: string): Json | null {
  const raw = Array.isArray(payload)
    ? payload
    : isJson(payload) && Array.isArray(payload[key])
    ? payload[key]
    : null;
  if (raw === null) return null;
  return { [key]: raw.map(projectRecord) };
}

const DOCTOR_COUNT_KEYS = [
  "totalTracked",
  "active",
  "stale",
  "orphaned",
] as const;

/**
 * Project the run-doctor response to its four documented counts.
 *
 * An absent count stays absent — the report renders it as unsupported rather
 * than as zero — but a count that is PRESENT and not a nonnegative integer
 * invalidates the snapshot, because there is no honest value to fall back to.
 * Unknown keys (a future build's extra counter, `reaped` today) are dropped
 * instead of rejected: a new field must not blind the dashboard, and it must
 * not reach the datastore either.
 */
function projectDoctor(payload: unknown): Json | null {
  if (!isJson(payload)) return null;
  const projected: Json = {};
  for (const key of DOCTOR_COUNT_KEYS) {
    const value = payload[key];
    if (value === undefined || value === null) continue;
    if (!CountSchema.safeParse(value).success) return null;
    projected[key] = value;
  }
  return projected;
}

const PROJECTORS: Record<
  Observation["interface"],
  (payload: unknown) => Json | null
> = {
  "run-history": (payload) => projectRecords(payload, "runs"),
  "run-doctor": projectDoctor,
  "workflow-history": (payload) => projectRecords(payload, "results"),
  "stored-reports": (payload) => projectRecords(payload, "results"),
  // Never queried; present so the map is total over the interface names.
  "serve-heartbeat": () => null,
};

/**
 * Project and then re-validate a successful response.
 *
 * Exported because this is the redaction boundary of the whole model: whatever
 * this returns is exactly what lands in a 30-day resource, so it is worth
 * being able to test directly against real command output.
 */
export function projectPayload(
  name: Observation["interface"],
  payload: unknown,
): Observation["payload"] | undefined {
  const projected = PROJECTORS[name](payload);
  if (projected === null) return undefined;
  // The projector builds the object and the schema polices it. Two independent
  // statements of the same rule, so a future edit to one has to survive the
  // other before anything can be written.
  const parsed = PayloadSchema.safeParse(projected);
  return parsed.success ? parsed.data : undefined;
}

interface CommandResult {
  success: boolean;
  code: number;
  stdout: string;
  stderr: string;
  /** True when either stream passed its byte cap and the child was killed. */
  truncated?: boolean;
}

export type CommandRunner = (
  binary: string,
  args: string[],
  options: { cwd: string; env: Record<string, string>; signal: AbortSignal },
) => Promise<CommandResult>;

/**
 * The complete set of parent environment variables a Swamp child may inherit.
 *
 * The child used to inherit the entire parent environment. That environment is
 * a swamp run's environment: it routinely holds API keys, vault material and
 * cloud credentials for every other extension in the repository, none of which
 * this command needs. A replaced binary on PATH, a mistyped `swampBinary`, or
 * a compromised Swamp release then reads all of it for free.
 *
 * PATH is required to resolve a bare `swamp`; TMPDIR is where it writes scratch
 * files. Everything else is withheld.
 *
 * HOME is NOT on this list. The parent's HOME is where the Swamp CLI keeps its
 * own configuration, and that configuration can hold a credential and a
 * `server` pointing at a remote instance — the two things this extension
 * documents itself as not having. Inheriting it meant the child could recover
 * both from ambient state and address a host whose TLS, redirect and identity
 * behaviour nothing here controls, while every check in this file still passed.
 * The child is given an isolated empty HOME instead (see childHome()), so
 * "holds no credential, reaches no remote server" is a property of the process
 * this model launches rather than a claim about the one it hoped to launch.
 */
const INHERITED_ENV = ["PATH", "TMPDIR"] as const;

/**
 * Whether a path names the observed repository or something inside it.
 *
 * Purely textual, and sound only because every caller has already rejected
 * paths carrying a `.` or `..` segment: without those, a path's prefix is its
 * location. Exact when repoDir is absolute, which is the case that matters.
 */
function insideRepo(candidate: string, repoDir: string): boolean {
  const repo = repoDir.replace(/\/+$/, "");
  const normalized = candidate.replace(/\/+$/, "");
  return normalized === repo || normalized.startsWith(`${repo}/`);
}

/** Drop PATH entries whose meaning depends on the directory the child runs in. */
function usableSearchPath(value: string, repoDir: string): string {
  return value.split(":").filter((entry) => {
    // Covers the empty entry (`/usr/bin:`) as well as `.` and `bin/`.
    if (!entry.startsWith("/")) return false;
    if (entry.split("/").some((s) => s === "." || s === "..")) return false;
    return !insideRepo(entry, repoDir);
  }).join(":");
}

/**
 * Turn `swampBinary` into an absolute executable BEFORE any process is created.
 *
 * assertSwampBinary() refuses `./swamp`, but the child runs with `cwd: repoDir`
 * and the operating system, not this model, was doing the lookup for a bare
 * name — against the PARENT process's PATH, after the change of directory. So a
 * PATH carrying `.`, a stray trailing colon, or any relative entry made a bare
 * `swamp` mean `<repoDir>/swamp`: an executable supplied by the very repository
 * this model is only supposed to be reading, chosen without the operator asking
 * for it. Sanitizing the CHILD's PATH cannot close that, because the child's
 * PATH is not what the runtime searches.
 *
 * Doing the search here makes the decision ours and auditable: only absolute
 * PATH directories, none of them inside the repository, and the result handed
 * to Deno.Command as an absolute path so nothing is left for it to resolve.
 * Finding nothing is a launch failure, recorded as a coverage gap — never a
 * fallback to whatever the cwd happens to hold.
 */
function resolveBinary(binary: string, repoDir: string): string {
  const repo = Deno.realPathSync(repoDir);
  const acceptable = (candidate: string): string | undefined => {
    const resolved = Deno.realPathSync(candidate);
    if (insideRepo(resolved, repo)) return undefined;
    const info = Deno.statSync(resolved);
    return info.isFile && ((info.mode ?? 0o111) & 0o111) !== 0
      ? resolved
      : undefined;
  };
  if (binary.startsWith("/")) {
    const resolved = acceptable(binary);
    if (resolved) return resolved;
    throw new Error(
      "swampBinary must resolve to an executable outside the observed repository",
    );
  }
  const search = usableSearchPath(readEnv("PATH") ?? "", repo);
  for (const entry of search.split(":")) {
    if (entry === "") continue;
    try {
      const resolved = acceptable(`${entry}/${binary}`);
      if (resolved) return resolved;
    } catch {
      // Unreadable or absent: not a candidate.
    }
  }
  throw new Error(
    "swampBinary could not be resolved to an executable outside the observed repository",
  );
}

/**
 * Build the child environment from the allowlist plus explicitly passed values.
 *
 * `read` is a parameter so the allowlist can be tested without touching the
 * real process environment; `cwd` is the directory the child will run in, which
 * is what makes a relative PATH entry dangerous.
 */
export function buildChildEnv(
  explicit: Record<string, string>,
  read: (name: string) => string | undefined,
  cwd: string,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const name of INHERITED_ENV) {
    const value = read(name);
    if (value === undefined) continue;
    if (name === "PATH") {
      // An entirely unusable PATH is passed as no PATH at all: the launch then
      // fails and is recorded as a coverage gap, which is the honest outcome.
      const usable = usableSearchPath(value, cwd);
      if (usable !== "") env.PATH = usable;
      continue;
    }
    env[name] = value;
  }
  // Explicit last: what this model decided to pass always wins over anything
  // inherited under the same name.
  return { ...env, ...explicit };
}

/**
 * An empty, private HOME for the child, created once per process.
 *
 * Isolation, not convenience: with this HOME the Swamp executable finds no user
 * configuration, so it cannot pick up a stored credential or a configured
 * remote server from the operator's account. `makeTempDirSync` gives a
 * randomly named 0700 directory, so unlike a predictable path under TMPDIR
 * nobody else can pre-seed a configuration file into it.
 *
 * The directory is left in place when the process exits. It is empty and
 * owner-only; cleaning it up would mean tracking child lifetimes for no
 * security gain. A failure to create it propagates and the query is recorded as
 * a coverage gap — no command runs with the operator's HOME as a fallback.
 */
let isolatedHome: string | undefined;
function childHome(): string {
  if (isolatedHome === undefined) {
    isolatedHome = Deno.makeTempDirSync({
      prefix: "swamp-observability-home-",
    });
  }
  return isolatedHome;
}

function readEnv(name: string): string | undefined {
  try {
    return Deno.env.get(name);
  } catch {
    // No env permission. A missing PATH is a launch failure this model already
    // records as a coverage gap; it is not a reason to hand over more.
    return undefined;
  }
}

/**
 * How long a cancelled child has to exit on its own before it is killed.
 *
 * SIGTERM is a request, and a Swamp command that ignores or is wedged before
 * its handler keeps the pipes open, so the read below never settles and the
 * cancelled run hangs instead of ending. The forced kill is the bound on that.
 */
const FORCE_KILL_GRACE_MS = 5_000;

/**
 * Hard byte caps on what a child may hand back.
 *
 * `child.output()` buffers both pipes to completion with no limit, so the
 * amount of memory this model allocates was chosen by the command it launched:
 * a compromised or replaced binary, or a Swamp answering with a pathological
 * response, could hold the pipe open and write until the swamp process died —
 * taking every other extension's run down with it, from a program this model
 * was only supposed to be reading a few counts from. The caps make the ceiling
 * ours instead. stdout is generous because a large repository's run history is
 * legitimately big; stderr is small because it is classified and discarded.
 */
const MAX_STDOUT_BYTES = 4 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;

/**
 * Read one pipe up to `limit` bytes, then stop reading and report the overflow.
 *
 * The reader is always cancelled: on the overflow path that closes the pipe so
 * a child still writing gets EPIPE instead of blocking forever on a full pipe
 * with nobody draining it — which would leave `child.status` unsettled and the
 * run hung.
 */
async function readCapped(
  stream: ReadableStream<Uint8Array>,
  limit: number,
  onOverflow: () => void,
): Promise<string> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > limit) {
        onOverflow();
        break;
      }
      chunks.push(value);
      size += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => {
      // Already closed or errored; there is nothing left to release.
    });
  }
  const joined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(joined);
}

/**
 * Production runner. Exported so tests can exercise the pre-spawn abort guard
 * and the output caps directly, against a real process.
 */
export const defaultRunner: CommandRunner = async (binary, args, options) => {
  // Honour a signal that is ALREADY aborted before anything is launched.
  // `addEventListener` on an aborted signal never fires, so the old order —
  // spawn, then subscribe — started a process for a caller that had already
  // cancelled, and nothing was left to stop it.
  options.signal.throwIfAborted();
  // Resolved here, not by the runtime: an absolute path leaves the OS nothing
  // to search, and nothing for the child's own cwd to influence.
  const command = new Deno.Command(resolveBinary(binary, options.cwd), {
    args,
    cwd: options.cwd,
    // The isolated HOME goes in first so an explicit value from the caller
    // could still override it; production passes nothing.
    env: buildChildEnv(
      { HOME: childHome(), ...options.env },
      readEnv,
      options.cwd,
    ),
    // With clearEnv the env above is the child's ENTIRE environment.
    clearEnv: true,
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  });
  const child = command.spawn();
  let forceKill: ReturnType<typeof setTimeout> | undefined;
  const terminate = () => {
    // One escalation only: a second timer here would be one nobody clears.
    if (forceKill !== undefined) return;
    try {
      child.kill("SIGTERM");
    } catch {
      // The process may already have exited.
    }
    forceKill = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // Exited between the two signals; nothing left to kill.
      }
    }, FORCE_KILL_GRACE_MS);
  };
  options.signal.addEventListener("abort", terminate, { once: true });
  // The signal can abort between spawn() and the line above, and that abort is
  // delivered to nobody. Re-checking closes that window.
  if (options.signal.aborted) terminate();
  let truncated = false;
  const overflow = () => {
    truncated = true;
    // A child that is over the cap does not get to keep running: it is still
    // producing the output this model has just refused to hold.
    terminate();
  };
  try {
    const [stdout, stderr] = await Promise.all([
      readCapped(child.stdout, MAX_STDOUT_BYTES, overflow),
      readCapped(child.stderr, MAX_STDERR_BYTES, overflow),
    ]);
    const status = await child.status;
    return {
      success: status.success && !truncated,
      code: status.code,
      // The bytes read before the cap are dropped rather than returned. A
      // truncated JSON document is not a smaller document, it is a different
      // one, and parsing whatever prefix arrived is how a partial response
      // turns into a confident wrong number.
      stdout: truncated ? "" : stdout,
      stderr: truncated ? "" : stderr,
      truncated,
    };
  } finally {
    options.signal.removeEventListener("abort", terminate);
    if (forceKill !== undefined) clearTimeout(forceKill);
  }
};

/** Global arguments this model used to accept and no longer does. */
const REMOVED_REMOTE_ARGS = ["server", "token", "allowedServerHosts"] as const;

/**
 * Refuse a configuration that still asks for the removed remote mode.
 *
 * WHY THE REMOTE MODE IS GONE, not guarded.
 *
 * The earlier version passed `--server <https url>` and a bearer token to the
 * Swamp executable and pinned the URL's host against an allowlist. That pins
 * the FIRST hop and nothing after it. Whatever answers that first request can
 * reply `302 Location: http://attacker.invalid/`, and the HTTP client doing
 * the following is inside the child — a program whose redirect policy this
 * model does not set, cannot inspect, and does not ship. So the token can
 * still leave for an unpinned host, over cleartext, while every check here
 * passes. A pre-flight probe would not close it either: the hop that matters
 * is the one on the real request, not the one on the probe.
 *
 * The only ways to actually enforce "never forward authentication across a
 * redirect boundary" are to own the transport — which would mean speaking an
 * undocumented HTTP API this extension deliberately refuses to touch — or to
 * stop having authentication to forward. This takes the second: no server
 * URL, no token, no destination. The extension is named for and documented as
 * local observability, so this is the mode it always claimed to be.
 *
 * A stale configuration fails loudly instead of silently falling back to the
 * local repository, because "we observed something else and called it your
 * server" is exactly the kind of quiet substitution this extension exists to
 * refuse.
 */
function assertLocalOnly(raw: unknown): void {
  if (!isJson(raw)) return;
  const present = REMOVED_REMOTE_ARGS.filter((name) =>
    raw[name] !== undefined && raw[name] !== null
  );
  if (present.length === 0) return;
  throw new Error(
    `${
      present.join(", ")
    } is no longer accepted: this model observes the local repository only. A serve token handed to the Swamp executable can be carried across a redirect to an unpinned host, and nothing in this model can prevent that, so remote observation was removed rather than documented. Remove these arguments from the model configuration.`,
  );
}

/**
 * Refuse a Swamp executable whose meaning depends on where the run started.
 *
 * The child runs with `cwd: repoDir`, so a relative `swampBinary` such as
 * `./swamp` or `bin/swamp` names a file inside the observed repository — a
 * directory whose contents this model does not control and is not entitled to
 * execute. Worse, the resolution base for a relative program differs between
 * platforms, so the operator cannot even tell which file they asked for. A
 * bare name is resolved on PATH, an absolute path is unambiguous; nothing else
 * is accepted.
 */
function assertSwampBinary(binary: string): void {
  const bare = /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(binary);
  if (!bare && !binary.startsWith("/")) {
    throw new Error(
      "swampBinary must be a bare program name resolved on PATH or an absolute path; a relative path would resolve against the observed repository.",
    );
  }
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
      // Deliberately does not mention a configured credential: the child runs
      // with an isolated empty HOME, so there is no CLI configuration for it to
      // have taken one from.
      return "Swamp reported the command as unauthorized";
    case "timeout":
      return "Swamp interface did not respond before the timeout";
    case "unreachable":
      return "Swamp interface could not be reached";
    case "invalid-response":
      return "Swamp returned a response this interface could not validate";
    case "oversized":
      return "Swamp returned more output than this collector will read";
    case "unsupported":
      return "This Swamp build exposes no public serve-heartbeat query";
    default:
      return `Swamp command failed${
        code === undefined ? "" : ` (exit ${code})`
      }`;
  }
}

function unavailable(
  name: Observation["interface"],
  observedAt: string,
  kind: Observation["errorKind"],
  code?: number,
): Observation {
  return {
    interface: name,
    available: false,
    observedAt,
    errorKind: kind,
    error: safeError(kind, code),
    payload: null,
  };
}

async function query(
  g: GlobalArgs,
  name: Observation["interface"],
  args: string[],
  callerSignal: AbortSignal,
  runner: CommandRunner,
): Promise<Observation> {
  const observedAt = new Date().toISOString();
  const timeout = AbortSignal.timeout(g.timeoutMs);
  const signal = AbortSignal.any([callerSignal, timeout]);
  try {
    const result = await runner(
      g.swampBinary,
      [...args, "--json"],
      {
        cwd: g.repoDir,
        // Nothing to authenticate to: this model holds no credential.
        env: {},
        signal,
      },
    );
    if (callerSignal.aborted) throw callerSignal.reason;
    if (result.truncated) {
      return unavailable(name, observedAt, "oversized");
    }
    if (!result.success) {
      const kind = timeout.aborted
        ? "timeout"
        : classifyFailure(`${result.stderr}\n${result.stdout}`);
      return unavailable(name, observedAt, kind, result.code);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      return unavailable(name, observedAt, "invalid-response");
    }
    // Parsing proves the bytes were JSON, not that they were this interface's
    // answer. Only the projection is ever persisted; a response that cannot be
    // projected is a coverage gap, never a verbatim blob in the datastore.
    const payload = projectPayload(name, parsed);
    if (payload === undefined) {
      return unavailable(name, observedAt, "invalid-response");
    }
    return {
      interface: name,
      available: true,
      observedAt,
      errorKind: "",
      error: "",
      payload,
    };
  } catch (error) {
    if (callerSignal.aborted) throw error;
    const kind = timeout.aborted
      ? "timeout"
      : classifyFailure(error instanceof Error ? error.message : String(error));
    return unavailable(name, observedAt, kind);
  }
}

async function observe(
  _args: z.infer<typeof ObserveArgsSchema>,
  // deno-lint-ignore no-explicit-any
  ctx: any,
) {
  // Read the configuration as it was written, before zod strips the keys this
  // model no longer declares — a removed argument must be refused, not
  // silently ignored.
  assertLocalOnly(ctx.globalArgs);
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  // Runs before the first spawn: it describes a condition under which no
  // command should be launched at all.
  assertSwampBinary(g.swampBinary);
  const definitions = [
    ["run-history", ["run", "history", "--all"]],
    ["run-doctor", ["run", "doctor"]],
    ["workflow-history", ["workflow", "history", "search"]],
    ["stored-reports", ["report", "search"]],
  ] as const;

  // An override belongs only to this invocation. No importer can replace the
  // runner used by a later observation in the same process.
  const runner: CommandRunner = ctx.commandRunner ?? defaultRunner;
  const observations = await Promise.all(
    definitions.map(([name, args]) =>
      query(g, name, [...args], ctx.signal, runner)
    ),
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
  version: "2026.09.05.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    observation: {
      description:
        "One projected snapshot per documented local Swamp operational interface: counts, booleans, and statuses drawn from a fixed vocabulary. Response text and identifiers are dropped, errors are sanitized, and unavailable interfaces are retained explicitly.",
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
