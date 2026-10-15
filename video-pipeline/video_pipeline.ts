/**
 * Runs the operator-supplied video project bridge and records validated stage receipts.
 *
 * This adapter exposes typed Swamp methods and resources. It is not a renderer. Every stage
 * after preparation requires its dependencies' stored receipts and rechecks the
 * recorded artifacts before invoking the fixed Python bridge. The operator supplies the trusted executable and build/swamp-step.py.
 * That bridge owns artifact creation, content hashing, media verification,
 * process cleanup, and destination policy. This adapter is not a sandbox.
 *
 * @module
 */
import { z } from "npm:zod@4";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { kill } from "node:process";
import { Readable } from "node:stream";

const stages = [
  "prepare",
  "narrate",
  "render",
  "inspect",
  "package",
  "verify",
  "deliver",
] as const;

type Stage = typeof stages[number];
type DependentStage = Exclude<Stage, "prepare">;

const dependencies: Record<DependentStage, readonly Stage[]> = {
  narrate: ["prepare"],
  render: ["prepare", "narrate"],
  inspect: ["prepare", "narrate", "render"],
  package: ["prepare", "narrate", "inspect"],
  verify: ["prepare", "narrate", "inspect", "package"],
  deliver: ["prepare", "inspect", "verify"],
};

const HashSchema = z.string().regex(/^[0-9a-f]{64}$/);
const ReleaseSchema = z.string().regex(/^v[0-9]+$/);

/** Accept explicit POSIX paths without traversal, control characters, or root. */
function isAbsolutePath(value: string): boolean {
  return value.startsWith("/") && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value) &&
    value.slice(1).split("/").every((part) =>
      part !== "" && part !== "." && part !== ".."
    );
}

const AbsolutePathSchema = z.string().refine(isAbsolutePath, {
  message:
    "Use a canonical non-root absolute POSIX path without traversal or control characters",
});

const GlobalArgsSchema = z.object({
  workspaceRoot: AbsolutePathSchema.describe(
    "Operator-owned project containing scenes.json and build/swamp-step.py",
  ),
  pythonBin: AbsolutePathSchema.describe(
    "Trusted Python executable; inherits the operator environment",
  ),
  release: ReleaseSchema.describe("Numbered project release, such as v1"),
  deliveryFolders: z.array(AbsolutePathSchema).refine(
    (folders) =>
      folders.every((folder, index) =>
        !folders.some((other, otherIndex) =>
          index !== otherIndex &&
          (folder === other || folder.startsWith(`${other}/`))
        )
      ),
    { message: "Delivery folders must be distinct and non-overlapping" },
  ).describe("Explicit canonical folders permitted for delivery receipts"),
  timeoutSeconds: z.number().int().positive().max(2147483).default(600)
    .describe("Time limit for each bridge invocation"),
}).strict();

// Swamp validates a merged global+method input; strip known-global extras here.
const PrepareArgsSchema = z.object({});
const StepArgsSchema = z.object({ inputHash: HashSchema });
const DeliverArgsSchema = z.object({
  inputHash: HashSchema,
  videoSha256: HashSchema,
});

const StageReceiptSchema = z.object({
  stage: z.enum(stages),
  release: ReleaseSchema,
  inputHash: HashSchema,
  completedAt: z.iso.datetime({ offset: true }),
  artifacts: z.array(
    z.object({
      path: AbsolutePathSchema,
      bytes: z.number().int().positive(),
      sha256: HashSchema,
    }).strict(),
  ).min(1),
  videoSha256: HashSchema.nullable(),
  metrics: z.object({
    durationSeconds: z.number().nonnegative().nullable(),
    clippedSamples: z.number().int().nonnegative().nullable(),
    fileCount: z.number().int().nonnegative(),
    verified: z.boolean(),
  }).strict(),
}).strict();

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;
type PrepareArgs = z.infer<typeof PrepareArgsSchema>;
type StepArgs = z.infer<typeof StepArgsSchema>;
type DeliverArgs = z.infer<typeof DeliverArgsSchema>;
type StageReceipt = z.infer<typeof StageReceiptSchema>;
type DataHandle = { name: string };
type MethodResult = { dataHandles: DataHandle[] };

/** The subset of the Swamp method context used by this model. */
interface MethodContext {
  globalArgs: GlobalArgs;
  signal: AbortSignal;
  logger: {
    info: (message: string, properties: Record<string, unknown>) => void;
  };
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
  readResource: (name: string) => Promise<Record<string, unknown> | null>;
}

/** Require a file's resolved location to stay within the resolved workspace. */
async function containedFile(root: string, relative: string): Promise<string> {
  const path = `${root}/${relative}`;
  const real = await Deno.realPath(path);
  if (!real.startsWith(`${root}/`)) {
    throw new Error(
      `Required pipeline file escapes the workspace: ${relative}`,
    );
  }
  const stat = await Deno.stat(real);
  if (!stat.isFile) {
    throw new Error(
      `Required pipeline path is not a regular file: ${relative}`,
    );
  }
  return real;
}

/** Resolve the configured workspace and verify its fixed pipeline entry points. */
async function checkBoundary(args: GlobalArgs): Promise<{
  root: string;
  bridge: string;
  python: string;
  destinations: string[];
}> {
  const root = await Deno.realPath(args.workspaceRoot);
  if (root === "/" || !(await Deno.stat(root)).isDirectory) {
    throw new Error("workspaceRoot must resolve to a non-root directory");
  }
  await containedFile(root, "scenes.json");
  const bridge = await containedFile(root, "build/swamp-step.py");
  const python = await Deno.realPath(args.pythonBin);
  const executable = await Deno.stat(python);
  if (
    !executable.isFile ||
    (executable.mode !== null && (executable.mode & 0o111) === 0)
  ) {
    throw new Error("pythonBin must resolve to a regular executable file");
  }
  const destinations: string[] = [];
  const ancestry: string[][] = [];
  for (const folder of args.deliveryFolders) {
    // Missing names cannot be distinguished from case/Unicode aliases until
    // the filesystem creates them. Require pre-existing canonical directories.
    const real = await Deno.realPath(folder);
    if (real === "/" || real !== folder) {
      throw new Error("Delivery folder must be canonical and non-root");
    }
    const identities: string[] = [];
    let ancestor = folder;
    while (true) {
      const info = await Deno.stat(ancestor);
      if (!info.isDirectory || info.dev === null || info.ino === null) {
        throw new Error("Delivery directory identity is unavailable");
      }
      identities.push(`${info.dev}:${info.ino}`);
      if (ancestor === "/") break;
      ancestor = ancestor.slice(0, ancestor.lastIndexOf("/")) || "/";
    }
    destinations.push(real);
    ancestry.push(identities);
  }
  if (
    ancestry.some((parents, index) =>
      ancestry.some((other, otherIndex) =>
        index !== otherIndex && parents.includes(other[0])
      )
    )
  ) {
    throw new Error("Delivery directories must not alias or overlap");
  }
  return { root, bridge, python, destinations };
}

/** Reject traversal and symbolic links in an artifact or any of its ancestors. */
async function checkedArtifactPath(
  root: string,
  path: string,
): Promise<string> {
  if (!isAbsolutePath(path) || !path.startsWith(`${root}/`)) {
    throw new Error("Artifact is outside its authorized directory");
  }
  const parts = path.slice(root.length + 1).split("/");
  if (parts.some((part) => part.length === 0)) {
    throw new Error(
      "Predecessor artifact path must use single path separators",
    );
  }
  let ancestor = "";
  const absoluteParts = path.slice(1).split("/");
  for (let index = 0; index < absoluteParts.length; index++) {
    ancestor = `${ancestor}/${absoluteParts[index]}`;
    const stat = await Deno.lstat(ancestor);
    if (stat.isSymlink) {
      throw new Error("Artifact or ancestor is a symbolic link");
    }
    if (index < absoluteParts.length - 1 && !stat.isDirectory) {
      throw new Error("Artifact ancestor is not a directory");
    }
    if (index === absoluteParts.length - 1 && !stat.isFile) {
      throw new Error("Artifact is not a regular file");
    }
  }
  const real = await Deno.realPath(path);
  if (!real.startsWith(`${root}/`)) {
    throw new Error("Artifact resolves outside its authorized directory");
  }
  return real;
}

/** Validate real files without exposing private artifact paths in error logs. */
async function checkArtifacts(
  receipt: StageReceipt,
  roots: readonly string[],
  signal: AbortSignal,
): Promise<void> {
  if (
    !receipt.metrics.verified ||
    receipt.metrics.fileCount !== receipt.artifacts.length
  ) {
    throw new Error("Receipt has unverified or inconsistent artifacts");
  }
  const seen = new Set<string>();
  try {
    for (const artifact of receipt.artifacts) {
      signal.throwIfAborted();
      if (seen.has(artifact.path)) {
        throw new Error("Receipt repeats an artifact path");
      }
      seen.add(artifact.path);
      const root = roots.find((candidate) =>
        artifact.path.startsWith(`${candidate}/`)
      );
      if (!root) {
        throw new Error("Artifact is outside its authorized directory");
      }
      const real = await checkedArtifactPath(root, artifact.path);
      const file = await Deno.open(real, { read: true });
      try {
        const stat = await file.stat();
        if (!stat.isFile || stat.size !== artifact.bytes) {
          throw new Error("Artifact size changed");
        }
        const hash = createHash("sha256");
        const buffer = new Uint8Array(64 * 1024);
        let total = 0;
        while (true) {
          signal.throwIfAborted();
          const count = await file.read(buffer);
          signal.throwIfAborted();
          if (count === null) break;
          total += count;
          if (total > artifact.bytes) throw new Error("Artifact size changed");
          hash.update(buffer.subarray(0, count));
        }
        if (total !== artifact.bytes) throw new Error("Artifact size changed");
        if (hash.digest("hex") !== artifact.sha256) {
          throw new Error("Artifact content changed");
        }
      } finally {
        file.close();
      }
      await checkedArtifactPath(root, artifact.path);
    }
  } catch (error) {
    signal.throwIfAborted();
    if (error instanceof Error && Object.hasOwn(Deno.errors, error.name)) {
      throw new Error("Receipt artifact cannot be read or verified");
    }
    throw error;
  }
  signal.throwIfAborted();
}

/** Parse a bridge receipt without echoing its potentially sensitive payload. */
function parseReceipt(value: unknown): StageReceipt {
  const parsed = StageReceiptSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error("Bridge receipt does not satisfy the stage schema");
  }
  return parsed.data;
}

/** Verify the current bytes recorded in a required stage's Swamp resource. */
async function checkDependency(
  predecessor: Stage,
  inputHash: string,
  release: string,
  root: string,
  context: MethodContext,
): Promise<StageReceipt> {
  const stored = await context.readResource(predecessor);
  if (stored === null) {
    throw new Error(`Required Swamp resource is missing: ${predecessor}`);
  }
  const receipt = parseReceipt(stored);
  if (
    receipt.stage !== predecessor || receipt.inputHash !== inputHash ||
    receipt.release !== release
  ) {
    throw new Error(
      "Predecessor resource does not match this stage's inputs and release",
    );
  }
  await checkArtifacts(receipt, [root], context.signal);
  context.signal.throwIfAborted();
  return receipt;
}

/** Execute one fixed bridge stage, then persist only a valid matching receipt. */
async function runStage(
  stage: Stage,
  args: PrepareArgs | StepArgs | DeliverArgs,
  context: MethodContext,
): Promise<MethodResult> {
  context.signal.throwIfAborted();
  const globals = GlobalArgsSchema.parse(context.globalArgs);
  const methodArgs: { inputHash?: string; videoSha256?: string } =
    stage === "prepare"
      ? PrepareArgsSchema.parse(args)
      : stage === "deliver"
      ? DeliverArgsSchema.parse(args)
      : StepArgsSchema.parse(args);
  // Stage names remain stable for CEL consumers. Bind the instance to one
  // immutable release/input pair instead of letting a new preparation replace
  // the identity underneath its later receipts. Swamp serializes model runs.
  const prepared = stage === "prepare"
    ? await context.readResource("prepare")
    : null;
  const binding = prepared === null ? null : parseReceipt(prepared);
  if (
    binding &&
    (binding.stage !== "prepare" || binding.release !== globals.release)
  ) {
    throw new Error(
      "Prepared release is immutable; create a new model instance",
    );
  }
  let boundary: Awaited<ReturnType<typeof checkBoundary>>;
  try {
    boundary = await checkBoundary(globals);
  } catch {
    context.signal.throwIfAborted();
    throw new Error("Project bridge or executable boundary validation failed");
  }
  const { root, bridge, python, destinations } = boundary;
  const commandArgs = [bridge, stage, "--release", globals.release];
  let verified: StageReceipt | undefined;
  if (stage !== "prepare") {
    for (const dependency of dependencies[stage]) {
      const receipt = await checkDependency(
        dependency,
        methodArgs.inputHash!,
        globals.release,
        root,
        context,
      );
      if (
        stage === "deliver" && dependency === "verify" &&
        receipt.videoSha256 !== methodArgs.videoSha256
      ) {
        throw new Error(
          "Requested delivery video hash differs from Swamp verification",
        );
      }
      if (stage === "deliver" && dependency === "verify") verified = receipt;
    }
    commandArgs.push("--input-hash", methodArgs.inputHash!);
  }
  if (stage === "deliver") {
    if (globals.deliveryFolders.length === 0) {
      throw new Error(
        "deliver requires at least one configured delivery folder",
      );
    }
    commandArgs.push("--video-sha256", methodArgs.videoSha256!);
    for (const destination of destinations) {
      commandArgs.push("--destination", destination);
    }
  }

  context.signal.throwIfAborted();
  context.logger.info("Starting Video pipeline stage {stage} for {release}", {
    stage,
    release: globals.release,
    inputHash: methodArgs.inputHash ?? null,
  });
  const timeout = new AbortController();
  const timer = setTimeout(
    () => timeout.abort(),
    globals.timeoutSeconds * 1000,
  );
  const signal = AbortSignal.any([context.signal, timeout.signal]);
  let result: Pick<Deno.CommandOutput, "success" | "code" | "stdout">;
  let receiptTooLarge = false;
  try {
    // Node's POSIX detached mode creates a process group atomically at spawn.
    // Deno.Command has no equivalent: killing only Python can orphan renderers.
    const child = spawn(python, commandArgs, {
      cwd: root,
      detached: true,
      // Diagnostics are not receipt data and must not be buffered or exposed.
      stdio: ["ignore", "pipe", "ignore"],
    });
    const status = new Promise<{ success: boolean; code: number }>(
      (resolve) => {
        child.once("error", () => resolve({ success: false, code: -1 }));
        child.once(
          "exit",
          (code) => resolve({ success: code === 0, code: code ?? -1 }),
        );
      },
    );
    if (child.pid === undefined || child.stdout === null) {
      await status;
      throw new Error("Bridge did not start");
    }
    const pid = child.pid;
    const reader = Readable.toWeb(child.stdout).getReader();
    let stopping: Promise<void> | undefined;
    const stop = () => {
      if (stopping) return;
      const terminate = (signal: "SIGTERM" | "SIGKILL") => {
        try {
          kill(-pid, signal);
        } catch {
          // Also handles a child that failed before establishing its group.
          try {
            child.kill(signal);
          } catch { /* Already exited. */ }
        }
      };
      terminate("SIGTERM");
      void reader.cancel().catch(() => {});
      // Give bridge cleanup handlers a bounded chance, then stop resistant
      // descendants even when their parent exited immediately on SIGTERM.
      stopping = new Promise((resolve) => {
        setTimeout(() => {
          terminate("SIGKILL");
          resolve();
        }, 500);
      });
    };
    signal.addEventListener("abort", stop, { once: true });
    if (signal.aborted) stop();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    let exit: Awaited<typeof status>;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > 4 * 1024 * 1024) {
          receiptTooLarge = true;
          stop();
          break;
        }
        chunks.push(value);
      }
      exit = await status;
    } catch (error) {
      stop();
      await status;
      throw error;
    } finally {
      signal.removeEventListener("abort", stop);
      await stopping;
      await reader.cancel().catch(() => {});
    }
    const stdout = new Uint8Array(receiptTooLarge ? 0 : bytes);
    let offset = 0;
    if (!receiptTooLarge) {
      for (const chunk of chunks) {
        stdout.set(chunk, offset);
        offset += chunk.byteLength;
      }
    }
    result = { success: exit.success, code: exit.code, stdout };
  } catch {
    context.signal.throwIfAborted();
    if (timeout.signal.aborted) {
      throw new Error(`Video pipeline stage ${stage} timed out`);
    }
    throw new Error(
      `Could not execute the configured bridge for stage ${stage}`,
    );
  } finally {
    clearTimeout(timer);
  }
  context.signal.throwIfAborted();
  if (timeout.signal.aborted) {
    throw new Error(`Video pipeline stage ${stage} timed out`);
  }
  if (receiptTooLarge) {
    throw new Error("Bridge receipt exceeded the four-MiB output limit");
  }
  const decoder = new TextDecoder("utf-8", { fatal: true });
  if (!result.success) {
    throw new Error(
      `Video pipeline stage ${stage} exited ${result.code}; inspect the operator-owned bridge locally for diagnostics`,
    );
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(decoder.decode(result.stdout));
  } catch {
    throw new Error(`Video pipeline stage ${stage} returned invalid JSON`);
  }
  const payload = parseReceipt(decoded);
  if (payload.metrics.fileCount !== payload.artifacts.length) {
    throw new Error("Bridge receipt artifact count does not match its metrics");
  }
  if (payload.stage !== stage || payload.release !== globals.release) {
    throw new Error(
      "Bridge receipt does not match the requested stage and release",
    );
  }
  if (stage !== "prepare" && payload.inputHash !== methodArgs.inputHash) {
    throw new Error("Bridge receipt input hash does not match this invocation");
  }
  if (binding && payload.inputHash !== binding.inputHash) {
    throw new Error(
      "Prepared inputs are immutable; create a new model instance",
    );
  }
  if (stage === "deliver" && payload.videoSha256 !== methodArgs.videoSha256) {
    throw new Error(
      "Delivery receipt video hash does not match the verified video",
    );
  }
  if (
    ["render", "inspect", "package", "verify", "deliver"].includes(stage) &&
    payload.videoSha256 === null
  ) {
    throw new Error("Video-producing stage must record its video hash");
  }
  if (
    payload.videoSha256 !== null &&
    !payload.artifacts.some((artifact) =>
      artifact.sha256 === payload.videoSha256
    )
  ) {
    throw new Error("Recorded video hash must identify a receipt artifact");
  }
  const outputRoots = stage === "deliver" ? destinations : [root];
  await checkArtifacts(payload, outputRoots, context.signal);
  if (stage === "deliver") {
    for (const artifact of payload.artifacts) {
      if (
        !verified!.artifacts.some((prior) =>
          prior.sha256 === artifact.sha256 && prior.bytes === artifact.bytes
        )
      ) {
        throw new Error(
          "Delivery contains an artifact absent from verification",
        );
      }
    }
    for (const destination of destinations) {
      if (
        !payload.artifacts.some((artifact) =>
          artifact.path.startsWith(`${destination}/`) &&
          artifact.sha256 === verified!.videoSha256
        )
      ) {
        throw new Error(
          "Delivery is missing a verified video copy at a destination",
        );
      }
    }
  }

  context.signal.throwIfAborted();
  const handle = await context.writeResource(stage, stage, payload);
  context.logger.info("Completed Video pipeline stage {stage} for {release}", {
    stage,
    release: payload.release,
    inputHash: payload.inputHash,
    videoSha256: payload.videoSha256,
    fileCount: payload.metrics.fileCount,
    verified: payload.metrics.verified,
  });
  return { dataHandles: [handle] };
}

/** Declare a retained receipt for one film production stage. */
function resource(description: string) {
  return {
    description,
    schema: StageReceiptSchema,
    lifetime: "infinite" as const,
    garbageCollection: 5,
  };
}

/** Declare one input-hash-bound stage that accepts no free-form command data. */
function method(
  stage: Exclude<Stage, "prepare" | "deliver">,
  description: string,
) {
  return {
    description,
    arguments: StepArgsSchema,
    execute: (args: StepArgs, context: MethodContext): Promise<MethodResult> =>
      runStage(stage, args, context),
  };
}

/** One operator-owned video project, with an auditable resource for every production stage. */
export const model = {
  type: "@jpisgeek/video-pipeline",
  version: "2026.10.14.1",
  upgrades: [{
    toVersion: "2026.10.14.1",
    description: "Registry release; existing project arguments are unchanged",
    upgradeAttributes: (attributes: Record<string, unknown>) => attributes,
  }],
  globalArguments: GlobalArgsSchema,
  checks: {
    "project-boundary": {
      description:
        "Require the operator-owned project bridge and trusted executable",
      labels: ["policy"],
      execute: async (context: { globalArgs: GlobalArgs }) => {
        try {
          await checkBoundary(GlobalArgsSchema.parse(context.globalArgs));
          return { pass: true };
        } catch {
          return {
            pass: false,
            errors: ["Project bridge or executable boundary validation failed"],
          };
        }
      },
    },
  },
  resources: {
    prepare: resource("Prepared source manifest and content hash"),
    narrate: resource("Local neural narration artifacts"),
    render: resource("Animated film render artifacts"),
    inspect: resource("Decoded film inspection artifacts"),
    package: resource("Shareable video and companion package artifacts"),
    verify: resource("Verified release artifacts and metrics"),
    deliver: resource("Verified copies in the configured delivery folders"),
  },
  methods: {
    prepare: {
      description: "Prepare and hash the fixed film production inputs",
      arguments: PrepareArgsSchema,
      execute: (
        args: PrepareArgs,
        context: MethodContext,
      ): Promise<MethodResult> => runStage("prepare", args, context),
    },
    narrate: method("narrate", "Synthesize the approved narration locally"),
    render: method(
      "render",
      "Render the animation against the prepared inputs",
    ),
    inspect: method("inspect", "Decode frames and inspect the rendered film"),
    package: method(
      "package",
      "Package the selected film release and companions",
    ),
    verify: method("verify", "Verify the release, audio, and artifact hashes"),
    deliver: {
      description:
        "Copy the verified release to the configured delivery folders",
      arguments: DeliverArgsSchema,
      execute: (
        args: DeliverArgs,
        context: MethodContext,
      ): Promise<MethodResult> => runStage("deliver", args, context),
    },
  },
};
