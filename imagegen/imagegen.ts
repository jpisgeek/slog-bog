/** Local FLUX.1-schnell image generation. No shell or hosted inference API. */
import { z } from "npm:zod@4";

const absolute = z.string().min(2).max(4096).regex(/^\//).refine(
  (s) =>
    ![...s].some((character) => character.charCodeAt(0) < 32) &&
    !s.split("/").includes(".."),
  "Use an absolute path without traversal or control characters",
);
/** Validate trusted executable, local checkpoint, output root and time limit. */
export const GlobalArgsSchema = z.object({
  executable: absolute.describe("Trusted absolute path to mflux-generate"),
  modelPath: absolute.describe(
    "Prepared local FLUX.1-schnell 4-bit checkpoint directory",
  ),
  outputRoot: absolute.describe(
    "Existing private directory for new run folders",
  ),
  timeoutSeconds: z.number().int().min(1).max(7200).default(600),
}).strict();
/** Validate supported image controls and reject unknown controls. */
export const GenerateArgsSchema = z.object({
  prompt: z.string().min(1).max(8192),
  seed: z.number().int().min(0).max(4294967295).default(42),
  width: z.number().int().min(256).max(2048).multipleOf(64).default(1024),
  height: z.number().int().min(256).max(2048).multipleOf(64).default(1024),
  steps: z.number().int().min(1).max(50).default(4),
  imagePath: absolute.optional().describe(
    "Optional local reference PNG/JPEG; ordinary img2img, not identity preservation",
  ),
  imageStrength: z.number().min(0).max(1).default(0.4),
}).strict();
/** Swamp validates the union of global and method arguments at dispatch. */
export const SwampGenerateArgsSchema = GenerateArgsSchema.extend(
  GlobalArgsSchema.partial().shape,
);
/** Keep global configuration in the context; strip only known merged fields. */
export function executeGenerate(raw: unknown, ctx: Context) {
  const merged = SwampGenerateArgsSchema.parse(raw);
  const {
    executable: _executable,
    modelPath: _modelPath,
    outputRoot: _outputRoot,
    timeoutSeconds: _timeoutSeconds,
    ...methodArgs
  } = merged;
  return generate(methodArgs, ctx);
}
const ReceiptSchema = z.object({
  runId: z.string(),
  imagePath: z.string(),
  bytes: z.number().int(),
  sha256: z.string(),
  prompt: z.string(),
  seed: z.number().int(),
  width: z.number().int(),
  height: z.number().int(),
  steps: z.number().int(),
  model: z.literal("FLUX.1-schnell"),
  quantization: z.literal(4),
  offlineRequested: z.literal(true),
  completedAt: z.string(),
  referenceSha256: z.string().nullable(),
  imageStrength: z.number().nullable(),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;
type GenerateArgs = z.infer<typeof GenerateArgsSchema>;
interface Context {
  globalArgs: GlobalArgs;
  signal: AbortSignal;
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<unknown>;
}
/** Build a shell-free mflux argument vector from validated configuration. */
export function commandArgs(
  g: GlobalArgs,
  a: GenerateArgs,
  output: string,
): string[] {
  return [
    "--model",
    g.modelPath,
    "--base-model",
    "schnell",
    "--quantize",
    "4",
    "--prompt",
    a.prompt,
    "--seed",
    String(a.seed),
    "--steps",
    String(a.steps),
    "--width",
    String(a.width),
    "--height",
    String(a.height),
    "--output",
    output,
    ...(a.imagePath
      ? [
        "--image-path",
        a.imagePath,
        "--image-strength",
        String(a.imageStrength),
      ]
      : []),
  ];
}
async function hash(data: Uint8Array): Promise<string> {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>),
    ),
  ]
    .map((n) => n.toString(16).padStart(2, "0")).join("");
}
/** Reject symlinks in every component rather than following an output alias. */
async function checkedPath(path: string, directory: boolean): Promise<string> {
  let part = "";
  for (const component of path.split("/").filter(Boolean)) {
    part += `/${component}`;
    if ((await Deno.lstat(part)).isSymlink) {
      throw new Error("Symlink paths are not supported");
    }
  }
  const info = await Deno.stat(path);
  if (directory ? !info.isDirectory : !info.isFile) {
    throw new Error("Unexpected path type");
  }
  return await Deno.realPath(path);
}
/** Read declared PNG dimensions after validating its signature and IHDR marker. */
export function pngDimensions(
  bytes: Uint8Array,
): { width: number; height: number } {
  const signature = [137, 80, 78, 71, 13, 10, 26, 10];
  if (
    bytes.length < 33 || signature.some((n, i) => bytes[i] !== n) ||
    new TextDecoder().decode(bytes.slice(12, 16)) !== "IHDR"
  ) throw new Error("Output is not a PNG");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { width: view.getUint32(16), height: view.getUint32(20) };
}
/** Run local inference, verify the output and persist its provenance receipt. */
export async function generate(raw: unknown, ctx: Context) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const a = GenerateArgsSchema.parse(raw);
  ctx.signal.throwIfAborted();
  const executable = await checkedPath(g.executable, false);
  const modelPath = await checkedPath(g.modelPath, true);
  const outputRoot = await checkedPath(g.outputRoot, true);
  // Keep output private; a distinct directory prevents accidental replacement.
  const runId = crypto.randomUUID();
  const runDir = `${outputRoot}/${runId}`;
  let referenceSha256: string | null = null;
  if (a.imagePath) {
    a.imagePath = await checkedPath(a.imagePath, false);
    referenceSha256 = await hash(await Deno.readFile(a.imagePath));
  }
  await Deno.mkdir(runDir, { mode: 0o700 });
  const imagePath = `${runDir}/image.png`;
  const signal = AbortSignal.any([
    ctx.signal,
    AbortSignal.timeout(g.timeoutSeconds * 1000),
  ]);
  try {
    const result = await new Deno.Command(executable, {
      args: commandArgs({ ...g, modelPath }, a, imagePath),
      cwd: runDir,
      signal,
      stdin: "null",
      stdout: "null",
      stderr: "null",
      env: {
        HF_HUB_OFFLINE: "1",
        TRANSFORMERS_OFFLINE: "1",
        HF_HUB_DISABLE_TELEMETRY: "1",
        DO_NOT_TRACK: "1",
      },
    }).output();
    if (!result.success) {
      throw new Error(
        "Local generator failed; check installation and cached model assets",
      );
    }
    ctx.signal.throwIfAborted();
    await checkedPath(imagePath, false);
    const info = await Deno.stat(imagePath);
    if (info.size === 0 || info.size > 64 * 1024 * 1024) {
      throw new Error("Output size is invalid");
    }
    const bytes = await Deno.readFile(imagePath);
    const size = pngDimensions(bytes);
    if (size.width !== a.width || size.height !== a.height) {
      throw new Error("Output dimensions do not match request");
    }
    const receipt = ReceiptSchema.parse({
      runId,
      imagePath,
      bytes: bytes.length,
      sha256: await hash(bytes),
      prompt: a.prompt,
      seed: a.seed,
      width: a.width,
      height: a.height,
      steps: a.steps,
      model: "FLUX.1-schnell",
      quantization: 4,
      offlineRequested: true,
      completedAt: new Date().toISOString(),
      referenceSha256,
      imageStrength: a.imagePath ? a.imageStrength : null,
    });
    await Deno.writeTextFile(
      `${runDir}/provenance.json`,
      JSON.stringify(receipt, null, 2),
      { createNew: true, mode: 0o600 },
    );
    const handle = await ctx.writeResource("image", runId, receipt);
    return { dataHandles: [handle] };
  } catch {
    // Do not echo subprocess output, prompts, paths, or inherited secrets.
    // Keep partial artifacts for explicit operator inspection; do not claim success.
    throw new Error(
      signal.aborted
        ? "Image generation canceled or timed out"
        : "Image generation or Swamp receipt recording failed; inspect local artifacts",
    );
  }
}
/** Swamp behavior definition for local FLUX.1-schnell generation. */
export const model = {
  type: "@jpisgeek/imagegen",
  version: "2026.11.18.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    image: {
      description: "Private local image and reproducibility receipt",
      schema: ReceiptSchema,
      lifetime: "30d" as const,
      garbageCollection: 30,
    },
  },
  methods: {
    generate: {
      description:
        "Generate a local PNG from a prompt, optionally conditioned on a local image, using prepared schnell weights",
      arguments: SwampGenerateArgsSchema,
      execute: executeGenerate,
    },
  },
};
