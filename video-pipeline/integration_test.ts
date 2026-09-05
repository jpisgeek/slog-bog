/** Execute the real adapter against a real, stdlib-only synthetic bridge. */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { model } from "./video_pipeline.ts";

type Context = Parameters<typeof model.methods.prepare.execute>[1];
type Stage = keyof typeof model.methods;
const stages: Stage[] = [
  "prepare",
  "narrate",
  "render",
  "inspect",
  "package",
  "verify",
  "deliver",
];

/** Discover a runtime executable; no developer-specific Python path is stored. */
async function python3(): Promise<string> {
  for (const folder of (Deno.env.get("PATH") ?? "").split(":")) {
    if (!folder.startsWith("/")) continue;
    try {
      const path = await Deno.realPath(`${folder}/python3`);
      const stat = await Deno.stat(path);
      if (stat.isFile && (stat.mode === null || (stat.mode & 0o111) !== 0)) {
        return path;
      }
    } catch { /* Keep searching PATH. */ }
  }
  throw new Error("The synthetic integration example requires python3 on PATH");
}

async function fixture() {
  const root = await Deno.realPath(
    await Deno.makeTempDir({ prefix: "video-pipeline-example-" }),
  );
  await Deno.mkdir(`${root}/build`);
  for (
    const [source, relative] of [
      ["scenes.json", "scenes.json"],
      ["build/swamp-step.py.txt", "build/swamp-step.py"],
    ]
  ) {
    await Deno.copyFile(
      new URL(`./examples/synthetic/${source}`, import.meta.url),
      `${root}/${relative}`,
    );
  }
  const receipts = new Map<string, Record<string, unknown>>();
  const context: Context = {
    globalArgs: {
      workspaceRoot: root,
      pythonBin: await python3(),
      release: "v1",
      deliveryFolders: [`${root}/deliveries/example`],
      timeoutSeconds: 60,
    },
    signal: new AbortController().signal,
    logger: { info() {} },
    readResource(name) {
      return Promise.resolve(receipts.get(name) ?? null);
    },
    writeResource(spec, name, data) {
      assertEquals(spec, name);
      receipts.set(name, structuredClone(data));
      return Promise.resolve({ name });
    },
  };
  async function run(stage: Stage) {
    const args = {
      inputHash: receipts.get("prepare")?.inputHash,
      videoSha256: receipts.get("verify")?.videoSha256,
    };
    const method = model.methods[stage] as {
      execute(args: unknown, context: Context): Promise<unknown>;
    };
    return await method.execute(args, context);
  }
  return {
    root,
    receipts,
    context,
    run,
    close: () => Deno.remove(root, { recursive: true }),
  };
}

Deno.test("synthetic fixture: all seven stages retain valid receipts and deliver text only", async () => {
  const example = await fixture();
  try {
    for (const stage of stages) await example.run(stage);
    assertEquals([...example.receipts.keys()], stages);
    for (const stage of stages) {
      const receipt = example.receipts.get(stage)!;
      const metrics = receipt.metrics as Record<string, unknown>;
      assertEquals(metrics.verified, true);
      assertEquals(metrics.durationSeconds, null);
      assertEquals(metrics.clippedSamples, null);
      const artifacts = receipt.artifacts as { path: string }[];
      assertEquals(metrics.fileCount, artifacts.length);
      for (const artifact of artifacts) {
        assert(artifact.path.startsWith(`${example.root}/`));
        assert(artifact.path.endsWith(".txt"));
        assert(
          (await Deno.readTextFile(artifact.path)).startsWith(
            "SYNTHETIC CONTRACT FIXTURE:",
          ),
        );
      }
    }
    assertEquals(
      example.receipts.get("deliver")!.videoSha256,
      example.receipts.get("verify")!.videoSha256,
    );
    assertEquals(
      await Deno.readTextFile(
        `${example.root}/deliveries/example/synthetic-video.txt`,
      ),
      await Deno.readTextFile(
        `${example.root}/example-output/v1/synthetic-video.txt`,
      ),
    );
  } finally {
    await example.close();
  }
});

Deno.test("synthetic bridge: an outside delivery destination creates no files", async () => {
  const example = await fixture();
  const outside = await Deno.realPath(
    await Deno.makeTempDir({ prefix: "video-pipeline-outside-" }),
  );
  try {
    for (const stage of stages.slice(0, -1)) await example.run(stage);
    example.context.globalArgs.deliveryFolders = [`${outside}/must-not-exist`];
    await assertRejects(() => example.run("deliver"));
    assertEquals(await collect(outside), []);
    assertEquals(example.receipts.has("deliver"), false);
  } finally {
    await example.close();
    await Deno.remove(outside, { recursive: true });
  }
});

async function collect(path: string): Promise<Deno.DirEntry[]> {
  const entries = [];
  for await (const entry of Deno.readDir(path)) entries.push(entry);
  return entries;
}

Deno.test("synthetic bridge: modified scene input invalidates the prepared hash", async () => {
  const example = await fixture();
  try {
    await example.run("prepare");
    await Deno.writeTextFile(`${example.root}/scenes.json`, "\n", {
      append: true,
    });
    await assertRejects(() => example.run("narrate"));
    assertEquals(example.receipts.has("narrate"), false);
  } finally {
    await example.close();
  }
});
