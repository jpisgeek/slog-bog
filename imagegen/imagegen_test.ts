import {
  commandArgs,
  executeGenerate,
  generate,
  GenerateArgsSchema,
  GlobalArgsSchema,
  pngDimensions,
  SwampGenerateArgsSchema,
} from "./imagegen.ts";
function assert(value: unknown, message = "assertion failed"): asserts value {
  if (!value) throw new Error(message);
}
const config = {
  executable: "/example/runtime/mflux-generate",
  modelPath: "/example/models/schnell-q4",
  outputRoot: "/example/output",
  timeoutSeconds: 30,
};
Deno.test("defaults reproduce schnell four-step preset", () => {
  const a = GenerateArgsSchema.parse({ prompt: "swamp mascot" });
  assert(a.steps === 4 && a.width === 1024 && a.seed === 42);
});
Deno.test("prompt remains one argv value, never a shell command", () => {
  const a = GenerateArgsSchema.parse({
    prompt: "$(touch /example/unwanted); ' \"",
  });
  const args = commandArgs(config, a, "/example/output/image.png");
  assert(args[args.indexOf("--prompt") + 1] === a.prompt);
  assert(args[args.indexOf("--quantize") + 1] === "4");
  assert(!args.includes("--image-strength"));
});
Deno.test("reference parameters are explicit", () => {
  const a = GenerateArgsSchema.parse({
    prompt: "swamp",
    imagePath: "/example/input.png",
    imageStrength: 0.6,
  });
  const args = commandArgs(config, a, "/example/output/image.png");
  assert(args.includes("--image-path") && args.includes("0.6"));
});
Deno.test("reject unsafe paths and invalid sizes", () => {
  for (const path of ["relative", "/example/../private", "/example/\nfile"]) {
    assert(!GlobalArgsSchema.safeParse({ ...config, modelPath: path }).success);
  }
  for (const width of [0, 257, 4096]) {
    assert(!GenerateArgsSchema.safeParse({ prompt: "x", width }).success);
  }
  assert(!GenerateArgsSchema.safeParse({ prompt: "x", seed: -1 }).success);
  assert(
    !GenerateArgsSchema.safeParse({ prompt: "x", imageStrength: 2 }).success,
  );
});
Deno.test("reject unknown controls rather than pretend negative prompts work", () => {
  assert(
    !GenerateArgsSchema.safeParse({ prompt: "x", negativePrompt: "bad" })
      .success,
  );
});
Deno.test("PNG header dimensions and invalid header", () => {
  const data = new Uint8Array(33);
  data.set([137, 80, 78, 71, 13, 10, 26, 10]);
  data.set(new TextEncoder().encode("IHDR"), 12);
  new DataView(data.buffer).setUint32(16, 1024);
  new DataView(data.buffer).setUint32(20, 1024);
  assert(pngDimensions(data).width === 1024);
  let failed = false;
  try {
    pngDimensions(new Uint8Array(33));
  } catch {
    failed = true;
  }
  assert(failed);
});
Deno.test("aborted operation never invokes generator or records success", async () => {
  const control = new AbortController();
  control.abort();
  let writes = 0;
  try {
    await generate({ prompt: "x" }, {
      globalArgs: config,
      signal: control.signal,
      writeResource: () => {
        writes++;
        return Promise.resolve(undefined);
      },
    });
  } catch { /* expected */ }
  assert(writes === 0);
});
Deno.test("failed subprocess never records success", async () => {
  const root = await Deno.makeTempDir();
  let writes = 0;
  let failed = false;
  try {
    await generate({ prompt: "x" }, {
      globalArgs: {
        ...config,
        executable: "/usr/bin/false",
        modelPath: root,
        outputRoot: root,
      },
      signal: new AbortController().signal,
      writeResource: () => {
        writes++;
        return Promise.resolve(undefined);
      },
    });
  } catch {
    failed = true;
  } finally {
    await Deno.remove(root, { recursive: true });
  }
  assert(failed && writes === 0);
});

async function fixture(
  mode: string,
  callback: (root: string, executable: string) => Promise<void>,
) {
  const root = await Deno.makeTempDir();
  const executable = `${root}/fake-mflux`;
  const code =
    `#!/usr/bin/env -S ${Deno.execPath()} run --allow-env --allow-write
if (Deno.env.get("HF_HUB_OFFLINE") !== "1" || Deno.env.get("TRANSFORMERS_OFFLINE") !== "1") Deno.exit(3);
const args = Deno.args;
if (args[args.indexOf("--base-model") + 1] !== "schnell" || args[args.indexOf("--quantize") + 1] !== "4") Deno.exit(4);
const out = args[args.indexOf("--output") + 1];
if (${
      JSON.stringify(mode)
    } === "timeout") await new Promise(r => setTimeout(r, 10000));
if (${JSON.stringify(mode)} !== "missing") {
const data = new Uint8Array(33); data.set([137,80,78,71,13,10,26,10]);
data.set(new TextEncoder().encode("IHDR"), 12);
new DataView(data.buffer).setUint32(16, ${
      mode === "wrong-size"
        ? "512"
        : "Number(args[args.indexOf('--width') + 1])"
    });
new DataView(data.buffer).setUint32(20, Number(args[args.indexOf('--height') + 1]));
await Deno.writeFile(out, data);
}
`;
  await Deno.writeTextFile(executable, code, { mode: 0o700 });
  try {
    await callback(root, executable);
  } finally {
    await Deno.remove(root, { recursive: true });
  }
}
Deno.test("fake generator success checks argv, offline env and private receipt", async () => {
  await fixture("success", async (root, executable) => {
    let receipt: Record<string, unknown> = {};
    const result = await generate({ prompt: "$(do not execute); swamp" }, {
      globalArgs: { ...config, executable, modelPath: root, outputRoot: root },
      signal: new AbortController().signal,
      writeResource: (spec, name, data) => {
        assert(spec === "image" && name === data.runId);
        receipt = data;
        return Promise.resolve("test-handle");
      },
    });
    assert(result.dataHandles[0] === "test-handle");
    assert(receipt.bytes === 33 && receipt.offlineRequested === true);
    assert(String(receipt.sha256).length === 64);
    const provenance = JSON.parse(
      await Deno.readTextFile(`${root}/${receipt.runId}/provenance.json`),
    );
    assert(
      provenance.sha256 === receipt.sha256 &&
        provenance.prompt === "$(do not execute); swamp",
    );
  });
});
for (const mode of ["wrong-size", "missing", "timeout"]) {
  Deno.test(`fake generator ${mode} cannot produce a success receipt`, async () => {
    await fixture(mode, async (root, executable) => {
      let writes = 0;
      let failed = false;
      try {
        await generate({ prompt: "x" }, {
          globalArgs: {
            ...config,
            executable,
            modelPath: root,
            outputRoot: root,
            timeoutSeconds: 1,
          },
          signal: new AbortController().signal,
          writeResource: () => {
            writes++;
            return Promise.resolve(undefined);
          },
        });
      } catch {
        failed = true;
      }
      assert(failed && writes === 0);
    });
  });
}

Deno.test("Swamp dispatch accepts known merged globals but rejects unknown controls", () => {
  assert(
    SwampGenerateArgsSchema.safeParse({ ...config, prompt: "swamp" }).success,
  );
  assert(
    !SwampGenerateArgsSchema.safeParse({
      ...config,
      prompt: "swamp",
      guidance: 9,
    }).success,
  );
});
Deno.test("Swamp merged-argument execution records a successful receipt", async () => {
  await fixture("success", async (root, executable) => {
    const globalArgs = {
      ...config,
      executable,
      modelPath: root,
      outputRoot: root,
    };
    const result = await executeGenerate({ ...globalArgs, prompt: "swamp" }, {
      globalArgs,
      signal: new AbortController().signal,
      writeResource: () => Promise.resolve("merged-handle"),
    });
    assert(result.dataHandles[0] === "merged-handle");
  });
});
