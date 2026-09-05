import { model } from "./video_pipeline.ts";

const inputHash = "a".repeat(64);
const otherHash = "b".repeat(64);
const decoder = new TextDecoder();
const pythonLookup = await new Deno.Command("python3", {
  args: ["-c", "import sys; print(sys.executable)"],
  stdout: "piped",
  stderr: "null",
}).output();
if (!pythonLookup.success) throw new Error("Tests require Python 3 on PATH");
const pythonBin = await Deno.realPath(
  decoder.decode(pythonLookup.stdout).trim(),
);

async function fixture() {
  const root = await Deno.realPath(
    await Deno.makeTempDir({ prefix: "video-pipeline-test-" }),
  );
  await Deno.mkdir(`${root}/build`);
  await Deno.writeTextFile(`${root}/scenes.json`, "[]");
  const artifact = `${root}/artifact.txt`;
  await Deno.writeTextFile(artifact, "alpha");
  const hash = await crypto.subtle.digest(
    "SHA-256",
    await Deno.readFile(artifact),
  );
  const sha256 = Array.from(
    new Uint8Array(hash),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
  const receipt = {
    stage: "prepare",
    release: "v1",
    inputHash,
    completedAt: "2026-01-01T00:00:00Z",
    artifacts: [{ path: artifact, bytes: 5, sha256 }],
    videoSha256: null as string | null,
    metrics: {
      durationSeconds: null,
      clippedSamples: null,
      fileCount: 1,
      verified: true,
    },
  };
  const output = structuredClone({ ...receipt, stage: "narrate" });
  const marker = `${root}/started`;
  const writeBridge = async (body?: string) => {
    const contents = body ??
      `print(${JSON.stringify(JSON.stringify(output))})\n`;
    await Deno.writeTextFile(`${root}/build/swamp-step.py`, contents);
  };
  await writeBridge();
  const writes: unknown[] = [];
  const logs: unknown[] = [];
  const controller = new AbortController();
  const context = {
    globalArgs: {
      workspaceRoot: root,
      pythonBin,
      release: "v1",
      deliveryFolders: [] as string[],
      timeoutSeconds: 10,
    },
    signal: controller.signal,
    logger: {
      info: (message: string, properties: Record<string, unknown>) => {
        logs.push({ message, properties });
      },
    },
    readResource: (
      _name: string,
    ): Promise<Record<string, unknown> | null> => Promise.resolve(receipt),
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };
  return {
    root,
    artifact,
    receipt,
    output,
    marker,
    writes,
    logs,
    controller,
    context,
    writeBridge,
    close: () => Deno.remove(root, { recursive: true }),
  };
}

async function rejected(run: () => Promise<unknown>, expected: string) {
  try {
    await run();
  } catch (error) {
    if (String(error).includes(expected)) return String(error);
    throw error;
  }
  throw new Error(`Expected rejection: ${expected}`);
}

async function waitForFile(path: string) {
  const until = Date.now() + 2000;
  while (Date.now() < until) {
    try {
      if ((await Deno.stat(path)).isFile) return;
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("Fixture bridge did not start");
}

Deno.test("valid predecessor and current artifact persist one typed receipt", async () => {
  const f = await fixture();
  try {
    const result = await model.methods.narrate.execute(
      { inputHash },
      f.context,
    );
    if (f.writes.length !== 1 || result.dataHandles[0].name !== "narrate") {
      throw new Error("Missing validated receipt");
    }
    if (f.logs.length !== 2) throw new Error("Missing entry or completion log");
  } finally {
    await f.close();
  }
});

Deno.test("changed predecessor bytes are rejected before bridge execution", async () => {
  const f = await fixture();
  try {
    await Deno.writeTextFile(f.artifact, "omega");
    await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "content changed",
    );
    if (f.writes.length) throw new Error("Persisted failed stage");
  } finally {
    await f.close();
  }
});

Deno.test("symlinked predecessor is rejected", async () => {
  const f = await fixture();
  try {
    const target = `${f.root}/actual.txt`;
    await Deno.rename(f.artifact, target);
    await Deno.symlink(target, f.artifact);
    await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "symbolic link",
    );
    if (f.writes.length) throw new Error("Persisted failed stage");
  } finally {
    await f.close();
  }
});

Deno.test("missing Swamp predecessor prevents execution", async () => {
  const f = await fixture();
  try {
    f.context.readResource = () => Promise.resolve(null);
    await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "resource is missing",
    );
    if (f.writes.length) throw new Error("Persisted failed stage");
  } finally {
    await f.close();
  }
});

for (const field of ["release", "inputHash"] as const) {
  Deno.test(`predecessor ${field} mismatch prevents execution`, async () => {
    const f = await fixture();
    try {
      f.receipt[field] = field === "release" ? "v2" : otherHash;
      await rejected(
        () => model.methods.narrate.execute({ inputHash }, f.context),
        "does not match",
      );
      if (f.writes.length) throw new Error("Persisted failed stage");
    } finally {
      await f.close();
    }
  });
  Deno.test(`current receipt ${field} mismatch is not persisted`, async () => {
    const f = await fixture();
    try {
      f.output[field] = field === "release" ? "v2" : otherHash;
      await f.writeBridge();
      await rejected(
        () => model.methods.narrate.execute({ inputHash }, f.context),
        "does not match",
      );
      if (f.writes.length) throw new Error("Persisted invalid output");
    } finally {
      await f.close();
    }
  });
}

Deno.test("invalid current receipt schema is rejected without echoing output", async () => {
  const f = await fixture();
  const privateText = "PRIVATE_FIXTURE_PAYLOAD";
  try {
    await f.writeBridge(
      `print(${JSON.stringify(JSON.stringify({ diagnostic: privateText }))})\n`,
    );
    const error = await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "stage schema",
    );
    if (error.includes(privateText) || f.writes.length) {
      throw new Error("Unsafe invalid receipt handling");
    }
  } finally {
    await f.close();
  }
});

Deno.test("current receipt with false artifact hash is not persisted", async () => {
  const f = await fixture();
  try {
    f.output.artifacts[0].sha256 = otherHash;
    await f.writeBridge();
    await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "content changed",
    );
    if (f.writes.length) throw new Error("Persisted false artifact evidence");
  } finally {
    await f.close();
  }
});

Deno.test("empty current receipt artifacts are rejected", async () => {
  const f = await fixture();
  try {
    f.output.artifacts = [];
    f.output.metrics.fileCount = 0;
    await f.writeBridge();
    await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "stage schema",
    );
    if (f.writes.length) throw new Error("Persisted empty receipt");
  } finally {
    await f.close();
  }
});

Deno.test("subprocess failure omits sensitive stderr and stores no receipt", async () => {
  const f = await fixture();
  const privateText = "PRIVATE_FIXTURE_DIAGNOSTIC";
  try {
    await f.writeBridge(
      `import sys\nprint(${
        JSON.stringify(privateText)
      }, file=sys.stderr)\nsys.exit(7)\n`,
    );
    const error = await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "exited 7",
    );
    if (
      error.includes(privateText) ||
      JSON.stringify(f.logs).includes(privateText) || f.writes.length
    ) throw new Error("Leaked bridge stderr");
  } finally {
    await f.close();
  }
});

Deno.test("pre-aborted invocation starts no bridge and writes no receipt", async () => {
  const f = await fixture();
  try {
    f.controller.abort();
    await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "Abort",
    );
    if (f.logs.length || f.writes.length) {
      throw new Error("Aborted stage performed work");
    }
  } finally {
    await f.close();
  }
});

Deno.test("cancelling an active bridge prevents a receipt", async () => {
  const f = await fixture();
  try {
    await f.writeBridge(
      `from pathlib import Path\nimport time\nPath(${
        JSON.stringify(f.marker)
      }).write_text("started")\ntime.sleep(30)\n`,
    );
    const running = model.methods.narrate.execute({ inputHash }, f.context);
    const rejectedRun = rejected(() => running, "Abort");
    await waitForFile(f.marker);
    f.controller.abort();
    await rejectedRun;
    if (f.writes.length) throw new Error("Persisted cancelled stage");
  } finally {
    f.controller.abort();
    await f.close();
  }
});

Deno.test("bridge timeout prevents a receipt", async () => {
  const f = await fixture();
  try {
    f.context.globalArgs.timeoutSeconds = 1;
    await f.writeBridge("import time\ntime.sleep(30)\n");
    await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "timed out",
    );
    if (f.writes.length) throw new Error("Persisted timed out stage");
  } finally {
    await f.close();
  }
});

Deno.test("render receipt must identify an actual artifact as its video", async () => {
  const f = await fixture();
  try {
    f.context.readResource = (name) =>
      Promise.resolve({ ...f.receipt, stage: name });
    f.output.stage = "render";
    f.output.videoSha256 = otherHash;
    await f.writeBridge();
    await rejected(
      () => model.methods.render.execute({ inputHash }, f.context),
      "must identify a receipt artifact",
    );
    if (f.writes.length) throw new Error("Persisted unrelated video identity");
  } finally {
    await f.close();
  }
});

Deno.test("delivery receipt outside configured output folders is rejected", async () => {
  const f = await fixture();
  try {
    await Deno.mkdir(`${f.root}/copies`);
    f.context.globalArgs.deliveryFolders = [`${f.root}/copies`];
    const videoSha256 = f.receipt.artifacts[0].sha256;
    f.context.readResource = (name) =>
      Promise.resolve({
        ...f.receipt,
        stage: name,
        videoSha256,
      });
    f.output.stage = "deliver";
    f.output.videoSha256 = videoSha256;
    await f.writeBridge();
    await rejected(
      () =>
        model.methods.deliver.execute({ inputHash, videoSha256 }, f.context),
      "outside its authorized directory",
    );
    if (f.writes.length) {
      throw new Error("Persisted unauthorized delivery receipt");
    }
  } finally {
    await f.close();
  }
});

for (const tamper of [false, true]) {
  Deno.test(
    tamper
      ? "large artifact modification beyond its first buffer is rejected"
      : "large artifact with a partial final buffer verifies against its full digest",
    async () => {
      const f = await fixture();
      try {
        const bytes = new Uint8Array(4 * 1024 * 1024 + 17);
        for (let index = 0; index < bytes.length; index++) {
          bytes[index] = index % 251;
        }
        const expected = await crypto.subtle.digest("SHA-256", bytes);
        f.receipt.artifacts[0].bytes = bytes.length;
        f.receipt.artifacts[0].sha256 = Array.from(
          new Uint8Array(expected),
          (byte) => byte.toString(16).padStart(2, "0"),
        ).join("");
        f.output.artifacts = structuredClone(f.receipt.artifacts);
        await f.writeBridge();
        if (tamper) bytes[3 * 1024 * 1024] ^= 1;
        await Deno.writeFile(f.artifact, bytes);
        if (tamper) {
          await rejected(
            () => model.methods.narrate.execute({ inputHash }, f.context),
            "content changed",
          );
          if (f.writes.length) {
            throw new Error("Persisted changed large artifact");
          }
        } else {
          await model.methods.narrate.execute({ inputHash }, f.context);
          if (f.writes.length !== 1) {
            throw new Error("Missing large artifact receipt");
          }
        }
      } finally {
        await f.close();
      }
    },
  );
}
