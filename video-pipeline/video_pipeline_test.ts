import { model } from "./video_pipeline.ts";

const inputHash = "a".repeat(64);
const otherHash = "b".repeat(64);
const decoder = new TextDecoder();
// swamp-quality-ignore deno-command: Locate installed Python for disposable fixture tests with a fixed, non-mutating interpreter query.
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
      `from pathlib import Path\nimport time, signal\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nPath(${
        JSON.stringify(f.marker)
      }).write_text("started")\ntime.sleep(3)\n`,
    );
    const running = model.methods.narrate.execute({ inputHash }, f.context);
    const rejectedRun = rejected(() => running, "Abort");
    await waitForFile(f.marker);
    const abortedAt = Date.now();
    f.controller.abort();
    await rejectedRun;
    if (Date.now() - abortedAt >= 2000) {
      throw new Error("Cancellation did not stop a SIGTERM-resistant bridge");
    }
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
    await f.writeBridge(
      "import time, signal\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(3)\n",
    );
    const started = Date.now();
    await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "timed out",
    );
    if (Date.now() - started >= 2500) {
      throw new Error("Deadline did not stop a SIGTERM-resistant bridge");
    }
    if (f.writes.length) throw new Error("Persisted timed out stage");
  } finally {
    await f.close();
  }
});

for (const mode of ["cancellation", "timeout", "overflow"] as const) {
  Deno.test(`${mode} stops a resistant renderer descendant`, async () => {
    const f = await fixture();
    const escaped = `${f.root}/escaped`;
    try {
      // The descendant deliberately ignores TERM and closes inherited pipes.
      // Killing only its Python parent therefore cannot stop this write.
      const renderer = `from pathlib import Path
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(${JSON.stringify(f.marker)}).write_text("ready")
time.sleep(2)
Path(${JSON.stringify(escaped)}).write_text("orphan survived")
`;
      await f.writeBridge(`import subprocess, sys, time
from pathlib import Path
subprocess.Popen([sys.executable, "-c", ${
        JSON.stringify(renderer)
      }], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
while not Path(${JSON.stringify(f.marker)}).exists():
    time.sleep(0.01)
${
        mode === "overflow"
          ? 'sys.stdout.write("x" * (4 * 1024 * 1024 + 1)); sys.stdout.flush()'
          : ""
      }
time.sleep(60)
`);
      if (mode === "timeout") f.context.globalArgs.timeoutSeconds = 1;
      const running = model.methods.narrate.execute({ inputHash }, f.context);
      const failure = rejected(
        () => running,
        mode === "cancellation"
          ? "Abort"
          : mode === "timeout"
          ? "timed out"
          : "four-MiB output limit",
      );
      await waitForFile(f.marker);
      if (mode === "cancellation") f.controller.abort();
      await failure;
      await new Promise((resolve) => setTimeout(resolve, 2200));
      try {
        await Deno.stat(escaped);
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) throw error;
        if (f.writes.length) throw new Error("Persisted failed stage");
        return;
      }
      throw new Error("Renderer descendant survived termination");
    } finally {
      f.controller.abort();
      await f.close();
    }
  });
}

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

Deno.test("missing artifact errors do not reveal project paths or write receipts", async () => {
  const f = await fixture();
  try {
    await Deno.remove(f.artifact);
    const error = await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "Receipt artifact cannot be read or verified",
    );
    if (error.includes(f.root)) {
      throw new Error("Project path escaped into an error");
    }
    if (f.writes.length) {
      throw new Error("Persisted a missing artifact receipt");
    }
  } finally {
    await f.close();
  }
});

Deno.test("missing bridge errors do not reveal project paths or write receipts", async () => {
  const f = await fixture();
  try {
    await Deno.remove(`${f.root}/build/swamp-step.py`);
    const error = await rejected(
      () => model.methods.prepare.execute({}, f.context),
      "Project bridge or executable boundary validation failed",
    );
    if (error.includes(f.root)) {
      throw new Error("Project path escaped into an error");
    }
    if (f.writes.length) throw new Error("Persisted a missing bridge receipt");
  } finally {
    await f.close();
  }
});

Deno.test("oversized receipt output is refused without publishing or waiting for timeout", async () => {
  const f = await fixture();
  try {
    await f.writeBridge(
      "import sys\nsys.stdout.write('x' * (4 * 1024 * 1024 + 1))\n",
    );
    const started = Date.now();
    await rejected(
      () => model.methods.narrate.execute({ inputHash }, f.context),
      "Bridge receipt exceeded the four-MiB output limit",
    );
    if (Date.now() - started >= 5000) {
      throw new Error("Receipt cap did not stop collection promptly");
    }
    if (f.writes.length) throw new Error("Persisted an oversized receipt");
  } finally {
    await f.close();
  }
});

Deno.test("preparation keeps one immutable release/input binding per instance", async () => {
  const f = await fixture();
  try {
    f.output.stage = "prepare";
    await f.writeBridge();
    await model.methods.prepare.execute({}, f.context);
    if (f.writes.length !== 1) {
      throw new Error("Same-input preparation must be repeatable");
    }
    f.output.inputHash = otherHash;
    await f.writeBridge();
    await rejected(
      () => model.methods.prepare.execute({}, f.context),
      "Prepared inputs are immutable",
    );
    if (f.writes.length !== 1) {
      throw new Error("Changed inputs replaced a prepared receipt");
    }
    f.context.globalArgs.release = "v2";
    await rejected(
      () => model.methods.prepare.execute({}, f.context),
      "Prepared release is immutable",
    );
    if (f.writes.length !== 1) {
      throw new Error("Changed release replaced a prepared receipt");
    }
  } finally {
    await f.close();
  }

  const fresh = await fixture();
  try {
    fresh.context.readResource = () => Promise.resolve(null);
    fresh.output.stage = "prepare";
    fresh.output.inputHash = otherHash;
    await fresh.writeBridge();
    await model.methods.prepare.execute({}, fresh.context);
    if (fresh.writes.length !== 1) {
      throw new Error("A new instance must accept its own input binding");
    }
  } finally {
    await fresh.close();
  }
});

for (
  const mode of [
    "missing-first",
    "missing-second",
    "wrong",
    "extra",
    "complete",
  ]
) {
  Deno.test(`delivery requires verified video bytes in every destination: ${mode}`, async () => {
    const f = await fixture();
    try {
      const roots = [`${f.root}/copies-a`, `${f.root}/copies-b`];
      for (const root of roots) await Deno.mkdir(root);
      f.context.globalArgs.deliveryFolders = roots;
      const videoSha256 = f.receipt.artifacts[0].sha256;
      f.context.readResource = (name) =>
        Promise.resolve({ ...f.receipt, stage: name, videoSha256 });
      f.output.stage = "deliver";
      f.output.videoSha256 = videoSha256;
      f.output.artifacts = [];
      for (const [index, root] of roots.entries()) {
        if (
          (mode === "missing-first" && index === 0) ||
          (mode === "missing-second" && index === 1)
        ) continue;
        const text = mode === "wrong" && index === 1 ? "omega" : "alpha";
        const bytes = new TextEncoder().encode(text);
        const digest = new Uint8Array(
          await crypto.subtle.digest("SHA-256", bytes),
        );
        const path = `${root}/video.txt`;
        await Deno.writeFile(path, bytes);
        f.output.artifacts.push({
          path,
          bytes: bytes.length,
          sha256: Array.from(digest, (b) => b.toString(16).padStart(2, "0"))
            .join(""),
        });
      }
      if (mode === "extra") {
        const bytes = new TextEncoder().encode("extra");
        const digest = new Uint8Array(
          await crypto.subtle.digest("SHA-256", bytes),
        );
        const path = `${roots[1]}/extra.txt`;
        await Deno.writeFile(path, bytes);
        f.output.artifacts.push({
          path,
          bytes: bytes.length,
          sha256: Array.from(digest, (b) => b.toString(16).padStart(2, "0"))
            .join(""),
        });
      }
      f.output.metrics.fileCount = f.output.artifacts.length;
      await f.writeBridge();
      const run = () =>
        model.methods.deliver.execute({ inputHash, videoSha256 }, f.context);
      if (mode === "complete") {
        await run();
        if (f.writes.length !== 1) {
          throw new Error("Complete verified delivery must persist");
        }
      } else {
        await rejected(
          run,
          mode.startsWith("missing")
            ? "missing a verified video copy"
            : "absent from verification",
        );
        if (f.writes.length) {
          throw new Error("Persisted incomplete or unverified delivery");
        }
      }
    } finally {
      await f.close();
    }
  });
}

Deno.test("duplicate and nested delivery destinations are rejected", () => {
  for (
    const deliveryFolders of [["/example/output", "/example/output"], [
      "/example/output",
      "/example/output/nested",
    ]]
  ) {
    const parsed = model.globalArguments.safeParse({
      workspaceRoot: "/example/project",
      pythonBin: "/example/bin/python3",
      release: "v1",
      deliveryFolders,
    });
    if (parsed.success) throw new Error("Ambiguous destinations were accepted");
  }
});

Deno.test("missing potentially aliased destinations fail before the bridge can write", async () => {
  const f = await fixture();
  try {
    f.context.globalArgs.deliveryFolders = [
      `${f.root}/Output`,
      `${f.root}/output/nested`,
    ];
    f.output.stage = "prepare";
    await f.writeBridge(
      `from pathlib import Path\nPath(${JSON.stringify(f.marker)}).touch()\n` +
        `print(${JSON.stringify(JSON.stringify(f.output))})\n`,
    );
    await rejected(
      () => model.methods.prepare.execute({}, f.context),
      "boundary validation failed",
    );
    if (f.writes.length) throw new Error("Persisted ambiguous destinations");
    try {
      await Deno.stat(f.marker);
      throw new Error("Bridge ran before destinations were validated");
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
  } finally {
    await f.close();
  }
});
