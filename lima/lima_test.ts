/**
 * Tests for @jpisgeek/lima.
 *
 * Exported surface only, and not in the manifest, so this file does not move
 * the content hash a review is bound to.
 *
 * Two properties carry the weight. First, refusal: a name collision, a drift,
 * a wrong hash, a held lock, or a running instance at the destroy door must
 * stop the model, never be repaired around. Second, honesty: a missing
 * limactl, an unreadable answer, and an empty home are three different
 * facts and must be recorded as three different facts.
 *
 * limactl is faked with a shell script in a temp dir that answers from
 * canned files and logs its argv, so every flow runs without a VM.
 * Requires --allow-run --allow-write --allow-read --allow-env.
 */
// deno-lint-ignore-file no-explicit-any -- test doubles stand in for the host context
import {
  assert,
  assertEquals,
  assertMatch,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.14";
import {
  acquireLock,
  canonical,
  childEnv,
  configChecks,
  diffKeys,
  GlobalArgsSchema,
  limactlArgs,
  LimaInfoSchema,
  markerPath,
  model as behavior,
  mountIsDenied,
  observe,
  ownership,
  parseList,
  renderTemplate,
  runLimactl,
  safeText,
  sha256Hex,
  validatePaths,
} from "./lima.ts";

const DIGEST = "sha256:" + "7d".repeat(32);
const HOME = Deno.env.get("HOME") ?? "/Users/nobody";

function args(over: Record<string, unknown> = {}) {
  return {
    name: "assistant-vm",
    limaHome: "/opt/lima-homes/assistant",
    limaVersion: "2.2.0",
    image: {
      location: "https://images.example.com/ubuntu-24.04-arm64.img",
      arch: "aarch64",
      digest: DIGEST,
    },
    cpus: 4,
    memory: "8GiB",
    disk: "40GiB",
    ...over,
  };
}

const id = {
  modelType: "@jpisgeek/lima",
  modelId: "model-1",
  definitionId: "def-1",
};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

Deno.test("a minimal definition parses with the documented defaults", () => {
  const g = GlobalArgsSchema.parse(args());
  assertEquals(g.vmType, "vz");
  assertEquals(g.arch, "aarch64");
  assertEquals(g.limactlPath, "limactl");
  assertEquals(g.mounts, []);
  assertEquals(g.portForwards, []);
  assertEquals(g.sshLocalPort, 0);
});

Deno.test("instance name is tight: lowercase, letter first, no path or shell characters", () => {
  for (const bad of ["Vm", "-vm", "vm_1", "vm/1", "vm 1", "a".repeat(33), ""]) {
    assert(!GlobalArgsSchema.safeParse(args({ name: bad })).success, bad);
  }
});

Deno.test("limaHome must be a normalized safe absolute path", () => {
  for (const bad of ["relative", "/", "/x/", "/x;rm", "/x y", "/x/$HOME"]) {
    assert(!GlobalArgsSchema.safeParse(args({ limaHome: bad })).success, bad);
  }
});

Deno.test("limactlPath must name limactl and nothing else", () => {
  assert(
    GlobalArgsSchema.safeParse(
      args({ limactlPath: "/opt/homebrew/bin/limactl" }),
    ).success,
  );
  for (const bad of ["/bin/sh", "limactl.sh", "-limactl", "lima"]) {
    assert(
      !GlobalArgsSchema.safeParse(args({ limactlPath: bad })).success,
      bad,
    );
  }
});

Deno.test("image needs https and a full sha256 digest, and its arch must match", () => {
  const img = args().image as Record<string, string>;
  assert(
    !GlobalArgsSchema.safeParse(
      args({ image: { ...img, location: "http://x/y.img" } }),
    ).success,
  );
  assert(
    !GlobalArgsSchema.safeParse(
      args({ image: { ...img, digest: "sha256:abc" } }),
    ).success,
  );
  assert(
    !GlobalArgsSchema.safeParse(args({ image: { ...img, arch: "x86_64" } }))
      .success,
  );
});

Deno.test("mounts under the home, system, volumes, or temp trees are refused", () => {
  for (
    const bad of [
      "/",
      HOME,
      `${HOME}/git`,
      "/Volumes/nas",
      "/private/tmp/x",
      "/tmp/x",
      "/etc",
      "/var/run",
      "/srv/.ssh",
      "/srv/x/.swamp/y",
    ]
  ) {
    assert(mountIsDenied(bad, HOME), bad);
    assert(
      !GlobalArgsSchema.safeParse(args({ mounts: [{ location: bad }] }))
        .success,
      bad,
    );
  }
  assert(!mountIsDenied("/srv/share", HOME));
  assert(
    GlobalArgsSchema.safeParse(
      args({ mounts: [{ location: "/srv/share", writable: true }] }),
    ).success,
  );
  assert(
    !GlobalArgsSchema.safeParse(args({ mounts: [{ location: "/srv/a/../b" }] }))
      .success,
  );
});

Deno.test("port forwards bind loopback only, above 1024, and never twice", () => {
  assert(
    GlobalArgsSchema.safeParse(
      args({ portForwards: [{ guestPort: 7830, hostPort: 17830 }] }),
    ).success,
  );
  assert(
    !GlobalArgsSchema.safeParse(
      args({
        portForwards: [{ guestPort: 7830, hostPort: 17830, hostIP: "0.0.0.0" }],
      }),
    ).success,
  );
  assert(
    !GlobalArgsSchema.safeParse(
      args({ portForwards: [{ guestPort: 7830, hostPort: 80 }] }),
    ).success,
  );
  assert(
    !GlobalArgsSchema.safeParse(
      args({
        portForwards: [{ guestPort: 1, hostPort: 17830 }, {
          guestPort: 2,
          hostPort: 17830,
        }],
      }),
    ).success,
  );
});

Deno.test("unknown keys are refused rather than ignored", () => {
  assert(!GlobalArgsSchema.safeParse(args({ mountHome: true })).success);
});

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

Deno.test("the rendered template states every isolation setting explicitly", () => {
  const g = GlobalArgsSchema.parse(
    args({ portForwards: [{ guestPort: 7830, hostPort: 17830 }] }),
  );
  const t = renderTemplate(g, []) as Record<string, any>;
  assertEquals(t.mounts, []);
  assertEquals(t.ssh.forwardAgent, false);
  assertEquals(t.ssh.forwardX11, false);
  assertEquals(t.ssh.loadDotSSHPubKeys, false);
  assertEquals(t.propagateProxyEnv, false);
  assertEquals(t.containerd, { system: false, user: false });
  assertEquals(t.rosetta, { enabled: false, binfmt: false });
  assertEquals(t.images.length, 1, "no fallback image without a digest");
  assertEquals(t.images[0].digest, DIGEST);
  const pf = t.portForwards;
  assertEquals(pf[0].hostIP, "127.0.0.1");
  assertEquals(pf[0].hostPort, 17830);
  assertEquals(pf[pf.length - 1], { guestPortRange: [1, 65535], ignore: true });
  assert(!("mountType" in t), "no mount type without mounts");
});

Deno.test("render is deterministic and the hash moves with any input", async () => {
  const a = renderTemplate(GlobalArgsSchema.parse(args()), []);
  const b = renderTemplate(GlobalArgsSchema.parse(args()), []);
  assertEquals(canonical(a), canonical(b));
  const ha = await sha256Hex(canonical(a));
  const hc = await sha256Hex(
    canonical(renderTemplate(GlobalArgsSchema.parse(args({ cpus: 5 })), [])),
  );
  assert(ha !== hc);
  assertMatch(ha, /^[0-9a-f]{64}$/);
  assertEquals(
    diffKeys(
      a,
      renderTemplate(
        GlobalArgsSchema.parse(args({ cpus: 5, disk: "50GiB" })),
        [],
      ),
    ),
    ["cpus", "disk"],
  );
});

Deno.test("canonical JSON sorts keys at every level", () => {
  assertEquals(
    canonical({ b: 1, a: { d: [2, { z: 1, y: 2 }], c: 3 } }),
    '{"a":{"c":3,"d":[2,{"y":2,"z":1}]},"b":1}',
  );
});

Deno.test("provision scripts are embedded one per entry", () => {
  const g = GlobalArgsSchema.parse(
    args({
      provision: [{
        mode: "system",
        file: "/srv/p.sh",
        sha256: "0".repeat(64),
      }],
    }),
  );
  const t = renderTemplate(g, ["echo hi"]) as Record<string, any>;
  assertEquals(t.provision, [{ mode: "system", script: "echo hi" }]);
  let threw = false;
  try {
    renderTemplate(g, []);
  } catch {
    threw = true;
  }
  assert(threw);
});

// ---------------------------------------------------------------------------
// Process boundary
// ---------------------------------------------------------------------------

Deno.test("child environment is LIMA_HOME, HOME, PATH, LANG and nothing else", () => {
  const env = childEnv(GlobalArgsSchema.parse(args()));
  assertEquals(Object.keys(env).sort(), ["HOME", "LANG", "LIMA_HOME", "PATH"]);
  assertEquals(env.LIMA_HOME, "/opt/lima-homes/assistant");
});

Deno.test("every invocation turns the TUI off first", () => {
  assertEquals(limactlArgs(["list", "--json"]), [
    "--tty=false",
    "list",
    "--json",
  ]);
});

Deno.test("safeText escapes control and format characters and bounds length", () => {
  assertEquals(safeText("a\x1b[31mb‮c"), "a\\u001b[31mb\\u202ec");
  assertEquals(safeText("x".repeat(300)).length, 201);
});

Deno.test("parseList accepts an array, newline objects, and empty; refuses garbage", () => {
  const one = { name: "a", status: "Stopped", dir: "/h/a" };
  assertEquals(parseList("")?.length, 0);
  assertEquals(parseList(JSON.stringify([one]))?.length, 1);
  assertEquals(
    parseList(
      JSON.stringify(one) + "\n" + JSON.stringify({ ...one, name: "b" }),
    )?.length,
    2,
  );
  assertEquals(parseList("not json"), null);
  assertEquals(
    parseList(JSON.stringify({ name: "a" })),
    null,
    "missing status/dir is malformed, not empty",
  );
});

Deno.test("ownership needs the marker to match model, name, home, and instance dir", () => {
  const g = GlobalArgsSchema.parse(args());
  const inst = {
    name: g.name,
    status: "Stopped",
    dir: "/opt/lima-homes/assistant/assistant-vm",
  };
  const marker = {
    modelType: id.modelType,
    modelId: id.modelId,
    definitionId: id.definitionId,
    name: g.name,
    limaHome: g.limaHome,
    instanceDir: inst.dir,
    configHash: "0".repeat(64),
    imageDigest: DIGEST,
    createdAt: "2026-09-19T00:00:00Z",
  };
  assertEquals(ownership(marker, inst, g, id), "owned");
  assertEquals(ownership(null, inst, g, id), "unmanaged");
  assertEquals(ownership("malformed", inst, g, id), "unmanaged");
  assertEquals(
    ownership({ ...marker, modelId: "other" }, inst, g, id),
    "unmanaged",
  );
  assertEquals(
    ownership({ ...marker, instanceDir: "/elsewhere" }, inst, g, id),
    "unmanaged",
  );
  assertEquals(ownership(null, null, g, id), "missing");
  assertEquals(ownership(marker, null, g, id), "orphan-marker");
});

// ---------------------------------------------------------------------------
// Flows against a fake limactl
// ---------------------------------------------------------------------------

type Fake = {
  dir: string;
  bin: string;
  home: string;
  calls: () => Promise<string[]>;
  set: (name: string, text: string) => Promise<void>;
};

async function fakeLimactl(): Promise<Fake> {
  const dir = await Deno.realPath(
    await Deno.makeTempDir({ prefix: "lima-fake-" }),
  );
  const home = `${dir}/home`;
  await Deno.mkdir(home);
  const bin = `${dir}/limactl`;
  const script = `#!/bin/sh
printf '%s\\n' "$*" >> "${dir}/calls.log"
env > "${dir}/env.last"
shift # --tty=false
sub="$1"
[ -f "${dir}/exit.$sub" ] && { cat "${dir}/err.$sub" 2>/dev/null >&2; exit "$(cat "${dir}/exit.$sub")"; }
[ -f "${dir}/out.$sub" ] && cat "${dir}/out.$sub"
exit 0
`;
  await Deno.writeTextFile(bin, script, { mode: 0o755 });
  await Deno.writeTextFile(
    `${dir}/out.info`,
    JSON.stringify({
      version: "2.2.0",
      limaHome: home,
      vmTypes: ["vz", "qemu"],
    }),
  );
  await Deno.writeTextFile(`${dir}/out.list`, "");
  return {
    dir,
    bin,
    home,
    calls: async () =>
      (await Deno.readTextFile(`${dir}/calls.log`).catch(() => "")).trim()
        .split("\n").filter(Boolean),
    set: (name, text) => Deno.writeTextFile(`${dir}/${name}`, text),
  };
}

function fakeCtx(g: Record<string, unknown>) {
  const written: Record<string, unknown> = {};
  const files: Record<string, string> = {};
  return {
    ctx: {
      globalArgs: g,
      signal: new AbortController().signal,
      modelType: id.modelType,
      modelId: id.modelId,
      definition: { id: id.definitionId, name: "assistant" },
      logger: { info: () => {}, warning: () => {} },
      writeResource: (
        _spec: string,
        name: string,
        data: Record<string, unknown>,
      ) => {
        written[name] = data;
        return Promise.resolve({ name });
      },
      createFileWriter: (_spec: string, name: string) => ({
        writeText: (t: string) => {
          files[name] = t;
          return Promise.resolve({ name });
        },
      }),
    },
    written,
    files,
  };
}

function withFake(f: Fake, over: Record<string, unknown> = {}) {
  return args({ limaHome: f.home, limactlPath: f.bin, ...over });
}

for (const mode of ["timeout", "cancel"] as const) {
  Deno.test(`start: ${mode} reaps a TERM-resistant child and releases the mutation lock`, async () => {
    const f = await fakeLimactl();
    const controller = new AbortController();
    const reason = new Error("test caller cancelled");
    let pending: Promise<unknown> | undefined;
    let watchdog: ReturnType<typeof setTimeout> | undefined;
    let pid: number | undefined;
    try {
      // Hang during the under-lock host observation. Cancellation also covers
      // a child that closes both output streams but keeps running.
      await Deno.writeTextFile(
        f.bin,
        `#!/bin/sh
trap 'printf term > "${f.dir}/term"' TERM
${mode === "cancel" ? "exec 1>&- 2>&-" : ""}
printf '%s' "$$" > "${f.dir}/pid"
while :; do :; done
`,
      );
      const g = GlobalArgsSchema.parse(withFake(f, { commandTimeoutSec: 5 }));
      const { ctx } = fakeCtx(g);
      ctx.signal = controller.signal;
      const started = performance.now();
      pending = behavior.methods.start.execute({}, ctx as any).then(
        () => ({ error: undefined }),
        (error: unknown) => ({ error }),
      );
      const limit = new Promise<"watchdog">((resolve) => {
        watchdog = setTimeout(() => resolve("watchdog"), 7000);
      });
      for (let attempt = 0; attempt < 150; attempt++) {
        const text = await Deno.readTextFile(`${f.dir}/pid`).catch(() => "");
        if (text) {
          pid = Number(text);
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert(pid, "fake child did not become ready");
      // The caller cannot acquire the instance while start is still waiting.
      await assertRejects(
        () => acquireLock(g, "contender", ctx.logger),
        Error,
        "holds the lock",
      );
      const abortedAt = performance.now();
      if (mode === "cancel") controller.abort(reason);
      const result = await Promise.race([pending, limit]);
      assert(result !== "watchdog", "method stayed pending after termination");
      const error = (result as { error: unknown }).error;
      if (mode === "cancel") {
        assert(error === reason, "caller cancellation reason was replaced");
        assert(
          performance.now() - abortedAt < 2000,
          "cancellation was delayed",
        );
      } else {
        assert(error instanceof Error);
        assertStringIncludes(error.message, "no answer within 5s");
        assert(performance.now() - started < 6500, "deadline was delayed");
      }
      assertEquals(await Deno.readTextFile(`${f.dir}/term`), "term");
      assertThrowsProcessGone(pid);
      const release = await acquireLock(g, "after-termination", ctx.logger);
      await release();
    } finally {
      clearTimeout(watchdog);
      if (pid) {
        try {
          Deno.kill(pid, "SIGKILL");
        } catch { /* already reaped */ }
      }
      await pending;
      await Deno.remove(f.dir, { recursive: true });
    }
  });
}

function assertThrowsProcessGone(pid: number) {
  let gone = false;
  try {
    Deno.kill(pid, 0);
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
    gone = true;
  }
  assert(gone, "owned child is still alive after method completion");
}

Deno.test("cancellation stops reading pipes inherited by a descendant after limactl exits", async () => {
  const f = await fakeLimactl();
  const controller = new AbortController();
  const reason = new Error("cancel inherited pipes");
  let pending: Promise<unknown> | undefined;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  let descendant: number | undefined;
  try {
    await Deno.writeTextFile(
      f.bin,
      `#!/bin/sh
/bin/sleep 30 &
printf '%s %s' "$$" "$!" > "${f.dir}/pids"
exit 0
`,
    );
    pending = runLimactl(
      GlobalArgsSchema.parse(withFake(f)),
      ["info"],
      controller.signal,
    ).then(() => undefined, (e: unknown) => e);
    let leader: number | undefined;
    for (let attempt = 0; attempt < 150; attempt++) {
      const text = await Deno.readTextFile(`${f.dir}/pids`).catch(() => "");
      if (text) {
        [leader, descendant] = text.split(" ").map(Number);
        try {
          Deno.kill(leader, 0);
        } catch (e) {
          if (!(e instanceof Deno.errors.NotFound)) throw e;
          break;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert(leader && descendant, "fake processes did not become ready");
    assertThrowsProcessGone(leader);
    Deno.kill(descendant, 0); // The inherited pipes still have a live owner.
    controller.abort(reason);
    const result = await Promise.race([
      pending,
      new Promise<"watchdog">((resolve) => {
        watchdog = setTimeout(() => resolve("watchdog"), 2000);
      }),
    ]);
    assert(result === reason, "caller cancellation reason was replaced");
  } finally {
    clearTimeout(watchdog);
    if (descendant) {
      try {
        Deno.kill(descendant, "SIGKILL");
      } catch { /* already gone */ }
    }
    controller.abort(reason);
    await pending;
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("already-cancelled calls preserve the reason without spawning limactl", async () => {
  const f = await fakeLimactl();
  try {
    const controller = new AbortController();
    const reason = new Error("already cancelled");
    controller.abort(reason);
    let caught: unknown;
    try {
      await runLimactl(
        GlobalArgsSchema.parse(withFake(f)),
        ["info"],
        controller.signal,
      );
    } catch (e) {
      caught = e;
    }
    assert(caught === reason, "caller cancellation reason was replaced");
    assertEquals(await f.calls(), []);
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("runtime partial schema works while methods still enforce cross-field isolation", async () => {
  assert(behavior.globalArguments.partial().safeParse({ cpus: 3 }).success);
  const f = await fakeLimactl();
  try {
    for (
      const invalid of [
        { limaHome: HOME },
        { image: { ...args().image, arch: "x86_64" } },
        {
          portForwards: [{ guestPort: 8000, hostPort: 18000 }, {
            guestPort: 9000,
            hostPort: 18000,
          }],
        },
        { mounts: [{ location: "/srv/share" }, { location: "/srv/share" }] },
      ]
    ) {
      const r = fakeCtx(withFake(f, invalid));
      await assertRejects(() =>
        behavior.methods.inspect.execute({}, r.ctx as any)
      );
    }
    assertEquals(
      await f.calls(),
      [],
      "invalid inputs must fail before running limactl",
    );
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("inspect accepts runtime type objects and legacy markers without adopting another owner's VM", async () => {
  const f = await fakeLimactl();
  try {
    const g = GlobalArgsSchema.parse(withFake(f));
    const dir = `${f.home}/${g.name}`;
    await f.set(
      "out.list",
      JSON.stringify({ name: g.name, status: "Stopped", dir }),
    );
    await Deno.mkdir(`${f.home}/.swamp-owned`);
    for (
      const markerType of [id.modelType, {
        raw: id.modelType,
        normalized: id.modelType,
      }]
    ) {
      for (const definitionId of [id.definitionId, "another-definition"]) {
        await Deno.writeTextFile(
          markerPath(g),
          JSON.stringify({
            ...id,
            modelType: markerType,
            definitionId,
            name: g.name,
            limaHome: f.home,
            instanceDir: dir,
            configHash: "0".repeat(64),
            imageDigest: DIGEST,
            createdAt: "2026-09-19T00:00:00Z",
          }),
        );
        const r = fakeCtx(withFake(f));
        await behavior.methods.inspect.execute(
          {},
          {
            ...r.ctx,
            modelType: { raw: id.modelType, normalized: id.modelType },
          } as any,
        );
        assertEquals(
          (r.written[`instance-${g.name}`] as any).state,
          definitionId === id.definitionId ? "owned" : "unmanaged",
        );
      }
    }
    const r = fakeCtx(withFake(f));
    await assertRejects(() =>
      behavior.methods.inspect.execute({}, { ...r.ctx, modelType: {} } as any)
    );
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("inspect: a missing limactl is recorded as missing, not as an empty home", async () => {
  const f = await fakeLimactl();
  try {
    const g = GlobalArgsSchema.parse(
      withFake(f, { limactlPath: `${f.dir}/nope/limactl` }),
    );
    const obs = await observe(g, id, new AbortController().signal, "inspect");
    assertEquals(obs.host.limactl, "missing");
    assertEquals(obs.host.instancesInHome, null);
    assertEquals(obs.instance.state, "unknown");
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("inspect: wrong version, malformed info, and malformed list are three different facts", async () => {
  const f = await fakeLimactl();
  try {
    const g = GlobalArgsSchema.parse(withFake(f));
    const sig = new AbortController().signal;
    await f.set(
      "out.info",
      JSON.stringify({ version: "2.1.0", limaHome: f.home, vmTypes: ["vz"] }),
    );
    assertEquals(
      (await observe(g, id, sig, "inspect")).host.limactl,
      "unsupported-version",
    );
    await f.set("out.info", "time=... level=info msg=hello");
    assertEquals(
      (await observe(g, id, sig, "inspect")).host.limactl,
      "malformed",
    );
    await f.set(
      "out.info",
      JSON.stringify({ version: "2.2.0", limaHome: f.home, vmTypes: ["vz"] }),
    );
    await f.set("out.list", "{broken");
    const obs = await observe(g, id, sig, "inspect");
    assertEquals(obs.host.limactl, "malformed");
    assertEquals(obs.instance.state, "unknown");
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("inspect: an instance with the right name but no marker is unmanaged; LIMA_HOME reaches the child", async () => {
  const f = await fakeLimactl();
  try {
    const g = GlobalArgsSchema.parse(withFake(f));
    await f.set(
      "out.list",
      JSON.stringify({
        name: g.name,
        status: "Stopped",
        dir: `${f.home}/${g.name}`,
        vmType: "vz",
        arch: "aarch64",
        cpus: 4,
      }),
    );
    const obs = await observe(g, id, new AbortController().signal, "inspect");
    assertEquals(obs.instance.state, "unmanaged");
    assertEquals(obs.instance.status, "Stopped");
    assertEquals(obs.host.instancesInHome, 1);
    const env = await Deno.readTextFile(`${f.dir}/env.last`);
    assertStringIncludes(env, `LIMA_HOME=${f.home}`);
    assert(
      !/TYPESAFE|SWAMP|TOKEN|KEY=/.test(env),
      "no parent environment leaked",
    );
    assertEquals(
      env.trim().split("\n").filter((l) =>
        !l.startsWith("_") && !l.startsWith("PWD") && !l.startsWith("SHLVL")
      ).length,
      4,
    );
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("plan: missing instance plans a create; validate is called with the rendered file; config is stored", async () => {
  const f = await fakeLimactl();
  try {
    const { ctx, written, files } = fakeCtx(withFake(f));
    await behavior.methods.plan.execute({}, ctx as any);
    const plan = written["plan-assistant-vm"] as Record<string, any>;
    assertEquals(plan.action, "create");
    assertEquals(plan.validated, true);
    assertMatch(plan.configHash, /^[0-9a-f]{64}$/);
    const calls = await f.calls();
    assert(
      calls.some((c) => c.startsWith("--tty=false validate ")),
      calls.join("|"),
    );
    assertEquals(Object.keys(files).length, 1);
    const stored = JSON.parse(Object.values(files)[0]);
    assertEquals(stored.mounts, []);
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("plan: prerequisites block; an unmanaged instance blocks; drift says replacement-required", async () => {
  const f = await fakeLimactl();
  try {
    const g = withFake(f);
    await f.set(
      "out.info",
      JSON.stringify({ version: "2.1.0", limaHome: f.home, vmTypes: ["vz"] }),
    );
    let r = fakeCtx(g);
    await behavior.methods.plan.execute({}, r.ctx as any);
    assertEquals(
      (r.written["plan-assistant-vm"] as any).action,
      "blocked-prerequisites",
    );

    await f.set(
      "out.info",
      JSON.stringify({ version: "2.2.0", limaHome: f.home, vmTypes: ["vz"] }),
    );
    const dir = `${f.home}/assistant-vm`;
    await f.set(
      "out.list",
      JSON.stringify({ name: "assistant-vm", status: "Stopped", dir }),
    );
    r = fakeCtx(g);
    await behavior.methods.plan.execute({}, r.ctx as any);
    assertEquals(
      (r.written["plan-assistant-vm"] as any).action,
      "blocked-unmanaged",
    );

    await Deno.mkdir(`${f.home}/.swamp-owned`, { recursive: true });
    const marker = {
      modelType: id.modelType,
      modelId: id.modelId,
      definitionId: id.definitionId,
      name: "assistant-vm",
      limaHome: f.home,
      instanceDir: dir,
      configHash: "0".repeat(64),
      imageDigest: DIGEST,
      createdAt: "2026-09-19T00:00:00Z",
    };
    await Deno.writeTextFile(
      markerPath(GlobalArgsSchema.parse(g)),
      JSON.stringify(marker),
    );
    r = fakeCtx(g);
    await behavior.methods.plan.execute({}, r.ctx as any);
    const plan = r.written["plan-assistant-vm"] as any;
    assertEquals(plan.action, "replacement-required");
    assertEquals(plan.diff.length, 1);

    marker.configHash = plan.configHash;
    await Deno.writeTextFile(
      markerPath(GlobalArgsSchema.parse(g)),
      JSON.stringify(marker),
    );
    r = fakeCtx(g);
    await behavior.methods.plan.execute({}, r.ctx as any);
    assertEquals(
      (r.written["plan-assistant-vm"] as any).action,
      "replacement-required",
      "missing observed config must not become noop",
    );
    await f.set(
      "out.list",
      JSON.stringify({
        name: "assistant-vm",
        status: "Stopped",
        dir,
        config: renderTemplate(GlobalArgsSchema.parse(g), []),
      }),
    );
    r = fakeCtx(g);
    await behavior.methods.plan.execute({}, r.ctx as any);
    assertEquals((r.written["plan-assistant-vm"] as any).action, "noop");
    const drifted = renderTemplate(GlobalArgsSchema.parse(g), []);
    drifted.portForwards = [{ guestPortRange: [1, 10], ignore: true }];
    await f.set(
      "out.list",
      JSON.stringify({
        name: "assistant-vm",
        status: "Stopped",
        dir,
        config: drifted,
      }),
    );
    r = fakeCtx(g);
    await behavior.methods.plan.execute({}, r.ctx as any);
    assertEquals(
      (r.written["plan-assistant-vm"] as any).action,
      "replacement-required",
    );
    assertEquals((r.written["plan-assistant-vm"] as any).diff, [
      "portForwards",
    ]);
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("create: refuses a wrong hash and a name collision; on success writes the marker and releases the lock", async () => {
  const f = await fakeLimactl();
  try {
    const g = withFake(f);
    const dir = `${f.home}/assistant-vm`;
    await f.set(
      "out.list",
      JSON.stringify({ name: "assistant-vm", status: "Stopped", dir }),
    );
    await assertRejects(
      () =>
        behavior.methods.create.execute(
          { configHash: "0".repeat(64) },
          fakeCtx(g).ctx as any,
        ),
      Error,
      "already exists",
    );

    await f.set("out.list", "");
    await assertRejects(
      () =>
        behavior.methods.create.execute(
          { configHash: "0".repeat(64) },
          fakeCtx(g).ctx as any,
        ),
      Error,
      "does not match",
    );

    const planned = fakeCtx(g);
    await behavior.methods.plan.execute({}, planned.ctx as any);
    const hash = (planned.written["plan-assistant-vm"] as any)
      .configHash as string;

    // The fake create makes the instance appear on the next list.
    await f.set("out.create", "");
    const listAfter = JSON.stringify({
      name: "assistant-vm",
      status: "Stopped",
      dir,
      vmType: "vz",
    });
    // list is answered from a file, so flip it as soon as create is called.
    await Deno.writeTextFile(
      f.bin,
      (await Deno.readTextFile(f.bin)).replace(
        'sub="$1"',
        `sub="$1"\n[ "$sub" = create ] && printf '%s' '${listAfter}' > "${f.dir}/out.list"`,
      ),
    );
    const r = fakeCtx(g);
    await behavior.methods.create.execute({ configHash: hash }, r.ctx as any);
    const inst = r.written["instance-assistant-vm"] as any;
    assertEquals(inst.state, "owned");
    assertEquals(inst.changed, true);
    assertEquals(inst.createdConfigHash, hash);
    const calls = await f.calls();
    assert(
      calls.some((c) =>
        /^--tty=false create --name assistant-vm \S+\.yaml$/.test(c)
      ),
      calls.join("|"),
    );
    const marker = JSON.parse(
      await Deno.readTextFile(markerPath(GlobalArgsSchema.parse(g))),
    );
    assertEquals(marker.instanceDir, dir);
    assertEquals(marker.modelId, id.modelId);
    const release = await acquireLock(
      GlobalArgsSchema.parse(g),
      "post-create-test",
      { info: () => {}, warning: () => {} },
    );
    await release(); // Persistent inode remains, but the OS lock was released.
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("create: a failed limactl create is reported and nothing is deleted", async () => {
  const f = await fakeLimactl();
  try {
    const g = withFake(f);
    const planned = fakeCtx(g);
    await behavior.methods.plan.execute({}, planned.ctx as any);
    const hash = (planned.written["plan-assistant-vm"] as any)
      .configHash as string;
    await f.set("exit.create", "1");
    await f.set("err.create", "FATA[0000] disk image download failed");
    await assertRejects(
      () =>
        behavior.methods.create.execute(
          { configHash: hash },
          fakeCtx(g).ctx as any,
        ),
      Error,
      "Nothing was deleted",
    );
    const calls = await f.calls();
    assert(
      !calls.some((c) => c.includes(" delete ")),
      "no delete on the failure path",
    );
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("OS lock refuses even an old live owner, releases on close, and refuses legacy files", async () => {
  const f = await fakeLimactl();
  try {
    const g = GlobalArgsSchema.parse(withFake(f, { lockStaleSec: 60 }));
    const log = { info: () => {}, warning: () => {} };
    const release = await acquireLock(g, "test", log);
    const path = `${f.home}/.swamp-owned/assistant-vm.lock`;
    const old = new Date(Date.now() - 120_000);
    await Deno.utime(path, old, old);
    await assertRejects(
      () => acquireLock(g, "test", log),
      Error,
      "holds the lock",
    );
    await release();
    const release2 = await acquireLock(g, "after-close", log);
    await release2();
    await Deno.writeTextFile(path, "{}");
    await Deno.utime(path, old, old);
    await assertRejects(
      () => acquireLock(g, "legacy", log),
      Error,
      "legacy or unreadable",
    );
    assertEquals(
      await Deno.readTextFile(path),
      "{}",
      "legacy evidence is preserved",
    );
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("start/stop/destroy refuse an unmanaged instance; destroy refuses a running one, a wrong name, and a bare backup claim", async () => {
  const f = await fakeLimactl();
  try {
    const g = withFake(f);
    const dir = `${f.home}/assistant-vm`;
    await f.set(
      "out.list",
      JSON.stringify({ name: "assistant-vm", status: "Running", dir }),
    );
    await assertRejects(
      () => behavior.methods.start.execute({}, fakeCtx(g).ctx as any),
      Error,
      "not owned",
    );
    await assertRejects(
      () => behavior.methods.stop.execute({}, fakeCtx(g).ctx as any),
      Error,
      "not owned",
    );
    await assertRejects(
      () =>
        behavior.methods.destroy.execute({
          confirmName: "assistant-vm",
          preservation: "no-unique-data",
        }, fakeCtx(g).ctx as any),
      Error,
      "not owned",
    );
    await Deno.mkdir(`${f.home}/.swamp-owned`, { recursive: true });
    await Deno.writeTextFile(
      markerPath(GlobalArgsSchema.parse(g)),
      JSON.stringify({
        modelType: id.modelType,
        modelId: id.modelId,
        definitionId: id.definitionId,
        name: "assistant-vm",
        limaHome: f.home,
        instanceDir: dir,
        configHash: "0".repeat(64),
        imageDigest: DIGEST,
        createdAt: "2026-09-19T00:00:00Z",
      }),
    );
    await assertRejects(
      () =>
        behavior.methods.destroy.execute({
          confirmName: "other",
          preservation: "no-unique-data",
        }, fakeCtx(g).ctx as any),
      Error,
      "confirmName",
    );
    await assertRejects(
      () =>
        behavior.methods.destroy.execute({
          confirmName: "assistant-vm",
          preservation: "backup-verified",
        }, fakeCtx(g).ctx as any),
      Error,
      "backupRef",
    );
    await assertRejects(
      () =>
        behavior.methods.destroy.execute({
          confirmName: "assistant-vm",
          preservation: "no-unique-data",
        }, fakeCtx(g).ctx as any),
      Error,
      "stopped",
    );
    // A no-op still verifies the creation identity and observed config.
    const approved = renderTemplate(GlobalArgsSchema.parse(g), []);
    await f.set(
      "out.list",
      JSON.stringify({
        name: "assistant-vm",
        status: "Running",
        dir,
        config: approved,
      }),
    );
    const mp = markerPath(GlobalArgsSchema.parse(g));
    const marker = JSON.parse(await Deno.readTextFile(mp));
    marker.configHash = await sha256Hex(canonical(approved));
    await Deno.writeTextFile(mp, JSON.stringify(marker));
    // Running already: start is a no-op and calls nothing.
    const before = (await f.calls()).length;
    const r = fakeCtx(g);
    await behavior.methods.start.execute({}, r.ctx as any);
    assertEquals((r.written["instance-assistant-vm"] as any).changed, false);
    assert(!(await f.calls()).slice(before).some((c) => c.includes(" start ")));
    // Stop path: no --force ever.
    await Deno.writeTextFile(
      f.bin,
      (await Deno.readTextFile(f.bin)).replace(
        'sub="$1"',
        `sub="$1"\n[ "$sub" = stop ] && printf '%s' '${
          JSON.stringify({ name: "assistant-vm", status: "Stopped", dir })
        }' > "${f.dir}/out.list"`,
      ),
    );
    const s = fakeCtx(g);
    await behavior.methods.stop.execute({}, s.ctx as any);
    assertEquals((s.written["instance-assistant-vm"] as any).status, "Stopped");
    assert(
      (await f.calls()).some((c) => c === "--tty=false stop assistant-vm"),
    );
    assert(!(await f.calls()).some((c) => c.includes("--force")));
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

// Security regression cases from the independent review; all process fixtures are offline.
Deno.test("image URLs reject userinfo, all queries and fragments before persistence", () => {
  for (
    const location of [
      "https://user:FAKE_PASSWORD@example.com/i",
      "https://example.com/i?token=FAKE_TOKEN",
      "https://example.com/i?",
      "https://example.com/i#secret",
      "http://example.com/i",
    ]
  ) {
    assert(
      !GlobalArgsSchema.safeParse(
        args({ image: { location, arch: "aarch64", digest: DIGEST } }),
      ).success,
    );
  }
});

Deno.test("mounts and homes reject noncanonical lexical components", () => {
  for (
    const location of [
      "/./etc",
      "//etc",
      "/srv/../etc",
      "/srv/./data",
      "/srv//data",
    ]
  ) {
    assert(
      !GlobalArgsSchema.safeParse(args({ mounts: [{ location }] })).success,
    );
    assert(!GlobalArgsSchema.safeParse(args({ limaHome: location })).success);
  }
  for (const limaHome of [HOME, `${HOME}/.lima`, `${HOME}/.lima/child`]) {
    assert(!GlobalArgsSchema.safeParse(args({ limaHome })).success);
  }
});

Deno.test("filesystem boundaries reject symlink mounts and aliases to default homes", async () => {
  const f = await fakeLimactl();
  try {
    await Deno.symlink(HOME, `${f.dir}/alias`);
    await assertRejects(
      async () =>
        await validatePaths(
          GlobalArgsSchema.parse(withFake(f, { limaHome: `${f.dir}/alias` })),
        ),
      Error,
      "dedicated",
    );
    await assertRejects(
      async () =>
        await validatePaths(
          GlobalArgsSchema.parse(
            withFake(f, { mounts: [{ location: `${f.dir}/alias` }] }),
          ),
        ),
      Error,
    );
    await assertRejects(
      async () =>
        await validatePaths(
          GlobalArgsSchema.parse(
            withFake(f, { limaHome: `${f.dir}/alias/.lima/new` }),
          ),
        ),
      Error,
      "dedicated",
    );
    const invalid = withFake(f, { limaHome: `${f.dir}/alias` });
    for (
      const method of [
        "inspect",
        "plan",
        "create",
        "start",
        "verify",
        "stop",
        "destroy",
      ] as const
    ) {
      await assertRejects(() =>
        behavior.methods[method].execute(
          {
            confirmName: "assistant-vm",
            preservation: "no-unique-data",
            configHash: "0".repeat(64),
          } as never,
          fakeCtx(invalid).ctx as any,
        )
      );
    }
    assertEquals(
      (await f.calls()).length,
      0,
      "no child runs before the mandatory boundary",
    );
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("host metadata is discarded while malformed facts and unknown VM security config fail closed", () => {
  const facts = { version: "2.3.0", limaHome: "/h", vmTypes: ["vz"] };
  assertEquals(
    LimaInfoSchema.parse({
      ...facts,
      templates: [],
      defaultTemplate: {},
      hostOS: "darwin",
      hostArch: "aarch64",
      identityFile: "/h/_config/user",
    }),
    facts,
  );
  assert(!LimaInfoSchema.safeParse({ ...facts, vmTypes: "vz" }).success);
  const one = { name: "a", status: "Running", dir: "/h/a" };
  for (
    const config of [{ portForwards: {} }, { ssh: "bad" }, { mounts: [null] }, {
      unexpected: true,
    }, { portForwards: [{ guestPortRange: [1] }] }]
  ) {
    assertEquals(parseList(JSON.stringify({ ...one, config })), null);
    assert(
      configChecks(GlobalArgsSchema.parse(args()), [], config).every((c) =>
        !c.pass
      ),
    );
  }
  assertEquals(parseList(JSON.stringify({ ...one, surprise: true })), null);
});

Deno.test("verification compares full forwards, mount writability, SSH and complete config", () => {
  const g = GlobalArgsSchema.parse(
    args({
      mounts: [{ location: "/srv/data", writable: false }],
      portForwards: [{ guestPort: 8080, hostPort: 18080 }],
    }),
  );
  const approved = renderTemplate(g, []);
  assert(configChecks(g, [], approved).every((c) => c.pass));
  for (
    const change of [
      (c: any) => c.portForwards[0].hostIP = "0.0.0.0",
      (c: any) => c.portForwards[0].guestIP = "0.0.0.0",
      (c: any) => c.portForwards[0].guestPort = 22,
      (c: any) => c.portForwards[0].proto = "udp",
      (c: any) => c.portForwards[1].guestPortRange = [1, 10],
      (c: any) => c.portForwards[1].ignore = false,
      (c: any) => c.mounts[0].writable = true,
      (c: any) => c.ssh.forwardX11Trusted = true,
      (c: any) => c.provision = [{ mode: "system", script: "unexpected" }],
      (c: any) => delete c.mountInotify,
    ]
  ) {
    const modified = structuredClone(approved);
    change(modified);
    assert(!configChecks(g, [], modified).every((c) => c.pass));
  }
});

async function ownedFixture(f: Fake, status = "Stopped") {
  const g = GlobalArgsSchema.parse(withFake(f));
  const config = renderTemplate(g, []);
  const inst = { name: g.name, status, dir: `${f.home}/${g.name}`, config };
  await f.set("out.list", JSON.stringify(inst));
  await Deno.mkdir(`${f.home}/.swamp-owned`, { recursive: true });
  await Deno.writeTextFile(
    markerPath(g),
    JSON.stringify({
      ...id,
      name: g.name,
      limaHome: f.home,
      instanceDir: inst.dir,
      configHash: await sha256Hex(canonical(config)),
      imageDigest: DIGEST,
      createdAt: "2026-09-19T00:00:00Z",
    }),
  );
  return { g, config, inst };
}

Deno.test("all persisted process strings are escaped and bounded; verification uses fixed diagnostics", async () => {
  const f = await fakeLimactl();
  try {
    const { g, inst } = await ownedFixture(f, "Running");
    const attack = "x\x1b\u202e" + "z".repeat(500);
    await f.set(
      "out.list",
      JSON.stringify({
        ...inst,
        dir: attack,
        vmType: attack,
        arch: attack,
        limaVersion: attack,
        errors: [attack],
        config: { ...inst.config, vmType: attack },
      }),
    );
    const r = fakeCtx(withFake(f));
    await behavior.methods.inspect.execute({}, r.ctx as any);
    const saved = r.written[`instance-${g.name}`] as any;
    for (const key of ["dir", "vmType", "arch", "limaVersion"]) {
      assertEquals(saved[key], safeText(attack));
    }
    assertEquals(saved.errors, [safeText(attack)]);
    const checks = configChecks(g, [], { ...inst.config, vmType: attack });
    assert(!JSON.stringify(checks).includes(attack));
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("start refuses desired drift, observed drift and missing config, including running no-op", async () => {
  for (const status of ["Stopped", "Running"]) {
    const f = await fakeLimactl();
    try {
      const { inst } = await ownedFixture(f, status);
      await assertRejects(
        () =>
          behavior.methods.start.execute(
            {},
            fakeCtx(withFake(f, { cpus: 5 })).ctx as any,
          ),
        Error,
        "replacement-required",
      );
      await f.set(
        "out.list",
        JSON.stringify({
          ...inst,
          config: {
            ...inst.config,
            mounts: [{ location: "/srv/data", writable: true }],
          },
        }),
      );
      await assertRejects(
        () =>
          behavior.methods.start.execute({}, fakeCtx(withFake(f)).ctx as any),
        Error,
        "replacement-required",
      );
      const { config: _config, ...missing } = inst;
      await f.set("out.list", JSON.stringify(missing));
      await assertRejects(
        () =>
          behavior.methods.start.execute({}, fakeCtx(withFake(f)).ctx as any),
        Error,
        "replacement-required",
      );
      assert(!(await f.calls()).some((c) => c.includes(" start ")));
    } finally {
      await Deno.remove(f.dir, { recursive: true });
    }
  }
});

Deno.test("mutations observe ownership and state only after acquiring the lock", async () => {
  for (const method of ["start", "stop", "destroy"] as const) {
    const f = await fakeLimactl();
    try {
      const { inst } = await ownedFixture(
        f,
        method === "stop" ? "Running" : "Stopped",
      );
      // Fake list changes ownership whenever it is invoked while the lock exists.
      const changed = { ...inst, dir: `${f.home}/foreign` };
      await Deno.writeTextFile(
        f.bin,
        (await Deno.readTextFile(f.bin)).replace(
          'sub="$1"',
          `sub="$1"\n[ "$sub" = list ] && [ -f "${f.home}/.swamp-owned/assistant-vm.lock" ] && printf '%s' '${
            JSON.stringify(changed)
          }' > "${f.dir}/out.list"`,
        ),
      );
      await assertRejects(
        () =>
          behavior.methods[method].execute(
            {
              confirmName: "assistant-vm",
              preservation: "no-unique-data",
            } as never,
            fakeCtx(withFake(f)).ctx as any,
          ),
        Error,
        "not owned",
      );
      assert(
        !(await f.calls()).some((c) =>
          new RegExp(" (start|stop|delete) ").test(c)
        ),
      );
    } finally {
      await Deno.remove(f.dir, { recursive: true });
    }
  }
});

Deno.test("destroy rechecks running state and all mutations reject unmet prerequisites under lock", async () => {
  const f = await fakeLimactl();
  try {
    const { inst } = await ownedFixture(f);
    const running = { ...inst, status: "Running" };
    await Deno.writeTextFile(
      f.bin,
      (await Deno.readTextFile(f.bin)).replace(
        'sub="$1"',
        `sub="$1"\n[ "$sub" = list ] && [ -f "${f.home}/.swamp-owned/assistant-vm.lock" ] && printf '%s' '${
          JSON.stringify(running)
        }' > "${f.dir}/out.list"`,
      ),
    );
    await assertRejects(
      () =>
        behavior.methods.destroy.execute({
          confirmName: "assistant-vm",
          preservation: "no-unique-data",
        }, fakeCtx(withFake(f)).ctx as any),
      Error,
      "stopped",
    );
    await f.set(
      "out.info",
      JSON.stringify({
        version: "2.2.0",
        limaHome: "/wrong/home",
        vmTypes: ["vz"],
      }),
    );
    for (const method of ["start", "stop", "destroy"] as const) {
      await assertRejects(
        () =>
          behavior.methods[method].execute(
            {
              confirmName: "assistant-vm",
              preservation: "no-unique-data",
            } as never,
            fakeCtx(withFake(f)).ctx as any,
          ),
        Error,
        "host is not ready",
      );
    }
    assert(
      !(await f.calls()).some((c) =>
        new RegExp(" (start|stop|delete) ").test(c)
      ),
    );
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("approved start and stopped destroy still work under their locks", async () => {
  const f = await fakeLimactl();
  try {
    const { inst } = await ownedFixture(f);
    await Deno.writeTextFile(
      f.bin,
      (await Deno.readTextFile(f.bin)).replace(
        'sub="$1"',
        `sub="$1"\n[ "$sub" = start ] && printf '%s' '${
          JSON.stringify({ ...inst, status: "Running" })
        }' > "${f.dir}/out.list"\n[ "$sub" = delete ] && printf '' > "${f.dir}/out.list"`,
      ),
    );
    const started = fakeCtx(withFake(f));
    await behavior.methods.start.execute({}, started.ctx as any);
    assertEquals(
      (started.written["instance-assistant-vm"] as any).changed,
      true,
    );
    await f.set("out.list", JSON.stringify(inst));
    const destroyed = fakeCtx(withFake(f));
    await behavior.methods.destroy.execute({
      confirmName: "assistant-vm",
      preservation: "no-unique-data",
    }, destroyed.ctx as any);
    assertEquals(
      (destroyed.written["instance-assistant-vm"] as any).state,
      "missing",
    );
    assert(
      (await f.calls()).includes(
        "--tty=false start --timeout 600s assistant-vm",
      ),
    );
    assert((await f.calls()).includes("--tty=false delete assistant-vm"));
  } finally {
    await Deno.remove(f.dir, { recursive: true });
  }
});

Deno.test("OS lock excludes another process and releases after that process exits", async () => {
  const f = await fakeLimactl();
  let child: Deno.ChildProcess | undefined;
  try {
    const g = GlobalArgsSchema.parse(withFake(f));
    const module = new URL("./lima.ts", import.meta.url).href;
    const source = `import { acquireLock } from ${JSON.stringify(module)};
await acquireLock(${
      JSON.stringify(g)
    }, "child-test", {info:()=>{},warning:()=>{}});
console.log("locked"); setInterval(()=>{},1000);`;
    child = new Deno.Command(Deno.execPath(), {
      args: ["eval", "--cached-only", source],
      clearEnv: true,
      env: {
        HOME,
        DENO_DIR: Deno.env.get("DENO_DIR") ?? "",
        DENO_NO_UPDATE_CHECK: "1",
      },
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    const reader = child.stdout.getReader();
    try {
      const first = await reader.read();
      assertStringIncludes(new TextDecoder().decode(first.value), "locked");
    } finally {
      reader.releaseLock();
    }
    const log = { info: () => {}, warning: () => {} };
    await assertRejects(
      () => acquireLock(g, "parent-test", log),
      Error,
      "holds the lock",
    );
    child.kill("SIGKILL");
    await child.status;
    await child.stdout.cancel();
    await child.stderr.cancel();
    child = undefined;
    const release = await acquireLock(g, "after-exit", log);
    await release();
  } finally {
    if (child) {
      try {
        child.kill("SIGKILL");
      } catch { /* Already exited. */ }
      await child.status;
      await child.stdout.cancel();
      await child.stderr.cancel();
    }
    await Deno.remove(f.dir, { recursive: true });
  }
});
