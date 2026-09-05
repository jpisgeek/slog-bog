import {
  assertEquals,
  assertNotEquals,
  assertRejects,
} from "jsr:@std/assert@1";
import {
  buildChildEnv,
  type CommandRunner,
  defaultRunner,
  model,
  projectPayload,
} from "./swamp_observability.ts";

type Json = Record<string, unknown>;

Deno.test({
  name:
    "symlink and parent-directory aliases cannot launch a repository executable",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const base = await Deno.makeTempDir({ prefix: "example-observer-alias-" });
    const repo = `${base}/repo`;
    await Deno.mkdir(repo);
    const binary = `${repo}/example-binary`;
    const marker = `${repo}/executed`;
    await Deno.writeTextFile(binary, `#!/bin/sh\n: > '${marker}'\n`);
    await Deno.chmod(binary, 0o755);
    await Deno.symlink(binary, `${base}/alias`);
    try {
      for (
        const candidate of [`${base}/alias`, `${repo}/../repo/example-binary`]
      ) {
        await assertRejects(() =>
          defaultRunner(candidate, [], {
            cwd: repo,
            env: {},
            signal: new AbortController().signal,
          })
        );
      }
      await assertRejects(() => Deno.stat(marker), Deno.errors.NotFound);
    } finally {
      await Deno.remove(base, { recursive: true });
    }
  },
});

function context(
  written: Json[],
  globalArgs: Json = {},
  commandRunner?: CommandRunner,
) {
  return {
    commandRunner,
    globalArgs: {
      repoDir: "/tmp/synthetic-swamp-repo",
      swampBinary: "swamp",
      timeoutMs: 1000,
      ...globalArgs,
    },
    signal: new AbortController().signal,
    writeResource: (_spec: string, _name: string, data: Json) => {
      written.push(data);
      return Promise.resolve({});
    },
  };
}

/** A runner that answers every interface with one fixed payload. */
function respondWith(payload: unknown) {
  const calls: Array<{ env: Record<string, string> }> = [];
  const runner: CommandRunner = (_binary, _args, options) => {
    calls.push({ env: options.env });
    return Promise.resolve({
      success: true,
      code: 0,
      stdout: JSON.stringify(payload),
      stderr: "",
    });
  };
  return { calls, runner };
}

Deno.test("a caller's runner override cannot affect a subsequent default observation", async () => {
  const { calls, runner } = respondWith({
    runs: [],
    results: [],
    totalTracked: 0,
    active: 0,
    stale: 0,
    orphaned: 0,
  });
  const injected: Json[] = [];
  await model.methods.observe.execute({}, context(injected, {}, runner));
  assertEquals(
    injected.slice(0, 4).every((item) => item.available === true),
    true,
  );

  const dir = await Deno.makeTempDir({ prefix: "example-default-observer-" });
  const defaultWritten: Json[] = [];
  try {
    await model.methods.observe.execute(
      {},
      context(defaultWritten, {
        repoDir: dir,
        swampBinary: `${dir}/missing-example-executable`,
      }),
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
  assertEquals(calls.length, 4);
  assertEquals(
    defaultWritten.slice(0, 4).every((item) => item.available === false),
    true,
  );
});

Deno.test("collector records successful documented-interface responses", async () => {
  const runner: CommandRunner = (_binary, args) => {
    const payload = args[0] === "run" && args[1] === "doctor"
      ? { totalTracked: 0, active: 0, stale: 0, reaped: 0 }
      : args[0] === "run"
      ? { runs: [] }
      : { query: "", results: [] };
    return Promise.resolve({
      success: true,
      code: 0,
      stdout: JSON.stringify(payload),
      stderr: "",
    });
  };
  const written: Json[] = [];
  await model.methods.observe.execute({}, context(written, {}, runner));
  assertEquals(written.length, 5);
  assertEquals(
    written.slice(0, 4).every((item) => item.available === true),
    true,
  );
  assertEquals(written[4].errorKind, "unsupported");
});

Deno.test("collector classifies failures without persisting command output", async () => {
  const runner: CommandRunner = () =>
    Promise.resolve({
      success: false,
      code: 1,
      stdout: "response included private-host.example.invalid",
      stderr: "connection refused for private-host.example.invalid",
    });
  const written: Json[] = [];
  await model.methods.observe.execute({}, context(written, {}, runner));
  assertEquals(
    written.slice(0, 4).every((item) => item.available === false),
    true,
  );
  assertEquals(
    written.slice(0, 4).every((item) => item.errorKind === "unreachable"),
    true,
  );
  assertEquals(
    written.some((item) => JSON.stringify(item).includes("private-host")),
    false,
  );
});

Deno.test("a successful response is projected, never persisted verbatim", async () => {
  // Everything below is a field a real response can carry and this extension
  // has no business keeping for 30 days: repository paths, report and model
  // names, operator prose, an embedded credential. Only counts, statuses from
  // the closed vocabulary, and booleans may survive the projection.
  const { runner } = respondWith({
    results: [
      {
        reportName: "@acme/private-report",
        dataName: "/srv/private/repo/data.json",
        status: "SUCCEEDED",
        message: "token=synthetic-secret",
        owner: "someone@example.invalid",
      },
      { status: "a status long enough to be prose rather than a token" },
      "not even an object",
    ],
    query: "private search text",
  });
  const written: Json[] = [];
  await model.methods.observe.execute({}, context(written, {}, runner));
  const reports = written.find((item) => item.interface === "stored-reports");
  assertEquals(reports?.available, true);
  assertEquals(reports?.payload, {
    // The identity is reduced to the fact that there was one, and the prose
    // status to the fact that it was not recognized.
    results: [
      { status: "succeeded", identified: true },
      { status: "unknown" },
      {},
    ],
  });
  const serialized = JSON.stringify(written);
  for (
    const leaked of [
      "private-report",
      "/srv/private",
      "synthetic-secret",
      "example.invalid",
      "private search text",
      "prose rather than a token",
    ]
  ) {
    assertEquals(serialized.includes(leaked), false, leaked);
  }
});

Deno.test("a status is a vocabulary word or it is 'unknown', never remote text", async () => {
  // The status field was stored as it arrived whenever it fit a 32-character
  // shape. Every value below fits that shape, and every one of them is a real
  // thing a hostile or merely chatty response can put in a status field: a
  // short credential, an internal host, an address, an account number, a
  // person's machine. Length and alphabet were never what made a status safe;
  // being one of six known words is.
  const smuggled = [
    "sk-live-9f2c1d4b8e",
    "nas.internal.lan",
    "203.0.113.19",
    "acct-8841203",
    "example-device",
    "AKIAIOSFODNN7EXAMPLE",
  ];
  const { runner } = respondWith({
    runs: smuggled.map((status) => ({ status })),
  });
  const written: Json[] = [];
  await model.methods.observe.execute({}, context(written, {}, runner));
  const history = written.find((item) => item.interface === "run-history");
  assertEquals(history?.available, true);
  assertEquals(history?.payload, {
    runs: smuggled.map(() => ({ status: "unknown" })),
  });
  const serialized = JSON.stringify(written);
  for (const value of smuggled) {
    assertEquals(serialized.includes(value), false, value);
  }
});

Deno.test("recognized statuses still classify, and compound ones never pass", () => {
  // Classification moved to the collection boundary with the redaction, so the
  // vocabulary is exercised here now. "completed_with_errors" matched
  // /completed/ under the old substring probes and was counted as a success.
  const project = (status: string) =>
    (projectPayload("run-history", { runs: [{ status }] }) as {
      runs: Array<{ status?: string }>;
    }).runs[0].status;
  assertEquals(project("Completed"), "succeeded");
  assertEquals(project("running"), "active");
  assertEquals(project("cancelled"), "failed");
  assertEquals(project("stalled"), "stale");
  assertEquals(project("completed_with_errors"), "unknown");
  assertEquals(project("unsuccessful"), "failed");
  // An absent status stays absent: "this build exposes no status field" is a
  // different fact from "this status was not recognized".
  assertEquals(
    projectPayload("run-history", { runs: [{ id: "x" }] }),
    { runs: [{ identified: true }] },
  );
});

Deno.test("a diagnostic count outside nonnegative integers invalidates the snapshot", async () => {
  // JSON has no NaN or Infinity, so the reachable cases are a negative count,
  // a fraction, and a magnitude past the integers JavaScript can still count in.
  for (const stale of [-1, 1.5, 1e308]) {
    const { runner } = respondWith({
      totalTracked: 3,
      active: 0,
      stale,
      orphaned: 0,
    });
    const written: Json[] = [];
    await model.methods.observe.execute({}, context(written, {}, runner));
    const doctor = written.find((item) => item.interface === "run-doctor");
    assertEquals(doctor?.available, false, String(stale));
    assertEquals(doctor?.errorKind, "invalid-response", String(stale));
    assertEquals(doctor?.payload, null, String(stale));
  }
});

Deno.test("an unknown run doctor count is dropped rather than rejected", async () => {
  // `reaped` is real output from a current build. A future counter must not
  // reach the datastore, and must not blind the four counts that did arrive.
  const { runner } = respondWith({
    totalTracked: 2,
    active: 1,
    stale: 0,
    orphaned: 0,
    reaped: 7,
  });
  const written: Json[] = [];
  await model.methods.observe.execute({}, context(written, {}, runner));
  const doctor = written.find((item) => item.interface === "run-doctor");
  assertEquals(doctor?.available, true);
  assertEquals(doctor?.payload, {
    totalTracked: 2,
    active: 1,
    stale: 0,
    orphaned: 0,
  });
});

Deno.test("a response that is not the documented shape is a coverage gap", () => {
  assertEquals(projectPayload("run-history", { error: "nope" }), undefined);
  assertEquals(projectPayload("run-history", "a string"), undefined);
  assertEquals(projectPayload("run-doctor", [1, 2, 3]), undefined);
  // A bare list is the documented alternative container and still projects.
  assertEquals(projectPayload("run-history", [{ status: "ok" }]), {
    runs: [{ status: "succeeded" }],
  });
});

Deno.test("a configuration asking for the removed remote mode launches nothing", async () => {
  // The allowlist this model used to carry pinned the first hop only. Whatever
  // answered it could redirect to any host, over http, and the redirect was
  // followed inside the Swamp executable — a client whose policy this model
  // does not set and cannot see, carrying the token it had just been handed.
  // There is no destination and no credential now, and a configuration that
  // still asks for one fails instead of quietly observing the local repository
  // and presenting that as the remote answer.
  for (
    const remote of [
      { server: "https://swamp.example.invalid" },
      { token: "synthetic-secret" },
      { allowedServerHosts: ["swamp.example.invalid"] },
      {
        server: "https://swamp.example.invalid",
        token: "synthetic-secret",
        allowedServerHosts: ["swamp.example.invalid"],
      },
    ]
  ) {
    const { calls, runner } = respondWith({ runs: [] });
    await assertRejects(
      () => model.methods.observe.execute({}, context([], remote, runner)),
      Error,
      "no longer accepted",
    );
    assertEquals(calls.length, 0, JSON.stringify(remote));
  }
});

Deno.test("no argument can put a URL in argv or a credential in the child env", async () => {
  // The structural half of the same finding: even if the refusal above were
  // bypassed, there is nothing left for a destination or a credential to flow
  // through. The declared arguments do not include them, argv is built from
  // fixed command words, and the child environment is never given a value.
  assertEquals(
    Object.keys(model.globalArguments.shape).sort(),
    ["repoDir", "swampBinary", "timeoutMs"],
  );
  const calls: Array<{ args: string[]; env: Record<string, string> }> = [];
  const runner: CommandRunner = (_binary, args, options) => {
    calls.push({ args, env: options.env });
    return Promise.resolve({
      success: true,
      code: 0,
      stdout: JSON.stringify({ runs: [] }),
      stderr: "",
    });
  };
  await model.methods.observe.execute({}, context([], {}, runner));
  assertEquals(calls.length, 4);
  for (const call of calls) {
    assertEquals(call.args.includes("--server"), false);
    assertEquals(
      call.args.some((arg) => arg.includes("://")),
      false,
    );
    assertEquals(Object.keys(call.env).length, 0);
  }
});

Deno.test("a relative swamp binary is refused before it can be executed", async () => {
  const { calls, runner } = respondWith({ runs: [] });
  for (const binary of ["./swamp", "bin/swamp", "../swamp"]) {
    await assertRejects(
      () =>
        model.methods.observe.execute(
          {},
          context([], { swampBinary: binary }, runner),
        ),
      Error,
      "swampBinary",
    );
  }
  assertEquals(calls.length, 0);
});

Deno.test("the child environment is the allowlist plus what this model passes", () => {
  // The child used to inherit the whole parent environment, which on a swamp
  // host carries every other extension's credentials.
  const parent: Record<string, string> = {
    PATH: "/usr/bin",
    HOME: "/home/synthetic",
    TMPDIR: "/tmp",
    AWS_SECRET_ACCESS_KEY: "synthetic-aws",
    ANTHROPIC_API_KEY: "synthetic-anthropic",
    SWAMP_SERVER_TOKEN: "ambient-token-not-configured-here",
  };
  const env = buildChildEnv(
    { SWAMP_TEST_MARKER: "1" },
    (name) => parent[name],
    "/tmp/synthetic-swamp-repo",
  );
  assertEquals(env, {
    PATH: "/usr/bin",
    TMPDIR: "/tmp",
    SWAMP_TEST_MARKER: "1",
  });
  assertEquals(buildChildEnv({}, () => undefined, "/tmp/repo"), {});
});

Deno.test({
  name: "the child gets an isolated empty HOME, never the operator's",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    // HOME was inherited straight from the parent, so the executable ran with
    // the operator's own Swamp CLI configuration in reach: the credential that
    // configuration can hold, and the remote `server` it can point at, were one
    // file read away from a child this extension documents as having neither.
    // Nothing else in this model could tell — the argv is clean and no URL is
    // ever passed — which is exactly why the environment had to stop carrying
    // it. `env` is the honest witness: it prints what the child actually got.
    const result = await defaultRunner("/usr/bin/env", [], {
      cwd: "/tmp",
      env: {},
      signal: new AbortController().signal,
    });
    assertEquals(result.success, true);
    const line = result.stdout.split("\n").find((entry) =>
      entry.startsWith("HOME=")
    );
    if (line === undefined) {
      throw new Error("child environment carried no HOME");
    }
    const home = line.slice("HOME=".length);
    assertNotEquals(home, Deno.env.get("HOME"));
    // Isolated means empty: there is no configuration file in there for the
    // child to read a credential or a server URL out of.
    assertEquals([...Deno.readDirSync(home)].length, 0);
  },
});

Deno.test({
  name: "a bare binary cannot resolve inside the observed repository",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    // assertSwampBinary refuses `./swamp`, but the child runs with cwd:
    // repoDir and execvp resolves a relative or empty PATH entry against that
    // cwd. So a bare name — the default, and the other form the check allows —
    // still reached <repoDir>/swamp whenever the parent's PATH carried `.` or a
    // stray trailing colon. The front door was locked and the window was open.
    const repo = Deno.makeTempDirSync({ prefix: "swamp-observability-repo-" });
    const binary = "swamp-observability-planted";
    const marker = `${repo}/planted-binary-ran`;
    Deno.writeTextFileSync(
      `${repo}/${binary}`,
      `#!/bin/sh\n: > "${marker}"\necho '{"runs":[]}'\n`,
    );
    Deno.chmodSync(`${repo}/${binary}`, 0o755);
    const path = Deno.env.get("PATH");
    // `.` and the empty trailing entry both mean "the directory we are in",
    // and the absolute entry names the repository outright.
    Deno.env.set("PATH", `.:${repo}:`);
    let ran = true;
    try {
      // Nothing is left on PATH to resolve against, so the launch fails: a
      // coverage gap, which is the honest answer to "I will not run that".
      await assertRejects(() =>
        defaultRunner(binary, ["run", "history"], {
          cwd: repo,
          env: {},
          signal: new AbortController().signal,
        })
      );
      try {
        Deno.statSync(marker);
      } catch {
        ran = false;
      }
    } finally {
      if (path === undefined) Deno.env.delete("PATH");
      else Deno.env.set("PATH", path);
      Deno.removeSync(repo, { recursive: true });
    }
    assertEquals(ran, false);
  },
});

Deno.test({
  name: "a child that will not stop writing is capped and killed",
  // Deno.Command is unavailable on a platform this extension does not publish
  // for; `yes` is coreutils on linux and BSD on darwin, present at this path
  // on both.
  ignore: Deno.build.os === "windows",
  fn: async () => {
    // `child.output()` buffered both pipes to completion with no limit, so the
    // memory this model allocated was chosen by the command it launched. `yes`
    // is the honest version of that command: it never stops writing, so
    // without a cap this call does not return until the process dies. The cap
    // makes the ceiling ours, the child is killed rather than left writing,
    // and the bytes read before the cap are discarded rather than parsed.
    const started = Date.now();
    const result = await defaultRunner("/usr/bin/yes", ["swamp"], {
      cwd: "/tmp",
      env: {},
      signal: new AbortController().signal,
    });
    assertEquals(result.truncated, true);
    assertEquals(result.success, false);
    assertEquals(result.stdout, "");
    assertEquals(result.stderr, "");
    // A cap that is not enforced promptly is not a cap; 4 MiB of `yes` is a
    // fraction of a second, and the assertion is only here to fail loudly
    // rather than hang if the reader ever stops stopping.
    assertEquals(Date.now() - started < 30_000, true);
  },
});

Deno.test({
  name: "output past the cap is refused rather than returned",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    // A finite 8 MiB answer, twice the 4 MiB stdout cap. The `yes` case above
    // covers the unbounded attacker; this one pins the boundary itself, and it
    // fails immediately — rather than by hanging — if the cap stops being
    // enforced.
    const result = await defaultRunner(
      "/usr/bin/head",
      ["-c", String(8 * 1024 * 1024), "/dev/zero"],
      { cwd: "/tmp", env: {}, signal: new AbortController().signal },
    );
    assertEquals(result.truncated, true);
    assertEquals(result.success, false);
    assertEquals(result.stdout, "");
  },
});

Deno.test({
  name: "a child under the cap still returns its whole output",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    // The positive control for the cap above: capped reading must still be
    // reading. A guard that truncates everything would pass the `yes` test and
    // silently blind the collector.
    const result = await defaultRunner("/bin/echo", ['{"runs":[]}'], {
      cwd: "/tmp",
      env: {},
      signal: new AbortController().signal,
    });
    assertEquals(result.success, true);
    assertEquals(result.truncated, false);
    assertEquals(result.stdout.trim(), '{"runs":[]}');
  },
});

Deno.test("an oversized response is recorded as a coverage gap, not parsed", async () => {
  // The observation must say the interface was not read. Returning the prefix
  // that arrived would hand JSON.parse half a document, and a half-document
  // that happens to parse is how a partial answer becomes a confident number.
  const runner: CommandRunner = () =>
    Promise.resolve({
      success: false,
      code: 0,
      stdout: "",
      stderr: "",
      truncated: true,
    });
  const written: Json[] = [];
  await model.methods.observe.execute({}, context(written, {}, runner));
  for (const item of written.slice(0, 4)) {
    assertEquals(item.available, false);
    assertEquals(item.errorKind, "oversized");
    assertEquals(item.payload, null);
  }
});

Deno.test("an already-aborted signal is honored before a process exists", async () => {
  // addEventListener on an aborted signal never fires, so spawning first left
  // a process running for a caller that had already cancelled.
  const controller = new AbortController();
  controller.abort(new Error("cancelled before launch"));
  await assertRejects(
    () =>
      defaultRunner("swamp", ["run", "history"], {
        cwd: "/tmp/synthetic-swamp-repo",
        env: {},
        signal: controller.signal,
      }),
    Error,
    "cancelled before launch",
  );
});
