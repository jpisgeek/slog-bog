/**
 * Tests for @jpisgeek/mise.
 *
 * Exported surface only, and not in the manifest, so this file does not move
 * the content hash the security review is bound to.
 *
 * Two properties carry the weight here. First, injection: `dir` and
 * `misePath` are the only operator values that reach a remote command string,
 * so they must be rejected at parse time rather than quietly repaired.
 * Second, honesty: a host where mise never ran must never be recorded as a
 * host with no tools. An empty bog and an unmeasured bog look identical from
 * the road.
 *
 * Requires --allow-run --allow-write --allow-read (fake binary in a temp dir).
 */
import {
  assertEquals,
  assertMatch,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import {
  classifyFailure,
  classifyTool,
  GlobalArgsSchema,
  localArgs,
  model,
  notInEffect,
  parseConfigLs,
  parseLsCurrent,
  parseOutdated,
  parseTrustShow,
  parseVersion,
  remoteCommand,
  remoteErrorCode,
  runMise,
  safeRemoteKey,
  safeRemoteString,
  satisfiesExpect,
  sshArgs,
  SUB_LS,
} from "./mise.ts";

const okNode = { name: "workstation" };

function assertNoControlCharacters(value: unknown): void {
  if (typeof value === "string") {
    assertEquals(/[\u0000-\u001f\u007f-\u009f]/.test(value), false);
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) assertNoControlCharacters(entry);
    return;
  }
  if (value && typeof value === "object") {
    for (const entry of Object.values(value)) assertNoControlCharacters(entry);
  }
}

Deno.test("dir must be absolute and free of traversal", () => {
  const bad = [
    "relative/path",
    "/etc/../etc/passwd",
    "/tmp/it's-quoted",
    "/tmp/semi;colon",
    "-C/tmp",
  ];
  for (const dir of bad) {
    const r = GlobalArgsSchema.safeParse({ nodes: [{ ...okNode, dir }] });
    assertEquals(r.success, false, `dir should have been rejected: ${dir}`);
  }
  const good = GlobalArgsSchema.safeParse({
    nodes: [{ ...okNode, dir: "/srv/project" }],
  });
  assertEquals(good.success, true, "a plain absolute path should parse");
});

Deno.test("misePath rejects a leading dash and shell metacharacters", () => {
  for (const misePath of ["-oProxyCommand=x", "mise; rm -rf /", "mi'se"]) {
    const r = GlobalArgsSchema.safeParse({ nodes: [{ ...okNode, misePath }] });
    assertEquals(r.success, false, `misePath should be rejected: ${misePath}`);
  }
  const r = GlobalArgsSchema.safeParse({
    nodes: [{ ...okNode, misePath: "/opt/homebrew/bin/mise" }],
  });
  assertEquals(r.success, true);
  assertEquals(r.data!.nodes[0].misePath, "/opt/homebrew/bin/mise");
});

Deno.test("misePath defaults to bare mise", () => {
  const r = GlobalArgsSchema.parse({ nodes: [okNode] });
  assertEquals(r.nodes[0].misePath, "mise");
});

Deno.test("ssh host and user must not be parseable as ssh options", () => {
  const r = GlobalArgsSchema.safeParse({
    nodes: [{ ...okNode, ssh: { host: "-oProxyCommand=id", user: "reader" } }],
  });
  assertEquals(r.success, false);
  const r2 = GlobalArgsSchema.safeParse({
    nodes: [{ ...okNode, ssh: { host: "host.example.com", user: "-x" } }],
  });
  assertEquals(r2.success, false);
});

Deno.test("duplicate node names are rejected", () => {
  const r = GlobalArgsSchema.safeParse({
    nodes: [{ name: "workstation" }, { name: "workstation" }],
  });
  assertEquals(r.success, false, "two nodes cannot share a name");
});

Deno.test("node names cannot carry terminal control characters", () => {
  const r = GlobalArgsSchema.safeParse({
    nodes: [{ name: "builder\u001b[31m" }],
  });
  assertEquals(r.success, false);
});

Deno.test("expect matches on whole version segments, never string prefix", () => {
  assertEquals(satisfiesExpect("22", "22.23.2"), true);
  assertEquals(satisfiesExpect("22.23", "22.23.2"), true);
  assertEquals(satisfiesExpect("22.23.2", "22.23.2"), true);
  // the whole reason this is segment-wise: "22.2" is a string prefix of
  // "22.23.2" but a different minor line entirely.
  assertEquals(satisfiesExpect("22.2", "22.23.2"), false);
  assertEquals(satisfiesExpect("22", "2.22.0"), false);
  // asking for more precision than the host reports is not a match
  assertEquals(satisfiesExpect("22.23.2", "22.23"), false);
});

Deno.test("a configured tool the host never installed is notinstalled", () => {
  const d = classifyTool({
    installed: false,
    active: false,
    resolvedVersion: "1.0.0",
  }, {
    outdated: false,
    expectFail: false,
  });
  assertEquals(d, ["notinstalled"]);
});

Deno.test("installed but not active is its own class, not notinstalled", () => {
  const d = classifyTool({
    installed: true,
    active: false,
    resolvedVersion: "1.0.0",
  }, {
    outdated: false,
    expectFail: false,
  });
  assertEquals(d, ["notactive"]);
});

Deno.test("a healthy tool carries no drift", () => {
  const d = classifyTool({
    installed: true,
    active: true,
    resolvedVersion: "1.0.0",
  }, {
    outdated: false,
    expectFail: false,
  });
  assertEquals(d, []);
});

Deno.test("outdated and expect failures stack onto the install state", () => {
  const d = classifyTool({
    installed: true,
    active: true,
    resolvedVersion: "1.0.0",
  }, {
    outdated: true,
    expectFail: true,
  });
  assertEquals(d, ["outdated", "expected"]);
});

Deno.test("local invocation is an argv array with no shell involved", () => {
  assertEquals(localArgs("/srv/project", SUB_LS), [
    "-C",
    "/srv/project",
    "ls",
    "--current",
    "--json",
  ]);
  assertEquals(localArgs(undefined, SUB_LS), ["ls", "--current", "--json"]);
});

Deno.test("remote command single-quotes the dir and nothing else", () => {
  assertEquals(
    remoteCommand("mise", "/srv/project", SUB_LS),
    "mise -C '/srv/project' ls --current --json",
  );
  assertEquals(
    remoteCommand("/opt/homebrew/bin/mise", undefined, SUB_LS),
    "/opt/homebrew/bin/mise ls --current --json",
  );
});

Deno.test("every value in the remote command survived schema validation", () => {
  const parsed = GlobalArgsSchema.safeParse({
    nodes: [{ name: "n", dir: "/srv/it's" }],
  });
  assertEquals(parsed.success, false, "a quote in dir must never parse");
});

Deno.test("misePath reaches the remote command unquoted, so its charset is load-bearing", () => {
  for (const misePath of ["mise$(id)", "mise`id`", "mise path", "mise|tee"]) {
    const r = GlobalArgsSchema.safeParse({ nodes: [{ name: "n", misePath }] });
    assertEquals(r.success, false, `misePath should be rejected: ${misePath}`);
  }
});

/** Read an `-o Key=value` option out of an argv, independent of position. */
function sshOpt(args: string[], key: string): string | undefined {
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === "-o" && args[i + 1].startsWith(`${key}=`)) {
      return args[i + 1].slice(key.length + 1);
    }
  }
  return undefined;
}

Deno.test("ssh flags fail closed and never spawn a local shell", () => {
  const args = sshArgs(
    { host: "host.example.com", user: "reader", port: 2222 },
    15,
    "mise ls --current --json",
  );
  // Asserted by property rather than by exact argv, so adding an option does
  // not break the test that exists to protect the security posture.
  assertEquals(sshOpt(args, "BatchMode"), "yes");
  // BatchMode alone does not make an unknown host key fail closed -- it only
  // removes the prompt. Without an explicit policy, ambient ssh_config can set
  // StrictHostKeyChecking=no and ssh will trust a key it has never seen.
  assertEquals(sshOpt(args, "StrictHostKeyChecking"), "yes");
  assertEquals(args[args.length - 2], "reader@host.example.com");
  assertEquals(args[args.length - 1], "mise ls --current --json");
  assertEquals(args.includes("2222"), true);
  // Nothing that could reach a local shell. Not merely "we do not pass one":
  // ProxyCommand and LocalCommand are ambient directives that run a shell
  // command, and ssh expands %h and %u into them, so an operator config
  // written for interactive use would turn every value in this model's node
  // list into local shell input. Both are refused on the command line.
  assertEquals(sshOpt(args, "ProxyCommand"), "none");
  assertEquals(sshOpt(args, "PermitLocalCommand"), "no");
});

Deno.test("an unknown host key is never accepted on the ssh command line", () => {
  const args = sshArgs({ host: "h.example.com", user: "u", port: 22 }, 15, "x");
  const policy = sshOpt(args, "StrictHostKeyChecking");
  // "accept-new" would silently trust first contact, which is the failure this
  // guards: it looks strict and is not.
  assertEquals(policy, "yes");
  assertEquals(policy === "no" || policy === "accept-new", false);
});

Deno.test("connect timeout is capped at ten seconds", () => {
  const args = sshArgs({ host: "h.example.com", user: "u", port: 22 }, 90, "x");
  assertEquals(sshOpt(args, "ConnectTimeout"), "10");
  const quick = sshArgs({ host: "h.example.com", user: "u", port: 22 }, 5, "x");
  assertEquals(sshOpt(quick, "ConnectTimeout"), "5");
});

/** Write an executable fake mise emitting the given stdout/stderr/exit. */
async function fakeMise(
  opts: { stdout?: string; stderr?: string; exit?: number },
): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/mise`;
  const script = [
    "#!/bin/sh",
    opts.stdout ? `cat <<'STDOUT_EOF'\n${opts.stdout}\nSTDOUT_EOF` : "",
    opts.stderr ? `cat >&2 <<'STDERR_EOF'\n${opts.stderr}\nSTDERR_EOF` : "",
    `exit ${opts.exit ?? 0}`,
  ].join("\n");
  await Deno.writeTextFile(path, script);
  await Deno.chmod(path, 0o755);
  return { path, cleanup: () => Deno.remove(dir, { recursive: true }) };
}

Deno.test("exit 127 is a missing binary, not an empty result", () => {
  assertEquals(classifyFailure(127, ""), "notfound");
});

Deno.test("a command-not-found stderr is recognised whatever the exit code", () => {
  // some shells report 126 or 1 for this depending on how mise was invoked
  assertEquals(classifyFailure(1, "sh: mise: command not found"), "notfound");
  assertEquals(
    classifyFailure(126, "bash: line 1: mise: No such file or directory"),
    "notfound",
  );
});

Deno.test("an ordinary failure is not mistaken for a missing binary", () => {
  assertEquals(
    classifyFailure(1, "error: config file is invalid toml"),
    "failed",
  );
});

Deno.test("mise's own os error is a real failure, not a missing binary", () => {
  // mise is a Rust binary and renders io failures this way for an unreadable
  // config or a broken shim. That host ran mise and hit a problem, so calling
  // it "notfound" would file a measured failure as never measured.
  assertEquals(
    classifyFailure(1, "error: No such file or directory (os error 2)"),
    "failed",
  );
  // the shell-prefixed form is still a missing binary
  assertEquals(
    classifyFailure(126, "bash: line 1: mise: No such file or directory"),
    "notfound",
  );
});

Deno.test("a word ending in sh is not a shell prefix", () => {
  // mise's own wording. Matching any word ending in "sh" filed this as a
  // missing binary, which now reaches published data as failureKind.
  assertEquals(
    classifyFailure(1, "error: failed to refresh: No such file or directory"),
    "failed",
  );
  // named shells, with and without a path, still classify as a missing binary
  assertEquals(
    classifyFailure(1, "zsh: no such file or directory: /usr/local/bin/mise"),
    "notfound",
  );
  assertEquals(
    classifyFailure(1, "/bin/bash: mise: No such file or directory"),
    "notfound",
  );
});

Deno.test("a successful run returns stdout", async () => {
  const m = await fakeMise({ stdout: '{"node":[]}' });
  try {
    const r = await runMise(
      { name: "local", misePath: m.path },
      ["ls", "--current", "--json"],
      15,
      new AbortController().signal,
    );
    assertEquals(r.ok, true);
    assertEquals(r.ok && r.stdout.trim(), '{"node":[]}');
  } finally {
    await m.cleanup();
  }
});

Deno.test("a missing binary reports notfound rather than an empty tool list", async () => {
  const r = await runMise(
    { name: "local", misePath: "/nonexistent/mise" },
    ["ls", "--current", "--json"],
    15,
    new AbortController().signal,
  );
  assertEquals(r.ok, false);
  assertEquals(!r.ok && r.kind, "notfound");
});

Deno.test("no remote text reaches the error, from stdout or stderr", async () => {
  // This used to assert only that stdout was withheld while stderr was quoted
  // back. Quoting stderr was the bug: it routinely carries credential-bearing
  // URLs, tokens, private hostnames and home paths, and the error string is
  // written into resources AND logs, so one failure published infrastructure
  // detail permanently. Now NEITHER stream reaches it -- stderr is read to
  // classify and then discarded.
  const m = await fakeMise({
    stdout: "SENSITIVE-CONFIG-BODY",
    stderr:
      "error: could not read https://user:hunter2@vault.internal/secret/path",
    exit: 1,
  });
  try {
    const r = await runMise(
      { name: "local", misePath: m.path },
      ["ls", "--current", "--json"],
      15,
      new AbortController().signal,
    );
    assertEquals(r.ok, false);
    if (r.ok) return;
    for (
      const leak of [
        "SENSITIVE-CONFIG-BODY",
        "hunter2",
        "vault.internal",
        "secret/path",
        "user:",
      ]
    ) {
      assertEquals(
        r.error.includes(leak),
        false,
        `remote text ${JSON.stringify(leak)} must never reach the error`,
      );
    }
    // What survives is a closed-set code, not an excerpt.
    assertEquals(
      [
        "binary-missing",
        "permission-denied",
        "host-key-unknown",
        "connection-failed",
        "config-error",
        "timed-out",
        "nonzero-exit",
        "unclassified",
      ].includes(r.error),
      true,
      `error must be a fixed code, got ${JSON.stringify(r.error)}`,
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("stderr control characters never reach a run error", async () => {
  const m = await fakeMise({
    stderr: "\u001b[31merror:\u0007 could not read config\u009b0m",
    exit: 1,
  });
  try {
    const r = await runMise(
      { name: "local", misePath: m.path },
      ["ls", "--current", "--json"],
      15,
      new AbortController().signal,
    );
    assertEquals(r.ok, false);
    assertEquals(
      !r.ok && /[\u0000-\u001f\u007f-\u009f]/.test(r.error),
      false,
    );
  } finally {
    await m.cleanup();
  }
});

const LS_CURRENT = JSON.stringify({
  node: [{
    version: "22.23.2",
    requested_version: "22",
    install_path: "<home>/.local/share/mise/installs/node/22.23.2",
    source: { type: "mise.toml", path: "/srv/project/mise.toml" },
    installed: true,
    active: true,
  }],
  python: [{
    version: "3.12.14",
    requested_version: "3.12",
    install_path: "<home>/.local/share/mise/installs/python/3.12.14",
    source: { type: "mise.toml", path: "/srv/project/mise.toml" },
    installed: false,
    active: false,
  }],
});

const LS_CURRENT_CLEAN = JSON.stringify({
  node: [{
    version: "22.23.2",
    requested_version: "22",
    install_path: "<home>/.local/share/mise/installs/node/22.23.2",
    source: { type: "mise.toml", path: "/srv/project/mise.toml" },
    installed: true,
    active: true,
  }],
});

Deno.test("ls --current becomes one flat row per tool", () => {
  const rows = parseLsCurrent(LS_CURRENT);
  assertEquals(rows.length, 2);
  const node = rows.find((r) => r.tool === "node")!;
  assertEquals(node.requestedVersion, "22");
  assertEquals(node.resolvedVersion, "22.23.2");
  assertEquals(node.sourcePath, "/srv/project/mise.toml");
  assertEquals(node.installed, true);
  assertEquals(node.active, true);
  const py = rows.find((r) => r.tool === "python")!;
  assertEquals(py.installed, false);
});

Deno.test("empty and malformed ls output yield no rows rather than throwing", () => {
  assertEquals(parseLsCurrent("{}"), []);
  assertEquals(parseLsCurrent(""), []);
  assertEquals(parseLsCurrent("not json at all"), []);
  // a tool key whose value is not an array must not crash the sweep
  assertEquals(parseLsCurrent('{"node":"nonsense"}'), []);
});

Deno.test("config ls yields declared paths and their tools", () => {
  const c = parseConfigLs(
    '[{"path":"/srv/project/mise.toml","tools":["node","python"]}]',
  );
  assertEquals(c.length, 1);
  assertEquals(c[0].tools, ["node", "python"]);
  assertEquals(parseConfigLs("[]"), []);
  assertEquals(parseConfigLs("garbage"), []);
});

Deno.test("outdated maps tool to its latest version", () => {
  const o = parseOutdated('{"node":{"latest":"24.1.0"}}');
  assertEquals(o.node, "24.1.0");
  assertEquals(parseOutdated("{}"), {});
  assertEquals(parseOutdated("garbage"), {});
});

Deno.test("trust --show parses the path-colon-status lines", () => {
  const t = parseTrustShow(
    "/srv/project: untrusted\n/srv/other: trusted\n",
  );
  assertEquals(t["/srv/project"], false);
  assertEquals(t["/srv/other"], true);
  assertEquals(parseTrustShow(""), {});
});

Deno.test("remote fields are stored without control characters", () => {
  const hasControl = (v: string | null) =>
    v !== null && /[\u0000-\u001f\u007f-\u009f]/.test(v);
  const ls = parseLsCurrent(JSON.stringify({
    "node\u001b[31m": [{
      version: "22.23.2\u0007",
      requested_version: "22\u0085",
      install_path: "/srv/install\u007f",
      source: {
        type: "mise.toml\u0000",
        path: "/srv/project\u001b/mise.toml",
      },
      installed: true,
      active: true,
    }],
  }));
  assertEquals(ls.length, 1);
  for (
    const value of [
      ls[0].tool,
      ls[0].resolvedVersion,
      ls[0].requestedVersion,
      ls[0].installPath,
      ls[0].sourceType,
      ls[0].sourcePath,
    ]
  ) {
    assertEquals(hasControl(value), false);
  }

  const configs = parseConfigLs(JSON.stringify([{
    path: "/srv/project\u001b/mise.toml",
    tools: ["node\u0007"],
  }]));
  assertEquals(hasControl(configs[0].path), false);
  assertEquals(hasControl(configs[0].tools[0]), false);

  const outdated = parseOutdated(JSON.stringify({
    "node\u001b": { latest: "24.1.0\u009b" },
  }));
  const outdatedKey = Object.keys(outdated)[0];
  assertEquals(hasControl(outdatedKey), false);
  assertEquals(hasControl(outdated[outdatedKey]), false);

  const trust = parseTrustShow("/srv/project\u001b: trusted\n");
  assertEquals(hasControl(Object.keys(trust)[0]), false);
});

Deno.test("maps keyed by remote names have nothing behind them", () => {
  // A miss on a plain object walks up to Object.prototype, so a tool named
  // "constructor" reads back a function from a map whose type says string.
  // These maps are keyed entirely by names a remote host chose, so they are
  // built with no prototype and a miss is a miss.
  const o = parseOutdated('{"node":{"latest":"24.1.0"}}');
  assertEquals(Object.getPrototypeOf(o), null);
  assertEquals(o["constructor"], undefined);
  assertEquals(o.node, "24.1.0");
  const t = parseTrustShow("/srv/project: untrusted\n");
  assertEquals(Object.getPrototypeOf(t), null);
  assertEquals(t["constructor"], undefined);
  assertEquals(t["/srv/project"], false);
  // a key literally named __proto__ is recorded as a key, not acted on
  const p = parseOutdated('{"__proto__":{"latest":"9.9.9"}}');
  assertEquals(Object.hasOwn(p, "__proto__"), true);
  assertEquals(({} as Record<string, unknown>).latest, undefined);
});

Deno.test("a declared tool absent from ls --current is notineffect", () => {
  // the config asks for three, mise reports two: the third never took
  assertEquals(
    notInEffect(["node", "python", "go"], ["node", "python"]),
    ["go"],
  );
  assertEquals(notInEffect(["node"], ["node"]), []);
});

type Json = Record<string, unknown>;

/**
 * Mock ctx capturing writeResource calls, as the dashboard tests do.
 *
 * `existing` seeds what a previous sweep left in the datastore, so the prune
 * has something to find. `throwOnFirstWarning` makes the logger blow up once,
 * which is the cheapest way to inject an unexpected exception into the middle
 * of one node's sweep and prove it does not take the fleet with it.
 */
function mockCtx(
  globalArgs: Json,
  opts: {
    existing?: string[];
    throwOnFirstWarning?: boolean | string;
    signal?: AbortSignal;
  } = {},
) {
  const written: Array<
    { spec: string; name: string; data: Json; opts: Json }
  > = [];
  const deleted: string[] = [];
  const logs: Array<{ level: string; values: Json }> = [];
  let warnings = 0;
  return {
    written,
    deleted,
    logs,
    // deno-lint-ignore no-explicit-any
    ctx: {
      signal: opts.signal ?? new AbortController().signal,
      globalArgs,
      modelType: "@jpisgeek/mise",
      modelId: "m1",
      logger: {
        info: (_message: string, values: Json) => {
          logs.push({ level: "info", values });
        },
        warning: (_message: string, values: Json) => {
          logs.push({ level: "warning", values });
          warnings++;
          if (opts.throwOnFirstWarning && warnings === 1) {
            throw new Error(
              typeof opts.throwOnFirstWarning === "string"
                ? opts.throwOnFirstWarning
                : "logger exploded",
            );
          }
        },
      },
      writeResource: (spec: string, name: string, data: Json, o?: Json) => {
        written.push({ spec, name, data, opts: o ?? {} });
        return Promise.resolve({});
      },
      deleteResource: (name: string) => {
        deleted.push(name);
        return Promise.resolve();
      },
      dataRepository: {
        findAllForModel: () =>
          Promise.resolve((opts.existing ?? []).map((name) => ({ name }))),
        getContent: () => Promise.resolve(null),
        delete: () => Promise.resolve(),
      },
    } as any,
  };
}

/** Which secondary subcommands a fake mise should refuse to answer. */
type FailedSub = "config" | "outdated" | "trust" | "version";

/**
 * A fake mise that answers each subcommand with canned JSON, or refuses the
 * ones named in `fail`. The refusal path is the one that matters: a busy host
 * times out on `outdated` routinely, and that must not read as no drift.
 */
async function fakeMiseSuite(
  answers: {
    ls?: string;
    config?: string;
    outdated?: string;
    trust?: string;
    fail?: FailedSub[];
  },
): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/mise`;
  const failing = new Set(answers.fail ?? []);
  const refuse = (label: FailedSub) =>
    `echo "error: ${label} did not answer" >&2\nexit 1`;
  const branch = (argv1: string, label: FailedSub, payload: string) =>
    `if [ "$1" = "${argv1}" ]; then\n${
      failing.has(label)
        ? refuse(label)
        : `cat <<'EOF'\n${payload}\nEOF\nexit 0`
    }\nfi`;
  const script = [
    "#!/bin/sh",
    "# skip a leading -C <dir> so the fake accepts the same argv as the real one",
    'if [ "$1" = "-C" ]; then shift 2; fi',
    `if [ "$1" = "--version" ]; then\n${
      failing.has("version")
        ? refuse("version")
        : 'echo "2026.8.12 test"\nexit 0'
    }\nfi`,
    `if [ "$1" = "ls" ]; then cat <<'EOF'\n${
      answers.ls ?? "{}"
    }\nEOF\nexit 0; fi`,
    branch("config", "config", answers.config ?? "[]"),
    branch("outdated", "outdated", answers.outdated ?? "{}"),
    branch("trust", "trust", answers.trust ?? ""),
    "exit 0",
  ].join("\n");
  await Deno.writeTextFile(path, script);
  await Deno.chmod(path, 0o755);
  return { path, cleanup: () => Deno.remove(dir, { recursive: true }) };
}

/**
 * A fake `ssh` first on PATH, printing its argv one per line. Nothing else
 * proves the ssh branch of runMise is the branch an ssh node takes: sshArgs
 * and remoteCommand are pure and pass their unit tests whichever way the
 * transport ternary points.
 */
async function fakeSshOnPath(): Promise<
  { restore: () => Promise<void> }
> {
  const dir = await Deno.makeTempDir();
  const originalPath = Deno.env.get("PATH") ?? "";
  await Deno.writeTextFile(`${dir}/ssh`, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n");
  await Deno.chmod(`${dir}/ssh`, 0o755);
  Deno.env.set("PATH", `${dir}:${originalPath}`);
  return {
    restore: async () => {
      Deno.env.set("PATH", originalPath);
      await Deno.remove(dir, { recursive: true });
    },
  };
}

Deno.test("discover is the only method", () => {
  assertEquals(Object.keys(model.methods), ["discover"]);
});

Deno.test("a clean host writes tool rows with no drift", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const tools = c.written.filter((w) => w.spec === "tool");
    assertEquals(tools.length, 1);
    assertEquals(tools[0].data.drift, []);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.measured, true);
    assertEquals(node.toolCount, 1);
    const nodeWrite = c.written.find((w) => w.spec === "node")!;
    const nodeTags =
      (nodeWrite.opts as { tags?: Record<string, string> }).tags ?? {};
    assertEquals(
      nodeTags.measured,
      "true",
      "node resource must be tagged measured",
    );
    assertEquals(
      nodeTags.transport,
      "local",
      "node resource must be tagged with its transport",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("remote controls never reach resource fields or tags", async () => {
  const toolName = "node\u001b[31m";
  const m = await fakeMiseSuite({
    ls: JSON.stringify({
      [toolName]: [{
        version: "22.23.2\u0007",
        requested_version: "22\u0085",
        install_path: "/srv/install\u007f",
        source: {
          type: "mise.toml\u0000",
          path: "/srv/project\u001b/mise.toml",
        },
        installed: true,
        active: true,
      }],
    }),
    config: JSON.stringify([{
      path: "/srv/project\u001b/mise.toml",
      tools: [toolName],
    }]),
    outdated: JSON.stringify({
      [toolName]: { latest: "24.1.0\u009b" },
    }),
    trust: "/srv/project\u001b/mise.toml: trusted",
  });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    for (const write of c.written) {
      assertNoControlCharacters(write.data);
      assertNoControlCharacters(write.opts);
    }
    for (const log of c.logs) {
      assertNoControlCharacters(log.values);
    }
  } finally {
    await m.cleanup();
  }
});

Deno.test("a host without mise is unmeasured, never a zero tool count", async () => {
  const c = mockCtx({
    nodes: [{ name: "gone", misePath: "/nonexistent/mise" }],
  });
  await model.methods.discover.execute({}, c.ctx);
  const node = c.written.find((w) => w.spec === "node")!.data;
  assertEquals(node.measured, false);
  assertEquals(node.toolCount, null, "an unmeasured host has no tool count");
  assertEquals((node.drift as string[]).includes("unmeasured"), true);
  const summary = c.written.find((w) => w.spec === "summary")!.data;
  assertEquals(summary.nodesUnmeasured, 1);
  assertEquals(summary.nodesMeasured, 0);
});

Deno.test("miseVersion is null when never obtained, not empty string", async () => {
  const c = mockCtx({
    nodes: [{ name: "gone", misePath: "/nonexistent/mise" }],
  });
  await model.methods.discover.execute({}, c.ctx);
  const node = c.written.find((w) => w.spec === "node")!.data;
  assertEquals(node.miseVersion, null);
});

Deno.test("a declared tool that never took effect is recorded", async () => {
  const m = await fakeMiseSuite({
    ls:
      '{"node":[{"version":"22.23.2","requested_version":"22","installed":true,"active":true,"source":{"type":"mise.toml","path":"/srv/project/mise.toml"}}]}',
    config: '[{"path":"/srv/project/mise.toml","tools":["node","go"]}]',
  });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const cfg = c.written.find((w) => w.spec === "config")!.data;
    assertEquals(cfg.toolsNotInEffect, ["go"]);
  } finally {
    await m.cleanup();
  }
});

Deno.test("expect mismatch is flagged against the resolved version", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({
      nodes: [{ name: "workstation", misePath: m.path }],
      expect: { node: "24" },
    });
    await model.methods.discover.execute({}, c.ctx);
    const tool = c.written.find((w) => w.spec === "tool")!.data;
    assertEquals((tool.drift as string[]).includes("expected"), true);
  } finally {
    await m.cleanup();
  }
});

Deno.test("summary totals agree with the per-node counts", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({
      nodes: [
        { name: "workstation", misePath: m.path },
        { name: "gone", misePath: "/nonexistent/mise" },
      ],
    });
    await model.methods.discover.execute({}, c.ctx);
    const summary = c.written.find((w) => w.spec === "summary")!.data;
    assertEquals(summary.nodes, 2);
    assertEquals(summary.nodesMeasured, 1);
    assertEquals(summary.nodesUnmeasured, 1);
    assertEquals(summary.nodesDegraded, 0);
    // Not 1. One of the two hosts never answered, so a tool total counted
    // across the fleet is a total nobody can stand behind -- and `tools: 1`
    // reads as a fleet with one tool rather than a sweep half missing.
    assertEquals(summary.tools, null);
    assertEquals(summary.notinstalled, null);
    assertEquals(summary.notactive, null);
    assertEquals(summary.expected, null);
  } finally {
    await m.cleanup();
  }
});

Deno.test("summary totals are real numbers when the whole fleet answered", () => {
  // The other half. Nulling on incompleteness is only honest if a complete
  // sweep still produces counts.
  return (async () => {
    const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
    try {
      const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
      await model.methods.discover.execute({}, c.ctx);
      const summary = c.written.find((w) => w.spec === "summary")!.data;
      assertEquals(summary.nodesUnmeasured, 0);
      assertEquals(summary.tools, 1);
      assertEquals(summary.notinstalled, 0);
      assertEquals(summary.outdated, 0);
    } finally {
      await m.cleanup();
    }
  })();
});

// ---- partial readings -----------------------------------------------------
// The whole point of the model is that absence never renders as health. These
// cover the level below "the host never answered": the host answered, and one
// of the follow-up probes did not.

Deno.test("a failed outdated probe is degraded, not a clean zero", async () => {
  // outdated is the only subcommand that has to reach upstream registries, so
  // it is the one a busy host times out. Its empty fallback is shaped exactly
  // like "nothing is behind".
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN, fail: ["outdated"] });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.measured, true, "the tool list did come back");
    assertEquals(node.degraded, true);
    assertEquals(node.failedSubcommands, ["outdated"]);
    // A code, not a sentence. Which probe went quiet is on the record above,
    // in the field whose job that is.
    assertEquals(node.error, "partially-measured");
    const summary = c.written.find((w) => w.spec === "summary")!.data;
    assertEquals(summary.nodesMeasured, 1);
    assertEquals(
      summary.nodesDegraded,
      1,
      "the summary must surface the partial reading too",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("a failed config ls leaves configCount null, never zero", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN, fail: ["config"] });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.configCount, null, "zero is a measurement, null is not");
    assertEquals(node.degraded, true);
    assertEquals(node.failedSubcommands, ["config"]);
    assertEquals(
      c.written.filter((w) => w.spec === "config").length,
      0,
      "no config rows can be written from a config ls that never answered",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("every failed subcommand is named on the record", async () => {
  const m = await fakeMiseSuite({
    ls: LS_CURRENT_CLEAN,
    fail: ["config", "outdated", "trust", "version"],
  });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.failedSubcommands, [
      "config",
      "outdated",
      "trust",
      "version",
    ]);
    assertEquals(node.miseVersion, null);
    const tags = (c.written.find((w) => w.spec === "node")!.opts as {
      tags?: Record<string, string>;
    }).tags ?? {};
    assertEquals(tags.degraded, "true", "a partial reading is tagged as one");
  } finally {
    await m.cleanup();
  }
});

Deno.test("a whole reading carries no error and no failureKind", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.degraded, false);
    assertEquals(node.failedSubcommands, []);
    assertEquals(node.error, null);
    assertEquals(node.failureKind, null);
    assertEquals(
      Object.hasOwn(node, "reachable"),
      false,
      "reachable was identical to measured and wrong for a PATH miss",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("an unmeasured host records how it failed, not that it is degraded", async () => {
  const c = mockCtx({
    nodes: [{ name: "gone", misePath: "/nonexistent/mise" }],
  });
  await model.methods.discover.execute({}, c.ctx);
  const node = c.written.find((w) => w.spec === "node")!.data;
  // failureKind is what makes the README's "set misePath" advice actionable
  // from stored data. Never measured is not the same as measured in part, so
  // degraded stays false and the unmeasured drift class carries the fact.
  assertEquals(node.failureKind, "notfound");
  assertEquals(node.degraded, false);
  assertEquals(node.failedSubcommands, []);
});

Deno.test("an unparseable ls payload is unmeasured, never zero tools", async () => {
  // A login shell that prints anything to stdout prepends it to the payload,
  // and ssh calls that exit zero. Parsed tolerantly it becomes no tools at
  // all, which is the shape of a host with nothing wrong.
  const m = await fakeMiseSuite({ ls: "welcome to the bog\n{}" });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.measured, false);
    assertEquals(node.failureKind, "unparseable");
    assertEquals(node.toolCount, null);
    assertEquals(node.configCount, null);
    assertEquals(node.drift, ["unmeasured"]);
    // it was never part measured, so degraded stays out of it
    assertEquals(node.degraded, false);
    assertEquals(node.failedSubcommands, []);
    assertEquals(c.written.filter((w) => w.spec === "tool").length, 0);
    const summary = c.written.find((w) => w.spec === "summary")!.data;
    assertEquals(summary.nodesUnmeasured, 1);
  } finally {
    await m.cleanup();
  }
});

Deno.test("a valid empty ls payload is a reading of zero tools", async () => {
  // The other half of the same rule, and the half an over-eager fix breaks.
  // {} says the config in that directory declares no tools. That is a
  // measurement of zero, not an absence of one.
  const m = await fakeMiseSuite({ ls: "{}" });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.measured, true);
    assertEquals(node.toolCount, 0);
    assertEquals(node.failureKind, null);
    assertEquals(node.degraded, false);
    assertEquals(node.drift, []);
  } finally {
    await m.cleanup();
  }
});

Deno.test("an ls payload of the wrong shape is unmeasured too", async () => {
  // Valid JSON, wrong type. Object.entries over an array finds nothing to
  // report, or finds entries that every guard skips, and either way the
  // payload evaporates into the shape of a host with nothing wrong.
  for (const payload of ["[]", '[{"node":[]},"junk"]']) {
    const m = await fakeMiseSuite({ ls: payload });
    try {
      const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
      await model.methods.discover.execute({}, c.ctx);
      const node = c.written.find((w) => w.spec === "node")!.data;
      assertEquals(
        node.measured,
        false,
        `an array is not a tool list: ${payload}`,
      );
      assertEquals(node.failureKind, "unparseable");
      assertEquals(node.toolCount, null);
      assertEquals(node.drift, ["unmeasured"]);
      assertEquals(c.written.filter((w) => w.spec === "tool").length, 0);
    } finally {
      await m.cleanup();
    }
  }
});

Deno.test("a probe that answers in the wrong shape did not answer", async () => {
  // config ls promises a list of files. An object sails through a plain
  // "is it JSON" check and then dissolves in the parser, leaving
  // configCount: 0 on a probe that told us nothing.
  const m = await fakeMiseSuite({
    ls: LS_CURRENT_CLEAN,
    config: '{"path":"/srv/project/mise.toml"}',
    outdated: '[{"node":"24.1.0"}]',
  });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.measured, true, "the tool list itself was readable");
    assertEquals(node.failedSubcommands, ["config", "outdated"]);
    assertEquals(node.configCount, null, "zero configs was never measured");
    assertEquals(c.written.filter((w) => w.spec === "config").length, 0);
  } finally {
    await m.cleanup();
  }
});

Deno.test("a probe that exits zero with junk did not answer either", async () => {
  const m = await fakeMiseSuite({
    ls: LS_CURRENT_CLEAN,
    config: "welcome to the bog\n[]",
    outdated: "welcome to the bog\n{}",
  });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.measured, true, "the tool list itself was readable");
    assertEquals(node.degraded, true);
    assertEquals(node.failedSubcommands, ["config", "outdated"]);
    assertEquals(node.configCount, null);
    assertEquals(c.written.filter((w) => w.spec === "config").length, 0);
  } finally {
    await m.cleanup();
  }
});

Deno.test("a tool row carries its host's degraded flag", async () => {
  const partial = await fakeMiseSuite({
    ls: LS_CURRENT_CLEAN,
    fail: ["outdated"],
  });
  const whole = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({
      nodes: [
        { name: "workstation", misePath: partial.path },
        { name: "builder", misePath: whole.path },
      ],
    });
    await model.methods.discover.execute({}, c.ctx);
    const tagsFor = (node: string) => {
      const w = c.written.find((w) =>
        w.spec === "tool" && w.data.node === node
      )!;
      return (w.opts as { tags?: Record<string, string> }).tags ?? {};
    };
    // The row itself writes outdated: false because the probe never ran, so
    // without the tag a query over rows alone reads this host as clean.
    assertEquals(tagsFor("workstation").degraded, "true");
    assertEquals(tagsFor("builder").degraded, "false");
  } finally {
    await partial.cleanup();
    await whole.cleanup();
  }
});

// ---- cancellation is not a host failure ----------------------------------

Deno.test("a cancelled sweep writes nothing at all", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const ac = new AbortController();
    ac.abort();
    const c = mockCtx(
      {
        nodes: [
          { name: "studio", misePath: m.path },
          { name: "builder", misePath: m.path },
        ],
      },
      { existing: ["tool-studio-go-1234abcd"], signal: ac.signal },
    );
    await assertRejects(() => model.methods.discover.execute({}, c.ctx));
    // The caller took the run away. Writing a fleet of failure records for
    // hosts that were never asked would replace a good sweep with a lie, and
    // the prune would then delete whatever was not in it.
    assertEquals(c.written, []);
    assertEquals(c.deleted, []);
  } finally {
    await m.cleanup();
  }
});

/**
 * A fake mise that sits there, so a sweep can be cancelled while it is
 * genuinely in flight. This is the case that matters: Deno does not throw
 * when a signal aborts a running command, it kills the child and returns
 * success: false with SIGTERM, which reads as an ordinary host failure.
 */
async function slowFakeMise(
  seconds: number,
): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/mise`;
  await Deno.writeTextFile(path, `#!/bin/sh\nsleep ${seconds}\necho '{}'\n`);
  await Deno.chmod(path, 0o755);
  return { path, cleanup: () => Deno.remove(dir, { recursive: true }) };
}

Deno.test("a caller abort mid-run is a cancellation, not a dead host", async () => {
  const m = await slowFakeMise(5);
  try {
    const ac = new AbortController();
    const p = runMise(
      { name: "studio", misePath: m.path },
      SUB_LS,
      15,
      ac.signal,
    );
    setTimeout(() => ac.abort(), 50);
    // Without the check on the caller's signal this resolves to a tidy
    // { ok: false, kind: "failed" } and the host takes the blame for the
    // caller's decision.
    await assertRejects(() => p);
  } finally {
    await m.cleanup();
  }
});

Deno.test("a sweep cancelled mid-run writes nothing either", async () => {
  const m = await slowFakeMise(5);
  try {
    const ac = new AbortController();
    const c = mockCtx(
      { nodes: [{ name: "studio", misePath: m.path }] },
      { existing: ["tool-studio-go-1234abcd"], signal: ac.signal },
    );
    const run = model.methods.discover.execute({}, c.ctx);
    setTimeout(() => ac.abort(), 50);
    await assertRejects(() => run);
    assertEquals(c.written, []);
    assertEquals(c.deleted, []);
  } finally {
    await m.cleanup();
  }
});

Deno.test("cancellation is rethrown, never classified as a host failure", async () => {
  // The branch inside runMise, on its own. misePath does not exist, so
  // without the caller-signal check this returns a tidy notfound result and
  // the sweep files a failure against a host it never spoke to.
  const ac = new AbortController();
  ac.abort();
  await assertRejects(() =>
    runMise(
      { name: "studio", misePath: "/nonexistent/mise" },
      SUB_LS,
      15,
      ac.signal,
    )
  );
});

Deno.test("a per-command timeout is still a host failure", async () => {
  // The caller's signal and this model's own hard kill are composed with
  // AbortSignal.any and raise the same shape of error, so only the caller's
  // signal may be treated as cancellation. A host that ran out of time did
  // fail to answer. timeoutSec is a plain parameter here, so a negative one
  // makes the kill fire at once instead of making this test wait out the
  // real eleven seconds.
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const caller = new AbortController();
    const r = await runMise(
      { name: "studio", misePath: m.path },
      SUB_LS,
      -10,
      caller.signal,
    );
    assertEquals(r.ok, false);
    assertEquals(!r.ok && r.kind, "failed", "a timeout is not a cancellation");
    assertEquals(caller.signal.aborted, false, "the caller never cancelled");
  } finally {
    await m.cleanup();
  }
});

Deno.test("a host that ran mise and failed is recorded, not thrown", async () => {
  // The other half of the timeout case, at the level where it gets written
  // down: a run that failed for any reason other than the caller leaving
  // still produces an unmeasured record with failureKind "failed".
  const m = await fakeMise({
    stderr: "error: config file is invalid toml",
    exit: 1,
  });
  try {
    const c = mockCtx({ nodes: [{ name: "studio", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.measured, false);
    assertEquals(node.failureKind, "failed");
    assertEquals(node.drift, ["unmeasured"]);
  } finally {
    await m.cleanup();
  }
});

// ---- untrusted keys from a remote host -----------------------------------

Deno.test("a hostile tool name cannot reach the prototype chain", async () => {
  // Written as raw JSON: an object literal treats a __proto__ key as the
  // prototype setter, so building this with JSON.stringify would quietly drop
  // the very key under test.
  const entry = (v: string) =>
    `[{"version":"${v}","requested_version":"${v}","installed":true,` +
    `"active":true,"source":{"type":"mise.toml","path":"/srv/p/mise.toml"}}]`;
  const hostile = `{"constructor":${entry("1.0.0")},"__proto__":${
    entry("2.0.0")
  }}`;
  const m = await fakeMiseSuite({
    ls: hostile,
    config: '[{"path":"constructor","tools":["constructor"]}]',
  });
  try {
    const c = mockCtx({
      nodes: [{ name: "workstation", misePath: m.path }],
      // No expect entry for either name. Unguarded, g.expect["constructor"]
      // is a function, and satisfiesExpect calls .split on it.
      expect: { node: "22" },
    });
    await model.methods.discover.execute({}, c.ctx);
    const tools = c.written.filter((w) => w.spec === "tool");
    assertEquals(tools.length >= 1, true, "the sweep must still write rows");
    for (const t of tools) {
      assertEquals(t.data.latestVersion, null);
      assertEquals((t.data.drift as string[]).includes("expected"), false);
    }
    const cfg = c.written.find((w) => w.spec === "config")!.data;
    assertEquals(cfg.trusted, null, "an unknown path's trust is unknown");
  } finally {
    await m.cleanup();
  }
});

Deno.test("one node's exception never discards the fleet", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({
      nodes: [
        { name: "gone", misePath: "/nonexistent/mise" },
        { name: "workstation", misePath: m.path },
      ],
    }, { throwOnFirstWarning: "\u001b[31mlogger\u0007 exploded" });
    await model.methods.discover.execute({}, c.ctx);
    const nodes = c.written.filter((w) => w.spec === "node");
    assertEquals(nodes.length, 2, "the healthy host must still be written");
    const workstation = nodes.find((n) => n.data.name === "workstation")!.data;
    assertEquals(workstation.measured, true);
    const gone = nodes.find((n) => n.data.name === "gone")!.data;
    assertEquals(gone.measured, false);
    assertEquals(
      /[\u0000-\u001f\u007f-\u009f]/.test(String(gone.error)),
      false,
    );
    // The exception's own text must NOT survive into the resource. It used
    // to, escaped and truncated, which is not sanitisation -- an exception
    // message carries a path, a host, or a credential just as easily as the
    // word "logger". A closed-set code is what gets written now.
    assertEquals(
      String(gone.error).includes("logger"),
      false,
      "exception text must never reach a written resource",
    );
    // "unclassified" is the right answer here and worth asserting: the
    // failure was a thrown logger, not a remote condition, so the classifier
    // declines to name it rather than guessing at the nearest code.
    assertEquals(String(gone.error), "unclassified");
    for (const log of c.logs) {
      assertNoControlCharacters(log.values);
    }
    assertEquals(gone.drift, ["unmeasured"]);
  } finally {
    await m.cleanup();
  }
});

// ---- what was actually measured ------------------------------------------

Deno.test("dir records the directory measured, not the field left blank", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    // Two sweeps from different working directories judge different configs.
    // Recording the operator's blank field would make them indistinguishable.
    assertEquals(node.dir, Deno.cwd());
    const c2 = mockCtx({
      nodes: [{ name: "workstation", misePath: m.path, dir: "/srv/project" }],
    });
    await model.methods.discover.execute({}, c2.ctx);
    assertEquals(
      c2.written.find((w) => w.spec === "node")!.data.dir,
      "/srv/project",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("an ssh node with no dir records null, the login directory", async () => {
  const ssh = await fakeSshOnPath();
  try {
    const c = mockCtx({
      nodes: [{
        name: "builder",
        ssh: { host: "builder.example.com", user: "reader" },
      }],
    });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.dir, null);
    assertEquals(node.transport, "ssh");
  } finally {
    await ssh.restore();
  }
});

Deno.test("an ssh node is reached with ssh, not the local binary", async () => {
  const ssh = await fakeSshOnPath();
  try {
    const r = await runMise(
      {
        name: "builder",
        misePath: "/nonexistent/mise",
        ssh: { host: "builder.example.com", user: "reader", port: 2222 },
      },
      SUB_LS,
      15,
      new AbortController().signal,
    );
    // misePath does not exist, so a run that took the local branch would come
    // back notfound. Success here means ssh was the process that ran.
    assertEquals(r.ok, true);
    const argv = r.ok ? r.stdout.trim().split("\n") : [];
    // Asserted by position from the END and by option lookup, not by fixed
    // index: adding an ssh option must not break a test about which binary
    // ran. An earlier version indexed argv[6]/argv[7] and broke the moment
    // StrictHostKeyChecking was added.
    assertEquals(sshOpt(argv, "BatchMode"), "yes");
    assertEquals(sshOpt(argv, "StrictHostKeyChecking"), "yes");
    assertEquals(argv[argv.length - 2], "reader@builder.example.com");
    assertEquals(
      argv[argv.length - 1],
      "/nonexistent/mise ls --current --json",
    );
  } finally {
    await ssh.restore();
  }
});

// ---- error classification, added when raw remote text stopped being stored --

/** The complete vocabulary remoteErrorCode may ever return. */
const ERROR_CODES = [
  "binary-missing",
  "permission-denied",
  "host-key-unknown",
  "connection-failed",
  "config-error",
  "timed-out",
  "nonzero-exit",
  "unclassified",
];

Deno.test("remoteErrorCode returns only closed-set codes, so it cannot leak", () => {
  // The guarantee is structural rather than filter-based: if the output is
  // always drawn from a fixed vocabulary, no input can survive into it. That
  // is stronger than checking for known-bad substrings, which only catches
  // the secrets someone thought to list.
  const hostile = [
    "ssh://deploy:s3cr3t@vault.internal:8200/v1/kv/prod",
    "Permission denied (publickey) for /Users/someone/.ssh/id_ed25519",
    "could not read /srv/private-project/mise.toml",
    "Host key verification failed for build-01.corp.example",
    "mise failed: token=eyJhbGciOiJIUzI1NiJ9.secret.sig",
    "",
  ];
  for (const h of hostile) {
    const code = remoteErrorCode(h);
    assertEquals(
      ERROR_CODES.includes(code),
      true,
      `${JSON.stringify(code)} is not in the closed set`,
    );
  }
});

Deno.test("identifying detail from the input never appears in the code", () => {
  // Spot-check the classes that actually matter, on top of the structural
  // guarantee above: credentials, hosts, and paths.
  const cases: [string, string[]][] = [
    ["ssh://deploy:s3cr3t@vault.internal/v1/kv", [
      "s3cr3t",
      "vault.internal",
      "deploy",
    ]],
    ["Permission denied for /Users/someone/.ssh/id_ed25519", [
      "someone",
      "id_ed25519",
      "Users",
    ]],
    ["Host key verification failed for build-01.corp.example", [
      "build-01",
      "corp.example",
    ]],
  ];
  for (const [input, secrets] of cases) {
    const code = remoteErrorCode(input);
    for (const sec of secrets) {
      assertEquals(
        code.includes(sec),
        false,
        `code ${JSON.stringify(code)} leaked ${JSON.stringify(sec)}`,
      );
    }
  }
});

Deno.test("remoteErrorCode classifies the cases that matter, in priority order", () => {
  assertEquals(
    remoteErrorCode("Host key verification failed."),
    "host-key-unknown",
  );
  assertEquals(
    remoteErrorCode("bash: mise: command not found"),
    "binary-missing",
  );
  assertEquals(
    remoteErrorCode("Permission denied (publickey)."),
    "permission-denied",
  );
  // "connection timed out" is a network fact, not our deadline expiring --
  // the connection pattern must win over the generic timeout one.
  assertEquals(
    remoteErrorCode("ssh: connect to host x: Connection timed out"),
    "connection-failed",
  );
  assertEquals(remoteErrorCode("something nobody predicted"), "unclassified");
});

Deno.test("an unknown host key is classified, not quoted back", () => {
  const code = remoteErrorCode(
    "Host key verification failed for builder.internal.example",
  );
  assertEquals(code, "host-key-unknown");
  assertEquals(code.includes("builder"), false);
  assertEquals(code.includes("internal"), false);
});

// ---- remote data is validated and screened before it is persisted ---------

Deno.test("credential-shaped values are omitted, never persisted", () => {
  const hostile = [
    "https://deploy:hunter2@artifacts.internal/tools/node",
    "https://artifacts.example/tool?access_token=abcdefghijklmnop",
    "https://artifacts.example/tool#api_key=abcdefghijklmnop",
    "Authorization Bearer abcdefghijklmnopqrstuvwx",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
  ];
  for (const h of hostile) {
    assertEquals(
      safeRemoteString(h),
      null,
      `${JSON.stringify(h)} must be omitted, not persisted`,
    );
  }
});

Deno.test("ordinary paths and versions survive screening untouched", () => {
  // The screen must not be so eager that it eats normal data -- a collector
  // that drops real values is a different kind of broken.
  for (
    const ok of [
      "/opt/tools/node/22.1.0",
      "https://artifacts.example/tools/node-22.tar.gz",
      "22.1.0",
      "mise.toml",
      "/srv/project/.config/mise/config.toml",
    ]
  ) {
    assertEquals(safeRemoteString(ok), ok, `${ok} must survive`);
  }
});

Deno.test("a malformed ls entry is skipped, not coerced into a measured row", () => {
  // `entries[0] as Record<string, unknown>` accepted any of these and then
  // read properties off them, producing a row of nulls that looked measured.
  const malformed = [
    '{"node":[42]}',
    '{"node":["a string"]}',
    '{"node":[null]}',
    '{"node":[{"installed":"true","active":"yes"}]}',
  ];
  for (const j of malformed) {
    const rows = parseLsCurrent(j);
    assertEquals(rows.length, 0, `${j} must produce no rows`);
  }
});

Deno.test("a well-formed entry still parses, and unknown fields do not break it", () => {
  // Tolerating unknown fields is deliberate: mise adds them between releases,
  // and failing the probe on an upstream addition would make every mise
  // upgrade an outage of this collector.
  const rows = parseLsCurrent(
    '{"node":[{"version":"22.1.0","installed":true,"active":true,' +
      '"source":{"type":"mise.toml","path":"/srv/p/mise.toml"},' +
      '"a_field_added_next_release":123}]}',
  );
  assertEquals(rows.length, 1);
  assertEquals(rows[0].resolvedVersion, "22.1.0");
  assertEquals(rows[0].installed, true);
  assertEquals(rows[0].sourcePath, "/srv/p/mise.toml");
  // Not yet asked: the outdated probe has not run at parse time.
  assertEquals(rows[0].outdated, null);
});

Deno.test("a source path carrying a credential is dropped from the row", () => {
  const rows = parseLsCurrent(
    '{"node":[{"version":"22.1.0","installed":true,"active":true,' +
      '"source":{"type":"http","path":"https://u:p@registry.internal/n.tgz"}}]}',
  );
  assertEquals(rows.length, 1, "the row itself is still worth having");
  assertEquals(
    rows[0].sourcePath,
    null,
    "the credential-bearing path must be absent, not redacted",
  );
  assertEquals(
    rows[0].resolvedVersion,
    "22.1.0",
    "the rest of the row survives",
  );
});

Deno.test("an unmeasured outdated probe is null and drifts as unmeasured", () => {
  // The bug this guards: a failed outdated probe used to make every tool
  // report outdated:false, which reads as "up to date" -- an unknown rounded
  // into a healthy value.
  const drift = classifyTool(
    { installed: true, active: true, resolvedVersion: "1.0.0" },
    { outdated: null, expectFail: false },
  );
  assertEquals(drift.includes("unmeasured"), true);
  assertEquals(drift.includes("outdated"), false);
});

// ---- errorDetail: opt-in diagnostics without a default leak ---------------

Deno.test("errorDetail is off by default and no host text is stored", async () => {
  const m = await fakeMise({
    stderr: "error: could not reach https://u:p@registry.internal/x",
    exit: 1,
  });
  try {
    const c = mockCtx({ nodes: [{ name: "host", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.errorDetail, null, "detail must be absent by default");
    for (const leak of ["registry.internal", "u:p", "https://"]) {
      assertEquals(
        JSON.stringify(node).includes(leak),
        false,
        `${leak} must not appear anywhere in the node resource`,
      );
    }
  } finally {
    await m.cleanup();
  }
});

Deno.test("errorDetail on preserves the diagnosis the code alone loses", async () => {
  // The point of the option: "unclassified" is safe but tells an operator
  // nothing. On a private fleet whose datastore you own, the excerpt is what
  // explains a novel failure.
  const m = await fakeMise({
    stderr: "mise: something nobody wrote a pattern for",
    exit: 1,
  });
  try {
    const c = mockCtx({
      nodes: [{ name: "host", misePath: m.path }],
      errorDetail: true,
    });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(
      node.error,
      "unclassified",
      "the code stays a closed-set code",
    );
    assertStringIncludes(
      String(node.errorDetail),
      "nobody wrote a pattern for",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("errorDetail never widens the error field itself", async () => {
  // Whatever errorDetail is set to, `error` remains a code. The two fields
  // exist separately so the always-safe one cannot become the unsafe one.
  const m = await fakeMise({
    stderr: "Permission denied (publickey)",
    exit: 1,
  });
  try {
    for (const on of [false, true]) {
      const c = mockCtx({
        nodes: [{ name: "host", misePath: m.path }],
        errorDetail: on,
      });
      await model.methods.discover.execute({}, c.ctx);
      const node = c.written.find((w) => w.spec === "node")!.data;
      assertEquals(
        ERROR_CODES.includes(String(node.error)),
        true,
        `error must stay a closed-set code with errorDetail=${on}`,
      );
    }
  } finally {
    await m.cleanup();
  }
});

// ---- pruning --------------------------------------------------------------

Deno.test("a full sweep prunes rows the fleet no longer reports", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx(
      { nodes: [{ name: "workstation", misePath: m.path }] },
      { existing: ["tool-workstation-go-1234abcd", "summary"] },
    );
    await model.methods.discover.execute({}, c.ctx);
    // Without this the summary would say notinstalled: 0 while last sweep's
    // row still carried the drift, two published views of one fact.
    assertEquals(c.deleted, ["tool-workstation-go-1234abcd"]);
  } finally {
    await m.cleanup();
  }
});

Deno.test("a single-node run never deletes anything", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx(
      {
        nodes: [
          { name: "workstation", misePath: m.path },
          { name: "builder", misePath: m.path },
        ],
      },
      { existing: ["tool-builder--go-1234abcd"] },
    );
    await model.methods.discover.execute({ node: "workstation" }, c.ctx);
    assertEquals(c.deleted, [], "a filtered run legitimately sees a subset");
  } finally {
    await m.cleanup();
  }
});

Deno.test("a single-node run leaves the fleet summary alone", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({
      nodes: [
        { name: "workstation", misePath: m.path },
        { name: "builder", misePath: m.path },
      ],
    });
    await model.methods.discover.execute({ node: "workstation" }, c.ctx);
    // summary sits under a fixed name and says "fleet". One host's totals
    // written there read as the whole fleet, with only nodes: 1 to hint
    // otherwise. The standing record keeps its own sweptAt instead.
    assertEquals(
      c.written.filter((w) => w.spec === "summary").length,
      0,
      "a targeted run must not rewrite a fleet record",
    );
    assertEquals(
      c.written.filter((w) => w.spec === "node").length,
      1,
      "the host it named is still written",
    );
    assertEquals(c.written.filter((w) => w.spec === "tool").length, 1);
  } finally {
    await m.cleanup();
  }
});

Deno.test("a full sweep still writes the fleet summary", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    assertEquals(c.written.filter((w) => w.spec === "summary").length, 1);
  } finally {
    await m.cleanup();
  }
});

Deno.test("a host that could not be measured keeps its history", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN, fail: ["config"] });
  try {
    const c = mockCtx(
      {
        nodes: [
          { name: "gone", misePath: "/nonexistent/mise" },
          { name: "workstation", misePath: m.path },
        ],
      },
      {
        existing: [
          "tool-gone--go-1234abcd",
          "config-workstation--mise-toml-5678abcd",
          "tool-retired--go-9999abcd",
        ],
      },
    );
    await model.methods.discover.execute({}, c.ctx);
    // gone was never measured and workstation's config ls never answered, so
    // neither host's stored rows are evidence of anything departing. The
    // retired host really is gone from the fleet config.
    assertEquals(c.deleted, ["tool-retired--go-9999abcd"]);
  } finally {
    await m.cleanup();
  }
});

// ---- schema discipline ----------------------------------------------------

Deno.test("resource names carry a full-width identity hash", async () => {
  // Tool names come off a remote host, and slugPart collapses punctuation
  // runs, so the readable half hides a lot of variation. The hash is what
  // keeps two of those apart.
  const m = await fakeMiseSuite({
    ls: LS_CURRENT_CLEAN,
    config: '[{"path":"/srv/project/mise.toml","tools":["node"]}]',
  });
  try {
    const c = mockCtx({ nodes: [{ name: "studio", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const names = c.written
      .filter((w) => w.spec !== "summary")
      .map((w) => w.name);
    assertEquals(names.length, 3, "one node, one tool, one config");
    for (const n of names) assertMatch(n, /-[0-9a-f]{64}$/);
  } finally {
    await m.cleanup();
  }
});

/**
 * Two tool names that flatten to the same readable text and collide under a
 * short non-cryptographic hash. Found by searching punctuation variants
 * against 32-bit FNV-1a, the hash this model shipped with first: both give
 * c395a465 over their length-prefixed identity, so both wrote to the one
 * resource name and the second sweep entry silently replaced the first.
 * Exactly the trick a compromised host would use to bury another host's row.
 */
const COLLIDING_TOOLS = [
  "npm.prettier.-plugin-.sort_imports__v2",
  "npm--prettier._plugin__sort..imports_v2",
];

Deno.test("two identities that collide under a weak hash stay apart", async () => {
  const entry = '[{"version":"3.6.2","requested_version":"3","installed":' +
    'true,"active":true,"source":{"type":"mise.toml","path":' +
    '"/srv/project/mise.toml"}}]';
  const m = await fakeMiseSuite({
    ls: `{${
      COLLIDING_TOOLS.map((t) => `${JSON.stringify(t)}:${entry}`).join(",")
    }}`,
  });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const tools = c.written.filter((w) => w.spec === "tool");
    assertEquals(tools.length, 2, "both tools must be written");
    // Same readable half by construction. Only the hash separates them, and
    // under the old one it did not: one name, one surviving row, one tool
    // quietly gone from the reading.
    assertEquals(
      new Set(tools.map((t) => t.name.replace(/-[0-9a-f]{64}$/, ""))).size,
      1,
      "the fixture is only meaningful if the readable halves match",
    );
    assertEquals(
      new Set(tools.map((t) => t.name)).size,
      2,
      "two identities, two resource names",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("the same identity always names the same resource", async () => {
  // Collision resistance is worthless if the name wanders between sweeps.
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const names = [] as string[];
    for (let i = 0; i < 2; i++) {
      const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
      await model.methods.discover.execute({}, c.ctx);
      names.push(c.written.find((w) => w.spec === "tool")!.name);
    }
    assertEquals(names[0], names[1]);
  } finally {
    await m.cleanup();
  }
});

Deno.test("a misspelled drift class never reaches stored data", () => {
  const row = {
    node: "workstation",
    tool: "node",
    requestedVersion: "22",
    resolvedVersion: "22.23.2",
    installPath: null,
    sourceType: null,
    sourcePath: null,
    installed: true,
    active: true,
    outdated: false,
    latestVersion: null,
    drift: ["notinstaled"],
  };
  const schema = model.resources.tool.schema;
  assertEquals(schema.safeParse(row).success, false, "a typo must not parse");
  assertEquals(
    schema.safeParse({ ...row, drift: ["notinstalled"] }).success,
    true,
  );
});

Deno.test("a bidi override in a tool name is escaped, not rendered", () => {
  // U+202E flips the rendering of everything after it, so a name stored as
  // "nod‮elbat" reads on screen as a different tool than the one the row
  // is about. The bytes are not control bytes, so the old C0/C1 filter passed
  // them through untouched and the escape landed in a resource NAME.
  const rows = parseLsCurrent(
    '{"nod‮elbat":[{"version":"22.1.0","installed":true,"active":true}]}',
  );
  assertEquals(rows.length, 1);
  assertEquals(
    rows[0].tool.includes("‮"),
    false,
    "no bidi override may survive into stored text",
  );
  assertStringIncludes(rows[0].tool, "\\u202e");
});

Deno.test("a zero-width joiner cannot hide inside a stored name", () => {
  const rows = parseLsCurrent(
    '{"no‍de":[{"version":"1.0.0","installed":true,"active":true}]}',
  );
  assertEquals(rows[0].tool, "no\\u200dde");
});

Deno.test("a tool name shaped like a credential drops the row and is counted", () => {
  // A key cannot be nulled the way a field can, so the whole entry goes --
  // and the count is what stops that from looking like a host with one tool.
  const sink = { dropped: 0 };
  const rows = parseLsCurrent(
    '{"https://u:p@host/x":[{"version":"1.0.0","installed":true,' +
      '"active":true}],"node":[{"version":"22.1.0","installed":true,' +
      '"active":true}]}',
    sink,
  );
  assertEquals(rows.map((r) => r.tool), ["node"]);
  assertEquals(sink.dropped, 1, "the dropped entry must be visible");
});

Deno.test("a declared tool name shaped like a credential is dropped from tags", () => {
  const sink = { dropped: 0 };
  const cfgs = parseConfigLs(
    '[{"path":"/etc/mise.toml","tools":["node","https://u:p@host/x"]}]',
    sink,
  );
  assertEquals(cfgs.length, 1);
  assertEquals(cfgs[0].tools, ["node"]);
  assertEquals(sink.dropped, 1);
});

Deno.test("a config entry that is not an object is dropped, not read through", () => {
  const sink = { dropped: 0 };
  const cfgs = parseConfigLs(
    '[7,null,{"path":"/etc/mise.toml","tools":["node"]}]',
    sink,
  );
  assertEquals(cfgs.length, 1);
  assertEquals(cfgs[0].path, "/etc/mise.toml");
  assertEquals(sink.dropped, 2);
});

Deno.test("a config with no tools field is not a config declaring nothing", () => {
  // Absence is not emptiness. `tools ?? []` made a host that did not say
  // look like a host that declares no tools, which is a measurement.
  const sink = { dropped: 0 };
  const cfgs = parseConfigLs('[{"path":"/etc/mise.toml"}]', sink);
  assertEquals(cfgs.length, 0);
  assertEquals(sink.dropped, 1);
});

Deno.test("a username-only URL is still an account name", () => {
  // The old rule needed user AND password. A bare username in a source URL
  // is an operator identity, and it went straight into stored data.
  assertEquals(safeRemoteString("https://deploybot@git.internal/x.git"), null);
});

Deno.test("any query or fragment on a source URL is withheld", () => {
  // Not a list of secret-looking parameter names: a source URL needs a
  // scheme, a host and a path, so anything past that is withheld whatever
  // it is called.
  assertEquals(
    safeRemoteString("https://reg.internal/n.tgz?sv=2024&x=1"),
    null,
  );
  assertEquals(safeRemoteString("https://reg.internal/n.tgz#tok"), null);
  assertEquals(
    safeRemoteString("https://reg.internal/n.tgz"),
    "https://reg.internal/n.tgz",
    "an ordinary source URL is not collateral damage",
  );
  assertEquals(
    safeRemoteString("/opt/homebrew/bin/node"),
    "/opt/homebrew/bin/node",
    "a plain path is not a URL and is left alone",
  );
});

Deno.test("ls output that is not an object yields no rows", () => {
  // parseJson<Record<string, unknown>> used to hand an array straight back,
  // and Object.entries over it produced rows keyed "0", "1", "2".
  assertEquals(parseLsCurrent("[1,2,3]").length, 0);
  assertEquals(parseLsCurrent("not json").length, 0);
  assertEquals(parseConfigLs('{"path":"/x"}').length, 0);
});

Deno.test("malformed entries are counted, not silently skipped", () => {
  // The whole point: ten clean rows out of fifty is a broken answer, and
  // before the sink there was nothing in the record that said so.
  const sink = { dropped: 0 };
  parseLsCurrent(
    '{"a":[{"version":22}],"b":[],"c":[{"version":"1.0.0",' +
      '"installed":true,"active":true}]}',
    sink,
  );
  assertEquals(sink.dropped, 2);
});

Deno.test("an unreadable trust line is counted rather than ignored", () => {
  const sink = { dropped: 0 };
  const trusted = parseTrustShow(
    "/etc/mise.toml: trusted\nthis is a banner line\n/o.toml: sideways\n",
    sink,
  );
  assertEquals(trusted["/etc/mise.toml"], true);
  assertEquals(sink.dropped, 2, "the banner and the unknown status both count");
});

Deno.test("a blank trust line is not a dropped entry", () => {
  const sink = { dropped: 0 };
  parseTrustShow("/etc/mise.toml: trusted\n\n", sink);
  assertEquals(sink.dropped, 0);
});

Deno.test("a version banner is not a version", () => {
  // A login shell printing over the answer used to pass on exit code alone.
  assertEquals(parseVersion("2025.1.0 macos-arm64 (abc)"), "2025.1.0");
  assertEquals(parseVersion("v2025.1.0"), "v2025.1.0");
  assertEquals(parseVersion("Welcome to the host!"), null);
  assertEquals(parseVersion(""), null);
});

Deno.test("an oversized remote value is refused, not truncated", () => {
  // The output cap stops a host filling memory; it did not stop one putting
  // a multi-megabyte tool name into a resource field and its tags, because
  // only the readable half of the resource NAME was capped. Refused rather
  // than truncated: truncating stores a different string under the same
  // identity and calls it the measurement.
  const sink = { dropped: 0 };
  const long = "x".repeat(5000);
  const rows = parseLsCurrent(
    `{"${long}":[{"version":"1.0.0","installed":true,"active":true}],` +
      `"node":[{"version":"22.1.0","installed":true,"active":true}]}`,
    sink,
  );
  assertEquals(rows.map((r) => r.tool), ["node"]);
  assertEquals(sink.dropped, 1, "and counted, so the sweep reads as partial");
});

Deno.test("a long but plausible path still survives", () => {
  // The ceiling has to clear anything real. Linux paths top out around 4096
  // bytes and tool names are far shorter.
  const p = "/home/deploy/" + "sub/".repeat(200) + "bin/node";
  assertEquals(p.length < 4096, true);
  assertEquals(safeRemoteString(p), p);
});

Deno.test("safeRemoteKey screens the same shapes as safeRemoteString", () => {
  const sink = { dropped: 0 };
  assertEquals(safeRemoteKey("node", sink), "node");
  assertEquals(safeRemoteKey("https://u:p@host/x", sink), null);
  assertEquals(safeRemoteKey("", sink), null);
  assertEquals(sink.dropped, 2);
});

Deno.test("screening keeps ordinary values and drops credential-bearing ones", () => {
  // Both halves matter equally. A screen that drops real install paths makes
  // the model useless, and one that keeps a token makes it dangerous.
  const keep = [
    "/opt/homebrew/bin/node",
    "/Users/alice/.local/share/mise/installs/node/22.1.0/bin/node",
    "https://nodejs.org/dist/v22.1.0/node-v22.1.0-darwin-arm64.tar.gz",
    "/nix/store/9zm3s1kqlp0v5hbc7d8xj2wq4nf6rytg-node-22.1.0/bin/node",
    "core:node",
    "22.1.0",
  ];
  for (const v of keep) {
    assertEquals(safeRemoteString(v), v, `must survive screening: ${v}`);
  }
  const drop = [
    "https://deploybot@git.internal/x.git",
    "https://u:p@reg.internal/n.tgz",
    "https://reg.internal/n.tgz?sv=2024",
    // Wrapped in punctuation: the anchored form never saw this one.
    "(https://tok@reg.internal/n.tgz)",
    "fetched from https://a:b@h/x and failed",
    // A bare assignment with no URL separator in front of it.
    "token=aX9fQ2LmZ",
    "api_key: 8f3a9c",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    // Spacing changed inside the header.
    "-----BEGIN  RSA  PRIVATE  KEY-----",
    // A bare key with nothing around it to name it.
    "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
  ];
  for (const v of drop) {
    assertEquals(safeRemoteString(v), null, `must be withheld: ${v}`);
  }
});

Deno.test("a version must be a version all the way through", () => {
  // Unanchored, "1evil" matched its leading digit, was accepted, and kept
  // the host off the degraded list -- the opposite of what the check is for.
  assertEquals(parseVersion("1evil"), null);
  assertEquals(parseVersion("2025.1.0-rc1 macos"), "2025.1.0-rc1");
  assertEquals(parseVersion("2025.1.0"), "2025.1.0");
  assertEquals(parseVersion("mise 2025.1.0"), null);
});

Deno.test("an ls entry missing the measurement is not a measured tool", () => {
  // `{}` used to parse into a row saying not-installed, not-active, null
  // versions -- a complete-looking reading of a host that said nothing.
  const sink = { dropped: 0 };
  const rows = parseLsCurrent(
    '{"a":[{}],"b":[{"installed":true,"active":true,"version":"1.0.0"}]}',
    sink,
  );
  assertEquals(rows.map((r) => r.tool), ["b"]);
  assertEquals(sink.dropped, 1);
});

Deno.test("a tool declared but never installed is still a measurement", () => {
  // The other half: absent version and path are what mise genuinely returns
  // for a declared-but-uninstalled tool, and that absence is the finding.
  const rows = parseLsCurrent('{"a":[{"installed":false,"active":false}]}');
  assertEquals(rows.length, 1);
  assertEquals(rows[0].resolvedVersion, null);
  assertEquals(rows[0].installPath, null);
});

Deno.test("a summary total is null, not zero, when a probe went unanswered", async () => {
  // The node record refuses to write zero for a failed probe, and then the
  // summary used to add those refusals up into a fleet zero and publish it
  // as good news -- the same mistake one level up.
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN, fail: ["outdated"] });
  try {
    const c = mockCtx({ nodes: [{ name: "workstation", misePath: m.path }] });
    await model.methods.discover.execute({}, c.ctx);
    const summary = c.written.find((w) => w.spec === "summary")!.data;
    assertEquals(summary.outdated, null);
    assertEquals(
      summary.configsNotInEffect,
      0,
      "the config probe did answer, so its total is a real zero",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("misePath has to name a mise binary", () => {
  // The charset rule alone let it name any executable on the box. The
  // subcommands are fixed, so this was a guarantee the schema advertised
  // and did not keep, rather than a live exploit.
  const ok = (p: string) =>
    GlobalArgsSchema.safeParse({
      nodes: [{ name: "a", misePath: p }],
    }).success;
  assertEquals(ok("/opt/homebrew/bin/mise"), true);
  assertEquals(ok("mise"), true);
  assertEquals(ok("/usr/local/bin/mise.exe"), true);
  assertEquals(ok("/bin/sh"), false);
  assertEquals(ok("/usr/bin/curl"), false);
});

Deno.test("a sweep never offers the agent or a display to a remote host", () => {
  // ssh inherits ambient config. A ForwardAgent in the operator's ~/.ssh/config
  // -- ordinary to have there for hosts you use interactively -- would put the
  // authentication agent on every host this model sweeps, where it can sign
  // for the key it holds.
  const a = sshArgs({ host: "h", user: "u", port: 22 }, 10, "mise ls");
  assertEquals(sshOpt(a, "ForwardAgent"), "no");
  assertEquals(sshOpt(a, "ForwardX11"), "no");
  assertEquals(sshOpt(a, "ForwardX11Trusted"), "no");
  assertEquals(sshOpt(a, "ClearAllForwardings"), "yes");
});

Deno.test("a tool whose outdated entry was malformed is unmeasured, not current", () => {
  // outdated is read by asking whether a tool is a key in the map, so a
  // dropped entry fell out of the map and came back as "not outdated":
  // absence read as health, one level below where that was already being
  // prevented.
  const sink = { dropped: 0, unmeasuredTools: new Set<string>() };
  const outdated = parseOutdated(
    '{"node":{"latest":"22.2.0"},"python":{"latest":7}}',
    sink,
  );
  assertEquals(Object.hasOwn(outdated, "node"), true);
  assertEquals(Object.hasOwn(outdated, "python"), false);
  assertEquals(sink.unmeasuredTools.has("python"), true);
  assertEquals(
    sink.unmeasuredTools.has("node"),
    false,
    "a tool that answered is not marked unmeasured",
  );
});

Deno.test("an auth scheme and its token are withheld together", async () => {
  // `Bearer abc123` is two whitespace-separated tokens and neither is a
  // credential on its own: the scheme word is a word, and the token is
  // opaque with nothing about it to match. Only the pair means anything,
  // and per-token screening walked straight through it.
  const m = await fakeMise({
    stderr: "auth failed: Bearer shortOpaqueToken123 rejected",
    exit: 1,
  });
  try {
    const c = mockCtx({
      nodes: [{ name: "host", misePath: m.path }],
      errorDetail: true,
    });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    const detail = String(node.errorDetail);
    assertEquals(
      detail.includes("shortOpaqueToken123"),
      false,
      `the token survived screening: ${detail}`,
    );
    assertStringIncludes(detail, "[withheld]");
    assertStringIncludes(
      detail,
      "auth failed",
      "the sentence around it is still worth keeping",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("a spaced assignment is withheld across its tokens", async () => {
  const m = await fakeMise({
    stderr: "config error: password = swordfish",
    exit: 1,
  });
  try {
    const c = mockCtx({
      nodes: [{ name: "host", misePath: m.path }],
      errorDetail: true,
    });
    await model.methods.discover.execute({}, c.ctx);
    const node = c.written.find((w) => w.spec === "node")!.data;
    assertEquals(String(node.errorDetail).includes("swordfish"), false);
  } finally {
    await m.cleanup();
  }
});

Deno.test("a multi-word secret is withheld whole, not by its first word", () => {
  // Stopping at the first space withheld the opening word and published the
  // rest, which is worse than withholding nothing: it reads as though the
  // screening worked.
  return (async () => {
    const m = await fakeMise({
      stderr: "config error: password = correct horse battery staple",
      exit: 1,
    });
    try {
      const c = mockCtx({
        nodes: [{ name: "host", misePath: m.path }],
        errorDetail: true,
      });
      await model.methods.discover.execute({}, c.ctx);
      const d = String(
        c.written.find((w) => w.spec === "node")!.data.errorDetail,
      );
      for (const word of ["correct", "horse", "battery", "staple"]) {
        assertEquals(d.includes(word), false, `"${word}" survived: ${d}`);
      }
    } finally {
      await m.cleanup();
    }
  })();
});

Deno.test("a PEM header spanning five words is caught in error text", () => {
  // Tokenized, not one of those five words is a private key, so the marker
  // this model has screened for from the start never matched inside error
  // text at all.
  return (async () => {
    const m = await fakeMise({
      stderr: "read failed: -----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNz",
      exit: 1,
    });
    try {
      const c = mockCtx({
        nodes: [{ name: "host", misePath: m.path }],
        errorDetail: true,
      });
      await model.methods.discover.execute({}, c.ctx);
      const d = String(
        c.written.find((w) => w.spec === "node")!.data.errorDetail,
      );
      assertEquals(
        d.includes("b3BlbnNz"),
        false,
        `key material survived: ${d}`,
      );
      assertStringIncludes(d, "withheld");
    } finally {
      await m.cleanup();
    }
  })();
});

Deno.test("misePath must be named mise exactly", () => {
  const ok = (p: string) =>
    GlobalArgsSchema.safeParse({ nodes: [{ name: "a", misePath: p }] }).success;
  assertEquals(ok("/opt/homebrew/bin/mise"), true);
  assertEquals(ok("/usr/local/bin/mise.exe"), true);
  // Any-extension was allowed by the first form of the rule, which made the
  // README's "the basename must be mise" untrue.
  assertEquals(ok("/tmp/mise.sh"), false);
  assertEquals(ok("/tmp/mise.evil"), false);
});

Deno.test("a bad --node names neither the value nor the fleet", async () => {
  // Echoing the argument put caller-controlled text into a logged error, and
  // listing every configured label turned one wrong guess into a directory
  // of the fleet.
  const c = mockCtx({
    nodes: [{ name: "workstation" }, { name: "controller" }],
  });
  await assertRejects(
    () => model.methods.discover.execute({ node: "nope" }, c.ctx),
    Error,
    "No node by that name is configured",
  );
  try {
    await model.methods.discover.execute({ node: "nope" }, c.ctx);
  } catch (e) {
    const msg = (e as Error).message;
    assertEquals(msg.includes("nope"), false, "must not echo the argument");
    assertEquals(msg.includes("workstation"), false, "must not list the fleet");
    assertEquals(msg.includes("controller"), false, "must not list the fleet");
  }
});

Deno.test("scp-style and scheme-relative locations are screened too", () => {
  // The URL rule only ever saw scheme://, and the form most git remotes are
  // actually written in has no scheme at all -- so the likeliest way for a
  // credential to arrive was the one way nothing looked at.
  for (
    const v of [
      "git@git.internal:org/repo.git",
      "deploy:hunter2@git.internal:org/repo.git",
      "//deploybot@reg.internal/n.tgz",
      "cloned from git@private.host:team/x.git",
    ]
  ) {
    assertEquals(safeRemoteString(v), null, `must be withheld: ${v}`);
  }
  // And the things that merely look similar are not collateral damage.
  for (
    const v of [
      "contact ops@example.com for help",
      "registry.internal:5000/image",
      "/opt/homebrew/bin/node",
    ]
  ) {
    assertEquals(safeRemoteString(v), v, `must survive: ${v}`);
  }
});

Deno.test("a node component is separated from a tool component unambiguously", async () => {
  // A single dash could not carry the boundary: slugs contain dashes, so
  // `tool-web-server-ruby-<hash>` was node `web` with tool `server-ruby` AND
  // node `web-server` with tool `ruby`, and the hash covers the pair rather
  // than either half. That was worked around twice with heuristics standing
  // in for a fact the name did not carry. slugPart collapses every run of
  // non-alphanumerics to one dash, so no slug contains `--`, so the first
  // `--` is always the real boundary.
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    // Belongs to web-server, unambiguously, and web-server answered.
    const stale = "tool-web-server--ruby-" + "0".repeat(64);
    const c = mockCtx(
      {
        nodes: [
          { name: "web", misePath: "/nonexistent/mise" },
          { name: "web-server", misePath: m.path },
        ],
      },
      { existing: [stale] },
    );
    await model.methods.discover.execute({}, c.ctx);
    assertEquals(
      c.deleted.includes(stale),
      true,
      "unmeasured `web` no longer has any claim on a web-server record",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("an unmeasured host still holds its own rows", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const mine = "tool-web--ruby-" + "0".repeat(64);
    const c = mockCtx(
      {
        nodes: [
          { name: "web", misePath: "/nonexistent/mise" },
          { name: "web-server", misePath: m.path },
        ],
      },
      { existing: [mine] },
    );
    await model.methods.discover.execute({}, c.ctx);
    assertEquals(
      c.deleted.includes(mine),
      false,
      "web said nothing about its tools, so its rows are not read as gone",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("an installed, active tool with no version is a hole, not a pass", () => {
  // Every version-dependent judgement passes silently on a missing version:
  // an `expect` rule cannot fail a version the row does not have, so the
  // tool came back with no drift at all and read as healthy.
  const d = classifyTool(
    { installed: true, active: true, resolvedVersion: null },
    { outdated: false, expectFail: false },
  );
  assertEquals(d, ["unmeasured"]);
  // And a row that did report one is still clean.
  assertEquals(
    classifyTool(
      { installed: true, active: true, resolvedVersion: "22.1.0" },
      { outdated: false, expectFail: false },
    ),
    [],
  );
});

Deno.test("a bracketed IPv6 host does not slip past the schemeless rules", () => {
  // A literal address is a private address, and the first version of the
  // host alternative only matched names and dotted quads.
  assertEquals(safeRemoteString("deploy:hunter2@[fd00::1]:org/repo.git"), null);
  assertEquals(safeRemoteString("//deploy@[2001:db8::1]/n.tgz"), null);
});

Deno.test("two node labels that slug alike do not overwrite each other's hold", async () => {
  // "web server" and "web-server" both slug to web-server, so setting the
  // map entry let whichever node came last decide for both -- which could
  // delete a failed host's retained rows. Holding when ANY colliding node
  // is held errs toward keeping data.
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const stale = "tool-web-server--ruby-" + "0".repeat(64);
    const c = mockCtx(
      {
        nodes: [
          { name: "web-server", misePath: m.path },
          { name: "web server", misePath: "/nonexistent/mise" },
        ],
      },
      { existing: [stale] },
    );
    await model.methods.discover.execute({}, c.ctx);
    assertEquals(
      c.deleted.includes(stale),
      false,
      "one of the two colliding nodes was unmeasured, so the row is held",
    );
  } finally {
    await m.cleanup();
  }
});

Deno.test("a URL-shaped value that will not parse fails closed", () => {
  // This returned "carries nothing extra" on a parse failure, so anything
  // URL-shaped that would not parse skipped the check entirely and went
  // into stored data with its credentials intact.
  assertEquals(safeRemoteString("https://user:pass@"), null);
  assertEquals(safeRemoteString("http://@"), null);
  // Only URL-shaped strings reach that rule, so ordinary values are not
  // collateral damage.
  assertEquals(safeRemoteString("core:node"), "core:node");
  assertEquals(safeRemoteString("22.1.0"), "22.1.0");
  assertEquals(
    safeRemoteString("registry.internal:5000/image"),
    "registry.internal:5000/image",
  );
});

Deno.test("escaping is injective, so two tools cannot become one", () => {
  // The escape did not escape its own introducer, so a tool whose name
  // contains a real newline and a tool literally named "\\u000a" rendered
  // as the same string -- same resource name, same identity hash, one
  // silently overwriting the other.
  const rows = parseLsCurrent(
    JSON.stringify({
      "a\nb": [{ installed: true, active: true, version: "1.0.0" }],
      "a\\u000ab": [{ installed: true, active: true, version: "2.0.0" }],
    }),
  );
  assertEquals(rows.length, 2);
  assertEquals(
    rows[0].tool === rows[1].tool,
    false,
    "distinct inputs must stay distinct after escaping",
  );
});

Deno.test("a repeated config path is counted, not silently overwritten", () => {
  // Two rows under one resource name: the second overwrites the first while
  // both are counted in the summary, so the data and the total disagree.
  const sink = { dropped: 0 };
  const cfgs = parseConfigLs(
    '[{"path":"/etc/mise.toml","tools":["node"]},' +
      '{"path":"/etc/mise.toml","tools":["python"]}]',
    sink,
  );
  assertEquals(cfgs.length, 1);
  assertEquals(cfgs[0].tools, ["node"], "the first reading wins");
  assertEquals(sink.dropped, 1, "and the repeat marks the host degraded");
});

Deno.test("ssh host and user are held to hostname and username shapes", () => {
  const ok = (ssh: Record<string, unknown>) =>
    GlobalArgsSchema.safeParse({ nodes: [{ name: "a", ssh }] }).success;
  assertEquals(ok({ host: "h.example.com", user: "reader" }), true);
  // An @ or : inside either silently changes which host is contacted.
  assertEquals(ok({ host: "h.example.com", user: "u@elsewhere" }), false);
  assertEquals(ok({ host: "a@b.example.com", user: "u" }), false);
  assertEquals(ok({ host: "-oProxyCommand=x", user: "u" }), false);
});

Deno.test("a short Basic credential is withheld from a stored field", () => {
  // The field filter required twelve characters and knew only about bearer,
  // while the free-text filter had already been widened -- so the stricter
  // rule guarded error prose and the looser one guarded what is published.
  assertEquals(safeRemoteString("Basic YWxpY2U6cHc="), null);
  assertEquals(safeRemoteString("Bearer abc"), null);
});

Deno.test("a record every candidate node measured is still pruned", () => {
  // Holding unconditionally on ambiguity meant a record whose every
  // candidate node answered stayed forever, contradicting the documented
  // promise that a full sweep deletes what it did not write.
  return (async () => {
    const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
    try {
      const stale = "tool-web-server--ruby-" + "0".repeat(64);
      const c = mockCtx(
        {
          nodes: [
            { name: "web", misePath: m.path },
            { name: "web-server", misePath: m.path },
          ],
        },
        { existing: [stale] },
      );
      await model.methods.discover.execute({}, c.ctx);
      assertEquals(
        c.deleted.includes(stale),
        true,
        "both candidates were measured, so the attribution never had to " +
          "be resolved to know the row is gone",
      );
    } finally {
      await m.cleanup();
    }
  })();
});
