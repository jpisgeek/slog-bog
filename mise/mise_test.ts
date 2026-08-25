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
import { assertEquals } from "jsr:@std/assert@1";
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
  remoteCommand,
  runMise,
  satisfiesExpect,
  sshArgs,
  SUB_LS,
} from "./mise.ts";

const okNode = { name: "studio" };

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
    nodes: [{ name: "studio" }, { name: "studio" }],
  });
  assertEquals(r.success, false, "two nodes cannot share a name");
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
  const d = classifyTool({ installed: false, active: false }, {
    outdated: false,
    expectFail: false,
  });
  assertEquals(d, ["notinstalled"]);
});

Deno.test("installed but not active is its own class, not notinstalled", () => {
  const d = classifyTool({ installed: true, active: false }, {
    outdated: false,
    expectFail: false,
  });
  assertEquals(d, ["notactive"]);
});

Deno.test("a healthy tool carries no drift", () => {
  const d = classifyTool({ installed: true, active: true }, {
    outdated: false,
    expectFail: false,
  });
  assertEquals(d, []);
});

Deno.test("outdated and expect failures stack onto the install state", () => {
  const d = classifyTool({ installed: true, active: true }, {
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

Deno.test("ssh flags fail closed and never spawn a local shell", () => {
  const args = sshArgs(
    { host: "host.example.com", user: "reader", port: 2222 },
    15,
    "mise ls --current --json",
  );
  assertEquals(args, [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-p",
    "2222",
    "reader@host.example.com",
    "mise ls --current --json",
  ]);
});

Deno.test("connect timeout is capped at ten seconds", () => {
  const args = sshArgs({ host: "h.example.com", user: "u", port: 22 }, 90, "x");
  assertEquals(args[3], "ConnectTimeout=10");
  const quick = sshArgs({ host: "h.example.com", user: "u", port: 22 }, 5, "x");
  assertEquals(quick[3], "ConnectTimeout=5");
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

Deno.test("stdout is withheld from the error on a failed run", async () => {
  // stdout can carry config contents. Errors reach swamp run logs and
  // reports, so only stderr is quoted back.
  const m = await fakeMise({
    stdout: "SENSITIVE-CONFIG-BODY",
    stderr: "error: could not read config",
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
      !r.ok && r.error.includes("SENSITIVE-CONFIG-BODY"),
      false,
      "stdout must never reach the error string",
    );
    assertEquals(!r.ok && r.error.includes("could not read config"), true);
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

Deno.test("a declared tool absent from ls --current is notineffect", () => {
  // the config asks for three, mise reports two: the third never took
  assertEquals(
    notInEffect(["node", "python", "go"], ["node", "python"]),
    ["go"],
  );
  assertEquals(notInEffect(["node"], ["node"]), []);
});

type Json = Record<string, unknown>;

/** Mock ctx capturing writeResource calls, as the dashboard tests do. */
function mockCtx(globalArgs: Json) {
  const written: Array<
    { spec: string; name: string; data: Json; opts: Json }
  > = [];
  return {
    written,
    // deno-lint-ignore no-explicit-any
    ctx: {
      signal: new AbortController().signal,
      globalArgs,
      modelType: "@jpisgeek/mise",
      modelId: "m1",
      logger: { info: () => {}, warning: () => {} },
      writeResource: (spec: string, name: string, data: Json, opts?: Json) => {
        written.push({ spec, name, data, opts: opts ?? {} });
        return Promise.resolve({});
      },
      deleteResource: () => Promise.resolve(),
      dataRepository: {
        findAllForModel: () => Promise.resolve([]),
        getContent: () => Promise.resolve(null),
        delete: () => Promise.resolve(),
      },
    } as any,
  };
}

/** A fake mise that answers each subcommand with canned JSON. */
async function fakeMiseSuite(
  answers: { ls?: string; config?: string; outdated?: string; trust?: string },
): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/mise`;
  const script = [
    "#!/bin/sh",
    "# skip a leading -C <dir> so the fake accepts the same argv as the real one",
    'if [ "$1" = "-C" ]; then shift 2; fi',
    'if [ "$1" = "--version" ]; then echo "2026.8.12 test"; exit 0; fi',
    `if [ "$1" = "ls" ]; then cat <<'EOF'\n${
      answers.ls ?? "{}"
    }\nEOF\nexit 0; fi`,
    `if [ "$1" = "config" ]; then cat <<'EOF'\n${
      answers.config ?? "[]"
    }\nEOF\nexit 0; fi`,
    `if [ "$1" = "outdated" ]; then cat <<'EOF'\n${
      answers.outdated ?? "{}"
    }\nEOF\nexit 0; fi`,
    `if [ "$1" = "trust" ]; then cat <<'EOF'\n${
      answers.trust ?? ""
    }\nEOF\nexit 0; fi`,
    "exit 0",
  ].join("\n");
  await Deno.writeTextFile(path, script);
  await Deno.chmod(path, 0o755);
  return { path, cleanup: () => Deno.remove(dir, { recursive: true }) };
}

Deno.test("discover is the only method", () => {
  assertEquals(Object.keys(model.methods), ["discover"]);
});

Deno.test("a clean host writes tool rows with no drift", async () => {
  const m = await fakeMiseSuite({ ls: LS_CURRENT_CLEAN });
  try {
    const c = mockCtx({ nodes: [{ name: "studio", misePath: m.path }] });
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

Deno.test("a host without mise is unmeasured, never a zero tool count", async () => {
  const c = mockCtx({
    nodes: [{ name: "gone", misePath: "/nonexistent/mise" }],
  });
  await model.methods.discover.execute({}, c.ctx);
  const node = c.written.find((w) => w.spec === "node")!.data;
  assertEquals(node.measured, false);
  assertEquals(node.reachable, false);
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
    const c = mockCtx({ nodes: [{ name: "studio", misePath: m.path }] });
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
      nodes: [{ name: "studio", misePath: m.path }],
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
        { name: "studio", misePath: m.path },
        { name: "gone", misePath: "/nonexistent/mise" },
      ],
    });
    await model.methods.discover.execute({}, c.ctx);
    const summary = c.written.find((w) => w.spec === "summary")!.data;
    assertEquals(summary.nodes, 2);
    assertEquals(summary.nodesMeasured, 1);
    assertEquals(summary.nodesUnmeasured, 1);
    assertEquals(summary.tools, 1);
  } finally {
    await m.cleanup();
  }
});
