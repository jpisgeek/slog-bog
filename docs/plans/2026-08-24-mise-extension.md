# @jpisgeek/mise Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `@jpisgeek/mise`, a read-only swamp model that sweeps mise toolchain state across a fleet and records where each host disagrees with its own config.

**Architecture:** One model file exporting a single `discover` method. All decision logic lives in small exported pure functions (version matching, drift classification, command construction, failure classification) so the test suite drives them directly rather than through a live host. Subprocess execution goes through one runner that treats "mise did not run" as a distinct state from "mise found nothing". Local nodes use an argv array with no shell. SSH nodes reuse `netdata`'s hardened flag set.

**Tech Stack:** Deno, TypeScript, `npm:zod@4`, `jsr:@std/assert@1`. No other dependencies (`dependencies: []` in the manifest, matching every sibling).

**Spec:** `docs/design/2026-08-24-mise-extension.md`

## Global Constraints

- **Package name:** `@jpisgeek/mise`. **Model type:** `@jpisgeek/mise`. **Version:** `2026.08.24.1`, identical in `manifest.yaml` and the `model.version` field.
- **Voice, from the start.** Prose is inside the content hash, so per `vault:projects/slog-bog/voice-pass-requirement.md` the voice pass happens before the first review, not after. Write the module header, comments, `.describe()` strings, manifest description, and `readme.vars.yaml` in the house voice as you go, so the Fable review runs once instead of twice. Register: restrained, dry, bog-themed asides. Calibrate against `netdata/readme.vars.yaml` ("This model just wades in, records the verdicts"; "Something in the swamp is always powered off"). Meaning always wins over the bit: `.describe()` text is how a stranger learns what to type.
- **No em-dashes and no prose semicolons** in any markdown or prose surface. The repo's markdown docs measure zero em-dashes.
- **Comments explain why, not what.** This is the repo's established comment style, visible throughout `netdata.ts`.
- **No real identifiers anywhere.** No hostname, username, home path, or real project directory in any file. Examples use `host.example.com`, `<home>`, `/srv/project`. `scripts/scan-identifiers.sh` runs at gate 5 with a private denylist.
- **Never edit `mise/README.md` by hand.** It is generated from `mise/readme.vars.yaml` plus the source. Edit vars, then regenerate.
- **Do not theme the LICENSE.** MIT text is verbatim, copied from a sibling.
- **Nullable, never empty-string, for identity fields.** "Never reached this host" is a different fact from "host reported an empty version". Pattern at `netdata.ts:107-112`.
- **Run tests with:** `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/` (the flag set `scripts/publish.sh` gate 2 uses).

---

## File Structure

| File | Responsibility |
|---|---|
| `mise/manifest.yaml` | Package metadata, version, published file list |
| `mise/mise.ts` | Schemas, pure decision functions, the runner, the `discover` method |
| `mise/mise_test.ts` | Full suite. Not in the manifest, so it does not move the content hash |
| `mise/readme.vars.yaml` | The only hand-written README input |
| `mise/README.md` | Generated. Never hand-edited |
| `mise/LICENSE` | MIT, verbatim copy from a sibling |

Everything lives in one model file because that is the repo's established shape: `netdata.ts` is 903 lines, `truenas.ts` 883, `firewalla.ts` 863. Only `lmstudio` splits, and it splits across two genuinely distinct model types. A second file here would break the pattern without earning anything.

---

### Task 1: Scaffold, manifest, and the validating schemas

The injection surface is closed here, before any code can call a subprocess. `dir` and `misePath` reach the remote command string, so they are rejected at parse time rather than repaired.

**Files:**
- Create: `mise/manifest.yaml`, `mise/LICENSE`, `mise/mise.ts`, `mise/mise_test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `GlobalArgsSchema`, `NodeSchema` (exported for test), and the `model` object skeleton with `type`, `version`, `globalArguments`.

- [ ] **Step 1: Create the directory and copy the LICENSE verbatim**

```bash
mkdir -p mise
cp netdata/LICENSE mise/LICENSE
```

- [ ] **Step 2: Write `mise/manifest.yaml`**

```yaml
manifestVersion: 1
name: "@jpisgeek/mise"
version: 2026.08.24.1
description: >
  Read-only sweep of mise toolchain state across a fleet. Records which tool
  versions each host is actually running and where that disagrees with the
  host's own config: requested but never installed, installed but not active,
  declared in a config that never took effect, or behind the latest. Installs
  nothing and upgrades nothing. mise already does that well. This one only
  wades through the fleet and writes down what it finds, including which hosts
  refused to answer, because a host that could not be measured is not a host
  that is clean.
repository: https://github.com/jpisgeek/slog-bog/tree/main/mise
paths:
  base: manifest
models:
  - mise.ts
workflows: []
vaults: []
drivers: []
datastores: []
reports: []
additionalFiles:
  - README.md
  - LICENSE
platforms:
  - darwin-aarch64
  - linux-x86_64
labels:
  - mise
  - toolchain
  - drift
  - fleet
  - versions
dependencies: []
```

- [ ] **Step 3: Write the failing test**

Create `mise/mise_test.ts`:

```ts
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
import { GlobalArgsSchema } from "./mise.ts";

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
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: FAIL. `mise.ts` does not exist yet, so the import cannot resolve.

- [ ] **Step 5: Write `mise/mise.ts` with the schemas**

```ts
/**
 * mise toolchain drift across a fleet.
 *
 * mise already installs tools and pins versions, and it does that well. This
 * model installs nothing, upgrades nothing, and trusts nothing. It walks the
 * fleet, asks each host what it is actually running, and writes down where
 * that disagrees with what the host's own config asked for.
 *
 * The distinction the whole model is built around: a host that did not answer
 * is not a host with nothing to report. mise is routinely absent from a
 * non-login shell's PATH, and an empty tool list from a host that never ran
 * mise reads exactly like a host that is perfectly clean. So every failure to
 * measure is recorded as a failure to measure, never as a zero.
 */
import { z } from "npm:zod@4";

/**
 * Absolute path, and only characters that cannot change the meaning of the
 * single-quoted remote command they are interpolated into. No quote, no
 * semicolon, no dollar, no backtick, no whitespace.
 */
const SAFE_ABS_PATH = /^\/[A-Za-z0-9._/-]*$/;
/** Same character class, but a bare command name like `mise` is also fine. */
const SAFE_BIN_PATH = /^[A-Za-z0-9._/-]+$/;

const SshSchema = z.object({
  // host/user become the positional `user@host` argument to ssh. A value
  // starting with "-" would be read as an ssh option (-oProxyCommand=...).
  host: z.string().min(1).refine((v) => !v.startsWith("-"), {
    message: "ssh.host must not start with '-'",
  }),
  user: z.string().min(1).refine((v) => !v.startsWith("-"), {
    message: "ssh.user must not start with '-'",
  }),
  port: z.number().int().positive().default(22),
});

export const NodeSchema = z.object({
  name: z.string().min(1).describe("Label for this host in the written data"),
  ssh: SshSchema.optional().describe(
    "Reach this host over SSH. Omit for the machine swamp is running on.",
  ),
  dir: z
    .string()
    .refine(
      (v) => SAFE_ABS_PATH.test(v) && !v.split("/").includes(".."),
      {
        message:
          "dir must be an absolute path made of [A-Za-z0-9._/-] with no '..' " +
          "segment. It is interpolated into the remote command, so a value " +
          "that could change that command's meaning is refused rather than " +
          "stripped: a half-repaired path that silently measures the wrong " +
          "directory is worse than a config error.",
      },
    )
    .optional()
    .describe(
      "Which directory's config to evaluate. mise config is directory-scoped, " +
        "so without this the question has no fixed answer. Defaults to the " +
        "swamp working directory locally and the login directory over SSH.",
    ),
  misePath: z
    .string()
    .refine((v) => SAFE_BIN_PATH.test(v) && !v.startsWith("-"), {
      message:
        "misePath must match [A-Za-z0-9._/-] and must not start with '-'",
    })
    .default("mise")
    .describe(
      "Path to the mise binary. Worth setting for SSH hosts: a non-login " +
        "shell often has no ~/.local/bin on PATH, and mise lives there.",
    ),
});

export const GlobalArgsSchema = z.object({
  nodes: z
    .array(NodeSchema)
    .min(1)
    .refine(
      (ns) => new Set(ns.map((n) => n.name)).size === ns.length,
      { message: "Duplicate node name: each node needs its own label" },
    ),
  timeoutSec: z.number().int().positive().default(15),
  maxConcurrency: z
    .number()
    .int()
    .positive()
    .default(8)
    .describe(
      "How many hosts to poll at once. A long nodes list otherwise spawns an " +
        "unbounded pile of ssh processes at the same time.",
    ),
  expect: z
    .record(z.string(), z.string())
    .default({})
    .describe(
      "Optional fleet-wide expectation, e.g. {node: '22'}. A version matches " +
        "when its dot-separated segments start with these, so '22' accepts " +
        "22.23.2 but '22.2' does not. Omit it and each host is judged only " +
        "against its own config.",
    ),
});

export const model = {
  type: "@jpisgeek/mise",
  version: "2026.08.24.1",
  globalArguments: GlobalArgsSchema,
  resources: {},
  methods: {},
};
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: PASS, 5 tests.

- [ ] **Step 7: Format and commit**

```bash
deno fmt mise/
git add mise/
git commit -m "mise: scaffold, manifest, and the schemas that close the injection surface"
```

---

### Task 2: Version matching and drift classification

Two pure functions, no I/O. They hold the only judgement calls in the model, so they get tested directly rather than through a subprocess.

**Files:**
- Modify: `mise/mise.ts`
- Test: `mise/mise_test.ts`

**Interfaces:**
- Consumes: nothing from Task 1 beyond the module.
- Produces: `type Drift`, `satisfiesExpect(expected: string, resolved: string): boolean`, `classifyTool(entry: ToolEntry, opts: { outdated: boolean; expectFail: boolean }): Drift[]`, and `type ToolEntry = { installed: boolean; active: boolean }`.

- [ ] **Step 1: Write the failing test**

Append to `mise/mise_test.ts`:

```ts
import { classifyTool, satisfiesExpect } from "./mise.ts";

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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: FAIL. `classifyTool` and `satisfiesExpect` are not exported from `mise.ts`.

- [ ] **Step 3: Write the implementation**

Add to `mise/mise.ts`, above the `model` export:

```ts
export type Drift =
  | "notinstalled"
  | "notactive"
  | "notineffect"
  | "outdated"
  | "expected"
  | "unmeasured";

export type ToolEntry = { installed: boolean; active: boolean };

/**
 * Does `resolved` satisfy the `expect` value? Compared segment by segment, so
 * "22" accepts 22.23.2 while "22.2" does not. A plain string prefix would
 * quietly accept 22.23.2 for an operator who asked for the 22.2 line, which is
 * the sort of near-miss nobody notices until a build breaks.
 */
export function satisfiesExpect(expected: string, resolved: string): boolean {
  const want = expected.split(".");
  const got = resolved.split(".");
  if (want.length > got.length) return false;
  return want.every((seg, i) => seg === got[i]);
}

/**
 * Drift for a single tool the current config asked for. Install state is
 * mutually exclusive (a tool cannot be both missing and merely inactive), so
 * those two are an either/or. Outdated and expect are independent judgements
 * layered on top.
 */
export function classifyTool(
  entry: ToolEntry,
  opts: { outdated: boolean; expectFail: boolean },
): Drift[] {
  const drift: Drift[] = [];
  if (!entry.installed) drift.push("notinstalled");
  else if (!entry.active) drift.push("notactive");
  if (opts.outdated) drift.push("outdated");
  if (opts.expectFail) drift.push("expected");
  return drift;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: PASS, 10 tests.

- [ ] **Step 5: Format and commit**

```bash
deno fmt mise/
git add mise/
git commit -m "mise: segment-wise expect matching and drift classification"
```

---

### Task 3: Command construction for both transports

Pure functions returning argv arrays and the remote command string. The SSH path cannot be exercised against a real host in CI, so its correctness is asserted here on the constructed command rather than through a connection.

**Files:**
- Modify: `mise/mise.ts`
- Test: `mise/mise_test.ts`

**Interfaces:**
- Consumes: `NodeSchema`'s parsed shape from Task 1.
- Produces: `localArgs(dir: string | undefined, sub: string[]): string[]`, `remoteCommand(misePath: string, dir: string | undefined, sub: string[]): string`, `sshArgs(ssh: { host: string; user: string; port: number }, timeoutSec: number, remote: string): string[]`, and the constant `SUB_LS = ["ls", "--current", "--json"]`.

- [ ] **Step 1: Write the failing test**

Append to `mise/mise_test.ts`:

```ts
import { localArgs, remoteCommand, sshArgs, SUB_LS } from "./mise.ts";

Deno.test("local invocation is an argv array with no shell involved", () => {
  assertEquals(localArgs("/srv/project", SUB_LS), [
    "-C",
    "/srv/project",
    "ls",
    "--current",
    "--json",
  ]);
  // no dir means no -C, which lets mise use the working directory
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
  // dir cannot contain a quote (Task 1 rejects it), so single-quoting is
  // sufficient rather than merely hopeful. This test states the coupling so
  // that loosening SAFE_ABS_PATH without revisiting the quoting fails here.
  const parsed = GlobalArgsSchema.safeParse({
    nodes: [{ name: "n", dir: "/srv/it's" }],
  });
  assertEquals(parsed.success, false, "a quote in dir must never parse");
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
  // a generous overall timeout should not mean waiting a minute on a host
  // that is simply switched off
  const args = sshArgs({ host: "h.example.com", user: "u", port: 22 }, 90, "x");
  assertEquals(args[3], "ConnectTimeout=10");
  const quick = sshArgs({ host: "h.example.com", user: "u", port: 22 }, 5, "x");
  assertEquals(quick[3], "ConnectTimeout=5");
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: FAIL. `localArgs`, `remoteCommand`, `sshArgs`, and `SUB_LS` are not exported.

- [ ] **Step 3: Write the implementation**

Add to `mise/mise.ts`:

```ts
/** The three read-only invocations this model ever makes. */
export const SUB_LS = ["ls", "--current", "--json"];
export const SUB_CONFIG = ["config", "ls", "--json"];
export const SUB_OUTDATED = ["outdated", "--json"];
export const SUB_VERSION = ["--version"];
export const SUB_TRUST = ["trust", "--show"];

/**
 * Local argv. Handed straight to Deno.Command, which does not go through a
 * shell, so nothing here can be reinterpreted no matter what dir holds.
 */
export function localArgs(dir: string | undefined, sub: string[]): string[] {
  return dir ? ["-C", dir, ...sub] : [...sub];
}

/**
 * The one place operator data is interpolated into a string a remote shell
 * will parse. `dir` is single-quoted, which is sufficient rather than merely
 * hopeful because the schema has already refused any value containing a
 * quote. Everything else in the string is a fixed literal.
 */
export function remoteCommand(
  misePath: string,
  dir: string | undefined,
  sub: string[],
): string {
  const parts = [misePath];
  if (dir) parts.push("-C", `'${dir}'`);
  parts.push(...sub);
  return parts.join(" ");
}

/**
 * BatchMode=yes so an unknown host key or a password prompt fails closed
 * instead of hanging a sweep forever. ConnectTimeout is capped at ten seconds
 * because a switched-off host should not consume the whole per-node budget
 * before the command even starts.
 */
export function sshArgs(
  ssh: { host: string; user: string; port: number },
  timeoutSec: number,
  remote: string,
): string[] {
  return [
    "-o",
    "BatchMode=yes",
    "-o",
    `ConnectTimeout=${Math.min(timeoutSec, 10)}`,
    "-p",
    String(ssh.port),
    `${ssh.user}@${ssh.host}`,
    remote,
  ];
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: PASS, 15 tests.

- [ ] **Step 5: Format and commit**

```bash
deno fmt mise/
git add mise/
git commit -m "mise: command construction for the local and ssh transports"
```

---

### Task 4: The runner, and unmeasured as a first-class state

This is the honesty property. A host where mise never ran must never be recorded as a host with no tools.

**Files:**
- Modify: `mise/mise.ts`
- Test: `mise/mise_test.ts`

**Interfaces:**
- Consumes: `localArgs`, `sshArgs`, `remoteCommand`, `SUB_LS` from Task 3.
- Produces: `classifyFailure(code: number, stderr: string): "notfound" | "failed"`, `type RunResult = { ok: true; stdout: string } | { ok: false; kind: "notfound" | "failed"; error: string }`, and `runMise(node: ParsedNode, sub: string[], timeoutSec: number, signal: AbortSignal): Promise<RunResult>` where `ParsedNode = z.infer<typeof NodeSchema>`.

- [ ] **Step 1: Write the failing test**

Append to `mise/mise_test.ts`:

```ts
import { classifyFailure, runMise } from "./mise.ts";

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
  assertEquals(classifyFailure(1, "error: config file is invalid toml"), "failed");
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: FAIL. `classifyFailure` and `runMise` are not exported.

- [ ] **Step 3: Write the implementation**

Add to `mise/mise.ts`:

```ts
/**
 * A shell that cannot find mise reports it in several ways depending on which
 * shell answered: 127 is conventional, but the message alone is the reliable
 * signal across sh, bash, and zsh. This distinction is the whole point of the
 * unmeasured state, so it is detected on both.
 */
const NOT_FOUND_RE = /command not found|No such file or directory/i;

export function classifyFailure(
  code: number,
  stderr: string,
): "notfound" | "failed" {
  if (code === 127 || NOT_FOUND_RE.test(stderr)) return "notfound";
  return "failed";
}

export type RunResult =
  | { ok: true; stdout: string }
  | { ok: false; kind: "notfound" | "failed"; error: string };

export type ParsedNode = z.infer<typeof NodeSchema>;

/**
 * Run one read-only mise subcommand against one node.
 *
 * Only stderr is quoted back into the error. mise prints config contents on
 * stdout, and error strings end up in swamp run logs and reports, so stdout
 * stays out of them.
 */
export async function runMise(
  node: ParsedNode,
  sub: string[],
  timeoutSec: number,
  signal: AbortSignal,
): Promise<RunResult> {
  const bin = node.misePath ?? "mise";
  const cmd = node.ssh
    ? new Deno.Command("ssh", {
      args: sshArgs(
        node.ssh,
        timeoutSec,
        remoteCommand(bin, node.dir, sub),
      ),
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
      signal: AbortSignal.any([
        signal,
        AbortSignal.timeout((timeoutSec + 10) * 1000),
      ]),
    })
    : new Deno.Command(bin, {
      args: localArgs(node.dir, sub),
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
      signal: AbortSignal.any([
        signal,
        AbortSignal.timeout((timeoutSec + 10) * 1000),
      ]),
    });

  try {
    const out = await cmd.output();
    const stderr = new TextDecoder().decode(out.stderr).trim();
    if (!out.success) {
      return {
        ok: false,
        kind: classifyFailure(out.code, stderr),
        error: stderr.slice(0, 160) || `exit ${out.code}`,
      };
    }
    return { ok: true, stdout: new TextDecoder().decode(out.stdout) };
  } catch (e) {
    // Deno throws NotFound when the local binary itself is absent, which is
    // the same fact as a shell's 127 and must classify the same way.
    const msg = (e as Error).message;
    return {
      ok: false,
      kind: e instanceof Deno.errors.NotFound
        ? "notfound"
        : classifyFailure(-1, msg),
      error: msg.slice(0, 160),
    };
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: PASS, 21 tests.

- [ ] **Step 5: Format and commit**

```bash
deno fmt mise/
git add mise/
git commit -m "mise: runner that tells a missing binary apart from an empty result"
```

---

### Task 5: Parsing mise output into tool rows

Turns the three JSON payloads into flat rows, including the `notineffect` class, which is the one drift the spec derives from two sources rather than one.

**Files:**
- Modify: `mise/mise.ts`
- Test: `mise/mise_test.ts`

**Interfaces:**
- Consumes: `Drift`, `classifyTool`, `satisfiesExpect` from Task 2.
- Produces: `type ToolRow = { tool: string; requestedVersion: string | null; resolvedVersion: string | null; installPath: string | null; sourceType: string | null; sourcePath: string | null; installed: boolean; active: boolean; outdated: boolean; latestVersion: string | null; drift: Drift[] }`, `parseLsCurrent(json: string): ToolRow[]`, `parseConfigLs(json: string): { path: string; tools: string[] }[]`, `parseOutdated(json: string): Record<string, string | null>`, `parseTrustShow(text: string): Record<string, boolean>`, and `notInEffect(declared: string[], present: string[]): string[]`.

- [ ] **Step 1: Write the failing test**

Append to `mise/mise_test.ts`:

```ts
import {
  notInEffect,
  parseConfigLs,
  parseLsCurrent,
  parseOutdated,
  parseTrustShow,
} from "./mise.ts";

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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: FAIL. The five parse helpers are not exported.

- [ ] **Step 3: Write the implementation**

Add to `mise/mise.ts`:

```ts
export type ToolRow = {
  tool: string;
  requestedVersion: string | null;
  resolvedVersion: string | null;
  installPath: string | null;
  sourceType: string | null;
  sourcePath: string | null;
  installed: boolean;
  active: boolean;
  outdated: boolean;
  latestVersion: string | null;
  drift: Drift[];
};

/** JSON.parse that yields a fallback instead of throwing mid-sweep. */
function parseJson<T>(raw: string, fallback: T): T {
  try {
    const v = JSON.parse(raw);
    return v == null ? fallback : v as T;
  } catch {
    return fallback;
  }
}

const str = (v: unknown): string | null =>
  typeof v === "string" && v !== "" ? v : null;

/**
 * `mise ls --current --json` is keyed by tool name, each holding an array of
 * entries. Only the first entry per tool is the one the config selected, so
 * that is the row. Anything shaped unexpectedly is skipped rather than cast:
 * this data crosses a process boundary and nothing validates it upstream.
 */
export function parseLsCurrent(json: string): ToolRow[] {
  const obj = parseJson<Record<string, unknown>>(json, {});
  const rows: ToolRow[] = [];
  for (const [tool, entries] of Object.entries(obj)) {
    if (!Array.isArray(entries) || entries.length === 0) continue;
    const e = entries[0] as Record<string, unknown>;
    if (!e || typeof e !== "object") continue;
    const source = (e.source ?? {}) as Record<string, unknown>;
    rows.push({
      tool,
      requestedVersion: str(e.requested_version),
      resolvedVersion: str(e.version),
      installPath: str(e.install_path),
      sourceType: str(source.type),
      sourcePath: str(source.path),
      installed: e.installed === true,
      active: e.active === true,
      outdated: false,
      latestVersion: null,
      drift: [],
    });
  }
  return rows;
}

export function parseConfigLs(
  json: string,
): { path: string; tools: string[] }[] {
  const arr = parseJson<unknown[]>(json, []);
  if (!Array.isArray(arr)) return [];
  const out: { path: string; tools: string[] }[] = [];
  for (const raw of arr) {
    const c = raw as Record<string, unknown>;
    const path = str(c?.path);
    if (!path) continue;
    const tools = Array.isArray(c.tools) ? c.tools.map((t) => String(t)) : [];
    out.push({ path, tools });
  }
  return out;
}

/** Tool name to its latest version, for whatever mise reports as behind. */
export function parseOutdated(json: string): Record<string, string | null> {
  const obj = parseJson<Record<string, unknown>>(json, {});
  const out: Record<string, string | null> = {};
  for (const [tool, v] of Object.entries(obj)) {
    const rec = v as Record<string, unknown>;
    out[tool] = str(rec?.latest);
  }
  return out;
}

/**
 * `trust --show` has no JSON output, so this parses its "<path>: <status>"
 * lines. Recorded for context only. An untrusted plain [tools] config still
 * applies, so trust is never a drift trigger on its own.
 */
export function parseTrustShow(text: string): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const line of text.split("\n")) {
    const idx = line.lastIndexOf(": ");
    if (idx === -1) continue;
    const path = line.slice(0, idx).trim();
    const status = line.slice(idx + 2).trim();
    if (!path) continue;
    if (status === "trusted") out[path] = true;
    else if (status === "untrusted") out[path] = false;
  }
  return out;
}

/** Tools a config declares that never appeared in `ls --current`. */
export function notInEffect(declared: string[], present: string[]): string[] {
  const have = new Set(present);
  return declared.filter((t) => !have.has(t));
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: PASS, 27 tests.

- [ ] **Step 5: Format and commit**

```bash
deno fmt mise/
git add mise/
git commit -m "mise: parse ls, config, outdated, and trust into flat rows"
```

---

### Task 6: The discover method and its resources

Wires everything into the swamp model surface: resource schemas, the bounded-concurrency sweep, and the summary.

**Files:**
- Modify: `mise/mise.ts`
- Test: `mise/mise_test.ts`

**Interfaces:**
- Consumes: everything from Tasks 1 through 5.
- Produces: `model.resources.node`, `model.resources.tool`, `model.resources.config`, `model.resources.summary`, and `model.methods.discover`.

- [ ] **Step 1: Write the failing test**

Append to `mise/mise_test.ts`:

```ts
import { model } from "./mise.ts";

type Json = Record<string, unknown>;

/** Mock ctx capturing writeResource calls, as the dashboard tests do. */
function mockCtx(globalArgs: Json) {
  const written: Array<{ spec: string; name: string; data: Json }> = [];
  return {
    written,
    // deno-lint-ignore no-explicit-any
    ctx: {
      signal: new AbortController().signal,
      globalArgs,
      modelType: "@jpisgeek/mise",
      modelId: "m1",
      logger: { info: () => {}, warning: () => {} },
      writeResource: (spec: string, name: string, data: Json) => {
        written.push({ spec, name, data });
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
    `if [ "$1" = "ls" ]; then cat <<'EOF'\n${answers.ls ?? "{}"}\nEOF\nexit 0; fi`,
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
  } finally {
    await m.cleanup();
  }
});

Deno.test("a host without mise is unmeasured, never a zero tool count", async () => {
  const c = mockCtx({ nodes: [{ name: "gone", misePath: "/nonexistent/mise" }] });
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
  const c = mockCtx({ nodes: [{ name: "gone", misePath: "/nonexistent/mise" }] });
  await model.methods.discover.execute({}, c.ctx);
  const node = c.written.find((w) => w.spec === "node")!.data;
  assertEquals(node.miseVersion, null);
});

Deno.test("a declared tool that never took effect is recorded", async () => {
  const m = await fakeMiseSuite({
    ls: '{"node":[{"version":"22.23.2","requested_version":"22","installed":true,"active":true,"source":{"type":"mise.toml","path":"/srv/project/mise.toml"}}]}',
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
```

Add this constant near the top of the test file, beside `LS_CURRENT`:

```ts
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: FAIL. `model.methods.discover` does not exist, so `Object.keys(model.methods)` is empty and `execute` is undefined.

- [ ] **Step 3: Write the resource schemas**

Replace `resources: {}` in `mise/mise.ts`:

```ts
const NodeStateSchema = z.object({
  name: z.string(),
  /**
   * Did mise actually run here? Everything downstream depends on this being
   * separate from the counts. A host that did not answer has null counts, not
   * zero ones, because zero is a measurement and this is the absence of one.
   */
  measured: z.boolean(),
  reachable: z.boolean(),
  transport: z.string(),
  error: z.string().nullable(),
  miseVersion: z.string().nullable(),
  dir: z.string().nullable(),
  configCount: z.number().nullable(),
  toolCount: z.number().nullable(),
  drift: z.array(z.string()),
});

const ToolStateSchema = z.object({
  node: z.string(),
  tool: z.string(),
  requestedVersion: z.string().nullable(),
  resolvedVersion: z.string().nullable(),
  installPath: z.string().nullable(),
  sourceType: z.string().nullable(),
  sourcePath: z.string().nullable(),
  installed: z.boolean(),
  active: z.boolean(),
  outdated: z.boolean(),
  latestVersion: z.string().nullable(),
  drift: z.array(z.string()),
});

const ConfigStateSchema = z.object({
  node: z.string(),
  path: z.string(),
  trusted: z.boolean().nullable(),
  toolsDeclared: z.array(z.string()),
  toolsInEffect: z.array(z.string()),
  toolsNotInEffect: z.array(z.string()),
});

const SummarySchema = z.object({
  nodes: z.number(),
  nodesMeasured: z.number(),
  nodesUnmeasured: z.number(),
  tools: z.number(),
  notinstalled: z.number(),
  notactive: z.number(),
  notineffect: z.number(),
  outdated: z.number(),
  expected: z.number(),
  sweptAt: z.string(),
});
```

And the resources block:

```ts
  resources: {
    node: {
      description:
        "One record per host: whether mise answered at all, which directory " +
        "was measured, and how much drift was found there.",
      schema: NodeStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    tool: {
      description:
        "One record per tool per host: what the config asked for, what the " +
        "host resolved it to, and whether it is installed, active, or behind.",
      schema: ToolStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    config: {
      description:
        "One record per mise config file in scope, with the tools it " +
        "declares and the tools that never took effect.",
      schema: ConfigStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    summary: {
      description: "Fleet totals for the most recent sweep.",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },
```

- [ ] **Step 4: Write the discover method**

Replace `methods: {}`:

```ts
  methods: {
    discover: {
      description:
        "Ask every configured host what toolchain it is running and write " +
        "down where that disagrees with its own config. Read-only: nothing " +
        "is installed, upgraded, or trusted.",
      arguments: z.object({
        node: z.string().optional().describe("Limit the sweep to one node"),
      }),
      // deno-lint-ignore no-explicit-any
      execute: async (args: { node?: string }, ctx: any) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const targets = args.node
          ? g.nodes.filter((n) => n.name === args.node)
          : g.nodes;

        ctx.logger.info("sweeping {n} host(s) for mise state", {
          n: targets.length,
        });

        const handles = [];
        const nodeStates: z.infer<typeof NodeStateSchema>[] = [];
        const toolStates: z.infer<typeof ToolStateSchema>[] = [];
        const configStates: z.infer<typeof ConfigStateSchema>[] = [];

        // Bounded concurrency: a long nodes list otherwise spawns an
        // unbounded pile of ssh processes at once.
        const queue = [...targets];
        const worker = async () => {
          for (;;) {
            const node = queue.shift();
            if (!node) return;
            const transport = node.ssh ? "ssh" : "local";
            const run = (sub: string[]) =>
              runMise(node, sub, g.timeoutSec, ctx.signal);

            const ls = await run(SUB_LS);
            if (!ls.ok) {
              // The honesty case. Counts stay null so that "we could not ask"
              // never reads downstream as "there was nothing to find".
              ctx.logger.warning(
                "{name} unmeasured ({kind}): {err}",
                { name: node.name, kind: ls.kind, err: ls.error },
              );
              nodeStates.push({
                name: node.name,
                measured: false,
                // Deliberately false even when ssh itself connected and only
                // mise was missing. The schema has no field for "answered but
                // could not be measured", so `measured` carries that signal
                // and `error` keeps the kind. See the plan's self-review note.
                reachable: false,
                transport,
                error: ls.error,
                miseVersion: null,
                dir: node.dir ?? null,
                configCount: null,
                toolCount: null,
                drift: ["unmeasured"],
              });
              continue;
            }

            const rows = parseLsCurrent(ls.stdout);
            const ver = await run(SUB_VERSION);
            const cfg = await run(SUB_CONFIG);
            const outd = await run(SUB_OUTDATED);
            const trust = await run(SUB_TRUST);

            const outdated = outd.ok ? parseOutdated(outd.stdout) : {};
            const configs = cfg.ok ? parseConfigLs(cfg.stdout) : [];
            const trusted = trust.ok ? parseTrustShow(trust.stdout) : {};

            const nodeDrift = new Set<string>();
            for (const r of rows) {
              const expected = g.expect[r.tool];
              const expectFail = expected !== undefined &&
                r.resolvedVersion !== null &&
                !satisfiesExpect(expected, r.resolvedVersion);
              const isOutdated = Object.hasOwn(outdated, r.tool);
              const drift = classifyTool(r, {
                outdated: isOutdated,
                expectFail,
              });
              for (const d of drift) nodeDrift.add(d);
              toolStates.push({
                node: node.name,
                tool: r.tool,
                requestedVersion: r.requestedVersion,
                resolvedVersion: r.resolvedVersion,
                installPath: r.installPath,
                sourceType: r.sourceType,
                sourcePath: r.sourcePath,
                installed: r.installed,
                active: r.active,
                outdated: isOutdated,
                latestVersion: outdated[r.tool] ?? null,
                drift,
              });
            }

            const present = rows.map((r) => r.tool);
            for (const c of configs) {
              const missing = notInEffect(c.tools, present);
              if (missing.length > 0) nodeDrift.add("notineffect");
              configStates.push({
                node: node.name,
                path: c.path,
                // trust --show reports the directory, config ls the file, so
                // a miss here is unknown rather than false.
                trusted: trusted[c.path] ??
                  trusted[c.path.replace(/\/[^/]+$/, "")] ?? null,
                toolsDeclared: c.tools,
                toolsInEffect: c.tools.filter((t) => present.includes(t)),
                toolsNotInEffect: missing,
              });
            }

            nodeStates.push({
              name: node.name,
              measured: true,
              reachable: true,
              transport,
              error: null,
              miseVersion: ver.ok ? ver.stdout.trim().split(" ")[0] : null,
              dir: node.dir ?? null,
              configCount: configs.length,
              toolCount: rows.length,
              drift: [...nodeDrift],
            });
          }
        };
        await Promise.all(
          Array.from(
            { length: Math.min(g.maxConcurrency, targets.length) },
            worker,
          ),
        );

        for (const n of nodeStates) {
          handles.push(
            await ctx.writeResource("node", `node-${n.name}`, n, {
              tags: { measured: String(n.measured), transport: n.transport },
            }),
          );
        }
        for (const t of toolStates) {
          handles.push(
            await ctx.writeResource("tool", `tool-${t.node}-${t.tool}`, t, {
              tags: { node: t.node, tool: t.tool, drift: t.drift.join(",") },
            }),
          );
        }
        for (const c of configStates) {
          handles.push(
            await ctx.writeResource(
              "config",
              `config-${c.node}-${slug(c.path)}`,
              c,
              { tags: { node: c.node } },
            ),
          );
        }

        const count = (d: Drift) =>
          toolStates.filter((t) => t.drift.includes(d)).length;
        handles.push(
          await ctx.writeResource("summary", "summary", {
            nodes: nodeStates.length,
            nodesMeasured: nodeStates.filter((n) => n.measured).length,
            nodesUnmeasured: nodeStates.filter((n) => !n.measured).length,
            tools: toolStates.length,
            notinstalled: count("notinstalled"),
            notactive: count("notactive"),
            notineffect: configStates.filter((c) =>
              c.toolsNotInEffect.length > 0
            ).length,
            outdated: count("outdated"),
            expected: count("expected"),
            sweptAt: new Date().toISOString(),
          }, { tags: { nodes: String(nodeStates.length) } }),
        );

        return { dataHandles: handles };
      },
    },
  },
```

- [ ] **Step 5: Add the slug helper**

Add above the `model` export, copying `dashboard`'s collision-safe scheme so two config paths that normalise alike still get separate resource names:

```ts
/** Deterministic 32-bit FNV-1a, eight lowercase hex characters. */
function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

/**
 * Resource-name fragment for a config path. The hash is taken over the raw
 * path, so two paths that normalise to the same slug still land on different
 * resources instead of overwriting each other.
 */
function slug(path: string): string {
  const s = path.replace(/[^a-zA-Z0-9]+/g, "-").toLowerCase().replace(
    /^-+|-+$/g,
    "",
  );
  return `${s || "config"}-${fnv1a(path)}`;
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/`
Expected: PASS, 34 tests.

- [ ] **Step 7: Format and commit**

```bash
deno fmt mise/
git add mise/
git commit -m "mise: the discover sweep, its resources, and the fleet summary"
```

---

### Task 7: README vars, generated README, and the local gate run

**Files:**
- Create: `mise/readme.vars.yaml`
- Generate: `mise/README.md`
- Modify: `README.md` (the root table is stamped by the generator)

**Interfaces:**
- Consumes: the finished `mise/mise.ts` and `mise/manifest.yaml`.
- Produces: a committed, drift-free README.

- [ ] **Step 1: Write `mise/readme.vars.yaml`**

```yaml
# Hand-written inputs for scripts/gen-readme.ts. Everything else in README.md
# comes from the code. Placeholders only, never a real host, path, or vault item.
package: "@jpisgeek/mise"
purpose: >-
  Toolchain state across a fleet, as measured rather than as assumed. Records
  which tool versions each host is actually running and where that parts ways
  with the host's own config: asked for but never installed, installed but not
  active, declared in a config that never took, or simply behind. Installs
  nothing and upgrades nothing. mise already does that job. This one wades
  through the fleet, writes down what it finds, and leaves the acting to
  whatever workflow wants it.
example: |
  globalArguments:
    nodes:
      - name: workstation
        dir: /srv/project
      - name: builder
        dir: /srv/project
        ssh:
          host: builder.example.com
          user: toolchain-reader
          port: 22
        # A non-login shell usually has no ~/.local/bin on PATH, and that is
        # exactly where mise tends to live.
        misePath: /usr/local/bin/mise
    timeoutSec: 15
    maxConcurrency: 8
    expect:
      node: "22"
      python: "3.12"
caveats: >-
  A host that does not answer is recorded as unmeasured, and its counts stay
  null rather than dropping to zero. This matters more than it sounds: mise is
  routinely missing from a non-login shell's PATH, and a zero tool count from a
  host that never ran mise is indistinguishable from a host that is genuinely
  clean. Set `misePath` when a host reports unmeasured with a not-found error.
  mise config is directory-scoped, so `dir` decides which config is being
  judged. Leave it off and you measure the swamp working directory locally and
  the login directory over SSH, which is rarely the question you meant to ask.
  Trust is recorded but never treated as drift. A plain `[tools]` file reports
  as untrusted while applying perfectly, because mise only demands trust for
  configs that can execute something. Config resource names carry a hash
  suffix, so find them with `swamp data list <model>` rather than building the
  name by hand.
security: >-
  Read-only throughout. The model runs `ls --current`, `config ls`, `outdated`,
  `trust --show`, and `--version`, and nothing else. It never calls
  `mise install`, `mise upgrade`, `mise token`, `mise settings`, or `mise
  trust` without `--show`, so it cannot change a host or surface a credential.
  Local hosts are invoked as an argv array that never reaches a shell. Over
  SSH, `dir` is the only operator value interpolated into the remote command,
  it is single-quoted, and the schema refuses any value containing a quote, a
  space, a `..` segment, or a leading dash rather than repairing it: a
  half-fixed path that measures the wrong directory silently is worse than a
  config error. `misePath`, `ssh.host`, and `ssh.user` are refused on the same
  grounds, so none can be read as an ssh option such as `-oProxyCommand=`. SSH
  uses `BatchMode=yes`, so an unknown host key fails closed instead of
  prompting. Errors quote stderr only, never stdout, because stdout carries
  config contents and error strings reach swamp run logs. Written data: host
  labels, the measured directory, mise version, tool names and versions,
  install paths, and config file paths. Install and config paths embed the
  remote account's home directory and real project directory names, so treat
  the datastore as infrastructure detail.
```

- [ ] **Step 2: Generate the README and the root table**

```bash
scripts/gen-readme.ts mise
```

- [ ] **Step 3: Verify no drift**

Run: `scripts/gen-readme.ts --check`
Expected: exit 0, no output about differing READMEs.

- [ ] **Step 4: Run format, tests, and the identifier scan**

```bash
deno fmt mise/ scripts/
deno fmt --check mise/ scripts/
deno test --allow-read --allow-write --allow-env --allow-net --allow-run mise/
scripts/scan-identifiers.sh mise/
```
Expected: fmt clean, 34 tests pass, scan reports 0 hits.

- [ ] **Step 5: Commit**

```bash
git add mise/ README.md
git commit -m "mise: readme vars, generated README, and the root table entry"
```

---

### Task 8: The publish gate run

Nothing new is written here. This runs the release sequence and stops for approval, which is the one human step.

**Files:** none modified by hand. `reviews/mise/<hash>.md` is produced by gate 6.

- [ ] **Step 1: Export the private denylist**

Gate 5 falls back to generic rules and warns without it.

```bash
export SLOG_BOG_DENYLIST=<path to the private denylist, outside this repo>
```

- [ ] **Step 2: Run gates 1 through 6 and stop**

```bash
scripts/publish.sh mise --review-only
```
Expected: gates 1 to 5 pass, then the Fable security review writes `reviews/mise/<hash>.md`. The verdict line must read PASS.

- [ ] **Step 3: Read the verdict before going further**

```bash
cat reviews/mise/*.md
```
If the verdict is not PASS, or it carries `fix`-severity findings, stop and fix them. A fix changes the content hash, so the review must run again afterwards. Do not carry `fix` findings into a publish. `dashboard` is the standing example: it holds a PASS with four unresolved `fix` findings and has been kept back from the registry because of them.

- [ ] **Step 4: Commit the verdict**

```bash
bash scripts/check-review-verdicts.sh
git add reviews/mise/
git commit -m "mise: Fable security gate PASS for 2026.08.24.1"
```

- [ ] **Step 5: Run the full sequence and stop at gate 8**

```bash
scripts/publish.sh mise
```
Expected: gates 1 to 7 pass, including `swamp extension push --dry-run`, then the run halts at gate 8 for operator approval. **Stop here and hand back to Jason.** Publishing is his call, not the implementer's.

---

## Self-Review

**Spec coverage.** Every section of `docs/design/2026-08-24-mise-extension.md` maps to a task: verified command surface to Tasks 3 and 5, trust-is-not-the-signal to Task 5 (`parseTrustShow` recorded, `notInEffect` as the trigger) and Task 6 (`trusted` field, never drift), configuration to Task 1, expect semantics to Task 2, the six drift classes to Tasks 2, 5, and 6, unmeasured to Task 4 and Task 6, resources to Task 6, transport and injection to Tasks 1 and 3, data written to Task 7's `security` block, voice to Global Constraints, testing distributed across all tasks, gates to Task 8.

**Placeholder scan.** No TBD, TODO, or "similar to Task N". Every code step carries the actual code. The one deliberately unfilled value is `SLOG_BOG_DENYLIST` in Task 8 Step 1, which is a path held outside the repo and known only to the operator.

**Type consistency.** `Drift` is defined once in Task 2 and used unchanged in Tasks 5 and 6. `ToolRow` (Task 5) feeds `ToolStateSchema` (Task 6) field for field, with `node` added at write time. `RunResult` (Task 4) is consumed only through its `ok` discriminant. `ParsedNode` is `z.infer<typeof NodeSchema>` throughout. `classifyTool` takes `ToolEntry`, and `ToolRow` structurally satisfies it, which is why Task 6 passes `r` directly.

**One known rough edge, left deliberate.** In Task 6, `reachable` is written as `false` for every unmeasured host regardless of `kind`. A host that answered SSH but lacks mise is reachable in the ordinary sense, yet it is recorded unreachable. Rather than encode a distinction the resource schema cannot express, `kind` is preserved in `error` and `measured` carries the real signal. If the Fable review flags it, the fix is a `reason` field on the node resource rather than a change to `reachable`.
