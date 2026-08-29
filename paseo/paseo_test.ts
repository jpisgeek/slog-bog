import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import {
  agentDeleteArgs,
  agentLsArgs,
  agentRunArgs,
  agentSendArgs,
  assertConfirmed,
  assertPositional,
  coerceList,
  GlobalArgsSchema,
  hostArgs,
  pairFlags,
  parseHostTarget,
  parseJson,
  permitAllowArgs,
  pick,
  redactHost,
  scheduleDeleteArgs,
  terminalCreateArgs,
  terminalKillArgs,
  terminalSendKeysArgs,
} from "./paseo.ts";

// --- the password fence ----------------------------------------------------

Deno.test("a host carrying a password is refused, in any casing", () => {
  for (
    const bad of [
      "tcp://box:6767?ssl=true&password=hunter2",
      "box:6767?PASSWORD=x",
      "box:6767?PaSsWoRd=x",
    ]
  ) {
    assertThrows(() => parseHostTarget(bad), Error, "password");
  }
});

Deno.test("a host carrying userinfo or a scheme is refused", () => {
  assertThrows(() => parseHostTarget("user@box:6767"), Error, "userinfo");
  assertThrows(() => parseHostTarget("tcp://box:6767"), Error, "scheme");
});

Deno.test("host accepts a plain address and an address:port", () => {
  assertEquals(parseHostTarget("localhost"), "localhost");
  assertEquals(parseHostTarget("localhost:6768"), "localhost:6768");
  assertEquals(parseHostTarget("192.0.2.10:6767"), "192.0.2.10:6767");
});

Deno.test("host refuses shell-meaningful and space-bearing values", () => {
  for (
    const bad of ["box;rm -rf /", "box 6767", "box|nc", "-box", "box/../x"]
  ) {
    assertThrows(() => parseHostTarget(bad), Error);
  }
});

Deno.test("hostArgs omits --host entirely when no host is set", () => {
  assertEquals(hostArgs(undefined), []);
  assertEquals(hostArgs(""), []);
});

Deno.test("hostArgs passes a bare address through unchanged", () => {
  assertEquals(hostArgs("box:6767"), ["--host", "box:6767"]);
});

Deno.test("a password becomes a tcp:// URL and is percent-encoded", () => {
  const [flag, url] = hostArgs("box:6767", "p@ss word&x");
  assertEquals(flag, "--host");
  assertEquals(url.startsWith("tcp://box:6767?ssl=true&password="), true);
  // The raw secret must not survive verbatim -- an unencoded '&' would end the
  // parameter and silently truncate the password to something that still
  // "works" as a string but is not the password.
  assertEquals(url.includes("p@ss word&x"), false);
  assertEquals(url.includes("p%40ss%20word%26x"), true);
});

Deno.test("a password defaults to port 6767 when the address omits one", () => {
  const [, url] = hostArgs("box", "s3cret");
  assertEquals(url.startsWith("tcp://box:6767?ssl=true&password="), true);
});

Deno.test("redactHost never returns a query string", () => {
  assertEquals(redactHost(undefined), "local");
  assertEquals(redactHost("box:6767"), "box:6767");
  assertEquals(
    redactHost("tcp://box:6767?ssl=true&password=hunter2"),
    "box:6767",
  );
});

// --- leading-dash screening ------------------------------------------------

Deno.test("a leading dash is refused wherever a value becomes an operand", () => {
  assertThrows(() => assertPositional("--all", "agent id"), Error, "'-'");
  assertThrows(() => agentSendArgs("--all", "hi"), Error);
  assertThrows(() => agentRunArgs({ prompt: "--help" }), Error);
  assertThrows(() => terminalSendKeysArgs("t1", ["--version"]), Error);
  assertThrows(() => permitAllowArgs("-x"), Error);
});

Deno.test("an empty operand is refused rather than silently dropped", () => {
  assertThrows(() => assertPositional("", "agent id"), Error, "empty");
});

// --- destructive guards ----------------------------------------------------

Deno.test("destructive methods require the id twice, compared exactly", () => {
  assertEquals(agentDeleteArgs("ag_1", "ag_1"), [
    "agent",
    "delete",
    "ag_1",
    "--json",
  ]);
  assertThrows(() => agentDeleteArgs("ag_1", "ag_2"), Error, "confirm");
  assertThrows(() => scheduleDeleteArgs("s1", "s2"), Error, "confirm");
  assertThrows(() => terminalKillArgs("t1", "t2"), Error, "confirm");
});

Deno.test("confirmation does not fold case or trim whitespace", () => {
  // Both are a caller that built the two values by different routes, which is
  // the mistake the guard exists to catch rather than to paper over.
  assertThrows(() => assertConfirmed("Ag_1", "ag_1", "delete agent"), Error);
  assertThrows(() => assertConfirmed("ag_1", " ag_1", "delete agent"), Error);
  assertEquals(assertConfirmed("ag_1", "ag_1", "delete agent"), "ag_1");
});

// --- argv construction -----------------------------------------------------

Deno.test("agent run omits every flag it was not given", () => {
  assertEquals(agentRunArgs({ prompt: "do the thing" }), [
    "agent",
    "run",
    "--json",
    "do the thing",
  ]);
});

Deno.test("agent run carries provider, model and mode through in order", () => {
  const args = agentRunArgs({
    prompt: "review",
    provider: "anthropic",
    model: "claude-opus-5",
    mode: "plan",
    background: true,
  });
  assertEquals(args.slice(0, 2), ["agent", "run"]);
  assertEquals(args.includes("--background"), true);
  assertEquals(args[args.length - 1], "review");
  for (
    const [f, v] of [
      ["--provider", "anthropic"],
      ["--model", "claude-opus-5"],
      ["--mode", "plan"],
    ]
  ) {
    assertEquals(args[args.indexOf(f) + 1], v);
  }
});

Deno.test("env and label pairs are sorted, so argv is stable across runs", () => {
  assertEquals(pairFlags("--env", { B: "2", A: "1" }), [
    "--env",
    "A=1",
    "--env",
    "B=2",
  ]);
  assertEquals(pairFlags("--label", undefined), []);
});

Deno.test("a pair key containing '=' is refused, not concatenated", () => {
  // "a=b": "c" would render as --env a=b=c, which the CLI reads as key "a"
  // with value "b=c" -- a silently different variable than the caller named.
  assertThrows(() => pairFlags("--env", { "a=b": "c" }), Error, "'='");
});

Deno.test("send-keys keeps each key a separate operand", () => {
  assertEquals(terminalSendKeysArgs("t1", ["echo hi", "Enter"]), [
    "terminal",
    "send-keys",
    "t1",
    "echo hi",
    "Enter",
  ]);
  assertThrows(() => terminalSendKeysArgs("t1", []), Error, "at least one");
});

Deno.test("terminal create omits absent options", () => {
  assertEquals(terminalCreateArgs(), ["terminal", "create", "--json"]);
  assertEquals(terminalCreateArgs({ name: "build" }), [
    "terminal",
    "create",
    "--name",
    "build",
    "--json",
  ]);
});

Deno.test("agent ls flags are additive and always ask for json", () => {
  assertEquals(agentLsArgs(), ["agent", "ls", "--json"]);
  assertEquals(agentLsArgs({ all: true, global: true }), [
    "agent",
    "ls",
    "--all",
    "--global",
    "--json",
  ]);
});

Deno.test("permit allow makes the request id genuinely optional", () => {
  assertEquals(permitAllowArgs("ag_1"), ["permit", "allow", "ag_1", "--json"]);
  assertEquals(permitAllowArgs("ag_1", "rq_2"), [
    "permit",
    "allow",
    "ag_1",
    "rq_2",
    "--json",
  ]);
});

// --- output handling -------------------------------------------------------

Deno.test("a non-zero exit reports the first stderr line, bounded", () => {
  assertThrows(
    () =>
      parseJson(
        { ok: false, code: 2, stdout: "", stderr: "no such agent\ntrace..." },
        "agent inspect",
      ),
    Error,
    "no such agent",
  );
});

Deno.test("exit 0 with non-JSON is an error, not an empty reading", () => {
  // A login banner printed over the answer must not read as "nothing there".
  assertThrows(
    () =>
      parseJson(
        { ok: true, code: 0, stdout: "Welcome!\n{}", stderr: "" },
        "agent ls",
      ),
    Error,
    "did not return JSON",
  );
});

Deno.test("exit 0 with empty stdout is null, which is a valid empty answer", () => {
  assertEquals(
    parseJson({ ok: true, code: 0, stdout: "  ", stderr: "" }, "x"),
    null,
  );
});

Deno.test("coerceList handles both the bare array and the wrapped forms", () => {
  assertEquals(coerceList([{ id: "a" }], "agents"), [{ id: "a" }]);
  assertEquals(coerceList({ agents: [{ id: "b" }] }, "agents"), [{ id: "b" }]);
  assertEquals(coerceList({ other: 1 }, "agents"), []);
  assertEquals(coerceList(null, "agents"), []);
});

Deno.test("pick takes the first present key and stringifies numbers", () => {
  assertEquals(pick({ id: "x" }, "agentId", "id"), "x");
  assertEquals(pick({ agentId: 7 }, "agentId", "id"), "7");
  assertEquals(pick({ id: "" }, "id"), null);
  assertEquals(pick({}, "id"), null);
});

// --- global arguments ------------------------------------------------------

Deno.test("binary must be named paseo, not merely charset-clean", () => {
  assertEquals(GlobalArgsSchema.parse({}).binary, "paseo");
  assertEquals(
    GlobalArgsSchema.parse({ binary: "/opt/homebrew/bin/paseo" }).binary,
    "/opt/homebrew/bin/paseo",
  );
  // Charset-legal but not paseo: the guarantee this model advertises is that
  // it runs paseo, and a charset rule alone would not keep it.
  assertThrows(() => GlobalArgsSchema.parse({ binary: "/tmp/curl" }));
  assertThrows(() => GlobalArgsSchema.parse({ binary: "-paseo" }));
  assertThrows(() => GlobalArgsSchema.parse({ binary: "pas eo" }));
});

Deno.test("timeoutSec has a default and a ceiling", () => {
  assertEquals(GlobalArgsSchema.parse({}).timeoutSec, 120);
  assertThrows(() => GlobalArgsSchema.parse({ timeoutSec: 0 }));
  assertThrows(() => GlobalArgsSchema.parse({ timeoutSec: 99999 }));
});
