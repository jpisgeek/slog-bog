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
import { classifyTool, GlobalArgsSchema, satisfiesExpect } from "./mise.ts";

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
