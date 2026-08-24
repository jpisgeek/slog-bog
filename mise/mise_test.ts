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
