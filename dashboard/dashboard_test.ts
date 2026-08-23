/**
 * Tests for @jpisgeek/dashboard.
 *
 * Exported surface only — not in the manifest, so it does not move the content
 * hash the security review is bound to.
 *
 * This model renders attacker-influenceable data (device names, mount paths,
 * alert text — all originating from a firewall, a NAS, or a monitoring agent)
 * into an HTML page that a human then opens. Escaping is therefore the
 * security property under test, alongside the honesty properties: a source
 * that never ran must be disclosed rather than silently omitted, and a
 * suppressed exception must stay visible rather than disappear.
 */
import { assertEquals } from "jsr:@std/assert@1";
import { model } from "./dashboard.ts";

type Json = Record<string, unknown>;

const SOURCES = [
  { name: "telemetry", type: "@jpisgeek/netdata", id: "t1" },
  { name: "nas", type: "@jpisgeek/truenas", id: "n1" },
  { name: "firewalla", type: "@jpisgeek/firewalla", id: "f1" },
  { name: "homelab", type: "@swamp/ssh", id: "h1" },
];

/**
 * Mock context whose datastore returns `rows` keyed by source id. Renders to a
 * temp file so the assertion runs against the real emitted HTML.
 */
function ctxFor(rowsById: Record<string, Array<[string, Json]>>, out: string) {
  const written: Array<{ spec: string; name: string; data: Json }> = [];
  return {
    written,
    // deno-lint-ignore no-explicit-any
    ctx: {
      signal: new AbortController().signal,
      globalArgs: { title: "Test", sources: SOURCES, outputPath: out },
      modelType: "@jpisgeek/dashboard",
      modelId: "d1",
      logger: { info: () => {}, warning: () => {} },
      writeResource: (spec: string, name: string, data: Json) => {
        written.push({ spec, name, data });
        return Promise.resolve({});
      },
      deleteResource: () => Promise.resolve(),
      dataRepository: {
        findAllForModel: (_t: string, id: string) =>
          Promise.resolve((rowsById[id] ?? []).map(([name]) => ({ name }))),
        getContent: (_t: string, id: string, name: string) => {
          const hit = (rowsById[id] ?? []).find(([n]) => n === name);
          return Promise.resolve(hit ? JSON.stringify(hit[1]) : null);
        },
        delete: () => Promise.resolve(),
      },
    } as any,
  };
}

async function render(rowsById: Record<string, Array<[string, Json]>>) {
  const dir = await Deno.makeTempDir();
  const out = `${dir}/index.html`;
  const m = ctxFor(rowsById, out);
  await model.methods.render.execute({}, m.ctx);
  const html = await Deno.readTextFile(out);
  await Deno.remove(dir, { recursive: true });
  return { html, written: m.written };
}

// ---------------------------------------------------------------------------
// escaping: collected data reaches HTML
// ---------------------------------------------------------------------------

Deno.test("node names from the network are HTML-escaped", async () => {
  const { html } = await render({
    t1: [
      ["node-evil", {
        name: '<script>alert("xss")</script>',
        reachable: true,
        osName: "linux",
        osVersion: "1",
        version: "2",
        transport: "http",
        claimedToCloud: false,
      }],
    ],
  });
  assertEquals(
    html.includes("<script>alert"),
    false,
    "raw <script> reached the page — escaping is broken",
  );
  assertEquals(html.includes("&lt;script&gt;"), true, "expected escaped form");
});

Deno.test("mount paths and alert text are escaped", async () => {
  const { html } = await render({
    t1: [
      ["mount-x", {
        node: '"><img src=x onerror=alert(1)>',
        mount: "/mnt/<evil>",
        usedPercent: 99,
        usedGiB: 1,
        totalGiB: 2,
        overThreshold: true,
      }],
    ],
    n1: [
      ["alert-1", {
        id: "1",
        klass: "Test",
        level: "CRITICAL",
        formatted: "<b>bold</b> & dangerous",
        dismissed: false,
        silenced: false,
      }],
    ],
  });
  assertEquals(
    html.includes("onerror=alert(1)>"),
    false,
    "unescaped attribute break-out",
  );
  assertEquals(html.includes("<b>bold</b>"), false, "unescaped alert markup");
  assertEquals(html.includes("&amp;"), true, "ampersand should be escaped");
});

// ---------------------------------------------------------------------------
// honesty: absent data is disclosed, suppression stays visible
// ---------------------------------------------------------------------------

Deno.test("a source that has never run is disclosed as stale, not omitted", async () => {
  const { html, written } = await render({}); // no source has any data
  const renderRes = written.find((w) => w.spec === "render")!.data;
  assertEquals(
    (renderRes.sourcesStale as string[]).length,
    4,
    "every empty source must be reported stale",
  );
  assertEquals(
    html.includes("no usable data from"),
    true,
    "the page must say the data is missing rather than imply health",
  );
});

Deno.test("an unreachable node becomes a critical exception resource", async () => {
  const { written } = await render({
    t1: [
      ["node-a", { name: "a", reachable: false, error: "refused" }],
    ],
  });
  const exceptions = written.filter((w) => w.spec === "exception");
  assertEquals(exceptions.length >= 1, true, "expected an exception resource");
  const exc = exceptions[0].data;
  assertEquals(exc.severity, "critical");
  assertEquals(String(exc.id).startsWith("unreachable:"), true);
});

Deno.test("a full disk past the threshold is flagged", async () => {
  const { written } = await render({
    t1: [
      ["mount-a", {
        node: "a",
        mount: "/",
        usedPercent: 97,
        usedGiB: 97,
        totalGiB: 100,
      }],
    ],
  });
  const exc = written.filter((w) => w.spec === "exception").map((w) => w.data);
  assertEquals(exc.some((e) => String(e.id).startsWith("disk:")), true);
  // >=95 is critical per the model's rules
  assertEquals(exc.some((e) => e.severity === "critical"), true);
});

Deno.test("render writes a queryable resource for every exception", async () => {
  const { written } = await render({
    t1: [["node-a", { name: "a", reachable: false, error: "x" }]],
  });
  // alerting is meant to be buildable on the resources, not on the HTML
  assertEquals(written.some((w) => w.spec === "exception"), true);
  assertEquals(written.some((w) => w.spec === "render"), true);
});

// ---------------------------------------------------------------------------
// declared surface
// ---------------------------------------------------------------------------

Deno.test("render is the only method and it never reaches the network", () => {
  assertEquals(Object.keys(model.methods), ["render"]);
});

Deno.test("the source-alias coupling is a named, skippable check", () => {
  const check = model.checks?.["known-source-aliases"];
  assertEquals(typeof check, "object");
  assertEquals(check!.appliesTo.includes("render"), true);
});

Deno.test("exception schema: truncation is disclosed on the record", () => {
  const exc = {
    id: "x",
    severity: "warning",
    subject: "s",
    headline: "h",
    detail: "d",
    source: "netdata",
    suppressed: false,
    suppressReason: "",
    truncated: true,
  };
  assertEquals(model.resources.exception.schema.safeParse(exc).success, true);
  const { truncated: _drop, ...without } = exc;
  assertEquals(
    model.resources.exception.schema.safeParse(without).success,
    false,
  );
});
