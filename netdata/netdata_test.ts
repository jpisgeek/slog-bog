/**
 * Tests for @jpisgeek/netdata.
 *
 * Written against the EXPORTED surface only (`model.globalArguments`,
 * `model.resources.*.schema`, `model.methods.*.execute`) — never module
 * internals. Two reasons: behaviour is what consumers depend on, and this file
 * is not listed in the manifest, so tests can be added or changed without
 * moving the extension's content hash (which is what the published security
 * review is bound to).
 *
 * Every case here corresponds to a real defect found in review. They are
 * regression locks, not coverage decoration:
 *   - a failed sub-fetch must never roll up as "healthy"
 *   - caller cancellation must not be recorded as a fleet of unreachable nodes
 *   - `url` must not accept file:/ftp:/userinfo (SSRF + credential leak)
 *   - a mount whose dimensions can't be resolved must not read as 0% used
 *   - stored `error` must not carry ssh user@host, ssh stderr, or an HTTP body
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./netdata.ts";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type Json = Record<string, unknown>;

/** A recording stand-in for the swamp model context. */
function mockCtx(globalArgs: Json, opts: {
  stored?: Record<string, Json>;
  signal?: AbortSignal;
} = {}) {
  const written: Array<{ spec: string; name: string; data: Json }> = [];
  const deleted: string[] = [];
  const warnings: string[] = [];
  const stored = opts.stored ?? {};
  return {
    written,
    deleted,
    warnings,
    ctx: {
      signal: opts.signal ?? new AbortController().signal,
      globalArgs,
      modelType: "@jpisgeek/netdata",
      modelId: "test-model",
      logger: {
        info: () => {},
        warning: (msg: string) => warnings.push(msg),
      },
      readResource: (name: string) => Promise.resolve(stored[name] ?? null),
      // deno-lint-ignore no-explicit-any
      writeResource: (spec: string, name: string, data: Json, _o?: any) => {
        written.push({ spec, name, data });
        return Promise.resolve({ spec, name });
      },
      deleteResource: (name: string) => {
        deleted.push(name);
        return Promise.resolve();
      },
      dataRepository: {
        findAllForModel: () =>
          Promise.resolve(Object.keys(stored).map((name) => ({ name }))),
        delete: (_t: string, _i: string, name: string) => {
          deleted.push(name);
          return Promise.resolve();
        },
      },
    },
  };
}

/** Route stubbed HTTP by URL substring. Returns a restore function. */
function stubFetch(
  routes: Array<[string, () => Response | Promise<Response>]>,
) {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request) => {
    const url = String(input instanceof Request ? input.url : input);
    for (const [needle, respond] of routes) {
      if (url.includes(needle)) return Promise.resolve(respond());
    }
    return Promise.reject(new Error(`unstubbed URL: ${url}`));
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

const NODE = (over: Json = {}) => ({
  name: "nodeA",
  url: "http://agent.example.com:19999",
  ...over,
});

// ---------------------------------------------------------------------------
// 1. url validation — SSRF / credential-leak surface
// ---------------------------------------------------------------------------

Deno.test("url: accepts http and https", () => {
  for (const url of ["http://a.example.com:19999", "https://a.example.com"]) {
    const r = model.globalArguments.safeParse({ nodes: [NODE({ url })] });
    assertEquals(r.success, true, `expected ${url} to be accepted`);
  }
});

Deno.test("url: rejects non-http(s) schemes (file/ftp/dict/data)", () => {
  for (
    const url of [
      "file:///etc/passwd",
      "ftp://a.example.com/x",
      "dict://a.example.com:2628/",
      "data:text/plain,hi",
    ]
  ) {
    const r = model.globalArguments.safeParse({ nodes: [NODE({ url })] });
    assertEquals(r.success, false, `expected ${url} to be REJECTED`);
  }
});

Deno.test("url: rejects embedded credentials", () => {
  const r = model.globalArguments.safeParse({
    nodes: [NODE({ url: "http://user:pass@a.example.com:19999" })],
  });
  assertEquals(r.success, false);
});

Deno.test("url: rejects a single quote (ssh remote-command quoting)", () => {
  const r = model.globalArguments.safeParse({
    nodes: [NODE({ url: "http://a.example.com:19999/'" })],
  });
  assertEquals(r.success, false);
});

Deno.test("ssh: rejects host/user beginning with '-' (argv injection)", () => {
  for (
    const ssh of [
      { host: "-oProxyCommand=touch /tmp/pwn", user: "ok" },
      { host: "ok.example.com", user: "-oProxyCommand=x" },
    ]
  ) {
    const r = model.globalArguments.safeParse({ nodes: [NODE({ ssh })] });
    assertEquals(r.success, false, `expected ${JSON.stringify(ssh)} rejected`);
  }
});

// ---------------------------------------------------------------------------
// 2. summary must not disguise a failed sub-fetch as health
// ---------------------------------------------------------------------------

Deno.test("summary: a failed /alarms fetch does not read as 0 alarms", async () => {
  // /info answers; /alarms 500s; the node previously recorded 3 alarms (1 crit).
  const restore = stubFetch([
    ["/api/v1/alarms", () => json({ error: "boom" }, 500)],
    ["/api/v1/charts", () => json({ charts: {} })],
    [
      "/api/v1/info",
      () => json({ version: "2.1", hostname: "h", cores_total: 4 }),
    ],
  ]);
  try {
    const prior = {
      "node-nodea": {
        name: "nodeA",
        alarmsActive: 3,
        alarmsCritical: 1,
        alarmsWarning: 2,
        charts: 10,
        mountsOverThreshold: 1,
        version: "2.1",
        hostname: "h",
        osName: "linux",
        osVersion: "1",
        cores: 4,
        collectors: 2,
        claimedToCloud: false,
      } as Json,
    };
    const m = mockCtx({ nodes: [NODE()] }, { stored: prior });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);

    const summary = m.written.find((w) => w.spec === "summary")!.data;
    assertEquals(
      summary.alarmsActive,
      3,
      "carried-forward alarms must appear in the roll-up, not 0",
    );
    assertEquals(summary.alarmsCritical, 1);
    assertEquals(
      summary.nodesDegraded,
      1,
      "a reachable node with a failed sub-fetch is degraded",
    );
    assertEquals(summary.nodesReachable, 1);
  } finally {
    restore();
  }
});

Deno.test("summary: a fully healthy sweep reports zero degraded", async () => {
  const restore = stubFetch([
    ["/api/v1/alarms", () => json({ alarms: {} })],
    ["/api/v1/charts", () => json({ charts: {} })],
    ["/api/v1/info", () => json({ version: "2.1", hostname: "h" })],
  ]);
  try {
    const m = mockCtx({ nodes: [NODE()] });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);
    const summary = m.written.find((w) => w.spec === "summary")!.data;
    assertEquals(summary.nodesDegraded, 0);
    assertEquals(summary.alarmsActive, 0);
    assertEquals(summary.nodesUnreachable, 0);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// 3. unreachable is data; cancellation is not
// ---------------------------------------------------------------------------

Deno.test("unreachable node is recorded, not thrown", async () => {
  const restore = stubFetch([
    ["/api/v1/info", () => {
      throw new Error("connection refused");
    }],
  ]);
  try {
    const m = mockCtx({ nodes: [NODE()] });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);
    const node = m.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.reachable, false);
    const summary = m.written.find((w) => w.spec === "summary")!.data;
    assertEquals(summary.nodesUnreachable, 1);
  } finally {
    restore();
  }
});

Deno.test("caller cancellation throws and writes nothing", async () => {
  const ac = new AbortController();
  const restore = stubFetch([
    ["/api/v1/info", () => {
      ac.abort();
      throw new DOMException("aborted", "AbortError");
    }],
  ]);
  try {
    const m = mockCtx({ nodes: [NODE()] }, { signal: ac.signal });
    let threw = false;
    try {
      // deno-lint-ignore no-explicit-any
      await model.methods.discover.execute({}, m.ctx as any);
    } catch {
      threw = true;
    }
    assertEquals(threw, true, "cancellation must propagate");
    assertEquals(
      m.written.length,
      0,
      "a cancelled sweep must not persist a fleet of false 'unreachable' rows",
    );
    assertEquals(m.deleted.length, 0, "a cancelled sweep must not prune");
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// 4. mounts: unresolvable dimensions are a failure, not 0% used
// ---------------------------------------------------------------------------

Deno.test("mount: missing avail/used labels are not written as 0% used", async () => {
  const restore = stubFetch([
    ["/api/v1/alarms", () => json({ alarms: {} })],
    ["/api/v1/charts", () => json({ charts: { "disk_space./": {} } })],
    // labels do NOT include avail/used — a renamed/reordered dimension
    ["/api/v1/data", () => json({ labels: ["time", "other"], data: [[1, 2]] })],
    ["/api/v1/info", () => json({ version: "2.1", hostname: "h" })],
  ]);
  try {
    const m = mockCtx({ nodes: [NODE()] });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);
    const mounts = m.written.filter((w) => w.spec === "mount");
    assertEquals(
      mounts.length,
      0,
      "an unresolvable mount must not be written as a healthy 0% filesystem",
    );
  } finally {
    restore();
  }
});

Deno.test("mount: resolvable dimensions produce a correct usedPercent", async () => {
  const restore = stubFetch([
    ["/api/v1/alarms", () => json({ alarms: {} })],
    ["/api/v1/charts", () => json({ charts: { "disk_space./": {} } })],
    [
      "/api/v1/data",
      () => json({ labels: ["avail", "used"], data: [[25, 75]] }),
    ],
    ["/api/v1/info", () => json({ version: "2.1", hostname: "h" })],
  ]);
  try {
    const m = mockCtx({ nodes: [NODE()], diskWarnPercent: 85 });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);
    const mount = m.written.find((w) => w.spec === "mount")!.data;
    assertEquals(mount.usedPercent, 75);
    assertEquals(mount.overThreshold, false);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// 5. stored error must not carry transport detail
// ---------------------------------------------------------------------------

Deno.test("stored error omits ssh user@host and stderr", async () => {
  const restore = stubFetch([]);
  try {
    // An ssh node whose remote command fails: the thrown message contains
    // user@host plus stderr; the STORED error must not.
    const m = mockCtx({
      nodes: [
        NODE({
          url: "http://127.0.0.1:19999",
          ssh: { host: "box.example.com", user: "netdata-reader", port: 22 },
        }),
      ],
      timeoutSec: 1,
    });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);
    const node = m.written.find((w) => w.spec === "node")!.data;
    const err = String(node.error ?? "");
    assertEquals(
      err.includes("netdata-reader"),
      false,
      `stored error leaked the ssh user: ${err}`,
    );
    assertEquals(
      err.includes("@"),
      false,
      `stored error leaked an ssh target: ${err}`,
    );
    assertEquals(
      /\.ssh\/|Permissions \d|id_ed25519/.test(err),
      false,
      `stored error leaked ssh stderr: ${err}`,
    );
  } finally {
    restore();
  }
});

Deno.test("stored error omits the HTTP response body", async () => {
  const restore = stubFetch([
    [
      "/api/v1/info",
      () =>
        new Response("SECRET-BODY-CONTENT-should-not-persist", { status: 500 }),
    ],
  ]);
  try {
    const m = mockCtx({ nodes: [NODE()] });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);
    const node = m.written.find((w) => w.spec === "node")!.data;
    const err = String(node.error ?? "");
    assertEquals(
      err.includes("SECRET-BODY-CONTENT"),
      false,
      `stored error leaked the response body: ${err}`,
    );
    assertEquals(err.includes("HTTP 500"), true, `expected a class: ${err}`);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// 6. schema contracts consumers rely on
// ---------------------------------------------------------------------------

Deno.test("summary schema requires nodesDegraded", () => {
  const without = {
    nodes: 1,
    nodesReachable: 1,
    nodesUnreachable: 0,
    alarmsActive: 0,
    alarmsCritical: 0,
    mountsOverThreshold: 0,
    syncedAt: new Date(0).toISOString(),
  };
  assertEquals(
    model.resources.summary.schema.safeParse(without).success,
    false,
  );
  assertEquals(
    model.resources.summary.schema.safeParse({ ...without, nodesDegraded: 0 })
      .success,
    true,
  );
});

Deno.test("node schema keeps identity nullable (unknown != empty string)", () => {
  const base = {
    name: "n",
    url: "http://a.example.com:19999",
    reachable: false,
    error: "",
    transport: "http",
    version: null,
    hostname: null,
    osName: null,
    osVersion: null,
    cores: 0,
    collectors: 0,
    charts: 0,
    alarmsActive: 0,
    alarmsCritical: 0,
    alarmsWarning: 0,
    claimedToCloud: false,
    mountsOverThreshold: 0,
  };
  assertEquals(model.resources.node.schema.safeParse(base).success, true);
});

Deno.test("discover rejects an unknown --input node", async () => {
  const m = mockCtx({ nodes: [NODE()] });
  await assertRejects(
    // deno-lint-ignore no-explicit-any
    () => model.methods.discover.execute({ node: "nope" }, m.ctx as any),
    Error,
    "No node named",
  );
});

Deno.test("duplicate node names are rejected at run time", async () => {
  const m = mockCtx({ nodes: [NODE(), NODE()] });
  let threw = false;
  try {
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);
  } catch (e) {
    threw = true;
    assertEquals(String(e).includes("Duplicate node name"), true);
  }
  assertEquals(threw, true);
});

// ---------------------------------------------------------------------------
// 7. a failed PER-MOUNT data query is degradation, not a drained disk
// ---------------------------------------------------------------------------

/** Run one discover() against stubbed routes and hand back the recorder. */
async function sweep(opts: {
  globalArgs: Json;
  routes: Array<[string, () => Response | Promise<Response>]>;
  stored?: Record<string, Json>;
  args?: Json;
}) {
  const restore = stubFetch(opts.routes);
  try {
    const m = mockCtx(opts.globalArgs, { stored: opts.stored });
    await model.methods.discover.execute(
      (opts.args ?? {}) as never,
      // deno-lint-ignore no-explicit-any
      m.ctx as any,
    );
    return m;
  } finally {
    restore();
  }
}

const infoRoute: [string, () => Response] = [
  "/api/v1/info",
  () => json({ version: "2.1", hostname: "h" }),
];
const noAlarms: [string, () => Response] = [
  "/api/v1/alarms",
  () => json({ alarms: {} }),
];

Deno.test("mount: a failed data query keeps the over-threshold count and flags degraded", async () => {
  const charts = { charts: { "disk_space./": {} } };
  // Round one: the mount answers and is over threshold (95% used).
  const healthy = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json(charts)],
      [
        "/api/v1/data",
        () => json({ labels: ["avail", "used"], data: [[5, 95]] }),
      ],
      infoRoute,
    ],
  });
  const firstMount = healthy.written.find((w) => w.spec === "mount")!;
  assertEquals(firstMount.data.overThreshold, true);
  assertEquals(
    healthy.written.find((w) => w.spec === "node")!.data.mountsOverThreshold,
    1,
  );

  // Round two: /charts still answers, this one mount's /data 500s.
  const stored: Record<string, Json> = {};
  for (const w of healthy.written) stored[w.name] = w.data;
  const degraded = await sweep({
    globalArgs: { nodes: [NODE()] },
    stored,
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json(charts)],
      ["/api/v1/data", () => json({ error: "boom" }, 500)],
      infoRoute,
    ],
  });

  const node = degraded.written.find((w) => w.spec === "node")!.data;
  const summary = degraded.written.find((w) => w.spec === "summary")!.data;
  assertEquals(
    node.mountsOverThreshold,
    1,
    "a mount we could not read must not drop out of the node's count",
  );
  assertEquals(
    summary.mountsOverThreshold,
    1,
    "nor out of the summary roll-up",
  );
  assertEquals(
    summary.nodesDegraded,
    1,
    "an unreadable mount makes the node degraded, so the roll-up is a floor",
  );
  assertEquals(
    degraded.deleted.includes(firstMount.name),
    false,
    "the preserved mount record must survive the prune",
  );
});

Deno.test("mount: a failed data query does not invent an over-threshold mount", async () => {
  // The counterpart to the test above: the last known reading was healthy, so
  // carrying it forward must not manufacture a threshold breach.
  const charts = { charts: { "disk_space./": {} } };
  const healthy = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json(charts)],
      [
        "/api/v1/data",
        () => json({ labels: ["avail", "used"], data: [[90, 10]] }),
      ],
      infoRoute,
    ],
  });
  const stored: Record<string, Json> = {};
  for (const w of healthy.written) stored[w.name] = w.data;
  const degraded = await sweep({
    globalArgs: { nodes: [NODE()] },
    stored,
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json(charts)],
      ["/api/v1/data", () => json({ error: "boom" }, 500)],
      infoRoute,
    ],
  });
  const summary = degraded.written.find((w) => w.spec === "summary")!.data;
  assertEquals(summary.mountsOverThreshold, 0);
  assertEquals(summary.nodesDegraded, 1);
});

// ---------------------------------------------------------------------------
// 8. cancellation must propagate from EVERY fetch, not just /info
// ---------------------------------------------------------------------------

async function assertCancelledSweepIsInert(
  routes: Array<[string, () => Response | Promise<Response>]>,
  ac: AbortController,
) {
  const restore = stubFetch(routes);
  try {
    const m = mockCtx({ nodes: [NODE()] }, { signal: ac.signal });
    let threw = false;
    try {
      // deno-lint-ignore no-explicit-any
      await model.methods.discover.execute({}, m.ctx as any);
    } catch {
      threw = true;
    }
    assertEquals(threw, true, "cancellation must propagate");
    assertEquals(
      m.written.length,
      0,
      "a cancelled sweep must not persist records or a fresh syncedAt",
    );
    assertEquals(m.deleted.length, 0, "a cancelled sweep must not prune");
  } finally {
    restore();
  }
}

Deno.test("cancellation during /alarms propagates, it is not a degraded sub-fetch", async () => {
  const ac = new AbortController();
  await assertCancelledSweepIsInert([
    ["/api/v1/alarms", () => {
      ac.abort();
      throw new DOMException("aborted", "AbortError");
    }],
    ["/api/v1/charts", () => json({ charts: {} })],
    infoRoute,
  ], ac);
});

Deno.test("cancellation during /charts propagates, it is not a degraded sub-fetch", async () => {
  const ac = new AbortController();
  await assertCancelledSweepIsInert([
    noAlarms,
    ["/api/v1/charts", () => {
      ac.abort();
      throw new DOMException("aborted", "AbortError");
    }],
    infoRoute,
  ], ac);
});

Deno.test("cancellation during a per-mount /data propagates", async () => {
  const ac = new AbortController();
  await assertCancelledSweepIsInert([
    noAlarms,
    ["/api/v1/charts", () => json({ charts: { "disk_space./": {} } })],
    ["/api/v1/data", () => {
      ac.abort();
      throw new DOMException("aborted", "AbortError");
    }],
    infoRoute,
  ], ac);
});

// ---------------------------------------------------------------------------
// 9. an unknown alarm value is null, not a real-looking zero
// ---------------------------------------------------------------------------

Deno.test("alarm: an uncalculable value stores null, and a real zero stays zero", async () => {
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      [
        "/api/v1/alarms",
        () =>
          json({
            alarms: {
              // Netdata serialises a nan calculation as null.
              gap: { chart: "c", status: "WARNING", value: null, units: "%" },
              odd: { chart: "c", status: "CRITICAL", value: "n/a", units: "%" },
              // A genuine reading of zero, which must NOT become null.
              zero: { chart: "c", status: "WARNING", value: 0, units: "%" },
            },
          }),
      ],
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });
  const value = (name: string) =>
    m.written.find((w) => w.spec === "alarm" && w.data.name === name)!.data
      .value;
  assertEquals(value("gap"), null, "a null value must not be stored as 0");
  assertEquals(value("odd"), null, "a non-numeric value must not become NaN/0");
  assertEquals(value("zero"), 0, "a genuine zero reading must stay 0");
});

Deno.test("alarm schema represents an unknown value as null", () => {
  const base = {
    node: "n",
    name: "a",
    chart: "c",
    status: "WARNING",
    units: "%",
    info: "",
  };
  assertEquals(
    model.resources.alarm.schema.safeParse({ ...base, value: null }).success,
    true,
    "null must be representable, otherwise 'unknown' has nowhere to go",
  );
  assertEquals(
    model.resources.alarm.schema.safeParse({ ...base, value: 12.5 }).success,
    true,
  );
  assertEquals(
    model.resources.alarm.schema.safeParse({ ...base, value: NaN }).success,
    false,
    "NaN must never be an accepted stored value",
  );
});

// ---------------------------------------------------------------------------
// 10. one node cannot impose unbounded work on a sweep
// ---------------------------------------------------------------------------

Deno.test("caps: maxMountsPerNode bounds the per-mount data calls", async () => {
  const many: Record<string, unknown> = {};
  for (let i = 0; i < 40; i++) many[`disk_space./m${i}`] = {};
  let dataCalls = 0;
  const m = await sweep({
    globalArgs: { nodes: [NODE()], maxMountsPerNode: 3 },
    // A stale mount record this round never rewrites: truncation means we did
    // not look, so it must be preserved rather than pruned.
    stored: { "mount-nodea-stale": { node: "nodeA" } },
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json({ charts: many })],
      ["/api/v1/data", () => {
        dataCalls++;
        return json({ labels: ["avail", "used"], data: [[90, 10]] });
      }],
      infoRoute,
    ],
  });
  assertEquals(dataCalls, 3, "the cap must bound the number of /data calls");
  assertEquals(m.written.filter((w) => w.spec === "mount").length, 3);
  assertEquals(
    m.written.find((w) => w.spec === "summary")!.data.nodesDegraded,
    1,
    "a truncated mount sweep is partial data, so the node is degraded",
  );
  assertEquals(
    m.deleted.includes("mount-nodea-stale"),
    false,
    "unpolled mounts are unknown, not gone",
  );
});

Deno.test("caps: maxAlarmsPerNode bounds the writes it performs", async () => {
  const many: Record<string, unknown> = {};
  for (let i = 0; i < 40; i++) {
    many[`alarm${i}`] = { chart: "c", status: "WARNING", value: 1 };
  }
  const m = await sweep({
    globalArgs: { nodes: [NODE()], maxAlarmsPerNode: 4 },
    stored: { "alarm-nodea-stale": { node: "nodeA" } },
    routes: [
      ["/api/v1/alarms", () => json({ alarms: many })],
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });
  assertEquals(
    m.written.filter((w) => w.spec === "alarm").length,
    4,
    "the cap must bound writeResource calls, not just what is returned",
  );
  assertEquals(
    m.written.find((w) => w.spec === "summary")!.data.nodesDegraded,
    1,
  );
  assertEquals(m.deleted.includes("alarm-nodea-stale"), false);
});

Deno.test("caps: an oversized response body is refused, not parsed", async () => {
  // 9 MiB, past the 8 MiB ceiling. The property under test is that the sweep
  // never gets a parsed object out of it -- the node reads as unreachable.
  const huge = JSON.stringify({
    version: "9.9",
    hostname: "evil",
    pad: "x".repeat(9 * 1024 * 1024),
  });
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json({ charts: {} })],
      ["/api/v1/info", () => new Response(huge, { status: 200 })],
    ],
  });
  const node = m.written.find((w) => w.spec === "node")!.data;
  assertEquals(node.reachable, false, "an over-cap body must not be accepted");
  assertEquals(
    node.version,
    null,
    "nothing from an over-cap body may reach stored data",
  );
});

Deno.test("caps: a normal-sized body is still accepted", async () => {
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });
  const node = m.written.find((w) => w.spec === "node")!.data;
  assertEquals(node.reachable, true);
  assertEquals(node.version, "2.1");
});

// ---------------------------------------------------------------------------
// 11. the prune-safety net must survive a node name past the label cap
// ---------------------------------------------------------------------------

Deno.test("prune: a node name past the label cap still protects its records", async () => {
  // 60 characters: longer than the 48-char instance-name label cap, so the
  // stored record's readable part is truncated and a prefix built from the
  // untruncated slug can never match it.
  const LONG = "n".repeat(60);
  const longNode = { name: LONG, url: "http://a.example.com:19999" };
  const alarms = {
    alarms: {
      diskfull: { chart: "disk_space./", status: "CRITICAL", value: 99 },
    },
  };

  const healthy = await sweep({
    globalArgs: { nodes: [longNode] },
    routes: [
      ["/api/v1/alarms", () => json(alarms)],
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });
  const alarmRecord = healthy.written.find((w) => w.spec === "alarm")!;
  assertEquals(alarmRecord.data.status, "CRITICAL");

  const stored: Record<string, Json> = {};
  for (const w of healthy.written) stored[w.name] = w.data;

  // Next round the alarms fetch fails: the firing CRITICAL is unknowable, so
  // its record must be preserved, not deleted.
  const degraded = await sweep({
    globalArgs: { nodes: [longNode] },
    stored,
    routes: [
      ["/api/v1/alarms", () => json({ error: "boom" }, 500)],
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });
  assertEquals(
    degraded.deleted.includes(alarmRecord.name),
    false,
    `a preserved CRITICAL alarm was pruned: ${alarmRecord.name}`,
  );
  assertEquals(
    degraded.written.find((w) => w.spec === "node")!.data.alarmsCritical,
    1,
    "and its count must carry forward",
  );
});

Deno.test("prune: a departed record with no protection is still deleted", async () => {
  // The safety net must not have become a blanket amnesty: a healthy sweep
  // still prunes what genuinely went away.
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    stored: { "mount-nodea-gone": { node: "nodeA" } },
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });
  assertEquals(m.deleted.includes("mount-nodea-gone"), true);
});

// ---------------------------------------------------------------------------
// 12. untrusted counts from /api/v1/info must not land as NaN
// ---------------------------------------------------------------------------

Deno.test("node: a non-numeric cores_total is stored as 0, never NaN", async () => {
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json({ charts: {} })],
      [
        "/api/v1/info",
        () => json({ version: "2.1", hostname: "h", cores_total: "lots" }),
      ],
    ],
  });
  const node = m.written.find((w) => w.spec === "node")!.data;
  assertEquals(node.cores, 0);
  assertEquals(
    model.resources.node.schema.safeParse(node).success,
    true,
    "the written record must satisfy its own schema",
  );
});

// ---------------------------------------------------------------------------
// 13. the agent must not be able to relocate our request
//
// review finding 2 (2026-08-23): `fetch` defaulted to redirect: "follow", so a
// server answering 302 with an http:// Location silently downgraded an
// operator's deliberate https:// configuration to cleartext -- and nothing in
// the stored record or in the log said it had happened.
// ---------------------------------------------------------------------------

/**
 * A fetch stub that HONOURS `init.redirect`, the way a real user agent does.
 *
 * The plain `stubFetch` above ignores init entirely, so a redirect test built
 * on it would pass whether or not the source sets a redirect policy at all --
 * the "typechecks perfectly, never runs" failure this repo keeps hitting. This
 * one re-issues the request itself when the policy is "follow", which is the
 * only way the test can tell a fix that runs from a fix that merely compiles.
 *
 * The cleartext side answers with a complete, HEALTHY payload on purpose: if
 * the redirect is ever followed again the sweep succeeds, so the assertions
 * below fail loudly rather than the downgrade hiding behind some unrelated
 * error.
 */
function stubRedirectingFetch(seen: string[]) {
  const original = globalThis.fetch;
  const serve = (url: string): Response => {
    if (url.includes("/api/v1/alarms")) return json({ alarms: {} });
    if (url.includes("/api/v1/charts")) return json({ charts: {} });
    return json({ version: "9.9", hostname: "downgraded" });
  };
  const impl = (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = String(input instanceof Request ? input.url : input);
    seen.push(url);
    if (url.startsWith("https://")) {
      const location = url.replace(/^https:/, "http:");
      const mode = init?.redirect ?? "follow";
      if (mode === "error") {
        return Promise.reject(new TypeError("redirect not allowed"));
      }
      if (mode === "manual") {
        return Promise.resolve(
          new Response(null, { status: 302, headers: { location } }),
        );
      }
      // "follow": a real agent transparently re-issues against the new URL.
      return impl(location, init);
    }
    return Promise.resolve(serve(url));
  };
  globalThis.fetch = impl as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

Deno.test("redirect: an https node is never downgraded to cleartext by a 302", async () => {
  const seen: string[] = [];
  const restore = stubRedirectingFetch(seen);
  try {
    const m = mockCtx({ nodes: [NODE({ url: "https://agent.example.com" })] });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);

    assertEquals(
      seen.some((u) => u.startsWith("http://")),
      false,
      `swamp made a cleartext request after being configured for https: ${
        seen.join(", ")
      }`,
    );
    const node = m.written.find((w) => w.spec === "node")!.data;
    assertEquals(
      node.reachable,
      false,
      "a refused redirect is a failed poll, not a successful one",
    );
    assertEquals(
      node.version,
      null,
      "nothing from the redirect target may reach stored data",
    );
    assertEquals(
      node.hostname,
      null,
      "nothing from the redirect target may reach stored data",
    );
    assertEquals(
      String(node.error).toLowerCase().includes("redirect"),
      true,
      `the stored error must name the refusal, got: ${node.error}`,
    );
  } finally {
    restore();
  }
});

Deno.test("redirect: the stored error names the refusal but not the Location", async () => {
  // The Location value is remote-supplied text, and the README's threat model
  // has an on-path party choosing it. It belongs in the log, not in a stored
  // field an operator reads as fact.
  const restore = stubRedirectingFetch([]);
  try {
    const m = mockCtx({ nodes: [NODE({ url: "https://agent.example.com" })] });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);
    const err = String(m.written.find((w) => w.spec === "node")!.data.error);
    assertEquals(err.includes("http://"), false, `Location persisted: ${err}`);
    assertEquals(err.includes("agent.example.com"), false, `leaked: ${err}`);
  } finally {
    restore();
  }
});

/** Replace Deno.Command with a stub returning one fixed ssh stdout. */
function stubSshCommand(stdout: string) {
  const original = Deno.Command;
  // deno-lint-ignore no-explicit-any
  (Deno as any).Command = class {
    constructor(_cmd: string, _opts: unknown) {}
    output() {
      return Promise.resolve({
        success: true,
        code: 0,
        signal: null,
        stdout: new TextEncoder().encode(stdout),
        stderr: new Uint8Array(),
      });
    }
  };
  return () => {
    // deno-lint-ignore no-explicit-any
    (Deno as any).Command = original;
  };
}

Deno.test("redirect: the ssh transport refuses a 3xx with the same class", async () => {
  // curl runs without -L so it never FOLLOWS a redirect, but a 3xx used to
  // arrive here as an empty body and get reported as "empty response over
  // ssh" -- the wrong class entirely. Both transports must say the same thing
  // about the same server behaviour, or an operator cannot compare them.
  const restore = stubSshCommand("__SWAMP_HTTP_STATUS__:302");
  try {
    const m = mockCtx({
      nodes: [
        NODE({
          url: "http://127.0.0.1:19999",
          ssh: { host: "box.example.com", user: "netdata-reader", port: 22 },
        }),
      ],
    });
    // deno-lint-ignore no-explicit-any
    await model.methods.discover.execute({}, m.ctx as any);
    const node = m.written.find((w) => w.spec === "node")!.data;
    assertEquals(node.reachable, false);
    assertEquals(
      String(node.error).toLowerCase().includes("redirect"),
      true,
      `the ssh transport misreported a 302 as: ${node.error}`,
    );
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// 14. agent-supplied text cannot forge an instance name or grow without bound
//
// review finding 5 (2026-08-23): the U+001F join separator was written as an
// escape but never excluded from the values being joined, so an agent could
// craft two distinct alarms that hashed to one instance name.
//
// Control characters are built with String.fromCharCode rather than written as
// literals, for the same reason the source writes the separator as an escape:
// a raw control byte makes the file read as binary to grep and to any tool
// doing exact-text matching.
// ---------------------------------------------------------------------------

/** U+001F, the separator instanceName() joins identity fields with. */
const SEP = String.fromCharCode(0x1f);

/** True if the string contains any C0 control character or DEL. */
function hasControlChar(s: string): boolean {
  return [...s].some((c) => {
    const n = c.charCodeAt(0);
    return n < 32 || n === 127;
  });
}

/** Every string value in every written record, flattened. */
function writtenStrings(written: Array<{ data: Json }>): string[] {
  return written.flatMap((w) =>
    Object.values(w.data).filter((v): v is string => typeof v === "string")
  );
}

Deno.test("names: two alarms differing only in separator placement stay two records", async () => {
  // instanceName joins (node, name, chart) with U+001F. These two alarms
  // produce the SAME join if the separator is not excluded from the inputs:
  //   nodeA | x       | y<US>z  ->  nodeA<US>x<US>y<US>z
  //   nodeA | x<US>y  | z       ->  nodeA<US>x<US>y<US>z
  // Same hash -- and slug() strips the control character, so the readable
  // label matches too. One instance name, and the second write silently
  // erases the first. Here the first is a firing CRITICAL.
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      [
        "/api/v1/alarms",
        () =>
          json({
            alarms: {
              "x": { chart: `y${SEP}z`, status: "CRITICAL", value: 99 },
              [`x${SEP}y`]: { chart: "z", status: "WARNING", value: 1 },
            },
          }),
      ],
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });

  const alarms = m.written.filter((w) => w.spec === "alarm");
  assertEquals(
    alarms.length,
    2,
    "both alarms must be written; the payload describes two distinct alarms",
  );
  assertEquals(
    new Set(alarms.map((a) => a.name)).size,
    2,
    `two alarms collided onto one instance name: ${
      alarms.map((a) => a.name).join(" == ")
    }`,
  );
  assertEquals(
    alarms.filter((a) => a.data.status === "CRITICAL").length,
    1,
    "the firing CRITICAL must not be overwritten by the benign alarm",
  );
});

Deno.test("names: no stored field or instance name carries a raw control character", async () => {
  // The class, not the instance: a raw NUL/CR/ESC in ANY stored field is a
  // reads-as-binary and terminal-escape problem for every consumer of this
  // data, and every one of these fields is chosen by an unauthenticated
  // remote.
  const NUL = String.fromCharCode(0);
  const CR = String.fromCharCode(13);
  const ESC = String.fromCharCode(27);
  const BEL = String.fromCharCode(7);
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      [
        "/api/v1/alarms",
        () =>
          json({
            alarms: {
              [`bad${SEP}name`]: {
                chart: `disk${NUL}space`,
                status: `CRIT${CR}ICAL`,
                value: 1,
                units: `%${ESC}[31m`,
                info: `line${NUL}one`,
              },
            },
          }),
      ],
      [
        "/api/v1/charts",
        () => json({ charts: { [`disk_space./mnt${NUL}x`]: {} } }),
      ],
      [
        "/api/v1/data",
        () => json({ labels: ["avail", "used"], data: [[10, 90]] }),
      ],
      [
        "/api/v1/info",
        () =>
          json({
            version: `2.1${BEL}`,
            hostname: `h${ESC}[0m`,
            os_name: `linux${CR}`,
            os_version: "1",
          }),
      ],
    ],
  });
  for (const s of writtenStrings(m.written)) {
    assertEquals(
      hasControlChar(s),
      false,
      `a stored field carried a raw control character: ${JSON.stringify(s)}`,
    );
  }
  // And the instance names, which become filenames and CLI arguments.
  for (const w of m.written) {
    assertEquals(
      hasControlChar(w.name),
      false,
      `an instance name carried a raw control character: ${
        JSON.stringify(w.name)
      }`,
    );
  }
});

Deno.test("names: an alarm's instance name still describes the record it stores", async () => {
  // Normalising in two places with two different rules is how a record ends
  // up named after one alarm and filled with another's text. The readable
  // part of the name must stay derived from the value actually stored.
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      [
        "/api/v1/alarms",
        () =>
          json({
            alarms: {
              "disk usage": { chart: "disk_space./", status: "WARNING" },
            },
          }),
      ],
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });
  const alarm = m.written.find((w) => w.spec === "alarm")!;
  assertEquals(alarm.data.name, "disk usage");
  assertEquals(
    alarm.name.startsWith("alarm-nodea-disk-usage-"),
    true,
    `the instance name lost its readable part: ${alarm.name}`,
  );
});

Deno.test("bounds: one agent-supplied field cannot be arbitrarily long", async () => {
  // MAX_RESPONSE_BYTES bounds a whole payload, not a field: a single alarm
  // carrying a 100k-character `info` string fits inside the 8 MiB ceiling and
  // used to land in the datastore whole.
  const huge = "A".repeat(100_000);
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      [
        "/api/v1/alarms",
        () =>
          json({
            alarms: {
              [huge]: {
                chart: huge,
                status: "WARNING",
                value: 1,
                units: huge,
                info: huge,
              },
            },
          }),
      ],
      ["/api/v1/charts", () => json({ charts: {} })],
      ["/api/v1/info", () => json({ version: huge, hostname: huge })],
    ],
  });
  for (const s of writtenStrings(m.written)) {
    assertEquals(
      s.length <= 512,
      true,
      `an agent-supplied field reached the datastore at ${s.length} chars`,
    );
  }
  const alarm = m.written.find((w) => w.spec === "alarm")!;
  assertEquals(
    alarm.name.length < 200,
    true,
    `the instance name grew with the input: ${alarm.name.length} chars`,
  );
  assertEquals(
    model.resources.alarm.schema.safeParse(alarm.data).success,
    true,
    "the bounded record must still satisfy its own schema",
  );
});

// ---------------------------------------------------------------------------
// 15. a payload of the wrong SHAPE is a failed sub-fetch, not a reading
//
// review finding 4 (2026-08-23): API responses are blind-cast and then walked.
// Object.entries on a string enumerates its CHARACTERS.
// ---------------------------------------------------------------------------

Deno.test("shape: a string 'alarms' payload mints no alarm records", async () => {
  const prior = {
    "node-nodea": {
      name: "nodeA",
      alarmsActive: 3,
      alarmsCritical: 1,
      alarmsWarning: 2,
      charts: 0,
      mountsOverThreshold: 0,
      version: "2.1",
      hostname: "h",
      osName: "linux",
      osVersion: "1",
      cores: 4,
      collectors: 2,
      claimedToCloud: false,
    } as Json,
  };
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    stored: prior,
    routes: [
      ["/api/v1/alarms", () => json({ alarms: "xxxx" })],
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });
  assertEquals(
    m.written.filter((w) => w.spec === "alarm").length,
    0,
    "enumerating a string minted one bogus alarm record per character",
  );
  const summary = m.written.find((w) => w.spec === "summary")!.data;
  assertEquals(
    summary.nodesDegraded,
    1,
    "an unusable payload is a failed sub-fetch, so the node is degraded",
  );
  assertEquals(
    summary.alarmsActive,
    3,
    "and the last known counts carry forward rather than being replaced",
  );
});

Deno.test("shape: an array 'charts' payload invents no mounts and no chart count", async () => {
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json({ charts: ["disk_space./", "cpu"] })],
      infoRoute,
    ],
  });
  const node = m.written.find((w) => w.spec === "node")!.data;
  assertEquals(m.written.filter((w) => w.spec === "mount").length, 0);
  assertEquals(node.charts, 0, "a fictional chart count must not be stored");
  assertEquals(
    m.written.find((w) => w.spec === "summary")!.data.nodesDegraded,
    1,
  );
});

Deno.test("shape: an absent alarms/charts key is still zero, not a failure", async () => {
  // The counterpart. Tightening the shape check must not turn a legitimately
  // quiet agent into a permanently degraded node -- absence has always meant
  // zero, and still does.
  const m = await sweep({
    globalArgs: { nodes: [NODE()] },
    routes: [
      ["/api/v1/alarms", () => json({ hostname: "h" })],
      ["/api/v1/charts", () => json({})],
      infoRoute,
    ],
  });
  const summary = m.written.find((w) => w.spec === "summary")!.data;
  assertEquals(summary.alarmsActive, 0);
  assertEquals(
    summary.nodesDegraded,
    0,
    "an empty but well-formed answer is not degradation",
  );
});

Deno.test("shape: a /data payload of the wrong shape invents no filesystem", async () => {
  // Both halves fabricate a real-looking capacity reading out of garbage under
  // the old blind casts, which is worse than failing:
  //
  //  - `data: ["25,75"]` is an array whose first element is a STRING. It is
  //    truthy, so the old `if (!row)` let it through, and row[0] / row[1] then
  //    read the CHARACTERS "2" and "5". Number() accepts both, so a 71.4%-used
  //    filesystem appeared from a string that describes no filesystem at all.
  //
  //  - `labels: "usedavail"` is a STRING, and String.prototype.indexOf answers
  //    happily: indexOf("used") is 0 and indexOf("avail") is 4. The old
  //    `labels.indexOf(...)` therefore resolved both dimensions to real row
  //    positions and stored row[0] and row[4] as used/avail.
  //
  // The property: a payload whose shape is not what /api/v1/data promises is
  // an unreadable mount -- a state this model already represents -- and never
  // a reading.
  for (
    const bad of [
      { labels: ["avail", "used"], data: ["25,75"] },
      { labels: "usedavail", data: [[10, 20, 30, 40, 50]] },
    ]
  ) {
    const m = await sweep({
      globalArgs: { nodes: [NODE()] },
      routes: [
        noAlarms,
        ["/api/v1/charts", () => json({ charts: { "disk_space./": {} } })],
        ["/api/v1/data", () => json(bad)],
        infoRoute,
      ],
    });
    assertEquals(
      m.written.filter((w) => w.spec === "mount").length,
      0,
      `a fabricated mount was written from ${JSON.stringify(bad)}`,
    );
    assertEquals(
      m.written.find((w) => w.spec === "summary")!.data.nodesDegraded,
      1,
      "an unreadable mount makes the node degraded",
    );
  }
});

// ---------------------------------------------------------------------------
// 16. node names that normalise to one instance name are rejected
// ---------------------------------------------------------------------------

Deno.test("nodes: names colliding after slugging are rejected, not silently merged", async () => {
  // The node record's instance name is `node-${slug(name)}` with no hash, and
  // slug() is not injective. Both members of each pair become one instance
  // name, so the second node's write used to overwrite the first's record --
  // one machine's reachability and alarm counts stored under the other's name,
  // with nothing anywhere saying a node had gone missing.
  for (const pair of [["NAS", "nas"], ["db 1", "db-1"]]) {
    const m = mockCtx({
      nodes: pair.map((name) => ({ name, url: "http://a.example.com:19999" })),
    });
    let threw = false;
    try {
      // deno-lint-ignore no-explicit-any
      await model.methods.discover.execute({}, m.ctx as any);
    } catch (e) {
      threw = true;
      assertEquals(
        String(e).includes("collide"),
        true,
        `expected a collision error, got: ${e}`,
      );
    }
    assertEquals(
      threw,
      true,
      `${pair.join(" / ")} share one instance name and must be rejected`,
    );
    assertEquals(
      m.written.length,
      0,
      "nothing may be written before the check",
    );
  }
});

Deno.test("nodes: names that merely differ are still accepted", async () => {
  // The check must reject collisions, not near-misses.
  const m = await sweep({
    globalArgs: {
      nodes: [
        { name: "nas", url: "http://a.example.com:19999" },
        { name: "nas-2", url: "http://b.example.com:19999" },
      ],
    },
    routes: [
      noAlarms,
      ["/api/v1/charts", () => json({ charts: {} })],
      infoRoute,
    ],
  });
  assertEquals(m.written.filter((w) => w.spec === "node").length, 2);
});
