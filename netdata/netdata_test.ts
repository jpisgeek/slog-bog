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
