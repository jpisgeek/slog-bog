/**
 * Tests for @jpisgeek/firewalla.
 *
 * Written against the exported surface only, so this file can change without
 * moving the extension's content hash (which the security review is bound to).
 *
 * The headline case is the MSP host check. The original implementation tested
 * the raw config string with a `/\.firewalla\.net$/` regex after stripping the
 * scheme, so `evil.example/#.firewalla.net` *ends with* ".firewalla.net" and
 * passed — sending the MSP token to evil.example. Those bypasses are the first
 * block of tests and must never regress: this is the one place in the package
 * where a validation slip hands a live credential to an attacker-chosen host.
 */
import { assertEquals } from "jsr:@std/assert@1";
import { model } from "./firewalla.ts";

const BASE = { token: "t0ken", mspDomain: "acme.firewalla.net" };
const parse = (over: Record<string, unknown> = {}) =>
  model.globalArguments.safeParse({ ...BASE, ...over });

// ---------------------------------------------------------------------------
// mspDomain — the token is sent here; a bypass is a credential leak
// ---------------------------------------------------------------------------

Deno.test("mspDomain: accepts a bare *.firewalla.net host", () => {
  for (
    const d of [
      "acme.firewalla.net",
      "my-msp.firewalla.net",
      "https://acme.firewalla.net",
      "https://acme.firewalla.net/",
      "acme.firewalla.net/",
    ]
  ) {
    assertEquals(parse({ mspDomain: d }).success, true, `expected ok: ${d}`);
  }
});

Deno.test("mspDomain: rejects suffix-spoofing that a string test would pass", () => {
  // Every one of these ENDS WITH ".firewalla.net" as a string but resolves to
  // an attacker-controlled host. This is the exact bypass found in review.
  for (
    const d of [
      "evil.example/#.firewalla.net",
      "evil.example/?x=.firewalla.net",
      "evil.example/path/.firewalla.net",
      "https://evil.example/#.firewalla.net",
      "https://evil.example/?q=acme.firewalla.net",
    ]
  ) {
    assertEquals(
      parse({ mspDomain: d }).success,
      false,
      `SUFFIX SPOOF ACCEPTED — token would go to evil.example: ${d}`,
    );
  }
});

Deno.test("mspDomain: rejects lookalike domains", () => {
  for (
    const d of [
      "firewalla.net.evil.example",
      "notfirewalla.net",
      "acme.firewalla.net.evil.example",
      "acmefirewalla.net",
    ]
  ) {
    assertEquals(parse({ mspDomain: d }).success, false, `accepted: ${d}`);
  }
});

Deno.test("mspDomain: rejects userinfo, port, and non-http schemes", () => {
  for (
    const d of [
      "user:pass@acme.firewalla.net",
      "https://user:pass@acme.firewalla.net",
      "acme.firewalla.net:8443",
      "ftp://acme.firewalla.net",
      "file://acme.firewalla.net",
    ]
  ) {
    assertEquals(parse({ mspDomain: d }).success, false, `accepted: ${d}`);
  }
});

Deno.test("mspDomain: is case-insensitive on the host", () => {
  assertEquals(parse({ mspDomain: "ACME.FIREWALLA.NET" }).success, true);
});

// ---------------------------------------------------------------------------
// token
// ---------------------------------------------------------------------------

Deno.test("token: required and marked sensitive", () => {
  assertEquals(
    model.globalArguments.safeParse({ mspDomain: BASE.mspDomain }).success,
    false,
    "token must be required",
  );
  // The sensitive marker is what keeps the token out of rendered config.
  //
  // The presence assertion is NOT optional and must come first. This used to
  // be `if (tokenMeta) { assertEquals(...) }` — and zod returns undefined
  // from `.meta()` when nothing is registered, so dropping `.meta({
  // sensitive: true })` made the guard falsy and skipped the only assertion
  // protecting it. The test went green on exactly the regression it exists
  // to catch.
  const shape = model.globalArguments as unknown as {
    shape?: Record<string, { meta?: () => Record<string, unknown> }>;
  };
  const tokenMeta = shape.shape?.token?.meta?.();
  assertEquals(
    typeof tokenMeta,
    "object",
    "token must carry registered metadata; .meta() returned nothing",
  );
  assertEquals(
    tokenMeta!.sensitive,
    true,
    "token must carry sensitive: true",
  );
});

// ---------------------------------------------------------------------------
// resource schemas: absent must stay distinguishable from blank
// ---------------------------------------------------------------------------

Deno.test("device schema: ip is optional (omitted != empty string)", () => {
  const device = {
    id: "aa:bb:cc:dd:ee:ff",
    name: "printer",
    mac: "aa:bb:cc:dd:ee:ff",
    macVendor: "(unknown)",
    deviceType: "printer",
    network: "Root",
    online: false,
    ipReserved: false,
    isRouter: false,
    isFirewalla: false,
    tier: "presence",
    sshCandidate: false,
    excluded: false,
  };
  // No `ip` key at all — the documented "unknown address" encoding.
  assertEquals(model.resources.device.schema.safeParse(device).success, true);
  // An explicit empty string is also structurally valid, but the model must
  // never *produce* it; that's asserted in the sync tests of the real fleet.
  assertEquals(
    model.resources.device.schema.safeParse({ ...device, ip: "10.0.0.5" })
      .success,
    true,
  );
});

Deno.test("device schema: traffic counters are optional (omitted != zero)", () => {
  // This fixture used to carry `totalDownload: 0, totalUpload: 0` because the
  // schema REQUIRED them, which is the old contract: absent was backfilled to
  // zero by `Number(raw.totalDownload ?? 0)` and the record could not express
  // "unknown". Same rule as `ip` now — a missing key means unknown.
  const device = {
    id: "aa:bb:cc:dd:ee:ff",
    name: "printer",
    mac: "aa:bb:cc:dd:ee:ff",
    macVendor: "(unknown)",
    deviceType: "printer",
    network: "Root",
    online: false,
    ipReserved: false,
    isRouter: false,
    isFirewalla: false,
    tier: "presence",
    sshCandidate: false,
    excluded: false,
  };
  assertEquals(
    model.resources.device.schema.safeParse(device).success,
    true,
    "a device with no traffic counters must be a valid record",
  );
  assertEquals(
    model.resources.device.schema.safeParse({
      ...device,
      totalDownload: 12,
      totalUpload: 34,
    }).success,
    true,
  );
});

Deno.test("machine schema: dependsOn is optional", () => {
  const machine = {
    name: "host",
    primaryIp: "203.0.113.10",
    deviceType: "desktop",
    macVendor: "v",
    tier: "deep",
    sshCandidate: true,
    online: true,
    networks: ["Root"],
    interfaces: [{
      name: "host-eth",
      ip: "203.0.113.10",
      mac: "aa:bb:cc:dd:ee:ff",
      network: "Root",
      online: true,
    }],
    interfaceCount: 1,
  };
  assertEquals(model.resources.machine.schema.safeParse(machine).success, true);
});

// ---------------------------------------------------------------------------
// declared policy surface
// ---------------------------------------------------------------------------

Deno.test("the destructive-prune policy is a named, skippable check", () => {
  const check = model.checks?.["full-sync-prunes-departed-records"];
  assertEquals(
    typeof check,
    "object",
    "policy check must exist and be nameable",
  );
  assertEquals(check!.appliesTo.includes("syncDevices"), true);
});

// ---------------------------------------------------------------------------
// sync harness
//
// Exercises `model.methods.syncDevices.execute` against a recording context
// and a stubbed fetch. Everything below is a regression lock on a defect found
// in review, not coverage decoration:
//   - an empty or shrunken /v2/devices response must never wipe the datastore
//   - excludeNetworks must match the way the sibling name matcher does
//   - the documented "online beats offline" primaryIp rule must actually fire
//   - two same-named hosts must not collapse into one machine
// ---------------------------------------------------------------------------

type Json = Record<string, unknown>;

/** A recording stand-in for the swamp model context. */
function mockCtx(
  globalArgs: Json,
  opts: { stored?: Record<string, Json> } = {},
) {
  const written: Array<{ spec: string; name: string; data: Json }> = [];
  const deleted: string[] = [];
  const warnings: string[] = [];
  const stored = opts.stored ?? {};
  return {
    written,
    deleted,
    warnings,
    ctx: {
      signal: new AbortController().signal,
      globalArgs: { ...BASE, ...globalArgs },
      modelType: "@jpisgeek/firewalla",
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
        // The real repository lists this model's stored resources; `inventory`
        // is seeded here only to stand in for the previous roll-up, so keep it
        // out of the prune candidate list.
        findAllForModel: () =>
          Promise.resolve(
            Object.keys(stored)
              .filter((n) => n !== "inventory")
              .map((name) => ({ name })),
          ),
      },
    },
  };
}

/** Stub /v2/devices with one JSON body. Returns a restore function. */
function stubDevices(body: unknown, status = 200) {
  const original = globalThis.fetch;
  globalThis.fetch = (() =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      }),
    )) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

/**
 * Stub fetch with an arbitrary handler and record every request init it was
 * given. `calls` is what proves a request OPTION is actually reaching fetch:
 * a `redirect: "error"` that typechecks but sits on the wrong object is
 * exactly the kind of dead fix this repo keeps shipping.
 */
function stubFetch(
  handler: (url: string, init: RequestInit) => Promise<Response>,
) {
  const original = globalThis.fetch;
  const calls: Array<{ url: string; init: RequestInit }> = [];
  globalThis.fetch = (((input: string | URL | Request, init: RequestInit) => {
    calls.push({ url: String(input), init: init ?? {} });
    return handler(String(input), init ?? {});
  }) as unknown) as typeof fetch;
  return { calls, restore: () => (globalThis.fetch = original) };
}

const jsonResponse = (body: unknown) =>
  Promise.resolve(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  );

/** Run and return the thrown Error, failing if the call unexpectedly succeeds. */
// deno-lint-ignore no-explicit-any
async function runExpectingThrow(ctx: any, args: Json = {}): Promise<Error> {
  try {
    await run(ctx, args);
  } catch (e) {
    return e as Error;
  }
  throw new Error("expected syncDevices to throw, but it returned");
}

const DEV = (over: Json = {}): Json => ({
  id: "aa:bb:cc:dd:ee:01",
  name: "host",
  mac: "aa:bb:cc:dd:ee:01",
  macVendor: "Acme",
  deviceType: "desktop",
  network: "Root",
  online: true,
  ...over,
});

// deno-lint-ignore no-explicit-any
const run = (ctx: any, args: Json = {}) =>
  model.methods.syncDevices.execute(
    // deno-lint-ignore no-explicit-any
    model.methods.syncDevices.arguments.parse(args) as any,
    ctx,
  );

const machinesWritten = (written: Array<{ spec: string; data: Json }>) =>
  written.filter((w) => w.spec === "machine").map((w) => w.data);

// ---------------------------------------------------------------------------
// prune plausibility guards — the destructive path
// ---------------------------------------------------------------------------

Deno.test("prune: a zero-device response does not delete the stored inventory", async () => {
  // A transient MSP fault returning `{"results": []}` used to be accepted as
  // ground truth: every device-*/machine-* record was deleted and the SSH
  // fleet generated from them read empty until a later sync happened to work.
  const m = mockCtx({}, {
    stored: {
      "device-aabbccddee01-11111111": { name: "keep" },
      "machine-nas-22222222": { name: "nas" },
      inventory: { total: 2 },
    },
  });
  const restore = stubDevices({ results: [] });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  assertEquals(
    m.deleted,
    [],
    "an empty device list must never be treated as 'everything departed'",
  );
  assertEquals(
    m.warnings.some((w) => w.includes("refusing to prune")),
    true,
    "declining to prune must be visible, not a silent no-op",
  );
});

Deno.test("prune: a collapse past pruneMaxShrink does not delete", async () => {
  // Previous run saw 10; this one sees 2. Default pruneMaxShrink 0.5 puts the
  // floor at 5, so this looks like a truncated or partial fetch, not a real
  // decommission of 8 hosts.
  const m = mockCtx({}, {
    stored: {
      "device-gone-33333333": { name: "gone" },
      inventory: { total: 10 },
    },
  });
  const restore = stubDevices({
    results: [
      DEV({ id: "aa:bb:cc:dd:ee:01", name: "a" }),
      DEV({ id: "aa:bb:cc:dd:ee:02", name: "b" }),
    ],
  });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  assertEquals(m.deleted, [], "a >50% collapse must not prune");
});

Deno.test("prune: still deletes departed records on a plausible full sync", async () => {
  // The guards must not disable pruning. Previous total 3, this run writes 3,
  // so the stale record is genuinely departed and must go.
  const m = mockCtx({}, {
    stored: {
      "device-gone-33333333": { name: "gone" },
      inventory: { total: 3 },
    },
  });
  const restore = stubDevices({
    results: [
      DEV({ id: "aa:bb:cc:dd:ee:01", name: "a" }),
      DEV({ id: "aa:bb:cc:dd:ee:02", name: "b" }),
      DEV({ id: "aa:bb:cc:dd:ee:03", name: "c" }),
    ],
  });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  assertEquals(
    m.deleted.includes("device-gone-33333333"),
    true,
    "a representative full sync must still prune departed records",
  );
});

Deno.test("prune: forcePrune overrides the guards after a real decommission", async () => {
  const m = mockCtx({}, {
    stored: {
      "device-gone-33333333": { name: "gone" },
      inventory: { total: 10 },
    },
  });
  const restore = stubDevices({ results: [] });
  try {
    await run(m.ctx, { forcePrune: true });
  } finally {
    restore();
  }
  assertEquals(m.deleted, ["device-gone-33333333"]);
});

Deno.test("prune: no previous roll-up leaves the shrink floor inactive", async () => {
  // A first-ever run has no `inventory` resource. An unreadable previous
  // total must mean "unknown", never "zero", but it must also not wedge the
  // prune permanently — a run that wrote devices still prunes.
  const m = mockCtx({}, { stored: { "device-gone-33333333": { name: "g" } } });
  const restore = stubDevices({ results: [DEV()] });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  assertEquals(m.deleted, ["device-gone-33333333"]);
});

// ---------------------------------------------------------------------------
// excludeNetworks — a scope control that silently matches nothing is worse
// than one that errors
// ---------------------------------------------------------------------------

Deno.test("excludeNetworks: matches case- and whitespace-insensitively", async () => {
  const m = mockCtx({ excludeNetworks: ["  GUEST "] });
  const restore = stubDevices({
    results: [
      DEV({ id: "aa:bb:cc:dd:ee:01", name: "a", network: "guest" }),
      DEV({ id: "aa:bb:cc:dd:ee:02", name: "b", network: "Root" }),
    ],
  });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  const devices = m.written.filter((w) => w.spec === "device");
  assertEquals(
    devices.length,
    1,
    "the guest-network device must not be stored",
  );
  assertEquals(devices[0].data.network, "Root");
  const inv = m.written.find((w) => w.spec === "inventory")!.data;
  assertEquals(inv.skippedByNetwork, 1);
});

// ---------------------------------------------------------------------------
// primaryIp tiebreak — this is the address the SSH fleet targets
// ---------------------------------------------------------------------------

Deno.test("primaryIp: an online wired NIC displaces an offline wired one", async () => {
  // `existingMachine.online` was OR-ed with the incoming device seven lines
  // before the predicate read `!existingMachine.online`, so the documented
  // "online beats offline" rule could never fire and the machine kept the
  // offline interface's stale address.
  const m = mockCtx({});
  const restore = stubDevices({
    results: [
      DEV({
        id: "aa:bb:cc:dd:ee:01",
        name: "nas-eth",
        online: false,
        ip: "192.168.1.50",
      }),
      DEV({
        id: "aa:bb:cc:dd:ee:02",
        name: "nas-lan",
        online: true,
        ip: "192.168.1.51",
      }),
    ],
  });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  const machines = machinesWritten(m.written);
  assertEquals(machines.length, 1);
  assertEquals(machines[0].primaryIp, "192.168.1.51");
});

Deno.test("primaryIp: an intervening online wireless NIC does not lock in the stale wired address", async () => {
  // Snapshotting the machine-wide `online` flag is not enough: once any NIC
  // is online it stays true, so the wired-vs-wired comparison has to ask
  // whether the interface CURRENTLY HOLDING primaryIp was online.
  const m = mockCtx({});
  const restore = stubDevices({
    results: [
      DEV({
        id: "aa:bb:cc:dd:ee:01",
        name: "nas-eth",
        online: false,
        ip: "192.168.1.50",
      }),
      DEV({
        id: "aa:bb:cc:dd:ee:02",
        name: "nas-wifi",
        online: true,
        ip: "192.168.1.60",
      }),
      DEV({
        id: "aa:bb:cc:dd:ee:03",
        name: "nas-lan",
        online: true,
        ip: "192.168.1.51",
      }),
    ],
  });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  const machines = machinesWritten(m.written);
  assertEquals(machines.length, 1);
  assertEquals(machines[0].primaryIp, "192.168.1.51");
});

// ---------------------------------------------------------------------------
// machine key collisions — a merged machine is a host lost from the fleet
// ---------------------------------------------------------------------------

Deno.test("machines: two hosts sharing a suffixed name stay separate", async () => {
  // A retired box the firewall still knows as `pi-eth` plus its same-named
  // replacement both had a suffix stripped, so the old `!hadSuffix &&
  // !collision.hadSuffix` guard never fired and they collapsed into one
  // machine whose interface list mixed both hosts.
  const m = mockCtx({});
  const restore = stubDevices({
    results: [
      DEV({
        id: "aa:bb:cc:dd:ee:11",
        mac: "aa:bb:cc:dd:ee:11",
        name: "pi-eth",
        ip: "192.168.1.11",
      }),
      DEV({
        id: "aa:bb:cc:dd:ee:22",
        mac: "aa:bb:cc:dd:ee:22",
        name: "pi-eth",
        ip: "192.168.1.22",
      }),
    ],
  });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  const machines = machinesWritten(m.written);
  assertEquals(machines.length, 2, "two distinct hosts must be two machines");
  assertEquals(
    new Set(machines.map((x) => x.primaryIp)),
    new Set(["192.168.1.11", "192.168.1.22"]),
    "neither host's address may be lost to a merge",
  );
});

Deno.test("machines: genuine multi-homing still collapses to one machine", async () => {
  // The collision fix must not split real hosts. Different NIC names, and
  // deliberately different macVendors (a Mac's built-in ethernet and its
  // Wi-Fi radio routinely differ) — vendor agreement is NOT a merge
  // precondition.
  const m = mockCtx({});
  const restore = stubDevices({
    results: [
      DEV({
        id: "aa:bb:cc:dd:ee:11",
        mac: "aa:bb:cc:dd:ee:11",
        name: "nas-eth",
        macVendor: "Apple",
        ip: "192.168.1.11",
      }),
      DEV({
        id: "aa:bb:cc:dd:ee:22",
        mac: "aa:bb:cc:dd:ee:22",
        name: "nas-wifi",
        macVendor: "Broadcom",
        ip: "192.168.1.22",
      }),
    ],
  });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  const machines = machinesWritten(m.written);
  assertEquals(machines.length, 1, "one host, one machine");
  assertEquals(machines[0].name, "nas");
  assertEquals(machines[0].interfaceCount, 2);
});

Deno.test("machines: two same-named unsuffixed devices stay separate", async () => {
  // The case the original guard was written for — a pair of identical air
  // purifiers. Must still hold after the rewrite.
  const m = mockCtx({});
  const restore = stubDevices({
    results: [
      DEV({
        id: "aa:bb:cc:dd:ee:11",
        mac: "aa:bb:cc:dd:ee:11",
        name: "purifier",
      }),
      DEV({
        id: "aa:bb:cc:dd:ee:22",
        mac: "aa:bb:cc:dd:ee:22",
        name: "purifier",
      }),
    ],
  });
  try {
    await run(m.ctx);
  } finally {
    restore();
  }
  assertEquals(machinesWritten(m.written).length, 2);
});

// ---------------------------------------------------------------------------
// the token-bearing request itself
// ---------------------------------------------------------------------------

Deno.test("request: redirects are refused rather than followed", async () => {
  // The init used to set only `headers` and `signal`, leaving fetch's default
  // `follow`. Whether the Authorization header survives a redirect to another
  // origin (or to http://) is then the runtime's business, so the "the token
  // only ever goes to *.firewalla.net" guarantee rested on somebody else's
  // header-stripping rules rather than on the hostname check three lines up.
  const m = mockCtx({});
  const f = stubFetch(() => jsonResponse({ results: [DEV()] }));
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(f.calls.length, 1);
  assertEquals(
    f.calls[0].init.redirect,
    "error",
    "the credential-bearing request must forbid redirects at the call site",
  );
  assertEquals(
    f.calls[0].url.startsWith("https://acme.firewalla.net/"),
    true,
    "the request must go to the validated host over https",
  );
});

// ---------------------------------------------------------------------------
// redaction — the property is "no foreign text reaches an Error unscrubbed",
// which is a CLASS of call sites, not the one the review happened to find
// ---------------------------------------------------------------------------

Deno.test("redaction: a JSON parser message quoting the body cannot leak the token", async () => {
  // V8's SyntaxError quotes a prefix of the offending body verbatim:
  //   Unexpected token '<', "<t0ken>ech"... is not valid JSON
  // This was the one body-derived path with no redact() on it, while the
  // README promised every error body was scrubbed. The quote window is only
  // about ten bytes, so the exposure is narrow rather than gaping — and
  // closing it costs one function call, which is why arguing about the width
  // of the window is not worth the round trip. The body here is shaped to
  // land inside that window deliberately; a wider body proves nothing about
  // whether redact() runs.
  const m = mockCtx({});
  const f = stubFetch(() =>
    Promise.resolve(
      new Response("<t0ken>echoed by a proxy</html>", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    )
  );
  let err: Error;
  try {
    err = await runExpectingThrow(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(
    err.message.includes("t0ken"),
    false,
    `parser message leaked the token: ${err.message}`,
  );
  assertEquals(err.message.includes("[REDACTED]"), true);
});

Deno.test("redaction: a network error message cannot leak the token", async () => {
  const m = mockCtx({});
  const f = stubFetch(() =>
    Promise.reject(new Error("proxy rejected: Authorization: Token t0ken"))
  );
  let err: Error;
  try {
    err = await runExpectingThrow(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(
    err.message.includes("t0ken"),
    false,
    `network error leaked the token: ${err.message}`,
  );
  assertEquals(err.message.includes("[REDACTED]"), true);
});

Deno.test("redaction: a datastore write error cannot leak the token", async () => {
  // Not an HTTP path, which is exactly why it was missed: a driver that
  // echoes the model's rendered configuration into its error message carries
  // the token straight out through here.
  const m = mockCtx({});
  m.ctx.writeResource = () =>
    Promise.reject(new Error("driver refused config token=t0ken"));
  const f = stubFetch(() => jsonResponse({ results: [DEV()] }));
  let err: Error;
  try {
    err = await runExpectingThrow(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(
    err.message.includes("t0ken"),
    false,
    `write error leaked the token: ${err.message}`,
  );
  assertEquals(err.message.includes("[REDACTED]"), true);
});

// ---------------------------------------------------------------------------
// abort signals — the timeout is the only bound on a credential-bearing call
// ---------------------------------------------------------------------------

Deno.test("signals: a context with no signal does not crash the sync", async () => {
  // `AbortSignal.any([ctx.signal, timeout])` is a TypeError when ctx.signal is
  // undefined, and ctx.signal is typed optional and genuinely absent in
  // reduced harnesses. The whole run died before the first fetch, taking the
  // timeout — the only bound on a token-bearing request — with it.
  const m = mockCtx({});
  // deno-lint-ignore no-explicit-any
  delete (m.ctx as any).signal;
  const f = stubFetch(() => jsonResponse({ results: [DEV()] }));
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(
    m.written.filter((w) => w.spec === "device").length,
    1,
    "a signal-less context must still complete a sync",
  );
});

Deno.test("signals: timeoutSec cuts a long Retry-After wait short and is not a cancellation", async () => {
  // The retry sleep listened to ctx.signal only, so `timeoutSec: 1` against a
  // server sending `Retry-After: 5` still sat in a five-second wait, three
  // times over, after the configured timeout had already fired. timeoutSec
  // bounded one fetch, never the call.
  const m = mockCtx({ timeoutSec: 1 });
  const f = stubFetch(() =>
    Promise.resolve(
      new Response("busy", { status: 503, headers: { "Retry-After": "5" } }),
    )
  );
  const started = Date.now();
  let err: Error;
  try {
    err = await runExpectingThrow(m.ctx);
  } finally {
    f.restore();
  }
  const elapsed = Date.now() - started;
  assertEquals(
    elapsed < 3000,
    true,
    `timeoutSec 1 should abandon the retry wait in ~1s, took ${elapsed}ms`,
  );
  assertEquals(
    err.message.includes("timed out"),
    true,
    `a fired timeout must be reported as a timeout: ${err.message}`,
  );
  assertEquals(
    err.message.includes("CANCELLED"),
    false,
    "a timeout is not the caller cancelling the run",
  );
});

// ---------------------------------------------------------------------------
// response narrowing — absent must stay distinguishable from a value, and one
// bad element must not abandon a run that already wrote most of its records
// ---------------------------------------------------------------------------

Deno.test("narrowing: non-object array entries are skipped, not fatal", async () => {
  // The array elements were blind-cast to Record<string, unknown>, so a null
  // reached `raw.id` and threw a context-free TypeError out of the middle of
  // the loop — losing every device after it.
  const m = mockCtx({});
  const f = stubFetch(() =>
    jsonResponse({
      results: [
        null,
        "not-a-device",
        42,
        [],
        DEV({ id: "aa:bb:cc:dd:ee:01", name: "a" }),
        DEV({ id: "aa:bb:cc:dd:ee:02", name: "b" }),
      ],
    })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(
    m.written.filter((w) => w.spec === "device").length,
    2,
    "the well-formed devices after a bad entry must still be written",
  );
  assertEquals(
    m.warnings.some((w) => w.includes("non-object")),
    true,
    "skipping malformed entries must be reported, not silent",
  );
});

Deno.test("narrowing: absent traffic counters are omitted, not written as zero", async () => {
  // `Number(raw.totalDownload ?? 0)` turned "the MSP did not send this field"
  // into the measurement "this device moved zero bytes".
  const m = mockCtx({});
  const f = stubFetch(() =>
    jsonResponse({
      results: [
        DEV({ id: "aa:bb:cc:dd:ee:01", name: "quiet" }),
        DEV({
          id: "aa:bb:cc:dd:ee:02",
          name: "busy",
          totalDownload: 123,
          totalUpload: 456,
        }),
      ],
    })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const devices = m.written.filter((w) => w.spec === "device");
  const quiet = devices.find((d) => d.data.name === "quiet")!.data;
  const busy = devices.find((d) => d.data.name === "busy")!.data;
  assertEquals(
    "totalDownload" in quiet,
    false,
    "an absent counter must leave the key off the record entirely",
  );
  assertEquals("totalUpload" in quiet, false);
  assertEquals(busy.totalDownload, 123, "a real counter must survive");
  assertEquals(busy.totalUpload, 456);
});

Deno.test('narrowing: the JSON string "false" is not a truthy boolean', async () => {
  // `Boolean(raw.online)` on the string "false" is true — a device reported
  // as down would have been recorded, tagged, and counted as up.
  const m = mockCtx({});
  const f = stubFetch(() =>
    jsonResponse({
      results: [
        DEV({ id: "aa:bb:cc:dd:ee:01", name: "down", online: "false" }),
      ],
    })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const device = m.written.find((w) => w.spec === "device")!.data;
  assertEquals(device.online, false, '"false" must not read as online');
  const inv = m.written.find((w) => w.spec === "inventory")!.data;
  assertEquals(inv.online, 0);
});

Deno.test("narrowing: a device with no online field is recorded offline and reported", async () => {
  // The deliberate exception to "absent stays absent": `online` remains a
  // required boolean because every consumer asks a two-state question, and
  // reading an absent presence signal as offline fails loudly rather than
  // silently green. The warning is what makes that loud failure diagnosable.
  const m = mockCtx({});
  const raw = DEV({ id: "aa:bb:cc:dd:ee:01", name: "mystery" });
  delete raw.online;
  const f = stubFetch(() => jsonResponse({ results: [raw] }));
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(m.written.find((w) => w.spec === "device")!.data.online, false);
  assertEquals(
    m.warnings.some((w) => w.includes("`online`")),
    true,
    "an absent presence signal must name itself in the log",
  );
});

// ---------------------------------------------------------------------------
// operator-config matching — the same class `foldNetwork` was written to fix,
// still live in the two matchers that were not audited at the time
// ---------------------------------------------------------------------------

Deno.test("apiManaged: matches case- and whitespace-insensitively", async () => {
  // `g.apiManaged.includes(machineKey(...))` was an exact comparison while its
  // sibling `isExcluded` folded both sides. `apiManaged: [nas]` against a box
  // the firewall names `NAS` left it an SSH fleet candidate — so the generated
  // fleet SSHes a host that is supposed to be reached through its own API,
  // the exact outcome the option exists to prevent.
  const m = mockCtx({ apiManaged: ["  NaS "] });
  const f = stubFetch(() =>
    jsonResponse({
      results: [
        DEV({
          id: "aa:bb:cc:dd:ee:01",
          name: "nas-eth",
          deviceType: "desktop",
        }),
      ],
    })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const device = m.written.find((w) => w.spec === "device")!.data;
  assertEquals(device.tier, "deep", "precondition: this is a deep-tier device");
  assertEquals(
    device.sshCandidate,
    false,
    "an apiManaged machine must never be an SSH fleet candidate",
  );
  assertEquals(machinesWritten(m.written)[0].sshCandidate, false);
});

Deno.test("dependencies: keys match case- and whitespace-insensitively", async () => {
  // An exact object-key lookup meant `{App-Server: nas}` against machine
  // `app-server` produced no edge, and downstream alerting lost the
  // suppression it needed to tell a consequence from a separate incident.
  const m = mockCtx({ dependencies: { "App-Server": "nas" } });
  const f = stubFetch(() =>
    jsonResponse({
      results: [DEV({ id: "aa:bb:cc:dd:ee:01", name: "app-server-eth" })],
    })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const machine = machinesWritten(m.written)[0];
  assertEquals(machine.name, "app-server");
  assertEquals(
    machine.dependsOn,
    "nas",
    "the configured dependency edge must survive a case difference",
  );
});

Deno.test("dependencies: two keys folding to one machine are reported, not silently merged", async () => {
  const m = mockCtx({ dependencies: { nas: "ups", NAS: "other-ups" } });
  const f = stubFetch(() => jsonResponse({ results: [DEV({ name: "nas" })] }));
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(
    m.warnings.some((w) => w.includes("more than one entry")),
    true,
    "an ambiguous dependency config must not be resolved by iteration order",
  );
});

// ---------------------------------------------------------------------------
// resource identity — a name collision is not a warning, it is one record
// overwriting another, which deletes a host from the inventory for good
// ---------------------------------------------------------------------------

Deno.test("identity: two devices whose identity tuples differ get different resource names", async () => {
  // The identity used to be hashed as `${gid}|${mac}|${id}`, which is not an
  // encoding of a tuple: the separator is a legal character in an MSP id, so
  // distinct identities render to the same string. These two do --
  //   ("a",     "m", "b|m|c")  ->  "a|m|b|m|c"
  //   ("a|m|b", "m", "c")      ->  "a|m|b|m|c"
  // -- and the slug is "m" for both, so the OLD code gave both devices the
  // resource name `device-m-<same fnv1a>` and the second silently overwrote
  // the first. No birthday luck required; this is the encoding being wrong.
  const m = mockCtx({});
  const f = stubFetch(() =>
    jsonResponse({
      results: [
        DEV({ gid: "a", mac: "m", id: "b|m|c", name: "one" }),
        DEV({ gid: "a|m|b", mac: "m", id: "c", name: "two" }),
      ],
    })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const names = m.written.filter((w) => w.spec === "device").map((w) => w.name);
  assertEquals(names.length, 2, "precondition: both devices were written");
  assertEquals(
    new Set(names).size,
    2,
    `two distinct devices shared one resource name: ${names.join(", ")}`,
  );
});

Deno.test("identity: a device named like a disambiguated machine key does not merge into it", async () => {
  // The duplicate-machine key was `${strippedName}-${last4OfMac}`. `-` is
  // legal -- and ubiquitous -- in a Firewalla device name, so a real device
  // the firewall reports as `purifier-ee22` was the same key as the
  // disambiguated second `purifier` whose MAC ends ee:22. The two collapsed
  // into a single machine holding both hosts' interfaces, and one host left
  // the SSH fleet.
  const m = mockCtx({});
  const f = stubFetch(() =>
    jsonResponse({
      results: [
        DEV({
          id: "aa:bb:cc:dd:ee:11",
          mac: "aa:bb:cc:dd:ee:11",
          name: "purifier",
        }),
        DEV({
          id: "aa:bb:cc:dd:ee:22",
          mac: "aa:bb:cc:dd:ee:22",
          name: "purifier",
        }),
        DEV({
          id: "aa:bb:cc:dd:ee:33",
          mac: "aa:bb:cc:dd:ee:33",
          name: "purifier-ee22",
        }),
      ],
    })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const machines = machinesWritten(m.written);
  assertEquals(machines.length, 3, "three hosts must be three machines");
  assertEquals(
    machines.every((x) => x.interfaceCount === 1),
    true,
    "no machine may end up holding another host's interface",
  );
  const names = m.written.filter((w) => w.spec === "machine").map((w) =>
    w.name
  );
  assertEquals(new Set(names).size, 3, "machine resource names must be unique");
});

Deno.test("identity: an absurdly long MSP id does not produce an unbounded resource name", async () => {
  // The slug was interpolated straight from the MSP's id. It is a readability
  // affordance -- the digest beside it carries the identity -- so it is
  // bounded now that it no longer has to be unique on its own.
  const m = mockCtx({});
  const long = "z".repeat(5000);
  const f = stubFetch(() =>
    jsonResponse({ results: [DEV({ id: long, mac: long, name: "big" })] })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const name = m.written.find((w) => w.spec === "device")!.name;
  assertEquals(
    name.length < 128,
    true,
    `resource name is unbounded (${name.length} chars)`,
  );
});

// ---------------------------------------------------------------------------
// machine addresses — absent must stay distinguishable from blank, on the
// field the generated SSH fleet actually connects to
// ---------------------------------------------------------------------------

Deno.test("machine schema: primaryIp and interface ip are optional", () => {
  // The old contract REQUIRED both, which is why the sync backfilled `""`.
  const machine = {
    name: "host",
    deviceType: "desktop",
    macVendor: "v",
    tier: "deep",
    sshCandidate: true,
    online: false,
    networks: ["Root"],
    interfaces: [{
      name: "host",
      mac: "aa:bb:cc:dd:ee:ff",
      network: "Root",
      online: false,
    }],
    interfaceCount: 1,
  };
  assertEquals(
    model.resources.machine.schema.safeParse(machine).success,
    true,
    "a machine with no known address must be a valid record",
  );
});

Deno.test("machine: an address the firewall never reported is omitted, not blank", async () => {
  // `primaryIp: device.ip ?? ""` made "the firewall has no address for this
  // host" indistinguishable from "the address is the empty string", on the one
  // field a generated SSH fleet dials. A consumer that checks for the key now
  // gets the truth; one that read `""` got a fleet entry pointing nowhere.
  const m = mockCtx({});
  const f = stubFetch(() =>
    jsonResponse({ results: [DEV({ name: "noaddr", deviceType: "desktop" })] })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const machine = machinesWritten(m.written)[0];
  assertEquals(
    "primaryIp" in machine,
    false,
    `an unknown address must leave the key off: ${JSON.stringify(machine)}`,
  );
  const iface = (machine.interfaces as Array<Record<string, unknown>>)[0];
  assertEquals("ip" in iface, false, "same rule on the interface list");
  assertEquals(
    model.resources.machine.schema.safeParse(machine).success,
    true,
    "the record the sync writes must satisfy its own schema",
  );
});

// ---------------------------------------------------------------------------
// exclude — the option says "never treated as machines" and now means it
// ---------------------------------------------------------------------------

Deno.test("exclude: an excluded device is not aggregated into a machine", async () => {
  // `exclude` only switched off SSH candidacy. The dock was still collapsed
  // into a machine, still written as a `machine` resource, and still counted
  // in `inventory.machines` -- so the roll-up reported machines the operator
  // had explicitly declared were not machines.
  const m = mockCtx({ exclude: ["dock-*"] });
  const f = stubFetch(() =>
    jsonResponse({
      results: [
        DEV({
          id: "aa:bb:cc:dd:ee:11",
          mac: "aa:bb:cc:dd:ee:11",
          name: "dock-desk",
          deviceType: "desktop",
          ip: "203.0.113.11",
        }),
        DEV({
          id: "aa:bb:cc:dd:ee:22",
          mac: "aa:bb:cc:dd:ee:22",
          name: "workstation",
          deviceType: "desktop",
          ip: "203.0.113.22",
        }),
      ],
    })
  );
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const machines = machinesWritten(m.written);
  assertEquals(machines.length, 1, "the dock must not become a machine");
  assertEquals(machines[0].name, "workstation");
  const inv = m.written.find((w) => w.spec === "inventory")!.data;
  assertEquals(inv.machines, 1, "the roll-up must not count excluded devices");
  assertEquals(inv.excluded, 1);
  // Still reported as a device, which is the point of the `excluded` flag.
  const dock = m.written
    .filter((w) => w.spec === "device")
    .find((w) => w.data.name === "dock-desk");
  assertEquals(dock !== undefined, true, "the dock must still be a device");
  assertEquals(dock!.data.excluded, true);
});

// ---------------------------------------------------------------------------
// excludeNetworks — "not stored" has to hold for records stored BEFORE the
// network was excluded, or it is not a scope control
// ---------------------------------------------------------------------------

Deno.test("excludeNetworks: previously stored records are purged even on a filtered run", async () => {
  // Excluding a network stopped new writes and did nothing about what was
  // already there. Ordinary pruning was never going to reach it either: a
  // filtered run does not prune at all, and a shrink-guarded full run keeps
  // everything by design. The operator read "not collected, not counted, not
  // stored" and kept a guest VLAN in the datastore indefinitely.
  //
  // This run is `network`-filtered, so the prune pass is skipped entirely --
  // every deletion below comes from the purge, which is the point.
  const m = mockCtx({ excludeNetworks: ["Guest"] }, {
    stored: {
      "device-old-11111111": { name: "guest-tv", network: "guest" },
      "machine-old-22222222": { name: "guest-tv", networks: ["Guest"] },
      "machine-mixed-33333333": { name: "nas", networks: ["Guest", "Root"] },
      "device-keep-44444444": { name: "server", network: "Root" },
      inventory: { total: 4 },
    },
  });
  const f = stubFetch(() =>
    jsonResponse({ results: [DEV({ name: "server", network: "Root" })] })
  );
  try {
    await run(m.ctx, { network: "Root" });
  } finally {
    f.restore();
  }
  assertEquals(
    m.deleted.sort(),
    ["device-old-11111111", "machine-old-22222222"],
    "records wholly on an excluded network must go, and nothing else",
  );
});

Deno.test("excludeNetworks: the purge does not run when nothing is excluded", async () => {
  // The purge authorises deletions outside the prune guards, so it must be
  // inert unless the operator asked for it.
  const m = mockCtx({}, {
    stored: {
      "device-old-11111111": { name: "guest-tv", network: "guest" },
      inventory: { total: 1 },
    },
  });
  const f = stubFetch(() =>
    jsonResponse({ results: [DEV({ name: "server", network: "Root" })] })
  );
  try {
    await run(m.ctx, { network: "Root" });
  } finally {
    f.restore();
  }
  assertEquals(
    m.deleted,
    [],
    "a filtered run with no exclusions deletes nothing",
  );
});

Deno.test("the excluded-network purge is a named, skippable check", () => {
  const check = model.checks?.["excluded-networks-are-purged-from-storage"];
  assertEquals(
    typeof check,
    "object",
    "the second destructive path must be nameable and skippable too",
  );
  assertEquals(check!.appliesTo.includes("syncDevices"), true);
});

// ---------------------------------------------------------------------------
// abort classification — a cancelled run must not be reported as a broken MSP
// ---------------------------------------------------------------------------

/**
 * A Response whose body rejects mid-read, aborting `controller` as it does so
 * -- the shape of a caller cancelling, or `timeoutSec` firing, while the body
 * is still arriving.
 */
function abortingBody(controller: AbortController, status = 200): Response {
  const body = new ReadableStream({
    pull() {
      controller.abort();
      return Promise.reject(new DOMException("aborted", "AbortError"));
    },
  });
  return new Response(body, {
    status,
    headers: { "content-type": "application/json" },
  });
}

Deno.test("abort: cancellation while reading the body is not reported as bad JSON", async () => {
  // Only the initial fetch catch told cancellation from failure. A body read
  // cut short went to `response.json()`'s catch and came out as "returned a
  // response that could not be parsed as JSON" -- sending the operator to look
  // at the vendor for a run their own workflow had cancelled.
  const m = mockCtx({});
  const ac = new AbortController();
  m.ctx.signal = ac.signal;
  const f = stubFetch(() => Promise.resolve(abortingBody(ac)));
  let err: Error;
  try {
    err = await runExpectingThrow(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(
    err.message.includes("CANCELLED"),
    true,
    `a cancelled body read must be reported as cancellation: ${err.message}`,
  );
  assertEquals(
    err.message.includes("could not be parsed as JSON"),
    false,
    `cancellation misreported as a parse failure: ${err.message}`,
  );
});

Deno.test("abort: cancellation while reading an HTTP error body is not swallowed", async () => {
  // The error path read the body with `.catch(() => "")`, so a cancellation
  // here vanished completely and the run was reported as an HTTP failure with
  // a blank detail. Same class as the JSON path, different call site.
  const m = mockCtx({});
  const ac = new AbortController();
  m.ctx.signal = ac.signal;
  const f = stubFetch(() => Promise.resolve(abortingBody(ac, 502)));
  let err: Error;
  try {
    err = await runExpectingThrow(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(
    err.message.includes("CANCELLED"),
    true,
    `a cancelled error-body read must be reported as such: ${err.message}`,
  );
  assertEquals(
    err.message.includes("502"),
    true,
    "the status already observed is still worth reporting",
  );
});

// ---------------------------------------------------------------------------
// Retry-After — the README says it is honoured, so both standard forms must be
// ---------------------------------------------------------------------------

Deno.test("Retry-After: an HTTP-date is honoured, not silently ignored", async () => {
  // `Number(header)` is NaN for the date form, so the code fell through to
  // exponential backoff (500ms on the first attempt) while the README claimed
  // the header was honoured -- documentation describing an unreachable branch.
  // A date ~2s out must therefore produce a wait well past that 500ms.
  const m = mockCtx({ timeoutSec: 30 });
  let attempt = 0;
  const f = stubFetch(() => {
    attempt++;
    if (attempt === 1) {
      return Promise.resolve(
        new Response("busy", {
          status: 503,
          headers: {
            "Retry-After": new Date(Date.now() + 2000).toUTCString(),
          },
        }),
      );
    }
    return jsonResponse({ results: [DEV()] });
  });
  const started = Date.now();
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  const elapsed = Date.now() - started;
  assertEquals(attempt, 2, "precondition: the 503 was retried");
  assertEquals(
    elapsed >= 900,
    true,
    `HTTP-date Retry-After ignored; retried after only ${elapsed}ms`,
  );
  assertEquals(
    elapsed < 6000,
    true,
    `the 5s cap must still apply, waited ${elapsed}ms`,
  );
});

Deno.test("Retry-After: an unparseable value falls back to backoff rather than throwing", async () => {
  const m = mockCtx({ timeoutSec: 30 });
  let attempt = 0;
  const f = stubFetch(() => {
    attempt++;
    if (attempt === 1) {
      return Promise.resolve(
        new Response("busy", {
          status: 503,
          headers: { "Retry-After": "soon-ish" },
        }),
      );
    }
    return jsonResponse({ results: [DEV()] });
  });
  const started = Date.now();
  try {
    await run(m.ctx);
  } finally {
    f.restore();
  }
  assertEquals(attempt, 2);
  assertEquals(Date.now() - started < 2000, true, "backoff, not a long wait");
});
