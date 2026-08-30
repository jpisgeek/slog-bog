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
    totalDownload: 0,
    totalUpload: 0,
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
