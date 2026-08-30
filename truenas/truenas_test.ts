/**
 * Tests for @jpisgeek/truenas.
 *
 * Exported surface only — this file is not in the manifest, so it does not
 * move the content hash the security review is bound to.
 *
 * `baseUrl` is validated at run time (not as a zod object refinement) because
 * swamp calls `.partial()` on globalArguments and zod 4 refuses that on an
 * object carrying refinements — an object-level `superRefine` here silently
 * broke every discover(). These tests therefore drive validation through
 * `discover`, which is also how a consumer hits it. Each rejection happens
 * before any socket is opened.
 *
 * The suite makes no network calls. The behavioural tests below swap
 * `globalThis.WebSocket` for an in-memory fake that speaks JSON-RPC back at
 * the model, which is the only way to reach the parts of `discover` that
 * matter most — the prune and the raw-payload contract — from the exported
 * surface. The fake also records every frame written to the socket, so a
 * test can assert the API key was never put on the wire rather than merely
 * assert on an error message.
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { __testOnly, model } from "./truenas.ts";

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type Responder = (method: string, params: unknown[]) => unknown;

/** A healthy NAS: one pool, one disk, one dismissed alert, one live cert. */
const healthyResponder: Responder = (method) => {
  switch (method) {
    case "auth.login_with_api_key":
      return true;
    case "system.info":
      return {
        hostname: "nas",
        version: "25.10.6",
        model: "x86",
        cores: 8,
        physmem: 1024,
        uptime_seconds: 60,
        loadavg: [0, 0, 0],
      };
    case "pool.query":
      return [{
        name: "tank",
        id: 1,
        status: "ONLINE",
        healthy: true,
        allocated: 50,
        free: 50,
        fragmentation: "3%",
      }];
    case "disk.query":
      return [{
        devname: "sda",
        identifier: "{serial}ABC",
        serial: "ABC",
        model: "WD",
        size: 100,
        type: "HDD",
        pool: "tank",
      }];
    case "alert.list":
      return [{
        uuid: "u1",
        klass: "CertificateIsExpiring",
        level: "WARNING",
        formatted: "expiring",
        dismissed: true,
      }];
    case "certificate.query":
      return [{
        id: 1,
        name: "cert",
        common: "example.com",
        until: "2099-01-01T00:00:00Z",
      }];
    default:
      throw new Error(`unexpected RPC method ${method}`);
  }
};

/** Swap in one canned reply, keeping the rest of the healthy NAS intact. */
const respondWith =
  (over: Record<string, unknown>): Responder => (method, params) =>
    method in over ? over[method] : healthyResponder(method, params);

/**
 * Marker a responder returns to make the fake answer with a JSON-RPC *error*
 * frame rather than a result. Without this the suite could only reach the
 * `result` branch of `onmessage`, and the two behaviours that live on the
 * error branch — the TrueNAS 27 hint on a failed auth, and the bound on a
 * remote error message — would have no way to be exercised at all.
 */
const rpcError = (code: number, message: string) => ({
  __rpcError: { code, message },
});

/**
 * Marker a responder returns to put an ARBITRARY frame on the wire instead of
 * a well-formed JSON-RPC envelope.
 *
 * The fake used to be incapable of producing a malformed frame at all, which
 * is precisely why the envelope handling went unvalidated for so long: every
 * test drove it through frames the fake itself had built correctly. `make`
 * receives the request id so a test can send a reply that is wrong in exactly
 * one way -- a string id, an `error: 0`, a bare `null` -- while everything
 * else about the exchange stays realistic.
 */
const rawFrame = (make: (id: number) => unknown) => ({ __rawFrame: make });

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static responder: Responder = healthyResponder;
  /** When false, the socket never opens on its own; the test drives onopen. */
  static autoOpen = true;

  onopen: (() => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  /** Every frame written to the wire, verbatim. */
  sent: string[] = [];

  constructor(public url: string) {
    FakeWebSocket.instances.push(this);
    if (FakeWebSocket.autoOpen) queueMicrotask(() => this.onopen?.());
  }

  send(data: string) {
    this.sent.push(data);
    const msg = JSON.parse(data) as {
      id: number;
      method: string;
      params: unknown[];
    };
    const result = FakeWebSocket.responder(msg.method, msg.params);
    const raw = result && typeof result === "object"
      ? (result as { __rawFrame?: (id: number) => unknown }).__rawFrame
      : undefined;
    if (raw) {
      const frame = JSON.stringify(raw(msg.id));
      queueMicrotask(() =>
        this.onmessage?.({ data: frame === undefined ? "undefined" : frame })
      );
      return;
    }
    const err = result && typeof result === "object"
      ? (result as { __rpcError?: { code: number; message: string } })
        .__rpcError
      : undefined;
    queueMicrotask(() =>
      this.onmessage?.({
        data: JSON.stringify(
          err
            ? { jsonrpc: "2.0", id: msg.id, error: err }
            : { jsonrpc: "2.0", id: msg.id, result },
        ),
      })
    );
  }

  close() {
    this.onclose?.();
  }
}

async function withFakeWs<T>(
  fn: () => Promise<T>,
  opts: { responder?: Responder; autoOpen?: boolean } = {},
): Promise<T> {
  const real = globalThis.WebSocket;
  FakeWebSocket.instances = [];
  FakeWebSocket.responder = opts.responder ?? healthyResponder;
  FakeWebSocket.autoOpen = opts.autoOpen ?? true;
  globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
  try {
    return await fn();
  } finally {
    globalThis.WebSocket = real;
  }
}

interface Recorder {
  written: Array<{ type: string; name: string; data: Record<string, unknown> }>;
  deleted: string[];
  /** Every log line the model emitted, so a test can assert on the ones the
   * operator is meant to see rather than only on thrown errors. */
  info: Array<{ msg: string; props: Record<string, unknown> }>;
  warnings: Array<{ msg: string; props: Record<string, unknown> }>;
}

/** The host-supplied context object; the model types it structurally. */
// deno-lint-ignore no-explicit-any
type Ctx = any;

const ctxFor = (globalArgs: Record<string, unknown>, opts: {
  signal?: AbortSignal;
  existing?: string[];
  recorder?: Recorder;
} = {}): Ctx => ({
  signal: opts.signal ?? new AbortController().signal,
  globalArgs,
  modelType: "@jpisgeek/truenas",
  modelId: "test",
  logger: {
    info: (msg: string, props: Record<string, unknown> = {}) => {
      opts.recorder?.info.push({ msg, props });
    },
    warning: (msg: string, props: Record<string, unknown> = {}) => {
      opts.recorder?.warnings.push({ msg, props });
    },
  },
  writeResource: (
    type: string,
    name: string,
    data: Record<string, unknown>,
  ) => {
    opts.recorder?.written.push({ type, name, data });
    return Promise.resolve({});
  },
  dataRepository: {
    findAllForModel: () =>
      Promise.resolve((opts.existing ?? []).map((name) => ({ name }))),
    delete: (_t: string, _i: string, name: string) => {
      opts.recorder?.deleted.push(name);
      return Promise.resolve();
    },
  },
});

const recorder = (): Recorder => ({
  written: [],
  deleted: [],
  info: [],
  warnings: [],
});

const OK = { baseUrl: "https://nas.example.com", apiKey: "k" };

// ---------------------------------------------------------------------------
// baseUrl — credential-carrying transport
// ---------------------------------------------------------------------------

Deno.test("baseUrl: rejects embedded credentials before connecting", async () => {
  await assertRejects(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, baseUrl: "https://user:pass@nas.example.com" }),
      ),
    Error,
    "must not embed credentials",
  );
});

Deno.test("baseUrl: rejects http:// unless explicitly opted in", async () => {
  await assertRejects(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, baseUrl: "http://nas.example.com" }),
      ),
    Error,
    "cleartext",
  );
});

Deno.test("baseUrl: rejects a non-http scheme", async () => {
  await assertRejects(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, baseUrl: "file:///etc/passwd" }),
      ),
    Error,
    "must start with http",
  );
});

Deno.test("baseUrl: rejects a malformed URL", async () => {
  await assertRejects(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, baseUrl: "https://" }),
      ),
    Error,
  );
});

// ---------------------------------------------------------------------------
// schema contracts
// ---------------------------------------------------------------------------

Deno.test("apiKey is required", () => {
  assertEquals(
    model.globalArguments.safeParse({ baseUrl: OK.baseUrl }).success,
    false,
  );
  assertEquals(model.globalArguments.safeParse(OK).success, true);
});

Deno.test("certificate schema: expiryKnown distinguishes 'no expiry' from a real number", () => {
  const cert = {
    name: "c",
    commonName: "example.com",
    notAfter: "",
    daysRemaining: -9999,
    expiryKnown: false,
    expiringSoon: false,
    expired: false,
  };
  assertEquals(
    model.resources.certificate.schema.safeParse(cert).success,
    true,
  );
  // Dropping the flag must fail — consumers rely on it to avoid reading the
  // -9999 sentinel as "expired 27 years ago".
  const { expiryKnown: _drop, ...without } = cert;
  assertEquals(
    model.resources.certificate.schema.safeParse(without).success,
    false,
  );
});

Deno.test("alert schema: silenced survives a UI dismissal", () => {
  const alert = {
    id: "1",
    klass: "CertificateIsExpiring",
    level: "WARNING",
    formatted: "cert expiring",
    dismissed: true,
    silenced: true,
  };
  assertEquals(model.resources.alert.schema.safeParse(alert).success, true);
  const { silenced: _drop, ...without } = alert;
  assertEquals(model.resources.alert.schema.safeParse(without).success, false);
});

Deno.test("summary schema: counts every category the dashboard gates on", () => {
  const summary = {
    hostname: "nas",
    version: "25.10",
    pools: 1,
    poolsUnhealthy: 0,
    // Rewritten, not deleted: this test asserted the pre-fix roll-up, which
    // had no way to say "capacity is unknown on N pools". A workflow gating on
    // the summary alone could not distinguish that from "capacity is fine".
    poolsCapacityUnknown: 0,
    // Rewritten again, same reason one level up: the roll-up could not say
    // "pool.query came back empty", which reads identically to "this box has
    // no unhealthy pools" in every other field.
    poolsReportedEmpty: false,
    disksReportedEmpty: false,
    discoveryDegraded: false,
    disks: 8,
    alerts: 0,
    alertsSilenced: 0,
    certificates: 2,
    certificatesExpiringSoon: 0,
    certificatesExpired: 0,
    certificatesWithoutExpiry: 0,
    syncedAt: new Date(0).toISOString(),
  };
  assertEquals(model.resources.summary.schema.safeParse(summary).success, true);
  const { poolsCapacityUnknown: _drop, ...without } = summary;
  assertEquals(
    model.resources.summary.schema.safeParse(without).success,
    false,
  );
  // Same guarantee for the degraded flag: a consumer must be able to rely on
  // it being there, or it is not something a gate can be written against.
  const { discoveryDegraded: _drop2, ...noFlag } = summary;
  assertEquals(model.resources.summary.schema.safeParse(noFlag).success, false);
});

Deno.test("discover is read-only: no method mutates TrueNAS", () => {
  assertEquals(Object.keys(model.methods), ["discover"]);
});

// ---------------------------------------------------------------------------
// cancellation — an aborted run must not put the API key on the wire
// ---------------------------------------------------------------------------

Deno.test("abort before connect: no socket is opened at all", async () => {
  const ac = new AbortController();
  ac.abort();
  await withFakeWs(async () => {
    await assertRejects(
      () =>
        model.methods.discover.execute(
          {},
          ctxFor({ ...OK, timeoutSec: 1 }, { signal: ac.signal }),
        ),
      Error,
      "aborted",
    );
    // The property, not the message: an already-aborted signal fires no
    // "abort" event, so before the guard the listener never ran and the
    // socket was opened (and then authenticated) for a cancelled run.
    assertEquals(FakeWebSocket.instances.length, 0);
  });
});

Deno.test("abort between connect and auth: the API key is never sent", async () => {
  const ac = new AbortController();
  const KEY = "top-secret-api-key";
  await withFakeWs(async () => {
    const p = model.methods.discover.execute(
      {},
      ctxFor(
        { ...OK, apiKey: KEY, timeoutSec: 1 },
        { signal: ac.signal },
      ),
    );
    // connect() runs synchronously up to its first await, so the socket
    // exists by now; drive it open by hand, then abort before the queued
    // continuation of `await connect(...)` gets to run the auth call.
    const ws = FakeWebSocket.instances[0];
    ws.onopen!();
    ac.abort();
    // Assert the wire first: if this regresses, the failure output names the
    // actual defect (the key was sent) rather than "expected a rejection".
    const err = await p.then(() => null, (e: Error) => e);
    assertEquals(ws.sent.join("").includes(KEY), false);
    assertEquals(ws.sent, []);
    assertEquals(err !== null && err.message.includes("aborted"), true);
    // The TrueNAS 27 hint is attached to auth failures, and a cancellation is
    // not one. Pointing an operator at a deprecated login call when they hit
    // Ctrl-C sends them to debug the wrong thing entirely.
    assertEquals(err!.message.includes("auth.login_ex"), false);
  }, { autoOpen: false });
});

// ---------------------------------------------------------------------------
// prune — "the box reported nothing" is not "nothing exists"
// ---------------------------------------------------------------------------

Deno.test("prune: stale records of a kind that IS reported are still deleted", async () => {
  const rec = recorder();
  await withFakeWs(() =>
    model.methods.discover.execute(
      {},
      ctxFor(OK, {
        recorder: rec,
        existing: ["pool-gone-11111111", "disk-gone-22222222", "summary"],
      }),
    )
  );
  // Protection must be conditional on an empty response, never blanket.
  assertEquals(rec.deleted.includes("pool-gone-11111111"), true);
  assertEquals(rec.deleted.includes("disk-gone-22222222"), true);
  assertEquals(rec.deleted.includes("summary"), false);
  const summary = rec.written.find((w) => w.type === "summary")!;
  assertEquals(summary.data.pools, 1);
  assertEquals(summary.data.disks, 1);
  assertEquals(summary.data.alertsSilenced, 1);
});

Deno.test("prune: an empty pool.query keeps existing pool records", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor(OK, {
          recorder: rec,
          existing: ["pool-tank-11111111", "alert-resolved-22222222"],
        }),
      ),
    { responder: respondWith({ "pool.query": [] }) },
  );
  // A pool still importing after a reboot answers []. Deleting the pool
  // record on that basis blanks the NAS during exactly the window a pool is
  // missing.
  assertEquals(rec.deleted.includes("pool-tank-11111111"), false);
  // ...but alerts are not protected: a resolved alert must still go.
  assertEquals(rec.deleted.includes("alert-resolved-22222222"), true);
});

Deno.test("prune: an empty disk.query keeps existing disk records", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor(OK, {
          recorder: rec,
          existing: ["disk-sda-11111111", "cert-old-22222222"],
        }),
      ),
    { responder: respondWith({ "disk.query": [] }) },
  );
  assertEquals(rec.deleted.includes("disk-sda-11111111"), false);
  assertEquals(rec.deleted.includes("cert-old-22222222"), true);
});

// ---------------------------------------------------------------------------
// raw payload contract — a renamed field must throw, not become a placeholder
// ---------------------------------------------------------------------------

Deno.test("certificate.query without an expiry field throws instead of writing notAfter:''", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      assertRejects(
        () =>
          model.methods.discover.execute(
            {},
            ctxFor(OK, { recorder: rec }),
          ),
        Error,
        "not_after",
      ),
    {
      responder: respondWith({
        "certificate.query": [{ id: 1, name: "cert", common: "example.com" }],
      }),
    },
  );
  // The consequence being prevented: silently recording every certificate as
  // "expiry unknown", which is indistinguishable from a cert two days out.
  assertEquals(rec.written.filter((w) => w.type === "certificate"), []);
  assertEquals(rec.written.filter((w) => w.type === "summary"), []);
});

Deno.test("certificate with a null expiry (a CSR) is still accepted", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "certificate.query": [{ id: 7, name: "csr", common: "x", until: null }],
      }),
    },
  );
  // The field is PRESENT and null, which is a real payload — tightening the
  // schema must not reject it. expiryKnown:false is the correct answer here.
  const cert = rec.written.find((w) => w.type === "certificate")!;
  assertEquals(cert.data.expiryKnown, false);
  const summary = rec.written.find((w) => w.type === "summary")!;
  assertEquals(summary.data.certificatesWithoutExpiry, 1);
});

Deno.test("disk.query without identifier or devname throws", async () => {
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK)),
        Error,
        "identifier",
      ),
    {
      responder: respondWith({
        "disk.query": [{ serial: "ABC", model: "WD", size: 100 }],
      }),
    },
  );
});

Deno.test("alert.list without any identity field throws", async () => {
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK)),
        Error,
        "uuid",
      ),
    {
      responder: respondWith({
        "alert.list": [{ klass: "K", level: "WARNING", formatted: "f" }],
      }),
    },
  );
});

// ---------------------------------------------------------------------------
// absent numerics — "TrueNAS did not say" must not read as "TrueNAS said zero"
// ---------------------------------------------------------------------------

Deno.test("pool without allocated/free: capacity reads unknown, not empty", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "pool.query": [{
          name: "tank",
          id: 1,
          status: "ONLINE",
          healthy: true,
          fragmentation: "3%",
        }],
      }),
    },
  );
  const pool = rec.written.find((w) => w.type === "pool")!;
  assertEquals(pool.data.capacityKnown, false);
  // The property, not the spelling: a capacity gate must not be able to read
  // this record as a pool with room. `usedPercent: 0` and `sizeBytes: 0` are
  // exactly what an empty-but-healthy pool looks like, which is what the
  // backfill produced for a pool whose fill level was in fact unreported.
  assertEquals(pool.data.usedPercent === 0, false);
  assertEquals(pool.data.sizeBytes === 0, false);
  assertEquals((pool.data.usedPercent as number) < 0, true);
  // ...and it is visible from the roll-up, for a workflow that only reads that.
  const summary = rec.written.find((w) => w.type === "summary")!;
  assertEquals(summary.data.poolsCapacityUnknown, 1);
});

Deno.test("pool with real capacity still computes usedPercent", async () => {
  const rec = recorder();
  await withFakeWs(() =>
    model.methods.discover.execute({}, ctxFor(OK, { recorder: rec }))
  );
  // Guards against over-tightening: the healthy NAS reports allocated 50 /
  // free 50, and that must still come through as a real 50%.
  const pool = rec.written.find((w) => w.type === "pool")!;
  assertEquals(pool.data.capacityKnown, true);
  assertEquals(pool.data.sizeBytes, 100);
  assertEquals(pool.data.usedPercent, 50);
  const summary = rec.written.find((w) => w.type === "summary")!;
  assertEquals(summary.data.poolsCapacityUnknown, 0);
});

Deno.test("system.info without cores/memory/uptime: absent uptime is not a fresh reboot", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "system.info": { hostname: "nas", version: "25.10.6", model: "x86" },
      }),
    },
  );
  const sys = rec.written.find((w) => w.type === "system")!;
  assertEquals(sys.data.metricsKnown, false);
  // A "rebooted in the last five minutes" gate reads uptimeSeconds. The
  // backfilled 0 made that gate fire on every run where TrueNAS simply left
  // the field out.
  assertEquals(sys.data.uptimeSeconds === 0, false);
  assertEquals(sys.data.cores === 0, false);
  assertEquals(sys.data.physmemBytes === 0, false);
});

Deno.test("disk without a size: sizeKnown false and sizeBytes is not zero", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "disk.query": [{
          devname: "sda",
          identifier: "{serial}ABC",
          serial: "ABC",
          model: "WD",
          type: "HDD",
          pool: "tank",
        }],
      }),
    },
  );
  const disk = rec.written.find((w) => w.type === "disk")!;
  assertEquals(disk.data.sizeKnown, false);
  assertEquals(disk.data.sizeBytes === 0, false);
});

// ---------------------------------------------------------------------------
// the TrueNAS 27 hint has to reach the path it was written for
// ---------------------------------------------------------------------------

Deno.test("auth rejection names the auth.login_with_api_key removal", async () => {
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    { responder: respondWith({ "auth.login_with_api_key": false }) },
  );
  // The warning that used to carry this ran only after system.info, i.e. only
  // once auth had already succeeded — so on the host it was written for it
  // never printed. Assert it is reachable from the failure itself.
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("auth.login_ex"), true);
  assertEquals(err!.message.includes("revoked"), true);
});

Deno.test("an RPC error on auth carries the removal hint alongside the remote message", async () => {
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "auth.login_with_api_key": rpcError(-32601, "Method does not exist"),
      }),
    },
  );
  // This is what a 27 host actually does: the method is gone, so the failure
  // arrives as an RPC error rather than a false result. Both halves must
  // survive — the remote message says what happened, the hint says why.
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("Method does not exist"), true);
  assertEquals(err!.message.includes("auth.login_ex"), true);
});

Deno.test("the hint is scoped to auth: a later RPC failure does not claim it", async () => {
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    { responder: respondWith({ "pool.query": rpcError(11, "pool is busy") }) },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("pool is busy"), true);
  assertEquals(err!.message.includes("auth.login_ex"), false);
});

// ---------------------------------------------------------------------------
// baseUrl -> wsUrl is built from the parsed URL, not pasted together
// ---------------------------------------------------------------------------

Deno.test("baseUrl: a query string is rejected before a socket opens", async () => {
  await withFakeWs(async () => {
    await assertRejects(
      () =>
        model.methods.discover.execute(
          {},
          ctxFor({ ...OK, baseUrl: "https://nas.example.com/?debug=1" }),
        ),
      Error,
      "query string or fragment",
    );
    // Concatenation used to turn this into
    // wss://nas.example.com/?debug=1/api/current — a URL that never reaches
    // the endpoint and copies whatever the operator typed after the ? into
    // the info log and every connection error on the way.
    assertEquals(FakeWebSocket.instances.length, 0);
  });
});

Deno.test("baseUrl: a fragment is rejected before a socket opens", async () => {
  await withFakeWs(async () => {
    await assertRejects(
      () =>
        model.methods.discover.execute(
          {},
          ctxFor({ ...OK, baseUrl: "https://nas.example.com/#frag" }),
        ),
      Error,
      "query string or fragment",
    );
    assertEquals(FakeWebSocket.instances.length, 0);
  });
});

Deno.test("the derived WebSocket URL addresses /api/current, port and subpath intact", async () => {
  for (
    const [baseUrl, expected] of [
      ["https://nas.example.com", "wss://nas.example.com/api/current"],
      ["https://nas.example.com/", "wss://nas.example.com/api/current"],
      [
        "https://nas.example.com:8443/truenas/",
        "wss://nas.example.com:8443/truenas/api/current",
      ],
    ] as const
  ) {
    await withFakeWs(async () => {
      await model.methods.discover.execute({}, ctxFor({ ...OK, baseUrl }));
      // Rebuilding from the parsed URL must not lose the port or a
      // reverse-proxied subpath, and must always land on /api/current.
      assertEquals(FakeWebSocket.instances[0].url, expected);
      assertEquals(
        new URL(FakeWebSocket.instances[0].url).pathname.endsWith(
          "/api/current",
        ),
        true,
      );
    });
  }
});

// ---------------------------------------------------------------------------
// remote text reaching an error message is bounded
// ---------------------------------------------------------------------------

Deno.test("a non-array result is previewed, not pasted whole into the error", async () => {
  const huge = "x".repeat(5000);
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    { responder: respondWith({ "pool.query": { detail: huge } }) },
  );
  assertEquals(err !== null, true);
  // The whole payload used to be JSON.stringify'd into the message verbatim,
  // so an unbounded amount of remote text went wherever the throw was logged.
  assertEquals(err!.message.length < 500, true);
  assertEquals(err!.message.includes(huge), false);
  // Truncated, not redacted: the type and the leading text still identify it.
  assertEquals(err!.message.includes("object"), true);
  assertEquals(err!.message.includes("detail"), true);
  assertEquals(err!.message.includes("truncated"), true);
});

Deno.test("an oversized RPC error message is bounded the same way", async () => {
  const huge = "y".repeat(5000);
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    { responder: respondWith({ "pool.query": rpcError(11, huge) }) },
  );
  // Same class, second instance: remote free text on the RPC error branch.
  assertEquals(err !== null, true);
  assertEquals(err!.message.length < 500, true);
  assertEquals(err!.message.includes("truncated"), true);
  assertEquals(err!.message.startsWith("TrueNAS RPC error 11:"), true);
});

// ---------------------------------------------------------------------------
// allowedHosts - the API key does not go to a host that was not pinned
// (block 2). The pin is optional; when set it is enforced without exception,
// and the reasoning for it not being mandatory is on assertHostAllowed().
// ---------------------------------------------------------------------------

Deno.test("allowedHosts: an unpinned host is refused before a socket opens", async () => {
  const KEY = "an-api-key-long-enough-to-be-real";
  await withFakeWs(async () => {
    await assertRejects(
      () =>
        model.methods.discover.execute(
          {},
          ctxFor({
            baseUrl: "https://typo.example.com",
            apiKey: KEY,
            allowedHosts: ["nas.example.com"],
          }),
        ),
      Error,
      "not in allowedHosts",
    );
    // The property, not the message: nothing was opened, so nothing was
    // authenticated. A check that ran after connect would still have put the
    // key on the wire to the wrong host.
    assertEquals(FakeWebSocket.instances.length, 0);
  });
});

Deno.test("allowedHosts: a pinned host still connects", async () => {
  await withFakeWs(async () => {
    await model.methods.discover.execute(
      {},
      ctxFor({ ...OK, allowedHosts: ["nas.example.com"] }),
    );
    assertEquals(
      FakeWebSocket.instances[0].url,
      "wss://nas.example.com/api/current",
    );
  });
});

Deno.test("allowedHosts: a port in the pin is matched, and a wrong port is not", async () => {
  await withFakeWs(async () => {
    await model.methods.discover.execute(
      {},
      ctxFor({
        ...OK,
        baseUrl: "https://nas.example.com:8443",
        allowedHosts: ["nas.example.com:8443"],
      }),
    );
    assertEquals(FakeWebSocket.instances.length, 1);
  });
  await withFakeWs(async () => {
    await assertRejects(
      () =>
        model.methods.discover.execute(
          {},
          ctxFor({
            ...OK,
            baseUrl: "https://nas.example.com:9999",
            allowedHosts: ["nas.example.com:8443"],
          }),
        ),
      Error,
      "not in allowedHosts",
    );
    assertEquals(FakeWebSocket.instances.length, 0);
  });
});

Deno.test("allowedHosts: a pin that could never match is a configuration error, not a silent deny", async () => {
  for (const bad of ["https://nas.example.com", "*.example.com", "nas/x"]) {
    await withFakeWs(async () => {
      const err = await model.methods.discover.execute(
        {},
        ctxFor({ ...OK, allowedHosts: [bad] }),
      ).then(() => null, (e: Error) => e);
      // A malformed pin must say it is malformed. Reported as an ordinary
      // "host is not in allowedHosts" it looks like the operator pinned the
      // wrong host, and they go and edit baseUrl instead of the pin.
      assertEquals(err !== null, true);
      assertEquals(err!.message.includes("bare host or host:port"), true);
      assertEquals(FakeWebSocket.instances.length, 0);
    });
  }
});

// ---------------------------------------------------------------------------
// remote text: bounded was not enough - it must also be key-redacted and
// screened, everywhere it lands (block 4, and the hardening under the
// operator-decision on stored alert text)
// ---------------------------------------------------------------------------

// Built with fromCharCode rather than written literally: this file has to stay
// free of raw control bytes, which is one of the things the identifier scan
// and the security review both check.
const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);
const NUL = String.fromCharCode(0x00);
const US = String.fromCharCode(0x1f);
const RLO = String.fromCharCode(0x202e);
const POP = String.fromCharCode(0x202c);
const ZWSP = String.fromCharCode(0x200b);
// deno-lint-ignore no-control-regex
const CONTROL_RE = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f]");
const INVISIBLE_RE = new RegExp(
  "[\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069\\ufeff]",
);

Deno.test("an RPC error that echoes the API key does not carry it into the thrown error", async () => {
  const KEY = "tn-01-abcdefghijklmnopqrstuvwxyz0123456789";
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, apiKey: KEY }),
      ).then(() => null, (e: Error) => e),
    {
      responder: respondWith({
        "auth.login_with_api_key": rpcError(
          22,
          `Invalid API key: ${KEY} rejected by validator`,
        ),
      }),
    },
  );
  assertEquals(err !== null, true);
  // auth.login_with_api_key takes the key as its ONLY argument, and
  // middlewared error prose echoes the argument that failed validation. This
  // error is thrown out of discover() and lands in swamp's log, where the
  // README promises the key never appears.
  assertEquals(err!.message.includes(KEY), false);
  assertEquals(err!.message.includes("[REDACTED]"), true);
  // Still diagnosable: the surrounding words survive.
  assertEquals(err!.message.includes("Invalid API key"), true);
});

Deno.test("control and bidi characters in an RPC error never reach the thrown message", async () => {
  const nasty =
    `before${ESC}]0;pwned${BEL} ${RLO}middle${POP} after${ZWSP}${NUL}end`;
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    { responder: respondWith({ "pool.query": rpcError(11, nasty) }) },
  );
  assertEquals(err !== null, true);
  // The property: nothing in this message can drive a terminal or reorder
  // what a human reads. Bounding the text addressed neither.
  assertEquals(CONTROL_RE.test(err!.message), false);
  assertEquals(INVISIBLE_RE.test(err!.message), false);
  assertEquals(err!.message.includes("middle"), true);
});

Deno.test("stored alert text is screened and bounded, not stored as the box wrote it", async () => {
  const rec = recorder();
  const huge = "z".repeat(20_000);
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "alert.list": [{
          uuid: "u1",
          klass: `Cert${ZWSP}Class`,
          level: `WARN${RLO}ING`,
          formatted: `${ESC}]0;title${BEL}alert body ${huge}`,
          dismissed: false,
        }],
      }),
    },
  );
  const alert = rec.written.find((w) => w.type === "alert")!;
  const formatted = alert.data.formatted as string;
  // lifetime is "infinite", so anything unbounded here is unbounded forever.
  assertEquals(formatted.length < 4300, true);
  assertEquals(CONTROL_RE.test(formatted), false);
  assertEquals(formatted.includes("alert body"), true);
  // klass and level are also TAGS, i.e. selectors: an invisible character in
  // one changes what the operator believes they selected.
  assertEquals(INVISIBLE_RE.test(alert.data.klass as string), false);
  assertEquals(INVISIBLE_RE.test(alert.data.level as string), false);
});

// ---------------------------------------------------------------------------
// raw schemas strip undeclared keys instead of retaining them (block 6)
// ---------------------------------------------------------------------------

Deno.test("raw schemas accept an enriched payload but do not retain the extra fields", () => {
  const enriched = {
    name: "tank",
    id: 1,
    status: "ONLINE",
    healthy: true,
    allocated: 50,
    free: 50,
    fragmentation: "3%",
    // A field a future TrueNAS release adds, or a hostile host invents.
    topology: { data: ["a".repeat(5000)] },
  };
  const parsed = __testOnly.RawPoolSchema.parse(enriched) as Record<
    string,
    unknown
  >;
  // Forward compatibility is preserved: a point release that enriches
  // pool.query must not take the whole model down, so `.strict()` is wrong.
  assertEquals(parsed.name, "tank");
  // ...but the undeclared blob does not travel any further. Under
  // `.passthrough()` this key survived onto the object every later line of
  // discover() handles, one spread away from an infinite-lifetime resource.
  assertEquals("topology" in parsed, false);
  const disk = __testOnly.RawDiskSchema.parse({
    devname: "sda",
    identifier: "{serial}ABC",
    pool: null,
    zfs_guid: "9999",
  }) as Record<string, unknown>;
  assertEquals("zfs_guid" in disk, false);
  const alert = __testOnly.RawAlertSchema.parse({
    uuid: "u1",
    klass: "K",
    level: "WARNING",
    formatted: "f",
    node: "leaked",
  }) as Record<string, unknown>;
  assertEquals("node" in alert, false);
});

// ---------------------------------------------------------------------------
// JSON-RPC envelope validation (block 7)
// ---------------------------------------------------------------------------

const safeForTest = (v: unknown, max?: number) =>
  __testOnly.safeRemoteText(v, "k", max);

Deno.test("classifyFrame refuses every frame shape the old cast accepted", () => {
  const c = (raw: unknown) => __testOnly.classifyFrame(raw, safeForTest);
  // `msg.id` on null threw a TypeError inside ws.onmessage, which sits in no
  // try/catch and is attached to no promise.
  assertEquals(c(null).kind, "invalid");
  assertEquals(c(42).kind, "invalid");
  assertEquals(c("hello").kind, "invalid");
  assertEquals(c([1, 2]).kind, "invalid");
  // A string id missed the number-keyed pending map entirely and the call
  // died of a timeout that blamed the network.
  assertEquals(c({ jsonrpc: "2.0", id: "1", result: [] }).kind, "invalid");
  // `if (msg.error)` was false for these, so they took the SUCCESS branch.
  assertEquals(c({ jsonrpc: "2.0", id: 1, error: 0 }).kind, "invalid");
  assertEquals(c({ jsonrpc: "2.0", id: 1, error: "boom" }).kind, "invalid");
  // Neither member: silently resolved with undefined.
  assertEquals(c({ jsonrpc: "2.0", id: 1 }).kind, "invalid");
  assertEquals(
    c({ jsonrpc: "2.0", id: 1, result: [], error: { code: 1, message: "x" } })
      .kind,
    "invalid",
  );
  assertEquals(c({ jsonrpc: "1.0", id: 1, result: [] }).kind, "invalid");
  // ...and the shapes that must still work, so this cannot pass by refusing
  // everything. A middlewared collection_update push carries no id and must
  // be dropped in silence, not warned about on every single run.
  assertEquals(
    c({ jsonrpc: "2.0", method: "collection_update" }).kind,
    "notification",
  );
  assertEquals(c({ jsonrpc: "2.0", id: 3, result: null }).kind, "result");
  assertEquals(c({ jsonrpc: "2.0", id: 3, result: [1] }).kind, "result");
  assertEquals(
    c({ jsonrpc: "2.0", id: 3, error: { code: -32601, message: "gone" } }).kind,
    "error",
  );
});

Deno.test("a falsy error member is reported as a protocol fault, not as a revoked API key", async () => {
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "auth.login_with_api_key": rawFrame((id) => ({
          jsonrpc: "2.0",
          id,
          error: 0,
        })),
      }),
    },
  );
  assertEquals(err !== null, true);
  // The consequence being prevented: `if (msg.error)` was false for
  // `error: 0`, so this resolved as a SUCCESS carrying `result: undefined`,
  // hit `authed !== true`, and told the operator their API key had been
  // revoked. They then rotate a perfectly good credential and the fault stays.
  assertEquals(err!.message.includes("revoked"), false);
  assertEquals(err!.message.includes("invalid JSON-RPC frame"), true);
  assertEquals(err!.message.includes("error member"), true);
});

Deno.test("a reply with a string id is diagnosed rather than left to time out in silence", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, timeoutSec: 1 }, { recorder: rec }),
      ).then(() => null, (e: Error) => e),
    {
      responder: respondWith({
        "pool.query": rawFrame((id) => ({
          jsonrpc: "2.0",
          id: String(id),
          result: [],
        })),
      }),
    },
  );
  assertEquals(err !== null, true);
  // The pending map is keyed by number, so this reply was dropped on the
  // floor and the run reported "timed out waiting for pool.query" - a
  // diagnosis pointing at the network for a protocol mismatch. It still times
  // out (there is no correlatable reply), but the operator is now told why.
  const said = rec.warnings.map((w) => JSON.stringify(w)).join(" ");
  assertEquals(said.includes("frame id is"), true);
  assertEquals(said.includes("cannot be matched to a call"), true);
});

Deno.test("a null frame does not escape as an unhandled TypeError", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, timeoutSec: 1 }, { recorder: rec }),
      ).then(() => null, (e: Error) => e),
    { responder: respondWith({ "pool.query": rawFrame(() => null) }) },
  );
  assertEquals(err !== null, true);
  // `const id = msg.id as number` on a null frame is a TypeError raised
  // inside ws.onmessage, outside every try/catch and attached to no promise.
  assertEquals(err!.message.includes("Cannot read properties"), false);
  assertEquals(
    rec.warnings.some((w) =>
      JSON.stringify(w).includes("not a JSON-RPC object")
    ),
    true,
  );
});

// ---------------------------------------------------------------------------
// contract drift throws instead of fabricating a value (block 8)
// ---------------------------------------------------------------------------

Deno.test("pool.query without `healthy` throws instead of marking every pool unhealthy", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
        Error,
        "healthy",
      ),
    {
      responder: respondWith({
        "pool.query": [{
          name: "tank",
          id: 1,
          status: "ONLINE",
          allocated: 1,
          free: 1,
        }],
      }),
    },
  );
  // The consequence: `Boolean(undefined)` is false, so a renamed field made
  // poolsUnhealthy equal pools on every run, forever - a box-wide false
  // degrade that trains an operator to ignore pool health entirely.
  assertEquals(rec.written.filter((w) => w.type === "pool"), []);
  assertEquals(rec.written.filter((w) => w.type === "summary"), []);
});

Deno.test("pool.query without `status` throws instead of writing the string UNKNOWN", async () => {
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK)),
        Error,
        "status",
      ),
    {
      responder: respondWith({
        "pool.query": [{
          name: "tank",
          id: 1,
          healthy: true,
          allocated: 1,
          free: 1,
        }],
      }),
    },
  );
});

Deno.test("alert.list without `level` throws instead of writing an alert no gate matches", async () => {
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK)),
        Error,
        "severity can no longer be read",
      ),
    {
      responder: respondWith({
        "alert.list": [{ uuid: "u1", klass: "K", formatted: "f" }],
      }),
    },
  );
});

Deno.test("a pool whose health is present-but-null counts as unhealthy, not as healthy", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "pool.query": [{
          name: "tank",
          id: 1,
          status: null,
          healthy: null,
          allocated: 50,
          free: 50,
        }],
      }),
    },
  );
  // Capacity errs toward "unknown" because guessing benign is the danger
  // there. Health is the mirror image: an unreadable health must not read as
  // a healthy pool, so this direction is deliberately the opposite one.
  const pool = rec.written.find((w) => w.type === "pool")!;
  assertEquals(pool.data.healthy, false);
  assertEquals(
    rec.written.find((w) => w.type === "summary")!.data.poolsUnhealthy,
    1,
  );
});

Deno.test("a disk whose pool membership was never answered does not claim to be orphaned", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        // No `pool` key at all: the extra.pools join did not happen.
        "disk.query": [{
          devname: "sda",
          identifier: "{serial}ABC",
          serial: "ABC",
          size: 100,
          type: "HDD",
        }],
      }),
    },
  );
  const disk = rec.written.find((w) => w.type === "disk")!;
  // `d.pool ?? "none"` made this identical to a disk genuinely outside every
  // pool - and when the join fails it fails for EVERY disk, so an "orphaned
  // disk" gate fires across the whole array at once.
  assertEquals(disk.data.poolKnown, false);
});

Deno.test("a disk that really is in no pool still says so", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "disk.query": [{
          devname: "sdb",
          identifier: "{serial}XYZ",
          serial: "XYZ",
          size: 100,
          type: "SSD",
          pool: null,
        }],
      }),
    },
  );
  // Guards against over-tightening: present-and-null is a real answer and
  // must stay distinguishable from the absent case above.
  const disk = rec.written.find((w) => w.type === "disk")!;
  assertEquals(disk.data.poolKnown, true);
  assertEquals(disk.data.pool, "");
});

// ---------------------------------------------------------------------------
// malformed is not the same fact as absent (block 9)
// ---------------------------------------------------------------------------

Deno.test("a malformed fragmentation throws instead of reporting a pristine 0%", async () => {
  for (const bad of ["not-a-number", "150%", -3, 1e9]) {
    const rec = recorder();
    await withFakeWs(
      () =>
        assertRejects(
          () =>
            model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
          Error,
          "0-100 percentage",
        ),
      {
        responder: respondWith({
          "pool.query": [{
            name: "tank",
            id: 1,
            status: "ONLINE",
            healthy: true,
            allocated: 50,
            free: 50,
            fragmentation: bad,
          }],
        }),
      },
    );
    // `Number("not-a-number")` is NaN and the old line answered 0, so drift
    // and hostility both rendered as a perfectly defragmented pool.
    assertEquals(rec.written.filter((w) => w.type === "pool"), []);
  }
});

Deno.test("an absent fragmentation is still the benign 0", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "pool.query": [{
          name: "tank",
          id: 1,
          status: "ONLINE",
          healthy: true,
          allocated: 50,
          free: 50,
          fragmentation: null,
        }],
      }),
    },
  );
  // Argued, not overlooked: 0% fragmentation is never itself an alarming
  // value, so no gate is lulled by it. Tightening the malformed case must not
  // drag the absent one along with it.
  assertEquals(
    rec.written.find((w) => w.type === "pool")!.data.fragmentationPercent,
    0,
  );
});

Deno.test("an unreadable certificate expiry throws instead of looking like a CSR", async () => {
  for (
    const bad of ["not-a-date", true, { weird: 1 }, "2026-13-45T99:99:99Z"]
  ) {
    const rec = recorder();
    await withFakeWs(
      () =>
        assertRejects(
          () =>
            model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
          Error,
          "cannot read",
        ),
      {
        responder: respondWith({
          "certificate.query": [{
            id: 1,
            name: "cert",
            common: "x",
            until: bad,
          }],
        }),
      },
    );
    // The exact trap the module header describes: `expiryKnown: false` is a
    // CSR's legitimate state, so "we could not read the expiry" wearing that
    // same state means a cert two days from lapsing reports as one with no
    // expiry to worry about.
    assertEquals(rec.written.filter((w) => w.type === "certificate"), []);
  }
});

Deno.test("the certificate date shapes TrueNAS actually sends still parse", () => {
  const t = (v: unknown) => __testOnly.toIsoOrNull(v, safeForTest);
  assertEquals(t("2099-01-01T00:00:00Z"), "2099-01-01T00:00:00Z");
  assertEquals(t({ $date: 4070908800000 }), "2099-01-01T00:00:00.000Z");
  assertEquals(t({ $date: "2099-01-01T00:00:00Z" }), "2099-01-01T00:00:00Z");
  // A real "no expiry", which must stay distinct from the throws above.
  assertEquals(t(null), null);
  assertEquals(t(undefined), null);
  assertEquals(t(""), null);
});

// ---------------------------------------------------------------------------
// instance names are storage paths: a collision merges two records (block 10)
// ---------------------------------------------------------------------------

Deno.test("identity tuples that differ only by a separator byte get different names", async () => {
  // Every field fed to instanceName is remote text off a TrueNAS payload, so
  // nothing stopped a disk identifier from containing the separator itself.
  // Under `identity.join(US)` these two tuples produced one identical digest,
  // and two different disks then shared one infinite-lifetime record, each
  // run overwriting the other's state.
  // Both tuples flatten to the identical byte sequence "a<US>b<US>c" once a
  // separator does the joining, so the digests were equal.
  const a = await __testOnly.instanceName("disk", `a${US}b`, "c");
  const b = await __testOnly.instanceName("disk", "a", `b${US}c`);
  assertEquals(a === b, false);
  assertEquals(
    __testOnly.encodeIdentity([`a${US}b`, "c"]) ===
      __testOnly.encodeIdentity(["a", `b${US}c`]),
    false,
  );
  // The same collision exists for a NUL, which was the separator before that
  // one -- changing which byte is special never fixed the class.
  assertEquals(
    await __testOnly.instanceName("disk", `a${NUL}b`, "c") ===
      await __testOnly.instanceName("disk", "a", `b${NUL}c`),
    false,
  );
});

Deno.test("instance names carry a digest wide enough that collisions are not a thing", async () => {
  const name = await __testOnly.instanceName("pool", "tank", "1");
  const digest = name.slice(name.lastIndexOf("-") + 1);
  // 32 bits of FNV-1a is a coin flip across ~77k identities, and the readable
  // half cannot break the tie: it is truncated, and slug() is not injective
  // (`foo/bar` and `foo-bar` both become `foo-bar`).
  assertEquals(/^[0-9a-f]{32}$/.test(digest), true);
  // Deterministic, or every run would rename every record it wrote.
  assertEquals(await __testOnly.instanceName("pool", "tank", "1"), name);
});

Deno.test("instance names stay bounded and filesystem-safe however long the identity is", async () => {
  const name = await __testOnly.instanceName(
    "disk",
    "x".repeat(4000),
    "y".repeat(4000),
  );
  // The name IS a storage path component; ext4 and APFS cap those at 255.
  assertEquals(name.length < 128, true);
  assertEquals(/^[a-z0-9-]+$/.test(name), true);
});

// ---------------------------------------------------------------------------
// an empty inventory is reported as empty, on the first run too (block 11)
// ---------------------------------------------------------------------------

Deno.test("an empty pool.query on a first run is warned about and flagged, not rolled up as healthy", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      // `existing: []` is the point: a first run, or the first run after a
      // datastore reset. There is no stale record to keep, which is exactly
      // when the old `if (keptStale > 0)` warning stayed silent.
      model.methods.discover.execute(
        {},
        ctxFor(OK, { recorder: rec, existing: [] }),
      ),
    { responder: respondWith({ "pool.query": [] }) },
  );
  const summary = rec.written.find((w) => w.type === "summary")!;
  // `pools: 0, poolsUnhealthy: 0` is also what a flawless box looks like.
  assertEquals(summary.data.pools, 0);
  assertEquals(summary.data.poolsUnhealthy, 0);
  assertEquals(summary.data.poolsReportedEmpty, true);
  assertEquals(summary.data.discoveryDegraded, true);
  assertEquals(rec.warnings.length > 0, true);
  assertEquals(
    rec.warnings.some((w) => w.msg.includes("not a steady state")),
    true,
  );
});

Deno.test("an empty disk.query is flagged the same way", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor(OK, { recorder: rec, existing: [] }),
      ),
    { responder: respondWith({ "disk.query": [] }) },
  );
  const summary = rec.written.find((w) => w.type === "summary")!;
  assertEquals(summary.data.disksReportedEmpty, true);
  assertEquals(summary.data.discoveryDegraded, true);
  assertEquals(rec.warnings.length > 0, true);
});

Deno.test("a healthy run is not flagged degraded and warns about nothing", async () => {
  const rec = recorder();
  await withFakeWs(() =>
    model.methods.discover.execute({}, ctxFor(OK, { recorder: rec }))
  );
  // Guards against the fix over-firing: a flag that is always true is a flag
  // nobody reads.
  const summary = rec.written.find((w) => w.type === "summary")!;
  assertEquals(summary.data.discoveryDegraded, false);
  assertEquals(summary.data.poolsReportedEmpty, false);
  assertEquals(summary.data.disksReportedEmpty, false);
  assertEquals(rec.warnings, []);
});
