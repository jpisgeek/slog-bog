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
import { model } from "./truenas.ts";

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
    queueMicrotask(() =>
      this.onmessage?.({
        data: JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }),
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
  logger: { info: () => {}, warning: () => {} },
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

const recorder = (): Recorder => ({ written: [], deleted: [] });

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
