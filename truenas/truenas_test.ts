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
import { assertEquals, assertRejects, assertThrows } from "jsr:@std/assert@1";
import { __testOnly, model } from "./truenas.ts";

// Behavioral tests need an in-memory socket, but the published model must not
// expose a factory that could bypass its maxPayload guard. Load a test-only
// copy of the same module with just the production constructor expression
// replaced; the real `model` remains byte-bounded and is used by the loopback
// payload/redirect tests below.
const productionSource = await Deno.readTextFile(
  new URL("./truenas.ts", import.meta.url),
);
const factoryStartMarker =
  "const openBoundedWebSocket: OpenWebSocket = (url) =>";
const factoryEndMarker = "  }) as unknown as RpcSocket;";
const factoryStart = productionSource.indexOf(factoryStartMarker);
const factoryEndStart = productionSource.indexOf(
  factoryEndMarker,
  factoryStart,
);
if (factoryStart < 0 || factoryEndStart < 0) {
  throw new Error("test harness could not locate the bounded socket factory");
}
const factoryEnd = factoryEndStart + factoryEndMarker.length;
const fakeSocketSource = productionSource.slice(0, factoryStart) +
  `const openBoundedWebSocket: OpenWebSocket = (url) =>
  new globalThis.WebSocket(url) as unknown as RpcSocket;` +
  productionSource.slice(factoryEnd);
const fakeSocketModule = await import(
  `data:application/typescript,${
    encodeURIComponent(fakeSocketSource)
  }#fake-socket`
) as { model: typeof model };
const fakeSocketModel = fakeSocketModule.model;

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

/** Send several arbitrary frames for one request, in wire order. */
const rawFrames = (make: (id: number) => unknown[]) => ({ __rawFrames: make });

/**
 * Marker that makes the fake answer with a BINARY frame.
 *
 * `ev.data` is typed as a string by this client and was cast as one, so a
 * binary frame used to be stringified into "[object Blob]" and reported as
 * malformed JSON -- a diagnosis that names the wrong fault, and a size the
 * client had already read into memory before deciding it could not use it.
 */
const binaryFrame = () => ({ __binaryFrame: true });
const rawTextFrame = (text: string) => ({ __rawTextFrame: text });

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static responder: Responder = healthyResponder;
  /** When false, the socket never opens on its own; the test drives onopen. */
  static autoOpen = true;
  /**
   * What the socket reports as its OWN url once open, when that differs from
   * the url it was constructed with. This is how a redirect looks from inside
   * the WebSocket API: there is no hook on the handshake, so the only thing a
   * client can observe is that the connection it holds says it landed
   * somewhere other than where it was aimed.
   */
  static connectedUrl: string | null = null;
  static constructorError: Error | null = null;

  onopen: (() => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  /** Every frame written to the wire, verbatim. */
  sent: string[] = [];

  /** The url the caller asked for, kept separate from the one reported. */
  readonly requestedUrl: string;
  url: string;

  constructor(url: string) {
    if (FakeWebSocket.constructorError) throw FakeWebSocket.constructorError;
    this.requestedUrl = url;
    this.url = FakeWebSocket.connectedUrl ?? url;
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
    const rawText = result && typeof result === "object"
      ? (result as { __rawTextFrame?: string }).__rawTextFrame
      : undefined;
    if (rawText !== undefined) {
      queueMicrotask(() => this.onmessage?.({ data: rawText }));
      return;
    }
    if (
      result && typeof result === "object" &&
      (result as { __binaryFrame?: boolean }).__binaryFrame
    ) {
      queueMicrotask(() =>
        this.onmessage?.(
          { data: new Uint8Array([1, 2, 3]) },
        )
      );
      return;
    }
    const raw = result && typeof result === "object"
      ? (result as { __rawFrame?: (id: number) => unknown }).__rawFrame
      : undefined;
    const raws = result && typeof result === "object"
      ? (result as { __rawFrames?: (id: number) => unknown[] }).__rawFrames
      : undefined;
    if (raws) {
      const frames = raws(msg.id).map((frame) => JSON.stringify(frame));
      queueMicrotask(() => {
        for (const frame of frames) {
          this.onmessage?.({ data: frame === undefined ? "undefined" : frame });
        }
      });
      return;
    }
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
  opts: {
    responder?: Responder;
    autoOpen?: boolean;
    connectedUrl?: string;
    constructorError?: Error;
  } = {},
): Promise<T> {
  const realWebSocket = globalThis.WebSocket;
  const realExecute = model.methods.discover.execute;
  FakeWebSocket.instances = [];
  FakeWebSocket.responder = opts.responder ?? healthyResponder;
  FakeWebSocket.autoOpen = opts.autoOpen ?? true;
  FakeWebSocket.connectedUrl = opts.connectedUrl ?? null;
  FakeWebSocket.constructorError = opts.constructorError ?? null;
  globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
  model.methods.discover.execute = fakeSocketModel.methods.discover.execute;
  try {
    return await fn();
  } finally {
    model.methods.discover.execute = realExecute;
    globalThis.WebSocket = realWebSocket;
    FakeWebSocket.connectedUrl = null;
    FakeWebSocket.constructorError = null;
  }
}

interface Recorder {
  written: Array<{
    type: string;
    name: string;
    data: Record<string, unknown>;
    tags: Record<string, string>;
  }>;
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
    options: { tags?: Record<string, string> } = {},
  ) => {
    opts.recorder?.written.push({
      type,
      name,
      data,
      tags: options.tags ?? {},
    });
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

const completedSummary = (rec: Recorder) =>
  rec.written.find((w) =>
    w.type === "summary" && w.data.generationComplete === true
  )!;

/** Build the documented `{positive id}-{64 alphanumerics}` TrueNAS shape. */
const testApiKey = (id: number, alphabet = "Ab3Cd4") =>
  `${id}-${alphabet.repeat(Math.ceil(64 / alphabet.length)).slice(0, 64)}`;

/**
 * This was `apiKey: "k"`, a value redaction could never meaningfully protect.
 * Every behavioural fixture now has the real TrueNAS raw-key framing so a
 * schema rejection cannot make a security test pass without exercising its
 * intended path.
 */
const TEST_KEY = testApiKey(1);
const TEST_GENERATION_ID = "00000000-0000-4000-8000-000000000000";

const OK = { baseUrl: "https://nas.example.com", apiKey: TEST_KEY };

// ---------------------------------------------------------------------------
// baseUrl — credential-carrying transport
// ---------------------------------------------------------------------------

Deno.test("baseUrl is marked sensitive in the published argument schema", () => {
  assertEquals(
    model.globalArguments.shape.baseUrl.meta()?.sensitive,
    true,
  );
});

Deno.test("allowedHosts is marked sensitive in the published argument schema", () => {
  assertEquals(
    model.globalArguments.shape.allowedHosts.meta()?.sensitive,
    true,
  );
});

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

Deno.test("baseUrl paths are rejected before a socket or log can receive them", async () => {
  const secretPath = "bearer-token-example-abcdef";
  const args = {
    ...OK,
    baseUrl: `https://nas.example.com/${secretPath}/proxy`,
  };

  const rec = recorder();
  await withFakeWs(async () => {
    const err = await model.methods.discover.execute(
      {},
      ctxFor(args, { recorder: rec }),
    ).then(() => null, (e: Error) => e);
    assertEquals(err !== null, true);
    assertEquals(err!.message.includes("must not carry a path"), true);
    assertEquals(err!.message.includes(secretPath), false);
    assertEquals(FakeWebSocket.instances.length, 0);
  });
  const logged = JSON.stringify(rec.info);
  assertEquals(logged.includes(secretPath), false);
  assertEquals(logged.includes("/proxy"), false);
});

Deno.test("an API-key form in baseUrl is refused before DNS or a socket", async () => {
  await withFakeWs(async () => {
    const err = await model.methods.discover.execute(
      {},
      ctxFor({ ...OK, baseUrl: `https://${TEST_KEY}.example.com` }),
    ).then(() => null, (e: Error) => e);
    assertEquals(err !== null, true);
    assertEquals(err!.message.includes("API key material"), true);
    assertEquals(err!.message.includes(TEST_KEY), false);
    assertEquals(FakeWebSocket.instances.length, 0);
  });
});

Deno.test("canonical URL hosts cannot reconstruct API-key material", async () => {
  const encoded = `https://${TEST_KEY.replace("A", "%41")}.example.com`;
  const fullwidthA = String.fromCodePoint(0xff21);
  const idna = `https://${TEST_KEY.replace("A", fullwidthA)}.example.com`;

  for (const baseUrl of [encoded, idna]) {
    await withFakeWs(async () => {
      const err = await model.methods.discover.execute(
        {},
        ctxFor({ ...OK, baseUrl }),
      ).then(() => null, (e: Error) => e);
      assertEquals(err !== null, true);
      assertEquals(err!.message.includes("API key material"), true);
      // The dangerous outcome is a DNS/socket destination containing the
      // reconstructed credential. Refusal must happen before one exists.
      assertEquals(FakeWebSocket.instances.length, 0);
    });
  }
});

Deno.test("case-folded API-key material cannot become a DNS destination", async () => {
  const key = testApiKey(2, "ABCDEF");
  await withFakeWs(async () => {
    const err = await model.methods.discover.execute(
      {},
      ctxFor({
        ...OK,
        apiKey: key,
        baseUrl: `https://${key.toLowerCase()}.example.com`,
      }),
    ).then(() => null, (e: Error) => e);
    assertEquals(err !== null, true);
    assertEquals(err!.message.includes("API key material"), true);
    assertEquals(FakeWebSocket.instances.length, 0);
  });
});

Deno.test("socket failures expose only locally defined diagnostics", async () => {
  const secret = `${TEST_KEY}-underlying-error`;
  const constructErr = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    { constructorError: new Error(`bad URL ${secret}`) },
  );
  assertEquals(constructErr !== null, true);
  assertEquals(constructErr!.message, "cannot open TrueNAS WebSocket");
  assertEquals(constructErr!.message.includes(secret), false);

  const timeoutErr = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, timeoutSec: 1 }),
      ).then(() => null, (e: Error) => e),
    { autoOpen: false },
  );
  assertEquals(timeoutErr !== null, true);
  assertEquals(
    timeoutErr!.message,
    "timed out connecting to TrueNAS WebSocket",
  );

  await withFakeWs(async () => {
    const pending = model.methods.discover.execute({}, ctxFor(OK)).then(
      () => null,
      (e: Error) => e,
    );
    const error = Object.assign(new Error(`failed ${secret}`), {
      code: "ECONNREFUSED",
    });
    FakeWebSocket.instances[0].onerror?.({ error });
    const connectionErr = await pending;
    assertEquals(connectionErr !== null, true);
    assertEquals(
      connectionErr!.message,
      "TrueNAS WebSocket connection failed (ECONNREFUSED)",
    );
    assertEquals(connectionErr!.message.includes(secret), false);
  }, { autoOpen: false });
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

Deno.test("an apiKey outside TrueNAS raw-key framing is refused before connecting", async () => {
  // The band that existed: `.min(1)` accepted these, and redactKey() skips
  // anything under eight characters to avoid shredding every message. So a
  // key in this range was a credential the model could not strip out of an
  // echoed error -- and auth.login_with_api_key takes the key as its only
  // argument, which is precisely the argument middlewared quotes back when it
  // rejects one.
  for (const short of ["k", "tn-01", "1234567"]) {
    assertEquals(
      model.globalArguments.safeParse({ ...OK, apiKey: short }).success,
      false,
    );
  }
  assertEquals(model.globalArguments.safeParse(OK).success, true);
  // And it is refused before a socket exists, not after the key is on it.
  await withFakeWs(async () => {
    await assertRejects(
      () => model.methods.discover.execute({}, ctxFor({ ...OK, apiKey: "k" })),
      Error,
    );
    assertEquals(FakeWebSocket.instances.length, 0);
  });
});

Deno.test("number- and date-shaped substitutes are refused before remote primitives can echo them", async () => {
  for (
    const substitute of [
      "12345678",
      "1".repeat(64),
      "9".repeat(128),
      "-1234567",
      "12.34567",
      "2026-08-31",
    ]
  ) {
    assertEquals(
      model.globalArguments.safeParse({ ...OK, apiKey: substitute }).success,
      false,
    );
  }

  const rec = recorder();
  await withFakeWs(async () => {
    await assertRejects(
      () =>
        model.methods.discover.execute(
          {},
          ctxFor({ ...OK, apiKey: "12345678" }, { recorder: rec }),
        ),
      Error,
      "TrueNAS raw-key format",
    );
    // No socket means a numeric error code, uptime, size, or count never gets
    // the credential in the first place; nothing can then log or store it.
    assertEquals(FakeWebSocket.instances.length, 0);
    assertEquals(rec.written, []);
  });
});

Deno.test("certificate schema: expiryKnown distinguishes 'no expiry' from a real number", () => {
  const cert = {
    generationId: TEST_GENERATION_ID,
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
    generationId: TEST_GENERATION_ID,
    id: "1",
    klass: "CertificateIsExpiring",
    level: "WARNING",
    formatted: "cert expiring",
    dismissed: true,
    silenced: true,
    contentKnown: true,
  };
  assertEquals(model.resources.alert.schema.safeParse(alert).success, true);
  const { silenced: _drop, ...without } = alert;
  assertEquals(model.resources.alert.schema.safeParse(without).success, false);
  // Same guarantee for contentKnown: a gate that has to ask "is this alert's
  // level real, or is it the string the model wrote when TrueNAS sent none?"
  // can only do that if the field is always present.
  const { contentKnown: _drop2, ...noFlag } = alert;
  assertEquals(model.resources.alert.schema.safeParse(noFlag).success, false);
});

Deno.test("summary schema: counts every category the dashboard gates on", () => {
  const summary = {
    generationId: TEST_GENERATION_ID,
    generationComplete: true,
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
    // Rewritten a third time, one level up again: the roll-up could not say
    // "some of these alerts arrived with no class or level", which reads
    // identically to "every alert on this box is readable and none of them
    // is critical".
    alertsContentUnknown: 0,
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
  const { generationComplete: _drop3, ...noCommitState } = summary;
  assertEquals(
    model.resources.summary.schema.safeParse(noCommitState).success,
    false,
  );
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
  const KEY = testApiKey(3);
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
  const summary = completedSummary(rec);
  assertEquals(summary.data.pools, 1);
  assertEquals(summary.data.disks, 1);
  assertEquals(summary.data.alertsSilenced, 1);
});

Deno.test("prune: datastore names are deleted exactly but never copied into logs", async () => {
  const rec = recorder();
  const hostileName = `stale-${TEST_KEY}-${String.fromCharCode(0x1b)}secret`;
  await withFakeWs(() =>
    model.methods.discover.execute(
      {},
      ctxFor(OK, { recorder: rec, existing: [hostileName] }),
    )
  );
  // The exact key still reaches delete; only the diagnostic surface is
  // removed. A legacy or injected datastore name is not trusted remote text.
  assertEquals(rec.deleted, [hostileName]);
  const logs = JSON.stringify(rec.info);
  assertEquals(logs.includes(hostileName), false);
  assertEquals(logs.includes(TEST_KEY), false);
  assertEquals(logs.includes(String.fromCharCode(0x1b)), false);
  assertEquals(logs.includes("pruned one stale TrueNAS resource"), true);
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
  const summary = completedSummary(rec);
  assertEquals(summary.data.certificatesWithoutExpiry, 1);
});

Deno.test("a null preferred expiry cannot mask a valid fallback", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "certificate.query": [{
          id: 7,
          name: "cert",
          common: "x",
          until: null,
          not_after: "2099-01-01T00:00:00Z",
        }],
      }),
    },
  );
  const cert = rec.written.find((w) => w.type === "certificate")!;
  assertEquals(cert.data.expiryKnown, true);
  assertEquals(cert.data.notAfter, "2099-01-01T00:00:00.000Z");
});

Deno.test("conflicting certificate expiry aliases abort before writes", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "certificate.query": [{
          id: 7,
          name: "cert",
          common: "x",
          until: "2099-01-01T00:00:00Z",
          not_after: "2098-01-01T00:00:00Z",
        }],
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("conflicting"), true);
  assertEquals(rec.written, []);
});

Deno.test("an unreadable secondary expiry alias is never ignored", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "certificate.query": [{
          id: 7,
          name: "cert",
          common: "x",
          until: "2099-01-01T00:00:00Z",
          not_after: "not-a-date",
        }],
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("cannot read"), true);
  assertEquals(rec.written, []);
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
        "alert.list": [{
          klass: "K",
          level: "WARNING",
          formatted: "f",
          dismissed: false,
        }],
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
  const summary = completedSummary(rec);
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
  const summary = completedSummary(rec);
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

Deno.test("an RPC error on auth keeps the removal hint but drops remote prose", async () => {
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
  // arrives as an RPC error rather than a false result. The local hint still
  // says why, but arbitrary server prose from the key-bearing call is absent.
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("Method does not exist"), false);
  assertEquals(err!.message.includes("authentication failed"), true);
  assertEquals(err!.message.includes("auth.login_ex"), true);
});

Deno.test("the hint is scoped to auth: a later RPC failure does not claim it", async () => {
  const remoteCode = 87_654_321;
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "pool.query": rpcError(remoteCode, "pool is busy"),
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("pool is busy"), true);
  assertEquals(err!.message.includes(String(remoteCode)), false);
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

Deno.test("the derived WebSocket URL addresses /api/current with its port intact", async () => {
  for (
    const [baseUrl, expected] of [
      ["https://nas.example.com", "wss://nas.example.com/api/current"],
      ["https://nas.example.com/", "wss://nas.example.com/api/current"],
      [
        "https://nas.example.com:8443",
        "wss://nas.example.com:8443/api/current",
      ],
    ] as const
  ) {
    await withFakeWs(async () => {
      await model.methods.discover.execute({}, ctxFor({ ...OK, baseUrl }));
      // Rebuilding from the parsed URL must not lose the port and must always
      // land on the one fixed endpoint.
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

Deno.test("a non-array result reports its type without serializing its contents", async () => {
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
  // The type is the diagnostic fact. Object contents are a second remote-text
  // surface and can contain escaped or obfuscated credentials, so none enter.
  assertEquals(err!.message.includes("object"), true);
  assertEquals(err!.message.includes("detail"), false);
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
  assertEquals(err!.message.startsWith("TrueNAS RPC failure:"), true);
  assertEquals(err!.message.includes("11"), false);
});

// ---------------------------------------------------------------------------
// allowedHosts - the API key does not go to a host that was not pinned
// (block 2). The pin is optional; when set it is enforced without exception,
// and the reasoning for it not being mandatory is on assertHostAllowed().
// ---------------------------------------------------------------------------

Deno.test("allowedHosts: an unpinned host is refused before a socket opens", async () => {
  const KEY = testApiKey(4);
  await withFakeWs(async () => {
    const err = await model.methods.discover.execute(
      {},
      ctxFor({
        baseUrl: "https://typo.example.com",
        apiKey: KEY,
        allowedHosts: ["nas.example.com"],
      }),
    ).then(() => null, (e: Error) => e);
    assertEquals(err !== null, true);
    assertEquals(err!.message.includes("not in allowedHosts"), true);
    assertEquals(err!.message.includes("typo.example.com"), false);
    assertEquals(err!.message.includes("nas.example.com"), false);
    // The property, not the message: nothing was opened, so nothing was
    // authenticated. A check that ran after connect would still have put the
    // key on the wire to the wrong host.
    assertEquals(FakeWebSocket.instances.length, 0);
  });
});

Deno.test("allowedHosts: a pinned host still connects", async () => {
  await withFakeWs(async () => {
    const rec = recorder();
    await model.methods.discover.execute(
      {},
      ctxFor(
        { ...OK, allowedHosts: ["nas.example.com"] },
        { recorder: rec },
      ),
    );
    assertEquals(
      FakeWebSocket.instances[0].url,
      "wss://nas.example.com/api/current",
    );
    assertEquals(JSON.stringify(rec.info).includes("nas.example.com"), false);
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
            baseUrl: "https://nas.example.com:8443",
            allowedHosts: ["nas.example.com"],
          }),
        ),
      Error,
      "default port",
    );
    // A bare host must not authorize an arbitrary TLS service sharing it.
    assertEquals(FakeWebSocket.instances.length, 0);
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

Deno.test("auth RPC prose cannot disclose complete or transformed API-key material", async () => {
  const KEY = testApiKey(5);
  const transformed = `${KEY.slice(0, 18)}-${KEY.slice(18)}`;
  for (
    const remote of [
      `Invalid API key: ${KEY} rejected by validator`,
      `Invalid API key fragment: ${transformed} rejected by validator`,
    ]
  ) {
    const err = await withFakeWs(
      () =>
        model.methods.discover.execute(
          {},
          ctxFor({ ...OK, apiKey: KEY }),
        ).then(() => null, (e: Error) => e),
      {
        responder: respondWith({
          "auth.login_with_api_key": rpcError(22, remote),
        }),
      },
    );
    assertEquals(err !== null, true);
    // This call takes the key as its only argument. A literal redactor can
    // catch the first echo but not every partial/transformed spelling, so the
    // dangerous outcome assertion is that NONE of the remote prose survives.
    assertEquals(err!.message.includes(KEY), false);
    assertEquals(err!.message.includes(transformed), false);
    assertEquals(err!.message.includes("Invalid API key"), false);
    assertEquals(err!.message.includes("authentication failed"), true);
    assertEquals(err!.message.includes("RPC error 22"), false);
  }
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
    dismissed: false,
    node: "leaked",
  }) as Record<string, unknown>;
  assertEquals("node" in alert, false);
});

// ---------------------------------------------------------------------------
// JSON-RPC envelope validation (block 7)
// ---------------------------------------------------------------------------

const safeForTest = (v: unknown, max?: number) =>
  __testOnly.safeRemoteText(v, TEST_KEY, max);

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
  assertEquals(
    c({ jsonrpc: "2.0", id: 1, result: [], error: null }).kind,
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
  // The pending map is keyed by number, so this cannot be correlated. The
  // connection must fail immediately rather than later blaming the network.
  assertEquals(err!.message.includes("frame id is"), true);
  assertEquals(err!.message.includes("timed out"), false);
  const said = rec.warnings.map((w) => JSON.stringify(w)).join(" ");
  assertEquals(said.includes("frame id is"), true);
  assertEquals(said.includes("cannot be matched to a call"), true);
});

Deno.test("a response for an unknown id fails the run immediately without writing", async () => {
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
          id: id + 1_000,
          result: [],
        })),
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("unknown or duplicate request id"), true);
  assertEquals(err!.message.includes("timed out"), false);
  assertEquals(rec.written, []);
  assertEquals(
    rec.warnings.some((w) =>
      JSON.stringify(w).includes("unknown or duplicate request id")
    ),
    true,
  );
});

Deno.test("a duplicate response id aborts the generation instead of being ignored", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, timeoutSec: 1 }, { recorder: rec }),
      ).then(() => null, (e: Error) => e),
    {
      responder: respondWith({
        "pool.query": rawFrames((id) => [
          { jsonrpc: "2.0", id, result: healthyResponder("pool.query", []) },
          { jsonrpc: "2.0", id, result: healthyResponder("pool.query", []) },
        ]),
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("unknown or duplicate request id"), true);
  assertEquals(err!.message.includes("timed out"), false);
  assertEquals(rec.written, []);
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
  assertEquals(err!.message.includes("timed out"), false);
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
        "alert.list": [{
          uuid: "u1",
          klass: "K",
          formatted: "f",
          dismissed: false,
        }],
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
    completedSummary(rec).data.poolsUnhealthy,
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
  for (
    const bad of [
      "",
      "   ",
      "\t",
      "%",
      "0x10",
      "1e2",
      "3 %",
      "3%junk",
      "not-a-number",
      "150%",
      -3,
      1e9,
    ]
  ) {
    const rec = recorder();
    await withFakeWs(
      () =>
        assertRejects(
          () =>
            model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
          Error,
          typeof bad === "number"
            ? "pool.query fragmentation"
            : "0-100 percentage",
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
  assertEquals(t("2099-01-01T00:00:00Z"), "2099-01-01T00:00:00.000Z");
  assertEquals(t({ $date: 4070908800000 }), "2099-01-01T00:00:00.000Z");
  assertEquals(
    t({ $date: "2099-01-01T00:00:00Z" }),
    "2099-01-01T00:00:00.000Z",
  );
  // A real "no expiry", which must stay distinct from the throws above.
  assertEquals(t(null), null);
  assertEquals(t(undefined), null);
  assertEquals(t(""), null);
});

// ---------------------------------------------------------------------------
// instance names are storage paths: a collision merges two records (block 10)
// ---------------------------------------------------------------------------

const testIdentity = (source: string, value: string | number) =>
  __testOnly.identityPart([source, value])!;

Deno.test("identity tuples that differ only by a separator byte get different names", async () => {
  // Every field fed to instanceName is remote text off a TrueNAS payload, so
  // nothing stopped a disk identifier from containing the separator itself.
  // Under `identity.join(US)` these two tuples produced one identical digest,
  // and two different disks then shared one infinite-lifetime record, each
  // run overwriting the other's state.
  // Both tuples flatten to the identical byte sequence "a<US>b<US>c" once a
  // separator does the joining, so the digests were equal.
  const a = await __testOnly.instanceName(
    "disk",
    TEST_KEY,
    safeForTest,
    testIdentity("identifier", `a${US}b`),
    testIdentity("serial", "c"),
  );
  const b = await __testOnly.instanceName(
    "disk",
    TEST_KEY,
    safeForTest,
    testIdentity("identifier", "a"),
    testIdentity("serial", `b${US}c`),
  );
  assertEquals(a === b, false);
  assertEquals(
    __testOnly.encodeIdentity([`a${US}b`, "c"]) ===
      __testOnly.encodeIdentity(["a", `b${US}c`]),
    false,
  );
  // The same collision exists for a NUL, which was the separator before that
  // one -- changing which byte is special never fixed the class.
  assertEquals(
    await __testOnly.instanceName(
      "disk",
      TEST_KEY,
      safeForTest,
      testIdentity("identifier", `a${NUL}b`),
      testIdentity("serial", "c"),
    ) ===
      await __testOnly.instanceName(
        "disk",
        TEST_KEY,
        safeForTest,
        testIdentity("identifier", "a"),
        testIdentity("serial", `b${NUL}c`),
      ),
    false,
  );
});

Deno.test("instance names carry a digest wide enough that collisions are not a thing", async () => {
  const name = await __testOnly.instanceName(
    "pool",
    TEST_KEY,
    safeForTest,
    testIdentity("name", "tank"),
    testIdentity("id", 1),
  );
  const digest = name.slice(name.lastIndexOf("-") + 1);
  // 32 bits of FNV-1a is a coin flip across ~77k identities, and the readable
  // half cannot break the tie: it is truncated, and slug() is not injective
  // (`foo/bar` and `foo-bar` both become `foo-bar`).
  assertEquals(/^[0-9a-f]{32}$/.test(digest), true);
  // Deterministic, or every run would rename every record it wrote.
  assertEquals(
    await __testOnly.instanceName(
      "pool",
      TEST_KEY,
      safeForTest,
      testIdentity("name", "tank"),
      testIdentity("id", 1),
    ),
    name,
  );
});

Deno.test("API-key forms in identities abort before hashing or writing", async () => {
  const KEY = testApiKey(6);
  const PER_CHARACTER_KEY = testApiKey(7, "JsonABC123");
  const PER_CHARACTER_ECHO = Array.from(
    PER_CHARACTER_KEY,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  ).join("");
  const CASED_KEY = testApiKey(8, "CASEABCDEF0123456789");
  // auth.login_with_api_key takes the key as its only argument, so the far
  // end holds it by the time it answers pool.query. Every identity field is
  // remote text. Redacting only the readable slug still left the raw key in
  // the deterministic digest input, creating a persistent verifier. Try both
  // a literal echo and one split by a zero-width character that screening
  // reconstructs before key detection.
  const splitAt = 15;
  const cases = [
    { key: KEY, echo: KEY },
    {
      key: KEY,
      echo: `${KEY.slice(0, splitAt)}${String.fromCharCode(0x200b)}${
        KEY.slice(splitAt)
      }`,
    },
    { key: PER_CHARACTER_KEY, echo: PER_CHARACTER_ECHO },
    { key: CASED_KEY, echo: CASED_KEY.toLowerCase() },
  ];
  for (const { key, echo } of cases) {
    const rec = recorder();
    const err = await withFakeWs(
      () =>
        model.methods.discover.execute(
          {},
          ctxFor({ ...OK, apiKey: key }, { recorder: rec, existing: [] }),
        ).then(() => null, (e: Error) => e),
      {
        responder: respondWith({
          "pool.query": [{
            name: echo,
            id: 1,
            status: "ONLINE",
            healthy: true,
            allocated: 50,
            free: 50,
          }],
        }),
      },
    );
    assertEquals(err !== null, true);
    assertEquals(err!.message.includes("before hashing or writing"), true);
    assertEquals(err!.message.includes(key), false);
    assertEquals(rec.written, []);
    assertEquals(rec.deleted, []);
  }
});

Deno.test("generated-name postcondition rejects case-folded credential text", () => {
  const key = testApiKey(9, "ABCDEF");
  const generated = `pool-${key.toLowerCase()}-0123456789abcdef`;
  assertThrows(
    () => __testOnly.assertNoApiKeyInGeneratedName(generated, key),
    Error,
    "API key material",
  );
});

Deno.test("instance names stay bounded and filesystem-safe however long the identity is", async () => {
  const name = await __testOnly.instanceName(
    "disk",
    TEST_KEY,
    safeForTest,
    testIdentity("identifier", "x".repeat(4000)),
    testIdentity("serial", "y".repeat(4000)),
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
  const summary = completedSummary(rec);
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
  const summary = completedSummary(rec);
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
  const summary = completedSummary(rec);
  assertEquals(summary.data.discoveryDegraded, false);
  assertEquals(summary.data.poolsReportedEmpty, false);
  assertEquals(summary.data.disksReportedEmpty, false);
  assertEquals(rec.warnings, []);
});

// ---------------------------------------------------------------------------
// the redaction boundary: screening must not be able to REBUILD the key
// ---------------------------------------------------------------------------

Deno.test("auth prose with an invisibly split API key is dropped entirely", async () => {
  const KEY = testApiKey(10);
  // The attack the ordering bug allowed, verbatim: split the key with a
  // character redaction does not match on and screening later DELETES.
  // Redaction ran first and saw no key; screening ran second and handed the
  // log line the key with the marker removed -- intact, 41 characters of live
  // credential, reassembled by the very function meant to sanitise it.
  const obfuscated = `${KEY.slice(0, 12)}${ZWSP}${KEY.slice(12)}`;
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor({ ...OK, apiKey: KEY })).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "auth.login_with_api_key": rpcError(
          22,
          `Invalid API key: ${obfuscated} rejected by validator`,
        ),
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes(KEY), false);
  assertEquals(err!.message.includes(obfuscated), false);
  assertEquals(err!.message.includes("Invalid API key"), false);
  assertEquals(err!.message.includes("authentication failed"), true);
});

Deno.test("a key pushed past the old pre-redaction cut is no longer leaked as a prefix", () => {
  const KEY = testApiKey(11);
  // The input was truncated to 65,536 characters BEFORE redaction ran, so a
  // key straddling that cut lost its tail and the literal match found
  // nothing. The far end chooses the padding: 65,500 spaces put 36 characters
  // of the key inside the slice and the rest outside it, and screening then
  // collapsed the padding away -- leaving those 36 characters of live
  // credential as the entire returned string, well inside the 500-character
  // ceiling. Redaction now runs over the whole string and truncation runs
  // last.
  const out = __testOnly.safeRemoteText(" ".repeat(65_500) + KEY, KEY, 500);
  assertEquals(out.includes(KEY.slice(0, 20)), false);
  assertEquals(out, "[REDACTED]");
});

Deno.test("apiKey shapes that would escape redaction are refused at the argument", () => {
  // Over the maximum: longer than the text safeRemoteText will match against
  // is a key whose echo is a prefix redaction never finds.
  const overMaxButOtherwiseValid = `${"1".repeat(64)}-${"A".repeat(64)}`;
  const atMax = `${"1".repeat(63)}-${"A".repeat(64)}`;
  assertEquals(
    model.globalArguments.safeParse({ ...OK, apiKey: overMaxButOtherwiseValid })
      .success,
    false,
  );
  assertEquals(
    model.globalArguments.safeParse({ ...OK, apiKey: atMax }).success,
    true,
  );
  // Invisible characters INSIDE the key. This is the mirror of the echo
  // attack: screening shortens the key itself, so the screened form drops
  // under the eight-character floor redactKey() refuses to match below, while
  // the raw form no longer appears in the screened text. Neither form is
  // redactable, and the key was 10 characters so the length floor waved it
  // through.
  for (
    const bad of [`abc${ZWSP}de${ZWSP}fg`, `tn-01${NUL}abcdefgh`, "tn 01 key"]
  ) {
    assertEquals(
      model.globalArguments.safeParse({ ...OK, apiKey: bad }).success,
      false,
    );
  }
});

Deno.test("every invisible character screening removes is tried as a splitter", () => {
  const KEY = testApiKey(12);
  // Screening deletes this whole class, so each of them is a way to write the
  // key that a literal substring match misses and a later normalisation puts
  // back together. One test per character class, because a fix that only
  // handled the zero-width space would still ship the same defect.
  // Built from char codes, like the constants above: this file stays free of
  // literal invisible bytes, which is exactly the property the identifier scan
  // and the security review are checking for.
  const invisibles = [
    0x0000,
    0x001f,
    0x007f,
    0x009f,
    0x00ad,
    0x034f,
    0x061c,
    0x200b,
    0x200c,
    0x200d,
    0x200e,
    0x202d,
    0x202e,
    0x2066,
    0x2060,
    0xfe0f,
    0xfeff,
    0xe0100,
  ]
    .map((c) => String.fromCodePoint(c));
  for (const invisible of invisibles) {
    const text = `error: ${KEY.slice(0, 5)}${invisible}${KEY.slice(5)} bad`;
    const out = __testOnly.safeRemoteText(text, KEY, 500);
    assertEquals(out.includes(KEY), false);
    assertEquals(out.includes("[REDACTED]"), true);
  }
  // A plain echo, with nothing hidden in it, must still be caught: the fix
  // reorders the boundary and must not lose the case it already handled.
  const plain = __testOnly.safeRemoteText(`error: ${KEY} bad`, KEY, 500);
  assertEquals(plain.includes(KEY), false);
  assertEquals(plain.includes("[REDACTED]"), true);
});

Deno.test("per-character JSON escapes cannot carry the API key through redaction", () => {
  const key = testApiKey(13, "AbCdEf0123456789");
  const escaped = Array.from(key, (character, index) => {
    const hex = character.charCodeAt(0).toString(16).padStart(4, "0");
    // JSON accepts either case for hexadecimal digits; alternate them so a
    // matcher for only JSON.stringify's canonical output cannot pass.
    const mixedCase = Array.from(
      hex,
      (digit) => index % 2 === 0 ? digit.toUpperCase() : digit,
    ).join("");
    return `\\u${mixedCase}`;
  }).join("");
  const rendered = __testOnly.safeRemoteText(
    `remote echoed ${escaped} in an error`,
    key,
    1_000,
  );

  // Assert the security outcome: no reversible spelling survives into the
  // log/field boundary, and it is replaced rather than merely causing an
  // unrelated exception.
  assertEquals(rendered.includes(escaped), false);
  assertEquals(rendered.includes(key), false);
  assertEquals(rendered.includes("[REDACTED]"), true);
});

Deno.test("ASCII case-folded key forms are redacted before logs or fields", () => {
  const key = testApiKey(14, "ABCDEF");
  const folded = key.toLowerCase();
  const escapedFolded = Array.from(
    folded,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  ).join("");

  for (const echo of [folded, escapedFolded]) {
    const rendered = __testOnly.safeRemoteText(
      `remote echoed ${echo}`,
      key,
      1_000,
    );
    assertEquals(rendered.includes(echo), false);
    assertEquals(rendered.includes("[REDACTED]"), true);
  }
});

// ---------------------------------------------------------------------------
// all or nothing: a derived value that throws must leave the datastore alone
// ---------------------------------------------------------------------------

Deno.test("cancellation during planning aborts before the first datastore write", async () => {
  const ac = new AbortController();
  const rec = recorder();
  let scheduled = false;
  const responder: Responder = (method, params) => {
    if (method === "certificate.query" && !scheduled) {
      scheduled = true;
      // All reply microtasks settle first. Planning then yields at SHA-256,
      // letting this cancellation land after collection but before writes.
      setTimeout(() => ac.abort(), 0);
    }
    if (method === "pool.query") {
      return Array.from({ length: 32 }, (_, id) => ({
        name: `pool-${id}`,
        id,
        status: "ONLINE",
        healthy: true,
        allocated: 50,
        free: 50,
        fragmentation: "3%",
      }));
    }
    return healthyResponder(method, params);
  };
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor(OK, { signal: ac.signal, recorder: rec, existing: ["stale"] }),
      ).then(() => null, (e: Error) => e),
    { responder },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("aborted"), true);
  assertEquals(rec.written, []);
  assertEquals(rec.deleted, []);
});

Deno.test("cancellation after the incomplete marker cannot leave a healthy summary", async () => {
  const ac = new AbortController();
  const rec = recorder();
  const ctx = ctxFor(OK, {
    signal: ac.signal,
    recorder: rec,
    existing: ["stale"],
  });
  const write = ctx.writeResource;
  ctx.writeResource = async (...args: unknown[]) => {
    const result = await write(...args);
    if (rec.written.length === 1) ac.abort();
    return result;
  };
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctx).then(
        () => null,
        (e: Error) => e,
      ),
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("aborted"), true);
  assertEquals(rec.written.length, 1);
  assertEquals(rec.written[0].type, "summary");
  assertEquals(rec.written[0].data.generationComplete, false);
  assertEquals(rec.deleted, []);
});

Deno.test("cancellation during prune stops further deletes and withholds summary", async () => {
  const ac = new AbortController();
  const rec = recorder();
  const ctx = ctxFor(OK, {
    signal: ac.signal,
    recorder: rec,
    existing: ["stale-one", "stale-two"],
  });
  const remove = ctx.dataRepository.delete;
  ctx.dataRepository.delete = async (...args: unknown[]) => {
    await remove(...args);
    if (rec.deleted.length === 1) ac.abort();
  };
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctx).then(
        () => null,
        (e: Error) => e,
      ),
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("aborted"), true);
  assertEquals(rec.deleted, ["stale-one"]);
  assertEquals(
    rec.written.some((w) =>
      w.type === "summary" && w.data.generationComplete === false
    ),
    true,
  );
  assertEquals(completedSummary(rec), undefined);
});

Deno.test("a failed datastore write leaves a linked incomplete generation", async () => {
  const rec = recorder();
  const ctx = ctxFor(OK, { recorder: rec, existing: ["stale"] });
  const write = ctx.writeResource;
  ctx.writeResource = async (...args: unknown[]) => {
    if (args[0] === "pool") throw new Error("simulated datastore failure");
    return await write(...args);
  };

  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctx).then(
        () => null,
        (e: Error) => e,
      ),
  );
  assertEquals(err?.message, "simulated datastore failure");
  assertEquals(rec.deleted, []);

  const marker = rec.written.find((w) => w.type === "summary");
  const partial = rec.written.find((w) => w.type === "system")!;
  assertEquals(marker !== undefined, true);
  assertEquals(marker!.data.generationComplete, false);
  assertEquals(typeof marker!.data.generationId, "string");
  assertEquals(partial.data.generationId, marker!.data.generationId);
  assertEquals(completedSummary(rec), undefined);
});

Deno.test("a successful generation links every record before committing it", async () => {
  const rec = recorder();
  await withFakeWs(() =>
    model.methods.discover.execute({}, ctxFor(OK, { recorder: rec }))
  );

  const summaries = rec.written.filter((w) => w.type === "summary");
  assertEquals(summaries.length, 2);
  assertEquals(summaries[0].data.generationComplete, false);
  assertEquals(summaries[1].data.generationComplete, true);
  const generationId = summaries[1].data.generationId;
  assertEquals(typeof generationId, "string");
  for (const written of rec.written) {
    assertEquals(written.data.generationId, generationId);
    assertEquals(written.tags.generationId, generationId);
  }
});

Deno.test("a certificate this model cannot read leaves no partial run behind", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      assertRejects(
        () =>
          model.methods.discover.execute(
            {},
            ctxFor(OK, { recorder: rec, existing: ["pool-old-1", "cert-old"] }),
          ),
        Error,
        "cannot read",
      ),
    {
      responder: respondWith({
        "certificate.query": [{ id: 1, name: "cert", until: "not-a-date" }],
      }),
    },
  );
  // The README and the method description both promise all-or-nothing. Before
  // this, `system` was written first and pools and disks followed, so a
  // certificate that threw left a datastore holding this run's system record,
  // this run's pools, and the PREVIOUS run's summary -- with nothing marking
  // which half was which. Certificates are parsed last, so this is the case
  // that proves the ordering rather than merely exercising it.
  assertEquals(rec.written, []);
  // ...and nothing was pruned either. A half-written run that also deleted
  // records would be worse than one that only wrote.
  assertEquals(rec.deleted, []);
});

Deno.test("a malformed fragmentation aborts before the system record is written", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
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
          fragmentation: "ERROR",
        }],
      }),
    },
  );
  // `system` is written before pools are even looked at, so this is the write
  // the old ordering leaked on every pool-level failure.
  assertEquals(rec.written, []);
});

// ---------------------------------------------------------------------------
// an alert with no content is not an ordinary alert
// ---------------------------------------------------------------------------

Deno.test("an alert whose class and level are null is flagged, not written as one no gate matches", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "alert.list": [{
          uuid: "u1",
          klass: null,
          level: null,
          formatted: null,
          dismissed: false,
        }],
      }),
    },
  );
  const alert = rec.written.find((w) => w.type === "alert")!;
  // The old backfill wrote "" here, which is a value a gate skips over
  // without noticing. A CRITICAL condition could sit in the datastore,
  // counted in summary.alerts, matched by no severity rule on the box.
  assertEquals(alert.data.level, "UNKNOWN");
  assertEquals(alert.data.klass, "UNKNOWN");
  assertEquals(alert.data.contentKnown, false);
  const summary = completedSummary(rec);
  assertEquals(summary.data.alertsContentUnknown, 1);
  // A workflow that only reads the roll-up still sees it.
  assertEquals(summary.data.discoveryDegraded, true);
  assertEquals(
    rec.warnings.some((w) => w.msg.includes("no class, level or text")),
    true,
  );
});

Deno.test("a readable alert is not dragged into the degraded case", async () => {
  const rec = recorder();
  await withFakeWs(() =>
    model.methods.discover.execute({}, ctxFor(OK, { recorder: rec }))
  );
  // Guards against the fix over-firing: the healthy NAS has one perfectly
  // ordinary alert, and a flag that is always true is a flag nobody reads.
  assertEquals(
    rec.written.find((w) => w.type === "alert")!.data.contentKnown,
    true,
  );
  assertEquals(
    completedSummary(rec).data.alertsContentUnknown,
    0,
  );
});

// ---------------------------------------------------------------------------
// a certificate must be identified by something that is not its position
// ---------------------------------------------------------------------------

Deno.test("a certificate with neither id nor name is refused, not named by its position", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
        Error,
        "stable identifier",
      ),
    {
      responder: respondWith({
        "certificate.query": [{ common: "x", until: "2099-01-01T00:00:00Z" }],
      }),
    },
  );
  // The old fallback put `idx0` in the instance name, so the record's identity
  // was the row's place in a response TrueNAS never promised to order. Two
  // certificates swapping places swapped their stored expiry history, and a
  // run reporting one fewer certificate pruned a record belonging to one still
  // installed -- on the exact resource this model exists to watch.
  assertEquals(rec.written, []);
});

Deno.test("a certificate with a name but no id is still accepted", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "certificate.query": [{
          name: "letsencrypt",
          common: "x.example.com",
          until: "2099-01-01T00:00:00Z",
        }],
      }),
    },
  );
  // A name is stable across polls, which is the property being required.
  // Demanding an `id` as well would refuse a payload that identifies itself
  // perfectly well.
  const cert = rec.written.find((w) => w.type === "certificate")!;
  assertEquals(cert.name.startsWith("cert-letsencrypt-"), true);
  // An empty-string id must not satisfy the requirement either: it stringifies
  // to "" and puts the position fallback straight back.
  assertEquals(
    __testOnly.RawCertificateSchema.safeParse({ id: "", until: null }).success,
    false,
  );
});

// ---------------------------------------------------------------------------
// where the key is sent: the destination we GOT, not the one we asked for
// ---------------------------------------------------------------------------

Deno.test("a connection that lands on another host never receives the API key", async () => {
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    { connectedUrl: "wss://elsewhere.example.com/api/current" },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("different host"), true);
  assertEquals(err!.message.includes("elsewhere.example.com"), false);
  assertEquals(err!.message.includes("nas.example.com"), false);
  // The assertion that matters is not the message: the WebSocket API has no
  // redirect policy, so every check before this one was made against a URL
  // STRING. `sent` is the wire. Nothing went onto it.
  assertEquals(FakeWebSocket.instances[0].sent, []);
});

Deno.test("a connection that downgrades to ws:// never receives the API key", async () => {
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    { connectedUrl: "ws://nas.example.com/api/current" },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("downgrade"), true);
  // allowInsecureHttp defaults false, so cleartext was never approved for this
  // run: arriving on ws:// after asking for wss:// is the redirect turning a
  // TLS-protected credential into one anybody on the path reads.
  assertEquals(FakeWebSocket.instances[0].sent, []);
});

Deno.test("the arrived-at destination is re-checked against the pin, not only the requested one", () => {
  const check = __testOnly.assertConnectedDestination;
  // The pin passed for the URL we aimed at; it has to pass for the URL we
  // reached, or it is an allowlist evaluated against a value nobody verified.
  check(
    "wss://nas.example.com/api/current",
    "wss://nas.example.com/api/current",
    ["nas.example.com"],
  );
  let threw = false;
  try {
    check(
      "wss://nas.example.com/api/current",
      "wss://nas.example.com/api/current",
      ["other.example.com"],
    );
  } catch {
    threw = true;
  }
  assertEquals(threw, true);
});

Deno.test("a socket that names no destination is refused, not credited with the one we asked for", async () => {
  // The check used to read `ws.url || wsUrl`, so a socket reporting nothing
  // was handed the URL we WANTED and passed a test about where it had landed.
  // That is the check failing open on precisely the runtime it cannot vouch
  // for. A socket that cannot say where it is does not get the API key.
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
        () => null,
        (e: Error) => e,
      ),
    { connectedUrl: "" },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("cannot be checked"), true);
  assertEquals(FakeWebSocket.instances[0].sent, []);
  assertEquals(rec.written, []);
});

Deno.test("timing out a still-connecting socket keeps its cleanup error handled", async () => {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  let connection: Deno.Conn | undefined;
  try {
    const run = model.methods.discover.execute(
      {},
      ctxFor({
        ...OK,
        baseUrl: `http://127.0.0.1:${port}`,
        allowInsecureHttp: true,
        timeoutSec: 1,
      }),
    ).then(() => null, (e: Error) => e);
    // Accept the TCP connection but never answer the HTTP upgrade. The client
    // remains CONNECTING until its own timeout closes it, which makes ws emit
    // the cleanup error that used to have no handler.
    connection = await listener.accept();
    const err = await run;
    assertEquals(err !== null, true);
    assertEquals(err!.message, "timed out connecting to TrueNAS WebSocket");
    await new Promise((resolve) => setTimeout(resolve, 25));
  } finally {
    try {
      connection?.close();
    } catch { /* peer already closed */ }
    listener.close();
  }
});

Deno.test("aborting a still-connecting socket keeps its cleanup error handled", async () => {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  const ac = new AbortController();
  let connection: Deno.Conn | undefined;
  try {
    const run = model.methods.discover.execute(
      {},
      ctxFor(
        {
          ...OK,
          baseUrl: `http://127.0.0.1:${port}`,
          allowInsecureHttp: true,
          timeoutSec: 2,
        },
        { signal: ac.signal },
      ),
    ).then(() => null, (e: Error) => e);
    connection = await listener.accept();
    ac.abort();
    const err = await run;
    assertEquals(err !== null, true);
    assertEquals(err!.message, "aborted");
    await new Promise((resolve) => setTimeout(resolve, 25));
  } finally {
    try {
      connection?.close();
    } catch { /* peer already closed */ }
    listener.close();
  }
});

Deno.test("the handshake refuses a redirect outright: the second origin is never contacted", async () => {
  // No fake here. This is the pinned, bounded WebSocket client against a real
  // server: a client that FOLLOWED the 302 would carry
  // auth.login_with_api_key to `target`, and `ws.url` is specified as the
  // constructor URL, so the destination check above would have seen nothing
  // wrong. The only thing that makes a redirect harmless is that it is never
  // taken.
  let targetHits = 0;
  const target = Deno.serve({ port: 0, onListen: () => {} }, (req) => {
    targetHits++;
    if (req.headers.get("upgrade") === "websocket") {
      const { response } = Deno.upgradeWebSocket(req);
      return response;
    }
    return new Response("target");
  });
  const targetPort = (target.addr as Deno.NetAddr).port;
  const redirector = Deno.serve(
    { port: 0, onListen: () => {} },
    () =>
      new Response(null, {
        status: 302,
        headers: {
          location: `http://127.0.0.1:${targetPort}/api/current`,
        },
      }),
  );
  const redirectorPort = (redirector.addr as Deno.NetAddr).port;
  try {
    const err = await model.methods.discover.execute(
      {},
      ctxFor({
        ...OK,
        // http:// and no pin: the weakest configuration this model allows, so
        // the refusal cannot be credited to a stricter setting.
        baseUrl: `http://127.0.0.1:${redirectorPort}`,
        allowInsecureHttp: true,
      }),
    ).then(() => null, (e: Error) => e);
    assertEquals(err !== null, true);
    // The key was never sent anywhere, because the handshake never completed.
    assertEquals(targetHits, 0);
  } finally {
    await redirector.shutdown();
    await target.shutdown();
  }
});

// ---------------------------------------------------------------------------
// the far end does not get to choose how much work this model does
// ---------------------------------------------------------------------------

Deno.test("an absurd row count is refused before a permanent record per row is written", async () => {
  const rec = recorder();
  const flood = Array.from({ length: 5001 }, (_, i) => ({
    devname: `sd${i}`,
    identifier: `id${i}`,
  }));
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
        Error,
        "more than 5000 entries; refused before element validation",
      ),
    { responder: respondWith({ "disk.query": flood }) },
  );
  // Each row costs a SHA-256, an instance name, and a datastore record with
  // lifetime "infinite". The cap is before the parse so none of that is paid.
  assertEquals(rec.written, []);
});

Deno.test("an oversized raw string is refused before it is hashed into an instance name", async () => {
  const rec = recorder();
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
        Error,
        "exceeds 1024 characters",
      ),
    {
      responder: respondWith({
        "disk.query": [{
          devname: "sda",
          identifier: "x".repeat(50_000),
          serial: "ABC",
        }],
      }),
    },
  );
  // Identity fields are length-prefixed, encoded and digested BEFORE anything
  // truncates them, so the bound has to live at the parse or it does not exist.
  assertEquals(rec.written, []);
});

Deno.test("alert prose gets the wide ceiling, and is truncated rather than refused", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "alert.list": [{
          uuid: "u1",
          klass: "K",
          level: "WARNING",
          formatted: `real alert text ${"z".repeat(20_000)}`,
          dismissed: false,
        }],
      }),
    },
  );
  // A wordy alert is a normal alert. Refusing the whole discovery over one
  // would be the model failing at the job it exists to do, so this ceiling is
  // far higher than the identity ones and storage truncates under it.
  const alert = rec.written.find((w) => w.type === "alert")!;
  assertEquals((alert.data.formatted as string).length < 4300, true);
  assertEquals((alert.data.formatted as string).includes("real alert"), true);
  // Past the ceiling it is refused, because at that size it is not prose.
  await withFakeWs(
    () =>
      assertRejects(
        () => model.methods.discover.execute({}, ctxFor(OK)),
        Error,
        "exceeds 65536 characters",
      ),
    {
      responder: respondWith({
        "alert.list": [{
          uuid: "u1",
          klass: "K",
          level: "WARNING",
          formatted: "z".repeat(70_000),
          dismissed: false,
        }],
      }),
    },
  );
});

Deno.test("loadavg is bounded: it is the one array written to a record verbatim", async () => {
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK)).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "system.info": {
          hostname: "nas",
          version: "25.10.6",
          model: "x86",
          cores: 8,
          physmem: 1024,
          uptime_seconds: 60,
          loadavg: new Array(5000).fill(1),
        },
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(
    err!.message,
    "TrueNAS system.info loadavg returned more than 8 entries; refused " +
      "before element validation",
  );
});

Deno.test("row limits run before Zod can traverse attacker-chosen elements", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor(OK, { recorder: rec }),
      ).then(() => null, (e: Error) => e),
    {
      // Null rows ensure that, without the up-front guard, Zod visits and
      // reports thousands of element errors before its array maximum matters.
      responder: respondWith({
        "pool.query": new Array(5_001).fill(null),
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(
    err!.message,
    "TrueNAS pool.query returned more than 5000 entries; refused before " +
      "element validation",
  );
  assertEquals(rec.written, []);
});

Deno.test("the production WebSocket enforces its byte cap before message assembly", async () => {
  const rec = recorder();
  const server = Deno.serve(
    { hostname: "127.0.0.1", port: 0, onListen: () => {} },
    (request) => {
      const { socket, response } = Deno.upgradeWebSocket(request);
      socket.onmessage = (event) => {
        const call = JSON.parse(String(event.data)) as {
          id: number;
          method: string;
          params: unknown[];
        };
        const frame = call.method === "auth.login_with_api_key"
          ? {
            jsonrpc: "2.0",
            id: call.id,
            result: true,
            // Unknown envelope members are otherwise harmless and ignored.
            // Without the receiver-level maxPayload this authenticates and
            // the dangerous 4 MB allocation has already happened.
            padding: "z".repeat(4_100_000),
          }
          : {
            jsonrpc: "2.0",
            id: call.id,
            result: healthyResponder(call.method, call.params),
          };
        socket.send(JSON.stringify(frame));
      };
      return response;
    },
  );
  const port = (server.addr as Deno.NetAddr).port;
  try {
    const err = await model.methods.discover.execute(
      {},
      ctxFor(
        {
          ...OK,
          baseUrl: `http://127.0.0.1:${port}`,
          allowInsecureHttp: true,
          timeoutSec: 2,
        },
        { recorder: rec },
      ),
    ).then(() => null, (e: Error) => e);
    assertEquals(err !== null, true);
    assertEquals(err!.message.includes("4000000-byte limit"), true);
    assertEquals(err!.message.includes("timed out"), false);
    assertEquals(rec.written, []);
  } finally {
    await server.shutdown();
  }
});

Deno.test("a binary frame is named as one rather than reported as malformed JSON", async () => {
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, timeoutSec: 2 }),
      ).then(() => null, (e: Error) => e),
    { responder: respondWith({ "pool.query": binaryFrame() }) },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("non-text WebSocket frame"), true);
});

Deno.test("parseable certificate expiry text is canonicalized before storage", async () => {
  const rec = recorder();
  const raw = `Thu, 01 Jan 2099 00:00:00 GMT (${
    String.fromCharCode(0)
  }${TEST_KEY})`;
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "certificate.query": [{
          id: 1,
          name: "cert",
          common: "example.com",
          until: raw,
        }],
      }),
    },
  );
  const cert = rec.written.find((w) => w.type === "certificate")!;
  assertEquals(cert.data.notAfter, "2099-01-01T00:00:00.000Z");
  assertEquals(String(cert.data.notAfter).includes(TEST_KEY), false);
  assertEquals(
    String(cert.data.notAfter).includes(String.fromCharCode(0)),
    false,
  );
});

Deno.test("oversized certificate expiry text is refused before any write", async () => {
  const rec = recorder();
  const raw = `Thu, 01 Jan 2099 00:00:00 GMT (${"x".repeat(1_100)})`;
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "certificate.query": [{ id: 1, name: "cert", until: raw }],
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("expiry"), true);
  assertEquals(rec.written, []);
});

Deno.test("object diagnostics never serialize API keys", () => {
  const keys = [
    testApiKey(15),
    testApiKey(16, "XYZ987"),
  ];
  for (const key of keys) {
    assertEquals(
      model.globalArguments.safeParse({ ...OK, apiKey: key }).success,
      true,
    );
    const rendered = __testOnly.safeRemoteText({ echoed: key }, key, 1_000);
    assertEquals(rendered, "[object]");
    assertEquals(rendered.includes(key), false);
    assertEquals(rendered.includes(JSON.stringify(key).slice(1, -1)), false);
  }
});

Deno.test("screened-empty alert content degrades the run instead of evading gates", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "alert.list": [{
          uuid: "u1",
          klass: " \t ",
          level: "\u200b",
          formatted: "\n\t",
          dismissed: false,
        }],
      }),
    },
  );
  const alert = rec.written.find((w) => w.type === "alert")!;
  const summary = completedSummary(rec);
  assertEquals(alert.data.klass, "UNKNOWN");
  assertEquals(alert.data.level, "UNKNOWN");
  assertEquals(alert.data.formatted, "");
  assertEquals(alert.data.contentKnown, false);
  assertEquals(summary.data.alertsContentUnknown, 1);
  assertEquals(summary.data.discoveryDegraded, true);
});

Deno.test("missing or null alert dismissal state is contract drift, never false", async () => {
  for (const dismissed of [undefined, null]) {
    const row: Record<string, unknown> = {
      uuid: "u1",
      klass: "CertificateIsExpiring",
      level: "WARNING",
      formatted: "expiring",
    };
    if (dismissed !== undefined) row.dismissed = dismissed;
    assertEquals(__testOnly.RawAlertSchema.safeParse(row).success, false);

    const rec = recorder();
    const err = await withFakeWs(
      () =>
        model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
          () => null,
          (e: Error) => e,
        ),
      { responder: respondWith({ "alert.list": [row] }) },
    );
    assertEquals(err !== null, true);
    assertEquals(rec.written, []);
  }
});

Deno.test("blank preferred identifiers use stable nonblank fallbacks", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "pool.query": [{
          name: " \t ",
          id: 9,
          status: "ONLINE",
          healthy: true,
          allocated: 1,
          free: 1,
        }],
        "disk.query": [{
          identifier: " ",
          devname: "sdb",
          serial: "SER",
          size: 1,
          pool: "tank",
        }],
        "alert.list": [{
          uuid: " ",
          id: 7,
          key: "fallback",
          klass: "WARNING",
          level: "WARNING",
          formatted: "warning",
          dismissed: false,
        }],
        "certificate.query": [{
          id: " ",
          name: "cert-two",
          common: "example.org",
          until: "2099-01-01T00:00:00Z",
        }],
      }),
    },
  );
  assertEquals(
    rec.written.find((w) => w.type === "pool")!.name.startsWith("pool-9-"),
    true,
  );
  assertEquals(
    rec.written.find((w) => w.type === "disk")!.name.startsWith(
      "disk-sdb-ser-",
    ),
    true,
  );
  assertEquals(
    rec.written.find((w) => w.type === "alert")!.name.startsWith(
      "alert-7-warning-",
    ),
    true,
  );
  assertEquals(
    rec.written.find((w) => w.type === "certificate")!.name.startsWith(
      "cert-cert-two-example-org-",
    ),
    true,
  );
});

Deno.test("rows with no nonblank stable identifier fail before writes", async () => {
  const cases: Array<{
    label: string;
    over: Record<string, unknown>;
    message: string;
  }> = [
    {
      label: "pool",
      over: {
        "pool.query": [{
          name: " ",
          id: "\u200b",
          status: "ONLINE",
          healthy: true,
        }],
      },
      message: "pool.query row has neither a usable",
    },
    {
      label: "disk",
      over: {
        "disk.query": [{ identifier: " ", devname: "\u200b", pool: null }],
      },
      message: "disk.query row has neither",
    },
    {
      label: "alert",
      over: {
        "alert.list": [{
          uuid: " ",
          key: "\u200b",
          klass: "WARNING",
          level: "WARNING",
          formatted: "warning",
          dismissed: false,
        }],
      },
      message: "alert.list row has none",
    },
    {
      label: "certificate",
      over: {
        "certificate.query": [{
          id: " ",
          name: "\u200b",
          until: "2099-01-01T00:00:00Z",
        }],
      },
      message: "certificate.query row has neither",
    },
  ];

  for (const testCase of cases) {
    const rec = recorder();
    const err = await withFakeWs(
      () =>
        model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
          () => null,
          (e: Error) => e,
        ),
      { responder: respondWith(testCase.over) },
    );
    assertEquals(err !== null, true, testCase.label);
    assertEquals(err!.message.includes(testCase.message), true, testCase.label);
    assertEquals(rec.written, [], testCase.label);
  }
});

Deno.test("a screened-empty disk pool is unknown, never a known blank", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "disk.query": [{
          devname: "sda",
          identifier: "{serial}ABC",
          serial: "ABC",
          size: 100,
          pool: " \u200b ",
        }],
      }),
    },
  );
  const disk = rec.written.find((w) => w.type === "disk")!;
  assertEquals(disk.data.pool, "");
  assertEquals(disk.data.poolKnown, false);
  assertEquals(disk.tags.pool, "unknown");
});

Deno.test("duplicate derived identities abort before overwrite or prune", async () => {
  const rec = recorder();
  const duplicate = {
    name: "tank",
    id: 1,
    status: "ONLINE",
    healthy: true,
    allocated: 50,
    free: 50,
  };
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor(OK, { recorder: rec, existing: ["pool-old"] }),
      ).then(() => null, (e: Error) => e),
    { responder: respondWith({ "pool.query": [duplicate, duplicate] }) },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("duplicate pool identity"), true);
  assertEquals(rec.written, []);
  assertEquals(rec.deleted, []);
});

Deno.test("negative and implausible remote numbers fail at the parse boundary", async () => {
  const cases: Array<[string, Record<string, unknown>]> = [
    [
      "system.info cores",
      {
        "system.info": {
          hostname: "nas",
          version: "25.10.6",
          cores: -1,
          physmem: 1,
          uptime_seconds: 1,
          loadavg: [0],
        },
      },
    ],
    [
      "pool.query allocated",
      {
        "pool.query": [{
          name: "tank",
          id: 1,
          status: "ONLINE",
          healthy: true,
          allocated: -1,
          free: 1,
        }],
      },
    ],
    [
      "disk.query size",
      {
        "disk.query": [{ identifier: "disk-1", size: -1, pool: null }],
      },
    ],
    [
      "system.info loadavg entry",
      {
        "system.info": {
          hostname: "nas",
          version: "25.10.6",
          cores: 1,
          physmem: 1,
          uptime_seconds: 1,
          loadavg: [1_000_001],
        },
      },
    ],
  ];
  for (const [field, over] of cases) {
    const rec = recorder();
    const err = await withFakeWs(
      () =>
        model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
          () => null,
          (e: Error) => e,
        ),
      { responder: respondWith(over) },
    );
    assertEquals(err !== null, true, field);
    assertEquals(err!.message.includes(field), true, field);
    assertEquals(rec.written, [], field);
  }
});

Deno.test("derived resource fields are schema-checked before the first write", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "pool.query": [{
          name: "tank",
          id: 1,
          status: "ONLINE",
          healthy: true,
          allocated: Number.MAX_SAFE_INTEGER,
          free: Number.MAX_SAFE_INTEGER,
        }],
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("sizeBytes"), true);
  assertEquals(rec.written, []);
});

Deno.test("a response without jsonrpc 2.0 is refused before records are written", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, timeoutSec: 2 }, { recorder: rec }),
      ).then(() => null, (e: Error) => e),
    {
      responder: respondWith({
        "pool.query": rawFrame((id) => ({ id, result: [] })),
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("JSON-RPC"), true, err!.message);
  assertEquals(err!.message.includes("timed out"), false);
  assertEquals(rec.written, []);
});

Deno.test("JSON-RPC notifications and errors are validated as distinct variants", () => {
  const classify = (raw: unknown) => __testOnly.classifyFrame(raw, safeForTest);
  assertEquals(classify({ id: 1, result: [] }).kind, "invalid");
  assertEquals(
    classify({ jsonrpc: "2.0", result: [] }).kind,
    "invalid",
  );
  assertEquals(
    classify({ jsonrpc: "2.0", id: null, result: [] }).kind,
    "invalid",
  );
  assertEquals(
    classify({ jsonrpc: "2.0", method: "collection_update", params: 1 }).kind,
    "invalid",
  );
  assertEquals(
    classify({
      jsonrpc: "2.0",
      id: 1,
      error: { code: 1.5, message: "no" },
    }).kind,
    "invalid",
  );
  assertEquals(
    classify({ jsonrpc: "2.0", method: "collection_update", params: [] }).kind,
    "notification",
  );
});

Deno.test("remote-text truncation never splits an astral code point", () => {
  const astral = String.fromCodePoint(0x1f600);
  const rendered = __testOnly.safeRemoteText(
    "a".repeat(199) + astral + "tail",
    TEST_KEY,
    200,
  );
  const kept = rendered.slice(0, rendered.indexOf("…"));
  assertEquals(kept.endsWith(astral), true);
  assertEquals(Array.from(kept).length, 200);
});

Deno.test("identity hashes retain source field and primitive type", async () => {
  const numeric = await __testOnly.instanceName(
    "alert",
    TEST_KEY,
    safeForTest,
    testIdentity("id", 1),
  );
  const textual = await __testOnly.instanceName(
    "alert",
    TEST_KEY,
    safeForTest,
    testIdentity("id", "1"),
  );
  const differentField = await __testOnly.instanceName(
    "alert",
    TEST_KEY,
    safeForTest,
    testIdentity("uuid", "1"),
  );
  assertEquals(numeric === textual, false);
  assertEquals(textual === differentField, false);
  assertEquals(numeric.startsWith("alert-1-"), true);
  assertEquals(textual.startsWith("alert-1-"), true);
});

Deno.test("unpaired surrogates are rejected before identity hashing or writes", async () => {
  for (
    const bad of [String.fromCharCode(0xd800), String.fromCharCode(0xdc00)]
  ) {
    assertEquals(
      __testOnly.RawPoolSchema.safeParse({
        name: bad,
        status: "ONLINE",
        healthy: true,
      }).success,
      false,
    );
    const rec = recorder();
    const err = await withFakeWs(
      () =>
        model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
          () => null,
          (e: Error) => e,
        ),
      {
        responder: respondWith({
          "pool.query": [{ name: bad, status: "ONLINE", healthy: true }],
        }),
      },
    );
    assertEquals(err !== null, true);
    assertEquals(err!.message.includes("unpaired UTF-16 surrogate"), true);
    assertEquals(rec.written, []);
  }
});

Deno.test("result plus error null is rejected, never accepted as success", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })).then(
        () => null,
        (e: Error) => e,
      ),
    {
      responder: respondWith({
        "pool.query": rawFrame((id) => ({
          jsonrpc: "2.0",
          id,
          result: [],
          error: null,
        })),
      }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("both result and error"), true);
  assertEquals(rec.written, []);
});

Deno.test("malformed JSON fails all pending calls immediately", async () => {
  const rec = recorder();
  const err = await withFakeWs(
    () =>
      model.methods.discover.execute(
        {},
        ctxFor({ ...OK, timeoutSec: 2 }, { recorder: rec }),
      ).then(() => null, (e: Error) => e),
    {
      responder: respondWith({ "pool.query": rawTextFrame("{") }),
    },
  );
  assertEquals(err !== null, true);
  assertEquals(err!.message.includes("malformed frame"), true);
  assertEquals(err!.message.includes("timed out"), false);
  assertEquals(rec.written, []);
});

Deno.test("missing disk and certificate strings use explicit UNKNOWN sentinels", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "disk.query": [{ identifier: "disk-1", size: null, pool: undefined }],
        "certificate.query": [{
          id: 1,
          until: "2099-01-01T00:00:00Z",
        }],
      }),
    },
  );
  const disk = rec.written.find((w) => w.type === "disk")!;
  assertEquals(disk.data.name, "UNKNOWN");
  assertEquals(disk.data.serial, "UNKNOWN");
  assertEquals(disk.data.model, "UNKNOWN");
  assertEquals(disk.data.type, "UNKNOWN");
  assertEquals(disk.tags.type, "UNKNOWN");
  const certificate = rec.written.find((w) => w.type === "certificate")!;
  assertEquals(certificate.data.name, "UNKNOWN");
  assertEquals(certificate.data.commonName, "UNKNOWN");
});

Deno.test("screened-empty system and pool strings use UNKNOWN, never ordinary blanks", async () => {
  const rec = recorder();
  await withFakeWs(
    () => model.methods.discover.execute({}, ctxFor(OK, { recorder: rec })),
    {
      responder: respondWith({
        "system.info": {
          hostname: "\u200b",
          version: " \t ",
          model: "\n",
          cores: 8,
          physmem: 1024,
          uptime_seconds: 60,
          loadavg: [0, 0, 0],
        },
        "pool.query": [{
          name: "\u200b",
          id: 1,
          status: "\t",
          healthy: true,
          allocated: 50,
          free: 50,
          fragmentation: "3%",
        }],
      }),
    },
  );
  const system = rec.written.find((w) => w.type === "system")!;
  const pool = rec.written.find((w) => w.type === "pool")!;
  const summary = completedSummary(rec);
  assertEquals(system.data.hostname, "UNKNOWN");
  assertEquals(system.data.version, "UNKNOWN");
  assertEquals(system.data.model, "UNKNOWN");
  assertEquals(system.tags.hostname, "UNKNOWN");
  assertEquals(pool.data.name, "UNKNOWN");
  assertEquals(pool.data.status, "UNKNOWN");
  assertEquals(pool.tags.status, "UNKNOWN");
  assertEquals(summary.data.hostname, "UNKNOWN");
  assertEquals(summary.data.version, "UNKNOWN");
});

Deno.test("published source and examples contain no internal identifiers", async () => {
  const source = await Deno.readTextFile(
    new URL("./truenas.ts", import.meta.url),
  );
  for (const foreign of ["netdata", ".swamp/pulled-extensions", "@swamp/ssh"]) {
    assertEquals(source.includes(foreign), false, foreign);
  }
  assertEquals(source.includes(String.raw`\u0000`), false);
  for (const name of ["README.md", "readme.vars.yaml"]) {
    const doc = await Deno.readTextFile(new URL(`./${name}`, import.meta.url));
    assertEquals(doc.includes("vault.get('myvault'"), false, name);
    assertEquals(doc.includes("vault.get('<your-vault>'"), true, name);
  }
});

Deno.test("published documentation states the actual response and storage contracts", async () => {
  const vars = await Deno.readTextFile(
    new URL("./readme.vars.yaml", import.meta.url),
  );
  assertEquals(
    /unknown certificate `daysRemaining` uses\s+`-9999`/.test(vars),
    true,
  );
  assertEquals(
    vars.includes("System `hostname` and `version` are required strings"),
    true,
  );
  assertEquals(vars.includes("the `name` key must be a string"), true);
  assertEquals(vars.includes("1,024 UTF-16"), true);
  assertEquals(vars.includes("4,096 Unicode code points"), true);
  assertEquals(
    vars.includes("bounded, screened form rather than blanked"),
    true,
  );
  assertEquals(vars.includes("kept in full"), false);
  assertEquals(vars.includes("4 KB"), false);
  assertEquals(vars.includes("65 KB"), false);
});
