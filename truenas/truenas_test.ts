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
 * before any socket is opened, so the suite makes no network calls.
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./truenas.ts";

// deno-lint-ignore no-explicit-any
const ctxFor = (globalArgs: Record<string, unknown>): any => ({
  signal: new AbortController().signal,
  globalArgs,
  modelType: "@jpisgeek/truenas",
  modelId: "test",
  logger: { info: () => {}, warning: () => {} },
  writeResource: () => Promise.resolve({}),
  dataRepository: {
    findAllForModel: () => Promise.resolve([]),
    delete: () => Promise.resolve(),
  },
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
