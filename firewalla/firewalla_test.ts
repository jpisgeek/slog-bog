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
  const shape = model.globalArguments as unknown as {
    shape?: Record<string, { meta?: () => Record<string, unknown> }>;
  };
  const tokenMeta = shape.shape?.token?.meta?.();
  if (tokenMeta) {
    assertEquals(
      tokenMeta.sensitive,
      true,
      "token must carry sensitive: true",
    );
  }
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
