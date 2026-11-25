/**
 * Acceptance tests for the provisioning surface of the Hyper-V model.
 *
 * Plan: docs/plans/2026-11-25-hyperv-provisioning.md (rev 3: heartbeat readiness; rev 2: deleteDisk; rev 1: secrets on stdin)
 *
 * The reviewer owns this file. Implementers make it pass and must not edit it:
 * its SHA-256 is recorded in the plan, and a changed hash fails review on its
 * own. Add your own cases to hyperv_test.ts instead.
 *
 * Like hyperv_test.ts, everything here runs without a host. The parts that
 * need one (building an image, creating and starting a VM, PowerShell Direct)
 * are proven by the live acceptance run described in the plan.
 */
import {
  assert,
  assertEquals,
  assertFalse,
  assertMatch,
  assertNotMatch,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import type { z } from "npm:zod@4";
import {
  AdminPassword,
  assertDiskDeleteConfirmed,
  BuildImageArgsSchema,
  classifyHeartbeat,
  ComputerName,
  CreateVmArgsSchema,
  createVmRequest,
  DeleteDiskArgsSchema,
  encodeCommand,
  encodeUnattendPassword,
  GlobalArgsSchema,
  GuestExecArgsSchema,
  guestExecRequest,
  invocation,
  renderSetupComplete,
  renderUnattend,
  sshArgs,
  SshPublicKey,
  STDIN_LAUNCHER,
  stdinRequest,
  WaitReadyArgsSchema,
  WindowsPath,
} from "./hyperv.ts";

// Throwaway fixture keys. Their private halves were discarded at creation.
const KEY_A =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGV1K2ZLpIKGtS1ULVwlvdP1Q2kFqYn9+jfNIHVSzFJd fixture@example.invalid";
const KEY_B =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKsy+bWRZvzZ9oKiXocFjfIp1rF0Pri4NYBwfFN9HXwG second@example.invalid";
const KEY_ECDSA =
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBILH3M5Rnf4YReoJNZCKwXlwg1pkoiQL+VlMIMObd5htIxXwRWiI4GHCagnQz+rDaoPoUvONNBb0S9Xmh63Ui7g= ecdsa@example.invalid";
const BLOB_A = KEY_A.split(" ")[1];
const BLOB_B = KEY_B.split(" ")[1];

const PASSWORD = "Zebra-Plum-42-correct";

const ok = (s: z.ZodType, v: unknown) => s.safeParse(v).success;

function b64Utf16le(s: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    bytes.push(c & 0xff, c >> 8);
  }
  return btoa(String.fromCharCode(...bytes));
}

const ASCII_ONLY = /^[\t\n\r -~]*$/;

// ---------------------------------------------------------------------------
// WindowsPath: the only path shape a provisioning method accepts.
// ---------------------------------------------------------------------------

Deno.test("WindowsPath accepts drive-absolute backslash paths, spaces included", () => {
  assert(ok(WindowsPath, "C:\\vm-images\\base.vhdx"));
  assert(ok(WindowsPath, "D:\\Hyper-V\\Virtual Hard Disks\\e2e-win01.vhdx"));
});

Deno.test("WindowsPath refuses relative, UNC, device and traversal paths", () => {
  for (
    const bad of [
      "",
      "vm-images\\base.vhdx",
      "\\vm-images\\base.vhdx",
      "\\\\server\\share\\base.iso",
      "\\\\?\\C:\\base.vhdx",
      "C:\\vm-images\\..\\Windows\\base.vhdx",
      "C:\\vm-images\\.\\base.vhdx",
      "C:/vm-images/base.vhdx",
      "C:vm-images\\base.vhdx",
    ]
  ) {
    assertFalse(ok(WindowsPath, bad), `accepted ${JSON.stringify(bad)}`);
  }
});

Deno.test("WindowsPath refuses characters Windows forbids and control characters", () => {
  for (
    const bad of [
      'C:\\a"b\\x.vhdx',
      "C:\\a<b\\x.vhdx",
      "C:\\a|b\\x.vhdx",
      "C:\\a*\\x.vhdx",
      "C:\\a?\\x.vhdx",
      "C:\\a\nb\\x.vhdx",
      "C:\\a\u0000b\\x.vhdx",
      " C:\\x.vhdx",
      "C:\\x.vhdx ",
    ]
  ) {
    assertFalse(ok(WindowsPath, bad), `accepted ${JSON.stringify(bad)}`);
  }
});

Deno.test("WindowsPath caps length below MAX_PATH", () => {
  assert(ok(WindowsPath, "C:\\" + "a".repeat(230) + ".vhdx"));
  assertFalse(ok(WindowsPath, "C:\\" + "a".repeat(260) + ".vhdx"));
});

// ---------------------------------------------------------------------------
// ComputerName: what Windows will actually accept as a NetBIOS name.
// ---------------------------------------------------------------------------

Deno.test("ComputerName accepts short NetBIOS-safe names", () => {
  for (const good of ["E2E-WIN01", "ws1", "A", "abcdefghijklmno"]) {
    assert(ok(ComputerName, good), `refused ${good}`);
  }
});

Deno.test("ComputerName refuses names Windows setup would reject or truncate", () => {
  for (
    const bad of [
      "",
      "abcdefghijklmnop", // 16 characters
      "has_underscore",
      "has space",
      "dot.name",
      "-lead",
      "trail-",
      "12345", // all digits
      "naïve",
    ]
  ) {
    assertFalse(ok(ComputerName, bad), `accepted ${JSON.stringify(bad)}`);
  }
});

// ---------------------------------------------------------------------------
// SshPublicKey: one validated public key, never options, never private.
// ---------------------------------------------------------------------------

Deno.test("SshPublicKey accepts ed25519 and ecdsa public keys", () => {
  assert(ok(SshPublicKey, KEY_A));
  assert(ok(SshPublicKey, KEY_B));
  assert(ok(SshPublicKey, KEY_ECDSA));
  assert(ok(SshPublicKey, `ssh-ed25519 ${BLOB_A}`), "comment is optional");
});

Deno.test("SshPublicKey refuses a declared type that the blob contradicts", () => {
  assertFalse(ok(SshPublicKey, `ssh-rsa ${BLOB_A} lie@example.invalid`));
  assertFalse(ok(SshPublicKey, `ecdsa-sha2-nistp256 ${BLOB_A}`));
});

Deno.test("SshPublicKey refuses options, line breaks, private keys and junk", () => {
  for (
    const bad of [
      `from="10.0.0.0/8" ${KEY_A}`,
      `restrict ${KEY_A}`,
      `${KEY_A}\n${KEY_B}`,
      `${KEY_A}\r`,
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "ssh-ed25519 not*base64",
      "ssh-ed25519",
      `ssh-dss ${BLOB_A}`,
      "",
    ]
  ) {
    assertFalse(ok(SshPublicKey, bad), `accepted ${JSON.stringify(bad)}`);
  }
});

Deno.test("SshPublicKey refuses comments that could break out of a quoted string", () => {
  for (
    const comment of [
      "o'brien",
      'say"hi',
      "a;b",
      "$(whoami)",
      "`id`",
      "a|b",
      "a&b",
    ]
  ) {
    assertFalse(
      ok(SshPublicKey, `ssh-ed25519 ${BLOB_A} ${comment}`),
      `accepted comment ${JSON.stringify(comment)}`,
    );
  }
});

// ---------------------------------------------------------------------------
// Method argument schemas.
// ---------------------------------------------------------------------------

Deno.test("buildWindowsImage defaults are conservative and complete", () => {
  const a = BuildImageArgsSchema.parse({
    isoPath: "C:\\vm-images\\iso\\server-2025.iso",
    edition: "Windows Server 2025 Standard",
    outputPath: "C:\\vm-images\\ws2025-std.vhdx",
  });
  assertEquals(a.sizeGb, 64);
  assertEquals(a.rebuild, false);
});

Deno.test("buildWindowsImage insists on an .iso source and a .vhdx output", () => {
  const base = {
    isoPath: "C:\\vm-images\\iso\\server-2025.iso",
    edition: "Windows Server 2025 Standard",
    outputPath: "C:\\vm-images\\ws2025-std.vhdx",
  };
  assert(ok(BuildImageArgsSchema, { ...base, isoPath: "C:\\x\\Server.ISO" }));
  assert(ok(BuildImageArgsSchema, { ...base, outputPath: "C:\\x\\Base.VHDX" }));
  assertFalse(
    ok(BuildImageArgsSchema, { ...base, isoPath: "C:\\x\\server.img" }),
  );
  assertFalse(
    ok(BuildImageArgsSchema, { ...base, outputPath: "C:\\x\\base.vhd" }),
  );
  assertFalse(
    ok(BuildImageArgsSchema, { ...base, outputPath: "C:\\x\\base.vhdx.ps1" }),
  );
});

Deno.test("buildWindowsImage bounds the disk size and the edition string", () => {
  const base = {
    isoPath: "C:\\vm-images\\iso\\server-2025.iso",
    edition: "Windows Server 2025 Standard (Desktop Experience)",
    outputPath: "C:\\vm-images\\ws2025-std.vhdx",
  };
  assert(ok(BuildImageArgsSchema, base));
  assert(ok(BuildImageArgsSchema, { ...base, sizeGb: 32 }));
  assert(ok(BuildImageArgsSchema, { ...base, sizeGb: 2048 }));
  assertFalse(ok(BuildImageArgsSchema, { ...base, sizeGb: 16 }));
  assertFalse(ok(BuildImageArgsSchema, { ...base, sizeGb: 4096 }));
  assertFalse(ok(BuildImageArgsSchema, { ...base, sizeGb: 64.5 }));
  assertFalse(ok(BuildImageArgsSchema, { ...base, edition: "" }));
  assertFalse(
    ok(BuildImageArgsSchema, { ...base, edition: "Standard\nRemove-Item" }),
  );
  assertFalse(ok(BuildImageArgsSchema, { ...base, edition: "x".repeat(129) }));
});

Deno.test("createVm defaults to a small differencing-disk VM with no guest setup", () => {
  const a = CreateVmArgsSchema.parse({
    vmName: "e2e-win01",
    baseImage: "C:\\vm-images\\ws2025-std.vhdx",
    switchName: "lan",
  });
  assertEquals(a.cpuCount, 2);
  assertEquals(a.memoryGb, 4);
  assertEquals(a.diskMode, "differencing");
  assertEquals(a.guest, undefined);
});

Deno.test("createVm bounds sizing and refuses unknown disk modes", () => {
  const base = {
    vmName: "e2e-win01",
    baseImage: "C:\\vm-images\\ws2025-std.vhdx",
    switchName: "lan",
  };
  assert(ok(CreateVmArgsSchema, { ...base, diskMode: "copy" }));
  assertFalse(ok(CreateVmArgsSchema, { ...base, diskMode: "linked" }));
  assertFalse(ok(CreateVmArgsSchema, { ...base, cpuCount: 0 }));
  assertFalse(ok(CreateVmArgsSchema, { ...base, cpuCount: 65 }));
  assertFalse(ok(CreateVmArgsSchema, { ...base, memoryGb: 0 }));
  assertFalse(ok(CreateVmArgsSchema, { ...base, memoryGb: 257 }));
  assertFalse(ok(CreateVmArgsSchema, { ...base, vmName: "" }));
  assertFalse(
    ok(CreateVmArgsSchema, { ...base, baseImage: "C:\\x\\base.iso" }),
  );
});

Deno.test("createVm Windows guest setup validates every field", () => {
  const base = {
    vmName: "e2e-win01",
    baseImage: "C:\\vm-images\\ws2025-std.vhdx",
    switchName: "lan",
  };
  const guest = {
    os: "windows",
    computerName: "E2E-WIN01",
    adminPassword: PASSWORD,
    authorizedKeys: [KEY_A],
  };
  const a = CreateVmArgsSchema.parse({ ...base, guest });
  assertEquals(a.guest?.enableSsh, true, "SSH is on unless switched off");

  assertFalse(
    ok(CreateVmArgsSchema, {
      ...base,
      guest: { ...guest, computerName: "bad_name" },
    }),
  );
  assertFalse(
    ok(CreateVmArgsSchema, {
      ...base,
      guest: { ...guest, adminPassword: "short" },
    }),
  );
  assertFalse(
    ok(CreateVmArgsSchema, {
      ...base,
      guest: { ...guest, authorizedKeys: ["nope"] },
    }),
  );
  assertFalse(
    ok(CreateVmArgsSchema, {
      ...base,
      guest: { ...guest, authorizedKeys: [KEY_A, KEY_A] },
    }),
    "duplicate keys are a caller mistake, not something to write twice",
  );
  assertFalse(
    ok(CreateVmArgsSchema, {
      ...base,
      guest: { ...guest, authorizedKeys: Array(17).fill(0).map(() => KEY_A) },
    }),
  );
});

Deno.test("AdminPassword is bounded and marked sensitive", () => {
  assert(ok(AdminPassword, PASSWORD));
  assertFalse(ok(AdminPassword, "a".repeat(13)));
  assertFalse(ok(AdminPassword, "a".repeat(128)));
  assertFalse(ok(AdminPassword, "Zebra-Plum-42\ncorrect"));
  assertEquals(AdminPassword.meta()?.sensitive, true);
});

Deno.test("waitReady defaults and bounds", () => {
  const a = WaitReadyArgsSchema.parse({ vmName: "e2e-win01" });
  assertEquals(a.timeoutSec, 600);
  assertEquals(a.tcpPort, undefined);
  assert(
    ok(WaitReadyArgsSchema, {
      vmName: "e2e-win01",
      tcpPort: 22,
      timeoutSec: 30,
    }),
  );
  assertFalse(ok(WaitReadyArgsSchema, { vmName: "e2e-win01", timeoutSec: 29 }));
  assertFalse(
    ok(WaitReadyArgsSchema, { vmName: "e2e-win01", timeoutSec: 1801 }),
  );
  assertFalse(ok(WaitReadyArgsSchema, { vmName: "e2e-win01", tcpPort: 0 }));
  assertFalse(ok(WaitReadyArgsSchema, { vmName: "e2e-win01", tcpPort: 65536 }));
});

Deno.test("guestExec bounds the script and the run time, and needs credentials", () => {
  const base = {
    vmName: "e2e-win01",
    user: "Administrator",
    password: PASSWORD,
    script: "hostname",
  };
  const a = GuestExecArgsSchema.parse(base);
  assertEquals(a.timeoutSec, 120);
  assertFalse(ok(GuestExecArgsSchema, { ...base, script: "" }));
  assertFalse(ok(GuestExecArgsSchema, { ...base, script: "x".repeat(65537) }));
  assertFalse(ok(GuestExecArgsSchema, { ...base, timeoutSec: 601 }));
  assertFalse(ok(GuestExecArgsSchema, { ...base, user: "evil@host" }));
  assertFalse(ok(GuestExecArgsSchema, { ...base, user: "-oProxyCommand" }));
  const { password: _p, ...noPassword } = base;
  assertFalse(ok(GuestExecArgsSchema, noPassword));
});

// ---------------------------------------------------------------------------
// Unattend rendering.
// ---------------------------------------------------------------------------

Deno.test("encodeUnattendPassword matches the encoding Windows setup expects", () => {
  assertEquals(
    encodeUnattendPassword("P@ss", "AdministratorPassword"),
    b64Utf16le("P@ssAdministratorPassword"),
  );
  assertEquals(
    encodeUnattendPassword("P@ss", "Password"),
    b64Utf16le("P@ssPassword"),
  );
  assertEquals(
    encodeUnattendPassword("Pässwörd-ünïcode", "AdministratorPassword"),
    b64Utf16le("Pässwörd-ünïcodeAdministratorPassword"),
  );
});

Deno.test("renderUnattend carries the name and an encoded, never plain, password", () => {
  const xml = renderUnattend({
    computerName: "E2E-WIN01",
    adminPassword: PASSWORD,
  });
  assert(xml.startsWith('<?xml version="1.0" encoding="utf-8"?>'));
  assertStringIncludes(xml, 'xmlns="urn:schemas-microsoft-com:unattend"');
  assertStringIncludes(xml, 'pass="specialize"');
  assertStringIncludes(xml, 'pass="oobeSystem"');
  assertStringIncludes(xml, 'processorArchitecture="amd64"');
  assertStringIncludes(xml, "<ComputerName>E2E-WIN01</ComputerName>");
  assertStringIncludes(
    xml,
    `<Value>${
      encodeUnattendPassword(PASSWORD, "AdministratorPassword")
    }</Value>`,
  );
  assertStringIncludes(xml, "<PlainText>false</PlainText>");
  assertNotMatch(xml, /<PlainText>true<\/PlainText>/);
  assertFalse(xml.includes(PASSWORD), "plain password leaked into unattend");
  assertStringIncludes(xml, "<HideEULAPage>true</HideEULAPage>");
  assertStringIncludes(xml, "<TimeZone>UTC</TimeZone>");
});

Deno.test("renderUnattend keeps XML well-formed for any password", () => {
  const nasty = `<&>"'-Zebra-Plum-42`;
  const xml = renderUnattend({
    computerName: "E2E-WIN01",
    adminPassword: nasty,
  });
  assertFalse(xml.includes(nasty));
  assertNotMatch(xml, /&(?!amp;|lt;|gt;|quot;|apos;)/, "unescaped ampersand");
});

Deno.test("renderUnattend honours a time zone and is deterministic", () => {
  const a = renderUnattend({
    computerName: "E2E-WIN01",
    adminPassword: PASSWORD,
    timeZone: "Eastern Standard Time",
  });
  const b = renderUnattend({
    computerName: "E2E-WIN01",
    adminPassword: PASSWORD,
    timeZone: "Eastern Standard Time",
  });
  assertStringIncludes(a, "<TimeZone>Eastern Standard Time</TimeZone>");
  assertEquals(a, b);
});

Deno.test("renderUnattend refuses inputs the schemas would refuse", () => {
  assertThrows(() =>
    renderUnattend({ computerName: "bad_name", adminPassword: PASSWORD })
  );
  assertThrows(() =>
    renderUnattend({ computerName: "E2E-WIN01", adminPassword: "short" })
  );
  assertThrows(() =>
    renderUnattend({
      computerName: "E2E-WIN01",
      adminPassword: PASSWORD,
      timeZone: "UTC</TimeZone><x>",
    })
  );
});

// ---------------------------------------------------------------------------
// SetupComplete: the first-boot script that turns SSH on and authorizes keys.
// ---------------------------------------------------------------------------

Deno.test("renderSetupComplete enables sshd, opens only 22/TCP and writes the keys", () => {
  const ps = renderSetupComplete({
    enableSsh: true,
    authorizedKeys: [KEY_A, KEY_B],
  });
  assertMatch(ps, /Set-Service\s+-Name\s+sshd\s+-StartupType\s+Automatic/);
  assertMatch(ps, /Start-Service\s+(-Name\s+)?sshd/);
  assertMatch(ps, /New-NetFirewallRule[^\n]*-Protocol\s+TCP/);
  assertMatch(ps, /New-NetFirewallRule[^\n]*-LocalPort\s+22\b/);
  assertStringIncludes(ps, "administrators_authorized_keys");
  assertStringIncludes(ps, BLOB_A);
  assertStringIncludes(ps, BLOB_B);
});

Deno.test("renderSetupComplete installs the OpenSSH capability only when sshd is missing", () => {
  const ps = renderSetupComplete({ enableSsh: true, authorizedKeys: [KEY_A] });
  assertMatch(
    ps,
    /Get-Service\s+(-Name\s+)?sshd[^\n]*-ErrorAction\s+SilentlyContinue/,
  );
  assertStringIncludes(ps, "Add-WindowsCapability");
  assertStringIncludes(ps, "OpenSSH.Server");
});

Deno.test("renderSetupComplete locks the keys file to SYSTEM and Administrators by SID", () => {
  const ps = renderSetupComplete({ enableSsh: true, authorizedKeys: [KEY_A] });
  assertStringIncludes(ps, "/inheritance:r");
  assertStringIncludes(ps, "*S-1-5-18:F");
  assertStringIncludes(ps, "*S-1-5-32-544:F");
  for (
    const broad of [
      "Everyone",
      "Users:",
      "Authenticated Users",
      "S-1-1-0",
      "S-1-5-11",
      "S-1-5-32-545",
    ]
  ) {
    assertFalse(ps.includes(broad), `grants ${broad}`);
  }
});

Deno.test("renderSetupComplete writes files without a BOM or UTF-16", () => {
  const ps = renderSetupComplete({ enableSsh: true, authorizedKeys: [KEY_A] });
  assertNotMatch(
    ps,
    /Out-File/,
    "Out-File defaults to UTF-16 on Windows PowerShell",
  );
  assertNotMatch(
    ps,
    /(^|[^\d])>>?\s*['"]?[A-Za-z]:\\/m,
    "redirecting into a file writes UTF-16 on Windows PowerShell",
  );
  assert(
    ps.includes("UTF8Encoding($false)") || /-Encoding\s+(ascii|ASCII)/.test(ps),
    "no explicit BOM-free encoding",
  );
});

Deno.test("renderSetupComplete output is plain ASCII", () => {
  const ps = renderSetupComplete({
    enableSsh: true,
    authorizedKeys: [KEY_A, KEY_ECDSA],
  });
  assertMatch(ps, ASCII_ONLY);
});

Deno.test("renderSetupComplete with SSH off touches neither sshd nor key files", () => {
  const ps = renderSetupComplete({ enableSsh: false, authorizedKeys: [] });
  assertFalse(ps.includes("sshd"));
  assertFalse(ps.includes("authorized_keys"));
  assertFalse(ps.includes("New-NetFirewallRule"));
});

Deno.test("renderSetupComplete refuses keys the schema refuses", () => {
  assertThrows(() =>
    renderSetupComplete({ enableSsh: true, authorizedKeys: ["nope"] })
  );
  assertThrows(() =>
    renderSetupComplete({
      enableSsh: true,
      authorizedKeys: [`ssh-ed25519 ${BLOB_A} x'; Remove-Item C:\\ -Recurse #`],
    })
  );
});

// ---------------------------------------------------------------------------
// Revision 1: secrets travel on stdin.
//
// No secret, and no reversible encoding of one, may appear in ssh's argv.
// Locally any user can read argv with `ps`; on the host it lands in the
// process command line that Win32_Process exposes. Base64 is not protection.
// Only a fixed, secret-free launcher goes in argv; the script and its data go
// on stdin, inside the ssh channel.
// ---------------------------------------------------------------------------

const G = GlobalArgsSchema.parse({ host: "10.0.0.5", user: "Administrator" });
const OTHER_PASSWORD = "Quartz-Fennel-77-orbit";

function b64Utf8(s: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(s)));
}

function decodeUtf16leB64(b64: string): string {
  const bin = atob(b64);
  let out = "";
  for (let i = 0; i + 1 < bin.length; i += 2) {
    out += String.fromCharCode(
      bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8),
    );
  }
  return out;
}

/** Every rendering of a secret that would let someone recover it. */
function secretForms(pw: string): string[] {
  return [
    pw,
    b64Utf8(pw),
    b64Utf16le(pw),
    encodeUnattendPassword(pw, "AdministratorPassword"),
    encodeUnattendPassword(pw, "Password"),
  ];
}

/** argv as ssh receives it, plus the decoded -EncodedCommand payload. */
function argvSurface(argv: string[]): string {
  const remote = argv.at(-1) ?? "";
  const m = remote.match(/-EncodedCommand\s+([A-Za-z0-9+/=]+)\s*$/);
  assert(m, "remote command is not an -EncodedCommand launcher");
  return argv.join("\u0000") + "\u0000" + decodeUtf16leB64(m[1]);
}

const GUEST_EXEC = {
  vmName: "e2e-win01",
  user: "Administrator",
  password: PASSWORD,
  script: "hostname",
};

const CREATE_WITH_GUEST = {
  vmName: "e2e-win01",
  baseImage: "C:\\vm-images\\ws2025-std.vhdx",
  switchName: "lan",
  guest: {
    os: "windows" as const,
    computerName: "E2E-WIN01",
    adminPassword: PASSWORD,
    authorizedKeys: [KEY_A],
  },
};

Deno.test("STDIN_LAUNCHER is a fixed, ASCII, secret-free reader of stdin", () => {
  assertMatch(STDIN_LAUNCHER, ASCII_ONLY);
  assertStringIncludes(STDIN_LAUNCHER, "[Console]::In.ReadToEnd()");
  assertStringIncludes(STDIN_LAUNCHER, "ConvertFrom-Json");
  assertFalse(STDIN_LAUNCHER.includes(PASSWORD));
});

Deno.test("stdinRequest is one JSON document carrying the script and its data", () => {
  const body = stdinRequest("Get-Date", { a: 1, s: "x'y\"z" });
  const parsed = JSON.parse(body);
  assertEquals(parsed.script, "Get-Date");
  assertEquals(parsed.data, { a: 1, s: "x'y\"z" });
  assertFalse(body.startsWith("\uFEFF"), "BOM in stdin request");
});

Deno.test("invocation reuses the hardened ssh arguments unchanged", () => {
  const inv = invocation(G, guestExecRequest(GUEST_EXEC));
  assertEquals(inv.argv, sshArgs(G, encodeCommand(STDIN_LAUNCHER)));
});

Deno.test("guestExec's password goes on stdin and nowhere in argv", () => {
  const req = guestExecRequest(GUEST_EXEC);
  for (const form of secretForms(PASSWORD)) {
    assertFalse(req.script.includes(form), "password in the script text");
  }
  assert(
    JSON.stringify(req.data).includes(PASSWORD),
    "password missing from data",
  );

  const inv = invocation(G, req);
  const surface = argvSurface(inv.argv);
  for (const form of secretForms(PASSWORD)) {
    assertFalse(surface.includes(form), "a secret form reached argv");
  }
  const sent = JSON.parse(inv.stdin);
  assertEquals(sent.script, req.script);
  assertEquals(sent.data, req.data);
});

Deno.test("argv does not depend on the secret at all", () => {
  const a = invocation(G, guestExecRequest(GUEST_EXEC));
  const b = invocation(
    G,
    guestExecRequest({ ...GUEST_EXEC, password: OTHER_PASSWORD }),
  );
  assertEquals(a.argv, b.argv);
  const c = invocation(G, createVmRequest(CREATE_WITH_GUEST));
  const d = invocation(
    G,
    createVmRequest({
      ...CREATE_WITH_GUEST,
      guest: { ...CREATE_WITH_GUEST.guest, adminPassword: OTHER_PASSWORD },
    }),
  );
  assertEquals(c.argv, d.argv);
});

Deno.test("createVm's unattend and first-boot script travel as data, not script", () => {
  const req = createVmRequest(CREATE_WITH_GUEST);
  for (const form of secretForms(PASSWORD)) {
    assertFalse(
      req.script.includes(form),
      "a secret form is in the script text",
    );
  }
  const data = JSON.stringify(req.data);
  assertStringIncludes(
    data,
    encodeUnattendPassword(PASSWORD, "AdministratorPassword"),
  );
  assertStringIncludes(data, BLOB_A);
  const surface = argvSurface(invocation(G, req).argv);
  for (const form of secretForms(PASSWORD)) {
    assertFalse(surface.includes(form), "a secret form reached argv");
  }
});

Deno.test("createVm without guest setup sends no unattend at all", () => {
  const { guest: _g, ...bare } = CREATE_WITH_GUEST;
  const data = JSON.stringify(createVmRequest(bare).data);
  assertFalse(data.includes("urn:schemas-microsoft-com:unattend"));
  assertFalse(data.includes("AdministratorPassword"));
});

Deno.test("the remote command line stays far below cmd.exe's 8191-character limit", () => {
  const inv = invocation(
    G,
    guestExecRequest({ ...GUEST_EXEC, script: "x".repeat(65536) }),
  );
  const remote = inv.argv.at(-1) ?? "";
  assert(remote.length < 4096, `remote command is ${remote.length} characters`);
});

Deno.test("request builders refuse what the schemas refuse", () => {
  assertThrows(() => guestExecRequest({ ...GUEST_EXEC, password: "" }));
  assertThrows(() => guestExecRequest({ ...GUEST_EXEC, script: "" }));
  assertThrows(() => createVmRequest({ ...CREATE_WITH_GUEST, vmName: "" }));
});

// ---------------------------------------------------------------------------
// Revision 2: deleteDisk.
//
// The existing `delete` treats a VM's whole disk chain as VM-owned, so with
// deleteDisks it would remove the golden parent of a differencing VM (or
// refuse outright when another VM shares it). `delete` keeps that reviewed
// contract unchanged. A VM made by createVm is removed with deleteDisks false,
// and its run-owned child disk is removed by deleteDisk, whose defaults refuse
// base disks, so a golden image cannot go through it by accident.
// ---------------------------------------------------------------------------

const CHILD = "C:\\source\\e2e-win01\\e2e-win01.vhdx";

Deno.test("deleteDisk requires an exact path confirmation and refuses base disks by default", () => {
  const a = DeleteDiskArgsSchema.parse({ path: CHILD, confirmPath: CHILD });
  assertEquals(a.allowBaseDisk, false);
  assert(
    ok(DeleteDiskArgsSchema, {
      path: "C:\\x\\disk.AVHDX",
      confirmPath: "C:\\x\\disk.AVHDX",
    }),
  );
  assertFalse(
    ok(DeleteDiskArgsSchema, { path: CHILD }),
    "confirmPath must be required",
  );
  assertFalse(
    ok(DeleteDiskArgsSchema, {
      path: "C:\\x\\image.iso",
      confirmPath: "C:\\x\\image.iso",
    }),
  );
  assertFalse(
    ok(DeleteDiskArgsSchema, {
      path: "C:\\x\\notes.txt",
      confirmPath: "C:\\x\\notes.txt",
    }),
  );
  assertFalse(
    ok(DeleteDiskArgsSchema, {
      path: "\\\\nas\\share\\d.vhdx",
      confirmPath: "\\\\nas\\share\\d.vhdx",
    }),
  );
  assertFalse(
    ok(DeleteDiskArgsSchema, {
      path: "C:\\x\\..\\y\\d.vhdx",
      confirmPath: "C:\\x\\..\\y\\d.vhdx",
    }),
  );
});

Deno.test("assertDiskDeleteConfirmed accepts only the identical path", () => {
  assertDiskDeleteConfirmed(CHILD, CHILD);
  for (
    const wrong of [
      "C:\\source\\e2e-win01\\E2E-WIN01.vhdx", // case differs: still not the same string
      "C:\\source\\e2e-win01\\e2e-win02.vhdx",
      "C:\\source\\e2e-win01\\",
      "",
    ]
  ) {
    assertThrows(() => assertDiskDeleteConfirmed(CHILD, wrong), Error);
  }
});

Deno.test("assertDiskDeleteConfirmed never echoes the paths it compared", () => {
  const secretish = "C:\\clients\\acme-merger\\d.vhdx";
  const err = assertThrows(
    () => assertDiskDeleteConfirmed(secretish, CHILD),
    Error,
  );
  assertFalse(err.message.includes("acme-merger"), "refusal quoted a path");
});

// ---------------------------------------------------------------------------
// Revision 3: heartbeat readiness.
//
// A healthy guest whose applications report nothing shows
// OkApplicationsUnknown, and that is the normal state for Server Core. "Ok"
// is not a value Hyper-V reports. Only exact names can be ready, and anything
// unrecognised waits rather than passes.
// ---------------------------------------------------------------------------

Deno.test("classifyHeartbeat: a running heartbeat is ready whatever the application health", () => {
  assertEquals(classifyHeartbeat("OkApplicationsHealthy"), "ready");
  assertEquals(classifyHeartbeat("OkApplicationsUnknown"), "ready");
});

Deno.test("classifyHeartbeat: states that waiting cannot fix fail at once", () => {
  for (const v of ["OkApplicationsCritical", "Error", "Paused", "Disabled"]) {
    assertEquals(classifyHeartbeat(v), "failed", v);
  }
});

Deno.test("classifyHeartbeat: boot-time states keep waiting", () => {
  for (const v of ["NoContact", "LostCommunication", "Unknown"]) {
    assertEquals(classifyHeartbeat(v), "waiting", v);
  }
});

Deno.test("classifyHeartbeat: nothing but an exact name can be ready", () => {
  for (
    const v of [
      "Ok", // not a value Hyper-V reports; revision 2's mistake
      "ok",
      "okapplicationshealthy",
      " OkApplicationsHealthy",
      "OkApplicationsHealthy ",
      "OkApplicationsSomethingNew",
      "",
      2, // enum number: names must be resolved PowerShell-side
      7,
      null,
      undefined,
      {},
      ["OkApplicationsHealthy"],
    ]
  ) {
    assertEquals(
      classifyHeartbeat(v),
      "waiting",
      JSON.stringify(v) ?? String(v),
    );
  }
});
