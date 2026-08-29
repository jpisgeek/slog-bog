/**
 * Tests for the pure surface of the Hyper-V model.
 *
 * Everything here runs without a host. That is the point: the logic worth
 * testing is the logic that is dangerous to prove any other way -- a delete
 * guard is not something to verify by deleting a machine, and a quoting bug is
 * not something to discover by watching a VM name become code on a Windows
 * box. The parts that need the host (runPowerShell, discover, the lifecycle
 * methods) stay unexported and are proven against the live host instead.
 */
import {
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import { z } from "npm:zod@4";
import {
  asArray,
  assertDeleteConfirmed,
  assertRestoreConfirmed,
  CheckpointArgsSchema,
  classifyRemote,
  DeleteArgsSchema,
  dotNetDate,
  encodeCommand,
  GlobalArgsSchema,
  num,
  parseRow,
  PART_SEP,
  psQuote,
  PsVmHostRow,
  PsVmRow,
  RemoveCheckpointArgsSchema,
  resourceId,
  RestoreArgsSchema,
  slugPart,
  StopArgsSchema,
  SWITCH_TYPES,
  VmNameArgs,
} from "./hyperv.ts";

/** Decode what -EncodedCommand would receive, so the test reads the wire. */
function decodeEncoded(b64: string): string {
  const bin = atob(b64);
  let out = "";
  for (let i = 0; i < bin.length; i += 2) {
    out += String.fromCharCode(
      bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8),
    );
  }
  return out;
}

Deno.test("encodeCommand produces UTF-16LE base64 that round-trips", () => {
  for (
    const s of [
      "Get-VM",
      "",
      "a",
      "Get-VM -Name 'x' | ConvertTo-Json -Compress",
      "$ErrorActionPreference='Stop'\n$x = 1",
    ]
  ) {
    assertEquals(decodeEncoded(encodeCommand(s)), s, `round-trip: ${s}`);
  }
});

Deno.test("encodeCommand emits little-endian pairs, not UTF-8", () => {
  // 'A' is 0x41. UTF-16LE is 0x41 0x00; UTF-8 would be a single 0x41. Getting
  // this backwards yields a command PowerShell decodes as mojibake rather than
  // one it rejects, so the failure would be silent.
  assertEquals(encodeCommand("A"), btoa("\x41\x00"));
  assertEquals(atob(encodeCommand("AB")).length, 4);
});

Deno.test("encodeCommand carries characters above ASCII intact", () => {
  // A VM name or comment can legitimately hold these, and cmd.exe is exactly
  // where they would otherwise be mangled.
  for (const s of ["café", "—dash", "日本語", "emoji 😀"]) {
    assertEquals(decodeEncoded(encodeCommand(s)), s);
  }
});

Deno.test("asArray normalises ConvertTo-Json's one-versus-many shapes", () => {
  // The whole reason this function exists: one item is an object, many are an
  // array, and code that assumes either breaks when the count changes.
  assertEquals(asArray('{"a":1}'), [{ a: 1 }]);
  assertEquals(asArray('[{"a":1},{"a":2}]'), [{ a: 1 }, { a: 2 }]);
  assertEquals(asArray("[]"), []);
});

Deno.test("asArray treats empty and null as no rows, not as failure", () => {
  // A host with no VMs answers with nothing. That is data, not an error.
  assertEquals(asArray(""), []);
  assertEquals(asArray("null"), []);
});

Deno.test("asArray refuses non-JSON and truncates what it quotes back", () => {
  // PowerShell printing a banner or an error over the answer is the common
  // case. The message must not paste an unbounded remote string into a log.
  const err = assertThrows(
    () => asArray("At line:1 char:1 + Get-VM : The term is not recognized"),
    Error,
  );
  assertStringIncludes(err.message, "expected JSON from PowerShell");

  const long = assertThrows(() => asArray("x".repeat(500)), Error);
  assertEquals(
    long.message.length < 200,
    true,
    "must not quote back 500 chars",
  );
});

Deno.test("num accepts only finite numbers", () => {
  assertEquals(num(0), 0);
  assertEquals(num(-1.5), -1.5);
  assertEquals(num(NaN), null);
  assertEquals(num(Infinity), null);
  assertEquals(num("7"), null, "a numeric string is not a number");
  assertEquals(num(null), null);
  assertEquals(num(undefined), null);
  assertEquals(num(true), null);
});

Deno.test("dotNetDate decodes /Date(ms)/ to ISO", () => {
  assertEquals(dotNetDate("/Date(0)/"), "1970-01-01T00:00:00.000Z");
  assertEquals(
    dotNetDate("/Date(1787883964960)/"),
    new Date(1787883964960).toISOString(),
  );
  assertEquals(
    dotNetDate("/Date(-86400000)/"),
    "1969-12-31T00:00:00.000Z",
    "pre-epoch dates are representable and must not be dropped",
  );
});

Deno.test("dotNetDate passes through a string that is already a date", () => {
  // Not every field arrives wrapped; passing through is deliberate.
  assertEquals(dotNetDate("2026-08-29T00:00:00Z"), "2026-08-29T00:00:00Z");
  assertEquals(dotNetDate("not a date"), "not a date");
});

Deno.test("dotNetDate returns null for non-strings", () => {
  assertEquals(dotNetDate(null), null);
  assertEquals(dotNetDate(1787883964960), null);
  assertEquals(dotNetDate(undefined), null);
});

Deno.test("psQuote makes interpolation impossible", () => {
  // Single-quoted PowerShell strings do not interpolate, so the only escape
  // that matters is the quote itself. These are the shapes that would become
  // code inside a double-quoted string.
  assertEquals(psQuote("web01"), "'web01'");
  assertEquals(psQuote("it's"), "'it''s'");
  assertEquals(psQuote("$(Get-Process)"), "'$(Get-Process)'");
  assertEquals(psQuote("`n"), "'`n'");
  assertEquals(psQuote("a; Remove-VM -Name b"), "'a; Remove-VM -Name b'");
  assertEquals(psQuote("$env:USERNAME"), "'$env:USERNAME'");
});

Deno.test("psQuote closes the quote it opens even for adversarial input", () => {
  // A value ending in a quote is the classic break-out. Doubling keeps the
  // literal balanced.
  for (const v of ["'", "''", "x'", "'; Remove-VM -Name x #"]) {
    const q = psQuote(v);
    assertEquals(q.startsWith("'"), true);
    assertEquals(q.endsWith("'"), true);
    const inner = q.slice(1, -1);
    // Every quote inside the literal must be part of a doubled pair.
    assertEquals(
      inner.replace(/''/g, "").includes("'"),
      false,
      `unbalanced quote for input ${JSON.stringify(v)}`,
    );
  }
});

Deno.test("assertRestoreConfirmed permits an exact acknowledgement", () => {
  assertRestoreConfirmed("nightly", "nightly");
});

Deno.test("assertRestoreConfirmed refuses anything less than exact", () => {
  // Case and whitespace are not forgiven on purpose: a caller who cannot
  // reproduce the name has not shown they know what is being discarded.
  for (
    const [name, confirm] of [
      ["nightly", "Nightly"],
      ["nightly", " nightly"],
      ["nightly", "nightly "],
      ["nightly", "other"],
      ["nightly", ""],
    ]
  ) {
    const err = assertThrows(
      () => assertRestoreConfirmed(name, confirm),
      Error,
      undefined,
      `should refuse ${JSON.stringify(confirm)}`,
    );
    assertStringIncludes(err.message, "refusing to restore");
  }
});

Deno.test("assertDeleteConfirmed permits an exact confirmation", () => {
  assertDeleteConfirmed("build-01", "build-01");
});

Deno.test("assertDeleteConfirmed refuses a mismatch", () => {
  for (
    const [vm, confirm] of [
      ["build-01", "build-02"],
      ["build-01", "Build-01"],
      ["build-01", ""],
      ["build-01", "build-01 "],
    ]
  ) {
    const err = assertThrows(
      () => assertDeleteConfirmed(vm, confirm),
      Error,
      undefined,
      `should refuse ${JSON.stringify(confirm)}`,
    );
    assertStringIncludes(err.message, "refusing to delete");
  }
});

Deno.test("destructive schemas require their confirmation field", () => {
  // The guard above is only reachable if the schema admits the call at all.
  assertThrows(() => DeleteArgsSchema.parse({ vmName: "a" }));
  assertThrows(() => RestoreArgsSchema.parse({ vmName: "a", name: "n" }));
  assertThrows(
    () => DeleteArgsSchema.parse({ vmName: "a", confirmName: "" }),
    Error,
    undefined,
    "an empty confirmation is not a confirmation",
  );
});

Deno.test("destructive defaults are the conservative ones", () => {
  // Defaults decide what happens when a workflow omits the field, which is
  // where a harsh default does its damage.
  assertEquals(
    DeleteArgsSchema.parse({ vmName: "a", confirmName: "a" }).deleteDisks,
    false,
    "disks must survive a delete that did not ask to remove them",
  );
  assertEquals(
    StopArgsSchema.parse({ vmName: "a" }).force,
    false,
    "a stop must ask the guest before cutting power",
  );
});

Deno.test("schemas reject empty names rather than passing them to the host", () => {
  assertThrows(() => VmNameArgs.parse({ vmName: "" }));
  assertThrows(() => StopArgsSchema.parse({ vmName: "" }));
  assertThrows(() => CheckpointArgsSchema.parse({ vmName: "a", name: "" }));
});

Deno.test("global args default the transport but demand an identity", () => {
  const g = GlobalArgsSchema.parse({ host: "h", user: "u" });
  assertEquals(g.port, 22);
  assertEquals(g.timeoutSec, 30);
  // host and user are vault-sourced and have no safe default.
  assertThrows(() => GlobalArgsSchema.parse({ user: "u" }));
  assertThrows(() => GlobalArgsSchema.parse({ host: "h" }));
  assertThrows(() => GlobalArgsSchema.parse({ host: "", user: "u" }));
});

Deno.test("switch types cover the enum Hyper-V actually returns", () => {
  assertEquals(SWITCH_TYPES[0], "Private");
  assertEquals(SWITCH_TYPES[1], "Internal");
  assertEquals(SWITCH_TYPES[2], "External");
  assertEquals(
    SWITCH_TYPES[3],
    undefined,
    "unknown stays unknown, not guessed",
  );
});

// --- security review round 2 -----------------------------------------------

Deno.test("resource ids cannot collide once names are slugged", async () => {
  // The whole point of the digest. These four VM names all slug to the same
  // string, and the old `vm-${name}` form would have written them all to one
  // record, each overwriting the last.
  const names = ["web server", "web-server", "web_server", "WEB  SERVER"];
  const ids = await Promise.all(
    names.map((n) => resourceId("vm", "host-a", n)),
  );
  assertEquals(new Set(ids).size, names.length);
  for (const id of ids) assertStringIncludes(id, "vm--host-a--web-server-");
});

Deno.test("resource ids are scoped by host", async () => {
  // Same VM name on two hosts is two machines, not one seen twice.
  const a = await resourceId("vm", "host-a", "db");
  const b = await resourceId("vm", "host-b", "db");
  assertEquals(a === b, false);
});

Deno.test("the part separator cannot occur inside a part", () => {
  // Two dashes is only unambiguous because slugPart collapses every run of
  // non-alphanumerics to exactly one dash. If that ever stops being true the
  // separator stops being a separator.
  for (const raw of ["a--b", "a  b", "a__b", "a...b", "-a-", "a/b\\c"]) {
    assertEquals(slugPart(raw).includes(PART_SEP), false);
  }
});

Deno.test("slugPart never returns an empty id fragment", () => {
  for (const raw of ["", "   ", "!!!", "---"]) {
    assertEquals(slugPart(raw), "unnamed");
  }
});

Deno.test("host records are rejected rather than zero-filled", () => {
  // The failure this guards: a cmdlet that returns nothing for MemoryCapacity
  // used to become 0, and a half-collected host was written down as a whole
  // one. A host with no memory is not a reading, it is a broken query.
  assertThrows(
    () =>
      parseRow(PsVmHostRow, {
        Name: "hv1",
        LogicalProcessorCount: 8,
        VirtualMachinePath: "C:\\VMs",
      }, "host record"),
    Error,
    "did not match the expected shape",
  );
});

Deno.test("parse failures name the field, never the value", () => {
  try {
    parseRow(PsVmRow, {
      Name: "SECRET-VM-NAME",
      State: "Running",
      Status: "OK",
      Generation: "two",
      ProcessorCount: 2,
      MemoryAssigned: 1,
    }, "VM record");
    throw new Error("should have thrown");
  } catch (e) {
    const msg = String(e);
    assertStringIncludes(msg, "Generation");
    // The offending row must not be echoed back into a message that lands in
    // a log or a resource.
    assertEquals(msg.includes("SECRET-VM-NAME"), false);
  }
});

Deno.test("remote stderr is classified, never echoed", () => {
  const leaky =
    "ssh: connect to host hv-01.corp.example port 22: Connection refused";
  const verdict = classifyRemote(leaky);
  assertEquals(verdict, "connection-failed");
  assertEquals(verdict.includes("hv-01"), false);
});

Deno.test("an unrecognised failure yields a verdict, not a sample", () => {
  const v = classifyRemote("C:\\ClusterStorage\\Volume1\\vm.vhdx is haunted");
  assertEquals(v, "unclassified");
  assertEquals(v.includes("vhdx"), false);
});

Deno.test("host strings that would redirect the connection are refused", () => {
  // ssh honours the LAST userinfo section, so a host carrying `user@` quietly
  // sends the connection somewhere else. A leading dash is read as an option.
  for (
    const bad of [
      "attacker@elsewhere",
      "-oProxyCommand=curl evil",
      "host with space",
      "ssh://host",
      "host:22",
      "host\nnewline",
    ]
  ) {
    assertEquals(
      GlobalArgsSchema.safeParse({ host: bad, user: "admin" }).success,
      false,
    );
  }
});

Deno.test("ordinary hosts still parse", () => {
  for (const ok of ["hv1", "hv-01.lan", "10.0.0.5", "[fe80::1]"]) {
    assertEquals(
      GlobalArgsSchema.safeParse({ host: ok, user: "admin" }).success,
      true,
    );
  }
});

Deno.test("user strings that would smuggle an option are refused", () => {
  for (const bad of ["-oProxyCommand=x", "a b", "u@h", ""]) {
    assertEquals(
      GlobalArgsSchema.safeParse({ host: "hv1", user: bad }).success,
      false,
    );
  }
});

Deno.test("create and remove no longer share one description", () => {
  // They shared a schema, so removeCheckpoint published the exact inverse of
  // the truth: that the checkpoint must NOT already exist.
  const create = z.toJSONSchema(CheckpointArgsSchema) as Record<string, any>;
  const remove = z.toJSONSchema(RemoveCheckpointArgsSchema) as Record<
    string,
    any
  >;
  assertStringIncludes(create.properties.name.description, "Must not already");
  assertStringIncludes(remove.properties.name.description, "Must already");
});

Deno.test("deleting a running VM needs the power-off acknowledged", () => {
  const args = z.toJSONSchema(DeleteArgsSchema) as Record<string, any>;
  assertStringIncludes(
    args.properties.confirmForcePowerOff.description,
    "RUNNING",
  );
  // Off by default: the acknowledgement has to be an act, not an inheritance.
  assertEquals(
    DeleteArgsSchema.parse({
      vmName: "a",
      confirmName: "a",
    }).confirmForcePowerOff,
    false,
  );
});
