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
  DiscoverEnvelope,
  DiskDeleteEnvelope,
  dotNetDate,
  encodeCommand,
  frameParts,
  GlobalArgsSchema,
  matchCheckpoints,
  MAX_OUTPUT_BYTES,
  num,
  oneEnvelope,
  parseRow,
  PART_SEP,
  PsCheckpointRow,
  psQuote,
  PsStateRow,
  PsSwitchRow,
  PsVmHostRow,
  PsVmRow,
  RemoteText,
  RemoveCheckpointArgsSchema,
  resourceId,
  RestoreArgsSchema,
  safeState,
  slugPart,
  sshArgs,
  StopArgsSchema,
  SWITCH_TYPES,
  targetKey,
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

Deno.test("dotNetDate normalises ISO input and rejects everything else", () => {
  // An already-ISO value is accepted and normalised.
  assertEquals(dotNetDate("2026-08-29T00:00:00Z"), "2026-08-29T00:00:00.000Z");
  // It used to `return v` for anything unrecognised, so a cmdlet answering
  // "Unknown" was stored in a field documented as ISO-8601 and every consumer
  // downstream inherited that as a date. Not a timestamp is now null.
  assertEquals(dotNetDate("not a date"), null);
  assertEquals(dotNetDate("Unknown"), null);
  assertEquals(dotNetDate(""), null);
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
    names.map((n) => resourceId("hv1:22", "vm", n)),
  );
  assertEquals(new Set(ids).size, names.length);
  for (const id of ids) assertStringIncludes(id, "vm--hv1-22--web-server-");
});

Deno.test("resource ids are scoped by the configured target", async () => {
  // Same VM name on two targets is two machines, not one seen twice. Scoping
  // by the name the HOST reports was the first attempt and is unsound: two
  // machines can answer to one hostname, and then their VMs share IDs.
  const a = await resourceId("hv-a:22", "vm", "db");
  const b = await resourceId("hv-b:22", "vm", "db");
  assertEquals(a === b, false);
  // Same address, different port is still a different endpoint.
  const c = await resourceId("hv-a:2222", "vm", "db");
  assertEquals(a === c, false);
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

// --- security review round 3 -----------------------------------------------

Deno.test("wildcard names are refused everywhere a target is named", () => {
  // `Remove-VM -Name *` selects every machine on the host. Quoting does not
  // help: the string is well-formed, it just means "all of them".
  for (const bad of ["*", "?", "vm-[0-9]", "web*", "]"]) {
    assertEquals(VmNameArgs.safeParse({ vmName: bad }).success, false);
    assertEquals(
      CheckpointArgsSchema.safeParse({ vmName: "ok", name: bad }).success,
      false,
    );
    assertEquals(
      RemoveCheckpointArgsSchema.safeParse({ vmName: "ok", name: bad }).success,
      false,
    );
  }
});

Deno.test("a wildcard cannot be confirmed twice to satisfy a guard", () => {
  // This is why the wildcard check belongs in the schema and not in the
  // guard: confirmName === vmName is trivially true for "*", so the guard
  // would have confirmed the caller's intent to destroy the whole host.
  assertEquals(
    DeleteArgsSchema.safeParse({ vmName: "*", confirmName: "*" }).success,
    false,
  );
  assertEquals(
    RestoreArgsSchema.safeParse({
      vmName: "vm",
      name: "*",
      confirmDiscardSince: "*",
    }).success,
    false,
  );
});

Deno.test("control characters are refused in names", () => {
  // NUL matters specifically: resource IDs digest their parts joined by NUL,
  // so a name allowed to contain one could move the boundary and make two
  // different names produce a single ID.
  for (const bad of ["a\u0000b", "a\nb", "a\tb", "a\u007fb"]) {
    assertEquals(VmNameArgs.safeParse({ vmName: bad }).success, false);
  }
});

Deno.test("ordinary names still pass", () => {
  for (const ok of ["web01", "Web Server 01", "db_primary", "vm.test"]) {
    assertEquals(VmNameArgs.safeParse({ vmName: ok }).success, true);
  }
});

Deno.test("a missing collection is an error, not zero found", () => {
  // `top.vms ?? []` turned a truncated response into "this host runs no VMs".
  assertThrows(
    () =>
      parseRow(DiscoverEnvelope, {
        host: {
          Name: "hv1",
          LogicalProcessorCount: 8,
          MemoryCapacity: 1,
          VirtualMachinePath: "C:\\VMs",
        },
        switches: [],
      }, "discover envelope"),
    Error,
    "did not match the expected shape",
  );
});

Deno.test("an empty collection is still fine", () => {
  const ok = parseRow(DiscoverEnvelope, {
    host: {
      Name: "hv1",
      LogicalProcessorCount: 8,
      MemoryCapacity: 1,
      VirtualMachinePath: "C:\\VMs",
    },
    vms: [],
    switches: [],
  }, "discover envelope");
  assertEquals(ok.vms.length, 0);
});

Deno.test("a malformed state probe is not read as 'no such VM'", () => {
  // delete verifies itself by asking this question, so a broken probe that
  // answered "absent" would confirm a deletion that never happened.
  assertThrows(
    () => parseRow(PsStateRow, {}, "VM state probe"),
    Error,
    "did not match the expected shape",
  );
  // An explicit null still means absent.
  assertEquals(parseRow(PsStateRow, { state: null }, "probe").state, null);
});

Deno.test("disk deletion proof must account for every disk", () => {
  assertThrows(
    () => parseRow(DiskDeleteEnvelope, { diskCount: 2 }, "disk envelope"),
    Error,
    "did not match the expected shape",
  );
});

// --- security review round 5 ---------------------------------------------

Deno.test("id framing cannot be forged by part contents", () => {
  // The NUL join was unambiguous only while every part was NUL-free, which
  // held for caller-supplied names and never held for names discovered on
  // the host. Length prefixes read the boundary before the content.
  assertEquals(frameParts(["ab", "c"]) === frameParts(["a", "bc"]), false);
  assertEquals(frameParts(["a-b"]) === frameParts(["a", "b"]), false);
  assertEquals(frameParts(["1:x"]) === frameParts(["1", "x"]), false);
});

Deno.test("framing introduces no control characters", () => {
  const framed = frameParts(["host", "vm name", "cp"]);
  for (const ch of framed) {
    const code = ch.charCodeAt(0);
    assertEquals(code >= 0x20 && code !== 0x7f, true);
  }
});

Deno.test("remote names are held to the same rule as caller names", () => {
  // These feed resource IDs, so a host reporting a control character or a
  // wildcard must not have it reach an identifier.
  const bads = ["a" + String.fromCharCode(0) + "b", "*", "vm\nname"];
  for (const bad of bads) {
    assertEquals(
      PsVmRow.safeParse({
        Name: bad,
        State: "Running",
        Status: "OK",
        Generation: 2,
        ProcessorCount: 1,
        MemoryAssigned: 1,
      }).success,
      false,
    );
  }
});

Deno.test("state text in messages comes from a closed set", () => {
  assertEquals(safeState("Running"), "Running");
  assertEquals(safeState(null), "absent");
  // A host cannot choose the words that end up in a log line.
  assertEquals(
    safeState("Running\n\nATTACKER CONTROLLED"),
    "unrecognised-state",
  );
  assertEquals(safeState("../../etc/passwd"), "unrecognised-state");
});

Deno.test("the output cap is a byte limit, not a time limit", () => {
  // A host that never stops talking should hit a byte cap, not a heap
  // limit. The timeout bounds how LONG it runs, not how much it can send.
  assertEquals(MAX_OUTPUT_BYTES, 4 * 1024 * 1024);
});

Deno.test("checkpoint names match the way PowerShell matches them", () => {
  // -Name is case-insensitive on the host, so a case-sensitive === here
  // asked a different question: a VM holding "Nightly" passed a uniqueness
  // precheck for "nightly", and the cmdlet then acted on whichever it found.
  const rows = [{ Name: "Nightly" }, { Name: "weekly" }];
  assertEquals(matchCheckpoints(rows, "nightly").length, 1);
  assertEquals(matchCheckpoints(rows, "NIGHTLY").length, 1);
  assertEquals(matchCheckpoints(rows, "missing").length, 0);
});

Deno.test("an ambiguous checkpoint name is detectable, not guessed", () => {
  const rows = [{ Name: "Nightly" }, { Name: "nightly" }];
  // Two matches means the caller confirmed a name, not a choice.
  assertEquals(matchCheckpoints(rows, "NightLy").length, 2);
});

Deno.test("invisible characters cannot enter a name", () => {
  const bads = [
    "a" + String.fromCharCode(0x85) + "b",
    "a" + String.fromCharCode(0x2028) + "b",
    "a" + String.fromCharCode(0x202e) + "b",
    "a" + String.fromCharCode(0x200b) + "b",
    "a" + String.fromCharCode(0xfeff) + "b",
  ];
  for (const bad of bads) {
    assertEquals(VmNameArgs.safeParse({ vmName: bad }).success, false);
  }
});

// --- security review round 7 ---------------------------------------------

Deno.test("disk proof requires coverage, not just a matching count", () => {
  // Three results for three disks can still be indices 0, 0, 1 -- the
  // totals agree while disk 2 is unaccounted for.
  const dup = DiskDeleteEnvelope.parse({
    diskCount: 3,
    results: [
      { index: 0, removed: true },
      { index: 0, removed: true },
      { index: 1, removed: true },
    ],
  });
  const seen = new Set(dup.results.map((r) => r.index));
  assertEquals(seen.size === dup.diskCount, false);
});

Deno.test("uptime and parent are required, not optional", () => {
  // optional() let a response that omitted the field read as "unknown"
  // rather than "incomplete" -- the same lie as a zeroed capacity.
  assertThrows(
    () =>
      parseRow(PsVmRow, {
        Name: "vm1",
        State: "Running",
        Status: "OK",
        Generation: 2,
        ProcessorCount: 1,
        MemoryAssigned: 1,
      }, "VM record"),
    Error,
    "did not match the expected shape",
  );
  // A null uptime is legitimate for a stopped machine.
  const ok = parseRow(PsVmRow, {
    Name: "vm1",
    State: "Off",
    Status: "OK",
    Generation: 2,
    ProcessorCount: 1,
    MemoryAssigned: 1,
    Uptime: null,
  }, "VM record");
  assertEquals(ok.Uptime, null);
});

Deno.test("a root checkpoint has no parent, a broken row has no field", () => {
  const root = parseRow(PsCheckpointRow, {
    VMName: "vm1",
    Name: "base",
    CheckpointType: "Standard",
    CreationTime: "2026-01-01T00:00:00Z",
    ParentSnapshotName: null,
  }, "checkpoint record");
  assertEquals(root.ParentSnapshotName, null);
  assertThrows(
    () =>
      parseRow(PsCheckpointRow, {
        VMName: "vm1",
        Name: "base",
        CheckpointType: "Standard",
        CreationTime: "2026-01-01T00:00:00Z",
      }, "checkpoint record"),
    Error,
  );
});

Deno.test("no remote state reaches a message unscreened", async () => {
  // Three of these were fixed one round and a fourth was missed because it
  // was worded differently. Assert the property over the source instead of
  // trusting that every site was found by eye.
  const src = await Deno.readTextFile(
    new URL("./hyperv.ts", import.meta.url),
  );
  const bare = src.match(/\$\{(?:before|after)\}/g) ?? [];
  assertEquals(bare.length, 0);
});

// --- security review round 9 ---------------------------------------------

Deno.test("a timestamp is one of two forms or it is rejected", () => {
  const base = {
    VMName: "vm1",
    Name: "cp",
    CheckpointType: "Standard",
    ParentSnapshotName: null,
  };
  // Both real forms pass.
  for (const t of ["/Date(1234567890000)/", "2026-01-01T00:00:00Z"]) {
    assertEquals(
      PsCheckpointRow.safeParse({ ...base, CreationTime: t }).success,
      true,
    );
  }
  // Anything else is a broken response, not a missing date. Accepting it
  // and letting dotNetDate return null stored "no creation time" for a
  // value that was never a time at all.
  for (const t of ["Unknown", "", "2026", "later"]) {
    assertEquals(
      PsCheckpointRow.safeParse({ ...base, CreationTime: t }).success,
      false,
    );
  }
});

Deno.test("the destination cannot be rewritten by ambient ssh config", () => {
  // A Host block in ssh_config can rewrite HostName, and canonicalisation
  // can rewrite it again -- so a validated host could still resolve to a
  // different machine, which for a model carrying delete is the whole
  // ballgame. Both are pinned on the command line.
  const args = sshArgs(
    { host: "hv1", user: "admin", port: 22, timeoutSec: 30 },
    "BASE64",
  ).join(" ");
  assertStringIncludes(args, "HostName=hv1");
  assertStringIncludes(args, "CanonicalizeHostname=no");
});

Deno.test("the transport refuses everything it should, by property", () => {
  const args = sshArgs(
    { host: "hv1", user: "admin", port: 2222, timeoutSec: 30 },
    "BASE64",
  );
  const opt = (name: string) => {
    const i = args.indexOf("-o");
    let at = i;
    while (at !== -1) {
      if (args[at + 1]?.startsWith(name + "=")) return args[at + 1];
      at = args.indexOf("-o", at + 1);
    }
    return undefined;
  };
  // Asserted by option name, not argv position, so reordering cannot make
  // this pass while the guarantee is gone.
  assertEquals(opt("StrictHostKeyChecking"), "StrictHostKeyChecking=yes");
  assertEquals(opt("ControlMaster"), "ControlMaster=no");
  assertEquals(opt("ControlPath"), "ControlPath=none");
  assertEquals(opt("ProxyCommand"), "ProxyCommand=none");
  assertEquals(opt("PermitLocalCommand"), "PermitLocalCommand=no");
  assertEquals(opt("ForwardAgent"), "ForwardAgent=no");
  assertEquals(opt("ClearAllForwardings"), "ClearAllForwardings=yes");
  assertEquals(
    opt("PreferredAuthentications"),
    "PreferredAuthentications=publickey",
  );
  assertEquals(opt("PasswordAuthentication"), "PasswordAuthentication=no");
  // The destination is last and preceded by `--`, so it can never be read as
  // an option however it was spelled.
  assertEquals(args[args.length - 3], "--");
  assertEquals(args[args.length - 2], "admin@hv1");
});

// --- security review round 10 --------------------------------------------

Deno.test("a pattern-shaped non-date is rejected, not stored as null", () => {
  const base = {
    VMName: "vm1",
    Name: "cp",
    CheckpointType: "Standard",
    ParentSnapshotName: null,
  };
  // Matches ISO_DATE and names no real instant. Shape is not enough.
  for (const t of ["2026-13-45T99:99:99Z", "0000-00-00T00:00:00Z"]) {
    assertEquals(
      PsCheckpointRow.safeParse({ ...base, CreationTime: t }).success,
      false,
    );
  }
  // Real ones still pass.
  for (const t of ["/Date(1234567890000)/", "2026-01-01T00:00:00Z"]) {
    assertEquals(
      PsCheckpointRow.safeParse({ ...base, CreationTime: t }).success,
      true,
    );
  }
});

Deno.test("the embedded PowerShell carries no backtick", async () => {
  // A backtick inside the PowerShell terminates the JS template literal it
  // lives in. That has broken this file twice, both times in a comment,
  // and both times the failure looked like a TypeScript syntax error
  // hundreds of lines away from the cause.
  const src = await Deno.readTextFile(
    new URL("./hyperv.ts", import.meta.url),
  );
  for (const line of src.split("\n")) {
    const t = line.trim();
    if (t.startsWith("#")) assertEquals(t.includes("`"), false);
  }
});

// --- security review round 11 --------------------------------------------

Deno.test("identity includes the account, not just host and port", () => {
  // Hyper-V shows an unprivileged account a subset, so two configurations
  // differing only by user expose different inventories and must not
  // overwrite each other.
  const a = targetKey({ host: "hv1", user: "admin", port: 22 });
  const b = targetKey({ host: "hv1", user: "readonly", port: 22 });
  assertEquals(a === b, false);
});

Deno.test("unpaired surrogates cannot collapse two names into one id", () => {
  // TextEncoder maps every lone surrogate to the same replacement char
  // before hashing, and slugPart drops them all -- so two different
  // malformed names would have produced one identical ID.
  const lone1 = "vm" + String.fromCharCode(0xd800);
  const lone2 = "vm" + String.fromCharCode(0xd801);
  assertEquals(VmNameArgs.safeParse({ vmName: lone1 }).success, false);
  assertEquals(VmNameArgs.safeParse({ vmName: lone2 }).success, false);
  // A well-formed pair is a real character and stays allowed.
  assertEquals(VmNameArgs.safeParse({ vmName: "vm-load" }).success, true);
});

Deno.test("stored remote text is bounded and screened", () => {
  const ok = RemoteText(16);
  assertEquals(ok.safeParse("Operating normally").success, false);
  assertEquals(ok.safeParse("Running").success, true);
  // Control and line-separator characters cannot reach a stored field,
  // and one of these fields is a datastore TAG -- a queryable index,
  // not an opaque blob.
  assertEquals(
    ok.safeParse("a" + String.fromCharCode(0x2028) + "b").success,
    false,
  );
  assertEquals(
    ok.safeParse("a" + String.fromCharCode(0x1b) + "b").success,
    false,
  );
});

// --- security review round 13 --------------------------------------------

Deno.test("stored remote text refuses the same families names do", () => {
  // These were added to SafeName and not to RemoteText, leaving the gap
  // open on the class of strings that is actually remote-controlled --
  // including the queryable state tag.
  const t = RemoteText(64);
  assertEquals(
    t.safeParse("a" + String.fromCharCode(0x202e) + "b").success,
    false,
  );
  assertEquals(
    t.safeParse("a" + String.fromCharCode(0x200b) + "b").success,
    false,
  );
  assertEquals(t.safeParse("a" + String.fromCharCode(0xd800)).success, false);
  assertEquals(t.safeParse("Operating normally").success, true);
});

Deno.test("impossible hardware values are rejected, not stored", () => {
  // The comment claimed a zero-memory host is not a plausible reading of
  // reality while the schema accepted it -- the gap between saying a thing
  // and enforcing it.
  const base = {
    Name: "hv1",
    LogicalProcessorCount: 8,
    MemoryCapacity: 1,
    VirtualMachinePath: "C:\\VMs",
  };
  assertEquals(PsVmHostRow.safeParse(base).success, true);
  assertEquals(
    PsVmHostRow.safeParse({ ...base, MemoryCapacity: 0 }).success,
    false,
  );
  assertEquals(
    PsVmHostRow.safeParse({ ...base, LogicalProcessorCount: 0 }).success,
    false,
  );
});

Deno.test("Hyper-V has two generations and no others", () => {
  const vm = {
    Name: "vm1",
    State: "Running",
    Status: "OK",
    ProcessorCount: 2,
    MemoryAssigned: 1,
    Uptime: null,
  };
  assertEquals(PsVmRow.safeParse({ ...vm, Generation: 2 }).success, true);
  assertEquals(PsVmRow.safeParse({ ...vm, Generation: 7 }).success, false);
  assertEquals(PsVmRow.safeParse({ ...vm, ProcessorCount: 0 }).success, false);
});

Deno.test("every mutating verb resolves exactly one VM first", async () => {
  // delete learned this and the others did not, so start, stop and the
  // checkpoint verbs acted on whichever match the host picked. Assert the
  // property over the source: any cmdlet that mutates must be handed the
  // resolved object, never a name for the host to resolve a second time.
  const src = await Deno.readTextFile(
    new URL("./hyperv.ts", import.meta.url),
  );
  for (
    const bad of [
      "Start-VM -Name",
      "Stop-VM -Name ${",
      "Restore-VMSnapshot -VMName",
      "Remove-VMSnapshot -VMName",
    ]
  ) {
    assertEquals(src.includes(bad), false);
  }
  // And the guard itself appears once per mutating verb plus its definition.
  const uses = src.split("resolveOneVm(").length - 1;
  assertEquals(uses >= 6, true);
});

// --- security review round 15 --------------------------------------------

Deno.test("one envelope means exactly one", () => {
  // asArray(raw)[0] took the first of any number and discarded the rest
  // unseen, so a stray Write-Output made a response look valid.
  assertEquals(oneEnvelope('{"a":1}', "x").a, 1);
  assertThrows(() => oneEnvelope("[]", "x"), Error, "got 0");
  assertThrows(
    () => oneEnvelope('[{"a":1},{"b":2}]', "x"),
    Error,
    "got 2",
  );
});

Deno.test("a JSON array of non-objects is an error, not empty records", () => {
  // A cast would have let these through and every field read downstream
  // would be undefined rather than a failure.
  assertThrows(() => asArray("[1,2,3]"), Error, "expected a JSON object");
  assertThrows(() => asArray('["a"]'), Error, "expected a JSON object");
  assertEquals(asArray('{"a":1}').length, 1);
});

Deno.test("an unknown switch type is rejected, not relabelled", () => {
  // Inventing Type7 for an unrecognised enum stored malformed data under
  // a plausible-looking label.
  assertEquals(
    PsSwitchRow.safeParse({ Name: "lan", SwitchType: 2 }).success,
    true,
  );
  assertEquals(
    PsSwitchRow.safeParse({ Name: "lan", SwitchType: 7 }).success,
    false,
  );
  assertEquals(
    PsSwitchRow.safeParse({ Name: "lan", SwitchType: -1 }).success,
    false,
  );
});

Deno.test("disk ownership fails closed, in the script that decides it", async () => {
  const src = await Deno.readTextFile(
    new URL("./hyperv.ts", import.meta.url),
  );
  // An unreadable chain or an over-long one must refuse, never fall back
  // to treating an unreadable parent as "no parent".
  assertStringIncludes(src, "refusing to judge disk ownership");
  assertEquals(src.includes("catch { $next = $null }"), false);
});

// --- security review round 16 --------------------------------------------

Deno.test("a self-duplicate disk is refused before anything is removed", async () => {
  // The README promised "the same file added twice" was refused and only
  // other-VM sharing was ever implemented. Undetected, the first pass
  // deletes the file and the second reports a failure for a disk already
  // gone -- after Remove-VM, with nothing left to abort into.
  const src = await Deno.readTextFile(
    new URL("./hyperv.ts", import.meta.url),
  );
  assertStringIncludes(src, "attached to this VM more than once");
  // Both refusals must precede the removal, not follow it.
  const guard = src.indexOf("attached to this VM more than once");
  const removal = src.indexOf("Remove-VM -VM $vm -Force");
  assertEquals(guard < removal && guard !== -1, true);
});

Deno.test("a genuine read failure is not swallowed as an overflow", async () => {
  // Catching every stream error meant a broken transport ended the read
  // quietly and handed back a partial response, which the caller then
  // treated as complete. For a method that proves a deletion by reading a
  // response, that is the worst available outcome.
  const src = await Deno.readTextFile(
    new URL("./hyperv.ts", import.meta.url),
  );
  assertStringIncludes(src, "reading the remote response failed");
  assertEquals(src.includes("} catch {\n    // The stream dies"), false);
});
