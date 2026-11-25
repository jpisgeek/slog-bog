# Plan: Hyper-V provisioning for `@jpisgeek/hyperv`

Status: ready for implementation, **revision 3** · Owner of plan and acceptance tests: reviewer · Implementer: assigned worker

Revision 3 (2026-11-25): live step 4 showed a healthy guest reporting `OkApplicationsUnknown`. The plan accepted
only `OkApplicationsHealthy` or `Ok`, and Hyper-V never reports `Ok`. Readiness is now `classifyHeartbeat`. See
"Heartbeat readiness".

Revision 2 (2026-11-25): the implementer showed from source that `delete` with `deleteDisks: true` treats a
differencing VM's golden parent as VM-owned. `delete` keeps its reviewed contract unchanged. A new guarded
`deleteDisk` method removes only the child, and live step 8 is rewritten around it. See "Removing a differencing
VM: `deleteDisk`".

Revision 1 (2026-11-25): secrets and large payloads now travel on SSH stdin, never in argv. The implementer
raised it: passwords inside `-EncodedCommand` are only base64, which shows up in local `ps` output and in the
host's process command line. See "Secrets and large payloads travel on stdin" below. The acceptance tests gained
a matching section.

## Goal

`@jpisgeek/hyperv` can read a host and act on existing VMs, but it cannot create one. This plan adds the
methods needed to go from an install ISO on the host to a running, SSH-reachable Windows Server guest, and
back to nothing, without a person at the console. The first consumer is the live acceptance run for
`@jpisgeek/herdr-windows`. Anyone who needs a disposable Windows guest on Hyper-V is the second.

## Scope

**Phase 1 (this plan):** Windows Server guests.

| Method | Mutates | What it does |
|---|---|---|
| `buildWindowsImage` | host disk | Applies one edition of an install ISO to a new, generic, bootable VHDX: a golden image. |
| `createVm` | host | Creates a Generation 2 VM on a differencing child of a golden image (or a full copy) and specializes the guest offline. |
| `waitReady` | no | Waits for the guest heartbeat, an IPv4 address from the integration services, and optionally an open TCP port. |
| `guestExec` | guest | Runs a PowerShell script inside the guest over PowerShell Direct (VMBus, no guest network needed). |
| `deleteDisk` | host disk | Deletes one VHDX/AVHDX that no VM uses. Refuses base (non-differencing) disks unless `allowBaseDisk`. This is how a differencing VM's child is removed. |

`start`, `stop`, `delete` and the checkpoint methods already exist and are reused as they are.

**Phase 2 (separate plan, later):** Linux guests via cloud-init NoCloud seed ISOs, the way the host's existing
Linux VMs were built.

**Not in scope:** clustering, live migration, replica, storage QoS, nested virtualization, editing existing VMs,
and activation. Volume-licence or evaluation media run unactivated, which is fine for disposable guests. An AVMA
or KMS key can be added later as an optional argument.

## Design

### Golden image, then specialize per VM

`buildWindowsImage` produces an image that is **generic**: no computer name, no password, no keys. Applying a
WIM with `Expand-WindowsImage` leaves Windows in the same state as a sysprepped image, so no sysprep pass is
needed. Steps on the host:

1. `Mount-DiskImage` the ISO. Find `sources\install.wim` (or `install.esd`).
2. `Get-WindowsImage` and select the image whose `ImageName` equals `edition` **exactly**. No match, or more than
   one, is an error that lists the available names, never a guess.
3. `New-VHD -Dynamic`, `Mount-VHD`, `Initialize-Disk -PartitionStyle GPT`, then create an EFI partition
   (FAT32, 260 MB), an MSR partition (16 MB) and an NTFS Windows partition. Use the GPT type GUIDs explicitly.
4. `Expand-WindowsImage` to the Windows partition, then `bcdboot <W>:\Windows /s <S>: /f UEFI`.
5. Dismount the VHD and the ISO **in a `finally` block**. A failed build must not leave either mounted. Delete
   a half-written output VHDX on failure.
6. Record an `image` resource: output path, size, source ISO path, ISO length and last-write time, the edition
   name and index, the WIM's build number, and the build duration.

The method is idempotent: if `outputPath` exists and its recorded metadata matches the request, it returns the
existing record. If the path exists and does not match, it refuses unless `rebuild: true`. `rebuild` refuses
while any VM's disk chain uses the image as a parent. Name that VM in the error.

`createVm` with `diskMode: "differencing"` (the default) creates a child VHDX next to the VM and **never writes
to the parent**. With a `guest` block it specializes the child **offline, before first boot**:

1. `Mount-VHD` the child (never the parent), find its Windows partition.
2. Write `Windows\Panther\unattend.xml` from `renderUnattend` (computer name, encoded admin password, OOBE
   skipped, time zone). The XML arrives in the stdin request's data (`$Data`), never in the script text.
3. Write `Windows\Setup\Scripts\SetupComplete.cmd`, a one-line launcher for `SetupComplete.ps1` from
   `renderSetupComplete` (also delivered in `$Data`). That script runs as SYSTEM at the end of setup. It enables sshd (installing the
   capability only if the service is missing), opens 22/TCP and writes the authorized keys. After a successful
   run it deletes itself and the unattend file, which holds the encoded password.
4. Dismount in `finally`.
5. `New-VM -Generation 2`, `Set-VMFirmware -SecureBootTemplate MicrosoftWindows`, attach the child, connect the
   switch, set CPU and memory (static memory: dynamic memory makes `waitReady` timing noisy), and enable the
   Guest Service Interface integration service.

`createVm` records the child's path and its parent's path on the `vm` resource (`diskPath`, `parentPath`).

### Removing a differencing VM: `deleteDisk`

The existing `delete` treats the attached disk **and every parent behind it** as VM-owned. That is right for
checkpoint chains, where the parent is the VM's own original disk. It is wrong for a `createVm` child, whose
parent is a shared golden image. With `deleteDisks: true` it would delete the golden image when no other VM uses
it, and refuse the whole delete when one does. `delete` keeps its reviewed contract unchanged. A VM created with
`diskMode: "differencing"` is removed with `delete` (`deleteDisks: false`), then `deleteDisk` on its child. The
README must say this in `delete`'s and `createVm`'s sections.

`deleteDisk` (`path`, `confirmPath`, `allowBaseDisk` default false) refuses, before touching anything, when:
- `confirmPath` is not the identical string. Checked locally with `assertDiskDeleteConfirmed`, whose error never
  quotes either path.
- The file does not exist or `Get-VHD` cannot read it (fail closed).
- Any VM has it attached, or it appears anywhere in the parent chain of any disk attached to any VM. Reuse the
  existing chain walk, applied to all VMs, with its depth bound and its fail-closed handling of unreadable chains.
- It is not a differencing disk and `allowBaseDisk` is false.

It re-checks attachment immediately before `Remove-Item`, as `delete` does, and records a `diskDelete` resource
with the path, the VHD type and the parent path.

`createVm` refuses if a VM with that name exists. It does not adopt, modify or "fix" an existing VM. It does not
start the VM. The caller runs `start`.

### Waiting and reaching the guest

`waitReady` polls `Get-VM` (heartbeat, classified by `classifyHeartbeat` below) and `Get-VMNetworkAdapter`
(`IPAddresses`, first non-link-local IPv4) until `timeoutSec` runs out. With `tcpPort` set, it also requires
`Test-NetConnection -Port` from the host to that address to succeed. It returns the address, the heartbeat state
and the elapsed time, and it records the address on the VM resource. Timing out is an error that says which
condition never became true.

**Heartbeat readiness (revision 3).** Hyper-V reports the heartbeat integration (the primary status) and guest
application health (the secondary status) in one value. A healthy guest whose applications report nothing,
which is normal for Server Core, shows `OkApplicationsUnknown`. `Ok` is not a value Hyper-V reports.
Resolve the value to its **name** on the PowerShell side (`[string]$vm.Heartbeat`), never the enum number, as
the model already does for `State`. Then `classifyHeartbeat(name)` returns:

| Result | Values | `waitReady` does |
|---|---|---|
| `ready` | `OkApplicationsHealthy`, `OkApplicationsUnknown` | The heartbeat condition is met. |
| `failed` | `OkApplicationsCritical`, `Error`, `Paused`, `Disabled` | Stops at once with an error naming the value. Waiting cannot fix any of these. |
| `waiting` | `NoContact`, `LostCommunication`, `Unknown`, and **anything else**, including numbers, empty, null or unrecognised names | Keeps polling. At timeout, the error names the last value seen. |

Unrecognised values wait rather than pass, so a value Microsoft adds later can never be read as healthy.

`guestExec` runs `Invoke-Command -VMName <name> -Credential <cred> -ScriptBlock { ... }` on the host. The host
script builds the credential from `$Data.user` and `$Data.password` (`ConvertTo-SecureString -AsPlainText
-Force`). Both arrive on stdin. The guest script also arrives in `$Data` and runs with
`[scriptblock]::Create`. Output is capped at `MAX_OUTPUT_BYTES` like every other method, and it is recorded as
an `exec` resource with exit status and truncation flag. The password is never recorded.

### Secrets and large payloads travel on stdin

The rule: **no secret, and no reversible encoding of one (base64 of UTF-8 or UTF-16LE, the unattend encoding),
ever appears in argv**, either in local ssh's (readable by any local user through `ps`) or in the remote process
command line (`Win32_Process.CommandLine`). Secrets also stay out of logs, resources and error text, as before.

How:

- `STDIN_LAUNCHER` is one fixed, ASCII PowerShell script with no placeholders. It reads
  `[Console]::In.ReadToEnd()`, parses the JSON with `ConvertFrom-Json`, exposes the `data` member to the request
  script as `$Data`, and runs the `script` member as a script block. It is the only thing ever encoded into argv
  for methods that carry a secret or a large payload. Its argv is the same for every request.
- `stdinRequest(script, data)` is the JSON document written to ssh's stdin, with no BOM. Write it, then close
  stdin so `ReadToEnd` returns.
- `guestExecRequest(args)` and `createVmRequest(args)` parse their arguments through the schemas (so they throw on
  bad input) and return `{ script, data }`. The script text references `$Data` and never holds a secret.
- `invocation(globalArgs, request)` returns `{ argv, stdin }`, where `argv` is exactly
  `sshArgs(globalArgs, encodeCommand(STDIN_LAUNCHER))`. The hardened ssh arguments are reused unchanged.
- `runPowerShell` gains an optional `input` argument. Without it, behaviour is byte-identical to today
  (`stdin: "null"`), so the existing methods and `hyperv_test.ts` stay untouched. With it, stdin is piped,
  written and closed. Output caps, kill-on-overflow and the abort/timeout distinction apply unchanged.
- `buildWindowsImage` and `waitReady` carry no secret and may keep the direct `-EncodedCommand` path, as long as
  their encoded command stays under 8,000 characters (cmd.exe's limit is 8,191). Otherwise they use the launcher
  too.

### Rules carried over from the existing model (non-negotiable)

- Every remote command goes through `encodeCommand` and `runPowerShell`. Every caller-supplied value
  interpolated into PowerShell goes through `psQuote`, unless it travels in `$Data`, which is never interpolated
  into script text. No exceptions for "safe" values.
- No defaults for identity or location: `host`, `user`, `isoPath`, `baseImage` and `switchName` are always
  explicit.
- `classifyRemote` handles stderr. Remote text is never echoed back raw.
- JSON out of PowerShell is parsed with the existing `asArray`. The host runs Windows PowerShell 5.1, which has no
  `ConvertTo-Json -AsArray`.
- Validation happens in schemas and is re-checked in the renderers. A renderer given input its schema would
  refuse throws.
- Sensitive arguments (`adminPassword`, `password`) carry `.meta({ sensitive: true })` and never reach a
  resource, a log line or an error message.

## Contract: exported surface

The acceptance tests import these from `hyperv.ts`. Names and shapes are fixed. Internals are yours.

| Export | Kind | Contract summary |
|---|---|---|
| `WindowsPath` | zod string | Drive-absolute, backslash-only. No UNC, device, `.` or `..` segments, no `"<>\|*?`, no control characters, no leading or trailing space, at most 240 characters. |
| `ComputerName` | zod string | 1–15 of `[A-Za-z0-9-]`, not all digits, no leading or trailing hyphen. |
| `SshPublicKey` | zod string | `<type> <base64> [comment]`. Types: ssh-ed25519, ecdsa-sha2-nistp256/384/521, sk-ssh-ed25519@openssh.com, ssh-rsa. The blob's embedded type must equal the declared type. Comment limited to `[A-Za-z0-9@._+:=-]` and spaces. No options, no line breaks. |
| `AdminPassword` | zod string | 14–127 characters, no control characters, `.meta({ sensitive: true })`. |
| `BuildImageArgsSchema` | zod object | `isoPath` (`.iso`), `edition` (1–128 printable), `outputPath` (`.vhdx`), `sizeGb` 32–2048 integer, default 64, `rebuild` default false. |
| `CreateVmArgsSchema` | zod object | `vmName` (`SafeName`), `baseImage` (`.vhdx`), `switchName` (`SafeName`), `cpuCount` 1–64 default 2, `memoryGb` 1–256 default 4, `diskMode` `differencing` or `copy`, optional `guest` discriminated on `os`. Phase 1 has only `"windows"`: `computerName`, `adminPassword`, `authorizedKeys` (≤16, unique), `enableSsh` default true, optional `timeZone`. |
| `WaitReadyArgsSchema` | zod object | `vmName`, `timeoutSec` 30–1800 default 600, optional `tcpPort` 1–65535. |
| `classifyHeartbeat(value)` | function | `"ready" \| "waiting" \| "failed"` per the heartbeat table. Takes `unknown`, and only exact string names can be `ready`. |
| `GuestExecArgsSchema` | zod object | `vmName`, `user` (plain login name), `password` (sensitive, required), `script` 1–65536 characters, `timeoutSec` ≤600 default 120. |
| `encodeUnattendPassword(pw, kind)` | function | base64 of UTF-16LE(`pw + kind`), `kind` ∈ `AdministratorPassword`, `Password`. |
| `renderUnattend({ computerName, adminPassword, timeZone? })` | function | Deterministic unattend XML for passes specialize and oobeSystem, amd64. Encoded password with `PlainText` false, OOBE pages hidden, default time zone `UTC`. Throws on invalid input. |
| `renderSetupComplete({ enableSsh, authorizedKeys })` | function | ASCII PowerShell. See the acceptance tests for the exact invariants: SIDs, no `Out-File`, BOM-free writes, capability install only when sshd is missing, nothing SSH-related when `enableSsh` is false. |
| `STDIN_LAUNCHER` | string | Fixed, ASCII, secret-free launcher that reads the stdin request (see above). |
| `stdinRequest(script, data)` | function | JSON `{ script, data }`, no BOM. |
| `guestExecRequest(args)` / `createVmRequest(args)` | function | Parse through the schemas (throw on invalid input) and return `{ script, data }`. No secret, or encoding of one, in `script`. |
| `DeleteDiskArgsSchema` | zod object | `path` and `confirmPath` (`WindowsPath`, ending `.vhdx` or `.avhdx`, case-insensitive), `allowBaseDisk` default false. |
| `assertDiskDeleteConfirmed(path, confirmPath)` | function | Throws unless the two strings are identical (case included). The error never contains either path. |
| `invocation(globalArgs, request)` | function | `{ argv, stdin }`, with `argv` equal to `sshArgs(globalArgs, encodeCommand(STDIN_LAUNCHER))` and independent of every secret. |

New resources: `image` (one per golden image) and `exec` (one per `guestExec` run). The `vm` resource gains an
optional `ipv4`.

## Acceptance

### Offline: `hyperv/hyperv_provision_acceptance_test.ts`

The reviewer owns this file. Do not edit it. Its SHA-256 is recorded in the private build brief and checked
before every review. `deno test --allow-all hyperv/` must pass, along with the existing `hyperv_test.ts`. Run
`deno fmt --check`, `deno lint`, `deno check` and `swamp extension fmt --check`, and do not let
`swamp extension quality` regress below the current score.

### Live: against a real Hyper-V host

Run from a scratch swamp repo, never from a repo that `swamp serve` is serving. Every VM the run creates is named
with the prefix `e2e-`. Any other VM on the host is read, never written. The run passes only if every step
passes:

0. Stdin probe → send a 1 MiB `stdinRequest` through `invocation` and the real runner. A script that returns the
   SHA-256 of `$Data` must return the same hash computed locally. This proves Windows PowerShell 5.1 reads the
   whole request under `-EncodedCommand` and that closing stdin ends `ReadToEnd`.
1. `discover` → record the VM list and states as the **before** snapshot.
2. `buildWindowsImage` → a golden image. Run it a second time with the same arguments and it must return the
   existing record in under 10 s, without rebuilding.
3. `createVm` `e2e-win01` with a `guest` block (generated password from the swamp vault, one test key), then
   `start`.
4. `waitReady` with `tcpPort: 22` → an address within 15 minutes.
5. `guestExec` `hostname` → equals the requested computer name. `guestExec` `Test-Path` on the unattend file and
   SetupComplete script → both gone.
6. SSH to the guest with the test key → `whoami` succeeds. A password login attempt fails.
7. `createVm` `e2e-win01` again → refuses (exists).
8. Remove the VM and only the disk this run created. `delete` is **never** called with `deleteDisks: true` here.
   1. Record the golden image's SHA-256, then read the child's path and parent from the `vm` resource that
      `createVm` wrote.
   2. `delete` `e2e-win01` with `deleteDisks: false` and `confirmName: e2e-win01` (stop it first, or also pass
      `confirmForcePowerOff: true`) → the VM is gone and the child VHDX is still on disk.
   3. `deleteDisk` with the golden image's path → **refused** (base disk, `allowBaseDisk` not set). Nothing changes.
   4. `deleteDisk` with the child's path and `confirmPath` → the child is gone.
   5. The golden image exists and its SHA-256 equals the one recorded in 8.1.
9. `discover` → the **after** snapshot equals **before** for every VM not named `e2e-*`.

Record the duration of each step and the evidence (resource ids, hashes, command output with secrets removed) in
the worker's report.

### Things the implementer must establish with evidence, not assume

- Whether this Windows Server 2025 media ships OpenSSH Server preinstalled (the capability check in
  `SetupComplete` must work either way, and the report says which branch ran).
- That the `encodeUnattendPassword` encoding is what setup accepts: the live run's `guestExec` login proves it.
- That `[Console]::In.ReadToEnd()` behaves under Windows PowerShell 5.1 started by sshd with `-EncodedCommand`
  (live step 0). If it doesn't (for example PowerShell consumes stdin itself), stop and report with evidence.
  Do not fall back to argv.
- (Settled in revision 2.) `delete` with `deleteDisks: true` treats the whole chain, parents included, as
  VM-owned. `delete` stays as reviewed: do not patch it. Removing a differencing VM is `delete` with
  `deleteDisks: false`, then `deleteDisk` on the child.

## Definition of done

The offline tests and checks are green. The live run passes steps 0–9 with evidence. README sections for
the five new methods are generated from `readme.vars.yaml` as for the existing ones, and the version is bumped
through `swamp extension version`. Nothing is pushed to any remote and nothing is published: publishing is a
separate, human-approved step after the reviewer's PASS.
