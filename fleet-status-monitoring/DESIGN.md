# Collector, policy and view

The package has two behavior types: `@jpisgeek/fleet-status-monitoring/system`
normalizes existing probe results, and `@jpisgeek/fleet-status-monitoring` owns
the scan marker, configurable health assessment and versioned report. Workflow
steps own external operations. The starter uses the typed `probe` method and
native read-only OS APIs; remote collection reuses official `@swamp/ssh`.
Extension code executes no subprocess.

The manifest explicitly lists the imported helper sources as additional files.
The repository's review hash therefore covers the renderer, host adapter,
schemas and probe sources as well as both behavior entrypoints and the workflow.

The native local probe uses OS memory, load, uptime and release APIs, plus a
bounded read of macOS SystemVersion metadata or Linux os-release. It reads
startup-data capacity with statfs. It collects no hostname, serial number,
process list, user-file contents or credential. On macOS it measures
`/System/Volumes/Data` when present, otherwise the actual root filesystem; on
Linux it measures `/`. It never enumerates mounted installers or disk images,
and never sums shared APFS capacity across volumes. An unavailable product
version remains null; a kernel release is not substituted for it. Windows NT
metadata is partial: product version, load and capacity stay unavailable. Load
is not CPU utilization. OS versions do not establish patch currency or support.

`probe_source.ts` exports an optional fixed Python 3 source for
restricted-command SSH deployments. It is not executed by the extension or the
local starter. Its macOS and Linux fixtures remain part of source tests.

Probe output is a strict version-1 sample. Counters may be null, but cannot be
negative or exceed their corresponding capacities. A source observation records
its original timestamp, data version and workflow provenance. SSH results must
have the target's declared host identity and belong to the current scan. The
latest attempt is chosen by start time, because version numbers belong to each
resource name and cannot be compared across the `script` and `exec` methods.
Attempt identity and start times are schema-validated before ranking. The
selected attempt's complete payload must then validate; a newer malformed
payload becomes a gap instead of reviving an earlier success. A typed
`localProbe` result retains its original start/finish times, sample and workflow
evidence. A missing or failed attempt cannot promote an earlier success to fresh
health.

`begin` writes a new cycle identity. `collect` normalizes each declared system.
`render` requires matching cycle identities and refuses mismatched workflow-run
metadata when available. Concurrent or missing source data produces a gap or a
failed render, never fabricated success. Previous snapshots retain their old
observation times and age visibly.

Health thresholds are global arguments. A known disk or memory warning still
appears when another metric is unavailable. Fresh OS coverage is counted
separately from complete health coverage. Unknown, stale, access-required,
unreachable and unsupported states are distinct. Inventory group and physical/VM
kind are operator declarations, not hardware facts inferred by this package.
Only one inventory row may use `collector: local`: it identifies the serve host,
and duplicating that sample under several identities would overstate coverage.

State and collector resources retain at most 192 versions or 30 days; HTML
retains at most 12 versions. At a 15-minute cadence those version caps are about
two days and three hours respectively, less with manual refreshes. Runtime
retention is not backup retention. Preserve needed evidence separately through
your approved backup process.

Global arguments, policy thresholds and owned resource contracts reject unknown
keys. The report projection explicitly removes only `sourceHost`, the private
transport locator; inventory enums and `sample.schemaVersion` are preserved.
Official SSH evidence may contain other official fields: the adapter explicitly
selects its six documented transport fields before validating a strict DTO.

Own cycle and local-probe attributes are read with `readResource`. That API
returns no version or workflow metadata, so a separate `readModelData` lookup
matches the complete validated attributes to exactly one metadata record. A
concurrent replacement fails the run instead of combining different versions.
Cross-behavior singleton results are ranked by validated start/check time,
independent of array order. Versions break timestamp ties only within the same
resource instance. A newer invalid payload remains invalid; an older successful
payload is never used as a substitute.

All four methods log their start and completion using structured fields. Probe
failures retain and log only `contract-validation` or `observation-failed`,
never raw exception text, paths or command output. Collection logs coverage gaps
at debug level. Missing prerequisites name the behavior and required workflow
steps.

Rendering and validation finish before either output is written. HTML is stored
first; canonical `state` is committed last. These writes are not a transaction:
if the final state write fails, a newer standalone HTML file can remain, while
the canonical state and dashboard keep their previous timestamps. A failed run
must not be reported as a successful refresh. Rerun the complete workflow;
historical snapshots are not rewritten. Hosts should render from canonical state
through `createFleetHandler`, rather than treating the latest standalone file as
proof of a successful scan.

Method tests use the pinned official Swamp test context with in-memory resource,
file and logging ports. Observer and renderer factories permit deterministic
failure injection; they are code-level test seams, not workflow arguments. No
method test runs the native host observer or a remote probe.
