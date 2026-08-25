# Swamp observability evidence

## Status

- **Lifecycle:** BUILD Task 7 complete
- **Verified:** 2026-08-25
- **Swamp version:** `20260821.000337.0-sha.14c38e70`
- **Package:** `@jpisgeek/dashboard-swamp` `2026.08.25.1`

## Public interface decision

The package uses only documented Swamp commands:

- `swamp run history --all --json`;
- `swamp run doctor --json`;
- `swamp workflow history search --json`;
- `swamp report search --json`.

The collector is a typed model. It invokes the configured Swamp executable with
a fixed argument array and no shell. A separate method report validates the
scoped resources and emits dashboard bundle v1. This follows the Swamp
architecture boundary in `design/models.md` and `design/reports.md`: the model
observes; the report analyzes and normalizes.

The optional `/internal/runs` API is not used. The current public CLI exposes
serve heartbeat configuration but no heartbeat query. The collector therefore
writes `serve-heartbeat` as an unsupported interface and the bundle remains
partial. General server reachability is not promoted into fictional heartbeat
freshness.

`run doctor` in this build returns stale-run data but does not return an
`orphaned` count when no such field is available. The report preserves that
dimension as unsupported rather than zero. Similarly, `report search` proves
stored artifact availability but does not expose result execution status; that
status remains unsupported.

## Community evaluation

Registry search found `@magistr/swamp-watch` `2026.08.21.1`. Its inspected
contract is schedule-specific: it compares declared workflow schedules with run
history and emits Prometheus exposition. It does not cover general model runs,
stored reports, serve heartbeat coverage, or dashboard bundle v1. It also
requires a Swamp binary path and is not an exact compatibility match. It was not
installed or made a dependency.

## Live proof

A disposable Swamp repository loaded the local package as its only extension
source. `swamp doctor extensions --json` loaded both the model and report, and
`swamp model validate swamp-ops --json` passed all five validations. The
validated `observe` method succeeded with final run ID
`ebe3544b-7832-47cd-b3e0-dcead9c8dd33` and wrote five typed resources.

During that run:

- run history reported the active observation run;
- run doctor reported active, non-stale runs but no orphan-count field, so that
  dimension stayed explicitly unsupported;
- workflow history was available and empty;
- two stored reports were observed, while their result-status dimension stayed
  explicitly unsupported;
- serve heartbeat was explicitly unsupported.

The attached `@jpisgeek/dashboard-swamp` report succeeded and persisted
`report-jpisgeek-dashboard-swamp-json`. `swamp report get` and `swamp data get`
both returned bundle v1 with overall state `partial`, healthy run-history
evidence, unknown empty workflow history, partial doctor and stored-report
coverage, and a visible heartbeat coverage exception. No private runtime output
is checked in.

## Synthetic coverage

Tests exercise:

- successful, active, and completed runs;
- failed histories;
- stale and orphaned states;
- empty histories;
- unreachable and unauthorized interfaces;
- missing orphan and report-status dimensions;
- caller cancellation;
- token exclusion from argv and persisted errors;
- exact inlined-contract conformance.
