# Dashboard vertical-slice evidence

## Status

- **Task:** PLAN Task 6
- **Verified:** 2026-08-25
- **Swamp version:** `20260821.000337.0-sha.14c38e70`
- **Fixture:** `examples/dashboard-vertical-slice`
- **Publication:** none

## Composition proved

The public-safe fixture selects only three local sources:

1. a deterministic Netdata-shaped collector model;
2. the real `@jpisgeek/dashboard-homelab` method report;
3. the real `@jpisgeek/dashboard` renderer model.

The collector definition requires the normalization report. Swamp persists its
JSON as `report-jpisgeek-dashboard-homelab-json`. The dashboard definition
passes that exact artifact as its declared `bundles` argument:

```text
[data.latest("synthetic-netdata",
  "report-jpisgeek-dashboard-homelab-json").attributes]
```

The workflow contains only model-method steps. `observe` must succeed before
`render`. Swamp generated and retains every model and workflow ID.

## Validation

Both model definitions passed all five model validations. The workflow passed
all eleven validations, including schema, dependency, cycle, method-input, and
global-argument input-reference checks. It was revalidated immediately before
each workflow run.

`swamp doctor extensions --json` reported all three selected local sources
healthy with no loader errors, warnings, catalog or bundle orphans.

## Healthy run

Workflow run `6b549c91-1829-4140-9caa-28347a2675f9` succeeded. Both steps
completed, and workflow history associated the normalized Markdown and JSON
reports with the `observe` step.

`swamp report get @jpisgeek/dashboard-homelab --model synthetic-netdata
--json`
returned:

```json
{
  "state": "healthy",
  "summary": "1/1 nodes reachable",
  "completeness": "exact"
}
```

`swamp data get synthetic-dashboard render --json` returned one valid bundle,
state `healthy`, zero exceptions, and zero warnings. The generated HTML showed
the accepted all-clear presentation.

## Partial run

Workflow run `ecb636d7-2651-43d6-8fa1-2642e4200bb7` succeeded with
`mode=partial`. The report JSON retained the valid node observation while
declaring bundle and section state `partial`, rejected count `1`, and the reason
`records rejected, missing, or carried forward`.

After removing duplicate bundle/section notices found during this live run, the
final render resource reported:

```json
{
  "exceptions": 1,
  "warning": 1,
  "bundlesReceived": 1,
  "bundlesValid": 1,
  "coverageStates": { "netdata-observability": "partial" }
}
```

The generated HTML contained `Coverage is partial` and did not contain
`Nothing needs you`.

## Missing-source run

Swamp generated a separate `synthetic-dashboard-missing` definition with the
default empty bundle list. Its validated direct `render` run succeeded and
wrote:

```json
{
  "exceptions": 1,
  "warning": 1,
  "bundlesReceived": 0,
  "bundlesValid": 0,
  "exceptionResources": ["exception-coverage-no-bundles-a6632e6c"]
}
```

The exception headline is `No dashboard bundles were provided`. Removing the
selected source therefore becomes an explicit coverage gap, not a healthy or
zero state.

## Integration defect found and corrected

The first live run persisted a report error. Swamp's stored report and stack
trace showed that live `context.modelType` is a coercible ModelType value, not a
primitive string. Object-key coercion selected the correct schemas, but strict
equality fell through to the Firewalla normalizer.

The adapter now normalizes `String(context.modelType)` once before schema and
normalizer selection. A regression test supplies a live-like coercible value.
The rerun produced valid Netdata bundle JSON.

## Boundaries

- No credential, inventory, private hostname, or routable fixture endpoint is
  present.
- Runtime `.swamp/` data and generated HTML are ignored.
- No extension was pulled, published, pushed, or deployed.
- The source list is local developer configuration and remains ignored; the
  README provides the supported setup commands.
