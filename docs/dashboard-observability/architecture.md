# Dashboard Observability Architecture Evidence

## Status

- **Decision:** accepted for BUILD
- **Task:** PLAN Task 1
- **Verified:** 2026-08-25
- **Swamp version:** `20260821.000337.0-sha.14c38e70`

## Decision

Use method- or workflow-scope report extensions to normalize collector outputs
when the normalization is analysis-only. Swamp persists each report's JSON as a
named data artifact owned by the originating model. Downstream models receive
that artifact explicitly through the documented CEL data namespace:

```yaml
globalArguments:
  bundle: >-
    ${{ data.latest("producer",
    "report-jpisgeek-dashboard-proof-report-json").attributes }}
```

The renderer remains a model because it writes a rendered resource and HTML
file. It must receive bundles through its declared arguments. It must not scan
other models or use `ctx.dataRepository` for cross-model discovery.

A report may use the scoped `context.dataHandles` and
`context.dataRepository.getContent()` interface documented by Swamp's Report
Extension API to read the outputs of the execution it is analyzing. That is a
public report interface, not the renderer's former unbounded cross-model scan.

If a future adapter must independently refresh, retain, or reconcile normalized
state rather than analyze a just-completed execution, it becomes a typed model.
This is the exception, not the default.

## Shared contract packaging

Keep one canonical TypeScript/Zod contract source in this public repository.
Each independently published model or report inlines that source into its entry
point before quality scoring. A conformance test compares the inlined block
byte-for-byte with the canonical body.

Therefore:

- `dashboard-contract` is a source and conformance boundary, not a runtime Swamp
  extension dependency;
- each collector adapter and renderer remains independently installable;
- consumers do not need a mandatory contract extension installed at runtime;
- `dependencies:` stays empty unless a package truly requires another Swamp
  extension's runtime content;
- schema version compatibility remains in the data contract itself.

The canonical contract should have its own tests and fixtures. It does not need
an otherwise meaningless model or report merely to satisfy the registry rule
that a manifest contain at least one extension content type.

This choice follows Swamp's `design/extension.md` packaging boundary: published
entry points must be standalone.

### Packaging correction from Task 4

Task 1 proved that local imports were present in the disposable extension format
output. Task 4 exercised the stronger hermetic publication-quality path.
`swamp extension quality` extracted report entry points into `reports/` but did
not place a sibling `additionalFiles` contract on the module resolution path.
The scorer failed `deno doc` on the unresolved import. A dry-run archive could
still be built, so dry-run alone was insufficient evidence.

The supported package shape is therefore an explicitly inlined contract block
inside each published entry point, guarded by a byte-for-byte conformance test.
This is packaging duplication, not a second contract authority: edits begin in
`dashboard-contract/dashboard_bundle.ts`, then the generated/inlined block is
refreshed. Runtime extension dependencies remain empty.

## Live proof

The proof ran in the disposable repository
`<temporary-directory>/dashboard-observability-proof-20260825`. It contained:

- a producer model writing a strict synthetic resource;
- a method-scope report validating that resource with a shared Zod schema and
  returning the same bundle as JSON;
- a consumer model importing the same schema and accepting the report JSON as a
  declared global argument;
- separate producer and consumer manifests with no extension dependencies.

### Report persistence

The producer method succeeded and returned the local report:

```text
model: producer
method: observe
status: succeeded
report: @jpisgeek/dashboard-proof-report
report status: healthy
```

`swamp data list producer --json` showed the machine-readable artifact:

```text
name: report-jpisgeek-dashboard-proof-report-json
type: report
contentType: application/json
lifetime: 30d
garbageCollection: 5
```

`swamp data get producer report-jpisgeek-dashboard-proof-report-json --json`
returned:

```json
{
  "schemaVersion": "1.0.0",
  "status": "healthy",
  "observedAt": "2026-08-25T15:16:19.136Z"
}
```

### CEL handoff

The consumer definition used:

```text
data.latest("producer", "report-jpisgeek-dashboard-proof-report-json").attributes
```

`swamp model validate consumer --json` passed all five validations, including
`Expression paths`. `swamp model method run consumer render --json` then
succeeded and wrote:

```json
{
  "consumedStatus": "healthy"
}
```

This proves the report-to-data-to-model path without renderer-side repository
enumeration.

### Static contract bundling

The producer, report, and consumer each statically imported `./contract.ts`.
Both independent manifests passed:

```text
swamp extension fmt producer-manifest.yaml --check --json
swamp extension fmt consumer-manifest.yaml --check --json
```

The bundled producer, report, and consumer JavaScript each contained the
contract's `schemaVersion` validation. Deno also type-checked all three entry
points. The consumer package did not declare the producer package as a
dependency.

## Report data-name rule

For a scoped report name such as `@jpisgeek/dashboard-proof-report`, Swamp
persisted:

- Markdown: `report-jpisgeek-dashboard-proof-report`
- JSON: `report-jpisgeek-dashboard-proof-report-json`

Adapter tests must assert their exact persisted data name. Renderer examples
must use that exact name rather than deriving it differently.

## Query observation

`swamp data get` and `data.latest()` both resolved the report JSON correctly. A
separate CLI query using `tags.type == "report"` unexpectedly returned no rows
even though `data get` showed the `type=report` tag. This does not affect the
selected explicit handoff path. Treat tag-wide report discovery as unverified
and do not use it for renderer inputs unless a later task proves its behavior.

## Repository enrollment decision

The worktree is an initialized Swamp repository, but `.swamp.yaml` currently
contains `tools: []` and the current commit does not track `AGENTS.md`. The
original checkout has uncommitted Codex-enrollment artifacts and must remain
untouched.

Do not copy those uncommitted files or run a forced reinitialization implicitly.
The already-read mandatory Swamp rules govern this lifecycle. Enrolling this
worktree for Codex with a supported Swamp repo init/upgrade command remains a
separate explicit approval because it changes repository-managed configuration.
It is not required for Swamp CLI execution in this coding agent.

## Consequences for later tasks

1. Task 3 creates the canonical contract source, conformance tests, and fixtures
   but not a fake standalone registry extension.
2. Every manifest includes only its actual model/report/workflow entry points;
   its entry points contain a conformance-checked inline copy of the contract.
3. Normalization reports produce explicit JSON bundles. Their persisted data
   names are documented in package examples.
4. The renderer accepts declared bundle arguments and never enumerates models.
5. Composition workflows order collector execution before rendering and use
   `data.latest()` to pass the exact report JSON artifact.
6. Tag-based discovery is not part of bundle composition.
