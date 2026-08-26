# LM Studio Headless-Daemon Observability

## Decision

Task 12 follows the operator's actual runtime: LM Studio runs headlessly on a
headless Mac Studio. The Ollama-specific adapter is deferred. Ollama remains a
valid future producer under the provider-neutral dashboard contract.

The local `@jpisgeek/lmstudio` package now owns a third, independently usable
model type: `@jpisgeek/lmstudio/daemon`. This keeps the adapter local-first and
does not add a dependency to the renderer or any unrelated collector.

## Supported surface

The collector uses an argv-only `Deno.Command` invocation of:

```text
lms ps --json
```

LM Studio's official CLI documentation defines `lms ps` as the loaded-model
inventory, documents JSON output, and supports `--host` for a remote instance:
<https://lmstudio.ai/docs/cli/local-models/ps>. LM Studio documents llmster as
its GUI-independent headless daemon:
<https://lmstudio.ai/docs/developer/core/headless>.

The model normally runs on the host beside llmster. An optional `host` argument
adds LM Studio's documented `--host` remote mode. The public extension contains
no private hostname or network default. BUILD did not contact the private Mac
Studio because that runtime was down and being updated.

## Accuracy and security

- A successful empty array is an exact zero loaded models and is degraded, not
  healthy.
- CLI missing, remote unreachable, timeout, command failure, and invalid JSON
  are distinct states. Their zero-valued storage fields are unavailable
  placeholders, not measurements.
- Caller cancellation throws and does not write a misleading timeout record.
- The observation is a point-in-time loaded-model inventory. It is not runtime
  request or token accounting.
- Stored model details are limited to identifier, type, and architecture.
  Local/remote model paths and raw stdout/stderr error text are discarded.
- The command uses a fixed argv shape and no shell.

## Compatibility evidence

The live registry search on 2026-08-25 returned only the existing
`@jpisgeek/lmstudio` package at `2026.08.23.1`; it exposed no separate shared LM
Studio daemon adapter matching this profile. The package is therefore extended
locally rather than adding a community dependency.

Mocked tests cover loaded models, an exact empty inventory, unreachable remote,
malformed output, missing CLI, timeout, and caller cancellation. The dashboard
adapter separately verifies healthy, degraded, critical, unsupported, and
unknown-metric behavior.

Final Task 12 checks passed formatting, type checking, lint, 35 tests, both
Swamp manifest format checks, 12/12 local quality scores, the generic identifier
scan with zero hits, and dry-run packaging for `@jpisgeek/lmstudio@2026.08.25.1`
and `@jpisgeek/dashboard-lmstudio@2026.08.25.2`. Dry run made no API calls. It
correctly reported that the new exact content hashes do not yet have adversarial
reviews; those reviews remain gated to Task 15. It also reported the existing
combined endpoint/probe test-file layout as a discoverability warning even
though those tests ran and passed; Task 15 must either add sibling entry files
or record an accepted review resolution before publication.

Task 12 uses Swamp's model/report split described by `design/models.md` and
`design/reports.md`: the model observes the external runtime and writes typed
data; the report validates and normalizes the scoped execution into bundle v1.
