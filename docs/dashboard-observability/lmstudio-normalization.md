# LM Studio normalization evidence

## Status

- **Lifecycle:** BUILD Task 8 complete
- **Verified:** 2026-08-25
- **Package:** `@jpisgeek/dashboard-lmstudio` `2026.08.25.1`
- **Source package:** `@jpisgeek/lmstudio` `2026.08.23.1`

## Boundary

`@jpisgeek/dashboard-lmstudio` is an independently installable method-report
extension. It contains no collector and does not change the existing LM Studio
package. Users may install the endpoint and request probes without the adapter,
or attach this report only where dashboard bundle v1 output is wanted.

This follows the Swamp `design/reports.md` boundary: the existing models observe
the external endpoint and the report analyzes the scoped execution resources.
The renderer receives only the stored report JSON through explicit CEL.

## Normalized distinctions

The adapter preserves:

- endpoint unreachable versus reachable but unauthorized;
- loaded model inventory and an empty model list;
- embedding capability and measured versus unknown vector dimension;
- completion finish reason;
- prompt, completion, total, and reasoning tokens in token units;
- request latency and capability-battery latency in milliseconds;
- inferred context exhaustion versus an exact requested output-token cap;
- reasoning-only empty output;
- complete, partial, failed, and truncated capability checks;
- malformed source records as visible rejected coverage.

Completion coverage is `observed-traffic` for one explicit probe request. The
bundle extension records `accountingScope: single-request` and
`aggregateAccounting: false`. Failed requests expose token metrics as unknown
without a numeric value. They do not turn collector sentinel zeros into measured
zero usage.

## Live proof

A disposable Swamp repository loaded the existing LM Studio package and the new
adapter as separate local sources. A `local_encryption` vault held a synthetic
test token, and the generated endpoint model referenced it through `vault.get`;
Swamp correctly rejected an earlier attempt to place even the synthetic token
directly in the model definition.

`swamp doctor extensions --json` reported three healthy sources with no loader
errors, warnings, catalog or bundle orphans.
`swamp model validate
synthetic-inference --json` passed all five validations.
The health method then ran against the reserved `.invalid` endpoint and
succeeded with final run ID `89582300-395c-4608-9b07-e2e06410429c`, recording
the endpoint as unreachable.

The attached report succeeded and persisted
`report-jpisgeek-dashboard-lmstudio-json`. Both `swamp report get` and
`swamp data get` returned a valid bundle with state `critical`, a fresh endpoint
observation, millisecond latency, explicit `reachable: false`, and an
`Endpoint unreachable` exception. The built-in method summary rendered the
vault-backed token as `***`. No disposable runtime state is checked in.

## Synthetic coverage

The existing 14 LM Studio tests and 12 adapter tests cover healthy, down,
unauthorized, empty inventory, embedding dimension known and unknown,
single-request tokens, context exhaustion, output cap, reasoning-only empty
output, failed token metrics, partial and truncated capabilities, malformed
source data, and exact inlined-contract conformance.
