# Dashboard and Observability Family — VERIFY

## Verdict

**Task 14 passes.** The implemented family satisfies the approved DEFINE at the
VERIFY boundary. No correctness gap requires a return to BUILD.

Release review and publication readiness are not implied by this verdict.
Exact-content adversarial reviews, the private denylist scan, final content
hashes, and final dry runs remain gated to Tasks 15 and 16.

## Verified revision

- Branch: `dashboard-observability`
- BUILD checkpoint entering VERIFY: `8fbdb2a`
- Verification date: 2026-08-25
- Live production/private systems contacted: none
- Publication, push, deployment, and production changes: none

## Whole-family checks

| Check                        | Result | Evidence                                                                                                                                |
| ---------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| Repository tests             | PASS   | `deno test --allow-all`: 189 passed, 0 failed                                                                                           |
| Changed-package formatting   | PASS   | `deno fmt --check` over 10 changed package/example directories: 73 files checked                                                        |
| Changed-package lint         | PASS   | `deno lint` over the TypeScript surface: 30 files checked                                                                               |
| Generated READMEs            | PASS   | Regenerated all nine package READMEs and the root table; `git diff --exit-code` remained clean                                          |
| Swamp manifest formatting    | PASS   | All nine prospective packages passed `swamp extension fmt --check`                                                                      |
| Swamp quality                | PASS   | All nine prospective packages passed `swamp extension quality`                                                                          |
| Independent loading          | PASS   | Each of the nine packages was the sole local source in a fresh isolated Swamp repository; `swamp doctor extensions --json` passed       |
| Public identifier pre-filter | PASS   | Exact changed, non-test Git surface: 81 files, 0 generic hits                                                                           |
| Renderer isolation           | PASS   | Its only import is `npm:zod@4`; no fetch, `Deno.Command`, `dataRepository`, collector import, or provider name exists in `dashboard.ts` |

The nine independently checked packages are `dashboard`, `dashboard-homelab`,
`dashboard-lmstudio`, `dashboard-swamp`, `openai-usage`, `anthropic-usage`,
`subscription-metadata`, `lmstudio`, and `dashboard-compose`. Their manifests
declare no unrelated extension dependency fan-out.

## Swamp execution evidence

The public-safe vertical slice was revalidated immediately before execution. All
three model definitions passed all five model validations, and the workflow
passed all eleven schema, dependency, cycle, method-input, and CEL-reference
validations with zero warnings.

- Healthy run `717dc3ac-833f-45b7-9dfd-607fa6ec36ff` succeeded. The renderer
  received one valid bundle, recorded `healthy`, and wrote zero exceptions.
- Partial run `5e11028f-e396-4c27-80c5-f3a211ec8238` succeeded. The renderer
  retained one valid bundle, recorded `partial`, and wrote one visible warning.
- The validated missing-source renderer run succeeded with zero received bundles
  and wrote `coverage:no-bundles`; it did not render an all-clear.
- Task 13's mixed workflow also ran with every optional domain disabled, then
  with only a synthetic homelab bundle enabled. Both succeeded without looking
  up an omitted domain.

Runtime `.swamp/` databases correctly contained absolute local paths after these
runs. They are ignored and absent from the Git/publication surface. A
directory-wide identifier scan caught them; the exact tracked change-set scan
was clean. This confirms why runtime state must never enter an extension
archive.

## DEFINE acceptance mapping

| DEFINE requirement                                                                                                                        | Result            | Verification                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Durable goals, users, scope, boundaries, schemas, Swamp, hosted usage, subscriptions, local inference, security, migration, and non-goals | PASS              | Approved `DEFINE.md` remains the controlling specification                                                                                                                                        |
| Versioned provider-neutral bundle                                                                                                         | PASS              | Contract v1 tests cover all eight states, provenance, coverage, freshness, completeness, units, sensitivity, additive v1 fields, and unsupported majors                                           |
| Piece-by-piece installation                                                                                                               | PASS              | Nine-package isolated-source matrix passed; composition is optional and contains no collectors                                                                                                    |
| Explicit CEL bundle handoff                                                                                                               | PASS              | Vertical-slice and composition workflows use exact `data.latest(...).attributes` report names                                                                                                     |
| Presentation-only renderer                                                                                                                | PASS              | Source scan plus tests prove no provider imports, source aliases, network, process, or repository discovery                                                                                       |
| Missing is not zero; unknown is not healthy                                                                                               | PASS              | Contract, adapters, renderer, and live missing/partial runs preserve unavailable values and coverage states                                                                                       |
| Four legacy correctness findings resolved                                                                                                 | PASS              | Named tests cover partial reads, missing `usedPercent`, certificate identity, and invalid scalar networks                                                                                         |
| Accepted visual direction retained                                                                                                        | PASS              | Structural visual regression preserves self-contained HTML, exceptions-first/all-clear behavior, Nodes/Storage/Certificates/Machines sections, and dark mode; generated pages remain network-free |
| Swamp monitoring                                                                                                                          | PASS              | Tests cover success, failure, stale, orphaned, empty history, unavailable interfaces, authorization, and cancellation through documented command interfaces                                       |
| Hosted usage and costs                                                                                                                    | PASS              | OpenAI and Anthropic tests cover exact windows, pagination, partial pages, authorization, unsupported capabilities, currency, malformed responses, and cancellation                               |
| Subscription metadata distinct from metering                                                                                              | PASS              | Unknown fields remain absent, explicit zero survives, and flat plan price never becomes usage cost or remaining quota                                                                             |
| Local inference first-class                                                                                                               | PASS              | LM Studio endpoint/probe/daemon tests preserve authorization, loaded state, request scope, token/performance evidence, timeout, cancellation, and no false aggregate accounting                   |
| Community extensions evaluated before custom work                                                                                         | PASS              | `compatibility.md` records current schemas/gaps and explicit fit/reject decisions; local-first remains authoritative                                                                              |
| Public/private separation                                                                                                                 | PASS              | Synthetic fixtures, exact changed-surface scan, ignored runtime state, and no private system access                                                                                               |
| Publication gates                                                                                                                         | PENDING BY DESIGN | Task 15 exact-hash REVIEW and Task 16 final dry run/SHIP gate have not started                                                                                                                    |

## State and adversarial coverage

The renderer model-level integration suite executes its real `render` method and
checks written HTML/resources for `unknown`, `stale`, `partial`, `unauthorized`,
`unsupported`, invalid bundles, missing bundles, and unsupported major versions.
Critical and degraded paths are covered by contract conformance and domain
adapter suites. Untrusted strings are exercised across exception, metric, and
fact fields and remain HTML-escaped.

The live workflow adds cross-extension evidence for healthy, partial, and
missing states. Provider authorization and remote-runtime failure cases remain
mocked deliberately; VERIFY did not contact hosted administrative APIs or the
Mac Studio.

## Migration comparison

The legacy visual relationships are retained, while these behaviors changed
intentionally:

- literal renderer aliases became explicit bundle inputs;
- a successful prefix followed by a read failure now becomes `partial`;
- a missing percentage stays unavailable instead of becoming `0%`;
- certificate alerts fold only with stable matching identity;
- invalid network collections reject the source record without crashing;
- absent sources, invalid bundles, and unsupported versions render coverage
  exceptions instead of an all-clear;
- request-level LM Studio usage is labeled observed traffic, never aggregate
  runtime accounting.

## Non-blocking repository observations

- A repository-root `deno fmt --check` reports 21 pre-existing Markdown files
  outside this project surface, including paused mise planning and historical
  review documents. They were not modified. Every changed package and example
  directory passes formatting.
- The generic scanner intentionally flags hostile strings when individual
  `_test.ts` files are supplied directly. Tests are excluded from extension
  publication payloads; the exact non-test Git change set is clean. Task 15
  still requires the private denylist over each exact publication payload.
- The LM Studio dry run previously noted the older combined endpoint/probe
  test-file discoverability layout. Tests execute and pass, but Task 15 must
  resolve or explicitly disposition that review warning before publication.

## Gate

VERIFY is complete. Stop here before Task 15. REVIEW requires a separate user
direction and will bind verdicts to the final package content hashes.
