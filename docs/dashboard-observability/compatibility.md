# Extension Compatibility Profile and Migration Baseline

## Status

- **Task:** PLAN Task 2
- **Verified:** 2026-08-25
- **Swamp version:** `20260821.000337.0-sha.14c38e70`
- **Decision posture:** local implementation by default; no candidate installed

## Compatibility profile

A community extension is eligible only when evidence establishes every required
dimension below. Registry metadata is discovery evidence, not implementation
evidence.

| Dimension        | Required evidence                                                                                   | Reject or defer when                                                 |
| ---------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Domain           | Methods cover the exact observation, not merely the same provider                                   | It performs generation or administration but not observability       |
| Resource schema  | Full field names, types, units, optionality, and version are captured                               | Registry lists only a resource name or prose description             |
| Semantics        | Zero, absent, unknown, unsupported, unauthorized, stale, and partial remain distinct                | Missing values are defaulted or failed sources are silently omitted  |
| Coverage         | Each counter declares time window, scope, completeness, and aggregation kind                        | Per-request samples can look like aggregate accounting               |
| Provenance       | Provider, source model/data name, observation time, and billing authority are available             | Cost or quota is inferred without authority                          |
| Failure behavior | Pagination, truncation, partial pages, rate limits, malformed data, and auth failures are testable  | Failures collapse into an empty or healthy result                    |
| CEL handoff      | Output can be selected explicitly with `data.latest()` and validated by the local contract          | Integration requires hidden datastore enumeration or alias discovery |
| Security         | Least privilege, vault handling, TLS, timeout, cancellation, and redaction are verified             | Credentials enter persisted output or network behavior is unclear    |
| Dependencies     | Installing the candidate does not drag unrelated providers into the selected slice                  | A narrow dashboard slice requires a broad collector suite            |
| Supply chain     | Repository identity, pinned imports, license, maintenance state, and published version are verified | License or dependency trust is unknown at adoption time              |
| Lifecycle        | Formatting, tests, quality, documentation, identifier scan, and exact-hash review can be reproduced | Only registry description text is available                          |
| Extensibility    | A missing method can be added without changing semantics or forcing unrelated dependencies          | Extension would be more coupled than a local typed collector         |

### Decision labels

- **fit:** all required dimensions pass with captured runtime and source
  evidence; direct use or a thin local normalization report is allowed.
- **extend:** the source contract is sound and narrow, but a specific supported
  method or field is missing; extend without bypassing its model type.
- **reject:** a known contract property conflicts with DEFINE.
- **pending runtime evidence:** metadata is relevant but insufficient. Do not
  install or depend on it yet.

## Registry and local-type evidence

The following commands were run from the project worktree on 2026-08-25:

```text
swamp extension info @webframp/ai-usage --json
swamp extension info @dougschaefer/openai-usage --json
swamp extension info @keeb/ollama --json
swamp model type search openai --json
swamp model type search anthropic --json
swamp model type search ollama --json
```

All three local type searches returned no matches. No extension was pulled,
trusted, or installed.

### `@webframp/ai-usage`

- **Observed registry version:** `2026.08.24.1`
- **Verified repository:** `https://github.com/webframp/swamp-extensions`
- **Registry surface:** one model, one workflow, and one workflow-scope report.
- **Model methods:** `status`, `generate(days)`.
- **Model resources:** `status` with `1h` lifetime; `report` with `6h` lifetime.
- **Workflow providers:** Bedrock, Vertex AI, Azure OpenAI, and Claude
  Enterprise.
- **Positive evidence:** the description and workflow explicitly represent
  unconfigured-provider coverage gaps.
- **Known mismatch:** the workflow is a broad multi-provider composition and
  does not include OpenAI organization usage. Direct adoption would introduce
  unrelated provider dependencies into narrower installations.
- **Unknown from registry metadata:** resource field schemas, exact partial-page
  semantics, invalid-record handling, security implementation, dependency
  versions, and license.
- **Decision:** **reject as the initial core/default dependency; pending runtime
  evidence as a future optional multi-cloud adapter source.** Local hosted-AI
  collectors and bundle contracts remain authoritative.

#### Task 10 re-check

Registry version `2026.08.24.1` still composes unrelated cloud providers and
does not cover Claude Platform organization Usage and Cost Admin APIs. Its
Anthropic dependency, `@webframp/anthropic/analytics`, covers only Claude
Enterprise Analytics and advertises a cost resource that is "zeroed otherwise"
when cost reports are unavailable. That conflicts with the approved rule that
missing is not zero. Registry metadata also does not expose its resource
schemas, pagination completeness, or dashboard bundle contract.

**Decision:** reject both as Task 10 dependencies. The local implementation
supports the separately documented Platform and Enterprise API families,
credential types, unavailable capabilities, minor-unit cost strings, refresh
timestamps, and grouped-result coverage limits without unrelated packages.

### `@dougschaefer/openai-usage`

- **Observed registry version:** `2026.06.29.1`
- **Verified repository:** `https://github.com/dougschaefer6/swamp-openai-usage`
- **Registry surface:** one model with `usage` and `costs` methods.
- **Authorization:** requires an OpenAI Admin API key with `api.usage.read`;
  standard project keys are explicitly insufficient.
- **Arguments:** optional `startDate` or `days`; month-to-date is the described
  default.
- **Resources:** `usage` and `costs`, both infinite lifetime.
- **Positive evidence:** domain and authorization description match part of the
  local profile.
- **Unknown from registry metadata:** resource field schemas and units,
  pagination/truncation behavior, missing-dimension behavior, currency schema,
  timeouts/cancellation, redaction tests, dependency versions, and license.
- **Task 9 re-check:** registry version `2026.06.29.1` still advertises only
  opaque `usage` and `costs` resources with infinite retention. It exposes no
  report and still provides no schema evidence for currency, partial pages,
  missing dimensions, timeouts, cancellation, or sanitized failures. Local type
  search returned no installed OpenAI type.
- **Decision:** **reject as the Task 9 implementation dependency.** The local
  package supplies the approved typed states, bounded retention, independent
  pagination, and bundle normalization. Re-evaluate the community package only
  if a future published contract closes every recorded gap.

### `@keeb/ollama`

- **Observed registry package version:** `2026.07.18.1`
- **Advertised model version:** `2026.03.28.1`
- **Verified repository:** `https://github.com/keeb/swamp-ollama`
- **Registry surface:** model plus skill.
- **Methods:** `generate`, `generate_batch`, and `unload`.
- **Resource:** generic `result` with infinite lifetime.
- **Known mismatch:** no advertised health, runtime inventory, loaded-model
  state, queue, accelerator, aggregate coverage, or dedicated token/performance
  observation resource.
- **Unknown from registry metadata:** exact result fields, metric units,
  timeout/cancellation behavior, authorization state, dependency versions, and
  license.
- **Decision:** **reject for the dashboard observability profile.** It remains
  prior art for generation operations. Task 12 defaults to a local observability
  collector and may reconsider `extend` only if source/runtime evidence shows a
  narrow extension would remain independently installable.

## Legacy dashboard baseline

The baseline is intentionally public-safe and contains only synthetic reserved
example identifiers. It consists of:

- `dashboard/fixtures/legacy-dashboard-baseline.json`;
- the existing renderer tests;
- five new migration characterization tests in `dashboard/dashboard_test.ts`.

The fixture exercises all four literal source aliases with a healthy Netdata
node and mount, TrueNAS pool and certificate, Firewalla machine, and SSH run.
The accepted structural baseline is:

- self-contained HTML;
- exceptions-first banner;
- `Nodes`, `Storage`, `Certificates`, and `Machines` detail sections;
- visible source-coverage warning when a source has no usable rows;
- queryable `exception` and `render` resources;
- `Nothing needs you` only in the fully populated healthy fixture;
- zero exceptions, four sources read, and no stale sources for that fixture.

This baseline preserves visual direction, not provider coupling. Task 5 may
change markup where necessary but must retain these user-facing relationships.

## Named migration regressions

The tests below deliberately assert current broken behavior. They are
characterization tests, not endorsements. Tasks 4 and 5 must replace them with
bundle-v1 honesty assertions.

### `partial-read-undisclosed`

A source returns one healthy row, then throws while reading a critical alarm.
The legacy renderer keeps the first row, does not list the source as stale, and
can render `Nothing needs you`.

Required replacement: the normalized bundle is `partial`, identifies rejected or
unreadable records, and the renderer cannot show an unqualified all-clear.

### `missing-used-percent-becomes-zero`

A mount row omits `usedPercent`. The legacy renderer displays `0%` and emits no
disk or unknown-data exception.

Required replacement: the value remains absent, coverage degrades visibly, and
no threshold decision is made from a fabricated zero.

### `certificate-alert-first-match`

Certificate `alpha` is expiring while a separate TrueNAS alert concerns
certificate `beta`. The legacy renderer sees the first `cert:` exception and
silently drops the `beta` alert.

Required replacement: fold only when a stable certificate identity matches;
otherwise preserve the alert independently.

### `networks-scalar-aborts-render`

A Firewalla machine contains a scalar `networks` value. The legacy renderer
blindly calls `.join()` and throws `TypeError` after beginning the render.

Required replacement: the adapter validates the row, reports its rejection, and
produces a partial bundle without crashing the renderer.

## Verification evidence

```text
deno fmt --check dashboard/dashboard_test.ts \
  dashboard/fixtures/legacy-dashboard-baseline.json

Checked 2 files

deno test --allow-read --allow-write --allow-env --allow-net --allow-run \
  dashboard/

14 passed | 0 failed
```

The dashboard manifest, renderer source, generated README, and existing review
content were not changed in Task 2. The new fixture and test file are not listed
in the extension manifest and do not alter its publication payload.
