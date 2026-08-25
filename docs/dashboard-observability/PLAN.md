# Dashboard and Observability Extension Family — PLAN

## Lifecycle Status

- **Phase:** BUILD — Tasks 1-13 complete; Task 14 pending
- **Spec:** [DEFINE.md](DEFINE.md), approved 2026-08-25
- **Build:** in progress
- **Completed tasks:** 13 of 16
- **Blockers:** none
- **Last updated:** 2026-08-25

## Delivery strategy

Build the family in independently working vertical slices. Establish the
provider-neutral contract and one local collector-to-dashboard path first, then
add domains without widening renderer knowledge.

Local `@jpisgeek` packages are the default. Community packages are inspected as
compatibility candidates only after the local contract and acceptance fixture
exist. No candidate is installed or depended on merely because it appears in a
registry search.

The primitive choices follow Swamp's `design/models.md`, `design/reports.md`,
`design/workflow.md`, `design/extension.md`, and `design/expressions.md` as
routed by the Swamp architecture guide:

- models observe one external system and write typed data;
- reports perform repeatable normalization and analysis;
- workflows compose model methods;
- CEL carries explicit data references;
- the renderer presents normalized bundles.

## Working rules

- Work only in the `dashboard-observability` Paseo worktree.
- Do not modify, clean, or inspect generated state in the original
  `mise-extension` checkout.
- Do not use raw CLI wrappers, `command/shell`, private datastore reads, or an
  internal API when a supported Swamp primitive exists.
- Run `swamp extension search`, `swamp extension info`, and
  `swamp model type search` before creating each external-service collector.
- Capture candidate contracts as public-safe evidence; do not pull a candidate
  until it passes the approved local compatibility profile.
- Use `data.latest("<name>", "<dataName>").attributes.<field>` CEL patterns.
- Treat prose, generated README content, manifests, and examples as published
  content from the first commit of each package.
- Use synthetic fixtures only. Run the identifier scan before any review.
- Finish and test one task before beginning the next. Commit each meaningful,
  independently working slice.
- If implementation evidence contradicts DEFINE, stop and request a spec
  amendment rather than silently changing scope.

## Planned package boundaries

Names are provisional until Task 1 proves the supported packaging shape.

| Provisional directory/package                               | Kind                   | Responsibility                                                                             |
| ----------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------ |
| `dashboard-contract`                                        | source contract module | Bundle v1 schemas, helpers, and conformance fixtures; statically bundled into each package |
| `dashboard` / `@jpisgeek/dashboard`                         | model                  | Provider-neutral HTML renderer                                                             |
| `dashboard-homelab` / `@jpisgeek/dashboard-homelab`         | report or model        | Normalize Netdata, TrueNAS, and Firewalla data                                             |
| `dashboard-lmstudio` / `@jpisgeek/dashboard-lmstudio`       | report or model        | Normalize LM Studio endpoint and probe data                                                |
| `swamp-observability` / `@jpisgeek/swamp-observability`     | model plus report      | Observe and normalize Swamp operational state                                              |
| `openai-usage` / `@jpisgeek/openai-usage`                   | model plus report      | Local OpenAI organization usage and cost                                                   |
| `anthropic-usage` / `@jpisgeek/anthropic-usage`             | model plus report      | Local Anthropic organization/enterprise usage                                              |
| `subscription-metadata` / `@jpisgeek/subscription-metadata` | model plus report      | Explicit plan metadata without invented quota                                              |
| `lmstudio` / `@jpisgeek/lmstudio/daemon`                   | model                  | LM Studio headless-daemon state and loaded-model inventory                                 |
| `dashboard-compose` / `@jpisgeek/dashboard-compose`         | workflow               | Optional composition of only user-selected pieces                                          |

No package above may make every other package an installation dependency. The
contract dependency is the only common dependency permitted by default.

## P0 — prove the foundation

### Task 1: Prove the Swamp-native bundle handoff and packaging shape

**Status:** complete — evidence and decisions are recorded in
[architecture.md](architecture.md).

**Goal:** establish the smallest supported architecture before implementation.

- Inspect current Swamp report, extension, model, data, and CEL capabilities
  through `swamp help` and the applicable current guides.
- Prove whether a report's JSON artifact can be explicitly selected by CEL and
  consumed by the renderer without private repository access.
- Prove how a shared Zod contract can be independently packaged and imported by
  separately installable extensions under the current bundler.
- Record the decision and evidence in
  `docs/dashboard-observability/architecture.md`.
- If reports cannot provide a CEL-addressable bundle, choose a typed
  normalization model and document why. Do not use `ctx.dataRepository` as a
  fallback.
- Resolve whether this worktree should receive a tracked Swamp-managed
  `AGENTS.md` without changing the original checkout or upgrading the repo
  without explicit approval.

**Verify:** a minimal synthetic producer-to-consumer experiment validates with
Swamp, and the architecture document identifies only public supported APIs.

### Task 2: Define the compatibility profile and capture baselines

**Status:** complete — profile, decisions, and baseline evidence are recorded in
[compatibility.md](compatibility.md).

**Goal:** make local-first reuse decisions repeatable and preserve migration
evidence.

- Write a candidate evaluation checklist covering resource schema, semantic
  accuracy, missing/partial behavior, coverage windows, authorization states,
  security, dependency fan-out, license, versioning, and CEL compatibility.
- Capture the current dashboard's visual and resource behavior with synthetic
  fixtures.
- Turn the four unresolved dashboard findings into named regression cases:
  partial reads, missing `usedPercent`, certificate association, and invalid
  network values.
- Record exact registry metadata for `@webframp/ai-usage`,
  `@dougschaefer/openai-usage`, and `@keeb/ollama` without installing them.

**Verify:** the baseline tests reproduce the legacy behavior/findings, and each
candidate has an explicit `fit`, `extend`, or `reject/pending runtime evidence`
status with reasons.

### Task 3: Build the bundle v1 contract package

**Goal:** provider-neutral canonical schemas before domain logic.

- Define strict Zod schemas for identity, provenance, observation/coverage
  windows, completeness, state, severity, confidence, metrics/units, facts,
  exceptions, sensitivity, and extension details.
- Define compatibility behavior for unsupported major versions and additive
  fields.
- Add helpers for overall-state derivation that cannot turn absent, stale, or
  partial data into healthy.
- Add conformance fixtures for healthy, degraded, critical, unknown, stale,
  partial, unsupported, and unauthorized bundles.
- Add adversarial fixtures for missing numeric values, invalid units, malformed
  timestamps, HTML-bearing strings, and invalid extension details.
- Add package documentation and license. Keep the contract as statically bundled
  source rather than an empty registry extension, as established by Task 1.

**Verify:** formatting, type-check, lint, unit tests, schema round trips,
static-import bundling evidence from Task 1, documentation, license, and
identifier scan pass for this package.

### Task 4: Build the first local adapter using existing homelab collectors

**Goal:** prove an independent existing-collector-to-bundle slice.

- Normalize local Netdata, TrueNAS, and Firewalla resource schemas without
  changing those collectors for renderer convenience.
- Validate every source record before normalization.
- Surface rejected records, partial reads, stale data, and missing fields.
- Preserve exception identity and associate TrueNAS certificate alerts with the
  correct certificate or leave them as separate alerts.
- Emit only bundle v1 output with explicit provenance and coverage.
- Package the adapter independently from the renderer and unrelated collectors.

**Verify:** conformance tests pass; the four mandatory regressions fail safely;
existing valid synthetic fixtures retain their operational signals.

### Task 5: Migrate the renderer to explicit bundle inputs

**Goal:** remove provider knowledge and hidden cross-model reads while
preserving the accepted visual direction.

- Replace literal aliases and provider-specific exception logic with explicit
  bundle inputs wired through CEL.
- Reject unsupported bundle major versions visibly.
- Render missing, stale, partial, invalid, unauthorized, and unsupported
  coverage above any reassuring healthy summary.
- Preserve exceptions-first layout, visible suppressions, escaping,
  self-contained HTML, and machine-queryable render results.
- Remove `ctx.dataRepository` cross-model enumeration from the renderer.
- Update manifest, README variables, generated README, and tests.

**Verify:** renderer tests prove it contains no provider names or hidden source
reads; visual snapshot comparison shows the accepted direction is preserved; all
adversarial content is escaped.

### Task 6: Compose and verify the first end-to-end vertical slice

**Goal:** demonstrate selected collectors → local adapter → renderer through
supported Swamp composition.

- Author a minimal Swamp workflow using model-method steps and CEL references.
- Include only the homelab pieces selected for the fixture.
- Validate the workflow before running it.
- Run against synthetic/public-safe fixture models and query the resulting data
  with Swamp commands.
- Inspect stored reports after any failure before changing definitions.

**Verify:** the workflow succeeds; the final HTML and render resource cite the
expected bundle; removing one source produces visible partial/unknown coverage.

## P1 — add first-class observability domains

### Task 7: Build local Swamp observability

**Goal:** expose Swamp's own operational state without coupling to the paused
control-plane project.

- Use supported run history, workflow history, stored report, heartbeat, and
  stale-run interfaces.
- Represent disabled or unavailable interfaces as coverage gaps.
- Avoid the optional internal runs API unless Task 1 proves a stable public
  compatibility boundary and the architecture document records it.
- Normalize active, succeeded, failed, stale, and orphaned states into bundle
  v1.

**Verify:** synthetic and available local evidence exercises success, failure,
stale, empty-history, and unavailable-interface cases without false health.

### Task 8: Build local LM Studio normalization

**Goal:** make existing LM Studio health and per-request probes first-class.

- Normalize endpoint availability, authorization, model capability, finish
  reason, token counts, context exhaustion, and timing/performance metrics.
- Declare request-level coverage explicitly and never present it as aggregate
  accounting.
- Preserve the distinction between endpoint down, token rejected, context
  exhausted, output-token limit reached, and reasoning-only empty output.

**Verify:** existing LM Studio tests plus new bundle conformance tests cover
each distinct state and performance unit.

### Task 9: Build local OpenAI organization usage and cost collection

**Status:** complete — implementation and evidence are recorded in
[openai-usage.md](openai-usage.md).

**Goal:** observe eligible OpenAI organization accounts through official APIs.

- Re-run registry/type search and inspect the candidate contract before coding.
- Implement the local typed collector against official organization usage and
  cost APIs with vault-supplied admin credentials, timeouts, cancellation, and
  pagination.
- Keep usage, billed cost, authorization failure, and unavailable dimensions
  distinct.
- Normalize through the shared contract with currency and coverage windows.
- Use or extend `@dougschaefer/openai-usage` only if captured runtime resources
  satisfy the compatibility profile exactly; otherwise retain the local model.

**Verify:** mocked API tests cover pagination, partial pages, rate limits,
authorization, malformed responses, missing dimensions, and exact totals.

### Task 10: Build local Anthropic usage collection

**Status:** complete — implementation and evidence are recorded in
[anthropic-usage.md](anthropic-usage.md).

**Goal:** observe eligible Anthropic organization or enterprise usage through
official supported APIs.

- Re-run registry/type search and inspect candidates before coding.
- Model capability and authorization differences explicitly; do not imply that
  every subscription exposes organization analytics.
- Implement a local typed collector only for documented stable endpoints.
- Normalize tokens, requests, cost when authoritative, breakdowns, windows, and
  coverage gaps.
- Use or extend `@webframp/ai-usage` or its Anthropic dependency only if runtime
  resources satisfy the local compatibility profile exactly.

**Verify:** mocked API tests cover eligible, unauthorized, unsupported,
paginated, partial, and malformed responses.

### Task 11: Build explicit subscription metadata

**Status:** complete — implementation and evidence are recorded in
[subscription-metadata.md](subscription-metadata.md).

**Goal:** represent plan facts without confusing them with API metering.

- Define a typed local model for explicit operator-supplied metadata and, only
  where available, authorized stable API facts.
- Represent plan name, cadence, price, currency, renewal window, seats, and
  declared limits as optional provenance-bearing fields.
- Forbid remaining-quota derivation and fabricated per-token cost.
- Normalize plan metadata into its own bundle section.

**Verify:** tests prove unknown limits remain absent, zero is preserved only
when explicitly supplied, and plan price never becomes usage cost.

### Task 12: Build LM Studio headless-daemon observability

**Status:** complete — implementation and evidence are recorded in
[lmstudio-daemon.md](lmstudio-daemon.md).

**Plan amendment (operator directed 2026-08-25):** the active runtime is LM
Studio on a remote Mac Studio, not Ollama. Keep Ollama first-class in the
provider-neutral contract, but defer an Ollama-specific adapter until it is an
actual operator requirement.

**Goal:** observe the Mac Studio's LM Studio headless daemon independently of
generation tooling and without private host defaults.

- Extend the local `@jpisgeek/lmstudio` package with an independently usable
  daemon model.
- Use the supported `lms ps --json` surface on the llmster host, with optional
  explicit `--host` remote mode, timeout, cancellation, and an argv-only
  process invocation.
- Preserve daemon reachability, exact loaded-model inventory, malformed output,
  missing CLI, and timeout as distinct states.
- Declare point-in-time inventory coverage and never infer aggregate requests
  or token accounting.
- Normalize through `@jpisgeek/dashboard-lmstudio` into the existing local
  inference bundle shape.

**Verify:** mocked tests cover remote daemon down, no loaded models, loaded
models, malformed JSON, missing CLI, partial coverage, timeout, and caller
cancellation. Do not contact the private Mac Studio during public BUILD.

### Task 13: Add optional composition workflows and examples

**Status:** complete — implementation and evidence are recorded in
[composition-workflows.md](composition-workflows.md).

**Goal:** make piece-by-piece installation practical without a mandatory
meta-package.

- Provide small workflows for homelab-only, Swamp-only, hosted-AI-only,
  local-inference-only, and mixed examples.
- Use CEL to pass explicit bundle data; do not rediscover models by aliases.
- Document how users omit any domain without a failed required dependency.
- Keep credentials and private identifiers out of all examples.

**Verify:** validate every workflow and run public-safe fixture variants that
omit at least one optional domain.

## P2 — whole-family verification and release preparation

### Task 14: Verify migration and family-level behavior

**Goal:** prove the implementation meets DEFINE as a coherent system.

- Run all unit, conformance, integration, workflow, and visual regression tests.
- Compare legacy signals with normalized output and document intentional
  changes.
- Test package installation matrices so each package works without unrelated
  collectors.
- Test unknown, stale, partial, unauthorized, invalid, and unsupported states
  end to end.
- Confirm the core renderer imports no collector and performs no network calls.

**Verify:** publish a VERIFY artifact mapping every DEFINE acceptance statement
to commands and results; unresolved gaps return the lifecycle to BUILD.

### Task 15: Run per-package quality and exact-content review gates

**Goal:** make every prospective public package reviewable on its final bytes.

For each changed or new manifest, run the repository gates in order:

1. `swamp extension fmt <manifest> --check`;
2. Deno format check and package tests;
3. `swamp extension quality <manifest>`;
4. generated README consistency check;
5. `scripts/scan-identifiers.sh` with generic rules and the private denylist;
6. `scripts/publish.sh <name> --review-only` to produce the exact-content-hash
   Fable security verdict;
7. resolve every `fix` or blocking finding, regenerate affected content, and
   repeat the review for the new hash;
8. run `scripts/check-review-verdicts.sh` and require exact-hash `PASS`.

**Verify:** every final package has a matching PASS review and no unresolved
correctness finding; changing any published byte invalidates the gate.

### Task 16: Dry run and stop at SHIP approval

**Goal:** prove registry readiness without publication.

- Run the repository publication pipeline through Swamp dry-run for each
  approved package.
- Record exact package versions, content hashes, dependencies, dry-run output,
  and any registry warnings in the REVIEW artifact.
- Confirm no private checkout, inventory, workflow, secret, or fixture is in the
  payload.
- Present the release set and any deferred adapters to the user.
- Stop before `swamp extension push`, Git push, deployment, or production
  configuration.

**Verify:** all dry runs pass and the lifecycle status reads
`SHIP — awaiting explicit publication approval`.

## Dependency order

```text
Task 1 architecture proof
  -> Task 2 compatibility and baselines
  -> Task 3 bundle contract
  -> Task 4 first local adapter
  -> Task 5 renderer migration
  -> Task 6 first vertical slice
  -> Tasks 7-12 domain slices (one at a time)
  -> Task 13 optional workflows
  -> Task 14 whole-family VERIFY
  -> Task 15 exact-content REVIEW
  -> Task 16 dry-run and SHIP gate
```

Tasks 7–12 share the contract but do not depend on one another. They remain
sequential during BUILD so each slice finishes and verifies independently.

## Risks and planned controls

| Risk                                                      | Control                                                                                       |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Reports are not CEL-addressable as normalized data        | Resolve in Task 1; use a typed normalization model if required                                |
| Shared contract packaging creates hidden install coupling | Prove bundling and independent installation in Tasks 1 and 3                                  |
| Community output differs from registry metadata           | Require captured runtime resources before adoption                                            |
| Provider APIs require unavailable account privileges      | Render `unauthorized` or `unsupported`; keep mock verification separate from live eligibility |
| Per-request local metrics look like complete totals       | Carry explicit coverage kind and observed-traffic scope                                       |
| Migration drops legacy exceptions                         | Baseline and parity checks in Tasks 2, 4, 5, and 14                                           |
| Invalid data crashes rendering or looks healthy           | Strict source validation plus conformance and adversarial fixtures                            |
| Package family becomes monolithic                         | Enforce dependency matrix and independent install tests                                       |
| Review PASS hides correctness findings                    | Require findings resolved, content regenerated, and fresh exact-hash review                   |
| Public artifacts leak private topology                    | Synthetic fixtures plus generic/private identifier scans before review                        |
| Original `mise-extension` work is disturbed               | Limit every command and edit to this Paseo worktree                                           |

## PLAN approval gate

Status: **approved by the user on 2026-08-25**.

Approval authorizes BUILD beginning with Task 1 only. It does not authorize
publication, Git push, deployment, production changes, or work in the original
`mise-extension` checkout.
