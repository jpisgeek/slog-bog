# Dashboard and Observability Extension Family — DEFINE

## Lifecycle Status

- **Phase:** BUILD — Tasks 1-12 complete; Task 13 pending
- **Spec:** this document
- **Plan:** [PLAN.md](PLAN.md), approved 2026-08-25
- **Build:** in progress
- **Blockers:** none
- **Last updated:** 2026-08-25

## Purpose

Turn the existing `@jpisgeek/dashboard` into a public, provider-neutral family
of independently installable Swamp extensions for operational monitoring, Swamp
observability, hosted AI usage, subscription metadata, and local LLM operations.

The existing visual direction remains the baseline. The project changes the data
contract and operational depth, not the dashboard's visual identity.

## Users

The primary user is a Swamp operator who wants one honest operational view but
does not want to install every supported collector. Secondary users are public
extension authors who want to publish a collector or adapter that can feed the
same dashboard contract without coupling to the renderer.

Users may operate a homelab, cloud services, hosted AI accounts, local inference
runtimes, or any subset of those domains.

## Product principles

1. **Local-first extensions.** The family is designed and implemented locally
   under `@jpisgeek` first. A community extension is adopted only after its
   exact current model, resource, accuracy, coverage, security, and lifecycle
   contracts are inspected and shown to fit. Registry existence alone is not a
   reason to depend on it.
2. **Search before building remains mandatory.** Registry and local type
   searches identify reusable work and prior art. Search informs the decision;
   it does not override the local-first product boundary.
3. **Independently installable pieces.** Installing the renderer or one domain
   adapter must not install unrelated collectors.
4. **Provider-neutral core.** The renderer consumes a versioned normalized
   bundle. It does not import collector implementations or key on provider names
   and literal source aliases.
5. **Missing is not zero. Unknown is not healthy.** Missing, stale, partial,
   rejected, unsupported, unauthorized, and failed observations remain distinct
   and visible.
6. **Collect once, compose through Swamp.** Collectors produce typed resources,
   reports normalize and analyze them, workflows compose model methods, and CEL
   passes explicit data references between stages.
7. **Evidence carries provenance.** Every normalized observation declares its
   source, observation time, coverage window, completeness, and freshness.
8. **No private topology in public source.** Public manifests, examples, tests,
   fixtures, documentation, and reviews contain no private hostnames, addresses,
   account identifiers, credentials, vault paths, or inventories.

These primitive boundaries follow Swamp's architecture guidance: models observe
or act on external resources, reports perform repeatable analysis, workflows
compose model methods, and data is referenced through CEL.

## Scope

### 1. Shared versioned bundle contract

Define a public, versioned dashboard bundle schema that supports independently
produced sections. Version 1 must represent:

- bundle identity and schema version;
- producer identity and source resource reference;
- observation and coverage windows;
- freshness and completeness;
- status, severity, and confidence without conflating them;
- metrics with explicit units and optional limits;
- inventory and capability facts;
- exceptions, degradations, and user-visible explanations;
- links or references to supporting Swamp data and reports;
- redaction and sensitivity metadata;
- extension-defined details that cannot invalidate core rendering.

Required state vocabulary includes at least `healthy`, `degraded`, `critical`,
`unknown`, `stale`, `partial`, `unsupported`, and `unauthorized`. Numeric values
are optional. Their absence must never be coerced to zero.

Compatibility is explicit: consumers reject unsupported major versions and
ignore unknown additive fields within a supported major version.

### 2. Renderer

Evolve `@jpisgeek/dashboard` into a presentation-only extension that:

- accepts explicit normalized bundle references through supported CEL wiring;
- has no hidden cross-model repository scans;
- has no knowledge of Netdata, TrueNAS, Firewalla, Swamp, OpenAI, Anthropic, LM
  Studio, Ollama, or any other provider;
- renders partial, stale, unknown, and unauthorized coverage prominently;
- preserves exceptions-first presentation and visible suppressions;
- safely renders untrusted bundle content;
- exposes a machine-queryable render result in addition to HTML;
- preserves the current self-contained, network-free output model unless PLAN
  establishes a supported Swamp-native delivery boundary.

### 3. Normalization adapters

Adapters are report extensions unless a confirmed Swamp API limitation requires
a different supported primitive. Each adapter consumes typed collector output
and emits one or more conforming bundles.

Initial adapter domains are:

- existing local Netdata, TrueNAS, and Firewalla collectors;
- existing local LM Studio endpoint and request probes;
- Swamp operational history and health;
- hosted AI usage and cost observations;
- subscription-plan metadata;
- local inference observations, including the contract needed for Ollama.

An adapter package depends only on its source contract and the shared bundle
contract. The renderer does not depend on adapters. Adapters do not depend on
each other.

### 4. Swamp monitoring

Swamp observability must cover, where supported by public Swamp interfaces:

- model run history and outcomes;
- workflow run history and outcomes;
- stored report availability and status;
- serve heartbeat freshness;
- active, stale, failed, and orphaned execution states;
- coverage gaps when an interface is disabled or unavailable.

The optional internal runs API is not a stable dependency unless PLAN verifies
and documents an acceptable public compatibility boundary. Public commands,
typed data, and stored reports are preferred.

### 5. Hosted AI usage and costs

The contract must support organization-level token usage, request counts, cost,
time windows, provider/model/project breakdowns, and coverage status.

The initial local implementation evaluates official provider APIs for which the
operator has eligible administrative access. OpenAI organization usage/cost
access and Anthropic organization or enterprise analytics are distinct
capabilities with distinct authorization states.

Community extensions are compatibility candidates, not default dependencies:

- `@webframp/ai-usage` currently covers Bedrock, Vertex AI, Azure OpenAI, and
  Claude Enterprise with explicit provider coverage reporting.
- `@dougschaefer/openai-usage` currently covers OpenAI organization usage and
  costs using an appropriately scoped admin key.

During PLAN, each candidate's actual resources must be captured and validated
against the local adapter profile. A candidate may be used directly, wrapped by
a local normalization report, extended, or rejected. No implementation is chosen
merely from registry description text.

### 6. Subscription metadata

Subscription-plan metadata and API metering are separate data classes. The
bundle may represent plan name, billing cadence, price, renewal window, seat
count, and declared limits only when obtained from an authorized stable API or
explicit operator configuration.

The system must not scrape personal account dashboards, infer remaining quota,
or translate a flat subscription price into fictional per-token cost. Unknown
limits and remaining quota remain unknown.

### 7. Local inference

Local inference is first-class in version 1 even if all runtime adapters do not
ship in the first release. The shared contract must represent:

- runtime and endpoint identity without exposing secrets;
- runtime availability and authorization state;
- loaded and available models;
- request counts and success/failure status;
- prompt, completion, cached, and reasoning tokens when reported;
- time to first token, generation duration, tokens per second, and load time;
- context length, truncation, finish reason, and token-limit exhaustion;
- observation coverage and whether totals are per-request or aggregate;
- accelerator, memory, and queue facts when the runtime exposes them.

The existing LM Studio endpoint and probe extensions are the first local source
contracts. Their per-request metrics do not become complete accounting unless
all relevant traffic is instrumented or a trustworthy aggregate runtime source
exists.

`@keeb/ollama` currently provides generation, batch generation, and unload. It
is prior art and a possible operational dependency, but it does not currently
satisfy the required observability and accounting profile. PLAN must evaluate
whether to extend it or build a local Ollama observation model through supported
APIs. Either result must normalize to the same provider-neutral contract.

## Package boundaries

The intended family has these logical packages. PLAN may refine names but not
collapse the independence boundary without new DEFINE approval.

| Package class        | Responsibility                             | May depend on            |
| -------------------- | ------------------------------------------ | ------------------------ |
| Contract             | Versioned schemas and conformance fixtures | Zod only                 |
| Renderer             | Render explicit normalized bundles         | Contract                 |
| Domain adapter       | Normalize one source contract              | Contract and that source |
| Collector            | Observe one provider/runtime/service       | Its API and vault refs   |
| Composition workflow | Run selected collectors/adapters/renderer  | Only selected pieces     |

There is no mandatory meta-package. An optional convenience bundle may be
considered later, but the piece-by-piece installation path is authoritative.

## Accuracy and coverage rules

Every adapter and renderer must enforce these rules:

1. A missing field is absent or unknown, never a fabricated default.
2. A partial read marks the affected bundle partial even when some records were
   successfully read.
3. A stale observation cannot produce an unqualified healthy state.
4. Invalid source records are counted and surfaced; they are not silently
   dropped or blindly cast.
5. Authorization failure is distinct from endpoint failure and unsupported
   capability.
6. Counters declare their coverage window and whether they are monotonic,
   sampled, estimated, or exact.
7. Cost declares currency and provenance. Estimated cost is visibly distinct
   from provider-billed cost.
8. Suppressions remain visible and do not alter underlying measured state.
9. Overall status is derived from explicit section states and coverage; no data
   cannot yield "all healthy."
10. The prior dashboard findings—partial-read masking, missing `usedPercent`
    becoming zero, incorrect certificate matching, and unvalidated network
    values—are mandatory migration regression cases.

## Security and privacy

- Credentials are supplied at runtime through Swamp vault references and never
  written to bundle resources, HTML, logs, fixtures, or documentation.
- Collectors request the least privilege required for read-only observation.
- Network clients use supported typed models, TLS verification, timeouts, and
  cancellation. Raw CLI wrappers and `command/shell` integrations are not used.
- Every string rendered into HTML is treated as untrusted.
- Bundles declare potentially identifying fields so operators can choose what to
  publish.
- Public examples use synthetic identifiers only.
- Generated dashboards are operational inventory and must be served behind
  suitable access control when they contain sensitive details.
- Public release requires an identifier scan and an exact-content-hash security
  review after all generated files are final.

## Migration

Migration is additive until the new path proves honest and complete:

1. Freeze the current dashboard contract as the legacy baseline.
2. Define bundle schemas and conformance fixtures independently.
3. Add local adapters for existing collectors and verify parity plus explicit
   degradation behavior.
4. Move the renderer to explicit bundle inputs through CEL.
5. Preserve the existing visual direction while replacing literal aliases and
   provider-specific exception logic.
6. Remove legacy hidden reads only after regression evidence shows that no
   supported signal was silently lost.

Existing collector packages remain independently publishable. Their source
schemas are not changed solely to make renderer access convenient when a report
adapter can normalize them.

## Non-goals

- Replacing the paused private control-plane project.
- Modifying, cleaning, or resuming the separate `mise-extension` checkout.
- Building a universal billing system or reconciling provider invoices.
- Scraping personal subscription dashboards.
- Inventing remaining subscription quota or translating plans into fake token
  balances.
- Proxying all LLM traffic in the first release.
- Treating request probes as complete accounting without coverage evidence.
- Making the renderer an alert delivery, remediation, or collection engine.
- Requiring every collector or adapter to install the full family.
- Publishing, pushing, deploying, or changing production configuration during
  DEFINE, PLAN, BUILD, VERIFY, or REVIEW without the explicit relevant gate.

## Definition of done

The project is done when:

- the shared versioned bundle contract and conformance tests are public-safe;
- the renderer uses only explicit normalized bundles through CEL;
- local adapters cover the agreed initial domains;
- Swamp, hosted AI, subscription, and local inference states are represented
  without false zero or false healthy behavior;
- each package is independently installable and documents only its own
  dependencies;
- community compatibility decisions are supported by captured schema evidence;
- migration preserves the accepted visual direction and improves operational
  usefulness;
- every eventual extension passes formatting, tests, quality, generated README,
  identifier scan, security review, dry run, and exact-content-hash review;
- publication occurs only after explicit SHIP approval.

## Constraints and repository state

- Work is confined to the Paseo worktree on branch `dashboard-observability`.
- The original `mise-extension` checkout remains untouched.
- The worktree is based on commit `2e6ab31`.
- The mandatory Swamp `AGENTS.md` rules were available in the original checkout
  but are not tracked in this worktree's current commit. Their rules govern this
  lifecycle. Resolving whether to enroll or track them here is a PLAN item and
  requires care not to disturb the original checkout.
- No BUILD work starts until this DEFINE is approved. After approval, PLAN is
  written and presented for a separate approval.

## Approval gate

Status: **approved by the user on 2026-08-25**.

Approval means: “This is what we are building.” It authorizes writing PLAN only.
It does not authorize BUILD, publication, push, deployment, or production
changes.
