# Optional Composition Workflows

## Decision

`@jpisgeek/dashboard-compose` is an optional workflow-only extension. It has no
collector, report, vault, driver, or datastore dependency. Operators install the
renderer, this package if desired, and only the producer/normalizer packages
they actually use.

The five workflows are:

- `@jpisgeek/dashboard-homelab-only`
- `@jpisgeek/dashboard-swamp-only`
- `@jpisgeek/dashboard-hosted-ai-only`
- `@jpisgeek/dashboard-local-inference-only`
- `@jpisgeek/dashboard-mixed`

Swamp assigned every workflow ID through `swamp workflow create`; no workflow ID
was generated or written manually.

## Composition contract

Each workflow performs one direct model-type execution of
`@jpisgeek/dashboard.render`. Its `bundles` global argument is an explicit CEL
list of `data.latest(<input model name>, <exact report data name>).attributes`
values. No workflow searches aliases, enumerates models, reads private Swamp
storage, or imports a collector.

The domain workflows offer per-producer include flags where the domain has more
than one producer. The mixed workflow defaults every domain off and adds a
domain only when its include flag is true. CEL conditional branches keep an
omitted domain's `data.latest` expression unevaluated, so an uninstalled domain
is not a failed dependency. Selecting a domain whose report does not exist does
fail instead of inventing a zero.

This split follows `design/workflow.md`, `design/reports.md`, and
`design/expressions.md`: workflows compose actions, reports normalize scoped
results, and CEL passes explicit persisted data to the renderer.

## Verification evidence

All five checked-in workflows were recreated from their Swamp-generated
scaffolds in an isolated public-safe repository and passed
`swamp workflow validate` with every validation true and zero warnings.

Two mixed-workflow fixture variants then ran successfully:

1. All four domain flags false. The renderer received zero bundles and wrote the
   visible `coverage:no-bundles` warning. No producer extension or model was
   required.
2. Homelab true and Swamp, hosted AI, and local inference false. A synthetic
   `.invalid` Netdata fixture produced one normalized homelab bundle. The
   renderer reported one received and valid bundle, zero exceptions, and no
   access to any omitted domain.

The fixture contained only reserved synthetic identifiers and contacted no
private or production system.
