# Dashboard bundle contract

The dashboard bundle is the provider-neutral boundary between Swamp collectors,
normalization reports, and renderers. It keeps status, coverage, freshness,
completeness, and numeric availability separate so missing data cannot become a
false zero or a false all-clear.

This directory is public source, but it is not a standalone Swamp extension.
Adapters and renderers import `dashboard_bundle.ts` statically. Swamp inlines
the contract into each extension's standalone bundle, so installing one adapter
does not require installing every other member of the family.

## Versioning

The current contract is `1.0.0`.

- Consumers reject unsupported major versions.
- Unknown additive fields survive parsing within major version 1.
- A breaking field or semantic change requires a new major version.

## Honesty rules

- Bundle and section states use explicit values such as `unknown`, `stale`,
  `partial`, `unsupported`, and `unauthorized`.
- An observed metric must carry a finite number and a unit.
- An unavailable metric must carry a reason and cannot carry a value, including
  a convenient-looking zero.
- Coverage declares whether it is exact, observed traffic, a sample, estimated,
  or unknown.
- Freshness and completeness are separate from health.
- Only required sections determine base overall state. Unsuppressed critical or
  warning exceptions can raise it; suppressed exceptions remain data but do not
  alter it.
- Reported overall state must equal the state derived by the contract helper.

## Source use

```ts
import {
  DASHBOARD_BUNDLE_VERSION,
  parseDashboardBundle,
} from "../dashboard-contract/dashboard_bundle.ts";

const bundle = parseDashboardBundle(input);
console.log(DASHBOARD_BUNDLE_VERSION, bundle.state);
```

Use `data.latest("<model>", "<report-data-name>").attributes` to pass a
normalization report's persisted JSON into a downstream renderer. Do not make
the renderer enumerate other models or infer providers from aliases.

## Test

```sh
~/.swamp/deno/deno check dashboard-contract/dashboard_bundle.ts
~/.swamp/deno/deno test --allow-read dashboard-contract/
```

Tests and fixtures cover all operational states, version compatibility, additive
fields, missing numbers, invalid units, malformed timestamps, HTML-bearing text,
invalid extension namespaces, freshness, and reversed coverage windows.

## Security

The contract performs no network, filesystem, process, environment, or vault
operations. It validates data already provided by an adapter or renderer. Bundle
contents may still contain operational inventory, so sensitivity metadata
travels with sections, facts, metrics, and exceptions. Renderers must escape all
strings and operators must protect published dashboards accordingly.
