# Contributing

Extensions here are building blocks, not opinions. Keep them thin: one model
type per concern, arguments for everything environment-specific, no thresholds
or policy baked in. A user's workflow decides what "bad" means.

## Layout

One directory per extension at the repo root, self-contained
(`paths.base: manifest` in its manifest):

```
<name>/manifest.yaml        publish manifest; repository: points at this directory
<name>/<name>.ts            source (a vault: <name>.ts exporting `vault`)
<name>/<name>_test.ts       tests beside the source (a *_test.ts file is correct —
                            the loader skips it as a model, which is what you want)
<name>/readme.vars.yaml     the ONLY hand-written README input
<name>/README.md            GENERATED — do not edit
<name>/LICENSE              MIT
```

## READMEs are generated

Do not write or edit any `<name>/README.md`, nor the extensions table in the root README. Edit
`readme.vars.yaml` (purpose line, a placeholder example config, caveats) and
run `scripts/gen-readme.ts`. Everything else in the README — type names,
methods, argument and resource schemas, version — comes from the code via
`swamp model type describe`. CI fails if a committed README differs from the
generated one. This is the rule because hand-written READMEs drifted from the
code on every fix and a README is published surface.

## Before you open a PR

```
deno fmt --check
swamp extension fmt <name>/manifest.yaml --check
deno test <name>/
swamp extension quality <name>/manifest.yaml
scripts/gen-readme.ts --check
scripts/scan-identifiers.sh <name>/
```

No real hostnames, IPs, domains, vault item paths, account IDs, or local paths —
not in code, comments, tests, or README examples. Use `<your-host>`,
`example.com`, `YOUR_API_KEY`, `203.0.113.0/24`, `2001:db8::/32`.

Pin every `npm:` import to an exact version. No new dependencies without
discussion — the registry bundles them, and each one is a supply-chain surface.

## Publishing

Maintainers only. `scripts/publish.sh <name>` runs every gate in order, writes
the review verdict, shows the exact publication payload, and stops for
approval. Nothing is pushed to the registry without a PASS verdict for the
current content hash.
