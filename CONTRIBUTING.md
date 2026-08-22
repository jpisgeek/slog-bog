# Contributing

Extensions here are building blocks, not opinions. Keep them thin: one model
type per concern, arguments for everything environment-specific, no thresholds
or policy baked in. A user's workflow decides what "bad" means.

## Layout

```
extensions/models/<name>.ts              model extension source
extensions/models/<name>_test.ts         its tests (sibling; a test file named
                                         *_test.ts is correct — the loader skips
                                         it as a model, which is what you want)
extensions/vaults/<name>/mod.ts          vault extension source
extensions/manifests/<name>/manifest.yaml  publish manifest
extensions/manifests/<name>/readme.vars.yaml  the ONLY hand-written README input
extensions/manifests/<name>/README.md    GENERATED — do not edit
```

## READMEs are generated

Do not write or edit `README.md` under `extensions/manifests/`. Edit
`readme.vars.yaml` (purpose line, a placeholder example config, caveats) and
run `scripts/gen-readme.ts`. Everything else in the README — type names,
methods, argument and resource schemas, version — comes from the code via
`swamp model type describe`. CI fails if a committed README differs from the
generated one. This is the rule because hand-written READMEs drifted from the
code on every fix and a README is published surface.

## Before you open a PR

```
deno fmt --check
swamp extension fmt extensions/manifests/<name>/manifest.yaml --check
deno test extensions/
swamp extension quality extensions/manifests/<name>/manifest.yaml
scripts/gen-readme.ts --check
scripts/scan-identifiers.sh extensions/
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
