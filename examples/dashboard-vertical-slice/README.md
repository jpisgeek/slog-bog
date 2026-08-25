# Dashboard vertical slice

This public-safe example proves the supported Swamp composition path:

1. a deterministic Netdata-shaped collector writes typed resources;
2. `@jpisgeek/dashboard-homelab` runs as a required method report and persists
   `report-jpisgeek-dashboard-homelab-json`;
3. a validated workflow passes that artifact explicitly with
   `data.latest(...).attributes` to `@jpisgeek/dashboard`;
4. the renderer writes `artifacts/dashboard.html` and a queryable `render`
   resource.

The fixture uses only reserved synthetic names and `.invalid` URLs. It contains
no inventory, credentials, hostnames, or private topology. Runtime `.swamp/`
data and generated HTML are ignored.

Use the checked-in workflow with `mode=healthy` or `mode=partial`. The latter
simulates a collector sub-fetch gap and must render visible partial coverage.

## Reproduce

From this directory, register only the three selected local sources:

```sh
swamp extension source add ./fixture-extension
swamp extension source add ../../dashboard-homelab
swamp extension source add ../../dashboard
swamp doctor extensions --json
```

Validate before every workflow run:

```sh
swamp model validate synthetic-netdata --json
swamp model validate synthetic-dashboard --json
swamp workflow validate dashboard-vertical-slice --json
swamp workflow run dashboard-vertical-slice --input mode=healthy
swamp report get @jpisgeek/dashboard-homelab --model synthetic-netdata --json
swamp data get synthetic-dashboard render --json

swamp workflow validate dashboard-vertical-slice --json
swamp workflow run dashboard-vertical-slice --input mode=partial
swamp data get synthetic-dashboard render --json
```

The separately generated `synthetic-dashboard-missing` definition has no bundle
inputs. Running its `render` method proves that removing the selected source
writes a visible `coverage:no-bundles` exception.
