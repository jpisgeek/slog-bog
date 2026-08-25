# slog-bog

Public [swamp](https://github.com/swamp-club/swamp) extensions, published to the
registry as `@jpisgeek/*`. Thin, unopinionated building blocks for workflows
that run over a homelab or small fleet. The opinions (thresholds, node lists,
dashboards) belong in your own models, not here.

<!-- extensions:start -->

| Extension                         | Version        | Source                                             | What it is                                                                                                                                            |
| --------------------------------- | -------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@jpisgeek/anthropic-usage`       | `2026.08.25.1` | [`anthropic-usage/`](anthropic-usage/)             | Local Anthropic Platform and Claude Enterprise organization usage and cost collection.                                                                |
| `@jpisgeek/dashboard`             | `2026.08.25.1` | [`dashboard/`](dashboard/)                         | Renders explicit provider-neutral dashboard bundle v1 inputs as a self-contained, exceptions-first HTML status page.                                  |
| `@jpisgeek/dashboard-homelab`     | `2026.08.25.1` | [`dashboard-homelab/`](dashboard-homelab/)         | Provider-neutral dashboard bundle adapter for the local Netdata, TrueNAS, and Firewalla collector contracts.                                          |
| `@jpisgeek/dashboard-lmstudio`    | `2026.08.25.2` | [`dashboard-lmstudio/`](dashboard-lmstudio/)       | Provider-neutral dashboard adapter for @jpisgeek/lmstudio endpoint, headless daemon, and per-request probes.                                          |
| `@jpisgeek/dashboard-swamp`       | `2026.08.25.1` | [`dashboard-swamp/`](dashboard-swamp/)             | Local Swamp operational observability.                                                                                                                |
| `@jpisgeek/firewalla`             | `2026.08.22.2` | [`firewalla/`](firewalla/)                         | Device and machine inventory from the Firewalla MSP API.                                                                                              |
| `@jpisgeek/lmstudio`              | `2026.08.25.1` | [`lmstudio/`](lmstudio/)                           | Probe and validate an OpenAI-compatible inference endpoint before you trust it.                                                                       |
| `@jpisgeek/netdata`               | `2026.08.23.1` | [`netdata/`](netdata/)                             | Netdata standalone agent state across a set of nodes.                                                                                                 |
| `@jpisgeek/openai-usage`          | `2026.08.25.1` | [`openai-usage/`](openai-usage/)                   | Local OpenAI organization usage and billed-cost collection through official APIs.                                                                     |
| `@jpisgeek/proton-pass`           | `2026.08.23.1` | [`proton-pass/`](proton-pass/)                     | Proton Pass vault provider: resolves ${{ vault.get('<vault>', 'KEY') }} live through the official pass-cli at run time.                               |
| `@jpisgeek/subscription-metadata` | `2026.08.25.1` | [`subscription-metadata/`](subscription-metadata/) | Explicit operator-supplied subscription plan metadata normalized into dashboard bundle v1 without scraping, quota inference, or fictional usage cost. |
| `@jpisgeek/truenas`               | `2026.08.23.1` | [`truenas/`](truenas/)                             | Read-only TrueNAS SCALE inventory and health over the JSON-RPC 2.0 WebSocket API.                                                                     |

<!-- extensions:end -->

Each extension lives in its own directory with its manifest, source, tests,
LICENSE, and a README generated from the source. That README is the reference
for arguments, methods, and data written.

## Using one

```
swamp extension pull @jpisgeek/<name>
swamp model create @jpisgeek/<type> <your-model-name>
```

## Trust

Everything here passes the same gates before publish: format and tests, registry
quality score, a generated-README drift check, a mechanical scan for private
identifiers, and a model-driven secrets & security review whose PASS verdict is
committed under `reviews/` against the exact content hash that shipped. Details
in [SECURITY.md](SECURITY.md); how to contribute in
[CONTRIBUTING.md](CONTRIBUTING.md).
