# slog-bog

Public [swamp](https://github.com/swamp-club/swamp) extensions, published to the
registry as `@jpisgeek/*`. Thin, unopinionated building blocks for workflows
that run over a homelab or small fleet. The opinions (thresholds, node lists,
dashboards) belong in your own models, not here.

<!-- extensions:start -->

| Extension                           | Version        | Source                                                 | What it is                                                                                                                                                                             |
| ----------------------------------- | -------------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@jpisgeek/anthropic-usage`         | `2026.09.05.1` | [`anthropic-usage/`](anthropic-usage/)                 | Local Anthropic Platform and Claude Enterprise organization usage and cost collection.                                                                                                 |
| `@jpisgeek/caddy`                   | `2026.09.04.1` | [`caddy/`](caddy/)                                     | Manage individual routes in an existing systemd Caddy wildcard site through Swamp SSH, with drift checks, validation, private backups and rollback.                                    |
| `@jpisgeek/dashboard-report-view`   | `2026.11.08.1` | [`dashboard-report-view/`](dashboard-report-view/)     | Interactive HTML snapshots with readable state tables, local filters and a named refresh button.                                                                                       |
| `@jpisgeek/firewalla`               | `2026.09.05.1` | [`firewalla/`](firewalla/)                             | Device and machine inventory from the Firewalla MSP API.                                                                                                                               |
| `@jpisgeek/fleet-status-monitoring` | `2026.11.09.1` | [`fleet-status-monitoring/`](fleet-status-monitoring/) | Fleet Status Monitoring: normalize versioned system probes, distinguish fresh health from access and coverage gaps, and render a filterable report with an authenticated host adapter. |
| `@jpisgeek/hyperv`                  | `2026.08.29.1` | [`hyperv/`](hyperv/)                                   | Read a Hyper-V host over SSH and act on its VMs.                                                                                                                                       |
| `@jpisgeek/lmstudio`                | `2026.09.05.1` | [`lmstudio/`](lmstudio/)                               | Probe and validate an OpenAI-compatible inference endpoint before you trust it.                                                                                                        |
| `@jpisgeek/mise`                    | `2026.08.28.3` | [`mise/`](mise/)                                       | Read-only sweep of mise toolchain state across a fleet.                                                                                                                                |
| `@jpisgeek/netdata`                 | `2026.09.05.1` | [`netdata/`](netdata/)                                 | Netdata standalone agent state across a set of nodes.                                                                                                                                  |
| `@jpisgeek/openai-usage`            | `2026.09.05.1` | [`openai-usage/`](openai-usage/)                       | Local OpenAI organization usage and billed-cost collection through official APIs.                                                                                                      |
| `@jpisgeek/proton-pass`             | `2026.09.05.1` | [`proton-pass/`](proton-pass/)                         | Proton Pass vault provider: resolves ${{ vault.get('<vault>', 'KEY') }} live through the official pass-cli at run time.                                                                |
| `@jpisgeek/subscription-metadata`   | `2026.09.05.1` | [`subscription-metadata/`](subscription-metadata/)     | Explicit operator-supplied subscription plan metadata normalized into dashboard bundle v1 without scraping, quota inference, or fictional usage cost.                                  |
| `@jpisgeek/truenas`                 | `2026.09.05.1` | [`truenas/`](truenas/)                                 | Read-only TrueNAS SCALE inventory and health over the JSON-RPC 2.0 WebSocket API.                                                                                                      |
| `@jpisgeek/video-pipeline`          | `2026.09.04.1` | [`video-pipeline/`](video-pipeline/)                   | Typed Swamp adapter for an operator-owned video production bridge, with content-checked stage receipts, explicit dependency checks, and cancellation.                                  |

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

Publication requires format and tests, a registry quality score, a
generated-README drift check, a mechanical scan for private identifiers, and an
independent secrets and security review. A PASS verdict must be committed under
`reviews/` for the exact release content hash before an extension ships. Details
in [SECURITY.md](SECURITY.md); how to contribute in
[CONTRIBUTING.md](CONTRIBUTING.md).
