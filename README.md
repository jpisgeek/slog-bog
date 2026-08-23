# slog-bog

Public [swamp](https://github.com/swamp-club/swamp) extensions, published to the
registry as `@jpisgeek/*`. Thin, unopinionated building blocks for workflows
that run over a homelab or small fleet — the opinions (thresholds, node lists,
dashboards) belong in your own models, not here.

<!-- extensions:start -->

| Extension               | Version        | Source                         | What it is                                                                                                              |
| ----------------------- | -------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `@jpisgeek/dashboard`   | `2026.08.22.2` | [`dashboard/`](dashboard/)     | Renders a self-contained HTML status page from resources other collector models have already written.                   |
| `@jpisgeek/firewalla`   | `2026.08.22.2` | [`firewalla/`](firewalla/)     | Device and machine inventory from the Firewalla MSP API.                                                                |
| `@jpisgeek/lmstudio`    | `2026.08.23.1` | [`lmstudio/`](lmstudio/)       | Probe and validate an OpenAI-compatible inference endpoint before you trust it.                                         |
| `@jpisgeek/netdata`     | `2026.08.23.1` | [`netdata/`](netdata/)         | Netdata standalone agent state across a set of nodes.                                                                   |
| `@jpisgeek/proton-pass` | `2026.08.23.1` | [`proton-pass/`](proton-pass/) | Proton Pass vault provider: resolves ${{ vault.get('<vault>', 'KEY') }} live through the official pass-cli at run time. |
| `@jpisgeek/truenas`     | `2026.08.23.1` | [`truenas/`](truenas/)         | Read-only TrueNAS SCALE inventory and health over the JSON-RPC 2.0 WebSocket API.                                       |

<!-- extensions:end -->

Each extension lives in its own directory with its manifest, source, tests,
LICENSE, and a README generated from the source — that README is the reference
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
