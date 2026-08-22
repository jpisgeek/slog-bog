# slog-bog

Public [swamp](https://github.com/swamp-club/swamp) extensions, published to the
registry as `@jpisgeek/*`. Thin, unopinionated building blocks for workflows
that run over a homelab or small fleet — the opinions (thresholds, node lists,
dashboards) belong in your own models, not here.

| Extension | What it is |
|-----------|------------|
| _arriving_ | Netdata agent state · Proton Pass vault · TrueNAS inventory · Firewalla MSP inventory · LM Studio endpoint probing |

Each extension's README under `extensions/manifests/<name>/` is generated from
its source and is the reference for arguments, methods, and data written.

## Using one

```
swamp extension pull @jpisgeek/<name>
swamp model create @jpisgeek/<type> <your-model-name>
```

## Trust

Everything here passes the same gates before publish: format and tests,
registry quality score, a generated-README drift check, a mechanical scan for
private identifiers, and a model-driven secrets & security review whose PASS
verdict is committed under `reviews/` against the exact content hash that
shipped. Details in [SECURITY.md](SECURITY.md); how to contribute in
[CONTRIBUTING.md](CONTRIBUTING.md).
