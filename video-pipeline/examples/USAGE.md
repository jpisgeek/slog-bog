# Synthetic adapter example

This example generates **plain text only**, with an explicit synthetic marker in
every artifact. It does not generate or inspect video or audio. The receipt
field `videoSha256` contains the hash of `synthetic-video.txt` solely to
exercise the adapter contract. `durationSeconds` and `clippedSamples` remain
`null`; `metrics.verified` means that the synthetic file/hash checks passed.

The workflow runs
`prepare → narrate → render → inspect → package → verify →
assert-receipt → deliver`.
Each method receives the prepared input hash through `data.latest()`. The
assertion checks the verified receipt, prepared hash, artifact count, and
matching artifact hash. Delivery receives the hash from verification. The bridge
additionally refuses destinations outside its own temporary workspace.

The bridge is supplied as the Python source template `build/swamp-step.py.txt`;
copy it to `build/swamp-step.py` in the example workspace before running it. The
bridge is intentionally small and uses only Python's standard library. It
illustrates the fixed `scenes.json` plus `build/swamp-step.py` interface;
replace it with a trusted production bridge that actually renders and verifies
media before using this adapter for a real release.

## Run from a source checkout

Requirements: Swamp, Python 3 on `PATH`, and a supported POSIX environment.
Start at the repository root. These commands create an isolated temporary Swamp
repo; the model ID and all machine-specific paths are assigned at runtime.

```sh
example_source="$(pwd -P)/video-pipeline"
example_python="$(python3 -c 'import os, sys; print(os.path.realpath(sys.executable))')"
example_repo="$(python3 -c 'import os, tempfile; print(os.path.realpath(tempfile.mkdtemp(prefix="video-pipeline-example-")))')"
swamp repo init "$example_repo"
cp -R "$example_source/examples/synthetic" "$example_repo/project"
mv "$example_repo/project/build/swamp-step.py.txt" "$example_repo/project/build/swamp-step.py"
cp "$example_source/examples/workflow-example-video.yaml" "$example_repo/workflows/"
cd "$example_repo"
swamp extension source add "$example_source" --only models
example_delivery="$(python3 -c 'import json, sys; print(json.dumps([sys.argv[1]]))' "$example_repo/project/deliveries/example")"
swamp model create @jpisgeek/video-pipeline example-video \
  --global-arg "workspaceRoot=$example_repo/project" \
  --global-arg "pythonBin=$example_python" \
  --global-arg release=v1 \
  --global-arg "deliveryFolders=$example_delivery" \
  --global-arg timeoutSeconds=60
swamp workflow validate @jpisgeek/example-video-pipeline
swamp workflow run @jpisgeek/example-video-pipeline
swamp data get example-video deliver --json
```

The expected result is seven stored stage receipts, one passing assertion, and
`project/deliveries/example/synthetic-video.txt`. Runtime models, Swamp state,
receipts, and produced artifacts stay in the temporary repo; none belong in the
published example. The workflow's ID was originally assigned by
`swamp workflow create` and is preserved in the distributed YAML.

## Integration checks

From the source checkout root:

```sh
deno test --allow-read --allow-write --allow-env=PATH --allow-run \
  video-pipeline/integration_test.ts
```

The tests locate `python3` through `PATH`, run all seven actual adapter methods
against fresh copies of the bridge, confirm every artifact is marked text,
reject an outside delivery destination without creating files there, and reject
changed scene inputs after preparation. No renderer, network service,
credentials, or private assets are needed.
