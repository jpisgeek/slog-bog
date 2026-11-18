# Mac setup

## Requirements

- Apple Silicon Mac (M-series), native arm64 Python 3.11 or newer. Python 3.13
  is the upstream installation example. This adapter targets mflux 0.24.0.
- A macOS release supported by the installed MLX Metal wheel. Current mflux pins
  MLX >=0.32,<0.33. Confirm the wheel's macOS requirement before installation;
  this package does not establish or test a minimum macOS version.
- Plan for 16 GB unified memory at minimum for an initial trial; 24–32 GB gives
  more room for 1024px output. These are planning recommendations, not tested
  minimums. Close large apps and start at 512px if memory is tight.
- Reserve tens of GB of free disk for the runtime, download cache, checkpoint
  and outputs. Saving a 4-bit checkpoint can first download full-precision
  weights, so the peak disk/memory requirement exceeds the final checkpoint
  size.
- Swamp installed from its official distribution. No LM Studio, hosted inference
  API key or frontier model is needed to execute the prepared behavior.

One-time installation and model downloads need Internet access. Read and accept
any upstream model license yourself. Do not commit or redistribute weights with
this source package.

## Prepare the runtime and weights

Use a dedicated virtual environment. Replace all `/example` paths with paths you
control. Use Python's native arm64 build, not Rosetta.

```sh
python3 -m venv /example/runtime
/example/runtime/bin/python -m pip install 'mflux==0.24.0'
/example/runtime/bin/mflux-generate --help
/example/runtime/bin/mflux-save --model schnell --quantize 4 --path /example/models/schnell-q4
mkdir -p /example/output
chmod 700 /example/output
```

`mflux-save` may download upstream full-precision weights before quantization.
Do this while online, then run one online smoke image to finish loading assets:

```sh
/example/runtime/bin/mflux-generate \
  --model /example/models/schnell-q4 --base-model schnell --quantize 4 \
  --steps 4 --seed 42 --width 512 --height 512 \
  --prompt 'A friendly moss-green swamp creature, bold silhouette, cel shading' \
  --output /example/output/online-smoke.png
```

Now disconnect networking and run the same command with a new output filename:

```sh
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 \
/example/runtime/bin/mflux-generate \
  --model /example/models/schnell-q4 --base-model schnell --quantize 4 \
  --steps 4 --seed 42 --width 512 --height 512 \
  --prompt 'A friendly moss-green swamp creature, bold silhouette, cel shading' \
  --output /example/output/offline-smoke.png
```

If a cache error occurs, reconnect only to obtain the named missing asset, then
repeat the disconnected test. Do not silently turn offline mode off in the
behavior. Keep the same environment, cache location and checkpoint for later
runs. Once the image opens correctly, record `pip freeze` and the checkpoint
hashes in private operator records. A seed alone does not ensure identical
pixels across runtime or model versions.

## Register and run with Swamp

Register the source as shown in the generated README. Create an instance named
`imagegen` of type `@jpisgeek/imagegen`, using the global arguments in that
README. Use your installed Swamp's command help for instance creation:

```sh
swamp help model create
swamp model type describe @jpisgeek/imagegen --json
swamp help model method run
```

Run its `generate` method with these method arguments:

```json
{
  "prompt": "A moss-green swamp creature mascot with amber eyes, bold clean silhouette, cel shading, simple dark background, centered avatar composition",
  "seed": 42,
  "width": 1024,
  "height": 1024,
  "steps": 4
}
```

For image-to-image, add `imagePath: /example/reference.png` and `imageStrength`
in 0–1. Confirm strength behavior against your pinned mflux version. Preserve
the reference image and recorded hash privately. Start with small changes and
inspect the result; this is not a guaranteed identity-preserving editor.

Use a local Swamp repository/datastore for disconnected execution. A remote
datastore can require networking and transmit receipts.

For a reusable Swamp workflow, run `swamp workflow create imagegen`. Copy the
fields in `examples/imagegen.workflow.yaml` into the new definition, preserving
the ID assigned by Swamp. The included template makes one `model_method` step
target the `imagegen` instance and its `generate` method. Pass prompt/seed
through workflow inputs, then `swamp workflow validate imagegen` before running.
This source package supplies the typed behavior, not a fabricated export of the
original workflow.

## Verification status

The implementation is a reconstruction, not recovered original source. A real
Apple M5 Mac with 32 GB unified memory was tested on 2026-11-18:

- Swamp workflow: validation passed, one generation step succeeded, 512 × 512,
  seed 43, four steps. Reported workflow duration: 13.630 seconds.
- Direct adapter invocation: 1024 × 1024, seed 42, four steps, 51.82 seconds.
- Both PNGs were decoded and visually inspected. Their SHA-256 values matched
  their provenance receipts. The workflow receipt was retrieved from Swamp data.
- Runtime: Python 3.12.14, mflux 0.24.0, MLX and mlx-metal 0.32.4, Pillow 13,
  Swamp 20261014.121640.0, Deno 2.9.8.
- Tested local checkpoint:
  [dhairyashil/FLUX.1-schnell-mflux-4bit](https://huggingface.co/dhairyashil/FLUX.1-schnell-mflux-4bit),
  revision `0e0b247ac48b8bf86fd5b440813b7da5854e238b`.

These timings are observations, not performance guarantees. The tested
checkpoint was downloaded already quantized; the upstream `mflux-save`
preparation route above was not separately tested. Check the model license
before downloading. The adapter's Hugging Face offline flags were enabled and
cached assets loaded, but networking was not disabled or firewalled during these
runs. This verifies local inference, not enforced network isolation. Complete
the disconnected smoke test above if you require that assurance. Image-to-image
conditioning was covered by argument tests, not a real reference-image render.
The tested setup required normal Metal access; an OS/process sandbox that hides
Metal cannot run inference.

## Primary references

- [Mflux installation](https://github.com/mflux-community/mflux#installation)
- [Mflux dependency definitions](https://github.com/mflux-community/mflux/blob/main/pyproject.toml)
- [FLUX.1 CLI and image tools](https://github.com/mflux-community/mflux/blob/main/src/mflux/models/flux/README.md)
- [Local checkpoints, quantization and caches](https://github.com/mflux-community/mflux/blob/main/src/mflux/models/common/README.md)
- [Swamp](https://github.com/swamp-club/swamp)
