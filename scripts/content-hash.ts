#!/usr/bin/env -S deno run --allow-read
// content-hash.ts — the identity of an extension's published surface.
//
// Prints a sha256 over every file the manifest publishes (plus the manifest
// itself), each prefixed by its repo-relative path, in sorted order. Any change
// to any published byte — source, README, LICENSE, manifest, version — changes
// the hash. Review verdicts are filed under this hash, so a verdict can never
// silently cover a different build.
//
// Usage:
//   scripts/content-hash.ts <name>/manifest.yaml [--list]
//
// --list prints the resolved file set instead of the hash (for debugging and
// for feeding the review prompt the exact same files).
//
// Path resolution (matches swamp's defaults as used in this repo):
//   models/vaults/workflows/reports: relative to the manifest's directory
//                    when paths.base is "manifest" (this repo), else extensions/<kind>/
//   additionalFiles: relative to the manifest's own directory
//   README.md, LICENSE beside the manifest are always included if present.

import { parse } from "jsr:@std/yaml@1.0.5";
import { crypto } from "jsr:@std/crypto@1.0.3";
import { encodeHex } from "jsr:@std/encoding@1.0.5/hex";
import { dirname, join, normalize, relative } from "jsr:@std/path@1.0.8";

const args = [...Deno.args];
const list = args.includes("--list");
const manifestPath = args.find((a) => !a.startsWith("--"));
if (!manifestPath) {
  console.error("usage: content-hash.ts <manifest.yaml> [--list]");
  Deno.exit(2);
}

const repoRoot = Deno.cwd();
const manifestDir = dirname(manifestPath);
const manifest = parse(await Deno.readTextFile(manifestPath)) as Record<
  string,
  unknown
>;

function strings(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.flatMap((e) => {
    if (typeof e === "string") return [e];
    if (e && typeof e === "object") {
      const o = e as Record<string, unknown>;
      for (const k of ["path", "file", "src"]) {
        if (typeof o[k] === "string") return [o[k] as string];
      }
    }
    return [];
  });
}

// paths.base: "manifest" resolves typed keys against the manifest's own
// directory (the per-extension layout this repo uses); the default
// "typedDir" resolves them against extensions/<kind>/.
const base = ((manifest.paths as Record<string, unknown> | undefined)?.base ??
  "typedDir") as string;
const typed = (kind: string, rel: string) =>
  normalize(
    base === "manifest"
      ? join(manifestDir, rel)
      : join("extensions", kind, rel),
  );
const files = new Set<string>([normalize(manifestPath)]);
for (const m of strings(manifest.models)) files.add(typed("models", m));
for (const v of strings(manifest.vaults)) files.add(typed("vaults", v));
for (const w of strings(manifest.workflows)) files.add(typed("workflows", w));
for (const r of strings(manifest.reports)) files.add(typed("reports", r));
for (const a of strings(manifest.additionalFiles)) {
  files.add(normalize(join(manifestDir, a)));
}
for (const side of ["README.md", "LICENSE"]) {
  const p = normalize(join(manifestDir, side));
  try {
    await Deno.stat(p);
    files.add(p);
  } catch { /* absent is fine */ }
}

const sorted = [...files].map((p) => relative(repoRoot, join(repoRoot, p)))
  .sort();

if (list) {
  for (const f of sorted) console.log(f);
  Deno.exit(0);
}

const enc = new TextEncoder();
const chunks: Uint8Array[] = [];
for (const f of sorted) {
  let data: Uint8Array;
  try {
    data = await Deno.readFile(f);
  } catch {
    console.error(`published file missing: ${f}`);
    Deno.exit(1);
  }
  chunks.push(
    enc.encode(`=== ${f} (${data.byteLength}) ===\n`),
    data,
    enc.encode("\n"),
  );
}
const total = chunks.reduce((n, c) => n + c.byteLength, 0);
const buf = new Uint8Array(total);
let off = 0;
for (const c of chunks) {
  buf.set(c, off);
  off += c.byteLength;
}
console.log(encodeHex(await crypto.subtle.digest("SHA-256", buf)));
