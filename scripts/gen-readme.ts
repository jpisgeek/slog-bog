#!/usr/bin/env -S deno run --allow-read --allow-write --allow-run --allow-env
// gen-readme.ts — renders <name>/README.md (per-extension dir) from:
//   templates/README.md.tmpl     the one template
//   <name>/readme.vars.yaml      the only hand-written input
//   <name>/manifest.yaml         version, repository, which source files publish
//   the source itself            model/vault exports, read by importing the
//                                module and converting its zod schemas with
//                                z.toJSONSchema — no swamp CLI involved, so this
//                                runs in CI as well as locally
// and stamps the extensions table in the root README between markers.
//
// Usage:
//   scripts/gen-readme.ts [--check] [<name> ...]     (no names = every manifest)
//
// --check renders in memory and exits 1 if any committed README differs.
// Nothing in the README is typed by hand except what readme.vars.yaml holds:
//
//   package:   "@jpisgeek/netdata"          registry package name
//   purpose:   one sentence
//   example:   |                            a model YAML using PLACEHOLDERS only
//     ...
//   caveats:   optional markdown
//   security:  markdown — transport, what is sensitive, what is written
//
// (`types:` in older vars files is ignored — types are discovered from the
// manifest's model/vault files.)

import { parse } from "jsr:@std/yaml@1.0.5";
import { join, resolve, toFileUrl } from "jsr:@std/path@1.0.8";
import { z } from "npm:zod@4";

type Json = Record<string, unknown>;

const argv = [...Deno.args];
const check = argv.includes("--check");
let names = argv.filter((a) => !a.startsWith("--"));
if (names.length === 0) {
  // Every top-level directory holding a manifest.yaml is an extension.
  for await (const e of Deno.readDir(".")) {
    if (!e.isDirectory || e.name.startsWith(".")) continue;
    try {
      await Deno.stat(join(e.name, "manifest.yaml"));
      names.push(e.name);
    } catch { /* not an extension dir */ }
  }
  names.sort();
}

const template = await Deno.readTextFile("templates/README.md.tmpl");

function md(s: unknown): string {
  return String(s ?? "").replace(/\|/g, "\\|").replace(/\n+/g, " ").trim();
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
}

/** zod schema → JSON Schema (draft 2020-12), tolerant of non-zod input. */
function toJson(schema: unknown): Json | undefined {
  if (!schema || typeof schema !== "object") return undefined;
  try {
    // deno-lint-ignore no-explicit-any
    return z.toJSONSchema(schema as any, { io: "input" }) as Json;
  } catch {
    return undefined;
  }
}

function schemaType(p: Json): string {
  if (Array.isArray(p.enum)) return p.enum.map((e) => `\`${e}\``).join(" \\| ");
  if (Array.isArray(p.anyOf)) {
    return (p.anyOf as Json[]).map((x) => schemaType(x)).join(" \\| ");
  }
  const t = Array.isArray(p.type) ? p.type.join("\\|") : p.type;
  if (t === "array") {
    const items = (p.items ?? {}) as Json;
    return `array of ${items.type === "object" ? "object" : schemaType(items)}`;
  }
  return String(t ?? "any");
}

/** Flatten a JSON-schema object into rows: name, type, required, default, description. */
function schemaRows(schema: Json | undefined, prefix = ""): string[][] {
  if (!schema || schema.type !== "object") return [];
  const props = (schema.properties ?? {}) as Record<string, Json>;
  const required = new Set((schema.required as string[]) ?? []);
  const rows: string[][] = [];
  for (const [k, p] of Object.entries(props)) {
    const name = prefix + k;
    rows.push([
      `\`${name}\``,
      schemaType(p),
      // JSON Schema lists defaulted fields as required (the output always has
      // them); for a reader, "required" means "you must supply it".
      required.has(k) && p.default === undefined ? "yes" : "no",
      p.default === undefined ? "" : `\`${JSON.stringify(p.default)}\``,
      md(p.description),
    ]);
    if (p.type === "object") rows.push(...schemaRows(p, name + "."));
    if (
      p.type === "array" && (p.items as Json | undefined)?.type === "object"
    ) {
      rows.push(...schemaRows(p.items as Json, name + "[]."));
    }
  }
  return rows;
}

function table(header: string[], rows: string[][]): string {
  if (rows.length === 0) return "_none_";
  const line = (r: string[]) => `| ${r.join(" | ")} |`;
  return [line(header), line(header.map(() => "---")), ...rows.map(line)].join(
    "\n",
  );
}

const ARG_HEADER = ["argument", "type", "required", "default", "description"];

/** Render one `export const model = {...}` into template context. */
function renderModel(m: Json): Json {
  const methods = (m.methods ?? {}) as Record<string, Json>;
  const resources = (m.resources ?? {}) as Record<string, Json>;
  return {
    type: String(m.type ?? ""),
    kind: "model",
    description: "",
    arguments: table(ARG_HEADER, schemaRows(toJson(m.globalArguments))),
    methods: Object.keys(methods).length === 0
      ? "_none_"
      : Object.entries(methods).map(
        ([name, def]) => {
          const rows = schemaRows(toJson(def.arguments));
          const args = rows.length === 0
            ? "No arguments."
            : table(ARG_HEADER, rows);
          return `#### \`${name}\`\n\n${md(def.description)}\n\n${args}`;
        },
      ).join("\n\n"),
    outputs: table(
      ["resource", "lifetime", "fields", "description"],
      Object.entries(resources).map(([name, def]) => [
        `\`${name}\``,
        String(def.lifetime ?? ""),
        Object.keys(((toJson(def.schema) ?? {}).properties ?? {}) as Json).map((
          f,
        ) => `\`${f}\``).join(", "),
        md(def.description),
      ]),
    ),
  };
}

/** Render one `export const vault = {...}` into template context. */
function renderVault(v: Json): Json {
  return {
    type: String(v.type ?? ""),
    kind: "vault",
    description: md(v.description),
    arguments: table(
      ["config", "type", "required", "default", "description"],
      schemaRows(toJson(v.configSchema)),
    ),
    methods:
      "`get(key)` — resolve a secret · `put(key, value)` — store one · `list()` — item names (vault provider contract)",
    outputs: "_none — a vault writes no resources_",
  };
}

/**
 * Run the rendered Markdown through `deno fmt` so the committed README is
 * byte-stable under both CI's `deno fmt --check` and swamp's own format check
 * (README.md is an additionalFile). Rendering straight from the template
 * would otherwise drift on table alignment and wrapping.
 */
async function fmtMarkdown(text: string): Promise<string> {
  const p = new Deno.Command(Deno.execPath(), {
    args: ["fmt", "--ext", "md", "-"],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const w = p.stdin.getWriter();
  await w.write(new TextEncoder().encode(text));
  await w.close();
  const out = await p.output();
  if (!out.success) {
    throw new Error(
      `deno fmt failed on generated README: ${
        new TextDecoder().decode(out.stderr)
      }`,
    );
  }
  return new TextDecoder().decode(out.stdout);
}

/** Minimal mustache: {{var}}, {{#list}}…{{/list}} (array → repeat, truthy → once, falsy → skip). */
function render(tpl: string, ctx: Json): string {
  tpl = tpl.replace(
    /\{\{#(\w+)\}\}([\s\S]*?)\{\{\/\1\}\}/g,
    (_, key: string, body: string) => {
      const v = ctx[key];
      if (Array.isArray(v)) {
        return v.map((item) => render(body, { ...ctx, ...(item as Json) }))
          .join("");
      }
      return v ? render(body, ctx) : "";
    },
  );
  return tpl.replace(
    /\{\{(\w+)\}\}/g,
    (_, key: string) => String(ctx[key] ?? ""),
  );
}

let drift = 0;
for (const name of names) {
  const dir = name;
  const manifest = parse(
    await Deno.readTextFile(join(dir, "manifest.yaml")),
  ) as Json;
  const vars = parse(
    await Deno.readTextFile(join(dir, "readme.vars.yaml")),
  ) as Json;
  for (const req of ["package", "purpose", "example", "security"]) {
    if (vars[req] === undefined) {
      throw new Error(`${name}: readme.vars.yaml missing '${req}'`);
    }
  }
  const base =
    ((manifest.paths as Json | undefined)?.base ?? "typedDir") as string;
  const src = (kind: string, rel: string) =>
    base === "manifest" ? join(dir, rel) : join("extensions", kind, rel);

  const types: Json[] = [];
  for (const f of strings(manifest.models)) {
    const mod = await import(toFileUrl(resolve(src("models", f))).href);
    if (mod.model) types.push(renderModel(mod.model as Json));
    // Some files export several models under other names.
    for (const [k, v] of Object.entries(mod)) {
      if (
        k !== "model" && v && typeof v === "object" && (v as Json).type &&
        (v as Json).methods
      ) {
        types.push(renderModel(v as Json));
      }
    }
  }
  for (const f of strings(manifest.vaults)) {
    const mod = await import(toFileUrl(resolve(src("vaults", f))).href);
    if (mod.vault) types.push(renderVault(mod.vault as Json));
  }
  // In-code model.version must match the manifest; fail loudly if not.
  for (const f of strings(manifest.models)) {
    const mod = await import(toFileUrl(resolve(src("models", f))).href);
    const v = (mod.model as Json | undefined)?.version;
    if (v && String(v) !== String(manifest.version)) {
      throw new Error(
        `${name}: ${f} model.version ${v} != manifest version ${manifest.version}`,
      );
    }
  }

  const repository = String(manifest.repository ?? vars.repository ?? "");
  // Repo root for links to repo-root files (SECURITY.md): strip the
  // /tree/main/<dir> suffix a per-extension `repository:` carries, else a link
  // like `${repository}/blob/main/SECURITY.md` 404s (tree/…/blob/… is invalid).
  const repoRoot = repository.replace(/\/tree\/[^/]+\/.*$/, "");
  const ctx: Json = {
    package: vars.package,
    purpose: String(vars.purpose).trim(),
    version: manifest.version ?? "",
    repository,
    repoRoot,
    types,
    example: String(vars.example).trimEnd(),
    caveats: vars.caveats ? String(vars.caveats).trim() : "",
    security: String(vars.security).trim(),
  };
  const out = await fmtMarkdown(
    render(template, ctx).replace(/\n{3,}/g, "\n\n"),
  );
  const target = join(dir, "README.md");
  let current = "";
  try {
    current = await Deno.readTextFile(target);
  } catch { /* new */ }
  if (check) {
    if (current !== out) {
      console.error(
        `DRIFT  ${target} differs from generated output — run scripts/gen-readme.ts ${name}`,
      );
      drift++;
    } else {
      console.log(`ok     ${target}`);
    }
  } else {
    await Deno.writeTextFile(target, out);
    console.log(`wrote  ${target}`);
  }
}

// ---- root README: the extensions table is generated too ----------------
// Always built from EVERY extension dir, not just the `names` passed for
// README regeneration — otherwise `gen-readme.ts truenas` would rewrite the
// root table with a single row.
const allNames: string[] = [];
for await (const e of Deno.readDir(".")) {
  if (!e.isDirectory || e.name.startsWith(".")) continue;
  try {
    await Deno.stat(join(e.name, "manifest.yaml"));
    allNames.push(e.name);
  } catch { /* not an extension dir */ }
}
allNames.sort();
const rows: string[] = [];
for (const name of allNames) {
  const m = parse(await Deno.readTextFile(join(name, "manifest.yaml"))) as Json;
  const desc = String(m.description ?? "").replace(/\s+/g, " ").trim();
  const first = desc.split(/(?<=\.)\s/)[0] ?? desc;
  rows.push(
    `| \`${m.name}\` | \`${m.version}\` | [\`${name}/\`](${name}/) | ${first} |`,
  );
}
const tableMd = [
  "| Extension | Version | Source | What it is |",
  "| --- | --- | --- | --- |",
  ...rows,
].join("\n");
const rootPath = "README.md";
const root = await Deno.readTextFile(rootPath);
const start = "<!-- extensions:start -->", end = "<!-- extensions:end -->";
const a = root.indexOf(start), b = root.indexOf(end);
if (a === -1 || b === -1) {
  console.error(`README.md is missing the ${start}/${end} markers`);
  Deno.exit(1);
}
const stamped = await fmtMarkdown(
  root.slice(0, a + start.length) + "\n" + tableMd + "\n" + root.slice(b),
);
if (check) {
  if (stamped !== root) {
    console.error(
      "DRIFT  README.md extensions table differs — run scripts/gen-readme.ts",
    );
    drift++;
  } else console.log("ok     README.md (extensions table)");
} else {
  await Deno.writeTextFile(rootPath, stamped);
  console.log("wrote  README.md (extensions table)");
}
if (check && drift > 0) Deno.exit(1);
