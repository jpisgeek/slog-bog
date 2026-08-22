#!/usr/bin/env -S deno run --allow-read --allow-write --allow-run --allow-env
// gen-readme.ts — renders extensions/manifests/<name>/README.md from:
//   templates/README.md.tmpl                      the one template
//   extensions/manifests/<name>/readme.vars.yaml  the only hand-written input
//   the extension source, via `swamp model type describe <type> --json`
//   extensions/manifests/<name>/manifest.yaml     version, repository
//
// Usage:
//   scripts/gen-readme.ts [--check] [<name> ...]     (no names = every manifest)
//
// --check renders in memory and exits 1 if any committed README differs.
// Nothing in the README is typed by hand except what readme.vars.yaml holds:
//
//   package:   "@jpisgeek/netdata"          registry package name
//   types:     ["@jpisgeek/netdata"]        model types this package provides
//   purpose:   one sentence
//   example:   |                            a model YAML using PLACEHOLDERS only
//     ...
//   caveats:   optional markdown
//   security:  markdown — transport, what is sensitive, what is written
//
// Requires the swamp CLI (the repo must be a swamp repo: `swamp repo init`)
// and deno. Runs locally and inside scripts/publish.sh, not in CI.

import { parse } from "jsr:@std/yaml@1.0.5";
import { join } from "jsr:@std/path@1.0.8";

type Json = Record<string, unknown>;

const argv = [...Deno.args];
const check = argv.includes("--check");
let names = argv.filter((a) => !a.startsWith("--"));
if (names.length === 0) {
  for await (const e of Deno.readDir("extensions/manifests")) {
    if (e.isDirectory) names.push(e.name);
  }
  names.sort();
}

const template = await Deno.readTextFile("templates/README.md.tmpl");

async function sh(cmd: string[]): Promise<string> {
  const swampBin = Deno.env.get("SWAMP_BIN") ?? "swamp";
  const p = new Deno.Command(cmd[0] === "swamp" ? swampBin : cmd[0], {
    args: cmd.slice(1),
    stdout: "piped",
    stderr: "piped",
    env: { ...Deno.env.toObject(), NO_COLOR: "1" },
  });
  const out = await p.output();
  if (!out.success) {
    throw new Error(
      `${cmd.join(" ")} failed: ${new TextDecoder().decode(out.stderr)}`,
    );
  }
  return new TextDecoder().decode(out.stdout);
}

function md(s: unknown): string {
  return String(s ?? "").replace(/\|/g, "\\|").replace(/\n+/g, " ").trim();
}

function schemaType(p: Json): string {
  if (Array.isArray(p.enum)) return p.enum.map((e) => `\`${e}\``).join(" \\| ");
  const t = p.type;
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
      required.has(k) ? "yes" : "no",
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

function renderType(d: Json): Json {
  const methods = (d.methods as Json[] | undefined) ?? [];
  const outputs = (d.dataOutputSpecs as Json[] | undefined) ?? [];
  return {
    type: (d.type as Json)?.normalized ?? "",
    description: md(d.description) || "",
    arguments: table(
      ["argument", "type", "required", "default", "description"],
      schemaRows(d.globalArguments as Json),
    ),
    methods: methods.length === 0 ? "_none_" : methods.map((m) => {
      const rows = schemaRows(m.arguments as Json);
      const args = rows.length === 0 ? "No arguments." : table(
        ["argument", "type", "required", "default", "description"],
        rows,
      );
      return `#### \`${m.name}\`\n\n${md(m.description)}\n\n${args}`;
    }).join("\n\n"),
    outputs: table(
      ["resource", "kind", "fields", "description"],
      outputs.map((o) => [
        `\`${o.specName}\``,
        String(o.kind ?? ""),
        Object.keys(((o.schema as Json)?.properties ?? {}) as Json).map((f) =>
          `\`${f}\``
        ).join(", "),
        md(o.description),
      ]),
    ),
  };
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
  const dir = join("extensions/manifests", name);
  const manifest = parse(
    await Deno.readTextFile(join(dir, "manifest.yaml")),
  ) as Json;
  const vars = parse(
    await Deno.readTextFile(join(dir, "readme.vars.yaml")),
  ) as Json;
  for (const req of ["package", "types", "purpose", "example", "security"]) {
    if (vars[req] === undefined) {
      throw new Error(`${name}: readme.vars.yaml missing '${req}'`);
    }
  }
  const types: Json[] = [];
  for (const t of vars.types as string[]) {
    const raw = await sh(["swamp", "model", "type", "describe", t, "--json"]);
    types.push(renderType(JSON.parse(raw) as Json));
  }
  const ctx: Json = {
    package: vars.package,
    purpose: String(vars.purpose).trim(),
    version: manifest.version ?? "",
    repository: manifest.repository ?? vars.repository ?? "",
    types,
    example: String(vars.example).trimEnd(),
    caveats: vars.caveats ? String(vars.caveats).trim() : "",
    security: String(vars.security).trim(),
  };
  const out = render(template, ctx).replace(/\n{3,}/g, "\n\n");
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
if (check && drift > 0) Deno.exit(1);
