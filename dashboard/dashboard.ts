/** Provider-neutral, network-free dashboard bundle renderer. */
import { z } from "npm:zod@4";
// BEGIN INLINED DASHBOARD CONTRACT V1
/** Current bundle schema version emitted by v1 producers. */
export const DASHBOARD_BUNDLE_VERSION = "1.0.0" as const;

/** Major schema version understood by this implementation. */
export const DASHBOARD_BUNDLE_MAJOR = 1 as const;

/** Operational state. These values are deliberately not boolean. */
export const DashboardStateSchema = z.enum([
  "healthy",
  "degraded",
  "critical",
  "unknown",
  "stale",
  "partial",
  "unsupported",
  "unauthorized",
]);

/** How strongly a section contributes to the bundle's overall state. */
export const SectionImpactSchema = z.enum([
  "required",
  "optional",
  "informational",
]);

/** Severity of an actionable or explanatory exception. */
export const SeveritySchema = z.enum(["critical", "warning", "info"]);

/** Confidence in a reported value, kept separate from health. */
export const ConfidenceSchema = z.enum([
  "exact",
  "estimated",
  "inferred",
  "unknown",
]);

/** Sensitivity class used by operators when deciding what may be published. */
export const SensitivityClassSchema = z.enum([
  "public",
  "operational",
  "sensitive",
]);

/** Units with stable cross-provider meaning, plus an explicit custom escape. */
export const MetricUnitSchema = z.union([
  z.enum([
    "count",
    "percent",
    "bytes",
    "seconds",
    "milliseconds",
    "tokens",
    "tokens-per-second",
    "requests",
    "currency",
    "watts",
    "celsius",
    "ratio",
    "boolean",
  ]),
  z.string().regex(
    /^custom:[a-z][a-z0-9._-]*$/,
    "custom units must use custom:<lowercase-name>",
  ),
]);

const IdentifierSchema = z.string().regex(
  /^[a-z][a-z0-9._:-]*$/,
  "identifier must start with a lowercase letter and use lowercase letters, digits, dot, underscore, colon, or hyphen",
);

const SemVerSchema = z.string().regex(
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/,
  "schemaVersion must be semantic version major.minor.patch",
);

/** Origin of the normalized bundle and the exact Swamp data that supports it. */
export const ProducerSchema = z.object({
  extension: z.string().min(1),
  extensionVersion: z.string().min(1),
  modelType: z.string().min(1),
  modelName: z.string().min(1),
  modelId: z.string().min(1).optional(),
  dataName: z.string().min(1),
  dataVersion: z.number().int().positive().optional(),
  reportName: z.string().min(1).optional(),
}).passthrough();

/** Time span and observation scope covered by a section. */
export const CoverageSchema = z.object({
  kind: z.enum([
    "exact",
    "observed-traffic",
    "sample",
    "estimated",
    "unknown",
  ]),
  start: z.iso.datetime().optional(),
  end: z.iso.datetime().optional(),
  scope: z.string().min(1),
  notes: z.string().min(1).optional(),
}).superRefine((coverage, ctx) => {
  if (
    coverage.start && coverage.end &&
    Date.parse(coverage.start) > Date.parse(coverage.end)
  ) {
    ctx.addIssue({
      code: "custom",
      message: "coverage start must not be after end",
      path: ["start"],
    });
  }
}).passthrough();

/** Freshness evidence. Unknown freshness is represented directly. */
export const FreshnessSchema = z.object({
  state: z.enum(["fresh", "stale", "unknown"]),
  observedAt: z.iso.datetime().optional(),
  maxAgeSeconds: z.number().nonnegative().finite().optional(),
  reason: z.string().min(1).optional(),
}).superRefine((freshness, ctx) => {
  if (freshness.state === "fresh" && !freshness.observedAt) {
    ctx.addIssue({
      code: "custom",
      message: "fresh observations require observedAt",
      path: ["observedAt"],
    });
  }
  if (freshness.state !== "fresh" && !freshness.reason) {
    ctx.addIssue({
      code: "custom",
      message: "stale or unknown freshness requires a reason",
      path: ["reason"],
    });
  }
}).passthrough();

const ExactCompletenessSchema = z.object({
  state: z.literal("exact"),
  observed: z.number().int().nonnegative().optional(),
  expected: z.number().int().nonnegative().optional(),
  rejected: z.literal(0).optional(),
}).passthrough();

const PartialCompletenessSchema = z.object({
  state: z.literal("partial"),
  observed: z.number().int().nonnegative().optional(),
  expected: z.number().int().nonnegative().optional(),
  rejected: z.number().int().nonnegative().optional(),
  reason: z.string().min(1),
}).passthrough();

const UnknownCompletenessSchema = z.object({
  state: z.literal("unknown"),
  reason: z.string().min(1),
}).passthrough();

/** Whether the producer knows it observed the full intended population. */
export const CompletenessSchema = z.discriminatedUnion("state", [
  ExactCompletenessSchema,
  PartialCompletenessSchema,
  UnknownCompletenessSchema,
]);

/** Publication sensitivity and any redaction applied before persistence. */
export const SensitivitySchema = z.object({
  classification: SensitivityClassSchema,
  fields: z.array(z.string().min(1)).default([]),
  redacted: z.boolean().default(false),
  note: z.string().min(1).optional(),
}).passthrough();

/** A reference back to supporting Swamp data or an operator-safe URL. */
export const EvidenceReferenceSchema = z.object({
  kind: z.enum(["swamp-data", "swamp-report", "url"]),
  label: z.string().min(1),
  modelName: z.string().min(1).optional(),
  dataName: z.string().min(1).optional(),
  dataVersion: z.number().int().positive().optional(),
  url: z.string().url().optional(),
}).superRefine((reference, ctx) => {
  if (reference.kind === "url" && !reference.url) {
    ctx.addIssue({
      code: "custom",
      message: "url references require url",
      path: ["url"],
    });
  }
  if (
    reference.kind !== "url" &&
    (!reference.modelName || !reference.dataName)
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Swamp references require modelName and dataName",
      path: ["dataName"],
    });
  }
}).passthrough();

/** Optional threshold or allocation attached to an observed metric. */
export const MetricLimitSchema = z.object({
  value: z.number().finite(),
  kind: z.enum(["warning", "critical", "allocation", "provider-limit"]),
  period: z.string().min(1).optional(),
  authoritative: z.boolean(),
}).passthrough();

const MetricCommonSchema = z.object({
  id: IdentifierSchema,
  label: z.string().min(1),
  unit: MetricUnitSchema,
  confidence: ConfidenceSchema,
  limit: MetricLimitSchema.optional(),
  sensitivity: SensitivityClassSchema.default("operational"),
});

const ObservedMetricSchema = MetricCommonSchema.extend({
  availability: z.literal("observed"),
  value: z.number().finite(),
}).passthrough();

const UnavailableMetricSchema = MetricCommonSchema.extend({
  availability: z.enum(["unknown", "unsupported", "unauthorized"]),
  value: z.never().optional(),
  reason: z.string().min(1),
}).passthrough();

/** Metric whose availability cannot be mistaken for its numeric value. */
export const MetricSchema = z.discriminatedUnion("availability", [
  ObservedMetricSchema,
  UnavailableMetricSchema,
]);

/** Scalar inventory or capability fact. */
export const FactSchema = z.object({
  id: IdentifierSchema,
  label: z.string().min(1),
  value: z.union([z.string(), z.number().finite(), z.boolean(), z.null()]),
  confidence: ConfidenceSchema,
  sensitivity: SensitivityClassSchema.default("operational"),
}).passthrough();

/** Actionable or explanatory condition retained even when suppressed. */
export const ExceptionSchema = z.object({
  id: z.string().min(1),
  severity: SeveritySchema,
  subject: z.string().min(1),
  headline: z.string().min(1),
  detail: z.string(),
  source: z.string().min(1),
  suppressed: z.boolean().default(false),
  suppressReason: z.string().default(""),
  sensitivity: SensitivityClassSchema.default("operational"),
}).superRefine((exception, ctx) => {
  if (exception.suppressed && !exception.suppressReason) {
    ctx.addIssue({
      code: "custom",
      message: "suppressed exceptions require suppressReason",
      path: ["suppressReason"],
    });
  }
}).passthrough();

/** One independently normalized dashboard domain. */
export const DashboardSectionSchema = z.object({
  id: IdentifierSchema,
  title: z.string().min(1),
  state: DashboardStateSchema,
  impact: SectionImpactSchema,
  summary: z.string().min(1),
  coverage: CoverageSchema,
  freshness: FreshnessSchema,
  completeness: CompletenessSchema,
  metrics: z.array(MetricSchema).default([]),
  facts: z.array(FactSchema).default([]),
  exceptions: z.array(ExceptionSchema).default([]),
  references: z.array(EvidenceReferenceSchema).default([]),
  sensitivity: SensitivitySchema,
}).passthrough();

/** Complete v1 bundle. Unknown additive fields are retained for v1 evolution. */
export const DashboardBundleV1Schema = z.object({
  schemaVersion: SemVerSchema,
  id: IdentifierSchema,
  title: z.string().min(1),
  generatedAt: z.iso.datetime(),
  producer: ProducerSchema,
  state: DashboardStateSchema,
  sections: z.array(DashboardSectionSchema).min(1),
  exceptions: z.array(ExceptionSchema).default([]),
  sensitivity: SensitivitySchema,
  extensions: z.record(
    z.string().regex(
      /^[a-z0-9][a-z0-9.-]*\/[a-z0-9][a-z0-9._-]*$/,
      "extension keys must be namespaced as owner/name",
    ),
    z.json(),
  ).default({}),
}).passthrough();

/** Parsed v1 dashboard state. */
export type DashboardState = z.infer<typeof DashboardStateSchema>;

/** Parsed v1 dashboard bundle. */
export type DashboardBundleV1 = z.infer<typeof DashboardBundleV1Schema>;

const STATE_RANK: Record<DashboardState, number> = {
  healthy: 0,
  unsupported: 100,
  unknown: 200,
  degraded: 300,
  stale: 400,
  partial: 500,
  unauthorized: 600,
  critical: 700,
};

/**
 * Derive overall state from required sections and unsuppressed exceptions.
 *
 * Optional and informational sections stay visible but cannot make a required
 * deployment look unhealthy. With no required section, coverage is unknown.
 */
export function deriveOverallState(
  sections: ReadonlyArray<z.infer<typeof DashboardSectionSchema>>,
  bundleExceptions: ReadonlyArray<z.infer<typeof ExceptionSchema>> = [],
): DashboardState {
  const required = sections.filter((section) => section.impact === "required");
  let state: DashboardState = required.length === 0 ? "unknown" : "healthy";

  for (const section of required) {
    if (STATE_RANK[section.state] > STATE_RANK[state]) state = section.state;
  }

  const exceptions = [
    ...bundleExceptions,
    ...sections.flatMap((section) => section.exceptions),
  ].filter((exception) => !exception.suppressed);

  if (exceptions.some((exception) => exception.severity === "critical")) {
    return "critical";
  }
  if (
    state === "healthy" &&
    exceptions.some((exception) => exception.severity === "warning")
  ) {
    return "degraded";
  }
  return state;
}

/** Error raised before field parsing when a bundle major version is unknown. */
export class UnsupportedBundleVersionError extends Error {
  /** Version that the caller attempted to parse. */
  readonly version: string;

  constructor(version: string) {
    super(
      `unsupported dashboard bundle major version ${version}; supported major is ${DASHBOARD_BUNDLE_MAJOR}`,
    );
    this.name = "UnsupportedBundleVersionError";
    this.version = version;
  }
}

/**
 * Parse a v1 bundle, reject unsupported major versions, and verify state.
 * Unknown additive v1 fields survive parsing through passthrough schemas.
 */
export function parseDashboardBundle(input: unknown): DashboardBundleV1 {
  const envelope = z.object({ schemaVersion: SemVerSchema }).passthrough()
    .parse(
      input,
    );
  const major = Number(envelope.schemaVersion.split(".")[0]);
  if (major !== DASHBOARD_BUNDLE_MAJOR) {
    throw new UnsupportedBundleVersionError(envelope.schemaVersion);
  }

  const bundle = DashboardBundleV1Schema.parse(input);
  const derived = deriveOverallState(bundle.sections, bundle.exceptions);
  if (bundle.state !== derived) {
    throw new Error(
      `bundle state ${bundle.state} does not match derived state ${derived}`,
    );
  }
  return bundle;
}
// END INLINED DASHBOARD CONTRACT V1

const SuppressionSchema = z.object({
  id: z.string().min(1).describe("Exact normalized exception id"),
  reason: z.string().min(1).describe("Why this condition is expected"),
});
const GlobalArgsSchema = z.object({
  title: z.string().default("Operations"),
  bundles: z.array(z.unknown()).default([]).describe(
    "Explicit bundle JSON, normally supplied by CEL data.latest(...).attributes",
  ),
  outputPath: z.string().default("./dashboard/index.html").describe(
    "Where the self-contained HTML file is written",
  ),
  suppress: z.array(SuppressionSchema).default([]).describe(
    "Known conditions retained visibly as expected exceptions",
  ),
});
const RenderArgsSchema = z.object({});
const RenderedExceptionSchema = z.object({
  id: z.string(),
  severity: z.enum(["critical", "warning", "info"]),
  subject: z.string(),
  headline: z.string(),
  detail: z.string(),
  source: z.string(),
  suppressed: z.boolean(),
  suppressReason: z.string(),
  truncated: z.boolean(),
});
const RenderSchema = z.object({
  outputPath: z.string(),
  bytes: z.number().int().nonnegative(),
  exceptions: z.number().int().nonnegative(),
  suppressed: z.number().int().nonnegative(),
  critical: z.number().int().nonnegative(),
  warning: z.number().int().nonnegative(),
  bundlesReceived: z.number().int().nonnegative(),
  bundlesValid: z.number().int().nonnegative(),
  bundleIds: z.array(z.string()),
  coverageStates: z.record(z.string(), z.string()),
  exceptionResources: z.array(z.string()),
  renderedAt: z.iso.datetime(),
});

interface Exc {
  id: string;
  severity: "critical" | "warning" | "info";
  subject: string;
  headline: string;
  detail: string;
  source: string;
  suppressed: boolean;
  suppressReason: string;
  truncated: boolean;
}

const SEV_RANK = { critical: 0, warning: 1, info: 2 } as const;
const COVERAGE_STATES = new Set([
  "unknown",
  "stale",
  "partial",
  "unsupported",
  "unauthorized",
]);

function esc(value: unknown): string {
  return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function fnv1a(value: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}
function resourceName(id: string): string {
  const slug = id.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(
    /^-+|-+$/g,
    "",
  ).slice(0, 48) || "condition";
  return `exception-${slug}-${fnv1a(id)}`;
}
function makeExc(input: Omit<Exc, "truncated">): Exc {
  const headCut = input.headline.length > 160;
  const detailCut = input.detail.length > 240;
  return {
    ...input,
    headline: input.headline.slice(0, 160),
    detail: input.detail.slice(0, 240),
    truncated: headCut || detailCut,
  };
}
function stateSeverity(state: string): Exc["severity"] {
  return state === "unauthorized"
    ? "critical"
    : state === "partial" || state === "stale"
    ? "warning"
    : "info";
}

function parseInputs(inputs: unknown[]) {
  const bundles: DashboardBundleV1[] = [];
  const issues: Exc[] = [];
  if (inputs.length === 0) {
    issues.push(makeExc({
      id: "coverage:no-bundles",
      severity: "warning",
      subject: "Dashboard coverage",
      headline: "No dashboard bundles were provided",
      detail: "Supply explicit report JSON through the bundles argument.",
      source: "renderer",
      suppressed: false,
      suppressReason: "",
    }));
  }
  for (const [index, input] of inputs.entries()) {
    try {
      bundles.push(parseDashboardBundle(input));
    } catch (error) {
      const unsupported = error instanceof UnsupportedBundleVersionError;
      issues.push(makeExc({
        id: `coverage:bundle-${index}:${
          unsupported ? "unsupported" : "invalid"
        }`,
        severity: unsupported ? "warning" : "critical",
        subject: `Bundle ${index + 1}`,
        headline: unsupported
          ? "Unsupported dashboard bundle version"
          : "Invalid dashboard bundle",
        detail: unsupported
          ? `This renderer does not support bundle version ${error.version}.`
          : "The value failed bundle-v1 validation; inspect its normalization report.",
        source: "renderer",
        suppressed: false,
        suppressReason: "",
      }));
    }
  }
  return { bundles, issues };
}

function collectExceptions(
  bundles: DashboardBundleV1[],
  issues: Exc[],
  suppressions: Array<{ id: string; reason: string }>,
): Exc[] {
  const out = [...issues];
  const ids = new Set(out.map((e) => e.id));
  for (const bundle of bundles) {
    const bundleExceptions = [
      ...bundle.exceptions,
      ...bundle.sections.flatMap((section) => section.exceptions),
    ];
    for (const e of bundleExceptions) {
      if (ids.has(e.id)) continue;
      out.push(makeExc({
        id: e.id,
        severity: e.severity,
        subject: e.subject,
        headline: e.headline,
        detail: e.detail,
        source: e.source,
        suppressed: e.suppressed,
        suppressReason: e.suppressReason,
      }));
      ids.add(e.id);
    }
    if (
      (bundle.state === "critical" || bundle.state === "degraded") &&
      !bundleExceptions.some((e) => !e.suppressed)
    ) {
      const id = `status:${bundle.id}:${bundle.state}`;
      out.push(makeExc({
        id,
        severity: bundle.state === "critical" ? "critical" : "warning",
        subject: bundle.title,
        headline: `Operational state is ${bundle.state}`,
        detail:
          "The bundle reported a non-healthy state without a separate exception.",
        source: bundle.producer.extension,
        suppressed: false,
        suppressReason: "",
      }));
      ids.add(id);
    }
    const states = [
      { id: bundle.id, title: bundle.title, state: bundle.state, summary: "" },
      ...bundle.sections.map((s) => ({
        id: `${bundle.id}:${s.id}`,
        title: s.title,
        state: s.state,
        summary: s.summary,
      })),
    ];
    for (const item of states) {
      if (!COVERAGE_STATES.has(item.state)) continue;
      const id = `coverage:${item.id}:${item.state}`;
      if (ids.has(id)) continue;
      out.push(makeExc({
        id,
        severity: stateSeverity(item.state),
        subject: item.title,
        headline: `Coverage is ${item.state}`,
        detail: item.summary ||
          "The normalized bundle reports incomplete coverage.",
        source: bundle.producer.extension,
        suppressed: false,
        suppressReason: "",
      }));
      ids.add(id);
    }
  }
  const configured = new Map(suppressions.map((s) => [s.id, s.reason]));
  for (const e of out) {
    const reason = configured.get(e.id);
    if (reason) {
      e.suppressed = true;
      e.suppressReason = reason;
    }
  }
  return out.sort((a, b) =>
    SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.id.localeCompare(b.id)
  );
}

function ago(iso: string): string {
  const seconds = Math.max(
    0,
    Math.floor((Date.now() - Date.parse(iso)) / 1000),
  );
  if (seconds < 90) return `${seconds}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function renderHtml(d: {
  title: string;
  now: string;
  bundles: DashboardBundleV1[];
  exceptions: Exc[];
}): string {
  const active = d.exceptions.filter((e) => !e.suppressed);
  const expected = d.exceptions.filter((e) => e.suppressed);
  const allClear = active.length === 0 && d.bundles.length > 0 &&
    d.bundles.every((bundle) => bundle.state === "healthy");
  const excRow = (e: Exc, muted = false) => `
<li class="exc ${esc(e.severity)}${muted ? " muted" : ""}">
<span class="sev">${
    e.severity === "critical" ? "●" : e.severity === "warning" ? "▲" : "•"
  }</span>
<div class="body"><div class="head"><strong>${esc(e.subject)}</strong> ${
    esc(e.headline)
  }</div>
<div class="det">${esc(e.detail)}${
    muted && e.suppressReason
      ? ` · <em>expected: ${esc(e.suppressReason)}</em>`
      : ""
  }</div></div>
<span class="src">${esc(e.source)}</span></li>`;
  const details = d.bundles.flatMap((bundle) =>
    bundle.sections.map((section) => {
      const metrics = section.metrics.map((metric) => {
        const value = metric.availability === "observed"
          ? `${esc(metric.value)} ${esc(metric.unit)}`
          : `<em>${esc(metric.availability)}: ${esc(metric.reason)}</em>`;
        return `<tr><td>${esc(metric.label)}</td><td>${value}</td><td>${
          esc(metric.confidence)
        }</td></tr>`;
      }).join("");
      const facts = section.facts.map((fact) =>
        `<tr><td>${esc(fact.label)}</td><td>${esc(fact.value)}</td><td>${
          esc(fact.confidence)
        }</td></tr>`
      ).join("");
      return `<details><summary>${esc(section.title)} · ${
        esc(section.state)
      }</summary>
<p class="summary">${esc(section.summary)}</p><div class="coverage">Coverage: ${
        esc(section.coverage.kind)
      } · ${esc(section.coverage.scope)} · Freshness: ${
        esc(section.freshness.state)
      } · Completeness: ${esc(section.completeness.state)}</div>
${
        metrics
          ? `<table><thead><tr><th>Metric</th><th>Value</th><th>Confidence</th></tr></thead><tbody>${metrics}</tbody></table>`
          : ""
      }
${
        facts
          ? `<table><thead><tr><th>Fact</th><th>Value</th><th>Confidence</th></tr></thead><tbody>${facts}</tbody></table>`
          : ""
      }</details>`;
    })
  ).join("\n");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>${
    esc(d.title)
  }</title><style>
:root{--bg:#fbfbfa;--fg:#1a1a19;--dim:#6b6b68;--line:#e4e4e1;--card:#fff;--crit:#b4231f;--warn:#a4620a;--ok:#2f6b34}
@media(prefers-color-scheme:dark){:root{--bg:#131313;--fg:#e8e8e6;--dim:#969692;--line:#2a2a29;--card:#1b1b1a;--crit:#ef6d63;--warn:#d99a3e;--ok:#71b877}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:22px 16px 64px}
header{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:19px;margin:0}.ts,.summary,.coverage{color:var(--dim);font-size:12.5px}
.banner{border:1px solid var(--line);background:var(--card);border-radius:10px;padding:14px 16px;margin-bottom:18px}
.banner.clear{border-color:color-mix(in srgb,var(--ok) 40%,var(--line))}.banner h2{margin:0 0 2px;font-size:15px}
ul.excs{list-style:none;margin:12px 0 0;padding:0}.exc{display:flex;gap:11px;align-items:flex-start;padding:11px 12px;background:var(--card);border:1px solid var(--line);border-radius:8px}
.exc+.exc{margin-top:6px}.sev{font-size:12px}.critical .sev{color:var(--crit)}.warning .sev{color:var(--warn)}
.body{flex:1;min-width:0}.head{font-size:14px}.det{color:var(--dim);font-size:12.5px;overflow-wrap:anywhere}
.src{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}.muted{opacity:.62}
details{border-top:1px solid var(--line);margin-top:26px;padding-top:14px}summary{cursor:pointer;font-size:13px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
.coverage{margin:8px 0 12px;color:var(--warn)}table{width:100%;border-collapse:collapse;font-size:13px;display:block;overflow-x:auto}
th{text-align:left;color:var(--dim);font-size:11px;text-transform:uppercase;padding:6px 18px 6px 0;border-bottom:1px solid var(--line)}
td{padding:7px 18px 7px 0;border-bottom:1px solid var(--line)}footer{margin-top:34px;color:var(--dim);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
</style></head><body><div class="wrap"><header><h1>${
    esc(d.title)
  }</h1><div class="ts">rendered ${
    esc(ago(d.now))
  }</div></header><div class="banner${allClear ? " clear" : ""}"><h2>${
    allClear
      ? "Nothing needs you"
      : `${active.length} thing${active.length === 1 ? "" : "s"} need${
        active.length === 1 ? "s" : ""
      } you`
  }</h2><div class="summary">${d.bundles.length} validated bundle${
    d.bundles.length === 1 ? "" : "s"
  }</div>${
    active.length
      ? `<ul class="excs">${active.map((e) => excRow(e)).join("")}</ul>`
      : ""
  }</div>${
    expected.length
      ? `<details><summary>Expected · ${expected.length}</summary><ul class="excs">${
        expected.map((e) => excRow(e, true)).join("")
      }</ul></details>`
      : ""
  }${details}<footer>Generated from explicit dashboard bundle v1 inputs. No provider discovery or network access.</footer></div></body></html>`;
}

/** The provider-neutral @jpisgeek/dashboard model. */
export const model = {
  type: "@jpisgeek/dashboard",
  version: "2026.08.25.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    exception: {
      description:
        "One queryable normalized or coverage exception, including visible suppressions.",
      schema: RenderedExceptionSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    render: {
      description: "Outcome and coverage of the latest explicit bundle render.",
      schema: RenderSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },
  methods: {
    render: {
      description:
        "Validate explicit bundles and write a self-contained, exceptions-first HTML page.",
      arguments: RenderArgsSchema,
      // deno-lint-ignore no-explicit-any
      execute: async (_args: unknown, ctx: any) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const parsed = parseInputs(g.bundles);
        const exceptions = collectExceptions(
          parsed.bundles,
          parsed.issues,
          g.suppress,
        );
        const active = exceptions.filter((e) => !e.suppressed);
        const expected = exceptions.filter((e) => e.suppressed);
        const now = new Date().toISOString();
        const html = renderHtml({
          title: g.title,
          now,
          bundles: parsed.bundles,
          exceptions,
        });
        const slash = g.outputPath.lastIndexOf("/");
        if (slash > 0) {
          await Deno.mkdir(g.outputPath.slice(0, slash), { recursive: true });
        }
        await Deno.writeTextFile(g.outputPath, html);

        const prior = await ctx.readResource("render");
        const handles = [];
        const currentNames: string[] = [];
        for (const exception of exceptions) {
          const name = resourceName(exception.id);
          currentNames.push(name);
          handles.push(
            await ctx.writeResource("exception", name, exception, {
              tags: {
                severity: exception.severity,
                suppressed: String(exception.suppressed),
                source: exception.source,
              },
            }),
          );
        }
        const priorNames = Array.isArray(prior?.exceptionResources)
          ? prior.exceptionResources.filter((name: unknown): name is string =>
            typeof name === "string"
          )
          : [];
        for (const name of priorNames) {
          if (!currentNames.includes(name)) await ctx.deleteResource(name);
        }
        const result = {
          outputPath: g.outputPath,
          bytes: new TextEncoder().encode(html).length,
          exceptions: active.length,
          suppressed: expected.length,
          critical: active.filter((e) => e.severity === "critical").length,
          warning: active.filter((e) => e.severity === "warning").length,
          bundlesReceived: g.bundles.length,
          bundlesValid: parsed.bundles.length,
          bundleIds: parsed.bundles.map((bundle) => bundle.id),
          coverageStates: Object.fromEntries(
            parsed.bundles.map((bundle) => [bundle.id, bundle.state]),
          ),
          exceptionResources: currentNames,
          renderedAt: now,
        };
        handles.push(
          await ctx.writeResource("render", "render", result, {
            tags: {
              exceptions: String(active.length),
              bundlesValid: String(parsed.bundles.length),
            },
          }),
        );
        return { dataHandles: handles };
      },
    },
  },
};
