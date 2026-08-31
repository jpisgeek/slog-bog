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
  url: z.string().url().refine(
    (value) => new URL(value).protocol === "https:",
    "evidence URLs must use https",
  ).optional(),
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
    let sectionState = section.state;
    const evidenceStates: DashboardState[] = [
      section.freshness.state === "stale"
        ? "stale"
        : section.freshness.state === "unknown"
        ? "unknown"
        : "healthy",
      section.completeness.state === "partial"
        ? "partial"
        : section.completeness.state === "unknown"
        ? "unknown"
        : "healthy",
      section.coverage.kind === "unknown" ? "unknown" : "healthy",
    ];
    for (const evidenceState of evidenceStates) {
      if (STATE_RANK[evidenceState] > STATE_RANK[sectionState]) {
        sectionState = evidenceState;
      }
    }
    if (STATE_RANK[sectionState] > STATE_RANK[state]) state = sectionState;
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
  sensitivity: SensitivityClassSchema,
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
  sensitivity: z.infer<typeof SensitivityClassSchema>;
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

/**
 * Output bounds.
 *
 * The inlined contract deliberately carries no `.max()` on any string or array:
 * it describes what a producer may legitimately mean, not what one renderer is
 * willing to paint. Bounding therefore belongs here. Previously only `headline`
 * and `detail` were cut, so a bundle could carry a 50 MB `subject` or `source`
 * straight into the published HTML file and into every exception resource, and
 * nothing limited how many bundles, sections, metrics, facts, or exceptions one
 * render could emit. Every cut below is reported rather than silent.
 */
const MAX_ID = 256;
const MAX_SUBJECT = 200;
const MAX_SOURCE = 120;
const MAX_HEADLINE = 160;
const MAX_DETAIL = 240;
const MAX_BUNDLES = 64;
const MAX_SECTIONS = 64;
const MAX_TABLE_ROWS = 200;
const MAX_EXCEPTIONS = 200;

type DashboardSection = z.infer<typeof DashboardSectionSchema>;

/**
 * Worst state a section's own evidence implies, ignoring its declared state.
 *
 * `deriveOverallState` escalates over impact:"required" sections only, and that
 * is correct: an optional section must not make a required deployment look
 * unhealthy. But the coverage pass in `collectExceptions` used to read each
 * section's *declared* state, which let an optional or informational section
 * say state:"healthy" while its own freshness said stale and its completeness
 * said partial. That section contributed nothing to bundle.state, then matched
 * bundle.state exactly and so was filtered out of the coverage pass entirely —
 * a six-day feed outage rendered as the word "stale" inside a collapsed
 * <details> under a green "Nothing needs you" banner. Impact governs whether a
 * section escalates the *bundle*; it must never govern whether the section's
 * own evidence is allowed to be silent.
 */
function sectionEvidenceState(section: DashboardSection): DashboardState {
  let state: DashboardState = section.state;
  const evidenceStates: DashboardState[] = [
    section.freshness.state === "stale"
      ? "stale"
      : section.freshness.state === "unknown"
      ? "unknown"
      : "healthy",
    section.completeness.state === "partial"
      ? "partial"
      : section.completeness.state === "unknown"
      ? "unknown"
      : "healthy",
    section.coverage.kind === "unknown" ? "unknown" : "healthy",
  ];
  for (const evidenceState of evidenceStates) {
    if (STATE_RANK[evidenceState] > STATE_RANK[state]) state = evidenceState;
  }
  return state;
}

/**
 * The producer's own explanation of why a section is not fresh/exact.
 *
 * The contract *requires* `freshness.reason` whenever state is not "fresh" and
 * `completeness.reason` whenever state is not "exact", precisely so the page
 * can say what happened. Both were validated and then dropped: the coverage
 * line printed the bare state word and the synthetic coverage exception used
 * the section's generic `summary`, so "collector last succeeded 2026-08-24; 3
 * retries timed out against 192.0.2.10" became "Freshness: stale".
 */
function evidenceReasons(section: DashboardSection): string[] {
  const reasons: string[] = [];
  if (section.freshness.state !== "fresh" && section.freshness.reason) {
    reasons.push(`freshness: ${section.freshness.reason}`);
  }
  if (section.completeness.state !== "exact" && section.completeness.reason) {
    reasons.push(`completeness: ${section.completeness.reason}`);
  }
  if (section.coverage.notes) {
    reasons.push(`coverage: ${section.coverage.notes}`);
  }
  return reasons;
}

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
function tupleId(...parts: string[]): string {
  return parts.map((part) => `${part.length}:${part}`).join("");
}
function syntheticId(family: string, ...parts: string[]): string {
  return tupleId("renderer", family, ...parts);
}
function scopedExceptionId(bundleId: string, exceptionId: string): string {
  return tupleId(bundleId, exceptionId);
}
/**
 * Bound an exception id without letting two distinct ids become one.
 *
 * The id is identity, not prose: the dedup set, the suppression config, and
 * `resourceName` all key on it, so a bare slice would let two long producer ids
 * collide into a single row and a single suppression. The cut form therefore
 * carries a hash of the original. Suppression stays workable because operators
 * copy the id out of the emitted exception resource, which is this same value.
 */
function capId(value: string): string {
  if (value.length <= MAX_ID) return value;
  return `${value.slice(0, MAX_ID - 9)}~${fnv1a(value)}`;
}
function makeExc(
  input:
    & Omit<Exc, "truncated" | "sensitivity">
    & Partial<Pick<Exc, "sensitivity">>,
): Exc {
  // Previously only headline and detail were cut and `truncated` was reported
  // from those two alone, so id, subject, and source rode the `...input` spread
  // through at whatever length the producer chose — into the published HTML,
  // into the exception resource, and into its `source` tag — while the record
  // still claimed truncated:false. All five free-text fields are bounded now
  // and `truncated` is true if any of them was cut.
  const id = capId(input.id);
  const subject = input.subject.slice(0, MAX_SUBJECT);
  const source = input.source.slice(0, MAX_SOURCE);
  const headline = input.headline.slice(0, MAX_HEADLINE);
  const detail = input.detail.slice(0, MAX_DETAIL);
  return {
    ...input,
    sensitivity: input.sensitivity ?? "operational",
    id,
    subject,
    source,
    headline,
    detail,
    truncated: id !== input.id || subject !== input.subject ||
      source !== input.source || headline !== input.headline ||
      detail !== input.detail,
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
  const bundleIds = new Set<string>();
  if (inputs.length === 0) {
    issues.push(makeExc({
      id: syntheticId("input", "no-bundles"),
      severity: "warning",
      subject: "Dashboard coverage",
      headline: "No dashboard bundles were provided",
      detail: "Supply explicit report JSON through the bundles argument.",
      source: "renderer",
      suppressed: false,
      suppressReason: "",
    }));
  }
  // Nothing bounded the bundles argument, so one CEL expression fanning out
  // over a whole datastore could drive an unbounded number of parses, HTML
  // sections, and exception resources. Render a bounded prefix and say plainly
  // that the rest was dropped rather than silently rendering everything.
  const accepted = inputs.slice(0, MAX_BUNDLES);
  if (inputs.length > accepted.length) {
    issues.push(makeExc({
      id: syntheticId("input", "too-many-bundles"),
      severity: "warning",
      subject: "Dashboard coverage",
      headline: `Only the first ${MAX_BUNDLES} bundles were rendered`,
      detail: `${inputs.length} bundles were supplied; ${
        inputs.length - accepted.length
      } were not read and are not represented anywhere on this page.`,
      source: "renderer",
      suppressed: false,
      suppressReason: "",
    }));
  }
  for (const [index, input] of accepted.entries()) {
    try {
      const bundle = parseDashboardBundle(input);
      if (bundleIds.has(bundle.id)) {
        issues.push(makeExc({
          id: syntheticId(
            "input",
            "duplicate-bundle",
            String(index),
            bundle.id,
          ),
          severity: "critical",
          subject: bundle.title,
          headline: "Duplicate dashboard bundle ID",
          detail: "Every input bundle must have a unique ID.",
          source: "renderer",
          suppressed: false,
          suppressReason: "",
        }));
        continue;
      }
      bundleIds.add(bundle.id);
      bundles.push(bundle);
    } catch (error) {
      const unsupported = error instanceof UnsupportedBundleVersionError;
      issues.push(makeExc({
        id: syntheticId(
          "input",
          "invalid-bundle",
          String(index),
          unsupported ? "unsupported" : "invalid",
        ),
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
      const id = scopedExceptionId(bundle.id, e.id);
      if (ids.has(id)) continue;
      out.push(makeExc({
        id,
        severity: e.severity,
        subject: e.subject,
        headline: e.headline,
        detail: e.detail,
        source: e.source,
        sensitivity: e.sensitivity,
        suppressed: e.suppressed,
        suppressReason: e.suppressReason,
      }));
      ids.add(id);
    }
    if (
      (bundle.state === "critical" || bundle.state === "degraded") &&
      !bundleExceptions.some((e) => !e.suppressed)
    ) {
      const id = syntheticId("status", bundle.id, bundle.state);
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
      {
        family: "bundle",
        parts: [bundle.id],
        title: bundle.title,
        state: bundle.state,
        // A bundle-level coverage state is always caused by some section's
        // evidence, so carry that producer-written explanation up instead of
        // falling through to the generic "reports incomplete coverage" line.
        reasons: bundle.sections
          .filter((s) => sectionEvidenceState(s) === bundle.state)
          .flatMap(evidenceReasons),
        summary: "",
      },
      // Filter on the section's *evidence* state, not its declared state. The
      // old `s.state !== bundle.state` filter dropped any section whose
      // declared state happened to equal the bundle's, which is exactly the
      // case a section lying about itself produces: declared "healthy" on a
      // healthy bundle, with stale freshness and partial completeness beneath.
      ...bundle.sections.map((s) => ({
        family: "section",
        parts: [bundle.id, s.id],
        title: s.title,
        state: sectionEvidenceState(s),
        reasons: evidenceReasons(s),
        summary: s.summary,
      })).filter((s) => s.state !== bundle.state),
    ];
    for (const item of states) {
      if (!COVERAGE_STATES.has(item.state)) continue;
      const id = syntheticId(item.family, ...item.parts, item.state);
      if (ids.has(id)) continue;
      out.push(makeExc({
        id,
        severity: stateSeverity(item.state),
        subject: item.title,
        headline: `Coverage is ${item.state}`,
        detail: item.reasons.join(" · ") || item.summary ||
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
  const bySeverity = (a: Exc, b: Exc) =>
    SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.id.localeCompare(b.id);
  out.sort(bySeverity);
  // Every exception becomes a row in the page and a written resource, and
  // nothing bounded how many one bundle could carry. Cap after sorting so the
  // most severe survive, and spend one slot saying what was dropped — a silent
  // cap would be the same failure this renderer exists to prevent.
  if (out.length > MAX_EXCEPTIONS) {
    const kept = out.slice(0, MAX_EXCEPTIONS - 1);
    const dropped = out.length - kept.length;
    kept.push(makeExc({
      id: syntheticId("render", "exception-overflow"),
      severity: "warning",
      subject: "Dashboard coverage",
      headline: `${dropped} further exceptions were not rendered`,
      detail:
        `This render produced ${out.length} exceptions; the ${dropped} least severe are not on this page and were not written as resources.`,
      source: "renderer",
      suppressed: false,
      suppressReason: "",
    }));
    return kept.sort(bySeverity);
  }
  return out;
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
  // The headline used to branch on active.length alone once allClear was false,
  // so suppressing the only exception on a degraded bundle printed the literal
  // "0 things need you" above a bundle whose state was degraded or critical.
  // Nothing was hidden — the banner lost its clear styling and the item stayed
  // under "Expected" — but the sentence contradicted itself. Say what is
  // actually true instead: quiet, and why quiet is not the same as healthy.
  const nonHealthy = [
    ...new Set(
      d.bundles.filter((bundle) => bundle.state !== "healthy").map((bundle) =>
        bundle.state
      ),
    ),
  ].sort((a, b) => STATE_RANK[b] - STATE_RANK[a]);
  const quietReason = nonHealthy.length
    ? `bundle state ${nonHealthy.join(", ")}`
    : "no validated bundles";
  // The only timestamp on the page was the renderer's own clock, so a page
  // rebuilt from a bundle generated six days ago still read as current. Show
  // the oldest bundle's own generatedAt next to it.
  const oldestGeneratedAt = d.bundles.length
    ? d.bundles.map((bundle) => bundle.generatedAt).reduce((a, b) =>
      Date.parse(b) < Date.parse(a) ? b : a
    )
    : "";
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
  // Bound the rendered rows per section and sections per bundle, and say how
  // many were dropped. An unbounded metrics array wrote an unbounded table into
  // a file that lands in a web root.
  const overflowRow = (total: number, shown: number, columns: number) =>
    total > shown
      ? `<tr><td colspan="${columns}"><em>${
        total - shown
      } more rows not shown</em></td></tr>`
      : "";
  const details = d.bundles.flatMap((bundle) => {
    const shownSections = bundle.sections.slice(0, MAX_SECTIONS);
    const rendered = shownSections.map((section) => {
      const shownMetrics = section.metrics.slice(0, MAX_TABLE_ROWS);
      const metrics = shownMetrics.map((metric) => {
        const value = metric.availability === "observed"
          ? `${esc(metric.value)} ${esc(metric.unit)}`
          : `<em>${esc(metric.availability)}: ${esc(metric.reason)}</em>`;
        // metric.limit was validated and then never rendered, so a metric
        // sitting at 95000 against a provider limit of 100000 looked identical
        // to one with no threshold at all.
        const limit = metric.limit
          ? `${esc(metric.limit.value)} ${esc(metric.unit)} · ${
            esc(metric.limit.kind)
          }${metric.limit.period ? ` / ${esc(metric.limit.period)}` : ""}${
            metric.limit.authoritative ? "" : " · unconfirmed"
          }`
          : "—";
        return `<tr><td>${esc(metric.label)}</td><td>${value}</td><td>${
          esc(metric.confidence)
        }</td><td>${limit}</td></tr>`;
      }).join("") + overflowRow(section.metrics.length, shownMetrics.length, 4);
      const shownFacts = section.facts.slice(0, MAX_TABLE_ROWS);
      const facts = shownFacts.map((fact) =>
        `<tr><td>${esc(fact.label)}</td><td>${esc(fact.value)}</td><td>${
          esc(fact.confidence)
        }</td></tr>`
      ).join("") + overflowRow(section.facts.length, shownFacts.length, 3);
      const reasons = evidenceReasons(section);
      return `<details><summary>${esc(section.title)} · ${
        esc(section.state)
      }</summary>
<p class="summary">${esc(section.summary)}</p><div class="coverage">Coverage: ${
        esc(section.coverage.kind)
      } · ${esc(section.coverage.scope)} · Freshness: ${
        esc(section.freshness.state)
      } · Completeness: ${
        esc(section.completeness.state)
      } · Generated <time datetime="${esc(bundle.generatedAt)}">${
        esc(bundle.generatedAt)
      }</time>${reasons.length ? ` · ${esc(reasons.join(" · "))}` : ""}</div>
${
        metrics
          ? `<table><thead><tr><th>Metric</th><th>Value</th><th>Confidence</th><th>Limit</th></tr></thead><tbody>${metrics}</tbody></table>`
          : ""
      }
${
        facts
          ? `<table><thead><tr><th>Fact</th><th>Value</th><th>Confidence</th></tr></thead><tbody>${facts}</tbody></table>`
          : ""
      }</details>`;
    });
    if (bundle.sections.length > shownSections.length) {
      rendered.push(
        `<details><summary>${esc(bundle.title)} · ${
          bundle.sections.length - shownSections.length
        } more sections not shown</summary><p class="summary">This bundle carries ${bundle.sections.length} sections; only the first ${MAX_SECTIONS} are rendered.</p></details>`,
      );
    }
    return rendered;
  }).join("\n");
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
  }</h1><div class="ts">rendered <time datetime="${esc(d.now)}">${
    esc(d.now)
  }</time>${
    oldestGeneratedAt
      ? ` · oldest bundle generated <time datetime="${
        esc(oldestGeneratedAt)
      }">${esc(oldestGeneratedAt)}</time>`
      : ""
  }</div></header><div class="banner${allClear ? " clear" : ""}"><h2>${
    allClear
      ? "Nothing needs you"
      : active.length === 0
      ? `Nothing active · ${esc(quietReason)}`
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
  version: "2026.08.25.2",
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
                sensitivity: exception.sensitivity,
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
