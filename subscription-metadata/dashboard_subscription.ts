/** Normalize explicit subscription metadata into dashboard bundle v1. */
// BEGIN INLINED DASHBOARD CONTRACT V1
/**
 * Provider-neutral dashboard bundle contract.
 *
 * Collectors observe. Reports normalize. Renderers present. This module is the
 * narrow waterline between them: it carries provenance and coverage strongly
 * enough that missing data cannot dress itself up as a reassuring zero.
 *
 * The file is a static source dependency, not a Swamp extension entry point.
 * Swamp bundles it into each independently published adapter and renderer that
 * imports it.
 *
 * @module
 */
import { z } from "npm:zod@4";

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
type Json = Record<string, unknown>;
const DecimalSchema = z.string().regex(/^\d+(\.\d+)?$/);
const ReferenceSchema = z.string().url().refine(
  (value) => {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password &&
      !url.search && !url.hash;
  },
  "sourceReference must use https and must not contain credentials, query parameters, or fragments",
);
const LimitSchema = z.object({
  name: z.string(),
  value: z.number().nonnegative().finite(),
  unit: z.string().regex(/^[a-z][a-z0-9._-]*$/),
  period: z.string().optional(),
  sourceReference: ReferenceSchema.optional(),
});
const SnapshotSchema = z.object({
  provider: z.string(),
  planName: z.string().optional(),
  billingCadence: z.string().optional(),
  priceMinor: DecimalSchema.optional(),
  currency: z.string().regex(/^[A-Z]{3}$/).optional(),
  renewalStart: z.iso.datetime().optional(),
  renewalEnd: z.iso.datetime().optional(),
  seats: z.number().int().nonnegative().optional(),
  declaredLimits: z.array(LimitSchema),
  sourceReference: ReferenceSchema.optional(),
  provenance: z.object({
    kind: z.literal("operator-config"),
    capturedAt: z.iso.datetime(),
    sourceReference: ReferenceSchema.optional(),
  }),
});
type Snapshot = z.infer<typeof SnapshotSchema>;
interface Context {
  scope: "method" | "model";
  modelType: string | { toString(): string };
  modelId: string;
  definition: { name: string; version: number };
  methodName: string;
  executionStatus: "succeeded" | "failed";
  dataHandles: { name: string; specName?: string; version?: number }[];
  dataRepository: {
    getContent(
      type: string | { toString(): string },
      modelId: string,
      dataName: string,
      version?: number,
    ): Promise<Uint8Array | null>;
  };
}
const sensitivity = {
  classification: "operational" as const,
  fields: ["planName", "priceMinor", "renewalStart", "renewalEnd", "seats"],
  redacted: false,
  note: "Subscription and billing metadata can be commercially sensitive",
};
async function read(ctx: Context): Promise<Snapshot | null> {
  const handle = ctx.dataHandles.find((h) => h.specName === "snapshot") ??
    ctx.dataHandles[0];
  if (!handle) return null;
  const bytes = await ctx.dataRepository.getContent(
    ctx.modelType,
    ctx.modelId,
    handle.name,
    handle.version,
  );
  if (!bytes) return null;
  try {
    return SnapshotSchema.parse(JSON.parse(new TextDecoder().decode(bytes)));
  } catch {
    return null;
  }
}
function section(snapshot: Snapshot | null) {
  if (!snapshot) {
    return DashboardSectionSchema.parse({
      id: "subscription",
      title: "Subscription metadata",
      state: "unknown",
      impact: "informational",
      summary: "No valid explicit subscription metadata was available",
      coverage: {
        kind: "unknown",
        scope: "operator-declared subscription facts",
      },
      freshness: { state: "unknown", reason: "No valid snapshot" },
      completeness: { state: "unknown", reason: "No valid snapshot" },
      metrics: [],
      facts: [],
      exceptions: [{
        id: "subscription:missing",
        severity: "info",
        subject: "Subscription metadata",
        headline: "Subscription metadata unavailable",
        detail: "No valid explicit subscription metadata was available",
        source: "@jpisgeek/subscription-metadata",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational",
      }],
      references: [],
      sensitivity,
    });
  }
  const metrics: Json[] = [];
  if (snapshot.priceMinor !== undefined && snapshot.currency) {
    metrics.push({
      id: `subscription-price-${snapshot.currency.toLowerCase()}`,
      label: `Declared subscription price (${snapshot.currency} minor units)`,
      value: Number(snapshot.priceMinor),
      unit: "currency",
      availability: "observed",
      confidence: "exact",
      sensitivity: "operational",
    });
  }
  if (snapshot.seats !== undefined) {
    metrics.push({
      id: "declared-seats",
      label: "Declared seats",
      value: snapshot.seats,
      unit: "count",
      availability: "observed",
      confidence: "exact",
      sensitivity: "operational",
    });
  }
  for (const [index, limit] of snapshot.declaredLimits.entries()) {
    metrics.push({
      id: `declared-limit-${index + 1}`,
      label: limit.name,
      value: limit.value,
      unit: /^[a-z][a-z0-9._-]*$/.test(limit.unit) &&
          [
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
          ].includes(limit.unit)
        ? limit.unit
        : `custom:${limit.unit}`,
      availability: "observed",
      confidence: "exact",
      sensitivity: "operational",
    });
  }
  const facts: Json[] = [{
    id: "provider",
    label: "Provider",
    value: snapshot.provider,
    confidence: "exact",
    sensitivity: "operational",
  }, {
    id: "provenance",
    label: "Provenance",
    value: "operator-config",
    confidence: "exact",
    sensitivity: "operational",
  }];
  for (
    const [id, label, value] of [
      ["plan-name", "Plan name", snapshot.planName],
      ["billing-cadence", "Billing cadence", snapshot.billingCadence],
      ["renewal-start", "Renewal start", snapshot.renewalStart],
      ["renewal-end", "Renewal end", snapshot.renewalEnd],
    ] as const
  ) {
    if (value !== undefined) {
      facts.push({
        id,
        label,
        value,
        confidence: "exact",
        sensitivity: "operational",
      });
    }
  }
  return DashboardSectionSchema.parse({
    id: "subscription",
    title: "Subscription metadata",
    state: "healthy",
    impact: "informational",
    summary: snapshot.planName
      ? `${snapshot.provider} — ${snapshot.planName}`
      : `${snapshot.provider} subscription metadata`,
    coverage: {
      kind: "exact",
      scope: "only explicitly configured subscription facts",
      notes:
        "Absence means unknown; no remaining quota or usage cost is inferred",
    },
    freshness: { state: "fresh", observedAt: snapshot.provenance.capturedAt },
    completeness: {
      state: "exact",
      observed: facts.length + metrics.length,
      rejected: 0,
    },
    metrics,
    facts,
    exceptions: [],
    references: snapshot.sourceReference
      ? [{
        kind: "url",
        label: "Operator-supplied source",
        url: snapshot.sourceReference,
      }]
      : [],
    sensitivity,
  });
}
export async function normalize(ctx: Context): Promise<DashboardBundleV1> {
  const snapshot = await read(ctx);
  const sections = [section(snapshot)];
  return DashboardBundleV1Schema.parse({
    schemaVersion: DASHBOARD_BUNDLE_VERSION,
    id: "subscription-metadata",
    title: "Subscription metadata",
    generatedAt: new Date().toISOString(),
    producer: {
      extension: "@jpisgeek/subscription-metadata",
      extensionVersion: "2026.08.25.2",
      modelType: String(ctx.modelType),
      modelName: ctx.definition.name,
      modelId: ctx.modelId,
      dataName: "report-jpisgeek-subscription-metadata-json",
      reportName: "@jpisgeek/subscription-metadata",
    },
    state: deriveOverallState(sections),
    sections,
    exceptions: [],
    sensitivity,
    extensions: {
      "jpisgeek/subscription-metadata": {
        dataClass: "subscription-metadata",
        apiMetering: false,
        remainingQuotaDerived: false,
        perTokenCostDerived: false,
      },
    },
  });
}
export const report = {
  name: "@jpisgeek/subscription-metadata",
  description:
    "Normalize explicit plan facts without treating them as API usage or quota.",
  scope: "method" as const,
  labels: ["dashboard", "subscription", "metadata"],
  execute: async (context: Context) => {
    const bundle = await normalize(context);
    const markdownEscape = (value: string) =>
      value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/([\\`*_[\]{}()#+.!|\-])/g, "\\$1").replace(/[\r\n]+/g, " ");
    return {
      markdown: `# ${markdownEscape(bundle.title)}\n\n${
        markdownEscape(bundle.sections[0].summary)
      }`,
      json: bundle,
    };
  },
};
