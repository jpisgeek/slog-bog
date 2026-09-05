/** Normalize @jpisgeek/openai-usage snapshots into dashboard bundle v1. */
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
  // Evidence links are persisted and rendered; reject embedded credentials.
  url: z.string().url().refine(
    (value) => {
      const parsed = new URL(value);
      return parsed.protocol === "https:" && parsed.username === "" &&
        parsed.password === "";
    },
    "evidence URLs must use https and must not carry credentials",
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

const ErrorKindSchema = z.enum([
  "",
  "unauthorized",
  "rate-limited",
  "timeout",
  "unreachable",
  "invalid-response",
  "http-error",
]);
const DimensionStatusSchema = z.object({
  state: z.enum(["complete", "partial", "unavailable"]),
  pagesRead: z.number().int().nonnegative(),
  errorKind: ErrorKindSchema,
  message: z.string(),
});
const SnapshotSchema = z.object({
  provider: z.literal("openai"),
  collectedAt: z.iso.datetime(),
  coverageStart: z.iso.datetime(),
  coverageEnd: z.iso.datetime(),
  usageStatus: DimensionStatusSchema,
  costStatus: DimensionStatusSchema,
  usage: z.object({
    inputTokens: z.number().int().nonnegative(),
    outputTokens: z.number().int().nonnegative(),
    cachedInputTokens: z.number().int().nonnegative(),
    inputAudioTokens: z.number().int().nonnegative(),
    outputAudioTokens: z.number().int().nonnegative(),
    requests: z.number().int().nonnegative(),
    breakdowns: z.array(z.object({
      projectId: z.string().nullable(),
      model: z.string().nullable(),
      inputTokens: z.number().int().nonnegative(),
      outputTokens: z.number().int().nonnegative(),
      cachedInputTokens: z.number().int().nonnegative(),
      inputAudioTokens: z.number().int().nonnegative(),
      outputAudioTokens: z.number().int().nonnegative(),
      requests: z.number().int().nonnegative(),
    })),
  }).nullable(),
  costs: z.object({
    totals: z.array(
      z.object({
        currency: z.string().regex(/^[a-z]{3}$/),
        value: z.number().nonnegative().finite(),
      }),
    ),
    breakdowns: z.array(
      z.object({
        projectId: z.string().nullable(),
        lineItem: z.string().nullable(),
        value: z.number().nonnegative().finite(),
        currency: z.string().regex(/^[a-z]{3}$/),
      }),
    ),
  }).nullable(),
});
type Snapshot = z.infer<typeof SnapshotSchema>;
type Status = z.infer<typeof DimensionStatusSchema>;

interface ReportContext {
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
  fields: ["projectId", "model", "lineItem"],
  redacted: false,
  note: "Breakdown dimensions can reveal internal project names and workloads",
};

/**
 * Bundle-level sensitivity has to cover the producer block as well as the
 * sections. `producer.modelName` is the operator's own Swamp model name and
 * `producer.modelId` its instance ID; both are local infrastructure naming,
 * and neither is derived from OpenAI. They were emitted into the JSON report
 * while the sensitivity metadata listed only the OpenAI breakdown dimensions,
 * so an operator deciding what was safe to publish read a field list that did
 * not mention the two identifiers naming their own host's model. The contract
 * requires modelName, so the fix is disclosure, not omission: an operator who
 * must redact now knows exactly which paths to strip.
 */
const bundleSensitivity = {
  classification: "operational" as const,
  fields: [
    "projectId",
    "model",
    "lineItem",
    "producer.modelName",
    "producer.modelId",
  ],
  redacted: false,
  note:
    "Breakdown dimensions can reveal internal project names and workloads; the producer block additionally names the local Swamp model and its instance ID",
};

async function readSnapshot(ctx: ReportContext): Promise<Snapshot | null> {
  const handle = ctx.dataHandles.find((item) => item.specName === "snapshot") ??
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

function state(status: Status): DashboardState {
  if (status.errorKind === "unauthorized") return "unauthorized";
  if (status.state === "complete") return "healthy";
  return status.state === "partial" ? "partial" : "unknown";
}

function unavailableSection(id: string, title: string, status: Status) {
  const sectionState = state(status);
  return DashboardSectionSchema.parse({
    id,
    title,
    state: sectionState,
    impact: "required",
    summary: status.message || `${title} unavailable`,
    coverage: {
      kind: "unknown",
      scope: `OpenAI organization ${id}`,
      notes: status.message || "No authoritative response was available",
    },
    freshness: {
      state: "unknown",
      reason: status.message || "No observation was persisted",
    },
    completeness: {
      state: "unknown",
      reason: status.message || "No authoritative response was available",
    },
    metrics: [{
      id: `${id}-total`,
      label: `${title} total`,
      unit: id === "costs" ? "currency" : "tokens",
      confidence: "unknown",
      sensitivity: "operational",
      availability: status.errorKind === "unauthorized"
        ? "unauthorized"
        : "unknown",
      reason: status.message || `${title} unavailable`,
    }],
    facts: [],
    exceptions: [{
      id: `openai:${id}:${status.errorKind || "unavailable"}`,
      severity: status.errorKind === "unauthorized" ? "critical" : "warning",
      subject: title,
      headline: status.errorKind === "unauthorized"
        ? "Admin API authorization rejected"
        : `${title} unavailable`,
      detail: status.message || "No authoritative response was available",
      source: "@jpisgeek/openai-usage",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational",
    }],
    references: [],
    sensitivity,
  });
}

function completeness(status: Status, count: number) {
  return status.state === "complete"
    ? { state: "exact" as const, observed: count, rejected: 0 as const }
    : { state: "partial" as const, observed: count, reason: status.message };
}

function usageSection(snapshot: Snapshot) {
  if (!snapshot.usage) {
    return unavailableSection("usage", "API usage", snapshot.usageStatus);
  }
  const partial = snapshot.usageStatus.state === "partial";
  const sectionState = state(snapshot.usageStatus);
  return DashboardSectionSchema.parse({
    id: "usage",
    title: "API usage",
    state: sectionState,
    impact: "required",
    // Text and audio counters are disjoint in OpenAI's usage contract, so the
    // headline total sums both modalities. Cached input tokens stay out of it:
    // they are a subset of inputTokens, not an addition to it.
    summary: `${snapshot.usage.requests} requests used ${
      snapshot.usage.inputTokens + snapshot.usage.outputTokens +
      snapshot.usage.inputAudioTokens + snapshot.usage.outputAudioTokens
    } tokens`,
    coverage: {
      kind: partial ? "sample" : "exact",
      start: snapshot.coverageStart,
      end: snapshot.coverageEnd,
      scope:
        "OpenAI organization completion usage grouped by project and model",
      notes: partial ? snapshot.usageStatus.message : undefined,
    },
    freshness: { state: "fresh", observedAt: snapshot.collectedAt },
    completeness: completeness(
      snapshot.usageStatus,
      snapshot.usage.breakdowns.length,
    ),
    metrics: [
      ["input-tokens", "Input tokens", snapshot.usage.inputTokens, "tokens"],
      ["output-tokens", "Output tokens", snapshot.usage.outputTokens, "tokens"],
      [
        "cached-input-tokens",
        "Cached input tokens",
        snapshot.usage.cachedInputTokens,
        "tokens",
      ],
      [
        "input-audio-tokens",
        "Input audio tokens",
        snapshot.usage.inputAudioTokens,
        "tokens",
      ],
      [
        "output-audio-tokens",
        "Output audio tokens",
        snapshot.usage.outputAudioTokens,
        "tokens",
      ],
      ["requests", "Requests", snapshot.usage.requests, "requests"],
    ].map(([id, label, value, unit]) => ({
      id,
      label,
      value,
      unit,
      availability: "observed",
      confidence: partial ? "unknown" : "exact",
      sensitivity: "operational",
    })),
    facts: [{
      id: "breakdown-count",
      label: "Project/model breakdowns",
      value: snapshot.usage.breakdowns.length,
      confidence: partial ? "unknown" : "exact",
      sensitivity: "operational",
    }],
    exceptions: partial
      ? [{
        id: `openai:usage:${snapshot.usageStatus.errorKind || "partial"}`,
        severity: sectionState === "unauthorized" ? "critical" : "warning",
        subject: "API usage",
        headline: sectionState === "unauthorized"
          ? "Admin API authorization rejected"
          : "Usage coverage is partial",
        detail: snapshot.usageStatus.message,
        source: "@jpisgeek/openai-usage",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational",
      }]
      : [],
    references: [],
    sensitivity,
  });
}

function costSection(snapshot: Snapshot) {
  if (!snapshot.costs) {
    return unavailableSection("costs", "Billed cost", snapshot.costStatus);
  }
  const partial = snapshot.costStatus.state === "partial";
  const sectionState = state(snapshot.costStatus);
  const missingCurrency = snapshot.costs.totals.length === 0;
  const metrics = snapshot.costs.totals.map((total) => ({
    id: `cost-${total.currency}`,
    label: `Billed cost (${total.currency.toUpperCase()})`,
    value: total.value,
    unit: "currency",
    availability: "observed",
    confidence: partial ? "unknown" : "exact",
    sensitivity: "operational",
  }));
  if (metrics.length === 0) {
    metrics.push({
      id: "cost-total",
      label: "Billed cost",
      unit: "currency",
      availability: "unknown",
      confidence: "unknown",
      sensitivity: "operational",
      reason: "OpenAI returned no cost currency dimension",
    } as never);
  }
  return DashboardSectionSchema.parse({
    id: "costs",
    title: "Billed cost",
    state: missingCurrency ? "unknown" : sectionState,
    impact: "required",
    summary: snapshot.costs.totals.length
      ? snapshot.costs.totals.map((total) =>
        `${total.value} ${total.currency.toUpperCase()}`
      ).join(", ")
      : "No authoritative currency total was returned",
    coverage: {
      kind: partial ? "sample" : "exact",
      start: snapshot.coverageStart,
      end: snapshot.coverageEnd,
      scope:
        "OpenAI organization billed costs grouped by project and line item",
      notes: partial ? snapshot.costStatus.message : undefined,
    },
    freshness: { state: "fresh", observedAt: snapshot.collectedAt },
    completeness: missingCurrency
      ? {
        state: "unknown",
        reason: "OpenAI returned no cost currency dimension",
      }
      : completeness(snapshot.costStatus, snapshot.costs.breakdowns.length),
    metrics,
    facts: [{
      id: "currency-count",
      label: "Currencies observed",
      value: snapshot.costs.totals.length,
      confidence: partial ? "unknown" : "exact",
      sensitivity: "operational",
    }],
    exceptions: partial
      ? [{
        id: `openai:costs:${snapshot.costStatus.errorKind || "partial"}`,
        severity: sectionState === "unauthorized" ? "critical" : "warning",
        subject: "Billed cost",
        headline: sectionState === "unauthorized"
          ? "Admin API authorization rejected"
          : "Cost coverage is partial",
        detail: snapshot.costStatus.message,
        source: "@jpisgeek/openai-usage",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational",
      }]
      : [],
    references: [],
    sensitivity,
  });
}

/** Stable producer namespace; a full digest avoids raw model IDs in bundle IDs. */
async function bundleId(modelId: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(
      `@jpisgeek/openai-usage\0bundle-id\0${modelId}`,
    ),
  );
  const hex = Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
  return `openai-organization-${hex}`;
}

export async function normalize(
  ctx: ReportContext,
): Promise<DashboardBundleV1> {
  const snapshot = await readSnapshot(ctx);
  const missing: Status = {
    state: "unavailable",
    pagesRead: 0,
    errorKind: "invalid-response",
    message: "No valid OpenAI organization snapshot was available",
  };
  const sections = snapshot
    ? [usageSection(snapshot), costSection(snapshot)]
    : [
      unavailableSection("usage", "API usage", missing),
      unavailableSection("costs", "Billed cost", missing),
    ];
  return DashboardBundleV1Schema.parse({
    schemaVersion: DASHBOARD_BUNDLE_VERSION,
    id: await bundleId(ctx.modelId),
    title: "OpenAI organization usage",
    generatedAt: new Date().toISOString(),
    producer: {
      extension: "@jpisgeek/openai-usage",
      extensionVersion: "2026.09.05.1",
      modelType: String(ctx.modelType),
      modelName: ctx.definition.name,
      modelId: ctx.modelId,
      dataName: "report-jpisgeek-openai-usage-json",
      reportName: "@jpisgeek/openai-usage",
    },
    state: deriveOverallState(sections),
    sections,
    exceptions: [],
    sensitivity: bundleSensitivity,
    extensions: {
      "jpisgeek/openai-usage": {
        usageEndpoint: "/v1/organization/usage/completions",
        costEndpoint: "/v1/organization/costs",
        subscriptionQuotaInferred: false,
      },
    },
  });
}

export const report = {
  name: "@jpisgeek/openai-usage",
  description:
    "Normalize OpenAI organization usage and billed costs into dashboard bundle v1.",
  scope: "method" as const,
  labels: ["dashboard", "openai", "usage", "cost"],
  execute: async (context: ReportContext) => {
    const bundle = await normalize(context);
    return {
      markdown: `# ${bundle.title}\n\nState: **${bundle.state}**\n\n${
        bundle.sections.map((section) =>
          `- ${section.title}: ${section.state} — ${section.summary}`
        ).join("\n")
      }`,
      json: bundle,
    };
  },
};
