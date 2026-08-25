/** Normalize scoped @jpisgeek/lmstudio execution output into bundle v1. */
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

type Json = Record<string, unknown>;

interface DataHandle {
  name: string;
  specName?: string;
  version?: number;
}

interface ReportContext {
  scope: "method" | "model";
  modelType: string | { toString(): string };
  modelId: string;
  definition: { name: string; version: number };
  methodName: string;
  methodArgs: Json;
  executionStatus: "succeeded" | "failed";
  errorMessage?: string;
  dataHandles: DataHandle[];
  dataRepository: {
    getContent(
      type: string | { toString(): string },
      modelId: string,
      dataName: string,
      version?: number,
    ): Promise<Uint8Array | null>;
  };
}

const HealthSchema = z.object({
  reachable: z.boolean(),
  authorized: z.boolean(),
  httpStatus: z.number(),
  latencyMs: z.number(),
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.iso.datetime(),
});

const ModelsSchema = z.object({
  modelIds: z.array(z.string()),
  modelCount: z.number().int().nonnegative(),
  syncedAt: z.iso.datetime(),
}).superRefine((value, ctx) => {
  if (value.modelCount !== value.modelIds.length) {
    ctx.addIssue({
      code: "custom",
      message: "modelCount must match modelIds length",
      path: ["modelCount"],
    });
  }
});

const EmbeddingSchema = z.object({
  model: z.string(),
  servesEmbeddings: z.boolean(),
  measuredDimension: z.number().int().nonnegative(),
  dimensionKnown: z.boolean(),
  latencyMs: z.number().nonnegative(),
  httpStatus: z.number(),
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.iso.datetime(),
});

const CompletionSchema = z.object({
  model: z.string(),
  latencyMs: z.number().nonnegative(),
  httpStatus: z.number(),
  finishReason: z.string(),
  promptTokens: z.number().int().nonnegative(),
  completionTokens: z.number().int().nonnegative(),
  totalTokens: z.number().int().nonnegative(),
  reasoningTokens: z.number().int().nonnegative(),
  reasoningChars: z.number().int().nonnegative(),
  contentChars: z.number().int().nonnegative(),
  emptyContentWithReasoning: z.boolean(),
  contextExhausted: z.boolean(),
  maxTokensHit: z.boolean(),
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.iso.datetime(),
}).superRefine((value, ctx) => {
  if (
    !value.errorKind &&
    value.totalTokens !== value.promptTokens + value.completionTokens
  ) {
    ctx.addIssue({
      code: "custom",
      message: "totalTokens must equal promptTokens plus completionTokens",
      path: ["totalTokens"],
    });
  }
  if (value.contextExhausted && value.maxTokensHit) {
    ctx.addIssue({
      code: "custom",
      message: "contextExhausted and maxTokensHit are mutually exclusive",
      path: ["contextExhausted"],
    });
  }
});

const CapabilitySchema = z.object({
  model: z.string(),
  emitsReasoning: z.boolean(),
  honorsResponseFormat: z.boolean(),
  wrapsInCodeFences: z.boolean(),
  checksCompleted: z.number().int().min(0).max(3),
  reasoningCheckTruncated: z.boolean(),
  formatCheckTruncated: z.boolean(),
  fenceCheckTruncated: z.boolean(),
  latencyMs: z.number().nonnegative(),
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.iso.datetime(),
});

const sensitivity = {
  classification: "operational" as const,
  fields: [] as string[],
  redacted: false,
};

const references = [] as never[];

function exception(
  id: string,
  severity: "critical" | "warning" | "info",
  headline: string,
  detail: string,
) {
  return {
    id,
    severity,
    subject: "Local inference",
    headline,
    detail,
    source: "@jpisgeek/dashboard-lmstudio",
    suppressed: false,
    suppressReason: "",
    sensitivity: "operational" as const,
  };
}

function failureState(kind: string): DashboardState {
  if (kind === "unauthorized") return "unauthorized";
  if (kind === "unreachable" || kind === "timeout") return "critical";
  if (kind === "malformed_response" || kind === "empty_response") {
    return "partial";
  }
  return "degraded";
}

function failureSeverity(kind: string): "critical" | "warning" {
  return kind === "unauthorized" || kind === "unreachable" || kind === "timeout"
    ? "critical"
    : "warning";
}

function classifyExecutionFailure(message = ""): {
  kind: string;
  detail: string;
} {
  if (/unauthorized|401|403/i.test(message)) {
    return {
      kind: "unauthorized",
      detail: "The endpoint rejected the configured API token.",
    };
  }
  if (/timeout|timed out/i.test(message)) {
    return {
      kind: "timeout",
      detail: "The endpoint did not respond before the probe timeout.",
    };
  }
  if (/unreachable|could not reach|connection|dns/i.test(message)) {
    return {
      kind: "unreachable",
      detail: "The endpoint could not be reached.",
    };
  }
  return {
    kind: "invalid-response",
    detail: "The probe execution failed without a usable typed observation.",
  };
}

function commonSection(
  id: string,
  title: string,
  state: DashboardState,
  summary: string,
  observedAt: string | undefined,
  completeness: Json,
  metrics: Json[],
  facts: Json[],
  exceptions: Json[],
  coverage: Json = {},
) {
  return DashboardSectionSchema.parse({
    id,
    title,
    state,
    impact: "required",
    summary,
    coverage: {
      kind: "sample",
      scope:
        "one explicit local inference probe execution; not aggregate accounting",
      ...coverage,
    },
    freshness: observedAt
      ? { state: "fresh", observedAt, maxAgeSeconds: 300 }
      : {
        state: "unknown",
        reason: "no valid observation timestamp was produced",
      },
    completeness,
    metrics,
    facts,
    exceptions,
    references,
    sensitivity,
  });
}

function observedMetric(
  id: string,
  label: string,
  unit: string,
  value: number,
  confidence = "exact",
) {
  return {
    id,
    label,
    unit,
    availability: "observed",
    value,
    confidence,
    sensitivity: "operational",
  };
}

function unavailableMetric(
  id: string,
  label: string,
  unit: string,
  reason: string,
) {
  return {
    id,
    label,
    unit,
    availability: "unknown",
    reason,
    confidence: "unknown",
    sensitivity: "operational",
  };
}

function failedSection(ctx: ReportContext) {
  const failure = classifyExecutionFailure(ctx.errorMessage);
  const state = failureState(failure.kind);
  return commonSection(
    `lmstudio-${ctx.methodName}`,
    `Local inference ${ctx.methodName}`,
    state,
    failure.detail,
    undefined,
    { state: "unknown", reason: failure.detail },
    [],
    [],
    [exception(
      `lmstudio:${ctx.methodName}:${failure.kind}`,
      failureSeverity(failure.kind),
      failure.kind === "unauthorized"
        ? "Endpoint token rejected"
        : "Probe failed",
      failure.detail,
    )],
    { kind: "unknown", notes: failure.detail },
  );
}

function invalidRecordSection(ctx: ReportContext) {
  const detail =
    "The scoped LM Studio resource did not match its published source contract.";
  return commonSection(
    `lmstudio-${ctx.methodName}`,
    `Local inference ${ctx.methodName}`,
    "partial",
    detail,
    undefined,
    { state: "partial", observed: 1, rejected: 1, reason: detail },
    [],
    [],
    [exception(
      `lmstudio:${ctx.methodName}:invalid-record`,
      "warning",
      "Probe record rejected",
      detail,
    )],
    { kind: "unknown", notes: detail },
  );
}

function healthSection(value: z.infer<typeof HealthSchema>) {
  const kind = value.errorKind;
  const state: DashboardState = !value.reachable
    ? "critical"
    : !value.authorized
    ? kind === "unauthorized" ? "unauthorized" : "degraded"
    : kind
    ? failureState(kind)
    : "healthy";
  const exceptions = kind
    ? [exception(
      `lmstudio:health:${kind}`,
      failureSeverity(kind),
      kind === "unauthorized"
        ? "Endpoint reachable but token rejected"
        : !value.reachable
        ? "Endpoint unreachable"
        : "Endpoint health degraded",
      value.error || `health probe reported ${kind}`,
    )]
    : [];
  return commonSection(
    "lmstudio-health",
    "Local inference endpoint",
    state,
    value.reachable
      ? value.authorized
        ? "Endpoint reachable and authorized"
        : "Endpoint reachable but not authorized"
      : "Endpoint unreachable",
    value.checkedAt,
    { state: "exact", observed: 1, rejected: 0 },
    [observedMetric(
      "latency",
      "Endpoint latency",
      "milliseconds",
      value.latencyMs,
    )],
    [
      {
        id: "reachable",
        label: "Reachable",
        value: value.reachable,
        confidence: "exact",
        sensitivity: "operational",
      },
      {
        id: "authorized",
        label: "Authorized",
        value: value.authorized,
        confidence: "exact",
        sensitivity: "operational",
      },
      {
        id: "http-status",
        label: "HTTP status",
        value: value.httpStatus > 0 ? value.httpStatus : null,
        confidence: value.httpStatus > 0 ? "exact" : "unknown",
        sensitivity: "operational",
      },
    ],
    exceptions,
  );
}

function modelsSection(value: z.infer<typeof ModelsSchema>) {
  const state: DashboardState = value.modelCount > 0 ? "healthy" : "degraded";
  return commonSection(
    "lmstudio-models",
    "Available local models",
    state,
    value.modelCount > 0
      ? `${value.modelCount} model(s) available`
      : "Endpoint returned no available models",
    value.syncedAt,
    { state: "exact", observed: value.modelCount, rejected: 0 },
    [observedMetric(
      "available-models",
      "Available models",
      "count",
      value.modelCount,
    )],
    value.modelIds.map((model, index) => ({
      id: `model-${index}`,
      label: `Model ${index + 1}`,
      value: model,
      confidence: "exact",
      sensitivity: "operational",
    })),
    value.modelCount === 0
      ? [
        exception(
          "lmstudio:models:none",
          "warning",
          "No models available",
          "The endpoint returned an empty model list.",
        ),
      ]
      : [],
  );
}

function embeddingSection(value: z.infer<typeof EmbeddingSchema>) {
  const state: DashboardState = value.errorKind
    ? failureState(value.errorKind)
    : value.servesEmbeddings && value.dimensionKnown
    ? "healthy"
    : "partial";
  const reason = value.error || "Embedding dimension was not observed";
  return commonSection(
    "lmstudio-embedding",
    "Embedding probe",
    state,
    state === "healthy"
      ? `${value.model} returned a ${value.measuredDimension}-dimension vector`
      : reason,
    value.checkedAt,
    value.dimensionKnown
      ? { state: "exact", observed: 1, rejected: 0 }
      : { state: "partial", observed: 1, reason },
    [
      value.dimensionKnown
        ? observedMetric(
          "embedding-dimension",
          "Embedding dimension",
          "count",
          value.measuredDimension,
        )
        : unavailableMetric(
          "embedding-dimension",
          "Embedding dimension",
          "count",
          reason,
        ),
      observedMetric(
        "latency",
        "Probe latency",
        "milliseconds",
        value.latencyMs,
      ),
    ],
    [
      {
        id: "model",
        label: "Model",
        value: value.model,
        confidence: "exact",
        sensitivity: "operational",
      },
      {
        id: "serves-embeddings",
        label: "Serves embeddings",
        value: value.servesEmbeddings,
        confidence: "exact",
        sensitivity: "operational",
      },
    ],
    state === "healthy" ? [] : [exception(
      `lmstudio:embedding:${value.errorKind || "unknown-dimension"}`,
      failureSeverity(value.errorKind),
      value.errorKind === "model_not_found"
        ? "Embedding model not found"
        : "Embedding capability unavailable",
      reason,
    )],
  );
}

function completionSection(value: z.infer<typeof CompletionSchema>) {
  const successful = value.errorKind === "";
  let state: DashboardState = successful
    ? "healthy"
    : failureState(value.errorKind);
  const exceptions = [];
  if (successful && value.contextExhausted) {
    state = "degraded";
    exceptions.push(exception(
      "lmstudio:completion:context-exhausted",
      "warning",
      "Context window exhausted",
      "The completion stopped for length before reaching the requested output-token cap; this is a heuristic from one request.",
    ));
  } else if (successful && value.maxTokensHit) {
    state = "degraded";
    exceptions.push(exception(
      "lmstudio:completion:max-tokens-hit",
      "warning",
      "Output-token cap reached",
      "The completion used the requested output-token allowance and stopped with finish reason length.",
    ));
  }
  if (successful && value.emptyContentWithReasoning) {
    state = "degraded";
    exceptions.push(exception(
      "lmstudio:completion:reasoning-only-empty",
      "warning",
      "Reasoning consumed the response budget",
      "The model produced reasoning evidence but no visible answer content.",
    ));
  }
  if (!successful) {
    exceptions.push(exception(
      `lmstudio:completion:${value.errorKind}`,
      failureSeverity(value.errorKind),
      value.errorKind === "model_not_found"
        ? "Completion model not found"
        : "Completion probe failed",
      value.error || `completion probe reported ${value.errorKind}`,
    ));
  }
  const tokenReason = "the request did not complete with valid usage data";
  const token = (id: string, label: string, value: number) =>
    successful
      ? observedMetric(id, label, "tokens", value)
      : unavailableMetric(id, label, "tokens", tokenReason);
  return commonSection(
    "lmstudio-completion",
    "Completion probe",
    state,
    successful
      ? `${value.model} finished with ${
        value.finishReason || "an unknown reason"
      }`
      : value.error || "Completion probe failed",
    value.checkedAt,
    successful ? { state: "exact", observed: 1, expected: 1, rejected: 0 } : {
      state: "partial",
      observed: 1,
      expected: 1,
      rejected: 1,
      reason: tokenReason,
    },
    [
      token("prompt-tokens", "Prompt tokens", value.promptTokens),
      token("completion-tokens", "Completion tokens", value.completionTokens),
      token("total-tokens", "Total tokens", value.totalTokens),
      token("reasoning-tokens", "Reasoning tokens", value.reasoningTokens),
      observedMetric(
        "latency",
        "Request latency",
        "milliseconds",
        value.latencyMs,
      ),
    ],
    [
      {
        id: "model",
        label: "Model",
        value: value.model,
        confidence: "exact",
        sensitivity: "operational",
      },
      {
        id: "finish-reason",
        label: "Finish reason",
        value: successful ? value.finishReason || null : null,
        confidence: successful ? "exact" : "unknown",
        sensitivity: "operational",
      },
      {
        id: "context-exhausted",
        label: "Context exhausted",
        value: successful ? value.contextExhausted : null,
        confidence: successful ? "inferred" : "unknown",
        sensitivity: "operational",
      },
      {
        id: "max-tokens-hit",
        label: "Output-token cap hit",
        value: successful ? value.maxTokensHit : null,
        confidence: successful ? "exact" : "unknown",
        sensitivity: "operational",
      },
      {
        id: "reasoning-only-empty",
        label: "Reasoning-only empty output",
        value: successful ? value.emptyContentWithReasoning : null,
        confidence: successful ? "exact" : "unknown",
        sensitivity: "operational",
      },
    ],
    exceptions,
    {
      kind: "observed-traffic",
      start: value.checkedAt,
      end: value.checkedAt,
      notes:
        "one instrumented probe request; not runtime-wide or aggregate token accounting",
    },
  );
}

function capabilitySection(value: z.infer<typeof CapabilitySchema>) {
  const truncated = value.reasoningCheckTruncated ||
    value.formatCheckTruncated || value.fenceCheckTruncated;
  const complete = value.checksCompleted === 3 && !value.errorKind;
  const state: DashboardState = value.errorKind
    ? failureState(value.errorKind)
    : !complete
    ? "partial"
    : truncated
    ? "degraded"
    : "healthy";
  const exceptions = [];
  if (!complete) {
    exceptions.push(exception(
      "lmstudio:capabilities:partial",
      "warning",
      "Capability battery incomplete",
      `${value.checksCompleted} of 3 checks completed${
        value.errorKind ? `; ${value.errorKind}` : ""
      }.`,
    ));
  }
  if (truncated) {
    exceptions.push(exception(
      "lmstudio:capabilities:truncated",
      "warning",
      "Capability response truncated",
      "At least one capability check stopped for length; negative findings from that check are not conclusive.",
    ));
  }
  return commonSection(
    "lmstudio-capabilities",
    "Model capabilities",
    state,
    complete
      ? `All capability checks completed for ${value.model}`
      : `${value.checksCompleted} of 3 checks completed`,
    value.checkedAt,
    complete ? { state: "exact", observed: 3, expected: 3, rejected: 0 } : {
      state: "partial",
      observed: value.checksCompleted,
      expected: 3,
      reason: "capability battery incomplete",
    },
    [
      observedMetric(
        "checks-completed",
        "Checks completed",
        "count",
        value.checksCompleted,
      ),
      observedMetric(
        "latency",
        "Battery latency",
        "milliseconds",
        value.latencyMs,
      ),
    ],
    [
      {
        id: "model",
        label: "Model",
        value: value.model,
        confidence: "exact",
        sensitivity: "operational",
      },
      {
        id: "emits-reasoning",
        label: "Emits reasoning",
        value: value.checksCompleted >= 1 && !value.reasoningCheckTruncated
          ? value.emitsReasoning
          : null,
        confidence: value.checksCompleted >= 1 && !value.reasoningCheckTruncated
          ? "exact"
          : "unknown",
        sensitivity: "operational",
      },
      {
        id: "honors-response-format",
        label: "Honors response format",
        value: value.checksCompleted >= 2 && !value.formatCheckTruncated
          ? value.honorsResponseFormat
          : null,
        confidence: value.checksCompleted >= 2 && !value.formatCheckTruncated
          ? "exact"
          : "unknown",
        sensitivity: "operational",
      },
      {
        id: "wraps-code-fences",
        label: "Wraps in code fences",
        value: value.checksCompleted >= 3 && !value.fenceCheckTruncated
          ? value.wrapsInCodeFences
          : null,
        confidence: value.checksCompleted >= 3 && !value.fenceCheckTruncated
          ? "exact"
          : "unknown",
        sensitivity: "operational",
      },
    ],
    exceptions,
  );
}

async function readRecord(ctx: ReportContext): Promise<Json | null> {
  const handle = ctx.dataHandles[0];
  if (!handle) return null;
  const content = await ctx.dataRepository.getContent(
    ctx.modelType,
    ctx.modelId,
    handle.name,
    handle.version,
  );
  if (!content) return null;
  return JSON.parse(new TextDecoder().decode(content));
}

/** Normalize one endpoint or request probe execution. */
export async function normalize(
  ctx: ReportContext,
): Promise<DashboardBundleV1> {
  const modelType = String(ctx.modelType);
  if (
    ![
      "@jpisgeek/lmstudio/endpoint",
      "@jpisgeek/lmstudio/probe",
    ].includes(modelType)
  ) {
    throw new Error(`unsupported LM Studio source ${modelType}`);
  }
  const record = await readRecord(ctx);
  let section;
  if (ctx.executionStatus === "failed" || !record) {
    section = failedSection(ctx);
  } else {
    try {
      if (
        modelType === "@jpisgeek/lmstudio/endpoint" &&
        ctx.methodName === "health"
      ) {
        section = healthSection(HealthSchema.parse(record));
      } else if (
        modelType === "@jpisgeek/lmstudio/endpoint" &&
        ctx.methodName === "models"
      ) {
        section = modelsSection(ModelsSchema.parse(record));
      } else if (
        modelType === "@jpisgeek/lmstudio/probe" &&
        ctx.methodName === "embedding"
      ) {
        section = embeddingSection(EmbeddingSchema.parse(record));
      } else if (
        modelType === "@jpisgeek/lmstudio/probe" &&
        ctx.methodName === "completion"
      ) {
        section = completionSection(CompletionSchema.parse(record));
      } else if (
        modelType === "@jpisgeek/lmstudio/probe" &&
        ctx.methodName === "capabilities"
      ) {
        section = capabilitySection(CapabilitySchema.parse(record));
      } else {
        throw new Error(
          `unsupported LM Studio method ${modelType}.${ctx.methodName}`,
        );
      }
    } catch (error) {
      if (!(error instanceof z.ZodError)) throw error;
      section = invalidRecordSection(ctx);
    }
  }
  const bundle = {
    schemaVersion: DASHBOARD_BUNDLE_VERSION,
    id: section.id,
    title: "Local inference",
    generatedAt: new Date().toISOString(),
    producer: {
      extension: "@jpisgeek/dashboard-lmstudio",
      extensionVersion: "2026.08.25.1",
      modelType,
      modelName: ctx.definition.name,
      modelId: ctx.modelId,
      dataName: "report-jpisgeek-dashboard-lmstudio-json",
      reportName: "@jpisgeek/dashboard-lmstudio",
    },
    state: deriveOverallState([section]),
    sections: [section],
    exceptions: [],
    sensitivity,
    extensions: {
      "jpisgeek/local-inference": {
        accountingScope: ctx.methodName === "completion"
          ? "single-request"
          : "not-applicable",
        aggregateAccounting: false,
      },
    },
  };
  return DashboardBundleV1Schema.parse(bundle);
}

function markdown(bundle: DashboardBundleV1): string {
  const section = bundle.sections[0];
  return `# ${bundle.title}\n\nState: **${bundle.state}**\n\n- ${section.title}: ${section.summary}`;
}

/** LM Studio dashboard normalization report. */
export const report = {
  name: "@jpisgeek/dashboard-lmstudio",
  description:
    "Normalize local inference endpoint and request probes into dashboard bundle v1.",
  scope: "method" as const,
  labels: ["dashboard", "observability", "lmstudio", "local-inference"],
  execute: async (context: ReportContext) => {
    const bundle = await normalize(context);
    return { markdown: markdown(bundle), json: bundle };
  },
};
