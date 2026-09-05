/** Normalize scoped @jpisgeek/lmstudio execution output into bundle v1. */
import { createHash } from "node:crypto";
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

// ---------------------------------------------------------------------------
// Source-record invariants.
//
// Every schema below describes a record written by a collector that talked to
// an untrusted endpoint. The collector is not the attacker, but it is the last
// place the endpoint's answer was touched, and a collector that mis-sets one
// field is indistinguishable here from one that was lied to. Before these
// cross-field rules a record could assert two contradictory things at once and
// this report believed the reassuring half: a 500 response carrying an empty
// errorKind derived "healthy" because the only success test was `errorKind ===
// ""`, and a daemon reporting daemonRunning:false with loaded models derived
// "healthy" because loadedModelCount was the only thing consulted.
//
// A record that fails one of these rules is a ZodError, which normalize()
// already turns into invalidRecordSection: a visible partial observation, not
// a silently believed one. That is deliberately the same treatment a
// structurally malformed record gets, because a self-contradicting record is
// exactly as unusable as a malformed one.
// ---------------------------------------------------------------------------

/** A status a real HTTP response can carry. 0 is this collector's "no response". */
function isHttpStatus(status: number): boolean {
  return Number.isInteger(status) && status >= 100 && status <= 599;
}

/** Success is the 2xx range only: 3xx, 4xx and 5xx are not a working endpoint. */
function isSuccessStatus(status: number): boolean {
  return Number.isInteger(status) && status >= 200 && status <= 299;
}

const HealthSchema = z.object({
  reachable: z.boolean(),
  authorized: z.boolean(),
  httpStatus: z.number(),
  latencyMs: z.number().nonnegative(),
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.iso.datetime(),
}).strict().superRefine((value, ctx) => {
  if (value.httpStatus !== 0 && !isHttpStatus(value.httpStatus)) {
    ctx.addIssue({
      code: "custom",
      message: "httpStatus must be 0 (no response) or in the range 100-599",
      path: ["httpStatus"],
    });
  }
  // "Unreachable" means no HTTP exchange happened at all, so there is no status
  // to report and nothing could have authorized the caller. A record claiming
  // both an unreachable endpoint and a status code is describing two different
  // requests, and whichever half a reader trusts is a coin flip.
  if (!value.reachable && (value.httpStatus !== 0 || value.authorized)) {
    ctx.addIssue({
      code: "custom",
      message:
        "an unreachable endpoint cannot report an HTTP status or authorization",
      path: ["reachable"],
    });
  }
  // An empty errorKind is the collector asserting success. Success has to agree
  // with every other field, or the assertion is worthless: this is the exact
  // combination (errorKind "" with httpStatus 500) that used to read healthy.
  if (
    value.errorKind === "" &&
    (!value.reachable || !value.authorized ||
      !isSuccessStatus(value.httpStatus))
  ) {
    ctx.addIssue({
      code: "custom",
      message:
        "an empty errorKind requires a reachable, authorized endpoint and a 2xx status",
      path: ["errorKind"],
    });
  }
  if (!value.authorized && value.errorKind === "") {
    ctx.addIssue({
      code: "custom",
      message: "an unauthorized result requires an errorKind",
      path: ["errorKind"],
    });
  }
});

const ModelsSchema = z.object({
  modelIds: z.array(z.string()),
  modelCount: z.number().int().nonnegative(),
  syncedAt: z.iso.datetime(),
}).strict().superRefine((value, ctx) => {
  if (value.modelCount !== value.modelIds.length) {
    ctx.addIssue({
      code: "custom",
      message: "modelCount must match modelIds length",
      path: ["modelCount"],
    });
  }
});

const DaemonSchema = z.object({
  cliAvailable: z.boolean(),
  daemonRunning: z.boolean(),
  status: z.enum(["running", "not-running", "unknown"]),
  loadedModelCount: z.number().int().nonnegative(),
  loadedModels: z.array(
    z.object({
      identifier: z.string().min(1),
      type: z.string(),
      architecture: z.string(),
    }).strict(),
  ),
  observedAt: z.iso.datetime(),
  errorKind: z.enum([
    "",
    "cli-unavailable",
    "unreachable",
    "timeout",
    "command-failed",
    "invalid-response",
  ]),
  error: z.string(),
}).strict().superRefine((value, ctx) => {
  if (value.loadedModelCount !== value.loadedModels.length) {
    ctx.addIssue({
      code: "custom",
      message: "loadedModelCount must match loadedModels length",
      path: ["loadedModelCount"],
    });
  }
  // A daemon that is not running holds nothing in memory. Accepting the pair
  // (daemonRunning false, loadedModelCount 5) let a dead runtime derive
  // "healthy", because the only input to that branch was the model count.
  if (!value.daemonRunning && value.loadedModelCount > 0) {
    ctx.addIssue({
      code: "custom",
      message: "a daemon that is not running cannot have models loaded",
      path: ["loadedModelCount"],
    });
  }
  // `status` and `daemonRunning` are two encodings of one fact. When they
  // disagree the record cannot say whether the runtime was observed at all.
  if ((value.status === "running") !== value.daemonRunning) {
    ctx.addIssue({
      code: "custom",
      message: "status running must agree with daemonRunning",
      path: ["status"],
    });
  }
  // An unknown status is a failed observation, and a failed observation names
  // its reason. Without this, "unknown" plus an empty errorKind is a record
  // that admits it saw nothing while claiming nothing went wrong.
  if (value.status === "unknown" && value.errorKind === "") {
    ctx.addIssue({
      code: "custom",
      message: "an unknown daemon status requires an errorKind",
      path: ["errorKind"],
    });
  }
  if ((value.errorKind === "cli-unavailable") !== !value.cliAvailable) {
    ctx.addIssue({
      code: "custom",
      message:
        "cliAvailable false must be reported as errorKind cli-unavailable",
      path: ["cliAvailable"],
    });
  }
  if (value.errorKind === "" && (!value.cliAvailable || !value.daemonRunning)) {
    ctx.addIssue({
      code: "custom",
      message:
        "an empty errorKind requires an available CLI and a running daemon",
      path: ["errorKind"],
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
}).strict().superRefine((value, ctx) => {
  if (value.httpStatus !== 0 && !isHttpStatus(value.httpStatus)) {
    ctx.addIssue({
      code: "custom",
      message: "httpStatus must be 0 (no response) or in the range 100-599",
      path: ["httpStatus"],
    });
  }
  if (value.httpStatus === 0 && value.errorKind === "") {
    ctx.addIssue({
      code: "custom",
      message: "a probe with no HTTP response requires an errorKind",
      path: ["errorKind"],
    });
  }
  // A capability finding is only worth as much as the exchange that produced
  // it. `servesEmbeddings: true` after a 500, or alongside an errorKind, is a
  // claim the probe never observed, and this section used to promote exactly
  // that pair to "healthy".
  if (
    value.servesEmbeddings &&
    (value.errorKind !== "" || !isSuccessStatus(value.httpStatus))
  ) {
    ctx.addIssue({
      code: "custom",
      message: "servesEmbeddings requires a 2xx response and no errorKind",
      path: ["servesEmbeddings"],
    });
  }
  if (value.errorKind === "" && !isSuccessStatus(value.httpStatus)) {
    ctx.addIssue({
      code: "custom",
      message: "an empty errorKind requires a 2xx status",
      path: ["errorKind"],
    });
  }
  // The dimension flag and the number it describes are one observation. A
  // known dimension of 0, or an unknown dimension carrying 768, means the
  // metric and its availability disagree about whether anything was measured.
  if (value.dimensionKnown !== (value.measuredDimension > 0)) {
    ctx.addIssue({
      code: "custom",
      message: "dimensionKnown must agree with a positive measuredDimension",
      path: ["dimensionKnown"],
    });
  }
  if (value.dimensionKnown && !value.servesEmbeddings) {
    ctx.addIssue({
      code: "custom",
      message: "a measured dimension requires servesEmbeddings",
      path: ["dimensionKnown"],
    });
  }
});

const CompletionSchema = z.object({
  model: z.string(),
  latencyMs: z.number().nonnegative(),
  httpStatus: z.number(),
  finishReason: z.string(),
  promptTokens: z.number().int().nonnegative().nullable(),
  completionTokens: z.number().int().nonnegative().nullable(),
  totalTokens: z.number().int().nonnegative().nullable(),
  reasoningTokens: z.number().int().nonnegative().nullable(),
  reasoningChars: z.number().int().nonnegative(),
  contentChars: z.number().int().nonnegative(),
  emptyContentWithReasoning: z.boolean(),
  contextExhausted: z.boolean().nullable(),
  maxTokensHit: z.boolean().nullable(),
  errorKind: z.string(),
  error: z.string(),
  checkedAt: z.iso.datetime(),
}).strict().superRefine((value, ctx) => {
  if (
    !value.errorKind && value.totalTokens !== null &&
    value.promptTokens !== null && value.completionTokens !== null &&
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
  if (value.httpStatus !== 0 && !isHttpStatus(value.httpStatus)) {
    ctx.addIssue({
      code: "custom",
      message: "httpStatus must be 0 (no response) or in the range 100-599",
      path: ["httpStatus"],
    });
  }
  // A completion that succeeded returned a status in the 2xx range and a
  // finish reason to explain how it stopped. Believing errorKind alone made a
  // 503 with an unset errorKind a healthy completion carrying observed token
  // metrics that no request had ever produced.
  if (
    value.errorKind === "" &&
    (!isSuccessStatus(value.httpStatus) || value.finishReason === "")
  ) {
    ctx.addIssue({
      code: "custom",
      message: "an empty errorKind requires a 2xx status and a finish reason",
      path: ["errorKind"],
    });
  }
  if (value.httpStatus === 0 && value.errorKind === "") {
    ctx.addIssue({
      code: "custom",
      message: "a probe with no HTTP response requires an errorKind",
      path: ["errorKind"],
    });
  }
  // Reasoning evidence is the whole basis of the emptyContentWithReasoning
  // finding, and "empty content" is the other half. A record asserting it with
  // visible content, or with no reasoning evidence of either kind, contradicts
  // the thing it is being consulted about. Reasoning tokens count as evidence
  // on their own: the collector sets this flag when a model reported reasoning
  // usage without emitting any reasoning text.
  if (
    value.emptyContentWithReasoning &&
    ((value.reasoningChars === 0 && (value.reasoningTokens ?? 0) === 0) ||
      value.contentChars > 0)
  ) {
    ctx.addIssue({
      code: "custom",
      message:
        "emptyContentWithReasoning requires reasoning characters and no content",
      path: ["emptyContentWithReasoning"],
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
}).strict().superRefine((value, ctx) => {
  // The battery runs its three checks in order, so a check that never ran
  // cannot have been truncated and cannot have produced a positive finding.
  // Without this, a record could report emitsReasoning:true from zero
  // completed checks and this section would publish it as an exact fact.
  const checks: Array<[boolean, boolean, number, string]> = [
    [value.emitsReasoning, value.reasoningCheckTruncated, 1, "emitsReasoning"],
    [
      value.honorsResponseFormat,
      value.formatCheckTruncated,
      2,
      "honorsResponseFormat",
    ],
    [
      value.wrapsInCodeFences,
      value.fenceCheckTruncated,
      3,
      "wrapsInCodeFences",
    ],
  ];
  for (const [finding, truncated, needed, field] of checks) {
    if ((finding || truncated) && value.checksCompleted < needed) {
      ctx.addIssue({
        code: "custom",
        message: `${field} requires at least ${needed} completed checks`,
        path: [field],
      });
    }
  }
  // An incomplete battery stopped for a reason. An empty errorKind with fewer
  // than three checks is a record that cannot say why it gave up.
  if (value.checksCompleted < 3 && value.errorKind === "") {
    ctx.addIssue({
      code: "custom",
      message: "an incomplete capability battery requires an errorKind",
      path: ["errorKind"],
    });
  }
});

/**
 * Sensitivity block for a section that carried no untrusted endpoint text.
 *
 * Sections that do carry it build their own from a Screen ledger, so the
 * `redacted` flag is a record of what the code actually did rather than a
 * constant the reader has to take on faith.
 */
const defaultSensitivity = {
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
  sensitivity: Json = defaultSensitivity,
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

// ---------------------------------------------------------------------------
// Untrusted-record clamps and screening.
//
// Length was only the first of the ways this text is dangerous, and clamping
// alone was never sanitization: `clampText` cut a two-megabyte error to 2048
// characters and published every one of them verbatim. The endpoint chooses
// that text. It routinely contains the URL the collector called (userinfo,
// query string and internal hostname included), the filesystem path of a model
// file, a proxy echoing back an `Authorization: Bearer ...` header, and — from a
// hostile endpoint — ESC sequences that rewrite the terminal of whoever runs
// `swamp data list`, or bidi overrides that make two different messages render
// identically. All of it landed in a stored bundle, a rendered dashboard, and a
// Markdown summary marked `redacted: false`.
//
// So every untrusted string now goes through screenText() before it reaches a
// fact, summary, exception detail, or id, and each section reports through a
// Screen ledger which of its fields actually had something removed.
//
// A report is a trust boundary. Every field clamped below arrives from whatever
// the configured LM Studio endpoint or `lms` CLI answered, and nothing upstream
// bounds it: lmstudio_endpoint.ts writes `modelIds: ids` straight from the
// /v1/models payload and derives `modelCount` from that same array, so the
// modelCount/length cross-check in ModelsSchema passes trivially at any size.
//
// Before these clamps, a hostile or broken endpoint answering with 500,000
// model ids expanded 1:1 into 500,000 Fact records that passed every schema
// check, were persisted to the datastore verbatim, and became 500,000 table
// rows in the renderer, which caps exception headline/detail at 160/240 chars
// but renders fact.value uncapped. Multi-megabyte `error` strings took the same
// path into section summaries and exception details.
//
// The clamps live here, at expansion time, and deliberately NOT as Zod .max()
// constraints: a schema cap would reject the whole record and fall through to
// invalidRecordSection, discarding a large-but-legitimate inventory entirely.
// Truncating keeps the observation and states plainly that the list was cut,
// which is exactly what the completeness contract exists to carry.
// ---------------------------------------------------------------------------

/** List entries expanded 1:1 into facts. Beyond this the enumeration is cut. */
const MAX_LISTED_ITEMS = 200;

/** Longest untrusted string permitted in a fact value. */
const MAX_FACT_TEXT = 256;

/** Longest untrusted free text permitted in a summary or exception detail. */
const MAX_FREE_TEXT = 2048;

/**
 * Largest stored resource this report will decode and parse.
 *
 * Sized well above any real observation: a 200-model inventory with long ids
 * is tens of kilobytes, and the largest legitimate record here is a daemon
 * inventory of the same shape. Anything at a megabyte is a broken or hostile
 * source, and refusing it costs one comparison against a length swamp already
 * knows, where parsing it costs the whole document.
 */
const MAX_RECORD_BYTES = 1024 * 1024;

/** Clamp untrusted text, marking the cut so a reader cannot mistake it. */
function clampText(value: string, limit = MAX_FACT_TEXT): string {
  return value.length <= limit ? value : `${value.slice(0, limit)} [truncated]`;
}

// C0/C1 controls and the Unicode line separators. Left in place, these drive
// the terminal of anyone who cats a stored bundle and split a single-line
// summary into several lines that each look like their own record.
// deno-lint-ignore no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

// Zero-width and bidi-formatting characters. Two distinct values containing
// these render identically to an operator, and a zero-width space inside a
// hostname would otherwise walk straight through the redaction patterns below,
// which is why this pass runs before them and not after.
const INVISIBLE_CHARS = /[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

/**
 * Structured redaction, applied in order.
 *
 * Each pattern removes a class of value that identifies infrastructure or
 * grants access to it. The order matters: a whole URL is taken out in one
 * piece before the bare-host and path patterns can rewrite its pieces
 * separately and leave the interesting half behind.
 *
 * These are deliberately greedy. Over-redaction costs a line of diagnostic
 * detail; under-redaction publishes a credential or an internal hostname into
 * a dashboard that may be shared. A model id containing a dot-separated suffix
 * can be caught by the host pattern, and that is the direction to fail in.
 *
 * Every quantifier here is bounded, and screenText() clamps its input before
 * running them, so no pattern can be walked into quadratic backtracking by a
 * megabyte-long error string.
 */
const REDACTIONS: ReadonlyArray<readonly [RegExp, string]> = [
  // Absolute URLs first, whole. Userinfo, query string, path and host are all
  // identifying and the endpoint decides all four, so the URL is taken out in
  // one piece — before any narrower pattern can carve a credential out of its
  // query string and leave the rest of the URL standing.
  [/\b[a-z][a-z0-9+.-]{0,32}:\/\/\S{1,4096}/gi, "[url redacted]"],
  // Scheme-less userinfo, the form curl and proxy errors print.
  [/\b[\w.+-]{1,128}:[^\s:@/]{1,128}@[\w.-]{1,255}/g, "[credential redacted]"],
  // Named credentials. A reverse proxy in front of LM Studio commonly echoes
  // the request headers it rejected, so the caller's own bearer token comes
  // back inside the error body the collector stored. The optional scheme word
  // is part of the match: without it `authorization: Bearer sk-...` consumed
  // only "Bearer" and published the token that followed it.
  [
    /\b(?:proxy-)?authorization\b\s*[:=]\s*(?:[A-Za-z][A-Za-z0-9-]{0,20}\s+)?\S{1,4096}/gi,
    "[credential redacted]",
  ],
  // The separator is optional because a credential is just as exposed when it
  // is announced in prose: `API key sk-...` and `password hunter2` carry no
  // `:` or `=` at all, and requiring one published both of them intact.
  [
    /\b(?:api[-_ ]?key|access[-_ ]?token|auth[-_ ]?token|token|secret|password|passwd|pwd)\b\s*[:=]?\s*(?:[A-Za-z][A-Za-z0-9-]{0,20}\s+)?\S{1,4096}/gi,
    "[credential redacted]",
  ],
  [
    /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,4096}/gi,
    "[credential redacted]",
  ],
  // Unlabelled tokens. A key pasted into an error body arrives with no name in
  // front of it, so the shape has to be enough: the issuer prefixes every
  // provider stamps on its keys, then any long mixed-class opaque run.
  [
    /\b(?:sk|pk|rk|hf|ghp|gho|ghu|ghs|ghr|glpat|xox[abprs])[-_][A-Za-z0-9_-]{8,4096}\b/gi,
    "[credential redacted]",
  ],
  [
    /\b(?:AKIA|ASIA)[0-9A-Z]{12,20}\b/g,
    "[credential redacted]",
  ],
  [
    /\b(?=[A-Za-z0-9_-]{32,4096}\b)(?=[A-Za-z0-9_-]*[A-Za-z])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{32,4096}\b/g,
    "[credential redacted]",
  ],
  // Filesystem paths. LM Studio's own errors name the model file on disk,
  // which carries the operator's username and local library layout.
  [/\b[A-Za-z]:\\[^\s"']{0,4096}/g, "[path redacted]"],
  [
    /(^|[\s"'(<[])(~?(?:\/[\w.@+-]{1,255}){2,}\/?)/g,
    "$1[path redacted]",
  ],
  // Mail addresses, before the host patterns get to them: redacting the domain
  // alone leaves the local part standing, and that half is a person.
  [/\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\b/g, "[email redacted]"],
  // Hardware addresses. A MAC names one machine permanently, and it is the
  // form an ARP or bridge error prints. Ahead of the IPv6 pattern, which would
  // otherwise swallow the colon form and label it a host.
  [
    /\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b/g,
    "[host redacted]",
  ],
  // IPv4, IPv6 bracketed and bare, dotted hostnames, and the local aliases. A
  // private address or an internal FQDN is infrastructure detail, not an
  // observation. Brackets are a URL convention, not part of the address: an
  // `lms` or socket error prints `link-local IPv6 prefix:1` with none, so requiring them
  // published every address that did not come out of a URL.
  [/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/g, "[host redacted]"],
  [/\[[0-9A-Fa-f:]{2,45}\](?::\d{1,5})?/g, "[host redacted]"],
  [
    /(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:.])/g,
    "[host redacted]",
  ],
  [
    /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}[a-z]{2,24}(?::\d{1,5})?\b/gi,
    "[host redacted]",
  ],
  [/\blocalhost(?::\d{1,5})?\b/gi, "[host redacted]"],
  // Undotted machine names, which is what a homelab actually runs on. There is
  // no shape that separates a bare hostname from an ordinary word, so the two
  // contexts that do name one are taken instead: a naming keyword in front of
  // it, and the host:port form.
  [
    /\b(?:host|hostname|server|node|machine)\b\s*[:=]?\s*[A-Za-z0-9][\w.-]{0,254}/gi,
    "[host redacted]",
  ],
  [
    /(?<![\w.:@/-])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?:\d{1,5}(?![\w.-])/g,
    "[host redacted]",
  ],
];

/** Strip characters that can drive a terminal, hide text, or forge identity. */
function screenChars(value: string): string {
  return value
    .replace(CONTROL_CHARS, " ")
    .replace(INVISIBLE_CHARS, "")
    // Lone surrogates survive JSON.parse and decode to the same replacement
    // character, so two distinct values can end up looking like one.
    .replace(/[\ud800-\udbff](?![\udc00-\udfff])/g, "\ufffd")
    .replace(/(^|[^\ud800-\udbff])([\udc00-\udfff])/g, "$1\ufffd")
    .replace(/\s+/g, " ")
    .trim();
}

/** Screened text plus whether anything at all was removed from the input. */
interface Screened {
  text: string;
  redacted: boolean;
}

/**
 * Make one untrusted string safe to persist.
 *
 * Character screening runs first so nothing invisible can hide a hostname from
 * the redaction patterns; the clamp runs next so the patterns only ever see a
 * bounded string; redaction runs last on that bounded, visible text.
 *
 * The flag compares against the original input, not against the clamped text.
 * Measured from the clamp, a value whose ESC sequence was stripped or whose
 * two megabytes were cut to 256 characters came back `redacted: false`, and an
 * operator reading the sensitivity block was told the stored text was exactly
 * what the endpoint sent. Every transformation is a removal and is reported.
 */
function screenText(value: string, limit = MAX_FACT_TEXT): Screened {
  const clamped = clampText(screenChars(value), limit);
  let text = clamped;
  for (const [pattern, replacement] of REDACTIONS) {
    text = text.replace(pattern, replacement);
  }
  return { text, redacted: text !== value };
}

/**
 * One section's record of what it removed.
 *
 * The bundle's sensitivity block is what an operator reads when deciding
 * whether a dashboard can be shared. Every section used to declare
 * `redacted: false` while publishing endpoint text that had never been through
 * a redaction pass, so that block was a claim nothing enforced. Now the flag
 * and the field list are produced by the same call that does the removing.
 */
class Screen {
  readonly #fields = new Set<string>();

  /** Record intentional omission of a sensitive source field. */
  omit(field: string): void {
    this.#fields.add(field);
  }

  /** Screen one source field, naming it if anything was removed from it. */
  text(field: string, value: string, limit = MAX_FACT_TEXT): string {
    // Arbitrary diagnostic prose has no safe structural guarantee: a short,
    // unlabelled password can evade every pattern. Discard the entire field.
    if (field === "error" && value !== "") {
      this.#fields.add(field);
      return "Collector diagnostic text was redacted; inspect the protected source record.";
    }
    const { text, redacted } = screenText(value, limit);
    if (redacted) this.#fields.add(field);
    return text;
  }

  /**
   * The sensitivity block describing what this screen actually did, merged
   * over a block already produced elsewhere.
   *
   * The base exists for the bundle, which screens its own producer fields and
   * republishes a section that screened its own: the reader needs one block
   * naming every field either pass touched, not whichever was written last.
   */
  sensitivity(base: Json = defaultSensitivity): Json {
    const inherited = Array.isArray(base.fields) ? base.fields as string[] : [];
    const fields = [...new Set([...inherited, ...this.#fields])].sort();
    return fields.length === 0 ? base : {
      classification: "operational",
      fields,
      redacted: true,
      note:
        "untrusted text was screened before persistence: control or invisible characters, over-length text, credentials, URLs, hosts, mail addresses, or filesystem paths were removed",
    };
  }
}

/** Collision-resistant digest of an unambiguously encoded source tuple. */
function identityDigest(parts: readonly string[]): string {
  const raw = parts.map((part) => `${part.length}:${part}`).join("");
  return createHash("sha256").update(raw).digest("hex").slice(0, 32);
}

/**
 * The error kinds the scoped collectors document, plus the tokens this report
 * raises on its own.
 *
 * `errorKind` is a free-form string on every schema but the daemon's, and it
 * used to be spliced into an exception id after nothing but a 64-character
 * slice. That gave an endpoint two ways to forge identity: `errorKind` values
 * carrying `:` split the id into different fields than intended, and two long
 * kinds sharing their first 64 characters produced one id, so one condition's
 * suppression and history silently covered the other. An id is identity, so
 * only known tokens are ever used literally; anything else is named by a hash
 * of the whole value, which cannot be truncated into a neighbour and cannot
 * carry a delimiter.
 */
const KNOWN_ERROR_KINDS: ReadonlySet<string> = new Set([
  // endpoint and probe collectors
  "unauthorized",
  "unreachable",
  "timeout",
  "cancelled",
  "http_error",
  "model_not_found",
  "malformed_response",
  "empty_response",
  "rate_limited",
  "server_error",
  "no_embedding_capability",
  // daemon collector
  "cli-unavailable",
  "command-failed",
  "invalid-response",
  // conditions this report names itself, where the source reported no kind
  "no-loaded-models",
  "unknown-dimension",
  "unsuccessful-status",
  "invalid-record",
  "record-oversized",
  "truncated",
  "none",
  "usage-unavailable",
  "context-exhausted",
  "max-tokens-hit",
  "reasoning-only-empty",
  "capabilities-partial",
  "capabilities-truncated",
]);

/** An id-safe token for an error kind. Unknown kinds are named, never quoted. */
function kindToken(kind: string): string {
  if (KNOWN_ERROR_KINDS.has(kind)) return kind;
  return `unclassified-${identityDigest([kind])}`;
}

/** Readable half of a section id, bounded to what IdentifierSchema accepts. */
function familySlug(value: string): string {
  const slug = value.toLowerCase().replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "").slice(0, 32);
  return slug || "method";
}

/**
 * The section family for a source, resolved from the source type and method
 * together.
 *
 * One function rather than a literal in each builder, because the family is
 * part of the identity: if the failure path derived a family from the method
 * name while the success path hard-coded one (`observe` versus `daemon`), the
 * same daemon would write its healthy observations under one id and its
 * rejected ones under another, and the history of a flapping source would come
 * apart into two half-series. An unrecognised pair still gets a stable, bounded
 * family from its method name.
 */
const SECTION_FAMILIES: Readonly<Record<string, string>> = {
  "@jpisgeek/lmstudio/daemon.observe": "daemon",
  "@jpisgeek/lmstudio/endpoint.health": "health",
  "@jpisgeek/lmstudio/endpoint.models": "models",
  "@jpisgeek/lmstudio/probe.embedding": "embedding",
  "@jpisgeek/lmstudio/probe.completion": "completion",
  "@jpisgeek/lmstudio/probe.capabilities": "capabilities",
};

function sectionFamily(ctx: ReportContext): string {
  return SECTION_FAMILIES[`${String(ctx.modelType)}.${ctx.methodName}`] ??
    familySlug(ctx.methodName);
}

/**
 * Identity for one observed source, not for one method.
 *
 * The bundle id and the section id were fixed strings per method
 * (`lmstudio-health` for every endpoint that exists), so two model definitions
 * pointing at two different LM Studio hosts produced byte-identical resource
 * identities. Downstream that is not a cosmetic clash: the renderer and the
 * datastore key history on the id, so the second endpoint's record overwrote
 * the first one's and an operator watching a "healthy" endpoint was watching
 * whichever probe happened to run last.
 *
 * Identity therefore comes from the inputs that make the observation what it
 * is — source type, model definition, model id, method, and the specific model
 * the probe addressed — hashed through the length-prefixed encoding above so
 * no two distinct tuples can land on one digest. The readable family stays in
 * front of the digest so an id is still legible in a dashboard.
 */
function sourceIdentity(ctx: ReportContext, family: string, subject: string) {
  const digest = identityDigest([
    String(ctx.modelType),
    ctx.definition.name,
    ctx.modelId,
    ctx.methodName,
    family,
    subject,
  ]);
  return {
    /** Section and bundle id: unique per observed source. */
    id: `lmstudio-${family}-${digest}`,
    /** Build an exception id in the same identity space. */
    exceptionId: (kind: string) =>
      `lmstudio:${family}:${kindToken(kind)}:${digest}`,
  };
}

/** Cut an untrusted list to the fact-expansion cap, reporting what was cut. */
function clampList<T>(items: readonly T[]): { listed: T[]; dropped: number } {
  return items.length <= MAX_LISTED_ITEMS
    ? { listed: [...items], dropped: 0 }
    : {
      listed: items.slice(0, MAX_LISTED_ITEMS),
      dropped: items.length - MAX_LISTED_ITEMS,
    };
}

/**
 * Completeness for a list whose fact expansion was cut at the cap.
 *
 * The population was fully observed, so `observed` stays at the real total;
 * what is partial is the enumeration this section can carry.
 */
function truncatedCompleteness(total: number, dropped: number): Json {
  return {
    state: "partial",
    observed: total,
    expected: total,
    rejected: 0,
    reason:
      `only the first ${MAX_LISTED_ITEMS} of ${total} entries are listed; ${dropped} were truncated`,
  };
}

/** Exception recording that a list was cut, so truncation is never silent. */
function truncationException(id: string, subject: string, total: number) {
  return exception(
    id,
    "warning",
    `${subject} list truncated`,
    `The source reported ${total} entries; only the first ${MAX_LISTED_ITEMS} are listed. The count metric remains exact.`,
  );
}

function failedSection(ctx: ReportContext) {
  const failure = classifyExecutionFailure(ctx.errorMessage);
  const state = failureState(failure.kind);
  const family = sectionFamily(ctx);
  const identity = sourceIdentity(ctx, family, "");
  return commonSection(
    identity.id,
    `Local inference ${family}`,
    state,
    failure.detail,
    undefined,
    { state: "unknown", reason: failure.detail },
    [],
    [],
    [exception(
      identity.exceptionId(failure.kind),
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
  const family = sectionFamily(ctx);
  const identity = sourceIdentity(ctx, family, "");
  return commonSection(
    identity.id,
    `Local inference ${family}`,
    "partial",
    detail,
    undefined,
    { state: "partial", observed: 1, rejected: 1, reason: detail },
    [],
    [],
    [exception(
      identity.exceptionId("invalid-record"),
      "warning",
      "Probe record rejected",
      detail,
    )],
    { kind: "unknown", notes: detail },
  );
}

/**
 * A resource too large to parse, reported as the partial observation it is.
 *
 * The size is the only thing said about it: nothing inside an oversized
 * response has been decoded, so there is nothing else this report knows.
 */
function oversizedRecordSection(ctx: ReportContext, bytes: number) {
  const detail =
    `The scoped LM Studio resource is ${bytes} bytes, over the ${MAX_RECORD_BYTES}-byte cap this report will parse.`;
  const family = sectionFamily(ctx);
  const identity = sourceIdentity(ctx, family, "");
  return commonSection(
    identity.id,
    `Local inference ${family}`,
    "partial",
    detail,
    undefined,
    { state: "partial", observed: 0, expected: 1, rejected: 1, reason: detail },
    [],
    [],
    [exception(
      identity.exceptionId("record-oversized"),
      "warning",
      "Probe record too large to parse",
      detail,
    )],
    { kind: "unknown", notes: detail },
  );
}

function healthSection(
  ctx: ReportContext,
  value: z.infer<typeof HealthSchema>,
) {
  // errorKind and error are the collector's classification of an untrusted
  // endpoint response and are both unbounded strings in HealthSchema. Screen
  // and clamp before one names an exception and the other becomes a detail.
  const screen = new Screen();
  const kind = value.errorKind;
  const errorDetail = screen.text("error", value.error, MAX_FREE_TEXT);
  const identity = sourceIdentity(ctx, sectionFamily(ctx), "");
  // Health is derived positively: every field that could contradict a healthy
  // endpoint has to agree, and the HTTP exchange has to have actually
  // succeeded. Asking only whether errorKind was empty meant a 500 response
  // whose kind the collector never set was published as a healthy endpoint,
  // with no exception raised at all because the exception list keyed on the
  // same empty string.
  const successful = value.reachable && value.authorized && kind === "" &&
    isSuccessStatus(value.httpStatus);
  const state: DashboardState = !value.reachable
    ? "critical"
    : !value.authorized
    ? kind === "unauthorized" ? "unauthorized" : "degraded"
    : successful
    ? "healthy"
    : failureState(kind);
  const exceptions = successful ? [] : [exception(
    identity.exceptionId(kind || "unsuccessful-status"),
    failureSeverity(kind),
    kind === "unauthorized"
      ? "Endpoint reachable but token rejected"
      : !value.reachable
      ? "Endpoint unreachable"
      : "Endpoint health degraded",
    errorDetail ||
      `health probe reported ${
        kind ? kindToken(kind) : `HTTP ${value.httpStatus}`
      }`,
  )];
  return commonSection(
    identity.id,
    "Local inference endpoint",
    state,
    value.reachable
      ? value.authorized
        ? successful
          ? "Endpoint reachable and authorized"
          : `Endpoint reachable and authorized but answered HTTP ${value.httpStatus}`
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
    {},
    screen.sensitivity(),
  );
}

function modelsSection(
  ctx: ReportContext,
  value: z.infer<typeof ModelsSchema>,
) {
  const screen = new Screen();
  const identity = sourceIdentity(ctx, sectionFamily(ctx), "");
  const state: DashboardState = value.modelCount > 0 ? "healthy" : "degraded";
  const { listed, dropped } = clampList(value.modelIds);
  return commonSection(
    identity.id,
    "Available local models",
    state,
    value.modelCount > 0
      ? `${value.modelCount} model(s) available`
      : "Endpoint returned no available models",
    value.syncedAt,
    // The count metric stays exact when the fact list is cut: the endpoint's
    // answer was fully observed, only its enumeration here is partial.
    dropped > 0
      ? truncatedCompleteness(value.modelCount, dropped)
      : { state: "exact", observed: value.modelCount, rejected: 0 },
    [observedMetric(
      "available-models",
      "Available models",
      "count",
      value.modelCount,
    )],
    // A model id is endpoint-chosen text: it reaches a fact value verbatim and
    // from there a rendered table cell, so it is screened like any other
    // untrusted string rather than trusted because it looks like a name.
    listed.map((model, index) => ({
      id: `model-${index}`,
      label: `Model ${index + 1}`,
      value: screen.text("modelIds", model),
      confidence: "exact",
      sensitivity: "operational",
    })),
    dropped > 0
      ? [truncationException(
        identity.exceptionId("truncated"),
        "Available model",
        value.modelCount,
      )]
      : value.modelCount === 0
      ? [
        exception(
          identity.exceptionId("none"),
          "warning",
          "No models available",
          "The endpoint returned an empty model list.",
        ),
      ]
      : [],
    {},
    screen.sensitivity(),
  );
}

function daemonSection(
  ctx: ReportContext,
  value: z.infer<typeof DaemonSchema>,
) {
  const screen = new Screen();
  const identity = sourceIdentity(ctx, sectionFamily(ctx), "");
  // Healthy means the CLI answered, the runtime is up, and it is holding
  // something. Deriving from loadedModelCount alone let a record that said
  // daemonRunning:false publish a healthy runtime; the schema now rejects that
  // pair outright, and this derivation no longer depends on it having done so.
  const running = value.cliAvailable && value.daemonRunning &&
    value.status === "running";
  const state: DashboardState = value.errorKind === "cli-unavailable"
    ? "unsupported"
    : value.errorKind === "unreachable" || value.errorKind === "timeout"
    ? "critical"
    : value.errorKind
    ? "partial"
    : !running
    ? "critical"
    : value.loadedModelCount === 0
    ? "degraded"
    : "healthy";
  // `error` is unbounded free text from `lms ps`, which reports the failure of
  // a local process: its messages carry model file paths and the runtime's own
  // host and port. It lands in both the section summary (min-1 string,
  // otherwise uncapped) and an exception detail.
  const summary = screen.text("error", value.error, MAX_FREE_TEXT) ||
    (value.loadedModelCount > 0
      ? `${value.loadedModelCount} model(s) loaded in LM Studio memory`
      : running
      ? "LM Studio is running with no models loaded"
      : "The LM Studio runtime is not running");
  const { listed, dropped } = clampList(value.loadedModels);
  const exceptions: ReturnType<typeof exception>[] = state === "healthy"
    ? []
    : [exception(
      identity.exceptionId(value.errorKind || "no-loaded-models"),
      state === "critical" ? "critical" : "warning",
      value.errorKind === "cli-unavailable"
        ? "LM Studio CLI unavailable"
        : value.errorKind === "unreachable"
        ? "LM Studio runtime unavailable"
        : value.errorKind === "timeout"
        ? "LM Studio runtime timed out"
        : value.errorKind
        ? "LM Studio daemon observation incomplete"
        : "No models loaded",
      summary,
    )];
  if (dropped > 0) {
    exceptions.push(truncationException(
      identity.exceptionId("truncated"),
      "Loaded model",
      value.loadedModelCount,
    ));
  }
  return commonSection(
    identity.id,
    "LM Studio headless daemon",
    state,
    summary,
    value.observedAt,
    value.errorKind
      ? {
        state: "partial",
        observed: 0,
        expected: 1,
        rejected: 1,
        reason: summary,
      }
      : dropped > 0
      ? truncatedCompleteness(value.loadedModelCount, dropped)
      : { state: "exact", observed: value.loadedModelCount, rejected: 0 },
    value.errorKind
      ? [unavailableMetric(
        "loaded-models",
        "Loaded models",
        "count",
        "lms ps did not return a valid inventory",
      )]
      : [observedMetric(
        "loaded-models",
        "Loaded models",
        "count",
        value.loadedModelCount,
      )],
    [
      {
        id: "daemon-running",
        label: "Daemon running",
        value: value.status === "unknown" ? null : value.daemonRunning,
        confidence: value.status === "unknown" ? "unknown" : "exact",
        sensitivity: "operational",
      },
      ...listed.map((model, index) => ({
        id: `loaded-model-${index}`,
        label: `Loaded model ${index + 1}`,
        value: screen.text("loadedModels", model.identifier),
        confidence: "exact",
        sensitivity: "operational",
      })),
    ],
    exceptions,
    {
      kind: value.errorKind ? "unknown" : "exact",
      scope:
        "models currently loaded in the configured LM Studio runtime as observed by lms ps",
      notes:
        "This is a point-in-time inventory, not aggregate request or token accounting.",
    },
    screen.sensitivity(),
  );
}

function embeddingSection(
  ctx: ReportContext,
  value: z.infer<typeof EmbeddingSchema>,
) {
  // model, error, and errorKind are all unbounded strings in EmbeddingSchema
  // and all three reach the summary, a fact value, or an exception id.
  const screen = new Screen();
  const model = screen.text("model", value.model);
  const reason = screen.text("error", value.error, MAX_FREE_TEXT) ||
    "Embedding dimension was not observed";
  // The probe model is part of the identity: one definition can probe several
  // models, and each of those is a different observation with its own history.
  const identity = sourceIdentity(ctx, sectionFamily(ctx), value.model);
  // Healthy requires the exchange that produced the finding to have succeeded,
  // not merely for errorKind to be empty.
  const state: DashboardState = value.errorKind
    ? failureState(value.errorKind)
    : value.servesEmbeddings && value.dimensionKnown &&
        isSuccessStatus(value.httpStatus)
    ? "healthy"
    : "partial";
  return commonSection(
    identity.id,
    "Embedding probe",
    state,
    state === "healthy"
      ? `${model} returned a ${value.measuredDimension}-dimension vector`
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
        value: model,
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
      identity.exceptionId(value.errorKind || "unknown-dimension"),
      failureSeverity(value.errorKind),
      value.errorKind === "model_not_found"
        ? "Embedding model not found"
        : "Embedding capability unavailable",
      reason,
    )],
    {},
    screen.sensitivity(),
  );
}

function completionSection(
  ctx: ReportContext,
  value: z.infer<typeof CompletionSchema>,
) {
  // model, finishReason, error, and errorKind are unbounded strings in
  // CompletionSchema and reach the summary, fact values, and exception ids.
  const screen = new Screen();
  const model = screen.text("model", value.model);
  const finishReason = screen.text("finishReason", value.finishReason);
  const errorDetail = screen.text("error", value.error, MAX_FREE_TEXT);
  const identity = sourceIdentity(ctx, sectionFamily(ctx), value.model);
  // A completion counts as successful only if the HTTP exchange succeeded too.
  // With errorKind as the sole test, a 503 whose kind the collector left empty
  // published observed token metrics for a request that never ran.
  const successful = value.errorKind === "" &&
    isSuccessStatus(value.httpStatus);
  const usageKnown = value.promptTokens !== null &&
    value.completionTokens !== null && value.totalTokens !== null;
  let state: DashboardState = successful
    ? "healthy"
    : failureState(value.errorKind);
  const exceptions = [];
  if (successful && value.contextExhausted) {
    state = "degraded";
    exceptions.push(exception(
      identity.exceptionId("context-exhausted"),
      "warning",
      "Context window exhausted",
      "The completion stopped for length before reaching the requested output-token cap; this is a heuristic from one request.",
    ));
  } else if (successful && value.maxTokensHit) {
    state = "degraded";
    exceptions.push(exception(
      identity.exceptionId("max-tokens-hit"),
      "warning",
      "Output-token cap reached",
      "The completion used the requested output-token allowance and stopped with finish reason length.",
    ));
  }
  if (successful && value.emptyContentWithReasoning) {
    state = "degraded";
    exceptions.push(exception(
      identity.exceptionId("reasoning-only-empty"),
      "warning",
      "Reasoning consumed the response budget",
      "The model produced reasoning evidence but no visible answer content.",
    ));
  }
  if (!successful) {
    exceptions.push(exception(
      identity.exceptionId(value.errorKind || "unsuccessful-status"),
      failureSeverity(value.errorKind),
      value.errorKind === "model_not_found"
        ? "Completion model not found"
        : "Completion probe failed",
      errorDetail ||
        `completion probe reported ${
          value.errorKind
            ? kindToken(value.errorKind)
            : `HTTP ${value.httpStatus}`
        }`,
    ));
  }
  if (successful && !usageKnown) {
    state = "partial";
    exceptions.push(exception(
      identity.exceptionId("usage-unavailable"),
      "warning",
      "Token usage unavailable",
      "The endpoint completed the request without valid token accounting.",
    ));
  }
  const tokenReason = "the request did not complete with valid usage data";
  // Reasoning tokens are an optional part of the OpenAI usage payload: a plain
  // non-reasoning chat model returns prompt/completion/total and simply omits
  // reasoning_tokens, which is why usageKnown above deliberately excludes it.
  // The old code reused tokenReason for every null token metric, so a fully
  // successful completion — healthy section, three observed token metrics, no
  // usage-unavailable exception — still rendered "Reasoning tokens: unknown,
  // the request did not complete with valid usage data", telling the operator
  // the request failed when it plainly succeeded. An absent optional counter
  // gets its own reason; the request-failure reason stays reserved for actual
  // failures, which is why a failed probe below still reports tokenReason.
  const missingReasoningReason =
    "the model did not report a reasoning token count";
  const token = (
    id: string,
    label: string,
    count: number | null,
    absentReason = tokenReason,
  ) =>
    successful && count !== null
      ? observedMetric(id, label, "tokens", count)
      : unavailableMetric(
        id,
        label,
        "tokens",
        successful ? absentReason : tokenReason,
      );
  return commonSection(
    identity.id,
    "Completion probe",
    state,
    successful
      ? `${model} finished with ${finishReason || "an unknown reason"}`
      : errorDetail || "Completion probe failed",
    value.checkedAt,
    successful && usageKnown
      ? { state: "exact", observed: 1, expected: 1, rejected: 0 }
      : {
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
      token(
        "reasoning-tokens",
        "Reasoning tokens",
        value.reasoningTokens,
        missingReasoningReason,
      ),
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
        value: model,
        confidence: "exact",
        sensitivity: "operational",
      },
      {
        id: "finish-reason",
        label: "Finish reason",
        value: successful ? finishReason || null : null,
        confidence: successful ? "exact" : "unknown",
        sensitivity: "operational",
      },
      {
        id: "context-exhausted",
        label: "Context exhausted",
        value: successful ? value.contextExhausted : null,
        confidence: successful && value.contextExhausted !== null
          ? "inferred"
          : "unknown",
        sensitivity: "operational",
      },
      {
        id: "max-tokens-hit",
        label: "Output-token cap hit",
        value: successful ? value.maxTokensHit : null,
        confidence: successful && value.maxTokensHit !== null
          ? "exact"
          : "unknown",
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
    screen.sensitivity(),
  );
}

function capabilitySection(
  ctx: ReportContext,
  value: z.infer<typeof CapabilitySchema>,
) {
  // model and errorKind are unbounded strings in CapabilitySchema and reach
  // the summary, a fact value, and an exception detail.
  const screen = new Screen();
  const model = screen.text("model", value.model);
  const identity = sourceIdentity(ctx, sectionFamily(ctx), value.model);
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
      identity.exceptionId("capabilities-partial"),
      "warning",
      "Capability battery incomplete",
      // The kind is named by its token, not quoted: an endpoint-chosen kind
      // reaching a detail verbatim is the same untrusted text every other
      // field here is screened for.
      `${value.checksCompleted} of 3 checks completed${
        value.errorKind ? `; ${kindToken(value.errorKind)}` : ""
      }.`,
    ));
  }
  if (truncated) {
    exceptions.push(exception(
      identity.exceptionId("capabilities-truncated"),
      "warning",
      "Capability response truncated",
      "At least one capability check stopped for length; negative findings from that check are not conclusive.",
    ));
  }
  return commonSection(
    identity.id,
    "Model capabilities",
    state,
    complete
      ? `All capability checks completed for ${model}`
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
        value: model,
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
    {},
    screen.sensitivity(),
  );
}

/**
 * A resource this report refuses to parse, reported rather than thrown.
 *
 * Carries the observed size because that is the only thing known about a
 * record nothing has decoded.
 */
class OversizedRecordError extends Error {
  /** Size of the resource that was refused. */
  readonly bytes: number;

  constructor(bytes: number) {
    super(
      `resource is ${bytes} bytes, over the ${MAX_RECORD_BYTES}-byte parse cap`,
    );
    this.name = "OversizedRecordError";
    this.bytes = bytes;
  }
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
  // The expansion caps further down bound the OUTPUT, not the work: they are
  // applied to an already-decoded, already-parsed, already-validated value.
  // A collector that stored a gigabyte-long array of model ids (which
  // ModelsSchema accepts, since modelCount is derived from that same array)
  // therefore cost a gigabyte of decoded UTF-16, a full JSON.parse, and a
  // whole-array Zod walk before clampList ever saw it, in a report process
  // that has no other reason to allocate at that scale. The cap belongs here,
  // ahead of the decode, where refusing is still cheap.
  if (content.byteLength > MAX_RECORD_BYTES) {
    throw new OversizedRecordError(content.byteLength);
  }
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
      "@jpisgeek/lmstudio/daemon",
    ].includes(modelType)
  ) {
    throw new Error("unsupported LM Studio source type");
  }
  let section;
  let record: Json | null = null;
  try {
    record = await readRecord(ctx);
  } catch (error) {
    if (error instanceof OversizedRecordError) {
      section = oversizedRecordSection(ctx, error.bytes);
    } else if (error instanceof SyntaxError || error instanceof RangeError) {
      // SyntaxError is malformed JSON. RangeError is what V8's recursive JSON
      // parser raises on a deeply nested document, which is the other way a
      // record that fits under the byte cap can still refuse to parse; both
      // are the same thing to a reader — a record that could not be read.
      section = invalidRecordSection(ctx);
    } else {
      // Repository errors can quote credentials and paths. Keep a coverage gap.
      section = invalidRecordSection(ctx);
    }
  }
  if (section) {
    // Malformed JSON is a visible invalid record, not a leaked parser error.
  } else if (ctx.executionStatus === "failed" || !record) {
    section = failedSection(ctx);
  } else {
    try {
      if (
        modelType === "@jpisgeek/lmstudio/daemon" &&
        ctx.methodName === "observe"
      ) {
        section = daemonSection(ctx, DaemonSchema.parse(record));
      } else if (
        modelType === "@jpisgeek/lmstudio/endpoint" &&
        ctx.methodName === "health"
      ) {
        section = healthSection(ctx, HealthSchema.parse(record));
      } else if (
        modelType === "@jpisgeek/lmstudio/endpoint" &&
        ctx.methodName === "models"
      ) {
        section = modelsSection(ctx, ModelsSchema.parse(record));
      } else if (
        modelType === "@jpisgeek/lmstudio/probe" &&
        ctx.methodName === "embedding"
      ) {
        section = embeddingSection(ctx, EmbeddingSchema.parse(record));
      } else if (
        modelType === "@jpisgeek/lmstudio/probe" &&
        ctx.methodName === "completion"
      ) {
        section = completionSection(ctx, CompletionSchema.parse(record));
      } else if (
        modelType === "@jpisgeek/lmstudio/probe" &&
        ctx.methodName === "capabilities"
      ) {
        section = capabilitySection(ctx, CapabilitySchema.parse(record));
      } else {
        throw new Error(
          "unsupported LM Studio source method",
        );
      }
    } catch (error) {
      if (!(error instanceof z.ZodError)) throw error;
      section = invalidRecordSection(ctx);
    }
  }
  // The producer names the model definition and instance this bundle came
  // from, and both are free-form operator-configured strings. A definition
  // named after the host it points at, or one carrying a key someone pasted
  // into the wrong field, was published here verbatim while the section beside
  // it had every equivalent string screened. They go through the same pass —
  // after identity is derived, which is why sourceIdentity() still hashes the
  // raw values: screening first would map two distinct sources onto one id.
  const producerScreen = new Screen();
  producerScreen.omit("producer.modelName");
  producerScreen.omit("producer.modelId");
  const bundle = {
    schemaVersion: DASHBOARD_BUNDLE_VERSION,
    id: section.id,
    title: "Local inference",
    generatedAt: new Date().toISOString(),
    producer: {
      extension: "@jpisgeek/dashboard-lmstudio",
      extensionVersion: "2026.09.05.1",
      modelType,
      modelName: "lmstudio-observation",
      dataName: "report-jpisgeek-dashboard-lmstudio-json",
      reportName: "@jpisgeek/dashboard-lmstudio",
    },
    state: deriveOverallState([section]),
    sections: [section],
    exceptions: [],
    // The bundle inherits the section's own sensitivity block, because the
    // bundle-level Markdown carries that section's summary. A fixed
    // `redacted: false` here would have contradicted a section that had just
    // redacted a credential out of the very string being republished. The
    // producer's own screening is merged in for the same reason.
    sensitivity: producerScreen.sensitivity(section.sensitivity),
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
  const safe = (value: string) =>
    value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/([\\`*_[\]{}()#+.!|\-])/g, "\\$1").replace(/[\r\n]+/g, " ");
  return `# ${safe(bundle.title)}\n\nState: **${bundle.state}**\n\n- ${
    safe(section.title)
  }: ${safe(section.summary)}`;
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
