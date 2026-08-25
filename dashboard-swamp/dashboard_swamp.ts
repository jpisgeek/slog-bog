/** Normalize scoped @jpisgeek/swamp-observability snapshots into bundle v1. */
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

const InterfaceNameSchema = z.enum([
  "run-history",
  "run-doctor",
  "workflow-history",
  "stored-reports",
  "serve-heartbeat",
]);

const ObservationSchema = z.object({
  interface: InterfaceNameSchema,
  available: z.boolean(),
  observedAt: z.iso.datetime(),
  errorKind: z.enum([
    "",
    "unsupported",
    "unauthorized",
    "timeout",
    "unreachable",
    "invalid-response",
    "command-failed",
  ]),
  error: z.string(),
  payload: z.json().nullable(),
});

type Observation = z.infer<typeof ObservationSchema>;

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
  executionStatus: "succeeded" | "failed";
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

const sensitivity = {
  classification: "operational" as const,
  fields: [] as string[],
  redacted: false,
};

function arrayFrom(payload: unknown, key: string): Json[] {
  if (Array.isArray(payload)) return payload.filter(isJson);
  if (isJson(payload) && Array.isArray(payload[key])) {
    return payload[key].filter(isJson);
  }
  return [];
}

function isJson(value: unknown): value is Json {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function statusOf(value: Json): string {
  for (const key of ["status", "state", "outcome"]) {
    if (typeof value[key] === "string") return value[key].toLowerCase();
  }
  return "unknown";
}

function unavailableState(observation: Observation): DashboardState {
  return observation.errorKind === "unauthorized" ? "unauthorized" : "partial";
}

function unavailableSection(observation: Observation, title: string) {
  const state = unavailableState(observation);
  return DashboardSectionSchema.parse({
    id: observation.interface,
    title,
    state,
    impact: "required",
    summary: observation.error,
    coverage: {
      kind: "unknown",
      scope: observation.interface,
      notes: observation.error,
    },
    freshness: {
      state: "unknown",
      reason: observation.error,
    },
    completeness: { state: "unknown", reason: observation.error },
    metrics: [],
    facts: [{
      id: "interface-available",
      label: "Interface available",
      value: false,
      confidence: "exact",
      sensitivity: "operational",
    }],
    exceptions: [{
      id: `swamp:${observation.interface}:${observation.errorKind}`,
      severity: observation.errorKind === "unauthorized"
        ? "critical"
        : "warning",
      subject: title,
      headline: observation.errorKind === "unsupported"
        ? "Interface unsupported"
        : "Interface unavailable",
      detail: observation.error,
      source: "@jpisgeek/swamp-observability",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational",
    }],
    references: [],
    sensitivity,
  });
}

function historySection(
  observation: Observation,
  title: string,
  key: string,
) {
  if (!observation.available) return unavailableSection(observation, title);
  const entries = arrayFrom(observation.payload, key);
  const counts = {
    active: 0,
    succeeded: 0,
    failed: 0,
    stale: 0,
    orphaned: 0,
    unknown: 0,
  };
  for (const entry of entries) {
    if (entry.stale === true) {
      counts.stale++;
      continue;
    }
    if (entry.orphaned === true) {
      counts.orphaned++;
      continue;
    }
    const status = statusOf(entry);
    if (/running|active|queued|pending/.test(status)) counts.active++;
    else if (/success|succeeded|completed|passed/.test(status)) {
      counts.succeeded++;
    } else if (/fail|failed|error|cancel/.test(status)) counts.failed++;
    else if (/stale/.test(status)) counts.stale++;
    else if (/orphan/.test(status)) counts.orphaned++;
    else counts.unknown++;
  }
  const state: DashboardState = entries.length === 0
    ? "unknown"
    : counts.stale > 0 || counts.orphaned > 0
    ? "critical"
    : counts.failed > 0 || counts.unknown > 0
    ? "degraded"
    : "healthy";
  const exceptions = [];
  if (entries.length === 0) {
    exceptions.push({
      id: `swamp:${observation.interface}:empty`,
      severity: "info",
      subject: title,
      headline: "No history observed",
      detail: "The interface responded successfully but returned no history.",
      source: "@jpisgeek/swamp-observability",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational",
    });
  }
  if (counts.failed > 0) {
    exceptions.push({
      id: `swamp:${observation.interface}:failed`,
      severity: "warning",
      subject: title,
      headline: "Failed executions observed",
      detail: `${counts.failed} execution(s) have a failed outcome.`,
      source: "@jpisgeek/swamp-observability",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational",
    });
  }
  if (counts.stale + counts.orphaned > 0) {
    exceptions.push({
      id: `swamp:${observation.interface}:stale-or-orphaned`,
      severity: "critical",
      subject: title,
      headline: "Stale or orphaned executions observed",
      detail:
        `${counts.stale} stale and ${counts.orphaned} orphaned execution(s).`,
      source: "@jpisgeek/swamp-observability",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational",
    });
  }
  return DashboardSectionSchema.parse({
    id: observation.interface,
    title,
    state,
    impact: "required",
    summary: entries.length === 0
      ? "History is available but empty"
      : `${entries.length} execution record(s) observed`,
    coverage: {
      kind: "exact",
      end: observation.observedAt,
      scope: `records returned by ${observation.interface}`,
    },
    freshness: {
      state: "fresh",
      observedAt: observation.observedAt,
      maxAgeSeconds: 300,
    },
    completeness: { state: "exact", observed: entries.length, rejected: 0 },
    metrics: Object.entries(counts).map(([id, value]) => ({
      id,
      label: id[0].toUpperCase() + id.slice(1),
      unit: "count",
      availability: "observed",
      value,
      confidence: "exact",
      sensitivity: "operational",
    })),
    facts: [],
    exceptions,
    references: [],
    sensitivity,
  });
}

function reportsSection(observation: Observation) {
  const title = "Stored reports";
  if (!observation.available) return unavailableSection(observation, title);
  const entries = arrayFrom(observation.payload, "results");
  const hasStatus = entries.length > 0 &&
    entries.every((entry) => statusOf(entry) !== "unknown");
  const state: DashboardState = entries.length === 0
    ? "unknown"
    : hasStatus
    ? "healthy"
    : "partial";
  return DashboardSectionSchema.parse({
    id: "stored-reports",
    title,
    state,
    impact: "required",
    summary: entries.length === 0
      ? "Report inventory is available but empty"
      : hasStatus
      ? `${entries.length} stored report(s) with status observed`
      : `${entries.length} stored report(s) observed; result status is unavailable`,
    coverage: {
      kind: hasStatus ? "exact" : "unknown",
      end: observation.observedAt,
      scope: "stored report inventory and exposed status fields",
      ...(hasStatus
        ? {}
        : { notes: "report search does not expose result status" }),
    },
    freshness: {
      state: "fresh",
      observedAt: observation.observedAt,
      maxAgeSeconds: 300,
    },
    completeness: hasStatus
      ? { state: "exact", observed: entries.length, rejected: 0 }
      : {
        state: "partial",
        observed: entries.length,
        reason: "stored report result status is unavailable",
      },
    metrics: [
      {
        id: "stored",
        label: "Stored reports",
        unit: "count",
        availability: "observed",
        value: entries.length,
        confidence: "exact",
        sensitivity: "operational",
      },
      hasStatus
        ? {
          id: "status-known",
          label: "Reports with known status",
          unit: "count",
          availability: "observed",
          value: entries.length,
          confidence: "exact",
          sensitivity: "operational",
        }
        : {
          id: "status-known",
          label: "Reports with known status",
          unit: "count",
          availability: "unsupported",
          reason: "report search does not expose result status",
          confidence: "unknown",
          sensitivity: "operational",
        },
    ],
    facts: [],
    exceptions: entries.length === 0
      ? [{
        id: "swamp:stored-reports:empty",
        severity: "info",
        subject: title,
        headline: "No stored reports observed",
        detail:
          "The interface responded successfully but returned no stored reports.",
        source: "@jpisgeek/swamp-observability",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational",
      }]
      : hasStatus
      ? []
      : [{
        id: "swamp:stored-reports:status-unsupported",
        severity: "warning",
        subject: title,
        headline: "Stored report status unavailable",
        detail:
          "The public report search result identifies artifacts but does not expose their execution status.",
        source: "@jpisgeek/swamp-observability",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational",
      }],
    references: [],
    sensitivity,
  });
}

function doctorSection(observation: Observation) {
  if (!observation.available) {
    return unavailableSection(observation, "Run diagnostics");
  }
  const payload = isJson(observation.payload) ? observation.payload : {};
  const number = (key: string) =>
    typeof payload[key] === "number" ? payload[key] : undefined;
  const stale = number("stale") ?? 0;
  const orphaned = number("orphaned");
  const active = number("active") ?? 0;
  const tracked = number("totalTracked") ?? 0;
  const state: DashboardState = stale + (orphaned ?? 0) > 0
    ? "critical"
    : orphaned === undefined
    ? "partial"
    : tracked === 0
    ? "unknown"
    : "healthy";
  return DashboardSectionSchema.parse({
    id: "run-doctor",
    title: "Run diagnostics",
    state,
    impact: "required",
    summary: orphaned === undefined
      ? `${tracked} run(s) diagnosed; orphan count is unavailable`
      : tracked === 0
      ? "No tracked runs to diagnose"
      : `${tracked} run(s) diagnosed`,
    coverage: {
      kind: orphaned === undefined ? "unknown" : "exact",
      end: observation.observedAt,
      scope: "run doctor snapshot",
      ...(orphaned === undefined
        ? { notes: "run doctor did not expose an orphan count" }
        : {}),
    },
    freshness: {
      state: "fresh",
      observedAt: observation.observedAt,
      maxAgeSeconds: 300,
    },
    completeness: orphaned === undefined
      ? {
        state: "partial",
        observed: tracked,
        reason: "orphan count is unavailable",
      }
      : { state: "exact", observed: tracked, rejected: 0 },
    metrics: [
      ...[
        ["tracked", "Tracked", tracked],
        ["active", "Active", active],
        ["stale", "Stale", stale],
      ].map(([id, label, value]) => ({
        id,
        label,
        unit: "count",
        availability: "observed",
        value,
        confidence: "exact",
        sensitivity: "operational",
      })),
      orphaned === undefined
        ? {
          id: "orphaned",
          label: "Orphaned",
          unit: "count",
          availability: "unsupported",
          reason: "run doctor did not expose an orphan count",
          confidence: "unknown",
          sensitivity: "operational",
        }
        : {
          id: "orphaned",
          label: "Orphaned",
          unit: "count",
          availability: "observed",
          value: orphaned,
          confidence: "exact",
          sensitivity: "operational",
        },
    ],
    facts: [],
    exceptions: stale + (orphaned ?? 0) > 0
      ? [{
        id: "swamp:run-doctor:stale-or-orphaned",
        severity: "critical",
        subject: "Run diagnostics",
        headline: "Stale or orphaned runs require attention",
        detail: `${stale} stale and ${orphaned ?? 0} orphaned run(s).`,
        source: "@jpisgeek/swamp-observability",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational",
      }]
      : orphaned === undefined
      ? [{
        id: "swamp:run-doctor:orphan-count-unsupported",
        severity: "warning",
        subject: "Run diagnostics",
        headline: "Orphan count unavailable",
        detail: "The public run doctor result did not expose an orphan count.",
        source: "@jpisgeek/swamp-observability",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational",
      }]
      : [],
    references: [],
    sensitivity,
  });
}

async function readObservations(ctx: ReportContext): Promise<Observation[]> {
  const observations: Observation[] = [];
  for (const handle of ctx.dataHandles) {
    if (
      handle.specName !== "observation" && !handle.name.startsWith("interface-")
    ) continue;
    const content = await ctx.dataRepository.getContent(
      ctx.modelType,
      ctx.modelId,
      handle.name,
      handle.version,
    );
    if (!content) continue;
    observations.push(
      ObservationSchema.parse(JSON.parse(new TextDecoder().decode(content))),
    );
  }
  return observations;
}

/** Normalize a completed observe execution into dashboard bundle v1. */
export async function normalize(
  ctx: ReportContext,
): Promise<DashboardBundleV1> {
  if (String(ctx.modelType) !== "@jpisgeek/swamp-observability") {
    throw new Error(
      `unsupported Swamp observability source ${String(ctx.modelType)}`,
    );
  }
  const observations = await readObservations(ctx);
  const byName = new Map(observations.map((item) => [item.interface, item]));
  const missing = (name: Observation["interface"]): Observation => ({
    interface: name,
    available: false,
    observedAt: new Date().toISOString(),
    errorKind: "invalid-response",
    error: "The collector did not return this required interface snapshot",
    payload: null,
  });
  const sections = [
    historySection(
      byName.get("run-history") ?? missing("run-history"),
      "Model and workflow runs",
      "runs",
    ),
    doctorSection(byName.get("run-doctor") ?? missing("run-doctor")),
    historySection(
      byName.get("workflow-history") ?? missing("workflow-history"),
      "Workflow history",
      "results",
    ),
    reportsSection(byName.get("stored-reports") ?? missing("stored-reports")),
    unavailableSection(
      byName.get("serve-heartbeat") ?? missing("serve-heartbeat"),
      "Serve heartbeat",
    ),
  ];
  const bundle = {
    schemaVersion: DASHBOARD_BUNDLE_VERSION,
    id: "swamp-observability",
    title: "Swamp observability",
    generatedAt: new Date().toISOString(),
    producer: {
      extension: "@jpisgeek/dashboard-swamp",
      extensionVersion: "2026.08.25.1",
      modelType: String(ctx.modelType),
      modelName: ctx.definition.name,
      modelId: ctx.modelId,
      dataName: "report-jpisgeek-dashboard-swamp-json",
      reportName: "@jpisgeek/dashboard-swamp",
    },
    state: deriveOverallState(sections),
    sections,
    exceptions: [],
    sensitivity,
    extensions: {
      "jpisgeek/swamp-observability": {
        interfacesExpected: 5,
        interfacesObserved: observations.length,
        internalRunsApiUsed: false,
      },
    },
  };
  return DashboardBundleV1Schema.parse(bundle);
}

function markdown(bundle: DashboardBundleV1): string {
  const lines = [`# ${bundle.title}`, "", `State: **${bundle.state}**`, ""];
  for (const section of bundle.sections) {
    lines.push(`- ${section.title}: ${section.state} — ${section.summary}`);
  }
  return lines.join("\n");
}

/** Swamp dashboard normalization report. */
export const report = {
  name: "@jpisgeek/dashboard-swamp",
  description:
    "Normalize documented Swamp operational interfaces into dashboard bundle v1.",
  scope: "method" as const,
  labels: ["dashboard", "observability", "swamp"],
  execute: async (context: ReportContext) => {
    const bundle = await normalize(context);
    return { markdown: markdown(bundle), json: bundle };
  },
};
