/** Normalize @jpisgeek/anthropic-usage snapshots into dashboard bundle v1. */
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
const StatusSchema = z.object({
  state: z.enum(["complete", "partial", "unavailable", "unsupported"]),
  pagesRead: z.number().int().nonnegative(),
  errorKind: z.string(),
  message: z.string(),
});
const RefreshStateSchema = z.enum(["absent", "observed", "invalid"]);
type RefreshState = z.infer<typeof RefreshStateSchema>;
const SnapshotSchema = z.object({
  provider: z.literal("anthropic"),
  accountKind: z.enum(["platform", "enterprise"]),
  collectedAt: z.iso.datetime(),
  coverageStart: z.iso.datetime(),
  coverageEnd: z.iso.datetime(),
  // Required, with no default and no inference from the timestamp beside it,
  // and one pair per dimension.
  //
  // The collector used to discard a present-but-unusable data_refreshed_at and
  // store null, which was also what it stored when Anthropic sent no refresh
  // evidence at all. This report then wrote `observedAt: s.dataRefreshedAt ??
  // s.collectedAt` and labelled the section fresh, so a response whose freshness
  // claim was garbage rendered as a healthy, recently-refreshed dashboard.
  //
  // The pair was also shared by both sections, so a usage timestamp was
  // rendered as the cost section's freshness too. Each section is now drawn
  // from the evidence of the endpoint it reports on, and neither borrows the
  // other's.
  //
  // A snapshot that does not state which of the three cases each dimension is
  // in cannot be rendered honestly, so it does not parse at all: read() returns
  // null and the bundle reports both dimensions unavailable. That is loud and
  // fail-safe, which is the correct direction — inferring "absent" from a null
  // timestamp would silently restore the exact substitution these fields exist
  // to stop.
  usageRefreshedAt: z.iso.datetime().nullable(),
  usageRefreshState: RefreshStateSchema,
  costRefreshedAt: z.iso.datetime().nullable(),
  costRefreshState: RefreshStateSchema,
  usageStatus: StatusSchema,
  costStatus: StatusSchema,
  // The breakdown rows mirror the collector's own row schemas rather than
  // standing in as an array of anything. Only their count is rendered, but a
  // count is a completeness claim: `z.array(z.unknown())` counted whatever
  // happened to be in the array, so a snapshot whose rows were not the rows this
  // report describes still produced an exact-looking "observed" figure.
  // The totals carry the same constraints the collector applied when it wrote
  // them. `z.number()` here was laxer than the writer: a negative or fractional
  // token count — impossible from the collector, so evidence the snapshot was
  // edited or produced by something else — parsed cleanly and was rendered as
  // an observed metric with `confidence: "exact"`. A reader that is more
  // permissive than the writer turns a corrupted file into a confident number.
  usage: z.object({
    uncachedInputTokens: z.number().int().nonnegative(),
    cacheCreation5mTokens: z.number().int().nonnegative(),
    cacheCreation1hTokens: z.number().int().nonnegative(),
    cacheReadTokens: z.number().int().nonnegative(),
    outputTokens: z.number().int().nonnegative(),
    requests: z.number().int().nonnegative().nullable(),
    breakdowns: z.array(z.object({
      product: z.string().nullable(),
      model: z.string().nullable(),
      workspaceId: z.string().nullable(),
      uncachedInputTokens: z.number().int().nonnegative(),
      cacheCreation5mTokens: z.number().int().nonnegative(),
      cacheCreation1hTokens: z.number().int().nonnegative(),
      cacheReadTokens: z.number().int().nonnegative(),
      outputTokens: z.number().int().nonnegative(),
      requests: z.number().int().nonnegative().nullable(),
    })),
    groupedTop100Cap: z.boolean(),
  }).nullable(),
  costs: z.object({
    // The collector retains fractional cents as decimal strings. The report
    // preserves exact strings even when a numeric metric cannot represent one.
    totals: z.array(
      z.object({
        currency: z.string().regex(/^[A-Z]{3}$/),
        amountMinor: z.string().regex(/^\d+(\.\d+)?$/),
      }),
    ),
    breakdowns: z.array(z.object({
      product: z.string().nullable(),
      model: z.string().nullable(),
      workspaceId: z.string().nullable(),
      description: z.string().nullable(),
      amountMinor: z.string().regex(/^\d+(\.\d+)?$/),
      currency: z.string().regex(/^[A-Z]{3}$/),
    })),
    groupedTop100Cap: z.boolean(),
  }).nullable(),
});
type Snapshot = z.infer<typeof SnapshotSchema>;
type Status = z.infer<typeof StatusSchema>;
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
  fields: ["workspaceId", "model", "product", "description"],
  redacted: false,
  note: "Breakdowns can reveal internal workspaces and workloads",
};
/**
 * Bundle-level sensitivity has to cover the producer block as well as the
 * Anthropic breakdowns.
 *
 * `producer.modelName` is the operator's own Swamp model name and
 * `producer.modelId` its instance ID. Neither comes from Anthropic; both name
 * the operator's local infrastructure, and both are written into the exportable
 * dashboard JSON. They were emitted while this field list mentioned only the
 * Anthropic dimensions, so an operator deciding what was safe to publish read a
 * list that omitted the two identifiers describing their own host. The bundle
 * contract requires modelName, so the fix is disclosure rather than omission:
 * anyone who must redact before publishing now knows exactly which paths to
 * strip, and the README says the same thing in prose.
 */
const bundleSensitivity = {
  classification: "operational" as const,
  fields: [
    "workspaceId",
    "model",
    "product",
    "description",
    "producer.modelName",
    "producer.modelId",
  ],
  redacted: false,
  note:
    "Breakdowns can reveal internal workspaces and workloads; the producer block additionally names the local Swamp model and its instance ID",
};
/**
 * Vendor freshness evidence, rendered as the three distinct things it can be.
 *
 * Only an `observed` refresh timestamp produces a fresh observation. An
 * `invalid` one — Anthropic sent a data_refreshed_at that is not a usable
 * timestamp — produces unknown freshness with a reason, which
 * deriveOverallState escalates so the bundle cannot read healthy on freshness
 * evidence that was malformed. `absent` keeps the collection timestamp, because
 * that really is when this observation was made, but says so in the reason
 * instead of presenting it as the vendor's own refresh time.
 */
const REFRESH_INVALID_REASON =
  "Anthropic returned a data refresh timestamp that is not a usable RFC 3339 value, so vendor freshness cannot be established";
function freshness(
  state: RefreshState,
  observed: string | null,
  collectedAt: string,
) {
  if (state === "invalid") {
    return { state: "unknown", reason: REFRESH_INVALID_REASON };
  }
  if (state === "observed" && observed) {
    return { state: "fresh", observedAt: observed };
  }
  return {
    state: "fresh",
    observedAt: collectedAt,
    reason:
      "Anthropic reported no data refresh timestamp for this dimension; this is the collection time, not a vendor refresh time",
  };
}
/** The exception raised on a section whose own freshness evidence is junk. */
function refreshExceptions(state: RefreshState, subject: string) {
  if (state !== "invalid") return [];
  return [{
    id: "anthropic:refresh:invalid-response",
    severity: "warning",
    subject,
    headline: "Vendor refresh timestamp is unreadable",
    detail: REFRESH_INVALID_REASON,
    source: "@jpisgeek/anthropic-usage",
    suppressed: false,
    suppressReason: "",
    sensitivity: "operational",
  }];
}
/** Malformed freshness evidence must not leave its section reading healthy. */
function withRefreshState(
  state: DashboardState,
  refresh: RefreshState,
): DashboardState {
  return refresh === "invalid" && state === "healthy" ? "unknown" : state;
}
/** Decimal string as an exact integer numerator at `places` decimal places. */
function scaled(amountMinor: string, places: number): bigint {
  const [whole, fraction = ""] = amountMinor.split(".");
  return BigInt(whole + fraction.padEnd(places, "0"));
}
/**
 * Whether each stated total is the sum of the breakdown rows under it.
 *
 * A total is a claim about those rows, and this report renders it as an exact
 * observed metric while rendering the row count as exact completeness beside
 * it. The collector derives both from the same rows, so a snapshot where they
 * disagree did not come from the collector this report describes: it was
 * edited, truncated, or written by something else. Rendering it would put a
 * confident figure on the dashboard that nothing underneath supports, so the
 * snapshot is refused whole and both sections report unavailable — the same
 * fail-safe path an unparseable snapshot already takes.
 *
 * Cost is compared as scaled integers rather than as doubles: "0.1" + "0.2" is
 * the textbook case where a float comparison would reject an honest snapshot.
 */
function totalsMatchBreakdowns(s: Snapshot): boolean {
  const usage = s.usage;
  if (usage) {
    const sum = (
      pick: (
        row: NonNullable<Snapshot["usage"]>["breakdowns"][number],
      ) => number,
    ) => usage.breakdowns.reduce((n, row) => n + pick(row), 0);
    if (
      sum((r) => r.uncachedInputTokens) !== usage.uncachedInputTokens ||
      sum((r) => r.cacheCreation5mTokens) !== usage.cacheCreation5mTokens ||
      sum((r) => r.cacheCreation1hTokens) !== usage.cacheCreation1hTokens ||
      sum((r) => r.cacheReadTokens) !== usage.cacheReadTokens ||
      sum((r) => r.outputTokens) !== usage.outputTokens ||
      // Platform reports no request count and stores null for both the total
      // and every row, which is agreement, not a mismatch.
      (usage.requests !== null &&
        sum((r) => r.requests ?? 0) !== usage.requests)
    ) return false;
  }
  const costs = s.costs;
  if (costs) {
    const places = Math.max(
      0,
      ...costs.breakdowns.map((r) =>
        (r.amountMinor.split(".")[1] ?? "").length
      ),
      ...costs.totals.map((t) => (t.amountMinor.split(".")[1] ?? "").length),
    );
    const sums = new Map<string, bigint>();
    for (const row of costs.breakdowns) {
      sums.set(
        row.currency,
        (sums.get(row.currency) ?? 0n) + scaled(row.amountMinor, places),
      );
    }
    // A currency present on one side only is a mismatch in either direction: a
    // total with no rows behind it, or rows whose currency no total covers.
    if (sums.size !== costs.totals.length) return false;
    for (const total of costs.totals) {
      if (sums.get(total.currency) !== scaled(total.amountMinor, places)) {
        return false;
      }
    }
  }
  return true;
}
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
    const snapshot = SnapshotSchema.parse(
      JSON.parse(new TextDecoder().decode(bytes)),
    );
    return totalsMatchBreakdowns(snapshot) ? snapshot : null;
  } catch {
    return null;
  }
}
function unavailable(id: string, title: string, status: Status) {
  const state: DashboardState = status.errorKind === "unauthorized"
    ? "unauthorized"
    : status.state === "unsupported"
    ? "unsupported"
    : "unknown";
  return DashboardSectionSchema.parse({
    id,
    title,
    state,
    impact: "required",
    summary: status.message || `${title} unavailable`,
    coverage: {
      kind: "unknown",
      scope: `Anthropic organization ${id}`,
      notes: status.message || "No authoritative response",
    },
    freshness: { state: "unknown", reason: status.message || "No observation" },
    completeness: {
      state: "unknown",
      reason: status.message || "No authoritative response",
    },
    metrics: [{
      id: `${id}-total`,
      label: `${title} total`,
      unit: id === "costs" ? "currency" : "tokens",
      confidence: "unknown",
      sensitivity: "operational",
      availability: state === "unauthorized"
        ? "unauthorized"
        : state === "unsupported"
        ? "unsupported"
        : "unknown",
      reason: status.message || `${title} unavailable`,
    }],
    facts: [],
    exceptions: [{
      id: `anthropic:${id}:${status.errorKind || status.state}`,
      severity: state === "unauthorized" ? "critical" : "warning",
      subject: title,
      headline: state === "unauthorized"
        ? "Organization credential rejected"
        : state === "unsupported"
        ? "Capability unsupported"
        : `${title} unavailable`,
      detail: status.message || "No authoritative response",
      source: "@jpisgeek/anthropic-usage",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational",
    }],
    references: [],
    sensitivity,
  });
}
function completeness(status: Status, count: number, capped: boolean) {
  if (status.state === "partial" || capped) {
    return {
      state: "partial" as const,
      observed: count,
      reason: status.message ||
        "Grouped Enterprise results are capped at the top 100 groups per bucket",
    };
  }
  return { state: "exact" as const, observed: count, rejected: 0 as const };
}
function usageSection(s: Snapshot) {
  if (!s.usage) return unavailable("usage", "Token usage", s.usageStatus);
  const partial = s.usageStatus.state === "partial" || s.usage.groupedTop100Cap;
  const sectionState: DashboardState =
    s.usageStatus.errorKind === "unauthorized"
      ? "unauthorized"
      : s.usageStatus.errorKind === "unsupported" ||
          s.usageStatus.state === "unsupported"
      ? "unsupported"
      : partial
      ? "partial"
      : "healthy";
  const metrics: Json[] = [
    [
      "uncached-input-tokens",
      "Uncached input tokens",
      s.usage.uncachedInputTokens,
    ],
    [
      "cache-creation-5m-tokens",
      "5-minute cache creation tokens",
      s.usage.cacheCreation5mTokens,
    ],
    [
      "cache-creation-1h-tokens",
      "1-hour cache creation tokens",
      s.usage.cacheCreation1hTokens,
    ],
    ["cache-read-tokens", "Cache read tokens", s.usage.cacheReadTokens],
    ["output-tokens", "Output tokens", s.usage.outputTokens],
  ].map(([id, label, value]) => ({
    id,
    label,
    value,
    unit: "tokens",
    availability: "observed",
    confidence: partial ? "unknown" : "exact",
    sensitivity: "operational",
  }));
  if (s.usage.requests === null) {
    metrics.push({
      id: "requests",
      label: "Requests",
      unit: "requests",
      availability: "unsupported",
      confidence: "unknown",
      sensitivity: "operational",
      reason:
        "The Platform Messages Usage report does not expose request count",
    });
  } else {metrics.push({
      id: "requests",
      label: "Requests",
      value: s.usage.requests,
      unit: "requests",
      availability: "observed",
      confidence: partial ? "unknown" : "exact",
      sensitivity: "operational",
    });}
  return DashboardSectionSchema.parse({
    id: "usage",
    title: "Token usage",
    state: withRefreshState(sectionState, s.usageRefreshState),
    impact: "required",
    summary: `${
      s.usage.uncachedInputTokens + s.usage.outputTokens
    } uncached input plus output tokens`,
    coverage: {
      kind: partial ? "sample" : "exact",
      start: s.coverageStart,
      end: s.coverageEnd,
      scope: `Anthropic ${s.accountKind} organization usage`,
      notes: partial
        ? "Grouped Enterprise buckets may omit groups beyond the documented top-100 cap"
        : undefined,
    },
    freshness: freshness(
      s.usageRefreshState,
      s.usageRefreshedAt,
      s.collectedAt,
    ),
    completeness: completeness(
      s.usageStatus,
      s.usage.breakdowns.length,
      s.usage.groupedTop100Cap,
    ),
    metrics,
    facts: [{
      id: "account-kind",
      label: "Anthropic account kind",
      value: s.accountKind,
      confidence: "exact",
      sensitivity: "operational",
    }],
    exceptions: [
      ...(partial
        ? [{
          id: `anthropic:usage:${s.usageStatus.errorKind || "partial"}`,
          severity: sectionState === "unauthorized" ? "critical" : "warning",
          subject: "Token usage",
          headline: sectionState === "unauthorized"
            ? "Organization API authorization rejected"
            : sectionState === "unsupported"
            ? "Usage capability unsupported"
            : "Usage coverage is partial",
          detail: s.usageStatus.message ||
            "Grouped Enterprise results have a documented top-100 cap",
          source: "@jpisgeek/anthropic-usage",
          suppressed: false,
          suppressReason: "",
          sensitivity: "operational",
        }]
        : []),
      ...refreshExceptions(s.usageRefreshState, "Token usage"),
    ],
    references: [],
    sensitivity,
  });
}
function costSection(s: Snapshot) {
  if (!s.costs) return unavailable("costs", "Authoritative cost", s.costStatus);
  const missing = s.costs.totals.length === 0;
  const partial = s.costStatus.state === "partial" || s.costs.groupedTop100Cap;
  const sectionState: DashboardState = s.costStatus.errorKind === "unauthorized"
    ? "unauthorized"
    : s.costStatus.errorKind === "unsupported" ||
        s.costStatus.state === "unsupported"
    ? "unsupported"
    : partial
    ? "partial"
    : "healthy";
  const metrics: Json[] = s.costs.totals.map((t) => {
    const value = Number(t.amountMinor);
    const canonical = (decimal: string) => {
      const [whole, fraction = ""] = decimal.split(".");
      const tail = fraction.replace(/0+$/, "");
      const head = whole.replace(/^0+(?=\d)/, "");
      return tail ? `${head}.${tail}` : head;
    };
    const common = {
      id: `cost-${t.currency.toLowerCase()}`,
      label: `Cost (${t.currency} minor units)`,
      unit: "custom:currency-minor",
      sensitivity: "operational",
    };
    return Number.isFinite(value) &&
        canonical(String(value)) === canonical(t.amountMinor)
      ? {
        ...common,
        availability: "observed",
        value,
        confidence: partial ? "unknown" : "exact",
      }
      : {
        ...common,
        availability: "unknown",
        confidence: "unknown",
        reason:
          "The exact minor-unit decimal is retained in the summary and fact; it cannot be represented losslessly as a numeric metric",
      };
  });
  if (missing) {
    metrics.push({
      id: "cost-total",
      label: "Cost",
      unit: "currency",
      availability: "unknown",
      confidence: "unknown",
      sensitivity: "operational",
      reason: "No authoritative currency total was returned",
    });
  }
  return DashboardSectionSchema.parse({
    id: "costs",
    title: "Authoritative cost",
    state: missing
      ? "unknown"
      : withRefreshState(sectionState, s.costRefreshState),
    impact: "required",
    summary: missing
      ? "No authoritative currency total was returned"
      : s.costs.totals.map((t) => `${t.amountMinor} ${t.currency} minor units`)
        .join(", "),
    coverage: {
      kind: partial ? "sample" : "exact",
      start: s.coverageStart,
      end: s.coverageEnd,
      scope: `Anthropic ${s.accountKind} organization cost`,
      notes: s.accountKind === "enterprise"
        ? "Amounts are the Cost Report's decimal values in minor units (fractional cents for USD); Enterprise values can be revised for 30 days"
        : "Amounts are the Cost Report's decimal values in minor units (fractional cents for USD)",
    },
    freshness: freshness(s.costRefreshState, s.costRefreshedAt, s.collectedAt),
    completeness: missing
      ? { state: "unknown", reason: "No currency total" }
      : completeness(
        s.costStatus,
        s.costs.breakdowns.length,
        s.costs.groupedTop100Cap,
      ),
    metrics,
    facts: [
      ...s.costs.totals.map((t) => ({
        id: `cost-${t.currency.toLowerCase()}-exact`,
        label: `Exact cost (${t.currency} minor units)`,
        value: t.amountMinor,
        confidence: partial ? "unknown" : "exact",
        sensitivity: "operational",
      })),
      {
        id: "currency-count",
        label: "Currencies observed",
        value: s.costs.totals.length,
        confidence: partial ? "unknown" : "exact",
        sensitivity: "operational",
      },
    ],
    exceptions: [
      ...(partial
        ? [{
          id: `anthropic:costs:${s.costStatus.errorKind || "partial"}`,
          severity: sectionState === "unauthorized" ? "critical" : "warning",
          subject: "Authoritative cost",
          headline: sectionState === "unauthorized"
            ? "Organization API authorization rejected"
            : sectionState === "unsupported"
            ? "Cost capability unsupported"
            : "Cost coverage is partial",
          detail: s.costStatus.message ||
            "Grouped Enterprise results have a documented top-100 cap",
          source: "@jpisgeek/anthropic-usage",
          suppressed: false,
          suppressReason: "",
          sensitivity: "operational",
        }]
        : []),
      ...refreshExceptions(s.costRefreshState, "Authoritative cost"),
    ],
    references: [],
    sensitivity,
  });
}
/** Stable producer namespace; a full digest avoids raw model IDs in bundle IDs. */
async function bundleId(modelId: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(
      `@jpisgeek/anthropic-usage\0bundle-id\0${modelId}`,
    ),
  );
  const hex = Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
  return `anthropic-organization-${hex}`;
}

export async function normalize(ctx: Context): Promise<DashboardBundleV1> {
  const s = await read(ctx);
  const missing: Status = {
    state: "unavailable",
    pagesRead: 0,
    errorKind: "invalid-response",
    message: "No valid Anthropic organization snapshot was available",
  };
  const sections = s ? [usageSection(s), costSection(s)] : [
    unavailable("usage", "Token usage", missing),
    unavailable("costs", "Authoritative cost", missing),
  ];
  return DashboardBundleV1Schema.parse({
    schemaVersion: DASHBOARD_BUNDLE_VERSION,
    id: await bundleId(ctx.modelId),
    title: "Anthropic organization usage",
    generatedAt: new Date().toISOString(),
    producer: {
      extension: "@jpisgeek/anthropic-usage",
      extensionVersion: "2026.09.05.1",
      modelType: String(ctx.modelType),
      modelName: ctx.definition.name,
      modelId: ctx.modelId,
      dataName: "report-jpisgeek-anthropic-usage-json",
      reportName: "@jpisgeek/anthropic-usage",
    },
    state: deriveOverallState(sections),
    sections,
    exceptions: [],
    sensitivity: bundleSensitivity,
    extensions: {
      "jpisgeek/anthropic-usage": {
        accountKind: s?.accountKind ?? "unknown",
        subscriptionQuotaInferred: false,
        // Reports whether THIS snapshot actually hit the cap. It used to be
        // `accountKind === "enterprise"`, which asserted truncation on every
        // Enterprise bundle including complete ones.
        groupedEnterpriseTop100Cap: Boolean(s?.usage?.groupedTop100Cap) ||
          Boolean(s?.costs?.groupedTop100Cap),
      },
    },
  });
}
export const report = {
  name: "@jpisgeek/anthropic-usage",
  description:
    "Normalize Anthropic Platform or Enterprise usage and cost into dashboard bundle v1.",
  scope: "method" as const,
  labels: ["dashboard", "anthropic", "usage", "cost"],
  execute: async (context: Context) => {
    const bundle = await normalize(context);
    return {
      markdown: `# ${bundle.title}\n\nState: **${bundle.state}**\n\n${
        bundle.sections.map((s) => `- ${s.title}: ${s.state} — ${s.summary}`)
          .join("\n")
      }`,
      json: bundle,
    };
  },
};
