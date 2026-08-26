/** Normalize @jpisgeek homelab collector resources into dashboard bundle v1. */
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

type Json = Record<string, unknown>;

interface DataHandle {
  name: string;
  specName?: string;
  version?: number;
  tags?: Record<string, string>;
  metadata?: { tags?: Record<string, string> };
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

function modelTypeName(ctx: ReportContext): string {
  return String(ctx.modelType);
}

const sensitivity = {
  classification: "operational" as const,
  fields: [] as string[],
  redacted: false,
};

const common = {
  references: [] as never[],
  sensitivity,
};

const NetdataNode = z.object({
  name: z.string(),
  url: z.string(),
  reachable: z.boolean(),
  error: z.string(),
  transport: z.string(),
  version: z.string().nullable(),
  hostname: z.string().nullable(),
  osName: z.string().nullable(),
  osVersion: z.string().nullable(),
  cores: z.number(),
  collectors: z.number(),
  charts: z.number(),
  alarmsActive: z.number(),
  alarmsCritical: z.number(),
  alarmsWarning: z.number(),
  claimedToCloud: z.boolean(),
  mountsOverThreshold: z.number(),
});
const NetdataAlarm = z.object({
  node: z.string(),
  name: z.string(),
  chart: z.string(),
  status: z.string(),
  value: z.number(),
  units: z.string(),
  info: z.string(),
});
const NetdataMount = z.object({
  node: z.string(),
  mount: z.string(),
  availGiB: z.number(),
  usedGiB: z.number(),
  totalGiB: z.number(),
  usedPercent: z.number(),
  overThreshold: z.boolean(),
});
const NetdataSummary = z.object({
  nodes: z.number(),
  nodesReachable: z.number(),
  nodesUnreachable: z.number(),
  nodesDegraded: z.number(),
  alarmsActive: z.number(),
  alarmsCritical: z.number(),
  mountsOverThreshold: z.number(),
  syncedAt: z.iso.datetime(),
});

const TrueNasSystem = z.object({
  hostname: z.string(),
  version: z.string(),
  model: z.string(),
  cores: z.number(),
  physmemBytes: z.number(),
  uptimeSeconds: z.number(),
  loadavg: z.array(z.number()),
});
const TrueNasPool = z.object({
  name: z.string(),
  status: z.string(),
  healthy: z.boolean(),
  allocatedBytes: z.number(),
  freeBytes: z.number(),
  sizeBytes: z.number(),
  usedPercent: z.number(),
  fragmentationPercent: z.number(),
});
const TrueNasDisk = z.object({
  name: z.string(),
  serial: z.string(),
  model: z.string(),
  sizeBytes: z.number(),
  type: z.string(),
  pool: z.string(),
});
const TrueNasAlert = z.object({
  id: z.string(),
  klass: z.string(),
  level: z.string(),
  formatted: z.string(),
  dismissed: z.boolean(),
  silenced: z.boolean(),
});
const TrueNasCertificate = z.object({
  name: z.string(),
  commonName: z.string(),
  notAfter: z.string(),
  daysRemaining: z.number(),
  expiryKnown: z.boolean(),
  expiringSoon: z.boolean(),
  expired: z.boolean(),
});
const TrueNasSummary = z.object({
  hostname: z.string(),
  version: z.string(),
  pools: z.number(),
  poolsUnhealthy: z.number(),
  disks: z.number(),
  alerts: z.number(),
  alertsSilenced: z.number(),
  certificates: z.number(),
  certificatesExpiringSoon: z.number(),
  certificatesExpired: z.number(),
  certificatesWithoutExpiry: z.number(),
  syncedAt: z.iso.datetime(),
});

const FirewallaDevice = z.object({
  id: z.string(),
  gid: z.string().optional(),
  name: z.string(),
  ip: z.string().optional(),
  mac: z.string(),
  macVendor: z.string(),
  deviceType: z.string(),
  network: z.string(),
  online: z.boolean(),
  ipReserved: z.boolean(),
  isRouter: z.boolean(),
  isFirewalla: z.boolean(),
  totalDownload: z.number(),
  totalUpload: z.number(),
  tier: z.string(),
  sshCandidate: z.boolean(),
  excluded: z.boolean(),
});
const FirewallaMachine = z.object({
  name: z.string(),
  primaryIp: z.string(),
  deviceType: z.string(),
  macVendor: z.string(),
  tier: z.string(),
  sshCandidate: z.boolean(),
  online: z.boolean(),
  networks: z.array(z.string()),
  interfaces: z.array(z.object({
    name: z.string(),
    ip: z.string(),
    mac: z.string(),
    network: z.string(),
    online: z.boolean(),
  })),
  interfaceCount: z.number(),
  dependsOn: z.string().optional(),
});
const FirewallaInventory = z.object({
  mspDomain: z.string(),
  total: z.number(),
  online: z.number(),
  offline: z.number(),
  deep: z.number(),
  presence: z.number(),
  reserved: z.number(),
  skippedByNetwork: z.number(),
  excludedNetworks: z.array(z.string()),
  machines: z.number(),
  sshCandidates: z.number(),
  excluded: z.number(),
  networks: z.array(z.string()),
  deviceTypes: z.record(z.string(), z.number()),
  syncedAt: z.iso.datetime(),
});

const sourceSchemas: Record<string, Record<string, z.ZodType>> = {
  "@jpisgeek/netdata": {
    node: NetdataNode,
    alarm: NetdataAlarm,
    mount: NetdataMount,
    summary: NetdataSummary,
  },
  "@jpisgeek/truenas": {
    system: TrueNasSystem,
    pool: TrueNasPool,
    disk: TrueNasDisk,
    alert: TrueNasAlert,
    certificate: TrueNasCertificate,
    summary: TrueNasSummary,
  },
  "@jpisgeek/firewalla": {
    device: FirewallaDevice,
    machine: FirewallaMachine,
    inventory: FirewallaInventory,
  },
};

interface ReadResult {
  records: Record<string, Json[]>;
  rejected: number;
  rejectionDetails: string[];
}

function specName(handle: DataHandle): string | undefined {
  return handle.specName ?? handle.tags?.specName ??
    handle.metadata?.tags?.specName;
}

async function readRecords(ctx: ReportContext): Promise<ReadResult> {
  const schemas = sourceSchemas[modelTypeName(ctx)];
  const records: Record<string, Json[]> = Object.fromEntries(
    Object.keys(schemas).map((name) => [name, []]),
  );
  const rejectionDetails: string[] = [];

  for (const handle of ctx.dataHandles) {
    const spec = specName(handle);
    if (!spec || !schemas[spec]) {
      rejectionDetails.push(`${handle.name}: unknown resource type`);
      continue;
    }
    try {
      const bytes = await ctx.dataRepository.getContent(
        ctx.modelType,
        ctx.modelId,
        handle.name,
        handle.version,
      );
      if (!bytes) throw new Error("content unavailable");
      let value: unknown;
      try {
        value = JSON.parse(new TextDecoder().decode(bytes));
      } catch {
        throw new Error("invalid JSON");
      }
      const parsed = schemas[spec].safeParse(value);
      if (!parsed.success) throw new Error("source schema validation failed");
      records[spec].push(parsed.data as Json);
    } catch (error) {
      rejectionDetails.push(`${handle.name}: ${(error as Error).message}`);
    }
  }
  return { records, rejected: rejectionDetails.length, rejectionDetails };
}

function stableId(prefix: string, ...parts: string[]): string {
  let hash = 0xcbf29ce484222325n;
  const raw = parts.map((part) => `${part.length}:${part}`).join("");
  for (let i = 0; i < raw.length; i++) {
    hash ^= BigInt(raw.charCodeAt(i));
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }
  return `${prefix}:${hash.toString(16).padStart(16, "0")}`;
}

function severity(level: string): "critical" | "warning" | "info" {
  const normalized = level.toUpperCase();
  if (["CRITICAL", "ALERT", "EMERGENCY"].includes(normalized)) {
    return "critical";
  }
  return normalized === "WARNING" ? "warning" : "info";
}

function freshness(observedAt: string | undefined) {
  if (!observedAt) {
    return {
      state: "unknown" as const,
      reason: "summary timestamp unavailable",
    };
  }
  const maxAgeSeconds = 900;
  const stale = Date.now() - Date.parse(observedAt) > maxAgeSeconds * 1000;
  return stale
    ? {
      state: "stale" as const,
      observedAt,
      maxAgeSeconds,
      reason: "collector summary is older than 15 minutes",
    }
    : { state: "fresh" as const, observedAt, maxAgeSeconds };
}

function completeness(rejected: number, reason?: string) {
  return rejected > 0
    ? { state: "partial" as const, rejected, reason: reason! }
    : { state: "exact" as const, rejected: 0 as const };
}

function executionUnauthorized(ctx: ReportContext): boolean {
  return ctx.executionStatus === "failed" &&
    /unauthor|forbidden|authentication|\b401\b|\b403\b/i.test(
      ctx.errorMessage ?? "",
    );
}

interface NormalizedException {
  id: string;
  severity: "critical" | "warning" | "info";
  subject: string;
  headline: string;
  detail: string;
  source: string;
  suppressed: boolean;
  suppressReason: string;
  sensitivity: "operational";
}

function sourceFailureExceptions(
  ctx: ReportContext,
  read: ReadResult,
): NormalizedException[] {
  const exceptions: NormalizedException[] = read.rejectionDetails.map((
    detail,
    index,
  ) => ({
    id: stableId("source-record-rejected", String(index), detail),
    severity: "warning" as const,
    subject: ctx.definition.name,
    headline: "Collector record rejected",
    detail,
    source: modelTypeName(ctx),
    suppressed: false,
    suppressReason: "",
    sensitivity: "operational" as const,
  }));
  if (ctx.executionStatus === "failed") {
    const unauthorized = executionUnauthorized(ctx);
    exceptions.push({
      id: stableId("collector-execution-failed", ctx.modelId, ctx.methodName),
      severity: unauthorized ? "warning" : "critical",
      subject: ctx.definition.name,
      headline: "Collector execution failed",
      detail: unauthorized
        ? "collector authentication or authorization failed; inspect the Swamp run log"
        : "collector execution failed; inspect the Swamp run log",
      source: modelTypeName(ctx),
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational",
    });
  }
  return exceptions;
}

function netdataSection(ctx: ReportContext, read: ReadResult) {
  const nodes = read.records.node as z.infer<typeof NetdataNode>[];
  const alarms = read.records.alarm as z.infer<typeof NetdataAlarm>[];
  const mounts = read.records.mount as z.infer<typeof NetdataMount>[];
  const summary = (read.records.summary as z.infer<typeof NetdataSummary>[])[0];
  const mismatch = summary && (
    summary.nodes !== nodes.length ||
    summary.nodesReachable !== nodes.filter((node) => node.reachable).length ||
    summary.nodesUnreachable !==
      nodes.filter((node) => !node.reachable).length ||
    summary.alarmsActive !== alarms.length ||
    summary.alarmsCritical !==
      alarms.filter((alarm) => severity(alarm.status) === "critical").length ||
    summary.mountsOverThreshold !== mounts.filter((m) => m.overThreshold).length
  );
  const exceptions = [
    ...nodes.filter((n) => !n.reachable).map((n) => ({
      id: stableId("netdata-node", n.name),
      severity: "critical" as const,
      subject: n.name,
      headline: "Netdata node unreachable",
      detail: n.error || "node did not answer",
      source: "netdata:node",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    })),
    ...alarms.map((a) => ({
      id: stableId("netdata-alarm", a.node, a.chart, a.name),
      severity: severity(a.status),
      subject: a.node,
      headline: a.name,
      detail: a.info || `${a.value} ${a.units}`,
      source: "netdata:alarm",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    })),
    ...mounts.filter((m) => m.overThreshold).map((m) => ({
      id: stableId("netdata-mount", m.node, m.mount),
      severity: "warning" as const,
      subject: m.node,
      headline: "Filesystem above threshold",
      detail: `${m.mount} is ${m.usedPercent}% used`,
      source: "netdata:mount",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    })),
    ...sourceFailureExceptions(ctx, read),
    ...(mismatch
      ? [{
        id: "netdata:summary-record-mismatch",
        severity: "warning" as const,
        subject: "Netdata coverage",
        headline: "Summary and record coverage differ",
        detail: "Collector summary counts do not match the available records.",
        source: "netdata:summary",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational" as const,
      }]
      : []),
  ];
  const rejected = read.rejected + (summary ? 0 : 1) +
    (summary?.nodesDegraded ?? 0) + (mismatch ? 1 : 0);
  const fresh = freshness(summary?.syncedAt);
  let state: DashboardState = exceptions.some((e) => e.severity === "critical")
    ? "critical"
    : exceptions.some((e) => e.severity === "warning")
    ? "degraded"
    : "healthy";
  if (rejected > 0 && state !== "critical") state = "partial";
  if (fresh.state !== "fresh" && state === "healthy") state = fresh.state;
  if (executionUnauthorized(ctx)) state = "unauthorized";
  return {
    id: "netdata",
    title: "Netdata",
    state,
    impact: "required" as const,
    summary: summary
      ? `${summary.nodesReachable}/${summary.nodes} nodes reachable`
      : "Netdata summary unavailable",
    coverage: { kind: "exact" as const, scope: "collector execution handles" },
    freshness: fresh,
    completeness: completeness(
      rejected,
      "records rejected, missing, or carried forward",
    ),
    metrics: [
      ...(summary
        ? [{
          id: "nodes.reachable",
          label: "Reachable nodes",
          unit: "count" as const,
          confidence: "exact" as const,
          availability: "observed" as const,
          value: summary.nodesReachable,
          sensitivity: "operational" as const,
        }]
        : []),
    ],
    facts: [],
    exceptions,
    ...common,
  };
}

function trueNasSection(ctx: ReportContext, read: ReadResult) {
  const pools = read.records.pool as z.infer<typeof TrueNasPool>[];
  const disks = read.records.disk as z.infer<typeof TrueNasDisk>[];
  const alerts = read.records.alert as z.infer<typeof TrueNasAlert>[];
  const certs = read.records.certificate as z.infer<
    typeof TrueNasCertificate
  >[];
  const summary = (read.records.summary as z.infer<typeof TrueNasSummary>[])[0];
  const mismatch = summary && (
    summary.pools !== pools.length ||
    summary.poolsUnhealthy !== pools.filter((p) => !p.healthy).length ||
    summary.disks !== disks.length || summary.alerts !== alerts.length ||
    summary.alertsSilenced !==
      alerts.filter((alert) => alert.silenced).length ||
    summary.certificates !== certs.length ||
    summary.certificatesExpiringSoon !==
      certs.filter((certificate) => certificate.expiringSoon).length ||
    summary.certificatesExpired !==
      certs.filter((certificate) => certificate.expired).length ||
    summary.certificatesWithoutExpiry !==
      certs.filter((certificate) => !certificate.expiryKnown).length
  );
  const exceptions = [
    ...pools.filter((p) => !p.healthy).map((p) => ({
      id: stableId("truenas-pool", p.name),
      severity: "critical" as const,
      subject: p.name,
      headline: "Storage pool unhealthy",
      detail: p.status,
      source: "truenas:pool",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    })),
    ...certs.filter((c) => c.expired || c.expiringSoon).map((c) => ({
      id: stableId("truenas-certificate", c.name),
      severity: c.expired ? "critical" as const : "warning" as const,
      subject: c.name,
      headline: c.expired ? "Certificate expired" : "Certificate expiring soon",
      detail: c.expiryKnown
        ? `${c.daysRemaining} days remaining; expires ${c.notAfter}`
        : "certificate expiry is unknown",
      source: "truenas:certificate",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    })),
    ...certs.filter((c) => !c.expiryKnown).map((c) => ({
      id: stableId("truenas-certificate-unknown", c.name),
      severity: "warning" as const,
      subject: c.name,
      headline: "Certificate expiry unknown",
      detail: "The collector could not determine this certificate's expiry.",
      source: "truenas:certificate",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    })),
    // Alert records expose no stable certificate identifier. Preserve every
    // alert independently instead of attaching it to the first certificate.
    ...alerts.map((a) => ({
      id: stableId("truenas-alert", a.id),
      severity: severity(a.level),
      subject: a.klass,
      headline: a.klass,
      detail: a.formatted,
      source: "truenas:alert",
      suppressed: a.silenced,
      suppressReason: a.silenced ? "silenced in TrueNAS" : "",
      sensitivity: "operational" as const,
    })),
    ...sourceFailureExceptions(ctx, read),
    ...(mismatch
      ? [{
        id: "truenas:summary-record-mismatch",
        severity: "warning" as const,
        subject: "TrueNAS coverage",
        headline: "Summary and record coverage differ",
        detail: "Collector summary counts do not match the available records.",
        source: "truenas:summary",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational" as const,
      }]
      : []),
  ];
  const rejected = read.rejected + (summary ? 0 : 1) + (mismatch ? 1 : 0);
  const fresh = freshness(summary?.syncedAt);
  let state: DashboardState =
    exceptions.some((e) => !e.suppressed && e.severity === "critical")
      ? "critical"
      : exceptions.some((e) => !e.suppressed && e.severity === "warning")
      ? "degraded"
      : "healthy";
  if (rejected > 0 && state !== "critical") state = "partial";
  if (fresh.state !== "fresh" && state === "healthy") state = fresh.state;
  if (executionUnauthorized(ctx)) state = "unauthorized";
  return {
    id: "truenas",
    title: "TrueNAS",
    state,
    impact: "required" as const,
    summary: summary
      ? `${
        summary.pools - summary.poolsUnhealthy
      }/${summary.pools} pools healthy`
      : "TrueNAS summary unavailable",
    coverage: { kind: "exact" as const, scope: "collector execution handles" },
    freshness: fresh,
    completeness: completeness(rejected, "records rejected or summary missing"),
    metrics: pools.map((p) => ({
      id: `pool.${p.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.${
        stableId("pool", p.name).split(":")[1]
      }.used`,
      label: `${p.name} used`,
      unit: "percent" as const,
      confidence: "exact" as const,
      availability: "observed" as const,
      value: p.usedPercent,
      sensitivity: "operational" as const,
    })),
    facts: [],
    exceptions,
    ...common,
  };
}

function firewallaSection(ctx: ReportContext, read: ReadResult) {
  const machines = read.records.machine as z.infer<typeof FirewallaMachine>[];
  const inventory =
    (read.records.inventory as z.infer<typeof FirewallaInventory>[])[0];
  const mismatch = inventory && inventory.machines !== machines.length;
  const exceptions = [
    ...machines.filter((m) => !m.online && m.tier === "deep").map((m) => ({
      id: stableId("firewalla-machine", m.name),
      severity: "warning" as const,
      subject: m.name,
      headline: "Deep-tier machine offline",
      detail: `Last classified on ${m.networks.join(", ")}`,
      source: "firewalla:machine",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    })),
    ...sourceFailureExceptions(ctx, read),
    ...(mismatch
      ? [{
        id: "firewalla:summary-record-mismatch",
        severity: "warning" as const,
        subject: "Firewalla coverage",
        headline: "Inventory and machine coverage differ",
        detail:
          "Collector inventory counts do not match the available records.",
        source: "firewalla:inventory",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational" as const,
      }]
      : []),
  ];
  const rejected = read.rejected + (inventory ? 0 : 1) + (mismatch ? 1 : 0);
  const fresh = freshness(inventory?.syncedAt);
  let state: DashboardState = exceptions.some((e) => e.severity === "critical")
    ? "critical"
    : exceptions.some((e) => e.severity === "warning")
    ? "degraded"
    : "healthy";
  if (rejected > 0 && state !== "critical") state = "partial";
  if (fresh.state !== "fresh" && state === "healthy") state = fresh.state;
  if (executionUnauthorized(ctx)) state = "unauthorized";
  const filtered = ctx.methodArgs.network ||
    (ctx.methodArgs.tier && ctx.methodArgs.tier !== "all") ||
    (inventory?.skippedByNetwork ?? 0) > 0 ||
    (inventory?.excludedNetworks.length ?? 0) > 0;
  return {
    id: "firewalla",
    title: "Firewalla",
    state,
    impact: "required" as const,
    summary: inventory
      ? `${inventory.online}/${inventory.total} devices online`
      : "Firewalla inventory unavailable",
    coverage: {
      kind: "exact" as const,
      scope: filtered
        ? "requested collector filter"
        : "full collector execution",
      notes: filtered
        ? "coverage is exact only for the requested or collector-reported filter"
        : undefined,
    },
    freshness: fresh,
    completeness: completeness(
      rejected,
      "records rejected or inventory missing",
    ),
    metrics: inventory
      ? [{
        id: "devices.online",
        label: "Online devices",
        unit: "count" as const,
        confidence: "exact" as const,
        availability: "observed" as const,
        value: inventory.online,
        sensitivity: "operational" as const,
      }]
      : [],
    facts: inventory
      ? [{
        id: "networks",
        label: "Networks",
        value: inventory.networks.join(", "),
        confidence: "exact" as const,
        sensitivity: "operational" as const,
      }]
      : [],
    exceptions,
    ...common,
  };
}

/** Normalize one completed collector execution into one standalone bundle. */
export async function normalize(
  ctx: ReportContext,
): Promise<DashboardBundleV1> {
  const modelType = modelTypeName(ctx);
  if (!sourceSchemas[modelType]) {
    throw new Error(`unsupported homelab collector type ${modelType}`);
  }
  const read = await readRecords(ctx);
  const section = modelType === "@jpisgeek/netdata"
    ? netdataSection(ctx, read)
    : modelType === "@jpisgeek/truenas"
    ? trueNasSection(ctx, read)
    : firewallaSection(ctx, read);
  const parsedSection = DashboardSectionSchema.parse(section);
  const bundle = {
    schemaVersion: DASHBOARD_BUNDLE_VERSION,
    id: `${section.id}-observability`,
    title: `${section.title} observability`,
    generatedAt: new Date().toISOString(),
    producer: {
      extension: "@jpisgeek/dashboard-homelab",
      extensionVersion: "2026.08.25.2",
      modelType,
      modelName: ctx.definition.name,
      modelId: ctx.modelId,
      dataName: "report-jpisgeek-dashboard-homelab-json",
      reportName: "@jpisgeek/dashboard-homelab",
    },
    state: deriveOverallState([parsedSection]),
    sections: [parsedSection],
    exceptions: [],
    sensitivity,
    extensions: {},
  };
  return DashboardBundleV1Schema.parse(bundle);
}

function markdown(bundle: DashboardBundleV1): string {
  const section = bundle.sections[0];
  return `# ${bundle.title}\n\n**State:** ${bundle.state}\n\n${section.summary}\n\n` +
    `Coverage: ${section.coverage.scope}; completeness: ${section.completeness.state}.\n`;
}

export const report = {
  name: "@jpisgeek/dashboard-homelab",
  description:
    "Normalize local Netdata, TrueNAS, and Firewalla observations into dashboard bundle v1.",
  scope: "method" as const,
  labels: ["dashboard", "observability", "homelab"],
  execute: async (context: ReportContext) => {
    const bundle = await normalize(context);
    return { markdown: markdown(bundle), json: bundle };
  },
};
