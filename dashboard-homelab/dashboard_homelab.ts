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

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

const HEX = "0123456789abcdef";

/**
 * Length-prefixed join of an identity tuple. Injective by construction: a
 * decoder reads the digit run before each colon and then takes exactly that
 * many characters, so no two distinct tuples can render to the same string.
 *
 * A separator join is not an encoding of a tuple at all. With any separator
 * `s`, `["ab", "c"]` and `["a", "bc"]` both come out as `ab s c` once the
 * parts themselves are allowed to contain `s` — and every character available
 * as a separator is a character a node name, chart name, mount path, pool
 * name or alert class is allowed to contain. An "identity derived from the
 * record" that a *different* record can also produce is not an identity: the
 * two records land on one key in whatever consumes this bundle, and one
 * record's history silently overwrites the other's.
 */
function identityTuple(parts: readonly string[]): string {
  return parts.map((part) => `${part.length}:${part}`).join("");
}

/**
 * 128 bits of SHA-256 over the length-prefixed tuple, as 32 lowercase hex
 * characters.
 *
 * This replaces a 64-bit FNV-1a. FNV-1a is a hash-table function, not a
 * collision-resistant one, and these strings are not bucket indexes: they are
 * the keys a dashboard keeps per-record history under, forever. 64 bits of a
 * non-cryptographic mixer puts a birthday collision inside reach of a few
 * billion values and — more to the point — inside reach of anything that can
 * choose record names, because FNV is trivially invertible byte by byte. The
 * consequence of one collision is not a warning; it is one exception's
 * history overwriting another's.
 *
 * Async because `crypto.subtle` is the only digest the runtime offers without
 * adding a dependency, and every call site here already sits inside an async
 * report execution. Same construction as @jpisgeek/firewalla's resource
 * identity, deliberately.
 */
async function identityDigest(parts: readonly string[]): Promise<string> {
  const data = new TextEncoder().encode(identityTuple(parts));
  const buf = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  let out = "";
  for (let i = 0; i < 16; i++) out += HEX[buf[i] >> 4] + HEX[buf[i] & 0x0f];
  return out;
}

/**
 * Per-execution identity factory.
 *
 * Every identifier this report emits is derived from two things: an opaque
 * namespace for the *producing collector instance*, and the distinguishing
 * fields of the record itself. Both halves are load-bearing.
 *
 * - The bundle id used to be `${section.id}-observability` — one fixed string
 *   per collector TYPE, not per collector. Two Netdata models (a production
 *   one and a lab one) published the identical bundle id on every run, so a
 *   consumer keyed by bundle id kept a single history for both and each run
 *   overwrote the other's. Same for two TrueNAS boxes, two Firewallas.
 * - Record ids were derived from record fields alone, so `node-a` on one
 *   Netdata instance and `node-a` on another produced the same exception id
 *   across bundles, with the same overwrite.
 *
 * The namespace is a digest of the model type and model ID rather than the
 * model ID itself: the model ID is a private Swamp identifier, it is
 * deliberately no longer published as a producer field (see `normalize`), and
 * so it must not be recoverable out of the identifiers either.
 */
interface Identities {
  /** Opaque, publishable namespace for this collector instance. */
  readonly namespace: string;
  /** Namespaced, collision-resistant id for one emitted record. */
  id(prefix: string, ...parts: string[]): Promise<string>;
  /** Namespaced digest with no readable prefix, for withheld identifiers. */
  opaque(...parts: string[]): Promise<string>;
}

async function identities(ctx: ReportContext): Promise<Identities> {
  const namespace = await identityDigest([
    "dashboard-homelab/producer/v1",
    modelTypeName(ctx),
    ctx.modelId,
  ]);
  return {
    namespace,
    async id(prefix: string, ...parts: string[]): Promise<string> {
      const digest = await identityDigest([
        "dashboard-homelab/record/v1",
        namespace,
        prefix,
        ...parts,
      ]);
      return `${prefix}:${digest}`;
    },
    opaque(...parts: string[]): Promise<string> {
      return identityDigest([
        "dashboard-homelab/opaque/v1",
        namespace,
        ...parts,
      ]);
    },
  };
}

/**
 * Collision *detection*, on top of collision resistance.
 *
 * SHA-256 makes two different inputs sharing an id a non-event. It does
 * nothing about two different records whose distinguishing fields are
 * genuinely equal: two TrueNAS alerts carrying the same `id`, two pools
 * reported under one name, two data handles with the same name. Those hash to
 * the same value legitimately, and a consumer keyed by exception id would keep
 * one and silently drop the other — the same history-overwrite failure by a
 * different route. Both conditions are real and both must survive, so second
 * and later occurrences get an occurrence suffix instead of being merged away.
 *
 * The suffix is `.<n>` rather than `#<n>` because metric ids must satisfy the
 * contract's `IdentifierSchema`, which permits only `[a-z0-9._:-]` — `#` would
 * make the whole bundle fail to parse. `.<n>` cannot be reached by a distinct
 * record: the segment it follows is a 32-hex digest, so no genuine second id
 * ends in a dotted decimal.
 */
function withDistinctIds<T extends { id: string }>(items: T[]): T[] {
  const seen = new Map<string, number>();
  return items.map((item) => {
    const occurrence = (seen.get(item.id) ?? 0) + 1;
    seen.set(item.id, occurrence);
    return occurrence === 1
      ? item
      : { ...item, id: `${item.id}.${occurrence}` } as T;
  });
}

// ---------------------------------------------------------------------------
// Text safety
//
// Everything below exists because this report persists its output: the JSON
// bundle is stored as Swamp data and rendered onto dashboards that are not
// necessarily as protected as the collector's own credentials. Any string this
// report copies out of a collector payload or out of a thrown error is a
// publication channel for whatever happens to be in it — a repository error
// carrying a connection URL with userinfo, a node error carrying the API token
// it was rejected for, an alarm `info` or a TrueNAS `formatted` message
// carrying paths, hostnames or a secret pasted into an alert template.
//
// The rule this file now follows: no free-form source text is ever emitted.
// Errors become enumerated classes chosen from a fixed vocabulary here; the
// only source-provided strings that survive are *names*, and only after
// passing a structural allow-list.
// ---------------------------------------------------------------------------

/**
 * Enumerated read-failure classes. These are the only descriptions of a failed
 * record read that ever reach the bundle.
 *
 * The previous code did `rejectionDetails.push(`${handle.name}: ${error.message}`)`,
 * which persisted whatever the data repository threw. That message is written
 * by code this extension does not own, is unbounded, and on a real failure
 * routinely contains the storage URL, a filesystem path, or the credential the
 * request was rejected for. There is no redaction of an arbitrary error string
 * that is worth trusting; the message is simply never read.
 */
const READ_FAILURE = {
  unknownType: "unknown-resource-type",
  repository: "repository-read-failed",
  unavailable: "content-unavailable",
  invalidJson: "invalid-json",
  schema: "schema-validation-failed",
  oversized: "record-size-limit-exceeded",
  recordLimit: "record-count-limit-exceeded",
} as const;

type ReadFailure = typeof READ_FAILURE[keyof typeof READ_FAILURE];

/** Control characters: they break Markdown and JSON rendering and can hide
 * appended content behind a carriage return. Never publishable. */
// Matching control characters is the entire point here: these are exactly
// what must never reach rendered output. The lint rule cannot tell that
// apart from an accidental literal, and the directive has to be the last
// line before the code or it silently applies to nothing.
// deno-lint-ignore no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/;
/**
 * Shapes a name has no business containing and that carry credentials when
 * they appear: a URL scheme, userinfo or an e-mail, a query string, a
 * key=value assignment, or a word that labels a secret.
 */
const CREDENTIAL_SHAPES =
  /:\/\/|@|[=?&]|\b(?:bearer|token|secret|password|passwd|credential|api[_-]?key|authorization)\b/i;
/**
 * A long unbroken run of token alphabet is what an API key, a session cookie
 * or a base64 blob looks like, and is not what a pool, node, chart or mount
 * name looks like. This does reject the occasional legitimate name — a
 * container overlay mount path with a 64-hex segment is the realistic case —
 * and that is the intended trade: a withheld mount path costs an operator one
 * lookup, a published token costs a credential rotation.
 */
const OPAQUE_RUN = /[A-Za-z0-9+/=_-]{32,}/;
/** Names are short. Anything longer is not a name, it is a payload. */
const LABEL_MAX = 96;
const WITHHELD = "(withheld: source text failed safe-label validation)";

/**
 * Structural allow-list for the one class of source text this report still
 * publishes: names and short status words that the operator needs in order to
 * know *which* pool, node, mount or alert is being reported.
 *
 * This is an allow-list, not a redactor. A redactor decides what to remove and
 * fails open on anything it did not anticipate; this decides what may pass and
 * fails closed on everything else.
 */
function safeLabel(raw: string): string {
  const value = raw.trim();
  if (value.length === 0 || value.length > LABEL_MAX) return WITHHELD;
  if (CONTROL_CHARACTERS.test(value)) return WITHHELD;
  if (CREDENTIAL_SHAPES.test(value)) return WITHHELD;
  if (OPAQUE_RUN.test(value)) return WITHHELD;
  return value;
}

/** Bounded, validated rendering of a list of names. Bounded because the list
 * length is source-controlled and a detail line is not a place to put a
 * thousand entries. */
function safeList(values: readonly string[], max: number): string {
  const shown = values.slice(0, max).map(safeLabel);
  const extra = values.length - shown.length;
  return [...shown, extra > 0 ? `+${extra} more` : ""]
    .filter((part) => part !== "")
    .join(", ");
}

/**
 * Enumerated transport-failure classes for an unreachable Netdata node.
 *
 * The node's own `error` string is free text off the wire — it is the string
 * the HTTP client produced, and it commonly embeds the full request URL. It is
 * matched against these patterns and then discarded; only the label on the
 * right, which is written here, is ever emitted. A crafted error can therefore
 * steer which class is reported, which is harmless, but cannot place one
 * character of its own into the bundle.
 */
const TRANSPORT_FAILURE_CLASSES: ReadonlyArray<readonly [RegExp, string]> = [
  [/timed?\s*out|timeout|etimedout/i, "request timed out"],
  [/refused|econnrefused/i, "connection refused"],
  [
    /enotfound|getaddrinfo|\bdns\b|unknown host|not known/i,
    "host name did not resolve",
  ],
  [/certificate|\btls\b|\bssl\b|self[- ]signed/i, "TLS failure"],
  [
    /unauthor|forbidden|\b401\b|\b403\b|api[_ -]?key|token/i,
    "rejected by the node",
  ],
  [/\b[45]\d\d\b|http/i, "HTTP error response"],
  [/econnreset|reset by peer|socket|network|unreachable/i, "connection reset"],
];

function transportFailureClass(raw: string): string {
  if (raw.trim() === "") return "no failure detail reported";
  for (const [pattern, label] of TRANSPORT_FAILURE_CLASSES) {
    if (pattern.test(raw)) return label;
  }
  return "unclassified transport failure";
}

/**
 * Re-render a source timestamp from the parsed instant rather than passing the
 * source string through. `notAfter` is typed `z.string()` by the collector, so
 * it is another free-text field; parsing it and printing our own ISO string
 * keeps the fact and drops the channel. Unparseable means unknown, not blank.
 */
function isoTimestamp(raw: string): string | null {
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

/**
 * Slug beside a digest is a readability affordance only — the digest carries
 * the identity — so it is bounded and stripped to the identifier alphabet.
 *
 * It takes the safe-label form of the name, never the raw one. Lowercasing and
 * punctuation-stripping are not redaction: `s3cr3t-Bearer-9f2a` survives both
 * as `s3cr3t-bearer-9f2a`, so slugifying a raw name would republish, inside a
 * metric id, exactly the text the allow-list withheld from the label.
 */
function slug(raw: string): string {
  return safeLabel(raw).toLowerCase().replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "").slice(0, 40);
}

// ---------------------------------------------------------------------------
// Sensitivity metadata
// ---------------------------------------------------------------------------

/**
 * The sensitivity block is the operator's machine-readable answer to "what is
 * in this bundle and may I publish it". It used to say `fields: []` and
 * `redacted: false` on every section, which is a claim that nothing sensitive
 * is present and nothing was withheld — both false. It now names the source
 * fields each section emits and records that source text is withheld.
 */
function sectionSensitivity(fields: readonly string[]) {
  return {
    classification: "operational" as const,
    fields: [...fields],
    redacted: true,
    note:
      "collector free text (repository errors, node errors, alarm info, formatted alert messages) is never emitted; names are emitted only after safe-label validation and are otherwise withheld",
  };
}

const bundleSensitivity = {
  classification: "operational" as const,
  fields: [
    "producer.extension",
    "producer.extensionVersion",
    "producer.modelType",
    "producer.modelName",
    "producer.dataName",
    "producer.reportName",
    "id",
    "generatedAt",
  ],
  redacted: true,
  note:
    "the collector model ID is not emitted; the bundle id carries only a one-way namespace derived from it",
};

// ---------------------------------------------------------------------------
// Source record schemas
// ---------------------------------------------------------------------------

const NetdataNode = z.object({
  name: z.string(),
  url: z.string(),
  reachable: z.boolean(),
  // Free text off the wire. Validated as a string, classified, never emitted.
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
  // Alarm template prose. Validated as a string, never emitted.
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
  // The rendered alert message. This is the single richest free-text field any
  // of these collectors produces — it interpolates hostnames, dataset paths,
  // job output and whatever an operator typed into a custom alert. Validated
  // as a string so the record shape is checked, never emitted.
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

/**
 * A cardinality. `z.number()` accepts -3 and 2.5, and this report published
 * whatever it accepted as a fact: "-3/2.5 devices online" was a healthy
 * summary line. A count of things is a nonnegative integer or it is not a
 * count, and a payload that says otherwise is corrupt or forged.
 */
const Count = z.number().int().nonnegative();

/**
 * Inventory counts, with the collector's own arithmetic enforced.
 *
 * These are not approximations. firewalla.ts computes the rollup as
 * `total = counted` (the device handle count), `offline = counted - online`
 * and `presence = counted - deep`, all in one pass, and builds machines by
 * collapsing those same devices. So `online + offline === total`,
 * `deep + presence === total` and `machines <= total` hold exactly for every
 * inventory the real collector can produce.
 *
 * A payload that breaks them describes a fleet that cannot exist — the review
 * example was `online: 5, total: 0`, which this report happily rendered as
 * "5/0 devices online" under a healthy state. An impossible count must not be
 * publishable at all, so the whole inventory record fails validation and is
 * rejected; the section then reports its inventory as unavailable and the run
 * as partial, which is the truth. Failing the record closed is deliberate:
 * the alternative is picking which of two contradictory numbers to believe.
 */
const FirewallaInventory = z.object({
  mspDomain: z.string(),
  total: Count,
  online: Count,
  offline: Count,
  deep: Count,
  presence: Count,
  reserved: Count,
  skippedByNetwork: Count,
  excludedNetworks: z.array(z.string()),
  machines: Count,
  sshCandidates: Count,
  excluded: Count,
  networks: z.array(z.string()),
  deviceTypes: z.record(z.string(), Count),
  syncedAt: z.iso.datetime(),
}).superRefine((inventory, ctx) => {
  if (inventory.online > inventory.total) {
    ctx.addIssue({
      code: "custom",
      message: "online devices cannot exceed the device total",
      path: ["online"],
    });
  }
  if (inventory.online + inventory.offline !== inventory.total) {
    ctx.addIssue({
      code: "custom",
      message: "online and offline devices must partition the device total",
      path: ["offline"],
    });
  }
  if (inventory.deep + inventory.presence !== inventory.total) {
    ctx.addIssue({
      code: "custom",
      message: "deep and presence tiers must partition the device total",
      path: ["presence"],
    });
  }
  if (inventory.machines > inventory.total) {
    ctx.addIssue({
      code: "custom",
      message: "machines are collapsed devices and cannot exceed the total",
      path: ["machines"],
    });
  }
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

/** One record this report could not use, named by an opaque handle digest and
 * an enumerated reason. Neither field can carry source text. */
interface Rejection {
  record: string;
  reason: ReadFailure;
}

interface ReadResult {
  records: Record<string, Json[]>;
  rejected: number;
  rejections: Rejection[];
}

function specName(handle: DataHandle): string | undefined {
  return handle.specName ?? handle.tags?.specName ??
    handle.metadata?.tags?.specName;
}

/**
 * Read every scoped data handle, validate it, and record the failures as
 * (opaque record id, enumerated reason) pairs.
 *
 * The failure path used to be one `try` around the whole body ending in
 * `${handle.name}: ${(error as Error).message}`, which published two untrusted
 * strings: the handle name (a Swamp resource name derived from collector data)
 * and the repository's own error text. The branches are separated here so each
 * failure has a name chosen from `READ_FAILURE`, and the handle is identified
 * by a digest instead of by its name — the operator can still tell two failing
 * records apart and correlate them across runs without the name being
 * published.
 */
async function readRecords(
  ctx: ReportContext,
  ids: Identities,
): Promise<ReadResult> {
  const schemas = sourceSchemas[modelTypeName(ctx)];
  const records: Record<string, Json[]> = Object.fromEntries(
    Object.keys(schemas).map((name) => [name, []]),
  );
  const rejections: Rejection[] = [];

  const acceptedHandles = ctx.dataHandles.slice(0, 5_000);
  if (ctx.dataHandles.length > acceptedHandles.length) {
    rejections.push({
      record: await ids.opaque("record-count-limit"),
      reason: READ_FAILURE.recordLimit,
    });
  }
  for (const handle of acceptedHandles) {
    const record = await ids.opaque("data-handle", handle.name);
    const spec = specName(handle);
    if (!spec || !schemas[spec]) {
      rejections.push({ record, reason: READ_FAILURE.unknownType });
      continue;
    }
    let bytes: Uint8Array | null;
    try {
      bytes = await ctx.dataRepository.getContent(
        ctx.modelType,
        ctx.modelId,
        handle.name,
        handle.version,
      );
    } catch {
      // The thrown value belongs to the data repository. It is not read.
      rejections.push({ record, reason: READ_FAILURE.repository });
      continue;
    }
    if (!bytes) {
      rejections.push({ record, reason: READ_FAILURE.unavailable });
      continue;
    }
    if (bytes.byteLength > 1024 * 1024) {
      rejections.push({ record, reason: READ_FAILURE.oversized });
      continue;
    }
    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      // A JSON syntax error quotes the offending input. Not read either.
      rejections.push({ record, reason: READ_FAILURE.invalidJson });
      continue;
    }
    const parsed = schemas[spec].safeParse(value);
    if (!parsed.success) {
      // Zod issues quote received values. The class is the whole message.
      rejections.push({ record, reason: READ_FAILURE.schema });
      continue;
    }
    records[spec].push(parsed.data as Json);
  }
  return { records, rejected: rejections.length, rejections };
}

/**
 * The one rollup record a section is allowed to have, or nothing.
 *
 * Every section used to take `records.summary[0]`, which cannot tell "no
 * rollup" from "two rollups" — it silently believes the first and discards the
 * rest. Two summary handles in one execution is exactly the shape a stale
 * carried-forward handle, a re-run, or a forged extra record takes, and the
 * discarded one is the one that disagrees: the section then publishes
 * "1/1 nodes reachable", freshness `fresh` and completeness `exact` off a
 * rollup that a second, contradicting rollup sat right beside.
 *
 * Zero and two-or-more are both "no usable rollup". Returning `undefined`
 * routes both into the path the sections already have for a missing summary:
 * the headline says unavailable, freshness becomes unknown, and the record
 * counts as rejected so completeness is `partial`. Picking one of two
 * disagreeing rollups is not available as an honest option.
 */
function soleRollup<T>(records: readonly Json[]): T {
  // Cast, not narrow: the call sites already treated `[0]` as a `T` that may
  // be absent at runtime and guard every use with `summary ? ...` / `?.`.
  // Widening the type here would be a larger change than the defect.
  return (records.length === 1 ? records[0] : undefined) as T;
}

// Severity levels this report recognizes, spelled out per bucket so that an
// unrecognized level is a distinguishable case rather than a silent default.
//
// The critical bucket carries the syslog levels at or above ERROR. ERROR sits
// above WARNING in the syslog ordering and, on a NAS, names a failure that has
// already happened (a scrub or replication that did not complete), not a
// prediction about one. TrueNAS emits it; this report used to file it as
// "info" and drop it out of state entirely.
const CRITICAL_LEVELS = [
  "CRITICAL",
  "CRIT",
  "ALERT",
  "EMERGENCY",
  "EMERG",
  "ERROR",
  "ERR",
  "FATAL",
];
const WARNING_LEVELS = ["WARNING", "WARN"];
// Levels that genuinely mean "not a raised condition". TrueNAS alerts carry
// the low syslog levels; Netdata alarm records carry its non-raised alarm
// statuses. Both must stay "info" or every quiet run reads as degraded.
const INFO_LEVELS = [
  "INFO",
  "INFORMATIONAL",
  "NOTICE",
  "DEBUG",
  "CLEAR",
  "OK",
  "NOMINAL",
  "UNDEFINED",
  "UNINITIALIZED",
  "REMOVED",
];

/**
 * Classify a source level string.
 *
 * The fall-through used to be "info", which made an unmapped level invisible:
 * "info" exceptions move neither the section state ladder nor
 * deriveOverallState, so an alert the collector could not label was published
 * as a low-priority line item under a healthy bundle. That case is reachable
 * without anything exotic — truenas.ts types the raw API field as
 * `level: z.string().nullable().optional()` and writes `level: a.level ?? ""`,
 * so an alert payload with no `level` key persists as the empty string.
 *
 * An unrecognized level now classifies as "warning": enough to take the
 * section out of "healthy" and put the condition in front of an operator,
 * without asserting a severity the source never gave us.
 */
function severity(level: string): "critical" | "warning" | "info" {
  const normalized = level.trim().toUpperCase();
  if (CRITICAL_LEVELS.includes(normalized)) return "critical";
  if (WARNING_LEVELS.includes(normalized)) return "warning";
  if (INFO_LEVELS.includes(normalized)) return "info";
  return "warning";
}

/** True when `level` is outside every bucket above, so it can be named. */
function levelUnmapped(level: string): boolean {
  const normalized = level.trim().toUpperCase();
  return !CRITICAL_LEVELS.includes(normalized) &&
    !WARNING_LEVELS.includes(normalized) &&
    !INFO_LEVELS.includes(normalized);
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

/**
 * Exceptions for records that could not be read and for a failed execution.
 *
 * `ctx.errorMessage` is matched to decide authorized-vs-not and is otherwise
 * never emitted: it is the collector's own thrown message and, in the
 * unauthorized case especially, routinely contains the credential or URL the
 * request was rejected for.
 *
 * `ctx.definition.name` goes through `safeLabel` for the same reason every
 * other source-controlled name does. It is free-form operator text typed into
 * a Swamp model definition — Swamp does not constrain it — so it is the one
 * name in this file that reached the bundle with no validation at all. A model
 * definition named after the URL it polls, or one carrying a pasted token or a
 * carriage return, published that verbatim as an exception subject.
 */
async function sourceFailureExceptions(
  ctx: ReportContext,
  read: ReadResult,
  ids: Identities,
): Promise<NormalizedException[]> {
  const exceptions: NormalizedException[] = await Promise.all(
    read.rejections.map(async (rejection) => ({
      id: await ids.id(
        "source-record-rejected",
        rejection.record,
        rejection.reason,
      ),
      severity: "warning" as const,
      subject: safeLabel(ctx.definition.name),
      headline: "Collector record rejected",
      detail: `record ${rejection.record} rejected: ${rejection.reason}`,
      source: modelTypeName(ctx),
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    })),
  );
  if (ctx.executionStatus === "failed") {
    const unauthorized = executionUnauthorized(ctx);
    exceptions.push({
      id: await ids.id("collector-execution-failed", ctx.methodName),
      severity: unauthorized ? "warning" : "critical",
      subject: safeLabel(ctx.definition.name),
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

async function netdataSection(
  ctx: ReportContext,
  read: ReadResult,
  ids: Identities,
) {
  const nodes = read.records.node as z.infer<typeof NetdataNode>[];
  const alarms = read.records.alarm as z.infer<typeof NetdataAlarm>[];
  const mounts = read.records.mount as z.infer<typeof NetdataMount>[];
  const summary = soleRollup<z.infer<typeof NetdataSummary>>(
    read.records.summary,
  );
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
  const exceptions = withDistinctIds([
    ...await Promise.all(
      nodes.filter((n) => !n.reachable).map(async (n) => ({
        id: await ids.id("netdata-node", n.name),
        severity: "critical" as const,
        subject: safeLabel(n.name),
        headline: "Netdata node unreachable",
        // `n.error` is the transport's own message and usually embeds the node
        // URL — which is where a Netdata API token lives when one is configured.
        // Only the class is published.
        detail: `node did not answer: ${transportFailureClass(n.error)}`,
        source: "netdata:node",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational" as const,
      })),
    ),
    ...await Promise.all(alarms.map(async (a) => ({
      id: await ids.id("netdata-alarm", a.node, a.chart, a.name),
      severity: severity(a.status),
      headline: safeLabel(a.name),
      subject: safeLabel(a.node),
      // `a.info` is the alarm template's prose, written by whoever authored
      // the alarm, and is not published. The numeric reading and the mapped
      // status say what the alarm is doing without quoting the source.
      detail: [
        `alarm status ${severity(a.status)}`,
        // An alarm with no units is ordinary, and "no units" is not a withheld
        // label — only a present-but-unsafe one is.
        a.units.trim() === ""
          ? `value ${a.value}`
          : `value ${a.value} ${safeLabel(a.units)}`,
        levelUnmapped(a.status)
          ? `unrecognized alarm status ${safeLabel(a.status)}`
          : "",
      ].filter((part) => part !== "").join(" — "),
      source: "netdata:alarm",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    }))),
    ...await Promise.all(
      mounts.filter((m) => m.overThreshold).map(async (m) => ({
        id: await ids.id("netdata-mount", m.node, m.mount),
        severity: "warning" as const,
        subject: safeLabel(m.node),
        headline: "Filesystem above threshold",
        detail: `${safeLabel(m.mount)} is ${m.usedPercent}% used`,
        source: "netdata:mount",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational" as const,
      })),
    ),
    ...await sourceFailureExceptions(ctx, read, ids),
    // Section-wide conditions carry a namespaced id for the same reason the
    // per-record ones do: "netdata:summary-record-mismatch" is one string for
    // every Netdata collector that ever runs, so two of them share the key.
    ...(mismatch
      ? [{
        id: await ids.id("netdata-summary-record-mismatch"),
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
  ]);
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
    references: [] as never[],
    sensitivity: sectionSensitivity([
      "node.name",
      "alarm.node",
      "alarm.name",
      // The mapped severity is always rendered, and an unrecognized status is
      // rendered verbatim (allow-listed) by `unrecognized alarm status ...`.
      // Omitting it made the list claim a field was dropped that is emitted.
      "alarm.status",
      "alarm.value",
      "alarm.units",
      "mount.node",
      // The source field is `mount`, not `path`. A field list that names a key
      // the record does not have cannot be diffed against the collector, which
      // is the only thing this list is for.
      "mount.mount",
      "mount.usedPercent",
      "summary.nodes",
      "summary.nodesReachable",
    ]),
  };
}

async function trueNasSection(
  ctx: ReportContext,
  read: ReadResult,
  ids: Identities,
) {
  const pools = read.records.pool as z.infer<typeof TrueNasPool>[];
  const disks = read.records.disk as z.infer<typeof TrueNasDisk>[];
  const alerts = read.records.alert as z.infer<typeof TrueNasAlert>[];
  const certs = read.records.certificate as z.infer<
    typeof TrueNasCertificate
  >[];
  const summary = soleRollup<z.infer<typeof TrueNasSummary>>(
    read.records.summary,
  );
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
  const exceptions = withDistinctIds([
    ...await Promise.all(
      pools.filter((p) => !p.healthy).map(async (p) => ({
        id: await ids.id("truenas-pool", p.name),
        severity: "critical" as const,
        subject: safeLabel(p.name),
        headline: "Storage pool unhealthy",
        detail: `pool status ${safeLabel(p.status)}`,
        source: "truenas:pool",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational" as const,
      })),
    ),
    ...await Promise.all(
      certs.filter((c) => c.expired || c.expiringSoon).map(async (c) => {
        // `notAfter` is a plain string on the source record. Re-render it from
        // the parsed instant so the published timestamp is ours, not the
        // source's, and say so plainly when it does not parse.
        const expiry = isoTimestamp(c.notAfter);
        return {
          id: await ids.id("truenas-certificate", c.name),
          severity: c.expired ? "critical" as const : "warning" as const,
          subject: safeLabel(c.name),
          headline: c.expired
            ? "Certificate expired"
            : "Certificate expiring soon",
          detail: !c.expiryKnown
            ? "certificate expiry is unknown"
            : expiry
            ? `${c.daysRemaining} days remaining; expires ${expiry}`
            : `${c.daysRemaining} days remaining; expiry timestamp unreadable`,
          source: "truenas:certificate",
          suppressed: false,
          suppressReason: "",
          sensitivity: "operational" as const,
        };
      }),
    ),
    ...await Promise.all(
      certs.filter((c) => !c.expiryKnown).map(async (c) => ({
        id: await ids.id("truenas-certificate-unknown", c.name),
        severity: "warning" as const,
        subject: safeLabel(c.name),
        headline: "Certificate expiry unknown",
        detail: "The collector could not determine this certificate's expiry.",
        source: "truenas:certificate",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational" as const,
      })),
    ),
    // Alert records expose no stable certificate identifier. Preserve every
    // alert independently instead of attaching it to the first certificate.
    //
    // `suppressed` is deliberately always false here. The collector sets
    // `silenced` from the TrueNAS `dismissed` flag and says so explicitly
    // (truenas.ts: "A dismissed alert is hidden in the TrueNAS UI but the
    // condition behind it is still true. Surface it rather than inherit the
    // dismissal."). This report used to map that flag straight onto
    // `suppressed`, which re-applied the dismissal one layer up: suppressed
    // exceptions are filtered out of the section state ladder below AND out of
    // deriveOverallState, and the renderer files them into a collapsed
    // "Expected" block. A CRITICAL alert somebody had dismissed months ago
    // therefore published as a healthy bundle with an all-clear banner. The
    // dismissal is kept as visible detail instead of as state.
    //
    // `a.formatted` is NOT published. It is the rendered alert message, and it
    // interpolates whatever the alert is about: dataset paths, replication
    // targets with user@host, job stderr, custom operator text. The class, the
    // mapped severity and the dismissal state say what an operator needs in
    // order to go look at the alert in TrueNAS.
    ...await Promise.all(alerts.map(async (a) => ({
      id: await ids.id("truenas-alert", a.id),
      severity: severity(a.level),
      subject: safeLabel(a.klass),
      headline: safeLabel(a.klass),
      detail: [
        `alert severity ${severity(a.level)}`,
        a.silenced
          ? "dismissed in the TrueNAS UI; the condition is still active"
          : "",
        // Name the level we could not classify rather than letting it vanish
        // into a bucket the operator cannot see from the rendered line. The
        // level is source text, so it goes through the allow-list first.
        levelUnmapped(a.level)
          ? `unrecognized alert level ${safeLabel(a.level)}`
          : "",
      ].filter((part) => part !== "").join(" — "),
      source: "truenas:alert",
      suppressed: false,
      suppressReason: "",
      sensitivity: "operational" as const,
    }))),
    ...await sourceFailureExceptions(ctx, read, ids),
    ...(mismatch
      ? [{
        id: await ids.id("truenas-summary-record-mismatch"),
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
  ]);
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
    // Duplicate-id detection applies to metrics for the same reason it applies
    // to exceptions. The pool metric id is derived from `p.name` alone, so two
    // pool records reported under one name — two `tank` records from a payload
    // that lists a pool twice — produce byte-identical metric ids, and a
    // consumer keyed by metric id keeps one utilization series and silently
    // overwrites the other's. Collision resistance cannot help here: the inputs
    // really are equal. The second occurrence gets its own id instead.
    metrics: withDistinctIds(
      await Promise.all(pools.map(async (p) => ({
        id: `pool.${slug(p.name)}.${await ids.opaque("pool", p.name)}.used`,
        label: `${safeLabel(p.name)} used`,
        unit: "percent" as const,
        confidence: "exact" as const,
        availability: "observed" as const,
        value: p.usedPercent,
        sensitivity: "operational" as const,
      }))),
    ),
    facts: [],
    exceptions,
    references: [] as never[],
    sensitivity: sectionSensitivity([
      "pool.name",
      "pool.status",
      "pool.usedPercent",
      "certificate.name",
      "certificate.daysRemaining",
      "certificate.notAfter",
      "alert.klass",
      // Emitted as the mapped severity, and verbatim (allow-listed) when the
      // level is outside the mapped vocabulary.
      "alert.level",
      // The dismissal state is emitted as detail — "dismissed in the TrueNAS
      // UI" — which is a source field reaching output, so it belongs here.
      "alert.silenced",
      "summary.pools",
      "summary.poolsUnhealthy",
    ]),
  };
}

async function firewallaSection(
  ctx: ReportContext,
  read: ReadResult,
  ids: Identities,
) {
  const machines = read.records.machine as z.infer<typeof FirewallaMachine>[];
  const devices = read.records.device as z.infer<typeof FirewallaDevice>[];
  const inventory = soleRollup<z.infer<typeof FirewallaInventory>>(
    read.records.inventory,
  );
  // The section headline and the `devices.online` metric are both read
  // straight off the inventory rollup. The only cross-check this section used
  // to run was `inventory.machines !== machines.length`, which validates a
  // different figure entirely — so a rollup that raced the device scan could
  // publish "12/12 devices online" at confidence "exact" against three machine
  // records and nothing would notice. Device records were being fetched and
  // Zod-validated by readRecords() and then thrown away.
  //
  // These two invariants are exact on the collector side, not approximate:
  // firewalla.ts sets `total` from `deviceCount = handles.length` taken
  // immediately after the device write loop, and increments `online` inside
  // that same loop. Devices on excluded networks are skipped before any write
  // and so are absent from both sides; name-excluded devices are written and
  // counted on both sides. So any difference here is real drift.
  //
  // Device coverage has THREE states, and the previous `deviceCountsKnown`
  // boolean collapsed two of them:
  //
  //   corroborated  device records exist and agree with the rollup
  //   contradicted  device records exist and disagree
  //   unmeasured    no device record was published at all
  //
  // "Unmeasured" is not "zero". With no device records the report cannot tell
  // an empty fleet from a device scan whose handles never landed, so
  // `total: 0, online: 0` must not publish as an observed zero under a healthy
  // state — that is precisely how a lost scan renders as "all quiet". Only the
  // corroborated case produces an observed value; the other two publish the
  // metric as unavailable-with-reason, mark coverage unknown, and count
  // against completeness.
  const devicesOnline = devices.filter((d) => d.online).length;
  const devicesUnmeasured = Boolean(inventory) && devices.length === 0;
  const deviceMismatch = Boolean(inventory) && devices.length > 0 &&
    (inventory.total !== devices.length || inventory.online !== devicesOnline);
  // An inventory claiming devices with no device record published alongside it
  // is drift too: readRecords sees every handle the execution produced.
  const devicesMissing = devicesUnmeasured && inventory.total > 0;
  const devicesCorroborated = Boolean(inventory) && devices.length > 0 &&
    !deviceMismatch;
  const mismatch = Boolean(inventory) &&
    (inventory.machines !== machines.length || deviceMismatch ||
      devicesMissing);
  const exceptions = withDistinctIds([
    ...await Promise.all(
      machines.filter((m) => !m.online && m.tier === "deep").map(
        async (m) => ({
          id: await ids.id("firewalla-machine", m.name),
          severity: "warning" as const,
          subject: safeLabel(m.name),
          headline: "Deep-tier machine offline",
          detail: `Last classified on ${safeList(m.networks, 8)}`,
          source: "firewalla:machine",
          suppressed: false,
          suppressReason: "",
          sensitivity: "operational" as const,
        }),
      ),
    ),
    ...await sourceFailureExceptions(ctx, read, ids),
    ...(mismatch
      ? [{
        id: await ids.id("firewalla-summary-record-mismatch"),
        severity: "warning" as const,
        subject: "Firewalla coverage",
        // Renamed from "machine coverage": this check now also covers the
        // device records the headline figure is actually derived from.
        headline: "Inventory and record coverage differ",
        detail: [
          "Collector inventory counts do not match the available records.",
          deviceMismatch
            ? `Inventory reports ${inventory.online}/${inventory.total} devices online; device records show ${devicesOnline}/${devices.length}.`
            : "",
          devicesMissing
            ? `Inventory reports ${inventory.total} devices but no device record was published.`
            : "",
        ].filter((part) => part !== "").join(" "),
        source: "firewalla:inventory",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational" as const,
      }]
      : []),
    // The zero-record, zero-total case. `devicesMissing` above covers an
    // inventory that claims devices; this covers the one that claims none,
    // which is indistinguishable from a device scan that produced nothing and
    // must not be reported as a verified empty fleet.
    ...(devicesUnmeasured && !devicesMissing
      ? [{
        id: await ids.id("firewalla-device-coverage-unmeasured"),
        severity: "warning" as const,
        subject: "Firewalla coverage",
        headline: "Device coverage unmeasured",
        detail:
          "No device record accompanied this inventory, so an empty fleet cannot be distinguished from a device scan that produced no records. The online device count is reported as unmeasured rather than as zero.",
        source: "firewalla:inventory",
        suppressed: false,
        suppressReason: "",
        sensitivity: "operational" as const,
      }]
      : []),
  ]);
  const rejected = read.rejected + (inventory ? 0 : 1) + (mismatch ? 1 : 0) +
    (devicesUnmeasured && !mismatch ? 1 : 0);
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
    // The headline states a device count only when the device records back it.
    // Otherwise it states what is actually known, which is that the count is
    // not corroborated — a rendered dashboard shows this line and nothing else.
    summary: !inventory
      ? "Firewalla inventory unavailable"
      : devicesCorroborated
      ? `${inventory.online}/${inventory.total} devices online`
      : devicesUnmeasured
      ? `device coverage unmeasured; no device records accompanied an inventory reporting ${inventory.total} device(s)`
      : `device counts uncorroborated; inventory reports ${inventory.online}/${inventory.total}, device records show ${devicesOnline}/${devices.length}`,
    coverage: {
      // Coverage is "exact" only when the device records corroborate the
      // rollup. Anything else is unknown coverage, which deriveOverallState
      // refuses to score as healthy.
      kind: devicesCorroborated ? "exact" as const : "unknown" as const,
      scope: filtered
        ? "requested collector filter"
        : "full collector execution",
      notes: !devicesCorroborated
        ? "device records do not corroborate the inventory rollup"
        : filtered
        ? "coverage is exact only for the requested or collector-reported filter"
        : undefined,
    },
    freshness: fresh,
    completeness: completeness(
      rejected,
      "records rejected, inventory missing, or device coverage unmeasured",
    ),
    metrics: !inventory ? [] : devicesCorroborated
      ? [{
        id: "devices.online",
        label: "Online devices",
        unit: "count" as const,
        confidence: "exact" as const,
        availability: "observed" as const,
        value: inventory.online,
        sensitivity: "operational" as const,
      }]
      // An uncorroborated count is not a reading. The contract's unavailable
      // metric carries no `value` at all, which is the only representation
      // that cannot be mistaken for an observation of zero or of the rollup's
      // own figure; the drift exception above still reports both numbers as
      // diagnostics.
      : [{
        id: "devices.online",
        label: "Online devices",
        unit: "count" as const,
        confidence: "unknown" as const,
        availability: "unknown" as const,
        reason: devicesUnmeasured
          ? "no device records were published with this inventory; the online device count is unmeasured"
          : "device records contradict the inventory rollup; the online device count is not established",
        sensitivity: "operational" as const,
      }],
    facts: inventory
      ? [{
        id: "networks",
        label: "Networks",
        value: safeList(inventory.networks, 16),
        confidence: "exact" as const,
        sensitivity: "operational" as const,
      }]
      : [],
    exceptions,
    references: [] as never[],
    sensitivity: sectionSensitivity([
      "machine.name",
      "machine.networks",
      // The drift detail publishes the online device-record count, which is
      // derived from this field on every device record.
      "device.online",
      "inventory.networks",
      "inventory.online",
      "inventory.total",
    ]),
  };
}

/** Normalize one completed collector execution into one standalone bundle. */
export async function normalize(
  ctx: ReportContext,
): Promise<DashboardBundleV1> {
  const modelType = modelTypeName(ctx);
  if (!sourceSchemas[modelType]) {
    // The rejected type is NOT interpolated. `modelType` is `String(ctx.modelType)`
    // off a live model object, so it is caller-controlled text, and a thrown
    // message is a publication channel: Swamp logs it, and a caller that
    // catches it can render it. Interpolating it turns this guard into an echo
    // of whatever the caller supplied. The message is fixed; the supported
    // types are already public in the README, so nothing diagnostic is lost.
    throw new Error("unsupported homelab collector type");
  }
  const ids = await identities(ctx);
  const read = await readRecords(ctx, ids);
  const section = modelType === "@jpisgeek/netdata"
    ? await netdataSection(ctx, read, ids)
    : modelType === "@jpisgeek/truenas"
    ? await trueNasSection(ctx, read, ids)
    : await firewallaSection(ctx, read, ids);
  const parsedSection = DashboardSectionSchema.parse(section);
  const bundle = {
    schemaVersion: DASHBOARD_BUNDLE_VERSION,
    // Bundle identity is per PRODUCER, not per collector type. `netdata` and
    // `netdata` from a second Netdata model are different producers and must
    // not share a key.
    id: `${section.id}-observability:${ids.namespace}`,
    title: `${section.title} observability`,
    generatedAt: new Date().toISOString(),
    producer: {
      extension: "@jpisgeek/dashboard-homelab",
      extensionVersion: "2026.09.05.1",
      modelType,
      // The Swamp model definition name. Contract-required, operator-chosen,
      // and documented in the README as emitted — but operator-chosen means
      // unvalidated free text, so it passes the same structural allow-list as
      // every other name before it is persisted. Without this, a definition
      // named `netdata?token=...`, or one holding a control character, is
      // published in producer metadata exactly as typed.
      modelName: safeLabel(ctx.definition.name),
      // `modelId` is deliberately absent. It is a private Swamp identifier
      // with no meaning to a dashboard consumer; what a consumer needs is a
      // stable per-producer key, and `id` above carries one that cannot be
      // reversed back to the model ID.
      dataName: "report-jpisgeek-dashboard-homelab-json",
      reportName: "@jpisgeek/dashboard-homelab",
    },
    state: deriveOverallState([parsedSection]),
    sections: [parsedSection],
    exceptions: [],
    sensitivity: bundleSensitivity,
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
