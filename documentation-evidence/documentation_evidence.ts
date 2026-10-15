/** Fixed-schema operational evidence; never an arbitrary field projection. */
import { z } from "npm:zod@4";

/** Shared byte ceiling for source resources, snapshots and reports. */
export const MAX_SNAPSHOT_BYTES = 64_000;
/** Fixed categories avoid copying operator-supplied labels into reports. */
export const Category = z.enum([
  "compute",
  "storage",
  "network",
  "applications",
  "automation",
  "documentation",
]);
const Count = z.number().int().min(0).max(1_000_000);
/** Version 1 producer contract. Every key is required; null means unknown. */
export const OperationalMetadata = z.object({
  schemaVersion: z.literal(1),
  observedAt: z.iso.datetime({ precision: 3 }).nullable(),
  collectorStatus: z.enum(["succeeded", "failed", "unknown"]),
  counts: z.object({
    expected: Count,
    observed: Count,
    unhealthy: Count,
    unknown: Count,
  }).strict().refine(
    (c) => c.observed <= c.expected && c.unhealthy + c.unknown <= c.observed,
    "Observed cannot exceed expected; unhealthy plus unknown cannot exceed observed",
  ),
  flags: z.object({
    reachable: z.boolean().nullable(),
    configured: z.boolean().nullable(),
  }).strict(),
}).strict();
/** Routing stays in private configuration, not copied into evidence outputs. */
export const Source = z.object({
  category: Category,
  modelType: z.string().regex(
    /^@?[A-Za-z][A-Za-z0-9_-]*(\/[A-Za-z][A-Za-z0-9_-]*)+$/,
  ),
  modelId: z.string().uuid(),
  dataName: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/),
}).strict();
/** At most one source per fixed category; arbitrary labels/selectors are rejected. */
export const Sources = z.array(Source).min(1).max(6).refine(
  (sources) => new Set(sources.map((s) => s.category)).size === sources.length,
  "Categories must be unique",
);
const GlobalArgs = z.object({ sources: Sources }).strict();
/** A missing resource is not a zero-valued or successful observation. */
export const Observation = z.object({
  category: Category,
  version: z.number().int().positive().safe().nullable(),
  available: z.boolean(),
  metadata: OperationalMetadata.nullable(),
}).strict().refine(
  (o) =>
    o.available === (o.metadata !== null) &&
    (!o.available || o.version !== null),
  "Availability requires versioned metadata",
);
/** Stored snapshot contains no arbitrary text or pre-rendered Markdown. */
export const Snapshot = z.object({
  collectedAt: z.iso.datetime({ precision: 3 }),
  observations: z.array(Observation).min(1).max(6).refine(
    (rows) => new Set(rows.map((r) => r.category)).size === rows.length,
    "Categories must be unique",
  ),
}).strict();
/** Use Swamp's actual type object, obtained from the model repository/context. */
export type TypeRef = { toString(): string; toDirectoryPath(): string };
/** Public repository subset; no raw datastore or filesystem access. */
export type EvidenceRepository = {
  findByName(
    type: TypeRef,
    id: string,
    name: string,
    version?: number,
  ): Promise<
    {
      name: string;
      version: number;
      size?: number;
      isDeleted?: boolean;
    } | null
  >;
  stream(
    type: TypeRef,
    id: string,
    name: string,
    version: number,
  ): AsyncIterable<Uint8Array>;
};
/** Resolve configured UUIDs to the runtime's real model type, not a duck-typed path. */
export type EvidenceModels = {
  findByIdGlobal(id: string): Promise<{ type: TypeRef } | null>;
};

/**
 * Exact-name metadata lookup and pinned streaming content read. Limits this
 * extension's buffer, not backend-internal metadata/hydration/worker allocation.
 */
export async function readStored(
  repo: EvidenceRepository,
  type: TypeRef,
  id: string,
  name: string,
  version?: number,
  signal?: AbortSignal,
): Promise<{ version: number; bytes: Uint8Array | null } | null> {
  signal?.throwIfAborted();
  const data = await repo.findByName(type, id, name, version);
  signal?.throwIfAborted();
  if (!data) return null;
  if (data.name !== name) throw Error("Renamed evidence is not an exact match");
  if (data.isDeleted) return null;
  const size = data.size;
  if (
    !Number.isSafeInteger(data.version) || data.version < 1 ||
    (version !== undefined && data.version !== version) ||
    typeof size !== "number" || !Number.isSafeInteger(size) || size < 0 ||
    size > MAX_SNAPSHOT_BYTES
  ) throw Error("Invalid or oversized evidence metadata");
  const buffer = new Uint8Array(MAX_SNAPSHOT_BYTES);
  let used = 0;
  for await (const chunk of repo.stream(type, id, name, data.version)) {
    signal?.throwIfAborted();
    if (chunk.byteLength > MAX_SNAPSHOT_BYTES - used) {
      throw Error("Evidence exceeds size limit");
    }
    buffer.set(chunk, used);
    used += chunk.byteLength;
  }
  signal?.throwIfAborted();
  if (used !== size) throw Error("Evidence size differs from metadata");
  return {
    version: data.version,
    bytes: used ? buffer.subarray(0, used) : null,
  };
}

function decimalIdentity(text: string): string | null {
  const [mantissa, exponent = "0"] = text.toLowerCase().split("e");
  const negative = mantissa.startsWith("-");
  const [whole, fraction = ""] = mantissa.replace(/^-/, "").split(".");
  const digits = (whole + fraction).replace(/^0+/, "");
  if (!digits) return "0";
  const significant = digits.replace(/0+$/, "");
  const power = Number(exponent);
  if (!Number.isSafeInteger(power)) return null;
  return `${negative ? "-" : ""}${significant}e${
    power - fraction.length + digits.length - significant.length
  }`;
}
/** Decode bounded UTF-8 JSON without silently rounded or underflowed numbers. */
export function parseEvidence(bytes: Uint8Array): unknown {
  if (bytes.length > MAX_SNAPSHOT_BYTES) {
    throw Error("Evidence exceeds size limit");
  }
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    (_key: string, value: unknown, context?: { source?: string }) => {
      if (
        typeof value === "number" &&
        (!Number.isFinite(value) || Object.is(value, -0) ||
          context?.source === undefined ||
          decimalIdentity(context.source) !== decimalIdentity(String(value)))
      ) {
        throw Error("Unsupported evidence number");
      }
      return value;
    },
  );
}

/** Read the latest exact version of each fixed-contract source, without live probes. */
export async function collect(
  sources: z.infer<typeof Source>[],
  repo: EvidenceRepository,
  models: EvidenceModels,
  signal?: AbortSignal,
): Promise<z.infer<typeof Observation>[]> {
  signal?.throwIfAborted();
  sources = Sources.parse(sources);
  const out: z.infer<typeof Observation>[] = [];
  for (const source of sources) {
    signal?.throwIfAborted();
    const producer = await models.findByIdGlobal(source.modelId);
    signal?.throwIfAborted();
    if (!producer || String(producer.type) !== source.modelType) {
      throw Error("Source model type does not match configured UUID");
    }
    const stored = await readStored(
      repo,
      producer.type,
      source.modelId,
      source.dataName,
      undefined,
      signal,
    );
    const bytes = stored?.bytes ?? null;
    let metadata = null;
    if (bytes !== null) {
      try {
        metadata = OperationalMetadata.parse(parseEvidence(bytes));
      } catch {
        throw Error("Source does not conform to operational metadata v1");
      }
    }
    out.push(
      Observation.parse({
        category: source.category,
        version: stored?.version ?? null,
        available: metadata !== null,
        metadata,
      }),
    );
  }
  return out;
}

/** Only fixed names, enum values, bounded integers, flags and ISO times are rendered. */
export function render(observations: z.infer<typeof Observation>[]): string {
  return [
    "# Infrastructure observations",
    "Stored evidence, not a fresh probe. Collection time is not observation time. Schema validation is not a universal secret detector.",
    ...observations.map((input) => {
      const o = Observation.parse(input);
      const m = o.metadata;
      return [
        `## ${o.category}`,
        `Available: ${o.available}. Data version: ${o.version ?? "unknown"}.`,
        m
          ? `Source observation: ${
            m.observedAt ?? "unknown"
          }. Collector: ${m.collectorStatus}.`
          : "Source observation: unknown.",
        ...(m
          ? [
            `Expected: ${m.counts.expected}; observed: ${m.counts.observed}; unhealthy: ${m.counts.unhealthy}; unknown: ${m.counts.unknown}.`,
            `Reachable: ${m.flags.reachable ?? "unknown"}; configured: ${
              m.flags.configured ?? "unknown"
            }.`,
          ]
          : []),
      ].join("\n\n");
    }),
  ].join("\n\n");
}

/** Capture validated stored metadata with bounded retention and no backend authority. */
export const model = {
  type: "@jpisgeek/documentation-evidence",
  version: "2026.10.14.1",
  globalArguments: GlobalArgs,
  resources: {
    snapshot: {
      description:
        "Fixed operational metadata with original observation times and pinned versions",
      schema: Snapshot,
      lifetime: "30d",
      garbageCollection: 30,
    },
  },
  methods: {
    capture: {
      description:
        "Validate operational metadata v1 from existing stored resources; no arbitrary projections",
      arguments: z.object({}),
      execute: async (args: Record<string, never>, context: {
        globalArgs: unknown;
        signal?: AbortSignal;
        dataRepository: EvidenceRepository;
        definitionRepository: EvidenceModels;
        logger?: { info(message: string): void };
        writeResource(
          spec: string,
          name: string,
          data: Record<string, unknown>,
        ): Promise<{ name: string }>;
      }) => {
        try {
          z.object({}).strict().parse(args);
          context.signal?.throwIfAborted();
          const { sources } = GlobalArgs.parse(context.globalArgs);
          context.logger?.info("Capturing fixed operational metadata");
          const observations = await collect(
            sources,
            context.dataRepository,
            context.definitionRepository,
            context.signal,
          );
          const snapshot = Snapshot.parse({
            collectedAt: new Date().toISOString(),
            observations,
          });
          context.signal?.throwIfAborted();
          const handle = await context.writeResource(
            "snapshot",
            "snapshot",
            snapshot,
          );
          context.signal?.throwIfAborted();
          context.logger?.info("Captured fixed operational metadata");
          return { dataHandles: [handle] };
        } catch {
          context.signal?.throwIfAborted();
          throw Error(
            "Documentation evidence capture failed; check routing, pinned versions and operational metadata v1 schema",
          );
        }
      },
    },
  },
};
