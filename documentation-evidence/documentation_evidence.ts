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
/** Object declarations retain Swamp's shape introspection; raw inputs are checked separately. */
export function strictObject<T extends z.ZodRawShape>(shape: T) {
  return z.object(shape).strict();
}
function unexpectedMember(value: unknown, shape: object): boolean {
  return value !== null && typeof value === "object" &&
    Reflect.ownKeys(value).some((key) => !Object.hasOwn(shape, key));
}
/** Check untouched global arguments before an object parser can discard reserved keys. */
export function parseArguments<T extends z.ZodRawShape>(
  schema: z.ZodObject<T>,
  value: unknown,
) {
  if (unexpectedMember(value, schema.shape)) {
    throw Error("Unexpected configuration member");
  }
  return schema.parse(value);
}
/** An empty finite-key record rejects every method input without merging globals. */
export const CaptureArgs = z.record(z.enum([]), z.never());
const Count = z.number().int().min(0).max(1_000_000);
/** Version 1 producer contract. Every key is required; null means unknown. */
export const OperationalMetadata = strictObject({
  schemaVersion: z.literal(1),
  observedAt: z.iso.datetime({ precision: 3 }).nullable(),
  collectorStatus: z.enum(["succeeded", "failed", "unknown"]),
  counts: strictObject({
    expected: Count,
    observed: Count,
    unhealthy: Count,
    unknown: Count,
  }).refine(
    (c) => c.observed <= c.expected && c.unhealthy + c.unknown <= c.observed,
    "Observed cannot exceed expected; unhealthy plus unknown cannot exceed observed",
  ),
  flags: strictObject({
    reachable: z.boolean().nullable(),
    configured: z.boolean().nullable(),
  }),
});
const SourceObject = strictObject({
  category: Category,
  modelType: z.string().regex(
    /^@?[A-Za-z][A-Za-z0-9_-]*(\/[A-Za-z][A-Za-z0-9_-]*)+$/,
  ),
  modelId: z.string().uuid().regex(/^[0-9a-f-]+$/),
  dataName: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/),
});
/** Reject raw routing members before Zod's version-dependent reserved-key handling. */
export const Source = z.preprocess((value, ctx) => {
  if (unexpectedMember(value, SourceObject.shape)) {
    ctx.addIssue({ code: "custom", message: "Unexpected source member" });
    return z.NEVER;
  }
  return value;
}, SourceObject);
/** At most one source per fixed category; arbitrary labels/selectors are rejected. */
export const Sources = z.array(Source).min(1).max(6).refine(
  (sources) => new Set(sources.map((s) => s.category)).size === sources.length,
  "Categories must be unique",
).refine(
  (sources) =>
    new Set(sources.map((s) =>
      JSON.stringify([
        s.modelType,
        s.modelId,
        s.dataName,
      ])
    )).size === sources.length,
  "A source resource cannot satisfy multiple categories",
);
const GlobalArgs = strictObject({ sources: Sources });
/** A missing resource is not a zero-valued or successful observation. */
export const Observation = strictObject({
  category: Category,
  version: z.number().int().positive().safe().nullable(),
  available: z.boolean(),
  metadata: OperationalMetadata.nullable(),
}).refine(
  (o) =>
    o.available === (o.metadata !== null) &&
    (!o.available || o.version !== null),
  "Availability requires versioned metadata",
);
/** Stored snapshot contains no arbitrary text or pre-rendered Markdown. */
export const Snapshot = strictObject({
  collectedAt: z.iso.datetime({ precision: 3 }),
  observations: z.array(Observation).min(1).max(6).refine(
    (rows) => new Set(rows.map((r) => r.category)).size === rows.length,
    "Categories must be unique",
  ),
});
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
  findAllByIdGlobal?(id: string): Promise<Array<{ type: TypeRef }>>;
};

// Bound caller waiting, not backend work: the repository API has no abort input.
async function readWithin<T>(
  read: (wait: <V>(pending: Promise<V>) => Promise<V>) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  signal?.throwIfAborted();
  let timer: ReturnType<typeof setTimeout>;
  let abort: () => void;
  let timeout: Error | undefined;
  const stopped = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      timeout = Error("Evidence read timed out");
      reject(timeout);
    }, 30_000);
    abort = () => reject(signal!.reason);
    signal?.addEventListener("abort", abort, { once: true });
  });
  try {
    return await read(async (pending) => {
      const value = await Promise.race([pending, stopped]);
      // An already fulfilled first entry can win even when stopped rejected.
      if (timeout) throw timeout;
      signal?.throwIfAborted();
      return value;
    });
  } finally {
    clearTimeout(timer!);
    signal?.removeEventListener("abort", abort!);
  }
}

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
  return await readWithin(async (wait) => {
    const data = await wait(repo.findByName(type, id, name, version));
    signal?.throwIfAborted();
    if (!data) return null;
    if (data.name !== name) {
      throw Error("Renamed evidence is not an exact match");
    }
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
    let chunks = 0;
    const iterator = repo.stream(type, id, name, data.version)
      [Symbol.asyncIterator]();
    let done = false;
    try {
      while (!done) {
        const item = await wait(iterator.next());
        signal?.throwIfAborted();
        done = item.done === true;
        if (done) break;
        // Empty chunks consume a finite budget too. Yield to tasks so an
        // immediately resolved iterator cannot starve deadline/abort timers.
        if (++chunks > MAX_SNAPSHOT_BYTES) {
          throw Error("Evidence exceeds chunk limit");
        }
        if (chunks % 64 === 0) {
          await new Promise<void>((resolve) => setTimeout(resolve, 1));
          signal?.throwIfAborted();
        }
        const chunk = item.value;
        if (chunk.byteLength > MAX_SNAPSHOT_BYTES - used) {
          throw Error("Evidence exceeds size limit");
        }
        buffer.set(chunk, used);
        used += chunk.byteLength;
      }
    } finally {
      if (!done) {
        // Do not wait indefinitely for a pending pull/close the API cannot cancel.
        try {
          void iterator.return?.().catch(() => undefined);
        } catch {
          // Cleanup must not replace cancellation or the original read failure.
        }
      }
    }
    signal?.throwIfAborted();
    if (used !== size) throw Error("Evidence size differs from metadata");
    return {
      version: data.version,
      bytes: used ? buffer.subarray(0, used) : null,
    };
  }, signal);
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
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  // Scan strings and structural tokens before JSON.parse discards duplicate
  // members. Full syntax and decimal validation remain with JSON.parse below.
  const stack: Array<{ keys: Set<string> | null; key: boolean }> = [];
  for (const [token] of text.matchAll(/"(?:\\.|[^"\\])*"|[{}[\],:]/g)) {
    const frame = stack.at(-1);
    if (token === "{" || token === "[") {
      stack.push({ keys: token === "{" ? new Set() : null, key: true });
      if (stack.length > 16) throw Error("Evidence nesting exceeds limit");
    } else if (token === "}" || token === "]") {
      stack.pop();
    } else if (token === "," && frame) {
      frame.key = true;
    } else if (token.startsWith('"') && frame?.keys && frame.key) {
      const key = JSON.parse(token) as string;
      if (key === "__proto__") throw Error("Unsupported evidence member");
      if (frame.keys.has(key)) throw Error("Duplicate evidence member");
      frame.keys.add(key);
      frame.key = false;
    }
  }
  return JSON.parse(
    text,
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
    if (!models.findAllByIdGlobal) {
      throw Error("Collision-safe definition lookup is required");
    }
    const producers = await readWithin(
      (wait) => wait(models.findAllByIdGlobal!(source.modelId)),
      signal,
    );
    signal?.throwIfAborted();
    const matches = producers.filter((p) =>
      String(p.type) === source.modelType
    );
    if (matches.length !== 1) {
      throw Error("Source UUID/type is missing or ambiguous");
    }
    const stored = await readStored(
      repo,
      matches[0].type,
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
  version: "2026.10.15.1",
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
      arguments: CaptureArgs,
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
          CaptureArgs.parse(args);
          context.signal?.throwIfAborted();
          const { sources } = parseArguments(GlobalArgs, context.globalArgs);
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
