import { z } from "npm:zod@4";

/** Minimal versioned evidence returned by Swamp's cross-behavior reader. */
export type EvidenceRecord = {
  name?: string;
  attributes?: unknown;
  version?: number;
  workflowRunId?: string;
  tags?: Record<string, string>;
};
/** Swamp ports used by evidence readers; no filesystem or provider access. */
export type EvidenceReader = {
  definition: { name: string };
  readResource: (name: string) => Promise<Record<string, unknown> | null>;
  readModelData: (name: string, spec?: string) => Promise<EvidenceRecord[]>;
};
/** Structured logging subset provided by Swamp. */
export type FleetLogger = {
  info: (message: string, ...args: unknown[]) => void;
  debug: (message: string, ...args: unknown[]) => void;
  warn: (message: string, ...args: unknown[]) => void;
};
/** Read nonempty, bounded workflow provenance without inventing a run identity. */
export function evidenceRun(
  record: EvidenceRecord | undefined,
  source = "stored evidence",
) {
  const value = record?.workflowRunId || record?.tags?.workflowRunId;
  if (!value) return undefined;
  const parsed = z.string().min(1).max(100).safeParse(value);
  if (!parsed.success) {
    throw Error(
      `Invalid workflow run identity in ${source}; rerun the complete fleet workflow`,
    );
  }
  return parsed.data;
}
/** Rank validated timestamps; version numbers break ties only within one instance. */
export function newestEvidence(
  rows: EvidenceRecord[],
  field: "startedAt" | "checkedAt",
  instance?: string,
): EvidenceRecord | undefined {
  return rows.flatMap((row) => {
    if (instance && row.name !== undefined && row.name !== instance) return [];
    const raw = row.attributes;
    const stamp = z.iso.datetime({ offset: true }).safeParse(
      raw && typeof raw === "object" && field in raw
        ? (raw as Record<string, unknown>)[field]
        : undefined,
    );
    return stamp.success ? [{ row, stamp: Date.parse(stamp.data) }] : [];
  }).sort((a, b) =>
    b.stamp - a.stamp ||
    (a.row.name === b.row.name
      ? (b.row.version ?? 0) - (a.row.version ?? 0)
      : (a.row.name ?? "").localeCompare(b.row.name ?? ""))
  )[0]?.row;
}

/**
 * Read own attributes through readResource, then recover their version/run metadata.
 * readResource exposes no metadata. The separate metadata lookup must match the
 * complete validated payload; a concurrent replacement fails rather than mixing runs.
 */
export async function ownEvidence<T extends Record<string, unknown>>(
  ctx: EvidenceReader,
  instance: string,
  schema: z.ZodType<T>,
): Promise<EvidenceRecord | undefined> {
  const raw = await ctx.readResource(instance);
  if (raw === null) return undefined;
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    throw Error(
      `Invalid ${instance} in ${ctx.definition.name}; rerun the complete fleet workflow from begin`,
    );
  }
  const attributes = parsed.data;
  const matching = (await ctx.readModelData(ctx.definition.name, instance))
    .filter((r) => {
      if (r.name !== undefined && r.name !== instance) return false;
      const candidate = schema.safeParse(r.attributes);
      return candidate.success &&
        JSON.stringify(candidate.data) === JSON.stringify(attributes);
    });
  if (matching.length !== 1) {
    throw Error(
      `Cannot match ${instance} attributes to versioned evidence in ${ctx.definition.name}; rerun the complete fleet workflow`,
    );
  }
  return { ...matching[0], attributes };
}
