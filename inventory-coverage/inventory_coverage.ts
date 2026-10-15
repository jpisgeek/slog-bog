/** Coverage of fixed operational metadata, not arbitrary selected conditions. */
import { z } from "npm:zod@4";
import {
  CaptureArgs,
  collect,
  type EvidenceModels,
  type EvidenceRepository,
  Observation,
  render as renderEvidence,
  Sources,
  strictObject,
} from "../documentation-evidence/documentation_evidence.ts";

const Args = strictObject({
  sources: Sources,
  maxAgeSeconds: z.number().int().positive().max(31_536_000).default(3600),
});
const Row = strictObject({
  observation: Observation,
  freshness: z.enum(["fresh", "stale", "unknown", "unavailable", "error"]),
  condition: z.enum(["clear", "degraded", "unknown"]),
  complete: z.boolean(),
});
type Row = z.infer<typeof Row>;

function assess(
  observation: z.infer<typeof Observation>,
  now: number,
  maxAge: number,
  error = false,
): Row {
  const m = observation.metadata;
  const when = m?.observedAt === null || m === null
    ? NaN
    : Date.parse(m.observedAt);
  const freshness = error
    ? "error"
    : !observation.available
    ? "unavailable"
    : !Number.isFinite(when) || when > now
    ? "unknown"
    : now - when > maxAge * 1000
    ? "stale"
    : "fresh";
  const incomplete = m === null || m.collectorStatus !== "succeeded" ||
    m.counts.expected !== m.counts.observed || m.counts.unknown > 0 ||
    m.flags.reachable === null || m.flags.configured === null;
  const degraded = m !== null &&
    (m.collectorStatus === "failed" || m.counts.unhealthy > 0 ||
      m.flags.reachable === false || m.flags.configured === false);
  return {
    observation,
    freshness,
    condition: degraded ? "degraded" : incomplete ? "unknown" : "clear",
    complete: freshness === "fresh" && !incomplete,
  };
}

/** Coverage is complete evidence, not necessarily healthy services; derived fields are checked. */
export const Summary = strictObject({
  assessedAt: z.iso.datetime({ precision: 3 }),
  maxAgeSeconds: z.number().int().positive().max(31_536_000),
  coverageComplete: z.boolean(),
  sources: z.number().int().min(1).max(6),
  fresh: z.number().int().min(0).max(6),
  degraded: z.number().int().min(0).max(6),
  rows: z.array(Row).min(1).max(6),
}).refine(
  (s) =>
    s.sources === s.rows.length &&
    new Set(s.rows.map((r) => r.observation.category)).size === s.rows.length &&
    s.fresh === s.rows.filter((r) => r.freshness === "fresh").length &&
    s.degraded === s.rows.filter((r) => r.condition === "degraded").length &&
    s.coverageComplete === s.rows.every((r) => r.complete) &&
    s.rows.every((r) => {
      if (
        r.freshness === "error" &&
        (r.observation.available || r.observation.version !== null)
      ) return false;
      const expected = assess(
        r.observation,
        Date.parse(s.assessedAt),
        s.maxAgeSeconds,
        r.freshness === "error",
      );
      return r.freshness === expected.freshness &&
        r.condition === expected.condition && r.complete === expected.complete;
    }),
  "Counters, fixed categories and derived assessments must agree with evidence",
);

/** Assess declared sources; errors remain explicit and never erase other source results. */
export async function capture(
  args: z.input<typeof Args>,
  repo: EvidenceRepository,
  models: EvidenceModels,
  now = Date.now(),
  signal?: AbortSignal,
): Promise<z.infer<typeof Summary>> {
  signal?.throwIfAborted();
  const parsed = Args.parse(args);
  const assessedAt = new Date(now).toISOString();
  const rows: Row[] = [];
  for (const source of parsed.sources) {
    try {
      const [observation] = await collect([source], repo, models, signal);
      rows.push(assess(observation, now, parsed.maxAgeSeconds));
    } catch {
      signal?.throwIfAborted();
      rows.push(
        assess(
          {
            category: source.category,
            version: null,
            available: false,
            metadata: null,
          },
          now,
          parsed.maxAgeSeconds,
          true,
        ),
      );
    }
  }
  signal?.throwIfAborted();
  return Summary.parse({
    assessedAt,
    maxAgeSeconds: parsed.maxAgeSeconds,
    coverageComplete: rows.every((r) => r.complete),
    sources: rows.length,
    fresh: rows.filter((r) => r.freshness === "fresh").length,
    degraded: rows.filter((r) => r.condition === "degraded").length,
    rows,
  });
}

/** Report freshness as of assessedAt; it is never re-stamped on report retrieval. */
export function render(input: z.infer<typeof Summary>): string {
  const s = Summary.parse(input);
  return [
    "# Inventory coverage",
    `Assessed: ${s.assessedAt}. Freshness budget: ${s.maxAgeSeconds} seconds.`,
    `Coverage complete: ${s.coverageComplete}. Fresh: ${s.fresh}/${s.sources}. Degraded stored observations: ${s.degraded}.`,
    "Complete coverage is not service health. Freshness describes stored observation age, not the latest collector run. Error means unreadable or invalid evidence; unavailable means missing evidence.",
    ...s.rows.map((r) =>
      `- ${r.observation.category}: ${r.freshness}; condition ${r.condition}; complete ${r.complete}.`
    ),
    renderEvidence(s.rows.map((r) => r.observation)),
  ].join("\n\n");
}

/** Fixed-contract stored-evidence model with no live-backend authority. */
export const model = {
  type: "@jpisgeek/inventory-coverage",
  version: "2026.10.14.2",
  globalArguments: Args,
  resources: {
    summary: {
      description:
        "Typed operational evidence with explicit coverage, unknown, stale and error states",
      schema: Summary,
      lifetime: "30d",
      garbageCollection: 30,
    },
  },
  methods: {
    capture: {
      description:
        "Assess operational metadata v1 without contacting external services",
      arguments: CaptureArgs,
      execute: async (args: Record<string, never>, ctx: {
        globalArgs: unknown;
        dataRepository: EvidenceRepository;
        definitionRepository: EvidenceModels;
        signal?: AbortSignal;
        logger?: { info(message: string): void };
        writeResource(
          spec: string,
          name: string,
          data: Record<string, unknown>,
        ): Promise<{ name: string }>;
      }) => {
        try {
          CaptureArgs.parse(args);
          ctx.logger?.info("Assessing fixed operational metadata coverage");
          const summary = await capture(
            Args.parse(ctx.globalArgs),
            ctx.dataRepository,
            ctx.definitionRepository,
            Date.now(),
            ctx.signal,
          );
          ctx.signal?.throwIfAborted();
          const handle = await ctx.writeResource("summary", "summary", summary);
          ctx.signal?.throwIfAborted();
          ctx.logger?.info("Captured operational metadata coverage");
          return { dataHandles: [handle] };
        } catch {
          ctx.signal?.throwIfAborted();
          throw Error(
            "Inventory coverage capture failed; check fixed-schema configuration and storage availability",
          );
        }
      },
    },
  },
};
