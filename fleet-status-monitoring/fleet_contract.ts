import { z } from "npm:zod@4";
const Text = z.string().max(160).refine((s) =>
  ![...s].some((c) => {
    const n = c.charCodeAt(0);
    return n < 32 || (n >= 127 && n <= 159);
  })
);
import { Observation as SourceObservation, Sample } from "./schema.ts";
export { Sample } from "./schema.ts";
/** Strict report projection: remove only the private transport locator. */
export const Observation = SourceObservation.omit({ sourceHost: true });
/** Explicitly project a validated source row; all enums and sample versions survive. */
export function projectObservation(raw: unknown): z.infer<typeof Observation> {
  const { sourceHost: _sourceHost, ...publicFields } = SourceObservation.parse(
    raw,
  );
  return Observation.parse(publicFields);
}
/** Operator-defined thresholds and maximum observation age. */
export const Policy = z.strictObject({
  maxAgeSeconds: z.number().int().min(60).max(86400).default(1800),
  minMemoryPercent: z.number().min(0).max(100).default(5),
  minDiskPercent: z.number().min(0).max(100).default(5),
  minDiskBytes: z.number().nonnegative().default(10 * 1024 ** 3),
  maxLoadPerCore: z.number().positive().default(2),
});
/** Assessed system row with explicit health and coverage findings. */
export const Row = Observation.extend({
  health: z.enum([
    "healthy",
    "attention",
    "unknown",
    "stale",
    "unreachable",
    "access-required",
    "unsupported",
  ]),
  issues: z.array(Text).max(16),
});
/** Canonical fleet report, preserving original observation and run evidence. */
export const State = z.strictObject({
  schemaVersion: z.literal(1),
  title: z.literal("Fleet Status Monitoring"),
  generatedAt: z.iso.datetime(),
  scanStartedAt: z.iso.datetime(),
  cycleId: z.string().uuid(),
  sourceVersion: z.number().int().positive().nullable(),
  workflowRunId: z.string().max(100).nullable(),
  policy: Policy,
  systems: z.array(Row).min(1).max(100),
  totals: z.strictObject({
    configured: z.number().int().nonnegative().max(100),
    scanned: z.number().int().nonnegative().max(100),
    healthy: z.number().int().nonnegative().max(100),
    attention: z.number().int().nonnegative().max(100),
    gaps: z.number().int().nonnegative().max(100),
  }),
  operatingSystems: z.array(
    z.strictObject({
      family: Sample.shape.family,
      version: Text,
      count: z.number().int().min(1).max(100),
    }),
  ).max(100),
  exclusions: z.array(z.string().max(500)).max(64),
});
/** Validated state shared by reporting and hosting. */
export type FleetState = z.infer<typeof State>;
