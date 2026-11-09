import { z } from "npm:zod@4";
const Text = z.string().max(160).refine((s) =>
  ![...s].some((c) => {
    const n = c.charCodeAt(0);
    return n < 32 || (n >= 127 && n <= 159);
  })
);
const Metric = z.number().finite().nonnegative().nullable();
/** Validated public projection of the collector contract. */
export const Sample = z.object({
  observedAt: z.iso.datetime({ offset: true }),
  family: z.enum(["macos", "linux", "windows", "other"]),
  osName: Text,
  osVersion: Text.nullable(),
  kernel: Text,
  architecture: Text,
  logicalCores: z.number().int().positive().nullable(),
  uptimeSeconds: Metric,
  memoryTotalBytes: Metric,
  memoryAvailableBytes: Metric,
  memoryAvailableKind: Text,
  diskTotalBytes: Metric,
  diskAvailableBytes: Metric,
  load1: Metric,
});
/** Validated public projection of the collector contract. */
export const Observation = z.object({
  id: z.string().min(1).max(64),
  label: Text,
  group: Text,
  kind: Text,
  collector: Text,
  note: Text,
  cycleId: z.string().uuid(),
  checkedAt: z.iso.datetime(),
  state: z.enum([
    "observed",
    "unreachable",
    "access-required",
    "unsupported",
    "unavailable",
  ]),
  reason: Text,
  sample: Sample.nullable(),
  sourceVersion: z.number().int().positive().nullable(),
  sourceWorkflowRunId: z.string().max(100).nullable(),
});
/** Operator-defined thresholds and maximum observation age. */
export const Policy = z.object({
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
  issues: z.array(Text),
});
/** Canonical fleet report, preserving original observation and run evidence. */
export const State = z.object({
  schemaVersion: z.literal(1),
  title: z.literal("Fleet Status Monitoring"),
  generatedAt: z.iso.datetime(),
  scanStartedAt: z.iso.datetime(),
  cycleId: z.string().uuid(),
  sourceVersion: z.number().int().positive().nullable(),
  workflowRunId: z.string().max(100).nullable(),
  policy: Policy,
  systems: z.array(Row).min(1).max(100),
  totals: z.object({
    configured: z.number().int().nonnegative().max(100),
    scanned: z.number().int().nonnegative().max(100),
    healthy: z.number().int().nonnegative().max(100),
    attention: z.number().int().nonnegative().max(100),
    gaps: z.number().int().nonnegative().max(100),
  }),
  operatingSystems: z.array(
    z.object({
      family: Text,
      version: Text,
      count: z.number().int().min(1).max(100),
    }),
  ).max(100),
  exclusions: z.array(z.string().max(500)).max(64),
});
/** Validated state shared by reporting and hosting. */
export type FleetState = z.infer<typeof State>;
