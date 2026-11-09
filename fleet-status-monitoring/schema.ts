import { z } from "npm:zod@4";
const Text = z.string().max(160).refine((s) =>
  ![...s].some((c) => {
    const n = c.charCodeAt(0);
    return n < 32 || (n >= 127 && n <= 159);
  })
);
const Count = z.number().finite().nonnegative().nullable();
export const Sample = z.strictObject({
  schemaVersion: z.literal(1),
  observedAt: z.iso.datetime({ offset: true }),
  family: z.enum(["macos", "linux", "windows", "other"]),
  osName: Text,
  osVersion: Text.nullable(),
  kernel: Text,
  architecture: Text,
  logicalCores: z.number().int().positive().nullable(),
  uptimeSeconds: Count,
  memoryTotalBytes: Count,
  memoryAvailableBytes: Count,
  memoryAvailableKind: Text,
  diskTotalBytes: Count,
  diskAvailableBytes: Count,
  load1: Count,
}).superRefine((s, c) => {
  for (
    const [a, t] of [[s.memoryAvailableBytes, s.memoryTotalBytes], [
      s.diskAvailableBytes,
      s.diskTotalBytes,
    ]]
  ) {
    if (a !== null && t !== null && (t <= 0 || a > t)) {
      c.addIssue({ code: "custom", message: "Invalid capacity counters" });
    }
  }
});
export const Target = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/),
  label: Text,
  group: z.enum(["macos", "linux", "windows", "appliances"]),
  kind: z.enum(["physical", "vm", "appliance", "unknown"]),
  collector: z.enum(["local", "ssh", "unconfigured"]),
  sourceHost: z.string().max(100).optional(),
  note: Text.default(""),
});
export const Observation = z.strictObject({
  ...Target.shape,
  checkedAt: z.iso.datetime(),
  cycleId: z.string().uuid(),
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
export type TargetValue = z.infer<typeof Target>;
export type ObservationValue = z.infer<typeof Observation>;
