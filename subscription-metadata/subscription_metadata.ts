/** Persist explicit operator-supplied subscription facts without inference. */
import { z } from "npm:zod@4";

const DecimalSchema = z.string().regex(/^\d+(\.\d+)?$/);
const ReferenceSchema = z.string().url().refine(
  (value) => {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password &&
      !url.search && !url.hash;
  },
  "sourceReference must use https and must not contain credentials, query parameters, or fragments",
);
const LimitSchema = z.object({
  name: z.string().min(1).describe("Provider-declared limit name"),
  value: z.number().nonnegative().finite().describe(
    "Declared numeric limit; explicit zero is preserved",
  ),
  unit: z.string().regex(/^[a-z][a-z0-9._-]*$/).describe(
    "Provider-declared unit",
  ),
  period: z.string().min(1).optional().describe(
    "Optional reset or measurement period",
  ),
  sourceReference: ReferenceSchema.optional().describe(
    "Optional authorized stable API or operator reference",
  ),
}).superRefine((limit, ctx) => {
  if (/remaining|available|left|per.?token|token.?price/i.test(limit.name)) {
    ctx.addIssue({
      code: "custom",
      path: ["name"],
      message: "remaining quota and per-token price declarations are forbidden",
    });
  }
});
const GlobalArgsSchema = z.object({
  provider: z.string().min(1).describe(
    "Subscription provider or product family",
  ),
  planName: z.string().min(1).optional(),
  billingCadence: z.enum([
    "monthly",
    "annual",
    "quarterly",
    "weekly",
    "one-time",
    "other",
  ]).optional(),
  priceMinor: DecimalSchema.optional().describe(
    "Declared recurring price in currency minor units",
  ),
  currency: z.string().regex(/^[A-Z]{3}$/).optional(),
  renewalStart: z.iso.datetime().optional(),
  renewalEnd: z.iso.datetime().optional(),
  seats: z.number().int().nonnegative().optional().describe(
    "Declared seat count; explicit zero is preserved",
  ),
  declaredLimits: z.array(LimitSchema).default([]),
  sourceReference: ReferenceSchema.optional().describe(
    "Optional authorized stable API or operator reference",
  ),
}).strict().superRefine((value, ctx) => {
  if ((value.priceMinor === undefined) !== (value.currency === undefined)) {
    ctx.addIssue({
      code: "custom",
      path: ["currency"],
      message: "priceMinor and currency must be supplied together",
    });
  }
  if (
    value.renewalStart && value.renewalEnd &&
    Date.parse(value.renewalStart) > Date.parse(value.renewalEnd)
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["renewalStart"],
      message: "renewalStart must not follow renewalEnd",
    });
  }
});
const CaptureArgsSchema = z.object({});
const SnapshotSchema = GlobalArgsSchema.safeExtend({
  provenance: z.object({
    kind: z.literal("operator-config"),
    capturedAt: z.iso.datetime(),
    sourceReference: ReferenceSchema.optional(),
  }),
}).strict();
interface Context {
  globalArgs: unknown;
  writeResource(
    spec: string,
    name: string,
    data: z.infer<typeof SnapshotSchema>,
    options?: { tags?: Record<string, string> },
  ): Promise<unknown>;
}
async function capture(_args: z.infer<typeof CaptureArgsSchema>, ctx: Context) {
  const declared = GlobalArgsSchema.parse(ctx.globalArgs);
  const snapshot = SnapshotSchema.parse({
    ...declared,
    provenance: {
      kind: "operator-config",
      capturedAt: new Date().toISOString(),
      sourceReference: declared.sourceReference,
    },
  });
  const handle = await ctx.writeResource(
    "snapshot",
    "subscription-metadata",
    snapshot,
    { tags: { provider: snapshot.provider, provenance: "operator-config" } },
  );
  return { dataHandles: [handle] };
}
export const model = {
  type: "@jpisgeek/subscription-metadata",
  version: "2026.08.25.2",
  globalArguments: GlobalArgsSchema,
  resources: {
    snapshot: {
      description:
        "Explicit subscription plan metadata with operator provenance and no derived quota or usage cost.",
      schema: SnapshotSchema,
      lifetime: "365d" as const,
      garbageCollection: 24,
    },
  },
  methods: {
    capture: {
      description:
        "Persist the configured plan facts exactly as declared without network access or derived values.",
      arguments: CaptureArgsSchema,
      execute: capture,
    },
  },
};
