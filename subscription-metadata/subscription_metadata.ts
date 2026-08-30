/** Persist explicit operator-supplied subscription facts without inference. */
import { z } from "npm:zod@4";

// priceMinor is read back by the report as Number(priceMinor). The old
// /^\d+(\.\d+)?$/ carried no length bound, so a pasted or fat-fingered
// 500-digit value validated here, persisted into a snapshot with a 365-day
// lifetime, and then coerced to Infinity in dashboard_subscription.ts, where
// ObservedMetricSchema requires .finite(). That threw inside the bundle parse,
// so every later report for the model failed whole rather than dropping one
// metric. Fifteen integer digits keeps every accepted value inside the
// exact-integer range of a double (2^53), so the round trip is lossless too.
const DecimalSchema = z.string().regex(/^\d{1,15}(\.\d{1,4})?$/);
const ReferenceSchema = z.string().url().refine(
  (value) => {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password &&
      !url.search && !url.hash;
  },
  "sourceReference must use https and must not contain credentials, query parameters, or fragments",
);
/**
 * Latin lookalikes, as source/target character pairs, for the Cyrillic and
 * Greek letters that can spell the forbidden words.
 */
const CONFUSABLE_PAIRS = "аaеeоoрpсcуyхxіiјjѕsмmтtкkвbнhαaεeοoρpνvιiκkτt";
const CONFUSABLES = new Map<string, string>();
for (let index = 0; index < CONFUSABLE_PAIRS.length; index += 2) {
  CONFUSABLES.set(CONFUSABLE_PAIRS[index], CONFUSABLE_PAIRS[index + 1]);
}

/**
 * Fold a declared string to the form the forbidden-pattern test runs against.
 * The old guard tested the raw string with a bare ASCII regex, so two spellings
 * a human reads as the forbidden phrase parsed cleanly: "rem<U+200B>aining
 * tokens", where a zero-width space splits the word, and "rem<U+0430>ining
 * quota", where Cyrillic U+0430 renders as a Latin "a". NFKC collapses
 * compatibility forms, the Cf/Cc strip removes zero-width and control
 * characters, and the confusable map collapses the lookalike letters.
 */
function foldDeclaredText(value: string): string {
  const stripped = value.normalize("NFKC").replace(/\p{Cf}|\p{Cc}/gu, "")
    .toLowerCase();
  return [...stripped].map((char) => CONFUSABLES.get(char) ?? char).join("");
}

/**
 * Declarations this package refuses to persist. "remain" and "avail" are stems
 * rather than whole words on purpose: the old /available/ never matched
 * "availability", which the README explicitly promises is rejected, and
 * /remaining/ never matched "remainder". The bounded gaps in the per-token
 * alternatives catch the spellings operators actually write, such as
 * "usd-per-1k-tokens".
 */
const FORBIDDEN_DECLARATION =
  /remain|avail|left|per.{0,8}tokens?|tokens?.{0,8}price/;
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
  // This guard is what backs the README's central promise: "never derives
  // remaining quota or per-token cost". It used to test limit.name only. The
  // unit and the period are declarations too, so ordinary, non-adversarial
  // entries carried the forbidden fact straight past it:
  //   {name: "Rate", value: 0.002, unit: "usd-per-token"}
  //   {name: "Included", value: 500, unit: "requests-remaining"}
  //   {name: "Budget", value: 5, unit: "usd", period: "per token remaining"}
  // Each of those validated, persisted into the 365-day snapshot, and rendered
  // on the dashboard as an exact observed metric — a per-token price published
  // under a guarantee that says per-token prices are rejected. All three fields
  // are checked now, and each is folded first so an invisible character or a
  // homoglyph cannot break a word the reader still sees intact.
  for (const field of ["name", "unit", "period"] as const) {
    const declared = limit[field];
    if (
      declared !== undefined &&
      FORBIDDEN_DECLARATION.test(foldDeclaredText(declared))
    ) {
      ctx.addIssue({
        code: "custom",
        path: [field],
        message:
          "remaining quota and per-token price declarations are forbidden",
      });
    }
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
