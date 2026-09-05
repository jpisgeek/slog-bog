/** Persist explicit operator-supplied subscription facts without inference. */
import { z } from "npm:zod@4";

// priceMinor is read back by the report as Number(priceMinor). The old
// /^\d+(\.\d+)?$/ carried no length bound, so a pasted or fat-fingered
// 500-digit value validated here, persisted into a snapshot with a 365-day
// lifetime, and then coerced to Infinity in dashboard_subscription.ts, where
// ObservedMetricSchema requires .finite(). That threw inside the bundle parse,
// so every later report for the model failed whole rather than dropping one
// metric. Fifteen integer digits keeps every accepted value inside the
// exact-integer range of a double (2^53), so the round trip is lossless for a
// whole number.
//
// The digit bound alone was not enough. Fifteen integer digits AND four
// decimals is up to nineteen significant digits, which a double cannot hold:
// "999999999999999.9999" matched the regex, persisted for 365 days, and was
// then published by the report as the exact observed metric 1000000000000000 —
// a different price, emitted under a README that promises the conversion is
// lossless. A digit count cannot express "fits in a double", so the accepted
// value is instead round-tripped through the exact conversion the report
// performs, and rejected when what comes back is not what was declared.
function canonicalDecimal(value: string): string {
  const [whole, fraction = ""] = value.split(".");
  const trimmedWhole = whole.replace(/^0+(?=\d)/, "");
  const trimmedFraction = fraction.replace(/0+$/, "");
  return trimmedFraction ? `${trimmedWhole}.${trimmedFraction}` : trimmedWhole;
}
/**
 * True when `Number(value)` and back is the same decimal the operator wrote.
 * Trailing fraction zeros and leading integer zeros are not loss, so both sides
 * are canonicalized before the comparison; anything else that changes is.
 */
function decimalSurvivesNumberConversion(value: string): boolean {
  const converted = Number(value);
  if (!Number.isFinite(converted)) return false;
  return canonicalDecimal(value) === canonicalDecimal(String(converted));
}
const DecimalSchema = z.string().regex(/^\d{1,15}(\.\d{1,4})?$/).refine(
  decimalSurvivesNumberConversion,
  "priceMinor must survive the report's Number() conversion without loss",
);
// Rejecting userinfo, queries, and fragments left the two places a URL most
// often IS the secret: a hostname label (a per-account or tunnel subdomain such
// as https://a1b2c3d4.trycloudflare.com) and a path segment (an invite or share
// capability such as /invite/AbCd3fGh1JkLmN0pQrS). Both validated, persisted
// into a snapshot with a 365-day lifetime, and were re-emitted by the report as
// a reference. No test on the shape of an arbitrary URL can demonstrate that it
// carries no secret, so the set of storable references is finite and written
// here: one of these public vendor origins, with one of these non-secret paths.
// That leaves an operator no room to carry a credential through at all. Naming
// a new vendor is a source change that goes through review. Kept in agreement
// with the copy in dashboard_subscription.ts.
const ALLOWED_REFERENCE_ORIGINS = new Set([
  "https://www.anthropic.com",
  "https://openai.com",
  "https://proton.me",
  "https://github.com",
]);
const ALLOWED_REFERENCE_PATHS = new Set(["/", "/pricing", "/plans"]);
const ReferenceSchema = z.string().url().refine(
  (value) => {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password &&
      !url.search && !url.hash &&
      ALLOWED_REFERENCE_ORIGINS.has(url.origin) &&
      ALLOWED_REFERENCE_PATHS.has(url.pathname);
  },
  "sourceReference must be one of the allowed public vendor origins with an allowed non-secret path, must use https, and must not contain credentials, query parameters, or fragments",
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
  // Marked sensitive for the same reason as the top-level argument below: an
  // operator reference is commercial provenance and is classified as such by
  // the report, so the rendered config must not carry it in the clear either.
  sourceReference: ReferenceSchema.optional().describe(
    "Optional authorized stable API or operator reference",
  ).meta({ sensitive: true }),
  // .strict() here, not just on the snapshot: the outer object was strict while
  // this one silently stripped unknown nested keys, so the report's copy of this
  // schema — which is strict — rejected limits that capture had happily written.
  // The two copies must return the same verdict on the same bytes or the read
  // path stops being a re-check of the write path's guarantee.
}).strict().superRefine((limit, ctx) => {
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
/**
 * The identity a declared limit is known by: what is limited, in what unit,
 * over what period. The value is deliberately excluded — two entries that name
 * the same limit with different numbers are a contradiction, not two limits.
 * Kept byte-identical to the copy in dashboard_subscription.ts, which turns the
 * same string into the metric id.
 */
function limitIdentity(
  limit: { name: string; unit: string; period?: string },
): string {
  return JSON.stringify([limit.name, limit.unit, limit.period ?? null]);
}
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
  ).meta({ sensitive: true }),
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
  // A declared limit's dashboard metric id is derived from this triple (see
  // limitMetricId in dashboard_subscription.ts). Two limits sharing it would
  // produce two metrics with one id in the same section, and a renderer keying
  // by id shows whichever it saw last — one declared limit silently replacing
  // another. Refusing the snapshot is the only outcome that keeps the id a
  // stable name for exactly one declaration.
  const identities = new Set<string>();
  for (const [index, limit] of value.declaredLimits.entries()) {
    const identity = limitIdentity(limit);
    if (identities.has(identity)) {
      ctx.addIssue({
        code: "custom",
        path: ["declaredLimits", index],
        message:
          "declared limits must be distinct in name, unit, and period; duplicate identity",
      });
    }
    identities.add(identity);
  }
});
const CaptureArgsSchema = z.object({});
const SnapshotSchema = GlobalArgsSchema.safeExtend({
  // .strict() on the nested provenance for the same reason as LimitSchema: the
  // report's copy is strict, and an unknown key that this schema strips but that
  // one rejects means a snapshot capture wrote can be unreadable on the way out.
  provenance: z.object({
    kind: z.literal("operator-config"),
    capturedAt: z.iso.datetime(),
    sourceReference: ReferenceSchema.optional(),
  }).strict(),
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
    // The provider tag is gone. Tags are resource metadata: they are listed,
    // filtered, and logged apart from the resource body, so a field this
    // package classifies commercially sensitive was readable in places none of
    // the body's protections reach. It is still in the snapshot, where the
    // classification travels with it. Only the constant provenance marker,
    // which is the same string for every capture, stays.
    { tags: { provenance: "operator-config" } },
  );
  return { dataHandles: [handle] };
}
export const model = {
  type: "@jpisgeek/subscription-metadata",
  version: "2026.09.05.1",
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
