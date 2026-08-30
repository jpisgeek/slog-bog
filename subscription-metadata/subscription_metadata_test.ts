import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./subscription_metadata.ts";
type Json = Record<string, unknown>;
async function run(globalArgs: Json) {
  const written: Json[] = [];
  await model.methods.capture.execute({}, {
    globalArgs,
    writeResource: (_s: string, _n: string, data: Json) => {
      written.push(data);
      return Promise.resolve({});
    },
  });
  return written[0];
}
Deno.test("unknown optional limits and plan facts remain absent", async () => {
  const snapshot = await run({ provider: "Example AI" });
  assertEquals("planName" in snapshot, false);
  assertEquals("priceMinor" in snapshot, false);
  assertEquals((snapshot.declaredLimits as unknown[]).length, 0);
  assertEquals("remainingQuota" in snapshot, false);
});
Deno.test("explicit zero seats and limits are preserved", async () => {
  const snapshot = await run({
    provider: "Example AI",
    seats: 0,
    declaredLimits: [{
      name: "included requests",
      value: 0,
      unit: "requests",
      period: "month",
    }],
  });
  assertEquals(snapshot.seats, 0);
  assertEquals((snapshot.declaredLimits as Json[])[0].value, 0);
});
Deno.test("price requires currency and remains a decimal minor-unit string", async () => {
  const snapshot = await run({
    provider: "Example AI",
    priceMinor: "2500",
    currency: "USD",
  });
  assertEquals(snapshot.priceMinor, "2500");
  await assertRejects(
    () => run({ provider: "Example AI", priceMinor: "2500" }),
    Error,
    "priceMinor and currency",
  );
});
Deno.test("remaining quota and token price declarations are rejected", async () => {
  for (
    const name of ["remaining tokens", "available quota", "per-token price"]
  ) {
    await assertRejects(
      () =>
        run({
          provider: "Example AI",
          declaredLimits: [{ name, value: 1, unit: "tokens" }],
        }),
      Error,
      "forbidden",
    );
  }
  await assertRejects(
    () => run({ provider: "Example AI", remainingQuota: 10 }),
    Error,
    "Unrecognized key",
  );
});

// The guard used to read limit.name only, so a per-token price or a remaining
// quota declared through the unit or the period validated and reached the
// dashboard as an exact observed metric. Each entry below is a plain thing an
// operator would type, not an evasion attempt.
Deno.test("forbidden declarations carried by unit or period are rejected", async () => {
  const forbidden = [
    { name: "Rate", value: 0.002, unit: "usd-per-token" },
    { name: "Included", value: 500, unit: "requests-remaining" },
    { name: "Bucket", value: 100, unit: "tokens", period: "per token" },
    { name: "Budget", value: 5, unit: "usd", period: "tokens remaining" },
    { name: "Blended", value: 3, unit: "usd-per-1k-tokens" },
    { name: "Availability window", value: 1, unit: "ratio" },
  ];
  for (const limit of forbidden) {
    await assertRejects(
      () => run({ provider: "Example AI", declaredLimits: [limit] }),
      Error,
      "forbidden",
      `expected ${JSON.stringify(limit)} to be rejected`,
    );
  }
});

// Zero-width and homoglyph spellings render to a human as the forbidden phrase.
// The old ASCII regex saw a different string and let both through.
Deno.test("invisible characters and homoglyphs do not evade the guard", async () => {
  const names = [
    "rem​aining tokens", // zero-width space splits the word
    "remаining quota", // Cyrillic а
    "аvаilable credits", // Cyrillic а twice
    "ᵖer-token price", // NFKC-foldable modifier letter
  ];
  for (const name of names) {
    await assertRejects(
      () =>
        run({
          provider: "Example AI",
          declaredLimits: [{ name, value: 1, unit: "tokens" }],
        }),
      Error,
      "forbidden",
      `expected ${JSON.stringify(name)} to be rejected`,
    );
  }
});

// Guard against the fix over-reaching: these are the ordinary declarations the
// README's own example uses, and they must still capture.
Deno.test("legitimate limit declarations still capture", async () => {
  const snapshot = await run({
    provider: "Example AI",
    declaredLimits: [
      {
        name: "Included requests",
        value: 1000,
        unit: "requests",
        period: "month",
      },
      { name: "Context window", value: 200000, unit: "tokens" },
      { name: "Throughput", value: 40, unit: "tokens-per-second" },
      {
        name: "Seats included",
        value: 4,
        unit: "count",
        period: "billing cycle",
      },
    ],
  });
  assertEquals((snapshot.declaredLimits as Json[]).length, 4);
});

// priceMinor had no digit bound, so a 500-digit paste persisted for 365 days and
// then coerced to Infinity in the report, where the bundle requires a finite
// value — the whole report threw rather than dropping one metric.
Deno.test("priceMinor is bounded to a value that survives Number()", async () => {
  await assertRejects(
    () =>
      run({
        provider: "Example AI",
        priceMinor: "9".repeat(500),
        currency: "USD",
      }),
    Error,
    "priceMinor",
  );
  const snapshot = await run({
    provider: "Example AI",
    priceMinor: "999999999999999",
    currency: "USD",
  });
  const value = Number(snapshot.priceMinor as string);
  assertEquals(Number.isFinite(value), true);
  assertEquals(Number.isSafeInteger(value), true);
});
Deno.test("renewal window must be ordered", async () => {
  await assertRejects(
    () =>
      run({
        provider: "Example AI",
        renewalStart: "2026-09-01T00:00:00Z",
        renewalEnd: "2026-08-01T00:00:00Z",
      }),
    Error,
    "renewalStart",
  );
});

Deno.test("source references reject embedded secrets and signed queries", async () => {
  for (
    const sourceReference of [
      "https://user:secret@example.invalid/docs",
      "https://example.invalid/docs?token=private",
      "http://example.invalid/docs",
      "file:///tmp/example",
    ]
  ) {
    await assertRejects(
      () => run({ provider: "Example AI", sourceReference }),
      Error,
      "sourceReference",
    );
  }
});
