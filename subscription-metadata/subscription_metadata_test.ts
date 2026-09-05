import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { z } from "npm:zod@4";
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
// The digit bound alone let nineteen significant digits through, which is more
// than a double holds: "999999999999999.9999" persisted for 365 days and the
// report published it as the exact price 1000000000000000. Every accepted value
// must come back out of Number() as the number that went in.
Deno.test("accepted prices round-trip through Number() exactly", async () => {
  for (
    const priceMinor of [
      "0",
      "2500",
      "999999999999999",
      "0.0001",
      "2500.0001",
      "12345678901.1234",
    ]
  ) {
    const snapshot = await run({
      provider: "Example AI",
      priceMinor,
      currency: "USD",
    });
    const converted = Number(snapshot.priceMinor as string);
    assertEquals(
      String(converted),
      priceMinor.replace(/^0+(?=\d)/, "").replace(/(\.\d*?)0+$/, "$1").replace(
        /\.$/,
        "",
      ),
      `${priceMinor} did not survive Number()`,
    );
  }
  for (
    const priceMinor of [
      "999999999999999.9999",
      "123456789012345.6789",
      "999999999999999.0001",
    ]
  ) {
    await assertRejects(
      () => run({ provider: "Example AI", priceMinor, currency: "USD" }),
      Error,
      "priceMinor",
      `expected ${priceMinor} to be rejected as lossy`,
    );
  }
});

// The report's copy of these schemas is strict all the way down. This one used
// to strip unknown nested keys instead, so capture wrote snapshots that the
// report then refused to read — the write path stopped being the thing the read
// path re-checks.
Deno.test("unknown keys nested in a limit or in provenance are rejected", async () => {
  await assertRejects(
    () =>
      run({
        provider: "Example AI",
        declaredLimits: [{
          name: "Included requests",
          value: 1000,
          unit: "requests",
          remaining: 12,
        }],
      }),
    Error,
    "Unrecognized key",
  );
  const parsed = model.resources.snapshot.schema.safeParse({
    provider: "Example AI",
    declaredLimits: [],
    provenance: {
      kind: "operator-config",
      capturedAt: "2026-08-25T20:00:00Z",
      capturedBy: "scraper",
    },
  });
  assertEquals(parsed.success, false);
});

// Two limits that name the same thing collapse onto one dashboard metric id, so
// one of them disappears behind the other in any renderer keyed by id.
Deno.test("declared limits with the same identity are rejected", async () => {
  const limit = { name: "Included requests", value: 1000, unit: "requests" };
  await assertRejects(
    () =>
      run({
        provider: "Example AI",
        declaredLimits: [limit, { ...limit, value: 2000 }],
      }),
    Error,
    "duplicate identity",
  );
  await assertRejects(
    () =>
      run({
        provider: "Example AI",
        declaredLimits: [
          { ...limit, period: "month" },
          {
            ...limit,
            period: "month",
            sourceReference: "https://openai.com/pricing",
          },
        ],
      }),
    Error,
    "duplicate identity",
  );
  // Same name and unit over a different period is a second, real limit.
  const snapshot = await run({
    provider: "Example AI",
    declaredLimits: [
      { ...limit, period: "month" },
      { ...limit, period: "day" },
    ],
  });
  assertEquals((snapshot.declaredLimits as Json[]).length, 2);
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
      // The URL itself is the credential: the capability is the path on an
      // otherwise legitimate vendor origin, or the unguessable subdomain.
      // Neither carries userinfo, a query, or a fragment, so both used to
      // validate and persist for 365 days.
      "https://www.anthropic.com/invite/AbCd3fGh1JkLmN0pQrS",
      "https://a1b2c3d4.trycloudflare.com/",
    ]
  ) {
    await assertRejects(
      () => run({ provider: "Example AI", sourceReference }),
      Error,
      "sourceReference",
    );
  }
});

// A reference this package will store is still commercial provenance, so the
// argument carries the marker this repo uses for a secret; without it a
// rendered model config prints the operator's reference in the clear. Both
// arguments are checked: the nested one is as persistable as the top-level one.
Deno.test("both source-reference arguments are marked sensitive", () => {
  const schema = z.toJSONSchema(model.globalArguments, {
    io: "input",
  }) as unknown as {
    properties: {
      sourceReference: Json;
      declaredLimits: { items: { properties: { sourceReference: Json } } };
    };
  };
  assertEquals(schema.properties.sourceReference.sensitive, true);
  assertEquals(
    schema.properties.declaredLimits.items.properties.sourceReference.sensitive,
    true,
  );
});

// Tags are resource metadata: listed, filtered, and logged apart from the
// resource body, so nothing this package classifies sensitive may go in one.
Deno.test("resource tags carry no commercially sensitive value", async () => {
  let tags: Record<string, string> | undefined;
  await model.methods.capture.execute({}, {
    globalArgs: { provider: "Example AI" },
    writeResource: (_s: string, _n: string, _d: Json, options?: {
      tags?: Record<string, string>;
    }) => {
      tags = options?.tags;
      return Promise.resolve({});
    },
  });
  assertEquals(tags, { provenance: "operator-config" });
});
