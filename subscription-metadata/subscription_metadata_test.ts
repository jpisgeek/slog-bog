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
