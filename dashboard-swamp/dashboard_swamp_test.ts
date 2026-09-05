import {
  assertEquals,
  assertNotEquals,
  assertRejects,
} from "jsr:@std/assert@1";
import { normalize, report } from "./dashboard_swamp.ts";
import { type CommandRunner, model } from "./swamp_observability.ts";

type Json = Record<string, unknown>;

Deno.test("handle overflow bounds repository work and reports omitted coverage", async () => {
  const ctx = reportContext(complete());
  const handle = ctx.dataHandles[0];
  ctx.dataHandles = Array.from({ length: 100 }, () => ({ ...handle }));
  const read = ctx.dataRepository.getContent;
  let reads = 0;
  ctx.dataRepository.getContent = (...args) => {
    reads++;
    return read(...args);
  };
  const result = await normalize(ctx);
  assertEquals(reads, 16);
  const coverage = result.sections.find((section) =>
    section.title === "Observation coverage"
  )!;
  assertEquals(coverage.state, "partial");
  assertEquals(coverage.impact, "required");
  assertEquals(coverage.completeness.observed, 16);
  assertEquals(coverage.completeness.expected, 100);
  assertEquals(coverage.summary.includes("84 handles were omitted"), true);
  assertEquals(result.state === "healthy", false);
});

Deno.test("separate observed repositories cannot share bundle or exception identities", async () => {
  const first = await normalize(reportContext(complete()));
  const other = reportContext(complete());
  other.modelId = "another-example-observer";
  const second = await normalize(other);
  assertNotEquals(first.id, second.id);
  const firstIds = new Set(first.sections.flatMap((section) => [
    section.id,
    ...section.exceptions.map((item) => item.id),
  ]));
  for (const section of second.sections) {
    assertEquals(firstIds.has(section.id), false);
    for (const item of section.exceptions) {
      assertEquals(firstIds.has(item.id), false);
    }
  }
  assertEquals(JSON.stringify(second).includes(other.modelId), false);
});

Deno.test("duplicate interface snapshots cannot overwrite a failed observation", async () => {
  const items = complete();
  items.push(items[0]);
  const result = await normalize(reportContext(items));
  const section = result.sections.find((item) =>
    item.title === "Model and workflow runs"
  )!;
  assertEquals(section.state === "healthy", false);
  assertEquals(section.exceptions.length > 0, true);
});

Deno.test("oversized stored snapshots are rejected before JSON decoding", async () => {
  const ctx = reportContext(complete());
  ctx.dataRepository.getContent = () =>
    Promise.resolve(new Uint8Array(4 * 1024 * 1024 + 1));
  const result = await normalize(ctx);
  assertEquals(result.sections.every((item) => item.state !== "healthy"), true);
});

// Freshness is now derived by comparing observedAt against the clock, so the
// default fixture has to represent what a normal run looks like: the collector
// and this report execute together, seconds apart. A frozen literal here would
// silently make every fixture stale as the calendar moved past it.
const observedAt = new Date().toISOString();

// One hour back, well past the 300s freshness budget.
const staleObservedAt = new Date(Date.now() - 3_600_000).toISOString();

function observation(
  name: string,
  payload: unknown,
  overrides: Json = {},
): Json {
  return {
    interface: name,
    available: true,
    observedAt,
    errorKind: "",
    error: "",
    payload,
    ...overrides,
  };
}

function reportContext(items: Json[], corrupt: Record<string, string> = {}) {
  const encoded = new Map(items.map((item) => [
    `interface-${item.interface}`,
    new TextEncoder().encode(JSON.stringify(item)),
  ]));
  // Overwrite a stored snapshot with bytes this report version cannot parse,
  // standing in for schema drift between the collector and an older report.
  for (const [name, body] of Object.entries(corrupt)) {
    encoded.set(`interface-${name}`, new TextEncoder().encode(body));
  }
  return {
    scope: "method" as const,
    modelType: { toString: () => "@jpisgeek/swamp-observability" },
    modelId: "synthetic-model-id",
    definition: { name: "synthetic-swamp", version: 1 },
    methodName: "observe",
    executionStatus: "succeeded" as const,
    dataHandles: items.map((item) => ({
      name: `interface-${item.interface}`,
      specName: "observation",
      version: 1,
    })),
    dataRepository: {
      getContent: (
        _type: string | { toString(): string },
        _id: string,
        name: string,
      ) => Promise.resolve(encoded.get(name) ?? null),
    },
  };
}

function complete(overrides: Record<string, Json> = {}): Json[] {
  const base: Record<string, Json> = {
    "run-history": observation("run-history", {
      runs: [{ status: "succeeded" }],
    }),
    "run-doctor": observation("run-doctor", {
      totalTracked: 1,
      active: 0,
      stale: 0,
      orphaned: 0,
    }),
    "workflow-history": observation("workflow-history", {
      results: [{ status: "succeeded" }],
    }),
    "stored-reports": observation("stored-reports", {
      results: [{ status: "succeeded" }],
    }),
    "serve-heartbeat": observation("serve-heartbeat", null, {
      available: false,
      errorKind: "unsupported",
      error: "This Swamp build exposes no public serve-heartbeat query",
    }),
  };
  return Object.values({ ...base, ...overrides });
}

Deno.test("successful public interfaces remain visible beside heartbeat gap", async () => {
  const bundle = await normalize(reportContext(complete()));
  assertEquals(bundle.state, "partial");
  assertEquals(bundle.sections[0].state, "healthy");
  assertEquals(bundle.sections[4].state, "partial");
  assertEquals(bundle.extensions["jpisgeek/swamp-observability"], {
    interfacesExpected: 5,
    interfacesObserved: 5,
    internalRunsApiUsed: false,
  });
});

Deno.test("the bundle names the producer without naming the deployment", async () => {
  // producer.modelName was `ctx.definition.name` and producer.modelId was the
  // instance UUID, so a stored report artifact — the thing that gets published
  // and handed to renderers — carried what the operator called their model and
  // which deployment it was. The bundle needs to say what produced it; it never
  // needed to say whose. Both identifiers are still used to READ the snapshots,
  // and neither may appear in the output.
  const context = {
    ...reportContext(complete()),
    modelId: "8b1d0e5a-private-instance-uuid",
    definition: { name: "example-swamp-model", version: 3 },
  };
  const bundle = await normalize(context);
  assertEquals(bundle.producer.modelName, "swamp-observability");
  assertEquals(bundle.producer.modelId, undefined);
  const serialized = JSON.stringify(bundle);
  for (const identifier of ["example-swamp-model", "private-instance-uuid"]) {
    assertEquals(serialized.includes(identifier), false, identifier);
  }
  // The snapshots were still read through those identifiers, so this is a
  // redaction of the output rather than a report that stopped working.
  assertEquals(bundle.sections.length, 5);
  assertEquals(bundle.sections[0].state, "healthy");
});

Deno.test("published report contains the canonical contract verbatim", async () => {
  const entry = await Deno.readTextFile(
    new URL("./dashboard_swamp.ts", import.meta.url),
  );
  const canonical = await Deno.readTextFile(
    new URL("../dashboard-contract/dashboard_bundle.ts", import.meta.url),
  );
  const inlined = entry.split("// BEGIN INLINED DASHBOARD CONTRACT V1\n")[1]
    .split("// END INLINED DASHBOARD CONTRACT V1")[0].trim();
  assertEquals(inlined, canonical.trim());
});

Deno.test("failed history degrades and is not counted as success", async () => {
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [{ status: "failed" }, { status: "succeeded" }],
    }),
  })));
  const section = bundle.sections[0];
  assertEquals(section.state, "degraded");
  assertEquals(section.metrics.find((m) => m.id === "failed")?.value, 1);
  assertEquals(section.exceptions[0].headline, "Failed executions observed");
});

Deno.test("stale and orphaned diagnostics are critical", async () => {
  const bundle = await normalize(reportContext(complete({
    "run-doctor": observation("run-doctor", {
      totalTracked: 3,
      active: 0,
      stale: 1,
      orphaned: 1,
    }),
  })));
  const section = bundle.sections[1];
  assertEquals(section.state, "critical");
  assertEquals(bundle.state, "critical");
});

Deno.test("run-history stale flag wins over a running status", async () => {
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [{ status: "active", stale: true }],
    }),
  })));
  assertEquals(bundle.sections[0].state, "critical");
  assertEquals(
    bundle.sections[0].metrics.find((m) => m.id === "stale")?.value,
    1,
  );
  assertEquals(
    bundle.sections[0].metrics.find((m) => m.id === "active")?.value,
    0,
  );
});

Deno.test("missing orphan and report status fields are not normalized to zero", async () => {
  const bundle = await normalize(reportContext(complete({
    "run-doctor": observation("run-doctor", {
      totalTracked: 1,
      active: 0,
      stale: 0,
    }),
    "stored-reports": observation("stored-reports", {
      results: [{ identified: true }],
    }),
  })));
  assertEquals(bundle.sections[1].state, "partial");
  assertEquals(
    bundle.sections[1].metrics.find((m) => m.id === "orphaned")?.availability,
    "unsupported",
  );
  assertEquals(bundle.sections[3].state, "partial");
  assertEquals(
    bundle.sections[3].metrics.find((m) => m.id === "status-known")
      ?.availability,
    "unsupported",
  );
});

Deno.test("a payload field outside the projected shape becomes a coverage gap", async () => {
  // Only the collector's projection may be persisted, so the report refuses a
  // snapshot carrying anything else — a report name here, a status that is not
  // a bounded token. Refusing it costs one interface, not the run: whatever
  // that field holds is never read, normalized, or handed to a renderer.
  for (
    const results of [
      [{ reportName: "@example/report" }],
      [{ identified: true, status: "   " }],
      [{ identified: true, status: "x".repeat(64) }],
    ]
  ) {
    const bundle = await normalize(reportContext(complete({
      "stored-reports": observation("stored-reports", { results }),
    })));
    const section = bundle.sections[3];
    assertEquals(section.state, "partial");
    assertEquals(section.coverage.kind, "unknown");
    assertEquals(
      section.exceptions[0].id.endsWith(
        ":swamp:stored-reports:invalid-response",
      ),
      true,
    );
    // The interfaces that were projected correctly still render.
    assertEquals(bundle.sections[0].state, "healthy");
  }
});

Deno.test("missing stale count is unsupported rather than zero", async () => {
  const bundle = await normalize(reportContext(complete({
    "run-doctor": observation("run-doctor", {
      totalTracked: 1,
      active: 0,
      orphaned: 0,
    }),
  })));
  const section = bundle.sections[1];
  assertEquals(section.state, "partial");
  assertEquals(
    section.metrics.find((metric) => metric.id === "stale")?.availability,
    "unsupported",
  );
  assertEquals(section.exceptions[0].headline, "Diagnostic count unavailable");
});

Deno.test("malformed history and report records make coverage partial", async () => {
  // `{}` is what the collector writes in place of a record it could not
  // project — a non-object entry, or a status that was not a bounded token.
  // The record is still counted so the population stays honest, and nothing it
  // contained survives into the snapshot.
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [{ status: "succeeded" }, {}, {}],
    }),
    "stored-reports": observation("stored-reports", {
      results: [{ status: "succeeded" }, {}, {}],
    }),
  })));
  for (const section of [bundle.sections[0], bundle.sections[3]]) {
    assertEquals(section.state, "partial");
    assertEquals(section.completeness.state, "partial");
    assertEquals(section.completeness.rejected, 2);
  }
});

Deno.test("every missing run diagnostic count remains unavailable", async () => {
  const bundle = await normalize(reportContext(complete({
    "run-doctor": observation("run-doctor", { stale: 0, orphaned: 0 }),
  })));
  const section = bundle.sections[1];
  assertEquals(section.state, "partial");
  for (const id of ["tracked", "active"]) {
    assertEquals(
      section.metrics.find((metric) => metric.id === id)?.availability,
      "unsupported",
    );
  }
});

Deno.test("the model exposes no remote destination for a credential to reach", () => {
  // There is no https/userinfo validation left to test because there is no URL
  // argument left to validate. A first-hop check could not survive a redirect
  // issued by the server it validated, and the redirect was followed inside the
  // Swamp executable, so the capability was removed instead.
  assertEquals(
    Object.keys(model.globalArguments.shape).sort(),
    ["repoDir", "swampBinary", "timeoutMs"],
  );
});

Deno.test("a negative diagnostic count can never render as healthy", async () => {
  // `typeof value === "number"` accepted -1, so `stale: -1, orphaned: 0` was a
  // complete response whose stale+orphaned sum was below zero: the section
  // rendered healthy with exact coverage off a result that described nothing
  // of the sort. A count outside nonnegative integers is now outside the
  // snapshot contract entirely, so it is a coverage gap, not a clean bill.
  const bundle = await normalize(reportContext(complete({
    "run-doctor": observation("run-doctor", {
      totalTracked: 3,
      active: 0,
      stale: -1,
      orphaned: 0,
    }),
  })));
  const section = bundle.sections[1];
  assertEquals(section.state, "partial");
  assertEquals(section.coverage.kind, "unknown");
  assertNotEquals(bundle.state, "healthy");
});

Deno.test("empty history is unknown rather than healthy or zero activity", async () => {
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", { runs: [] }),
  })));
  assertEquals(bundle.sections[0].state, "unknown");
  assertEquals(bundle.sections[0].summary, "History is available but empty");
});

Deno.test("unavailable and unauthorized interfaces remain distinct", async () => {
  const partial = await normalize(reportContext(complete({
    "stored-reports": observation("stored-reports", null, {
      available: false,
      errorKind: "unreachable",
      error: "Swamp interface could not be reached",
    }),
  })));
  assertEquals(partial.sections[3].state, "partial");

  const unauthorized = await normalize(reportContext(complete({
    "workflow-history": observation("workflow-history", null, {
      available: false,
      errorKind: "unauthorized",
      error: "Swamp rejected the configured serve credential",
    }),
  })));
  assertEquals(unauthorized.sections[2].state, "unauthorized");
  assertEquals(unauthorized.state, "critical");
});

Deno.test("collector invokes documented commands with no shell, URL, or credential", async () => {
  const calls: Array<{ args: string[]; env: Record<string, string> }> = [];
  const runner: CommandRunner = (_binary, args, options) => {
    calls.push({ args, env: options.env });
    const command = args.slice(0, 2).join(" ");
    const payload = command === "run doctor"
      ? { totalTracked: 0, active: 0, stale: 0, reaped: 0 }
      : command === "run history"
      ? { runs: [] }
      : { query: "", results: [] };
    return Promise.resolve({
      success: true,
      code: 0,
      stdout: JSON.stringify(payload),
      stderr: "",
    });
  };
  const written: Json[] = [];
  await model.methods.observe.execute({}, {
    commandRunner: runner,
    globalArgs: {
      repoDir: "/tmp/synthetic-swamp-repo",
      swampBinary: "swamp",
      timeoutMs: 1000,
    },
    signal: new AbortController().signal,
    writeResource: (_spec: string, _name: string, data: Json) => {
      written.push(data);
      return Promise.resolve({});
    },
  });
  assertEquals(calls.length, 4);
  assertEquals(
    calls.every((call) => call.args.every((arg) => !arg.includes("://"))),
    true,
  );
  assertEquals(
    calls.every((call) => Object.keys(call.env).length === 0),
    true,
  );
  assertEquals(written.length, 5);
  assertEquals(written[4].errorKind, "unsupported");
});

Deno.test("collector cancellation aborts instead of recording unavailability", async () => {
  const controller = new AbortController();
  const runner: CommandRunner = (_binary, _args, options) => {
    controller.abort(new Error("cancelled"));
    return Promise.reject(options.signal.reason);
  };
  await assertRejects(() =>
    model.methods.observe.execute({}, {
      commandRunner: runner,
      globalArgs: {
        repoDir: "/tmp/synthetic-swamp-repo",
        swampBinary: "swamp",
      },
      signal: controller.signal,
      writeResource: () => Promise.resolve({}),
    })
  );
});

Deno.test("an unrecognized bucket is counted as unknown, never as a success", async () => {
  // The vocabulary itself is exercised in the collector's tests, where the
  // response text still exists. What this report must guarantee is that the
  // `unknown` bucket — everything the collector could not recognize, with its
  // text discarded — is carried through as unknown and degrades the section,
  // rather than being folded into the healthy majority.
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [
        { status: "unknown" },
        { status: "failed" },
        { status: "unknown" },
      ],
    }),
  })));
  const section = bundle.sections[0];
  const value = (id: string) =>
    section.metrics.find((metric) => metric.id === id)?.value;
  assertEquals(value("succeeded"), 0);
  assertEquals(value("active"), 0);
  assertEquals(value("failed"), 1);
  assertEquals(value("unknown"), 2);
  assertEquals(section.state, "degraded");
});

Deno.test("each bucket lands in its own count", async () => {
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [
        { status: "succeeded" },
        { status: "succeeded" },
        { status: "active" },
        { status: "failed" },
      ],
    }),
  })));
  const section = bundle.sections[0];
  const value = (id: string) =>
    section.metrics.find((metric) => metric.id === id)?.value;
  assertEquals(value("succeeded"), 2);
  assertEquals(value("active"), 1);
  assertEquals(value("failed"), 1);
  assertEquals(value("unknown"), 0);
});

Deno.test("free-text status in a stored snapshot is refused, not displayed", async () => {
  // The read-side half of the redaction. A snapshot from a drifted or tampered
  // collector carrying a credential-shaped status must not be normalized into
  // a bundle a renderer will show; the interface becomes a coverage gap and
  // the text is never read.
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [{ status: "sk-live-9f2c1d4b8e" }],
    }),
  })));
  const section = bundle.sections[0];
  assertEquals(section.state, "partial");
  assertEquals(
    section.exceptions[0].id.endsWith(":swamp:run-history:invalid-response"),
    true,
  );
  assertEquals(JSON.stringify(bundle).includes("sk-live"), false);
});

Deno.test("a wholly failed report inventory does not render as healthy", async () => {
  // hasStatus was a presence probe only: every stored-reports branch keyed off
  // "is a status string there", never its value, so an inventory in which every
  // report failed produced a section byte-identical to one in which every
  // report succeeded.
  const failed = await normalize(reportContext(complete({
    "stored-reports": observation("stored-reports", {
      results: [
        { identified: true, status: "failed" },
        { identified: true, status: "failed" },
      ],
    }),
  })));
  const succeeded = await normalize(reportContext(complete({
    "stored-reports": observation("stored-reports", {
      results: [
        { identified: true, status: "succeeded" },
        { identified: true, status: "succeeded" },
      ],
    }),
  })));
  const section = failed.sections[3];
  assertEquals(section.state, "degraded");
  assertEquals(succeeded.sections[3].state, "healthy");
  assertEquals(
    section.metrics.find((metric) => metric.id === "failed")?.value,
    2,
  );
  assertEquals(
    section.metrics.find((metric) => metric.id === "succeeded")?.value,
    0,
  );
  assertEquals(
    section.exceptions.some((exception) =>
      exception.headline === "Unsuccessful stored report executions observed"
    ),
    true,
  );
  // The whole rendering must differ, not just one field a renderer may ignore.
  assertNotEquals(section.summary, succeeded.sections[3].summary);
  assertEquals(succeeded.sections[3].exceptions.length, 0);
});

Deno.test("an unrecognized report status degrades rather than passing", async () => {
  const bundle = await normalize(reportContext(complete({
    "stored-reports": observation("stored-reports", {
      results: [{ identified: true, status: "unknown" }],
    }),
  })));
  const section = bundle.sections[3];
  assertEquals(section.state, "degraded");
  assertEquals(
    section.metrics.find((metric) => metric.id === "succeeded")?.value,
    0,
  );
});

Deno.test("stored report status stays a capability probe, not a verdict", async () => {
  // Absent status must remain "this build does not expose it" — partial state
  // and unsupported metrics — never a health judgement in either direction.
  const bundle = await normalize(reportContext(complete({
    "stored-reports": observation("stored-reports", {
      results: [{ identified: true }],
    }),
  })));
  const section = bundle.sections[3];
  assertEquals(section.state, "partial");
  for (const id of ["status-known", "succeeded", "failed"]) {
    assertEquals(
      section.metrics.find((metric) => metric.id === id)?.availability,
      "unsupported",
      id,
    );
  }
});

Deno.test("an aged observation reports stale freshness instead of claiming fresh", async () => {
  // All three available-section call sites emitted the literal
  // { state: "fresh", observedAt, maxAgeSeconds: 300 } without ever reading
  // observedAt, so a re-run over a stored 30-day observation asserted the data
  // was under five minutes old while the timestamp was days back.
  const stale = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [{ status: "succeeded" }],
    }, { observedAt: staleObservedAt }),
    "run-doctor": observation("run-doctor", {
      totalTracked: 1,
      active: 0,
      stale: 0,
      orphaned: 0,
    }, { observedAt: staleObservedAt }),
    "stored-reports": observation("stored-reports", {
      results: [{ status: "succeeded" }],
    }, { observedAt: staleObservedAt }),
  })));
  for (const index of [0, 1, 3]) {
    const freshness = stale.sections[index].freshness;
    assertEquals(freshness.state, "stale", String(index));
    assertEquals(freshness.maxAgeSeconds, 300);
    assertEquals(typeof freshness.reason, "string");
  }

  const fresh = await normalize(reportContext(complete()));
  for (const index of [0, 1, 3]) {
    assertEquals(fresh.sections[index].freshness.state, "fresh", String(index));
  }
});

Deno.test("a snapshot cannot claim health it does not have, or print its own text", async () => {
  // Three shapes the flat, non-strict snapshot schema used to accept, all of
  // them from the same finding. The first claims `available: true` while
  // carrying a failure classification and a healthy payload — a failure wearing
  // the shape of health. The second is a legitimately unavailable snapshot
  // whose stored `error` string was copied verbatim into the summary, the
  // coverage note, the completeness reason, the exception detail and the report
  // Markdown, so whatever a drifted or tampered collector wrote there reached
  // every renderer downstream. The third carries an unexpected top-level field
  // the README already promised was rejected.
  const context = reportContext(complete({
    "run-history": observation("run-history", {
      runs: [{ status: "succeeded" }],
    }, {
      errorKind: "unauthorized",
      error: "token=synthetic-secret",
    }),
    "stored-reports": observation("stored-reports", null, {
      available: false,
      errorKind: "unreachable",
      error: "<img src=x onerror=alert(1)> nas.internal.lan",
    }),
    "workflow-history": observation("workflow-history", { results: [] }, {
      smuggled: "extra-top-level-field",
    }),
  }));
  const { markdown, json } = await report.execute(context);
  assertEquals(json.sections[0].state, "partial");
  assertEquals(
    json.sections[0].exceptions[0].id.endsWith(
      ":swamp:run-history:invalid-response",
    ),
    true,
  );
  assertEquals(json.sections[2].state, "partial");
  assertEquals(json.sections[3].state, "partial");
  assertNotEquals(json.state, "healthy");
  const rendered = `${markdown}\n${JSON.stringify(json)}`;
  for (
    const leaked of [
      "synthetic-secret",
      "onerror",
      "nas.internal.lan",
      "extra-top-level-field",
    ]
  ) {
    assertEquals(rendered.includes(leaked), false, leaked);
  }
  // Refusing three snapshots costs three interfaces, not the run.
  assertEquals(json.sections[1].state, "healthy");
});

Deno.test("an observation dated in the future is not evidence of freshness", async () => {
  // Freshness was a one-sided comparison, so a future timestamp — negative age
  // — passed it most comfortably of all, and a snapshot dated next year could
  // keep asserting "observed moments ago" forever.
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [{ status: "succeeded" }],
    }, { observedAt: new Date(Date.now() + 3_600_000).toISOString() }),
  })));
  const freshness = bundle.sections[0].freshness;
  assertEquals(freshness.state, "unknown");
  assertEquals(freshness.observedAt, undefined);
  assertEquals(typeof freshness.reason, "string");
  // The snapshot that is genuinely seconds old still reads as fresh.
  assertEquals(bundle.sections[1].freshness.state, "fresh");
});

Deno.test("run diagnostic counts that cannot all be true are refused", async () => {
  // Each count was validated alone and never against the others, so
  // totalTracked: 1 beside active: 5 was a healthy section with exact
  // coverage — a diagnosis of a repository that cannot exist.
  const bundle = await normalize(reportContext(complete({
    "run-doctor": observation("run-doctor", {
      totalTracked: 1,
      active: 5,
      stale: 0,
      orphaned: 0,
    }),
  })));
  const section = bundle.sections[1];
  assertEquals(section.state, "partial");
  assertEquals(section.coverage.kind, "unknown");
  assertEquals(
    section.exceptions[0].id.endsWith(":swamp:run-doctor:invalid-response"),
    true,
  );
  assertNotEquals(bundle.state, "healthy");
  // A snapshot whose counts are consistent is untouched.
  assertEquals(bundle.sections[0].state, "healthy");
});

Deno.test("an unexpected model type is refused without being repeated", async () => {
  // A model type names an extension the operator installed, often a private
  // one, and a misconfiguration is precisely how this branch is reached — so
  // reflecting it wrote that name into whatever log or stored failure caught
  // the throw.
  const error = await assertRejects(
    () =>
      normalize({
        ...reportContext(complete()),
        modelType: "@private-org/undisclosed-collector",
      }),
    Error,
  );
  for (const identifier of ["private-org", "undisclosed-collector"]) {
    assertEquals(error.message.includes(identifier), false, identifier);
  }
});

Deno.test("an unreadable snapshot degrades one interface, not the whole report", async () => {
  // readObservations parsed each stored resource unguarded and normalize() did
  // not catch, so a single snapshot this report version could not parse threw
  // out of report.execute and the operator got no dashboard at all.
  const bundle = await normalize(
    reportContext(complete(), { "run-history": "{not valid json" }),
  );
  assertEquals(bundle.sections.length, 5);
  const broken = bundle.sections[0];
  assertEquals(broken.state, "partial");
  assertEquals(broken.coverage.kind, "unknown");
  assertEquals(broken.freshness.state, "unknown");
  assertEquals(
    broken.exceptions[0].id.endsWith(":swamp:run-history:invalid-response"),
    true,
  );
  // The interfaces that parsed cleanly still carry their evidence.
  assertEquals(bundle.sections[1].state, "healthy");
  assertEquals(bundle.sections[3].state, "healthy");
});

Deno.test("a snapshot rejected by the inlined schema becomes a coverage gap", async () => {
  // Valid JSON, but an errorKind this report version's inlined
  // ObservationSchema does not know — the collector-drift case.
  const bundle = await normalize(
    reportContext(complete(), {
      "workflow-history": JSON.stringify({
        interface: "workflow-history",
        available: true,
        observedAt,
        errorKind: "quota-exhausted",
        error: "",
        payload: { results: [] },
      }),
    }),
  );
  assertEquals(bundle.sections.length, 5);
  assertEquals(bundle.sections[2].state, "partial");
  assertEquals(bundle.sections[0].state, "healthy");
});

Deno.test("a datastore read failure for one interface does not abort the run", async () => {
  const items = complete();
  const base = reportContext(items);
  const context = {
    ...base,
    dataRepository: {
      getContent: (
        type: string | { toString(): string },
        id: string,
        name: string,
      ) =>
        name === "interface-stored-reports"
          ? Promise.reject(new Error("datastore unavailable"))
          : base.dataRepository.getContent(type, id, name),
    },
  };
  const bundle = await normalize(context);
  assertEquals(bundle.sections.length, 5);
  assertEquals(bundle.sections[3].state, "partial");
  assertEquals(bundle.sections[0].state, "healthy");
});
