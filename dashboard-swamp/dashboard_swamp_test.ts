import {
  assertEquals,
  assertNotEquals,
  assertRejects,
} from "jsr:@std/assert@1";
import { normalize } from "./dashboard_swamp.ts";
import { model, setCommandRunnerForTest } from "./swamp_observability.ts";

type Json = Record<string, unknown>;

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
      runs: [{ status: "running", stale: true }],
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
      results: [{ reportName: "@example/report" }],
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

Deno.test("whitespace report status remains unavailable", async () => {
  const bundle = await normalize(reportContext(complete({
    "stored-reports": observation("stored-reports", {
      results: [{ reportName: "@example/report", status: "   " }],
    }),
  })));
  const section = bundle.sections[3];
  assertEquals(section.state, "partial");
  assertEquals(section.completeness.state, "partial");
  assertEquals(
    section.metrics.find((metric) => metric.id === "status-known")
      ?.availability,
    "unsupported",
  );
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
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [{ status: "succeeded" }, "malformed", { status: 7 }],
    }),
    "stored-reports": observation("stored-reports", {
      results: [{ status: "succeeded" }, 42, { status: 7 }],
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

Deno.test("remote server requires credential-free HTTPS", () => {
  for (
    const server of [
      "http://swamp.example.invalid",
      "file:///tmp/swamp",
      "https://user:token@swamp.example.invalid",
      "https://swamp.example.invalid?token=private",
      "https://swamp.example.invalid#private",
    ]
  ) {
    const parsed = model.globalArguments.safeParse({
      repoDir: "/tmp/synthetic-swamp-repo",
      server,
    });
    assertEquals(parsed.success, false, server);
  }
  assertEquals(
    model.globalArguments.safeParse({
      repoDir: "/tmp/synthetic-swamp-repo",
      server: "https://swamp.example.invalid",
    }).success,
    true,
  );
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

Deno.test("collector invokes documented commands without a shell or token argv", async () => {
  const calls: Array<{ args: string[]; env: Record<string, string> }> = [];
  setCommandRunnerForTest((_binary, args, options) => {
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
  });
  const written: Json[] = [];
  try {
    await model.methods.observe.execute({}, {
      globalArgs: {
        repoDir: "/tmp/synthetic-swamp-repo",
        swampBinary: "swamp",
        server: "https://swamp.example.invalid",
        token: "synthetic-secret",
        timeoutMs: 1000,
      },
      signal: new AbortController().signal,
      writeResource: (_spec: string, _name: string, data: Json) => {
        written.push(data);
        return Promise.resolve({});
      },
    });
  } finally {
    setCommandRunnerForTest();
  }
  assertEquals(calls.length, 4);
  assertEquals(
    calls.every((call) => !call.args.includes("synthetic-secret")),
    true,
  );
  assertEquals(
    calls.every((call) => call.env.SWAMP_SERVER_TOKEN === "synthetic-secret"),
    true,
  );
  assertEquals(written.length, 5);
  assertEquals(written[4].errorKind, "unsupported");
});

Deno.test("collector cancellation aborts instead of recording unavailability", async () => {
  const controller = new AbortController();
  setCommandRunnerForTest((_binary, _args, options) => {
    controller.abort(new Error("cancelled"));
    return Promise.reject(options.signal.reason);
  });
  try {
    await assertRejects(() =>
      model.methods.observe.execute({}, {
        globalArgs: {
          repoDir: "/tmp/synthetic-swamp-repo",
          swampBinary: "swamp",
        },
        signal: controller.signal,
        writeResource: () => Promise.resolve({}),
      })
    );
  } finally {
    setCommandRunnerForTest();
  }
});

Deno.test("compound statuses are never laundered into successes", async () => {
  // The old classifier used unanchored substring probes with the success test
  // ahead of the failure test, so "completed_with_errors" matched /completed/
  // and "unsuccessful" matched /success/ — both landed in counts.succeeded and
  // the section rendered healthy. Whole-token matching sends the first to
  // unknown and the second to failed; neither may ever count as a success.
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [
        { status: "completed_with_errors" },
        { status: "unsuccessful" },
        { status: "pending_failure" },
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

Deno.test("plain success and failure vocabularies still classify correctly", async () => {
  const bundle = await normalize(reportContext(complete({
    "run-history": observation("run-history", {
      runs: [
        { status: "succeeded" },
        { status: "Completed" },
        { status: "running" },
        { status: "cancelled" },
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

Deno.test("a wholly failed report inventory does not render as healthy", async () => {
  // hasStatus was a presence probe only: every stored-reports branch keyed off
  // "is a status string there", never its value, so an inventory in which every
  // report failed produced a section byte-identical to one in which every
  // report succeeded.
  const failed = await normalize(reportContext(complete({
    "stored-reports": observation("stored-reports", {
      results: [
        { reportName: "@jpisgeek/dashboard-swamp", status: "failed" },
        { reportName: "@jpisgeek/other", status: "failed" },
      ],
    }),
  })));
  const succeeded = await normalize(reportContext(complete({
    "stored-reports": observation("stored-reports", {
      results: [
        { reportName: "@jpisgeek/dashboard-swamp", status: "succeeded" },
        { reportName: "@jpisgeek/other", status: "succeeded" },
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
      results: [{ reportName: "@example/report", status: "completed_early" }],
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
      results: [{ reportName: "@example/report" }],
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
  assertEquals(broken.exceptions[0].id, "swamp:run-history:invalid-response");
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
