import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { model } from "./dashboard.ts";

type Json = Record<string, unknown>;

function exception(extra: Json = {}) {
  return {
    id: "condition:one",
    severity: "warning",
    subject: "Synthetic service",
    headline: "Needs attention",
    detail: "A synthetic condition exists",
    source: "synthetic:probe",
    suppressed: false,
    suppressReason: "",
    sensitivity: "operational",
    ...extra,
  };
}

function bundle(options: {
  id?: string;
  title?: string;
  section?: string;
  state?: string;
  exceptions?: Json[];
  summary?: string;
  metrics?: Json[];
  facts?: Json[];
} = {}) {
  const state = options.state ??
    (options.exceptions?.length ? "degraded" : "healthy");
  return {
    schemaVersion: "1.0.0",
    id: options.id ?? "synthetic-bundle",
    title: options.title ?? "Synthetic bundle",
    generatedAt: new Date().toISOString(),
    producer: {
      extension: "@example/synthetic-adapter",
      extensionVersion: "2026.08.25.1",
      modelType: "@example/synthetic",
      modelName: "synthetic",
      dataName: "report-example-synthetic-json",
    },
    state,
    sections: [{
      id: (options.section ?? "Services").toLowerCase(),
      title: options.section ?? "Services",
      state,
      impact: "required",
      summary: options.summary ?? "Synthetic observations are current",
      coverage: { kind: "exact", scope: "synthetic fixture" },
      freshness: { state: "fresh", observedAt: new Date().toISOString() },
      completeness: state === "partial"
        ? { state: "partial", rejected: 1, reason: "one invalid record" }
        : { state: "exact", rejected: 0 },
      metrics: options.metrics ?? [],
      facts: options.facts ?? [],
      exceptions: options.exceptions ?? [],
      references: [],
      sensitivity: {
        classification: "operational",
        fields: [],
        redacted: false,
      },
    }],
    exceptions: [],
    sensitivity: { classification: "operational", fields: [], redacted: false },
    extensions: {},
  };
}

async function render(
  bundles: unknown[],
  options: { suppress?: Json[]; prior?: Json | null } = {},
) {
  const dir = await Deno.makeTempDir();
  const outputPath = `${dir}/index.html`;
  const written: Array<{ spec: string; name: string; data: Json }> = [];
  const deleted: string[] = [];
  const ctx = {
    globalArgs: {
      title: "Test dashboard",
      bundles,
      outputPath,
      suppress: options.suppress ?? [],
    },
    logger: { info: () => {}, warning: () => {} },
    readResource: () => Promise.resolve(options.prior ?? null),
    writeResource: (spec: string, name: string, data: Json) => {
      written.push({ spec, name, data });
      return Promise.resolve({ spec, name });
    },
    deleteResource: (name: string) => {
      deleted.push(name);
      return Promise.resolve();
    },
  };
  try {
    await model.methods.render.execute({}, ctx);
    return {
      html: await Deno.readTextFile(outputPath),
      written,
      deleted,
      result: written.find((row) => row.spec === "render")!.data,
    };
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

Deno.test("renderer declares bundles and no provider-specific source arguments", () => {
  const parsed = model.globalArguments.parse({});
  assertEquals(parsed.bundles, []);
  assertEquals("sources" in parsed, false);
  assertEquals(Object.keys(model.methods), ["render"]);
});

Deno.test("renderer source contains no provider names or hidden repository reads", async () => {
  const source = await Deno.readTextFile(
    new URL("./dashboard.ts", import.meta.url),
  );
  for (
    const forbidden of [
      "Netdata",
      "TrueNAS",
      "Firewalla",
      "@swamp/ssh",
      "findAllForModel",
      "dataRepository",
      "telemetry",
      "certWarnDays",
      "diskWarnPercent",
    ]
  ) {
    assertEquals(source.includes(forbidden), false, forbidden);
  }
});

Deno.test("published entry point contains the canonical contract verbatim", async () => {
  const entry = await Deno.readTextFile(
    new URL("./dashboard.ts", import.meta.url),
  );
  const canonical = await Deno.readTextFile(
    new URL("../dashboard-contract/dashboard_bundle.ts", import.meta.url),
  );
  const inlined = entry.split("// BEGIN INLINED DASHBOARD CONTRACT V1\n")[1]
    .split("// END INLINED DASHBOARD CONTRACT V1")[0].trim();
  const canonicalBody = canonical.slice(
    canonical.indexOf("/** Current bundle schema version"),
  ).trim();
  assertEquals(inlined, canonicalBody);
});

Deno.test("missing bundles are visible and cannot render all-clear", async () => {
  const rendered = await render([]);
  assertStringIncludes(rendered.html, "No dashboard bundles were provided");
  assertEquals(rendered.html.includes("Nothing needs you"), false);
  assertEquals(rendered.result.bundlesReceived, 0);
  assertEquals(rendered.result.bundlesValid, 0);
});

Deno.test("unsupported major versions render a visible coverage exception", async () => {
  const input: Json = bundle();
  input.schemaVersion = "2.0.0";
  const rendered = await render([input]);
  assertStringIncludes(rendered.html, "Unsupported dashboard bundle version");
  assertEquals(rendered.result.bundlesValid, 0);
  assertEquals(rendered.result.warning, 1);
});

Deno.test("invalid bundles fail visibly without aborting the render", async () => {
  const input: Json = bundle();
  input.sections = [{ networks: "not-an-array" }];
  const rendered = await render([input]);
  assertStringIncludes(rendered.html, "Invalid dashboard bundle");
  assertEquals(rendered.result.critical, 1);
});

Deno.test("partial coverage appears before any reassuring summary", async () => {
  const rendered = await render([bundle({ state: "partial" })]);
  assertStringIncludes(rendered.html, "Coverage is partial");
  assertEquals(rendered.html.includes("Nothing needs you"), false);
  assertEquals(rendered.result.coverageStates, {
    "synthetic-bundle": "partial",
  });
  assertEquals(rendered.result.exceptions, 1);
});

Deno.test("non-healthy state without an exception never renders zero things", async () => {
  const rendered = await render([bundle({ state: "critical" })]);
  assertStringIncludes(rendered.html, "Operational state is critical");
  assertEquals(rendered.result.critical, 1);
});

Deno.test("unknown stale unsupported and unauthorized states are visible", async () => {
  for (const state of ["unknown", "stale", "unsupported", "unauthorized"]) {
    const input = bundle({ state });
    if (state === "stale") {
      (input.sections[0] as Json).freshness = {
        state: "stale",
        observedAt: "2026-08-01T00:00:00Z",
        reason: "observation expired",
      };
    }
    const rendered = await render([input]);
    assertStringIncludes(rendered.html, `Coverage is ${state}`);
    assertEquals(rendered.html.includes("Nothing needs you"), false);
  }
});

Deno.test("all bundle strings are escaped in exceptions metrics and facts", async () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const input = bundle({
    title: hostile,
    summary: hostile,
    exceptions: [exception({ headline: hostile, detail: hostile })],
    metrics: [{
      id: "requests",
      label: hostile,
      unit: "requests",
      confidence: "exact",
      availability: "observed",
      value: 4,
      sensitivity: "operational",
    }],
    facts: [{
      id: "runtime",
      label: hostile,
      value: hostile,
      confidence: "exact",
      sensitivity: "operational",
    }],
  });
  input.sections[0].title = hostile;
  const rendered = await render([input]);
  assertEquals(rendered.html.includes("<img"), false);
  assertStringIncludes(rendered.html, "&lt;img");
});

Deno.test("suppression remains visible and queryable", async () => {
  const rendered = await render([bundle({ exceptions: [exception()] })], {
    suppress: [{
      id: "16:synthetic-bundle13:condition:one",
      reason: "maintenance window",
    }],
  });
  assertStringIncludes(rendered.html, "Expected");
  assertStringIncludes(rendered.html, "maintenance window");
  assertEquals(rendered.result.exceptions, 0);
  assertEquals(rendered.result.suppressed, 1);
  const row = rendered.written.find((item) => item.spec === "exception")!.data;
  assertEquals(row.suppressed, true);
  assertEquals(row.id, "16:synthetic-bundle13:condition:one");
  assertEquals(row.sensitivity, "operational");
});

Deno.test("same producer exception id remains distinct across bundles", async () => {
  const rendered = await render([
    bundle({ id: "bundle-a", exceptions: [exception()] }),
    bundle({ id: "bundle-b", exceptions: [exception()] }),
  ]);
  const ids = rendered.written.filter((item) => item.spec === "exception").map(
    (item) => item.data.id,
  );
  assertEquals(ids, [
    "8:bundle-a13:condition:one",
    "8:bundle-b13:condition:one",
  ]);
});

Deno.test("exception tuple encoding cannot collide on colon placement", async () => {
  const rendered = await render([
    bundle({ id: "a:b", exceptions: [exception({ id: "c" })] }),
    bundle({ id: "a", exceptions: [exception({ id: "b:c" })] }),
  ]);
  const ids = rendered.written.filter((item) => item.spec === "exception").map(
    (item) => item.data.id,
  );
  assertEquals(ids, ["1:a3:b:c", "3:a:b1:c"]);
});

Deno.test("synthetic coverage tuple encoding cannot collide", async () => {
  const first = bundle({ id: "a:b", state: "unknown" });
  const second = bundle({ id: "a" });
  second.sections.push(
    {
      ...second.sections[0],
      id: "b",
      title: "Optional coverage",
      state: "unknown",
      impact: "optional",
      freshness: { state: "unknown", reason: "not observed" },
      completeness: { state: "unknown", reason: "not observed" },
    } as unknown as typeof second.sections[number],
  );
  const rendered = await render([first, second]);
  const ids = rendered.written.filter((item) => item.spec === "exception").map(
    (item) => item.data.id,
  );
  assertEquals(new Set(ids).size, ids.length);
  assertEquals(ids.length, 2);
});

Deno.test("duplicate bundle IDs fail visibly", async () => {
  const rendered = await render([
    bundle({ id: "same" }),
    bundle({ id: "same" }),
  ]);
  assertStringIncludes(rendered.html, "Duplicate dashboard bundle ID");
  assertEquals(rendered.result.bundlesValid, 1);
  assertEquals(rendered.result.critical, 1);
});

Deno.test("synthetic families and repeated duplicate IDs remain distinct", async () => {
  const rendered = await render([
    bundle({ id: "unknown" }),
    bundle({ id: "unknown" }),
    bundle({ id: "unknown" }),
    bundle({ id: "duplicate-bundle", state: "unknown" }),
  ]);
  const rows = rendered.written.filter((item) => item.spec === "exception");
  const ids = rows.map((item) => String(item.data.id));
  assertEquals(new Set(ids).size, ids.length);
  assertEquals(
    rows.filter((item) =>
      item.data.headline === "Duplicate dashboard bundle ID"
    )
      .length,
    2,
  );
  assertEquals(
    rows.filter((item) => item.data.headline === "Coverage is unknown").length,
    1,
  );
});

Deno.test("stale partial evidence cannot render all-clear", async () => {
  const input = bundle();
  (input.sections[0] as Json).freshness = {
    state: "stale",
    observedAt: "2026-08-01T00:00:00Z",
    reason: "expired",
  };
  (input.sections[0] as Json).completeness = {
    state: "partial",
    rejected: 1,
    reason: "missing record",
  };
  const rendered = await render([input]);
  assertEquals(rendered.html.includes("Nothing needs you"), false);
  assertStringIncludes(rendered.html, "Invalid dashboard bundle");
});

Deno.test("resolved exception resources are pruned through the model API", async () => {
  const rendered = await render([bundle()], {
    prior: { exceptionResources: ["exception-old-deadbeef"] },
  });
  assertEquals(rendered.deleted, ["exception-old-deadbeef"]);
});

Deno.test("accepted exceptions-first visual direction remains", async () => {
  const sections = ["Nodes", "Storage", "Certificates", "Machines"];
  const rendered = await render(
    sections.map((section, index) =>
      bundle({ id: `bundle-${index}`, section })
    ),
  );
  assertStringIncludes(rendered.html, "<!doctype html>");
  assertStringIncludes(rendered.html, "Nothing needs you");
  for (const section of sections) assertStringIncludes(rendered.html, section);
  assertStringIncludes(rendered.html, "prefers-color-scheme:dark");
  assertEquals(rendered.html.includes("http://"), false);
  assertEquals(rendered.html.includes("https://"), false);
});

Deno.test("exception records disclose truncation", async () => {
  const rendered = await render([bundle({
    exceptions: [exception({ headline: "x".repeat(200) })],
  })]);
  const row = rendered.written.find((item) => item.spec === "exception")!.data;
  assertEquals(row.truncated, true);
  assertEquals(String(row.headline).length, 160);
});
