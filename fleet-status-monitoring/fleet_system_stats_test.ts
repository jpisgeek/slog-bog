import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261105.71";
import { fixtureRecord } from "./test_fixtures.ts";
import {
  createSystemStatsModel,
  localResult,
  model,
} from "./fleet_system_stats.ts";
import { Target } from "./schema.ts";
const assert = (ok: unknown) => {
  if (!ok) throw Error("Assertion failed");
};
Deno.test("inventory rejects two local identities for the same serve host", () => {
  const local = {
    id: "example-local",
    label: "Example system",
    group: "macos",
    kind: "physical",
    collector: "local",
  };
  const args = { cycleBehavior: "fleet-health", targets: [local] };
  assert(model.globalArguments.safeParse(args).success);
  assert(
    !model.globalArguments.safeParse({
      ...args,
      targets: [local, { ...local, id: "example-other" }],
    }).success,
  );
  assert(
    model.globalArguments.safeParse({
      ...args,
      targets: [local, { ...local, id: "example-remote", collector: "ssh" }],
    }).success,
  );
});
const sample = (now: number) => ({
  schemaVersion: 1,
  observedAt: new Date(now - 600).toISOString(),
  family: "macos",
  osName: "macOS",
  osVersion: "example-version",
  kernel: "example-kernel",
  architecture: "arm64",
  logicalCores: 8,
  uptimeSeconds: 300,
  memoryTotalBytes: 16 * 1024 ** 3,
  memoryAvailableBytes: 8 * 1024 ** 3,
  memoryAvailableKind: "estimate",
  diskTotalBytes: 500 * 1024 ** 3,
  diskAvailableBytes: 100 * 1024 ** 3,
  load1: 2,
});
async function collect(local: unknown, offset = 0) {
  const now = Date.now(), calls: string[] = [];
  const t = createModelTestContext({
    definition: { name: "fleet-counters" },
    globalArgs: model.globalArguments.parse({
      targets: [Target.parse({
        id: "mac-mini",
        label: "Mac Mini",
        group: "macos",
        kind: "physical",
        collector: "local",
      })],
      cycleBehavior: "fleet-health",
      localProbeBehavior: "fleet-local-probe",
    }),
  });
  t.context.readModelData = (name) => {
    calls.push(name);
    if (name === "fleet-health") {
      return Promise.resolve([fixtureRecord({
        cycleId: "00000000-0000-4000-8000-000000000001",
        startedAt: new Date(now - 10000).toISOString(),
      }, "cycle")]);
    }
    if (name === "fleet-local-probe") {
      return Promise.resolve(
        local === null ? [] : [fixtureRecord(
          typeof local === "function"
            ? local(now + offset)
            : local as Record<string, unknown>,
          "localProbe",
          "00000000-0000-4000-8000-000000000002",
          7,
        )],
      );
    }
    throw Error("Unexpected source read");
  };
  await model.methods.collect.execute({}, t.context);
  const write = t.getWrittenResources()[0];
  assert(write.specName === "observations" && write.name === "observations");
  return {
    calls,
    value: model.resources.observations.schema.parse(write.data),
  };
}

Deno.test("local collection consumes typed native evidence without requiring SSH or executing a command", async () => {
  const r = await collect((now: number) => ({
    startedAt: new Date(now - 1000).toISOString(),
    finishedAt: new Date(now - 500).toISOString(),
    state: "observed",
    failureKind: null,
    sample: sample(now),
  }));
  assert(!r.calls.includes("fleet-transport"));
  assert(
    r.value.systems[0].state === "observed" &&
      r.value.systems[0].sourceVersion === 7 &&
      r.value.systems[0].sourceWorkflowRunId ===
        "00000000-0000-4000-8000-000000000002",
  );
});
Deno.test("missing command output produces a coverage gap", async () => {
  const r = await collect(null);
  assert(
    r.value.systems[0].state === "unavailable" &&
      r.value.systems[0].sample === null,
  );
});
Deno.test("failed local probe is unavailable, rather than falsely marking the responding server offline", async () => {
  const r = await collect((now: number) => ({
    startedAt: new Date(now - 1000).toISOString(),
    finishedAt: new Date(now - 500).toISOString(),
    state: "unavailable",
    failureKind: "observation-failed",
    sample: null,
  }));
  assert(
    r.value.systems[0].state === "unavailable" &&
      r.value.systems[0].sample === null,
  );
});
Deno.test("retained local success from a prior cycle is rejected", async () => {
  const r = await collect((now: number) => ({
    startedAt: new Date(now - 60500).toISOString(),
    finishedAt: new Date(now - 60000).toISOString(),
    state: "observed",
    failureKind: null,
    sample: sample(now - 60000),
  }));
  assert(r.value.systems[0].state === "unavailable");
});
Deno.test("malformed command timing does not become a fabricated fresh observation", () => {
  const target = Target.parse({
    id: "local",
    label: "Local",
    group: "linux",
    kind: "physical",
    collector: "local",
  });
  assert(
    localResult(target, {
      attributes: { startedAt: "bad" },
    })?.attributes === undefined,
  );
});

Deno.test("probe executes with an injected observer and records typed evidence and lifecycle logs", async () => {
  const t = createModelTestContext();
  const m = createSystemStatsModel(() => Promise.resolve(sample(Date.now())));
  const result = await m.methods.probe.execute({}, t.context);
  const [write] = t.getWrittenResources();
  assert(write.specName === "localProbe" && write.name === "localProbe");
  const value = m.resources.localProbe.schema.parse(write.data);
  assert(
    value.state === "observed" && value.sample?.schemaVersion === 1 &&
      value.failureKind === null,
  );
  assert(
    result.dataHandles[0] === write.handle &&
      t.getLogsByLevel("info").length === 2,
  );
});
Deno.test("probe classifies OS and invalid-payload failures without logging or retaining exception text", async () => {
  for (
    const [observer, expected] of [
      [
        () => Promise.reject(new Error("PRIVATE_SENTINEL")),
        "observation-failed",
      ],
      [
        () => Promise.resolve({ invalid: "PRIVATE_SENTINEL" }),
        "contract-validation",
      ],
    ] as const
  ) {
    const t = createModelTestContext();
    await createSystemStatsModel(observer).methods.probe.execute({}, t.context);
    const value = model.resources.localProbe.schema.parse(
      t.getWrittenResources()[0].data,
    );
    assert(
      value.state === "unavailable" && value.sample === null &&
        value.failureKind === expected,
    );
    assert(t.getLogsByLevel("warning").length === 1);
    assert(!JSON.stringify([t.getLogs(), value]).includes("PRIVATE_SENTINEL"));
  }
});
Deno.test("collect reports a missing marker with the behavior name and recovery action", async () => {
  const t = createModelTestContext({
    globalArgs: {
      targets: [{
        id: "example",
        label: "Example",
        group: "macos",
        kind: "physical",
        collector: "local",
      }],
      cycleBehavior: "fleet-health",
    },
  });
  try {
    await model.methods.collect.execute({}, t.context);
    throw Error("Expected prerequisite failure");
  } catch (error) {
    assert(
      error instanceof Error && error.message.includes("fleet-health") &&
        error.message.includes("run begin"),
    );
  }
  assert(t.getWrittenResources().length === 0);
});
Deno.test("collect reads its own localProbe through readResource and preserves matching run/version metadata", async () => {
  const now = Date.now();
  const local = {
    startedAt: new Date(now - 1000).toISOString(),
    finishedAt: new Date(now - 500).toISOString(),
    state: "observed",
    failureKind: null,
    sample: sample(now),
  };
  const marker = {
    cycleId: "00000000-0000-4000-8000-000000000001",
    startedAt: new Date(now - 2000).toISOString(),
  };
  const t = createModelTestContext({
    definition: { name: "fleet-counters" },
    storedResources: { localProbe: local },
    globalArgs: {
      targets: [{
        id: "example",
        label: "Example",
        group: "macos",
        kind: "physical",
        collector: "local",
      }],
      cycleBehavior: "fleet-health",
    },
  });
  const reads: string[] = [], original = t.context.readResource;
  t.context.readResource = (name) => {
    reads.push(name);
    return original(name);
  };
  t.context.readModelData = (name) =>
    Promise.resolve(
      name === "fleet-health"
        ? [fixtureRecord(marker, "cycle")]
        : [fixtureRecord(local, "localProbe", undefined, 8)],
    );
  await model.methods.collect.execute({}, t.context);
  const output = model.resources.observations.schema.parse(
    t.getWrittenResources()[0].data,
  );
  assert(
    reads.join() === "localProbe" && output.systems[0].state === "observed" &&
      output.systems[0].sourceVersion === 8,
  );
});
Deno.test("collector rejects misspelled global keys", () => {
  assert(
    !model.globalArguments.safeParse({
      targets: [],
      cycleBehavior: "fleet-health",
      transportBehavor: "typo",
    }).success,
  );
});

Deno.test("collect ranks cross-behavior cycle and native probe records by validated times in either array order", async () => {
  const now = Date.now(), cycleId = "00000000-0000-4000-8000-000000000001";
  const freshMarker = fixtureRecord(
    { cycleId, startedAt: new Date(now - 2000).toISOString() },
    "cycle",
    undefined,
    1,
  );
  const oldMarker = fixtureRecord(
    {
      cycleId: "00000000-0000-4000-8000-000000000009",
      startedAt: new Date(now - 20000).toISOString(),
    },
    "cycle",
    undefined,
    99,
  );
  const freshProbe = fixtureRecord(
    {
      startedAt: new Date(now - 1000).toISOString(),
      finishedAt: new Date(now - 500).toISOString(),
      state: "observed",
      failureKind: null,
      sample: sample(now),
    },
    "localProbe",
    undefined,
    2,
  );
  const oldProbe = fixtureRecord(
    {
      ...freshProbe.attributes,
      startedAt: new Date(now - 15000).toISOString(),
    },
    "localProbe",
    undefined,
    99,
  );
  for (const reverse of [false, true]) {
    const t = createModelTestContext({
      globalArgs: {
        cycleBehavior: "fleet-health",
        localProbeBehavior: "fleet-probe",
        targets: [{
          id: "example",
          label: "Example",
          group: "macos",
          kind: "physical",
          collector: "local",
        }],
      },
    });
    t.context.readModelData = (name) => {
      const rows = name === "fleet-health"
        ? [oldMarker, freshMarker]
        : [oldProbe, freshProbe];
      return Promise.resolve(reverse ? rows.reverse() : rows);
    };
    await model.methods.collect.execute({}, t.context);
    const output = model.resources.observations.schema.parse(
      t.getWrittenResources()[0].data,
    );
    assert(
      output.cycleId === cycleId && output.systems[0].sourceVersion === 2 &&
        output.systems[0].state === "observed",
    );
    assert(t.getLogsByLevel("info").length === 2);
  }
});
Deno.test("collect logs sanitized per-target coverage reasons and lifecycle counts", async () => {
  const now = Date.now();
  const t = createModelTestContext({
    globalArgs: {
      cycleBehavior: "fleet-health",
      targets: [{
        id: "example",
        label: "Example",
        group: "macos",
        kind: "physical",
        collector: "local",
      }],
    },
  });
  t.context.readModelData = () =>
    Promise.resolve([
      fixtureRecord({
        cycleId: "00000000-0000-4000-8000-000000000001",
        startedAt: new Date(now - 1000).toISOString(),
      }, "cycle"),
    ]);
  await model.methods.collect.execute({}, t.context);
  assert(
    t.getLogsByLevel("debug").length === 1 &&
      t.getLogsByLevel("info").length === 2,
  );
  const output = model.resources.observations.schema.parse(
    t.getWrittenResources()[0].data,
  );
  assert(
    output.systems[0].state === "unavailable" &&
      output.systems[0].sample === null,
  );
});

Deno.test("one malformed transport workflow identity becomes a gap without aborting other targets", async () => {
  const now = Date.now(), run = "00000000-0000-4000-8000-000000000002";
  for (const fromTag of [false, true]) {
    const marker = {
      cycleId: "00000000-0000-4000-8000-000000000001",
      startedAt: new Date(now - 2000).toISOString(),
    };
    const targets = ["example-first", "example-second"].map((id) => ({
      id,
      sourceHost: id,
      label: "Example system",
      group: "macos",
      kind: "physical",
      collector: "ssh",
    }));
    const t = createModelTestContext({
      globalArgs: { targets, cycleBehavior: "fleet-health" },
    });
    const rows = targets.map((target) =>
      fixtureRecord(
        {
          host: target.id,
          startedAt: new Date(now - 1000).toISOString(),
          finishedAt: new Date(now - 500).toISOString(),
          exitCode: 0,
          stdout: JSON.stringify(sample(now)),
        },
        "run-" + target.id,
        run,
      )
    );
    const invalid = "PRIVATE_SENTINEL".repeat(10);
    rows[0].workflowRunId = fromTag ? "" : invalid;
    rows[0].tags = fromTag ? { workflowRunId: invalid } : {};
    t.context.readModelData = (name) =>
      Promise.resolve(
        name === "fleet-health" ? [fixtureRecord(marker, "cycle", run)] : rows,
      );
    await model.methods.collect.execute({}, t.context);
    const output = model.resources.observations.schema.parse(
      t.getWrittenResources()[0].data,
    );
    assert(
      output.systems[0].state === "unavailable" &&
        output.systems[0].sample === null &&
        output.systems[0].sourceWorkflowRunId === null,
    );
    assert(output.systems[0].reason.includes("workflow identity is invalid"));
    assert(
      output.systems[1].state === "observed" &&
        output.systems[1].sourceWorkflowRunId === run,
    );
    assert(!JSON.stringify([output, t.getLogs()]).includes("PRIVATE_SENTINEL"));
  }
});
Deno.test("an invalid cycle workflow identity names its behavior and recovery steps without exposing the value", async () => {
  const now = Date.now(), invalid = "PRIVATE_SENTINEL".repeat(10);
  const t = createModelTestContext({
    globalArgs: {
      cycleBehavior: "fleet-health",
      targets: [{
        id: "example",
        label: "Example",
        group: "macos",
        kind: "physical",
        collector: "local",
      }],
    },
  });
  t.context.readModelData = () =>
    Promise.resolve([
      fixtureRecord(
        {
          cycleId: "00000000-0000-4000-8000-000000000001",
          startedAt: new Date(now - 1000).toISOString(),
        },
        "cycle",
        invalid,
      ),
    ]);
  let caught: unknown;
  try {
    await model.methods.collect.execute({}, t.context);
  } catch (error) {
    caught = error;
  }
  assert(
    caught instanceof Error && caught.message.includes("fleet-health") &&
      caught.message.includes("rerun") &&
      !caught.message.includes("PRIVATE_SENTINEL"),
  );
  assert(t.getWrittenResources().length === 0);
});
