import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261105.71";
import { createFleetModel, model, Policy } from "./fleet_status_monitoring.ts";
import { fixtureRecord, fixtureState } from "./test_fixtures.ts";
import { Collected } from "./schema.ts";
import { Observation, projectObservation, State } from "./fleet_contract.ts";
import { model as collector } from "./fleet_system_stats.ts";

const check = (ok: unknown) => {
  if (!ok) throw Error("Assertion failed");
};
async function rejects(action: () => Promise<unknown>, ...messages: string[]) {
  let caught: unknown;
  try {
    await action();
  } catch (error) {
    caught = error;
  }
  check(
    caught instanceof Error &&
      messages.every((m) => caught.message.includes(m)),
  );
}
function fixture() {
  const state = fixtureState();
  const cycle = { cycleId: state.cycleId, startedAt: state.scanStartedAt };
  const observations = Collected.parse({
    cycleId: state.cycleId,
    checkedAt: state.generatedAt,
    systems: state.systems.map(({ health: _health, issues: _issues, ...row }) =>
      row
    ),
  });
  const t = createModelTestContext({
    definition: { name: "fleet-health" },
    globalArgs: { sourceBehavior: "fleet-counters" },
    storedResources: { cycle, state },
  });
  const records = {
    cycles: [fixtureRecord(cycle, "cycle")],
    sources: [fixtureRecord(observations)],
  };
  t.context.readModelData = (name) =>
    Promise.resolve(name === "fleet-health" ? records.cycles : records.sources);
  return { ...t, cycle, observations, state, records };
}

Deno.test("render executes with SDK resource/file writers and embeds exactly the strict state", async () => {
  const t = fixture(), reads: string[] = [], original = t.context.readResource;
  t.context.readResource = (name) => {
    reads.push(name);
    return original(name);
  };
  const result = await model.methods.render.execute({}, t.context);
  const [write] = t.getWrittenResources(), [file] = t.getWrittenFiles();
  check(
    reads.join() === "cycle" && write.name === "state" &&
      write.specName === "state",
  );
  const state = State.parse(write.data);
  check(
    state.systems[0].sample?.schemaVersion === 1 &&
      state.workflowRunId === t.records.sources[0].workflowRunId,
  );
  check(file.specName === "html" && file.name === "fleet-report.html");
  const embedded = new TextDecoder().decode(file.content).match(
    /<script id="fleet-state" type="application\/json">(.*?)<\/script>/s,
  )![1];
  check(JSON.stringify(JSON.parse(embedded)) === JSON.stringify(state));
  check(
    result.dataHandles[0] === write.handle &&
      result.dataHandles[1] === file.handle,
  );
  check(t.getLogsByLevel("info").length === 2);
});
Deno.test("render names missing and invalid prerequisites with recovery instructions", async () => {
  for (
    const kind of [
      "missing-cycle",
      "invalid-cycle",
      "missing-source",
      "invalid-source",
    ] as const
  ) {
    const t = fixture();
    if (kind === "missing-cycle") {
      t.context.readResource = () => Promise.resolve(null);
    }
    if (kind === "invalid-cycle") {
      t.context.readResource = () =>
        Promise.resolve({ ...t.cycle, typo: true });
    }
    if (kind === "missing-source") t.records.sources = [];
    if (kind === "invalid-source") {
      t.records.sources[0].attributes = { ...t.observations, typo: true };
    }
    await rejects(
      () => model.methods.render.execute({}, t.context),
      kind.includes("cycle") ? "fleet-health" : "fleet-counters",
      kind === "invalid-source" ? "rerun" : "begin",
    );
    check(
      t.getWrittenFiles().length === 0 && t.getWrittenResources().length === 0,
    );
  }
});
Deno.test("render rejects mismatched or missing observation workflow metadata", async () => {
  for (const run of ["00000000-0000-4000-8000-000000000009", ""]) {
    const t = fixture();
    t.records.sources[0].workflowRunId = run;
    await rejects(
      () => model.methods.render.execute({}, t.context),
      t.records.cycles[0].workflowRunId,
      run || "missing",
      "rerun",
    );
    check(t.getWrittenResources().length === 0);
  }
});
Deno.test("render reports both marker and conflicting per-system cycle identities", async () => {
  const t = fixture(), other = "00000000-0000-4000-8000-000000000009";
  t.observations.systems[0].cycleId = other;
  await rejects(
    () => model.methods.render.execute({}, t.context),
    other,
    t.cycle.cycleId,
    "rerun",
  );
});
Deno.test("render completes HTML generation before touching either writer", async () => {
  const t = fixture(),
    m = createFleetModel(() => {
      throw Error("render failed");
    });
  await rejects(() => m.methods.render.execute({}, t.context), "render failed");
  check(
    t.getWrittenFiles().length === 0 && t.getWrittenResources().length === 0,
  );
});
Deno.test("failed HTML storage never commits a fresh state", async () => {
  const t = fixture(), original = t.context.createFileWriter;
  t.context.createFileWriter = (spec, name) => ({
    ...original(spec, name),
    writeText: () => Promise.reject(Error("file storage failed")),
  });
  await rejects(
    () => model.methods.render.execute({}, t.context),
    "file storage failed",
  );
  check(
    t.getWrittenResources().length === 0 && t.getWrittenFiles().length === 0,
  );
  check(
    JSON.stringify(await t.context.readResource("state")) ===
      JSON.stringify(t.state),
  );
});
Deno.test("state is the final commit after HTML storage; a failed state write preserves prior canonical state", async () => {
  const t = fixture();
  t.context.writeResource = () => {
    check(t.getWrittenFiles().length === 1);
    return Promise.reject(Error("state storage failed"));
  };
  await rejects(
    () => model.methods.render.execute({}, t.context),
    "state storage failed",
  );
  check(
    t.getWrittenResources().length === 0 &&
      JSON.stringify(await t.context.readResource("state")) ===
        JSON.stringify(t.state),
  );
});
Deno.test("render ranks source records by checkedAt before unrelated version counts", async () => {
  const t = fixture(),
    old = fixtureRecord(
      {
        ...t.observations,
        checkedAt: new Date(Date.parse(t.observations.checkedAt) - 10000)
          .toISOString(),
      },
      "observations",
      undefined,
      99,
    );
  const fresh = fixtureRecord(t.observations, "observations", undefined, 2);
  for (const rows of [[old, fresh], [fresh, old]]) {
    t.records.sources = rows;
    await model.methods.render.execute({}, t.context);
  }
  check(t.getWrittenResources().every((r) => r.data.sourceVersion === 2));
});
Deno.test("a newest malformed source never revives an older valid report", async () => {
  const t = fixture();
  t.records.sources.push(
    fixtureRecord({
      ...t.observations,
      checkedAt: new Date(Date.parse(t.observations.checkedAt) + 1)
        .toISOString(),
      systems: "bad",
    }),
  );
  await rejects(
    () => model.methods.render.execute({}, t.context),
    "Invalid observations",
    "fleet-counters",
  );
  check(t.getWrittenResources().length === 0);
});
Deno.test("concurrent replacement between own resource and metadata reads fails instead of mixing provenance", async () => {
  const t = fixture();
  t.records.cycles[0].attributes = {
    ...t.cycle,
    cycleId: "00000000-0000-4000-8000-000000000009",
  };
  await rejects(
    () => model.methods.render.execute({}, t.context),
    "Cannot match cycle",
    "rerun",
  );
  check(t.getWrittenResources().length === 0);
});
Deno.test("strict policy and global arguments reject misspelled keys", () => {
  check(!Policy.safeParse({ minDiskPercnt: 10 }).success);
  check(
    !model.globalArguments.safeParse({
      sourceBehavior: "fleet-counters",
      polcy: {},
    }).success,
  );
  check(
    !model.globalArguments.safeParse({
      sourceBehavior: "fleet-counters",
      policy: { minDiskPercnt: 10 },
    }).success,
  );
  check(
    !collector.globalArguments.safeParse({
      cycleBehavior: "fleet-health",
      targets: [{
        id: "local",
        label: "Example",
        group: "macos",
        kind: "physical",
        collector: "local",
      }],
      localProbeBehavor: "typo",
    }).success,
  );
});
Deno.test("the explicit report projection removes sourceHost only and preserves version and enums", () => {
  const t = fixture(),
    source = { ...t.observations.systems[0], sourceHost: "example-host" };
  const projected = projectObservation(source);
  check(!("sourceHost" in projected) && projected.sample?.schemaVersion === 1);
  for (
    const [key, value] of [["group", "typo"], ["kind", "typo"], [
      "collector",
      "typo",
    ], ["unexpected", true]] as const
  ) {
    check(!Observation.safeParse({ ...projected, [key]: value }).success);
  }
  check(!State.safeParse({ ...t.state, unexpected: true }).success);
  check(!Observation.safeParse(source).success);
});

Deno.test("render labels invalid run metadata with its behavior and never includes the malformed identity", async () => {
  for (const marker of [false, true]) {
    const t = fixture(), invalid = "PRIVATE_SENTINEL".repeat(10);
    (marker ? t.records.cycles : t.records.sources)[0].workflowRunId = invalid;
    let caught: unknown;
    try {
      await model.methods.render.execute({}, t.context);
    } catch (error) {
      caught = error;
    }
    check(
      caught instanceof Error &&
        caught.message.includes(marker ? "fleet-health" : "fleet-counters") &&
        caught.message.includes("rerun") &&
        !caught.message.includes("PRIVATE_SENTINEL"),
    );
    check(
      t.getWrittenResources().length === 0 && t.getWrittenFiles().length === 0,
    );
  }
});
