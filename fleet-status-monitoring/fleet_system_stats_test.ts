import { localResult, model } from "./fleet_system_stats.ts";
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
  const now = Date.now(), calls: string[] = [], writes: unknown[] = [];
  const context = {
    definition: { name: "fleet-counters" },
    globalArgs: {
      targets: [
        Target.parse({
          id: "mac-mini",
          label: "Mac Mini",
          group: "macos",
          kind: "physical",
          collector: "local",
        }),
      ],
      cycleBehavior: "fleet-health",
      transportBehavior: "fleet-transport",
      localProbeBehavior: "fleet-local-probe",
    },
    readModelData: async (name: string) => {
      calls.push(name);
      if (name === "fleet-health") {
        return [{
          attributes: {
            cycleId: "00000000-0000-4000-8000-000000000001",
            startedAt: new Date(now - 10000).toISOString(),
          },
        }];
      }
      if (name === "fleet-local-probe") {
        return local === null ? [] : [{
          version: 7,
          workflowRunId: "example-run",
          attributes: typeof local === "function" ? local(now + offset) : local,
        }];
      }
      throw Error("Unexpected source read");
    },
    writeResource: async (_s: string, _n: string, data: unknown) => {
      writes.push(data);
      return { name: "observations" };
    },
  };
  await model.methods.collect.execute({}, context);
  return {
    calls,
    value: writes[0] as {
      systems: Array<
        {
          state: string;
          sample: unknown;
          sourceVersion: number | null;
          sourceWorkflowRunId: string | null;
        }
      >;
    },
  };
}
Deno.test("local collection consumes typed native evidence without requiring SSH or executing a command", async () => {
  const r = await collect((now: number) => ({
    startedAt: new Date(now - 1000).toISOString(),
    finishedAt: new Date(now - 500).toISOString(),
    state: "observed",
    sample: sample(now),
  }));
  assert(!r.calls.includes("fleet-transport"));
  assert(
    r.value.systems[0].state === "observed" &&
      r.value.systems[0].sourceVersion === 7 &&
      r.value.systems[0].sourceWorkflowRunId === "example-run",
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
