import { Policy, summarize } from "./fleet_status_monitoring.ts";
/** Synthetic canonical report for host and rendering tests. */
export function fixtureState() {
  const now = Date.now(),
    cycle = {
      cycleId: "00000000-0000-4000-8000-000000000001",
      startedAt: new Date(now - 1000).toISOString(),
    };
  return summarize(
    {
      cycleId: cycle.cycleId,
      checkedAt: new Date(now).toISOString(),
      systems: [{
        id: "mac-mini",
        label: "Mac Mini",
        group: "macos",
        kind: "physical",
        collector: "local",
        note: "Example",
        cycleId: cycle.cycleId,
        checkedAt: new Date(now).toISOString(),
        state: "observed",
        reason: "Observed",
        sample: {
          schemaVersion: 1,
          observedAt: new Date(now).toISOString(),
          family: "macos",
          osName: "macOS",
          osVersion: "example",
          kernel: "example",
          architecture: "arm64",
          logicalCores: 8,
          uptimeSeconds: 123,
          memoryTotalBytes: 16 * 1024 ** 3,
          memoryAvailableBytes: 8 * 1024 ** 3,
          memoryAvailableKind: "estimate",
          diskTotalBytes: 500 * 1024 ** 3,
          diskAvailableBytes: 100 * 1024 ** 3,
          load1: 1,
        },
        sourceVersion: 1,
        sourceWorkflowRunId: "00000000-0000-4000-8000-000000000002",
      }],
    },
    cycle,
    Policy.parse({}),
    now,
    1,
    "00000000-0000-4000-8000-000000000002",
  );
}

/** Complete synthetic SDK record for tests; no live datastore is read. */
export function fixtureRecord(
  attributes: Record<string, unknown>,
  name = "observations",
  workflowRunId = "00000000-0000-4000-8000-000000000002",
  version = 1,
) {
  return {
    id: "00000000-0000-4000-8000-000000000003",
    name,
    version,
    isLatest: true,
    createdAt: new Date().toISOString(),
    namespace: "example",
    attributes,
    tags: {},
    modelName: "example-behavior",
    modelId: "00000000-0000-4000-8000-000000000004",
    modelType: "example/type",
    specName: name,
    dataType: "resource",
    contentType: "application/json",
    lifetime: "30d",
    ownerType: "model",
    streaming: false,
    size: 0,
    content: attributes,
    ownerRef: "example",
    workflowRunId,
    workflowName: "example-fleet",
    jobName: "scan",
    stepName: "example",
    source: "test",
  };
}
