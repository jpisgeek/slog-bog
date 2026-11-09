import { z } from "npm:zod@4";
import { renderFleet } from "./fleet_view.ts";
import {
  type FleetState,
  Observation,
  Policy,
  Row,
  State,
} from "./fleet_contract.ts";
import { ViewOptions } from "./view_options.ts";
export { type FleetState, Policy, State } from "./fleet_contract.ts";
const Globals = z.object({
  sourceBehavior: z.string().min(1).max(100).describe(
    "Behavior holding normalized observations",
  ),
  policy: Policy.default(() => Policy.parse({})),
  view: ViewOptions.default(() => ViewOptions.parse({})),
  coverageNotes: z.array(z.string().max(160)).max(50).default([]).describe(
    "Explicit operator-supplied coverage exclusions; none are assumed",
  ),
});
type RecordValue = {
  attributes?: unknown;
  version?: number;
  workflowRunId?: string;
  tags?: Record<string, string>;
};
type Context = {
  globalArgs: z.infer<typeof Globals>;
  readModelData: (name: string, spec?: string) => Promise<RecordValue[]>;
  writeResource: (
    spec: string,
    name: string,
    data: unknown,
  ) => Promise<unknown>;
  createFileWriter: (
    spec: string,
    name: string,
  ) => { writeText: (text: string) => Promise<unknown> };
  definition: { name: string };
};
/** Classify explicit measurements without treating missing counters as zero. */
export function assess(
  raw: z.infer<typeof Observation>,
  policy: z.infer<typeof Policy>,
  now: number,
): z.infer<typeof Row> {
  const r = Observation.parse(raw);
  let health: z.infer<typeof Row>["health"] = "unknown";
  const issues: string[] = [];
  if (r.state === "access-required") health = "access-required";
  else if (r.state === "unreachable") health = "unreachable";
  else if (r.state === "unsupported") health = "unsupported";
  else if (r.state !== "observed" || !r.sample) issues.push(r.reason);
  else {
    const s = r.sample;
    const age = now - Date.parse(s.observedAt);
    if (age < -60000) issues.push("System clock is ahead; freshness unknown");
    else if (age > policy.maxAgeSeconds * 1000) {
      health = "stale";
      issues.push("Observation is stale");
    } else {
      const capacities = [[s.memoryAvailableBytes, s.memoryTotalBytes], [
        s.diskAvailableBytes,
        s.diskTotalBytes,
      ]];
      const validCapacity = ([a, t]: Array<number | null>) =>
        a !== null && t !== null && t > 0 && a <= t;
      const memoryValid = validCapacity(capacities[0]),
        diskValid = validCapacity(capacities[1]);
      const valid = memoryValid && diskValid;
      if (
        memoryValid &&
        s.memoryAvailableBytes! / s.memoryTotalBytes! * 100 <
          policy.minMemoryPercent
      ) issues.push("Low memory headroom");
      if (
        diskValid &&
        (s.diskAvailableBytes! / s.diskTotalBytes! * 100 <
            policy.minDiskPercent ||
          s.diskAvailableBytes! < policy.minDiskBytes)
      ) issues.push("Low startup-data disk space");
      if (
        s.load1 !== null && s.logicalCores !== null &&
        s.load1 / s.logicalCores > policy.maxLoadPerCore
      ) issues.push("High one-minute load per core");
      health = issues.length
        ? "attention"
        : valid && s.load1 !== null && s.logicalCores !== null &&
            s.osVersion !== null
        ? "healthy"
        : "unknown";
      if (s.osVersion === null) issues.push("OS version unavailable");
      if (!valid) issues.push("Memory or disk counters unavailable or invalid");
      if (s.load1 === null || s.logicalCores === null) {
        issues.push("CPU load coverage incomplete");
      }
    }
  }
  if (
    health === "unreachable" || health === "access-required" ||
    health === "unsupported"
  ) {
    issues.push(r.reason);
  }
  return Row.parse({ ...r, health, issues });
}
/** Summarize exactly one scan cycle, counting OS observations separately from health. */
export function summarize(
  raw: unknown,
  cycle: { cycleId: string; startedAt: string },
  policy: z.infer<typeof Policy>,
  now: number,
  version: number | null,
  runId: string | null,
  coverageNotes: string[] = [],
): FleetState {
  const source = z.object({
    cycleId: z.string().uuid(),
    systems: z.array(Observation).min(1).max(100),
  }).parse(raw);
  if (
    source.cycleId !== cycle.cycleId ||
    source.systems.some((s) => s.cycleId !== cycle.cycleId)
  ) throw Error("Collector evidence is from a different fleet scan");
  if (new Set(source.systems.map((s) => s.id)).size !== source.systems.length) {
    throw Error("Duplicate system identities");
  }
  const systems = source.systems.map((s) => assess(s, policy, now));
  const os = new Map<
    string,
    { family: string; version: string; count: number }
  >();
  for (const r of systems) {
    if (
      !r.sample || r.sample.osVersion === null || r.state !== "observed" ||
      now - Date.parse(r.sample.observedAt) > policy.maxAgeSeconds * 1000 ||
      Date.parse(r.sample.observedAt) > now + 60000
    ) continue;
    const key = r.sample.family + " " + r.sample.osVersion;
    const old = os.get(key);
    os.set(key, {
      family: r.sample.family,
      version: r.sample.osVersion,
      count: (old?.count ?? 0) + 1,
    });
  }
  return State.parse({
    schemaVersion: 1,
    title: "Fleet Status Monitoring",
    generatedAt: new Date(now).toISOString(),
    scanStartedAt: cycle.startedAt,
    cycleId: cycle.cycleId,
    sourceVersion: version,
    workflowRunId: runId,
    policy,
    systems,
    totals: {
      configured: systems.length,
      scanned: systems.filter((s) =>
        s.state === "observed" && s.sample && s.sample.osVersion !== null &&
        now - Date.parse(s.sample.observedAt) <= policy.maxAgeSeconds * 1000 &&
        now - Date.parse(s.sample.observedAt) >= -60000
      ).length,
      healthy: systems.filter((s) =>
        s.health === "healthy"
      ).length,
      attention: systems.filter((s) => s.health === "attention").length,
      gaps: systems.filter((s) =>
        !["healthy", "attention"].includes(s.health)
      ).length,
    },
    operatingSystems: [...os.values()],
    exclusions: [
      ...coverageNotes,
      "Mounted disk images, installers and non-startup volumes are excluded from disk alerts.",
      "No process lists, user-file contents, credentials or automatic remediation collected.",
      "OS versions are observations, not an assessment of update or security support status.",
    ],
  });
}
/** Scan coordination, configurable health policy and versioned fleet reports. */
export const model = {
  type: "@jpisgeek/fleet-status-monitoring",
  version: "2026.11.09.1",
  description:
    "Fleet health policy, OS coverage and a readable versioned HTML dashboard snapshot",
  globalArguments: Globals,
  resources: {
    cycle: {
      description:
        "Start marker prevents stale transport successes being reused",
      schema: z.object({
        cycleId: z.string().uuid(),
        startedAt: z.iso.datetime(),
      }),
      lifetime: "30d",
      garbageCollection: 192,
    },
    state: {
      description:
        "Canonical fleet status with source versions, run evidence and honest coverage",
      schema: State,
      lifetime: "30d",
      garbageCollection: 192,
    },
  },
  files: {
    html: {
      description:
        "Self-contained filterable fleet snapshot for an existing dashboard host",
      contentType: "text/html",
      lifetime: "30d",
      garbageCollection: 12,
    },
  },
  methods: {
    begin: {
      description: "Start a new scan identity before transport collection",
      arguments: z.object({}),
      execute: async (_a: unknown, ctx: Context) => ({
        dataHandles: [
          await ctx.writeResource("cycle", "cycle", {
            cycleId: crypto.randomUUID(),
            startedAt: new Date().toISOString(),
          }),
        ],
      }),
    },
    render: {
      description:
        "Assess current scan evidence and render a human-readable fleet snapshot",
      arguments: z.object({}),
      execute: async (_a: unknown, ctx: Context) => {
        const cycleRecord =
          (await ctx.readModelData(ctx.definition.name, "cycle"))[0];
        const cycle = z.object({
          cycleId: z.string().uuid(),
          startedAt: z.iso.datetime(),
        }).parse(
          cycleRecord?.attributes,
        );
        const raw = (await ctx.readModelData(
          ctx.globalArgs.sourceBehavior,
          "observations",
        ))[0];
        const markerRun = cycleRecord?.workflowRunId ??
          cycleRecord?.tags?.workflowRunId;
        const observationRun = raw?.workflowRunId ?? raw?.tags?.workflowRunId;
        if (markerRun && observationRun && markerRun !== observationRun) {
          throw Error(
            "Observation and cycle belong to different workflow runs",
          );
        }
        const state = summarize(
          raw?.attributes,
          cycle,
          ctx.globalArgs.policy,
          Date.now(),
          raw?.version ?? null,
          raw?.workflowRunId ?? raw?.tags?.workflowRunId ?? null,
          ctx.globalArgs.coverageNotes,
        );
        const handle = await ctx.writeResource("state", "state", state);
        const html = await ctx.createFileWriter("html", "fleet-report.html")
          .writeText(renderFleet(state, ctx.globalArgs.view));
        return { dataHandles: [handle, html] };
      },
    },
  },
};

/** Existing-host integration; neither export starts a server. */
export { createFleetHandler, type FleetHost } from "./fleet_host.ts";
