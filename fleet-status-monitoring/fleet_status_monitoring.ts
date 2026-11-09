import { z } from "npm:zod@4";
import { renderFleet } from "./fleet_view.ts";
import {
  type FleetState,
  Observation,
  Policy,
  projectObservation,
  Row,
  State,
} from "./fleet_contract.ts";
import { ViewOptions } from "./view_options.ts";
export { type FleetState, Policy, State } from "./fleet_contract.ts";
import { Collected, Cycle } from "./schema.ts";
import {
  type EvidenceReader,
  evidenceRun,
  type FleetLogger,
  newestEvidence,
  ownEvidence,
} from "./evidence.ts";
const Globals = z.strictObject({
  sourceBehavior: z.string().min(1).max(100).describe(
    "Behavior holding normalized observations",
  ),
  policy: Policy.default(() => Policy.parse({})),
  view: ViewOptions.default(() => ViewOptions.parse({})),
  coverageNotes: z.array(z.string().max(160)).max(50).default([]).describe(
    "Explicit operator-supplied coverage exclusions; none are assumed",
  ),
});
type Context = EvidenceReader & {
  globalArgs: unknown;
  logger: FleetLogger;
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<unknown>;
  createFileWriter: (
    spec: string,
    name: string,
  ) => { writeText: (text: string) => Promise<unknown> };
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
  const source = Collected.parse(raw);
  if (
    source.cycleId !== cycle.cycleId ||
    source.systems.some((s) => s.cycleId !== cycle.cycleId)
  ) {
    throw Error(
      `Collector cycles ${
        [...new Set([source.cycleId, ...source.systems.map((s) => s.cycleId)])]
          .join(", ")
      } do not match marker ${cycle.cycleId}; rerun begin, probe and collect together`,
    );
  }
  if (new Set(source.systems.map((s) => s.id)).size !== source.systems.length) {
    throw Error("Duplicate system identities");
  }
  const systems = source.systems.map((s) =>
    assess(projectObservation(s), policy, now)
  );
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
export function createFleetModel(renderer: typeof renderFleet = renderFleet) {
  return {
    type: "@jpisgeek/fleet-status-monitoring",
    version: "2026.11.09.1",
    description:
      "Fleet health policy, OS coverage and a readable versioned HTML dashboard snapshot",
    globalArguments: Globals,
    resources: {
      cycle: {
        description:
          "Start marker prevents stale transport successes being reused",
        schema: Cycle,
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
        arguments: z.strictObject({}),
        execute: async (_a: unknown, ctx: Context) => {
          ctx.logger.info(
            "Starting fleet scan for {behavior}",
            { behavior: ctx.definition.name },
          );
          const cycle = Cycle.parse({
            cycleId: crypto.randomUUID(),
            startedAt: new Date().toISOString(),
          });
          const handle = await ctx.writeResource("cycle", "cycle", cycle);
          ctx.logger.info("Started fleet scan {cycleId}", {
            cycleId: cycle.cycleId,
          });
          return { dataHandles: [handle] };
        },
      },
      render: {
        description:
          "Assess current scan evidence and render a human-readable fleet snapshot",
        arguments: z.strictObject({}),
        execute: async (_a: unknown, ctx: Context) => {
          const globals = Globals.parse(ctx.globalArgs);
          ctx.logger.info(
            "Starting fleet report for {behavior}",
            { behavior: ctx.definition.name },
          );
          const cycleRecord = await ownEvidence(ctx, "cycle", Cycle);
          if (!cycleRecord) {
            throw Error(
              `No scan-start marker in ${ctx.definition.name}; run begin before render`,
            );
          }
          const cycle = Cycle.parse(cycleRecord.attributes);
          const raw = newestEvidence(
            await ctx.readModelData(globals.sourceBehavior, "observations"),
            "checkedAt",
            "observations",
          );
          if (!raw) {
            throw Error(
              `No observations in ${globals.sourceBehavior}; run begin, probe and collect before render`,
            );
          }
          if (!Collected.safeParse(raw.attributes).success) {
            throw Error(
              `Invalid observations in ${globals.sourceBehavior}; rerun the complete fleet workflow before render`,
            );
          }
          const markerRun = evidenceRun(cycleRecord, ctx.definition.name),
            observationRun = evidenceRun(raw, globals.sourceBehavior);
          if (markerRun && markerRun !== observationRun) {
            throw Error(
              `Observation workflow ${
                observationRun ?? "missing"
              } does not match marker workflow ${markerRun}; rerun the complete fleet workflow`,
            );
          }
          const state = summarize(
            raw.attributes,
            cycle,
            globals.policy,
            Date.now(),
            raw.version ?? null,
            observationRun ?? null,
            globals.coverageNotes,
          );
          // Complete rendering before either write. State is the commit record:
          // never publish fresh state before its corresponding HTML is stored.
          const text = renderer(state, globals.view);
          const html = await ctx.createFileWriter("html", "fleet-report.html")
            .writeText(text);
          const handle = await ctx.writeResource("state", "state", state);
          ctx.logger.info(
            "Completed fleet report: {scanned} scanned, {attention} attention, {gaps} gaps",
            {
              scanned: state.totals.scanned,
              attention: state.totals.attention,
              gaps: state.totals.gaps,
            },
          );
          return { dataHandles: [handle, html] };
        },
      },
    },
  };
}

/** Default behavior; tests can inject rendering failures without altering workflow inputs. */
export const model = {
  ...createFleetModel(),
  type: "@jpisgeek/fleet-status-monitoring",
  version: "2026.11.09.1",
};

/** Existing-host integration; neither export starts a server. */
export { createFleetHandler, type FleetHost } from "./fleet_host.ts";
