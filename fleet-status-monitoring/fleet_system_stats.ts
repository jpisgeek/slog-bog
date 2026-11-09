import { observeHost } from "./native_probe.ts";
import { z } from "npm:zod@4";
import {
  Collected,
  Cycle,
  LocalProbe,
  Observation,
  type ObservationValue,
  Sample,
  Target,
  type TargetValue,
} from "./schema.ts";
import {
  type EvidenceReader,
  type EvidenceRecord as RecordValue,
  evidenceRun,
  type FleetLogger,
  newestEvidence,
  ownEvidence,
} from "./evidence.ts";
const Globals = z.strictObject({
  targets: z.array(Target).min(1).max(100).refine(
    (targets) => targets.filter((t) => t.collector === "local").length <= 1,
    "Only one local target can identify the serve host",
  ),
  transportBehavior: z.string().min(1).max(100).default("fleet-transport")
    .describe(
      "Behavior holding official SSH runResult records; only read when SSH targets are declared",
    ),
  localProbeBehavior: z.string().min(1).max(100).nullable().default(null)
    .describe("Typed local probe behavior; null reads this collector instance"),
  cycleBehavior: z.string().min(1).max(100).describe(
    "Behavior holding the scan-start marker",
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
};
const Transport = z.strictObject({
  host: z.string(),
  startedAt: z.iso.datetime({ offset: true }),
  finishedAt: z.iso.datetime({ offset: true }),
  exitCode: z.number().nullable(),
  stdout: z.string().max(65536).optional(),
  stderr: z.string().max(16384).optional(),
});
const AttemptIdentity = Transport.pick({ host: true, startedAt: true });
function transportFields(raw: unknown) {
  if (!raw || typeof raw !== "object") return undefined;
  const fields = raw as Record<string, unknown>;
  return Object.fromEntries(
    ["host", "startedAt", "finishedAt", "exitCode", "stdout", "stderr"]
      .filter((key) => key in fields).map((key) => [key, fields[key]]),
  );
}
/** Choose the newest attempt; resource version numbers are local to each method. */
export function latestResult(
  rows: RecordValue[],
  host: string | undefined,
): RecordValue | undefined {
  // Rank only validated identity/timing. Keep the newest malformed payload so
  // normalize reports its gap instead of falling back to an earlier success.
  return rows.flatMap((row) => {
    const fields = transportFields(row.attributes);
    const parsed = AttemptIdentity.safeParse(
      fields && {
        host: fields.host,
        startedAt: fields.startedAt,
      },
    );
    return parsed.success && parsed.data.host === host
      ? [{ row, stamp: Date.parse(parsed.data.startedAt) }]
      : [];
  }).sort((a, b) =>
    b.stamp - a.stamp ||
    (a.row.name === b.row.name
      ? (b.row.version ?? 0) - (a.row.version ?? 0)
      : (a.row.name ?? "").localeCompare(b.row.name ?? ""))
  )[0]?.row;
}
/** Validate one probe result and reject observations outside the current scan. */
export function normalize(
  target: TargetValue,
  raw: RecordValue | undefined,
  cycle: { cycleId: string; startedAt: string; workflowRunId?: string },
  now: number,
): ObservationValue {
  let sourceWorkflowRunId: string | null = null;
  let invalidRun = false;
  try {
    sourceWorkflowRunId = evidenceRun(raw) ?? null;
  } catch {
    invalidRun = true;
  }
  const base = {
    ...target,
    cycleId: cycle.cycleId,
    checkedAt: new Date(now).toISOString(),
    sourceVersion: raw?.version ?? null,
    sourceWorkflowRunId,
  };
  const unavailable = (
    state: "unreachable" | "access-required" | "unsupported" | "unavailable",
    reason: string,
  ) => Observation.parse({ ...base, state, reason, sample: null });
  if (target.collector === "unconfigured") {
    return unavailable(
      "unsupported",
      target.note || "Collector not configured",
    );
  }
  if (invalidRun) {
    return unavailable(
      "unavailable",
      "Transport workflow identity is invalid; rerun the complete fleet workflow",
    );
  }
  const out = Transport.safeParse(transportFields(raw?.attributes));
  if (!out.success) {
    return unavailable(
      "unavailable",
      "No valid transport result for this scan",
    );
  }
  const s = out.data;
  if (cycle.workflowRunId && base.sourceWorkflowRunId !== cycle.workflowRunId) {
    return unavailable(
      "unavailable",
      "Transport result belongs to a different workflow run",
    );
  }
  if (s.host !== target.sourceHost) {
    return unavailable("unavailable", "Transport target mismatch");
  }
  if (
    Date.parse(s.finishedAt) < Date.parse(s.startedAt) ||
    Date.parse(s.startedAt) < Date.parse(cycle.startedAt) ||
    Date.parse(s.finishedAt) > now + 60000
  ) {
    return unavailable(
      "unavailable",
      "Transport result belongs to an earlier scan or has a future clock",
    );
  }
  if (
    target.collector === "ssh" && s.exitCode !== 0 &&
    /permission denied|authentication failed|load key|host key verification failed|agent refused/i
      .test(s.stderr ?? "")
  ) {
    return unavailable(
      "access-required",
      "Existing SSH identity did not authenticate; system health not assessed",
    );
  }
  if (s.exitCode === 127) {
    return unavailable(
      "unsupported",
      "Python 3 probe is not available on this target",
    );
  }
  if (s.exitCode !== 0) {
    return unavailable(
      target.collector === "local" ? "unavailable" : "unreachable",
      "Transport or probe failed; see the source run evidence",
    );
  }
  try {
    const sample = Sample.parse(JSON.parse(s.stdout || ""));
    const when = Date.parse(sample.observedAt);
    if (
      when > now + 60000 || when < Date.parse(s.startedAt) - 60000 ||
      now - when > 300000
    ) return unavailable("unavailable", "Probe clock outside this scan window");
    return Observation.parse({
      ...base,
      state: "observed",
      reason: "Read-only counters observed",
      sample,
    });
  } catch {
    return unavailable(
      "unavailable",
      "Probe response failed the system statistics contract",
    );
  }
}
/** Adapt a typed native probe result, retaining its original timing and evidence. */
export function localResult(
  target: TargetValue,
  record: RecordValue | undefined,
): RecordValue | undefined {
  const parsed = LocalProbe.safeParse(record?.attributes);
  if (!parsed.success) {
    return record ? { ...record, attributes: undefined } : undefined;
  }
  const p = parsed.data;
  return {
    ...record,
    attributes: {
      host: target.sourceHost ?? target.id,
      startedAt: p.startedAt,
      finishedAt: p.finishedAt,
      exitCode: p.state === "observed" && p.sample ? 0 : 1,
      stdout: p.sample ? JSON.stringify(p.sample) : "",
    },
  };
}
/** Native local observation and a read-only adapter for versioned probe evidence. */
export function createSystemStatsModel(
  observer: () => Promise<unknown> = observeHost,
) {
  return {
    type: "@jpisgeek/fleet-status-monitoring/system",
    version: "2026.11.09.1",
    description:
      "Observe and normalize bounded system statistics through native OS APIs and versioned official SSH evidence; no subprocesses",
    globalArguments: Globals,
    resources: {
      localProbe: {
        description: "Native local observation; the workflow owns when it runs",
        schema: LocalProbe,
        lifetime: "30d",
        garbageCollection: 192,
      },
      observations: {
        description:
          "Per-system observations for one scan; failed attempts replace old success",
        schema: Collected,
        lifetime: "30d",
        garbageCollection: 192,
      },
    },
    methods: {
      probe: {
        description:
          "Observe the serve host through native read-only OS APIs; startup data disk only",
        arguments: z.strictObject({}),
        execute: async (_args: unknown, ctx: Context) => {
          ctx.logger.info(
            "Starting native fleet probe for {behavior}",
            { behavior: ctx.definition.name },
          );
          const startedAt = new Date().toISOString();
          let sample: z.infer<typeof Sample> | null = null;
          let failureKind: z.infer<typeof LocalProbe>["failureKind"] = null;
          try {
            sample = Sample.parse(await observer());
          } catch (error) {
            failureKind = error instanceof z.ZodError
              ? "contract-validation"
              : "observation-failed";
            ctx.logger.warn(
              "Native fleet probe unavailable: {failureKind}",
              { failureKind },
            );
          }
          const result = LocalProbe.parse({
            startedAt,
            finishedAt: new Date().toISOString(),
            state: sample ? "observed" : "unavailable",
            failureKind,
            sample,
          });
          const handle = await ctx.writeResource(
            "localProbe",
            "localProbe",
            result,
          );
          ctx.logger.info(
            "Completed native fleet probe: {state}",
            { state: result.state },
          );
          return { dataHandles: [handle] };
        },
      },
      collect: {
        description:
          "Collect local counters and normalize only results from the current fleet scan",
        arguments: z.strictObject({}),
        execute: async (_args: unknown, ctx: Context) => {
          const globals = Globals.parse(ctx.globalArgs);
          ctx.logger.info(
            "Starting fleet collection for {count} systems",
            { count: globals.targets.length },
          );
          const cycleRecord = newestEvidence(
            await ctx.readModelData(globals.cycleBehavior, "cycle"),
            "startedAt",
            "cycle",
          );
          if (!cycleRecord) {
            throw Error(
              `No scan-start marker in ${globals.cycleBehavior}; run begin before collect`,
            );
          }
          const parsed = Cycle.safeParse(cycleRecord.attributes);
          if (!parsed.success) {
            throw Error(
              `Invalid scan-start marker in ${globals.cycleBehavior}; run begin before collect`,
            );
          }
          const cycle = {
            ...parsed.data,
            workflowRunId: evidenceRun(cycleRecord, globals.cycleBehavior),
          };
          const rows = globals.targets.some((t) => t.collector === "ssh")
            ? await ctx.readModelData(globals.transportBehavior, "runResult")
            : [];
          let local: RecordValue | undefined;
          if (globals.targets.some((t) => t.collector === "local")) {
            local = !globals.localProbeBehavior ||
                globals.localProbeBehavior === ctx.definition.name
              ? await ownEvidence(ctx, "localProbe", LocalProbe)
              : newestEvidence(
                await ctx.readModelData(
                  globals.localProbeBehavior,
                  "localProbe",
                ),
                "startedAt",
                "localProbe",
              );
          }
          const systems: ObservationValue[] = [];
          for (const target of globals.targets) {
            const raw = target.collector === "local"
              ? localResult(target, local)
              : latestResult(rows, target.sourceHost);
            systems.push(
              normalize(
                { ...target, sourceHost: target.sourceHost ?? target.id },
                raw,
                cycle,
                Date.now(),
              ),
            );
          }
          for (const system of systems) {
            if (system.state !== "observed") {
              ctx.logger.debug(
                "Fleet coverage gap: {id} {state} {reason}",
                { id: system.id, state: system.state, reason: system.reason },
              );
            }
          }
          const result = Collected.parse({
            cycleId: cycle.cycleId,
            checkedAt: new Date().toISOString(),
            systems,
          });
          const handle = await ctx.writeResource(
            "observations",
            "observations",
            result,
          );
          ctx.logger.info(
            "Completed fleet collection: {observed} observed, {gaps} gaps",
            {
              observed: systems.filter((s) => s.state === "observed").length,
              gaps: systems.filter((s) => s.state !== "observed").length,
            },
          );
          return { dataHandles: [handle] };
        },
      },
    },
  };
}

/** Default behavior; tests can inject a bounded observer without observing the host. */
export const model = {
  ...createSystemStatsModel(),
  type: "@jpisgeek/fleet-status-monitoring/system",
  version: "2026.11.09.1",
};

/** Optional fixed remote probe source; not executed by this behavior. */
export { probeScript } from "./probe_source.ts";
