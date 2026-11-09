import { observeHost } from "./native_probe.ts";
import { z } from "npm:zod@4";
import {
  Observation,
  type ObservationValue,
  Sample,
  Target,
  type TargetValue,
} from "./schema.ts";
const Globals = z.object({
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
type RecordValue = {
  name?: string;
  attributes?: unknown;
  version?: number;
  workflowRunId?: string;
  tags?: Record<string, string>;
};
type Context = {
  globalArgs: z.infer<typeof Globals>;
  definition: { name: string };
  readModelData: (name: string, spec?: string) => Promise<RecordValue[]>;
  writeResource: (
    spec: string,
    name: string,
    data: unknown,
  ) => Promise<unknown>;
};
const Transport = z.object({
  host: z.string(),
  startedAt: z.iso.datetime({ offset: true }),
  finishedAt: z.iso.datetime({ offset: true }),
  exitCode: z.number().nullable(),
  stdout: z.string().max(65536).optional(),
  stderr: z.string().max(16384).optional(),
});
const AttemptIdentity = Transport.pick({ host: true, startedAt: true });
/** Choose the newest attempt; resource version numbers are local to each method. */
export function latestResult(
  rows: RecordValue[],
  host: string | undefined,
): RecordValue | undefined {
  // Rank only validated identity/timing. Keep the newest malformed payload so
  // normalize reports its gap instead of falling back to an earlier success.
  return rows.flatMap((row) => {
    const parsed = AttemptIdentity.safeParse(row.attributes);
    return parsed.success && parsed.data.host === host
      ? [{ row, stamp: Date.parse(parsed.data.startedAt) }]
      : [];
  }).sort((a, b) =>
    b.stamp - a.stamp || (b.row.version ?? 0) - (a.row.version ?? 0)
  )[0]?.row;
}
/** Validate one probe result and reject observations outside the current scan. */
export function normalize(
  target: TargetValue,
  raw: RecordValue | undefined,
  cycle: { cycleId: string; startedAt: string; workflowRunId?: string },
  now: number,
): ObservationValue {
  const base = {
    ...target,
    cycleId: cycle.cycleId,
    checkedAt: new Date(now).toISOString(),
    sourceVersion: raw?.version ?? null,
    sourceWorkflowRunId: raw?.workflowRunId ?? raw?.tags?.workflowRunId ?? null,
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
  const out = Transport.safeParse(raw?.attributes);
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
  const parsed = z.object({
    startedAt: z.iso.datetime({ offset: true }),
    finishedAt: z.iso.datetime({ offset: true }),
    state: z.enum(["observed", "unavailable"]),
    sample: Sample.nullable(),
  }).safeParse(record?.attributes);
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
export const model = {
  type: "@jpisgeek/fleet-status-monitoring/system",
  version: "2026.11.09.1",
  description:
    "Observe and normalize bounded system statistics through native OS APIs and versioned official SSH evidence; no subprocesses",
  globalArguments: Globals,
  resources: {
    localProbe: {
      description: "Native local observation; the workflow owns when it runs",
      schema: z.object({
        startedAt: z.iso.datetime(),
        finishedAt: z.iso.datetime(),
        state: z.enum(["observed", "unavailable"]),
        sample: Sample.nullable(),
      }),
      lifetime: "30d",
      garbageCollection: 192,
    },
    observations: {
      description:
        "Per-system observations for one scan; failed attempts replace old success",
      schema: z.object({
        cycleId: z.string().uuid(),
        checkedAt: z.iso.datetime(),
        systems: z.array(Observation),
      }),
      lifetime: "30d",
      garbageCollection: 192,
    },
  },
  methods: {
    probe: {
      description:
        "Observe the serve host through native read-only OS APIs; startup data disk only",
      arguments: z.object({}),
      execute: async (_args: unknown, ctx: Context) => {
        const startedAt = new Date().toISOString();
        let sample: z.infer<typeof Sample> | null = null;
        try {
          sample = await observeHost();
        } catch {
          /* Retain an unavailable observation, without raw host errors. */
        }
        return {
          dataHandles: [
            await ctx.writeResource("localProbe", "localProbe", {
              startedAt,
              finishedAt: new Date().toISOString(),
              state: sample ? "observed" : "unavailable",
              sample,
            }),
          ],
        };
      },
    },
    collect: {
      description:
        "Collect local counters and normalize only results from the current fleet scan",
      arguments: z.object({}),
      execute: async (_args: unknown, ctx: Context) => {
        const cycles = await ctx.readModelData(
          ctx.globalArgs.cycleBehavior,
          "cycle",
        );
        const cycleValue = z.object({
          cycleId: z.string().uuid(),
          startedAt: z.iso.datetime(),
        }).parse(cycles[0]?.attributes);
        const sourceRun = cycles[0]?.workflowRunId ??
          cycles[0]?.tags?.workflowRunId;
        const cycle = {
          ...cycleValue,
          ...(sourceRun ? { workflowRunId: sourceRun } : {}),
        };
        const rows = ctx.globalArgs.targets.some((t) => t.collector === "ssh")
          ? await ctx.readModelData(
            ctx.globalArgs.transportBehavior,
            "runResult",
          )
          : [];
        const locals =
          ctx.globalArgs.targets.some((t) => t.collector === "local")
            ? await ctx.readModelData(
              ctx.globalArgs.localProbeBehavior ?? ctx.definition.name,
              "localProbe",
            )
            : [];
        const systems: ObservationValue[] = [];
        for (const target of ctx.globalArgs.targets) {
          const raw = target.collector === "local"
            ? localResult(target, locals[0])
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
        return {
          dataHandles: [
            await ctx.writeResource("observations", "observations", {
              cycleId: cycle.cycleId,
              checkedAt: new Date().toISOString(),
              systems,
            }),
          ],
        };
      },
    },
  },
};

/** Fixed optional Python source for independently authorized SSH probe deployments. */
export { probeScript } from "./probe_source.ts";
