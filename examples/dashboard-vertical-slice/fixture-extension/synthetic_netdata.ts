/** Public-safe deterministic collector used only by the dashboard vertical slice. */
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({});
const ObserveArgsSchema = z.object({
  mode: z.enum(["healthy", "partial"]).default("healthy").describe(
    "partial simulates a collector sub-fetch that retained valid node data",
  ),
});
const NodeSchema = z.object({
  name: z.string(),
  url: z.string(),
  reachable: z.boolean(),
  error: z.string(),
  transport: z.string(),
  version: z.string().nullable(),
  hostname: z.string().nullable(),
  osName: z.string().nullable(),
  osVersion: z.string().nullable(),
  cores: z.number(),
  collectors: z.number(),
  charts: z.number(),
  alarmsActive: z.number(),
  alarmsCritical: z.number(),
  alarmsWarning: z.number(),
  claimedToCloud: z.boolean(),
  mountsOverThreshold: z.number(),
});
const SummarySchema = z.object({
  nodes: z.number(),
  nodesReachable: z.number(),
  nodesUnreachable: z.number(),
  nodesDegraded: z.number(),
  alarmsActive: z.number(),
  alarmsCritical: z.number(),
  mountsOverThreshold: z.number(),
  syncedAt: z.iso.datetime(),
});

// deno-lint-ignore no-explicit-any
async function observe(args: unknown, ctx: any) {
  const input = ObserveArgsSchema.parse(args);
  const node = await ctx.writeResource("node", "node-synthetic", {
    name: "synthetic-node",
    url: "https://synthetic.example.invalid",
    reachable: true,
    error: "",
    transport: "fixture",
    version: "1.0.0",
    hostname: "synthetic-node",
    osName: "fixture",
    osVersion: "1",
    cores: 4,
    collectors: 1,
    charts: 2,
    alarmsActive: 0,
    alarmsCritical: 0,
    alarmsWarning: 0,
    claimedToCloud: false,
    mountsOverThreshold: 0,
  });
  const summary = await ctx.writeResource("summary", "summary", {
    nodes: 1,
    nodesReachable: 1,
    nodesUnreachable: 0,
    nodesDegraded: input.mode === "partial" ? 1 : 0,
    alarmsActive: 0,
    alarmsCritical: 0,
    mountsOverThreshold: 0,
    syncedAt: new Date().toISOString(),
  });
  return { dataHandles: [node, summary] };
}

/** Netdata-shaped fixture model; never publish as the real collector. */
export const model = {
  type: "@jpisgeek/netdata",
  version: "2026.08.25.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    node: {
      description: "One deterministic synthetic node.",
      schema: NodeSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
    summary: {
      description: "Synthetic sweep summary with optional partial coverage.",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
  },
  methods: {
    discover: {
      description: "Write a deterministic public-safe observation.",
      arguments: ObserveArgsSchema,
      execute: observe,
    },
  },
};
