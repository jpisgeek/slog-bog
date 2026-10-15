/** Render only a successful inventory-coverage execution's pinned summary. */
import {
  type EvidenceRepository,
  parseEvidence,
  readStored,
  type TypeRef,
} from "../documentation-evidence/documentation_evidence.ts";
import { render, Summary } from "./inventory_coverage.ts";
/** Report with no latest/previous-data fallback and no backend probes. */
export const report = {
  name: "@jpisgeek/inventory-coverage",
  description: "Coverage, freshness and degraded stored inventory observations",
  scope: "model",
  labels: ["inventory"],
  execute: async (ctx: {
    modelType: TypeRef;
    modelId: string;
    executionStatus: string;
    signal?: AbortSignal;
    dataHandles: Array<{ specName: string; name: string; version: number }>;
    dataRepository: EvidenceRepository;
  }) => {
    ctx.signal?.throwIfAborted();
    if (
      String(ctx.modelType) !== "@jpisgeek/inventory-coverage" ||
      ctx.executionStatus !== "succeeded"
    ) throw Error("Report requires a successful inventory-coverage capture");
    const handle = ctx.dataHandles.find((h) =>
      h.specName === "summary" && h.name === "summary"
    );
    if (
      !handle || !Number.isSafeInteger(handle.version) || handle.version < 1
    ) throw Error("No versioned coverage summary from this execution");
    try {
      const stored = await readStored(
        ctx.dataRepository,
        ctx.modelType,
        ctx.modelId,
        handle.name,
        handle.version,
        ctx.signal,
      );
      ctx.signal?.throwIfAborted();
      if (!stored?.bytes) throw Error("Summary unavailable");
      const summary = Summary.parse(parseEvidence(stored.bytes));
      return { markdown: render(summary), json: summary };
    } catch {
      ctx.signal?.throwIfAborted();
      throw Error(
        "Coverage summary unavailable or invalid; no report produced",
      );
    }
  },
};
