/** Human-readable report over a documentation evidence capture. */
import {
  type EvidenceRepository,
  parseEvidence,
  readStored,
  render,
  Snapshot,
  type TypeRef,
} from "./documentation_evidence.ts";
/** Render only this successful execution's versioned snapshot. */
export const report = {
  name: "@jpisgeek/infrastructure-guide",
  description:
    "Document strictly typed operational metadata with original observation times",
  scope: "model",
  labels: ["documentation"],
  execute: async (
    context: {
      modelType: TypeRef;
      modelId: string;
      executionStatus: string;
      signal?: AbortSignal;
      dataHandles: Array<{ specName: string; name: string; version: number }>;
      dataRepository: EvidenceRepository;
    },
  ) => {
    context.signal?.throwIfAborted();
    if (String(context.modelType) !== "@jpisgeek/documentation-evidence") {
      throw Error(
        "Attach the infrastructure guide to documentation-evidence only",
      );
    }
    if (context.executionStatus !== "succeeded") {
      throw Error(
        "Evidence capture failed; do not present a previous snapshot as this run",
      );
    }
    const handle = context.dataHandles.find((handle) =>
      handle.specName === "snapshot" && handle.name === "snapshot"
    );
    if (
      !handle || !Number.isSafeInteger(handle.version) || handle.version < 1
    ) {
      throw Error(
        "No versioned documentation evidence snapshot in this execution",
      );
    }
    let snapshot;
    try {
      const stored = await readStored(
        context.dataRepository,
        context.modelType,
        context.modelId,
        handle.name,
        handle.version,
        context.signal,
      );
      context.signal?.throwIfAborted();
      if (!stored?.bytes) throw Error("Snapshot unavailable");
      snapshot = Snapshot.parse(parseEvidence(stored.bytes));
    } catch {
      context.signal?.throwIfAborted();
      throw Error(
        "Documentation evidence snapshot unavailable or invalid; no guide produced",
      );
    }
    // The snapshot has no embedded free-text Markdown or sections.
    context.signal?.throwIfAborted();
    const markdown = render(snapshot.observations);
    return {
      markdown,
      json: {
        collectedAt: snapshot.collectedAt,
        observations: snapshot.observations,
        sections: [{ key: "infrastructure-observations", markdown }],
      },
    };
  },
};
