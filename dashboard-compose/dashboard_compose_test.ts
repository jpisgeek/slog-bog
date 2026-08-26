import { assertEquals, assertMatch } from "jsr:@std/assert@1";
import { parse } from "jsr:@std/yaml@1.0.5";

type Json = Record<string, unknown>;

const root = new URL("./", import.meta.url);
const manifest = parse(
  await Deno.readTextFile(new URL("manifest.yaml", root)),
) as Json;
const workflowPaths = manifest.workflows as string[];

Deno.test("manifest publishes five independently selectable workflows", () => {
  assertEquals(workflowPaths, [
    "workflows/workflow-dashboard-homelab-only.yaml",
    "workflows/workflow-dashboard-swamp-only.yaml",
    "workflows/workflow-dashboard-hosted-ai-only.yaml",
    "workflows/workflow-dashboard-local-inference-only.yaml",
    "workflows/workflow-dashboard-mixed.yaml",
  ]);
  assertEquals(manifest.dependencies, []);
});

Deno.test("every workflow passes explicit normalized bundles to the renderer", async () => {
  const names = new Set<string>();
  const outputs = new Set<string>();
  for (const path of workflowPaths) {
    const workflow = parse(
      await Deno.readTextFile(new URL(path, root)),
    ) as Json;
    const jobs = workflow.jobs as Json[];
    const steps = jobs[0].steps as Json[];
    const task = steps[0].task as Json;
    const globalArgs = task.globalArgs as Json;

    names.add(String(workflow.name));
    outputs.add(String(globalArgs.outputPath));
    assertEquals(workflow.version, 1);
    assertEquals(task.type, "model_method");
    assertEquals(task.modelType, "@jpisgeek/dashboard");
    assertEquals(task.methodName, "render");
    assertMatch(String(globalArgs.bundles), /data\.latest\(.+\.attributes/);
  }
  assertEquals(names.size, workflowPaths.length);
  assertEquals(outputs.size, workflowPaths.length);
});
