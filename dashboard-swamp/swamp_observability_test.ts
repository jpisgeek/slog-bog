import { assertEquals } from "jsr:@std/assert@1";
import { model, setCommandRunnerForTest } from "./swamp_observability.ts";

type Json = Record<string, unknown>;

function context(written: Json[]) {
  return {
    globalArgs: {
      repoDir: "/tmp/synthetic-swamp-repo",
      swampBinary: "swamp",
      timeoutMs: 1000,
    },
    signal: new AbortController().signal,
    writeResource: (_spec: string, _name: string, data: Json) => {
      written.push(data);
      return Promise.resolve({});
    },
  };
}

Deno.test("collector records successful documented-interface responses", async () => {
  setCommandRunnerForTest((_binary, args) => {
    const payload = args[0] === "run" && args[1] === "doctor"
      ? { totalTracked: 0, active: 0, stale: 0, reaped: 0 }
      : args[0] === "run"
      ? { runs: [] }
      : { query: "", results: [] };
    return Promise.resolve({
      success: true,
      code: 0,
      stdout: JSON.stringify(payload),
      stderr: "",
    });
  });
  const written: Json[] = [];
  try {
    await model.methods.observe.execute({}, context(written));
  } finally {
    setCommandRunnerForTest();
  }
  assertEquals(written.length, 5);
  assertEquals(
    written.slice(0, 4).every((item) => item.available === true),
    true,
  );
  assertEquals(written[4].errorKind, "unsupported");
});

Deno.test("collector classifies failures without persisting command output", async () => {
  setCommandRunnerForTest(() =>
    Promise.resolve({
      success: false,
      code: 1,
      stdout: "response included private-host.example.invalid",
      stderr: "connection refused for private-host.example.invalid",
    })
  );
  const written: Json[] = [];
  try {
    await model.methods.observe.execute({}, context(written));
  } finally {
    setCommandRunnerForTest();
  }
  assertEquals(
    written.slice(0, 4).every((item) => item.available === false),
    true,
  );
  assertEquals(
    written.slice(0, 4).every((item) => item.errorKind === "unreachable"),
    true,
  );
  assertEquals(
    written.some((item) => JSON.stringify(item).includes("private-host")),
    false,
  );
});
