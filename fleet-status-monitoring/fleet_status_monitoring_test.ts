import {
  assess,
  model as behavior,
  Policy,
  summarize,
} from "./fleet_status_monitoring.ts";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261105.71";
import { projectObservation } from "./fleet_contract.ts";
import { renderFleet } from "./fleet_view.ts";
import { latestResult, normalize } from "./fleet_system_stats.ts";
import {
  Observation as CollectorObservation,
  Sample,
  Target,
} from "./schema.ts";
import { Observation as ProjectedObservation } from "./fleet_contract.ts";
const check = (ok: unknown) => {
  if (!ok) throw Error("Assertion failed");
};
const now = Date.parse("2026-11-09T12:00:00.000Z");
const cycle = {
  cycleId: "00000000-0000-4000-8000-000000000001",
  startedAt: new Date(now - 2000).toISOString(),
};
const sample = Sample.parse({
  schemaVersion: 1,
  observedAt: new Date(now - 1000).toISOString(),
  family: "macos",
  osName: "macOS",
  osVersion: "test-version",
  kernel: "test-kernel",
  architecture: "arm64",
  logicalCores: 8,
  uptimeSeconds: 500,
  memoryTotalBytes: 16 * 1024 ** 3,
  memoryAvailableBytes: 8 * 1024 ** 3,
  memoryAvailableKind: "estimate",
  diskTotalBytes: 500 * 1024 ** 3,
  diskAvailableBytes: 100 * 1024 ** 3,
  load1: 2,
});
const target = Target.parse({
  id: "example-host",
  label: "Mac Air",
  group: "macos",
  kind: "physical",
  collector: "ssh",
  sourceHost: "example-host",
});
const transport = (
  stdout = JSON.stringify(sample),
  exitCode: number | null = 0,
) => ({
  version: 3,
  workflowRunId: "run-proof",
  attributes: {
    host: "example-host",
    startedAt: cycle.startedAt,
    finishedAt: new Date(now).toISOString(),
    exitCode,
    stdout,
  },
});
const row = () => normalize(target, transport(), cycle, now);
const policy = Policy.parse({});
Deno.test("collector and report projection enforce the same workflow evidence ID limit", () => {
  for (const schema of [CollectorObservation, ProjectedObservation]) {
    const evidence = schema === ProjectedObservation
      ? projectObservation(row())
      : row();
    check(
      schema.safeParse({ ...evidence, sourceWorkflowRunId: "r".repeat(100) })
        .success,
    );
    check(
      !schema.safeParse({ ...evidence, sourceWorkflowRunId: "r".repeat(101) })
        .success,
    );
    check(schema.safeParse({ ...evidence, sourceWorkflowRunId: null }).success);
  }
});
Deno.test("fresh counters normalize with source evidence and assess healthy", () => {
  const r = row();
  check(
    r.sample?.osVersion === "test-version" && r.sourceVersion === 3 &&
      r.sourceWorkflowRunId === "run-proof",
  );
  check(assess(projectObservation(r), policy, now).health === "healthy");
});
Deno.test("ranking validates attempt identity and cannot revive success after a newer malformed payload", () => {
  const good = transport();
  check(
    latestResult([
      { attributes: null },
      { attributes: { host: "example-host", startedAt: 123 } },
      good,
    ], "example-host") === good,
  );
  const malformed = {
    ...transport(),
    attributes: {
      ...transport().attributes,
      startedAt: new Date(now - 1000).toISOString(),
      stdout: 123,
    },
  };
  const latest = latestResult([good, malformed], "example-host");
  check(latest === malformed);
  const result = normalize(target, latest, cycle, now);
  check(result.state === "unavailable" && result.sample === null);
});
Deno.test("an old transport success cannot become a fresh successful scan", () => {
  const raw = transport();
  raw.attributes.startedAt = new Date(now - 5000).toISOString();
  check(normalize(target, raw, cycle, now).state === "unavailable");
});
Deno.test("failed SSH drops old counters instead of reusing them", () => {
  const r = normalize(
    target,
    transport(JSON.stringify(sample), 255),
    cycle,
    now,
  );
  check(r.state === "unreachable" && r.sample === null);
});
Deno.test("unexpected target, malformed output and future clocks fail closed", () => {
  const bad = transport();
  bad.attributes.host = "other";
  check(normalize(target, bad, cycle, now).sample === null);
  check(normalize(target, transport("not json"), cycle, now).sample === null);
  check(
    normalize(
      target,
      transport(
        JSON.stringify({
          ...sample,
          observedAt: new Date(now + 120000).toISOString(),
        }),
      ),
      cycle,
      now,
    ).sample === null,
  );
});
Deno.test("zero headroom is a real alert; null counters are unknown", () => {
  const r = row();
  r.sample = { ...sample, memoryAvailableBytes: 0 };
  check(assess(projectObservation(r), policy, now).health === "attention");
  r.sample = { ...sample, memoryAvailableBytes: null };
  check(assess(projectObservation(r), policy, now).health === "unknown");
});
Deno.test("stale observations are separated from unhealthy or healthy", () => {
  check(
    assess(projectObservation(row()), policy, now + 1900000).health === "stale",
  );
});
Deno.test("unsupported targets remain a coverage gap and are never called offline", () => {
  const r = normalize(
    { ...target, collector: "unconfigured", note: "Collector not configured" },
    undefined,
    cycle,
    now,
  );
  check(assess(projectObservation(r), policy, now).health === "unsupported");
});
Deno.test("OS coverage counts real observations independently of partial health counters", () => {
  const r = row();
  r.sample = { ...sample, memoryAvailableBytes: null };
  const state = summarize(
    {
      cycleId: cycle.cycleId,
      checkedAt: new Date(now).toISOString(),
      systems: [r],
    },
    cycle,
    policy,
    now,
    4,
    "run-proof",
  );
  check(
    state.totals.scanned === 1 && state.totals.healthy === 0 &&
      state.operatingSystems[0].count === 1,
  );
});
Deno.test("different cycles and duplicate identities reject a misleading fleet summary", () => {
  for (
    const raw of [{
      cycleId: crypto.randomUUID(),
      checkedAt: new Date(now).toISOString(),
      systems: [row()],
    }, {
      cycleId: cycle.cycleId,
      checkedAt: new Date(now).toISOString(),
      systems: [row(), row()],
    }]
  ) {
    let failed = false;
    try {
      summarize(raw, cycle, policy, now, 4, null);
    } catch {
      failed = true;
    }
    check(failed);
  }
});
Deno.test("readable HTML escapes labels and embeds exactly the canonical state", () => {
  const r = row();
  r.label = "<img src=x onerror=alert(1)>";
  const state = summarize(
    {
      cycleId: cycle.cycleId,
      checkedAt: new Date(now).toISOString(),
      systems: [r],
    },
    cycle,
    policy,
    now,
    4,
    "run-proof",
  );
  const html = renderFleet(state);
  check(!html.includes("<img src=x"));
  check(html.includes("8.0 GiB / 16.0 GiB"));
  check(
    html.includes('href="/dashboard"') && html.includes('id="filter"') &&
      html.includes("fetch(settings.refreshPath"),
  );
  const embedded = html.match(
    /<script id="fleet-state" type="application\/json">(.*?)<\/script>/s,
  )![1];
  check(JSON.stringify(JSON.parse(embedded)) === JSON.stringify(state));
});
Deno.test("capacity contract rejects free exceeding total and extra private fields", () => {
  check(
    !Sample.safeParse({
      ...sample,
      diskAvailableBytes: sample.diskTotalBytes! + 1,
    }).success,
  );
  check(!Sample.safeParse({ ...sample, username: "unwanted" }).success);
});
Deno.test("begin creates persisted scan identity rather than performing transport", async () => {
  const t = createModelTestContext({ definition: { name: "fleet-health" } });
  const result = await behavior.methods.begin.execute({}, t.context);
  const [write] = t.getWrittenResources();
  check(
    t.getWrittenResources().length === 1 && write.specName === "cycle" &&
      write.name === "cycle",
  );
  check(behavior.resources.cycle.schema.safeParse(write.data).success);
  check(
    result.dataHandles[0] === write.handle &&
      t.getLogsByLevel("info").length === 2,
  );
});

Deno.test("authentication failure is an access gap, not a claim that the system is offline", () => {
  const raw = {
    ...transport("", 255),
    attributes: {
      ...transport("", 255).attributes,
      stderr: "Permission denied (publickey).",
    },
  };
  const r = normalize(target, raw, cycle, now);
  check(
    r.state === "access-required" &&
      assess(projectObservation(r), policy, now).health === "access-required" &&
      r.sample === null,
  );
});

import vm from "node:vm";
function controlsFixture(versionMissing = false) {
  const good = row();
  if (versionMissing) good.sample = { ...sample, osVersion: null };
  const access = normalize(
    { ...target, id: "mac-studio", label: "Mac Studio" },
    {
      ...transport("", 255),
      attributes: {
        ...transport("", 255).attributes,
        stderr: "Permission denied",
      },
    },
    cycle,
    now,
  );
  const state = summarize(
    {
      cycleId: cycle.cycleId,
      checkedAt: new Date(now).toISOString(),
      systems: [good, access],
    },
    cycle,
    policy,
    now,
    5,
    "run-proof",
  );
  const html = renderFleet(state);
  const elements = new Map<string, any>();
  for (
    const id of [
      "fleet-state",
      "fleet-view-settings",
      "state-report",
      "query",
      "group",
      "status",
      "filter",
      "refresh",
      "visible-count",
      "empty",
      "scanned",
      "healthy",
      "attention",
      "gaps",
      "action-status",
    ]
  ) {
    elements.set(id, {
      value: ["group", "status"].includes(id) ? "all" : "",
      textContent: id === "fleet-state"
        ? JSON.stringify(state)
        : id === "fleet-view-settings"
        ? JSON.stringify({ refreshPath: "/fleet/refresh" })
        : "",
      hidden: false,
      disabled: false,
    });
  }
  const cards = state.systems.map((s) => ({
    dataset: {
      name: s.label.toLowerCase(),
      group: s.group,
      health: s.health,
      observed: s.sample?.observedAt ?? "",
    },
    hidden: false,
    badge: { textContent: s.health, className: s.health },
    querySelector() {
      return this.badge;
    },
  }));
  let clock = now;
  const intervals: Array<() => void> = [];
  let reloads = 0;
  const requests: unknown[] = [];
  class Clock extends Date {
    static override now() {
      return clock;
    }
  }
  const context = {
    document: {
      getElementById: (id: string) => elements.get(id),
      querySelectorAll: () => cards,
    },
    Date: Clock,
    setInterval: (fn: () => void) => intervals.push(fn),
    location: { reload: () => reloads++ },
    fetch: async (...args: unknown[]) => {
      requests.push(args);
      return { ok: true, json: async () => ({ ok: true }) };
    },
  };
  vm.runInNewContext(html.match(/<script>([\s\S]*)<\/script>/)![1], context);
  return {
    elements,
    cards,
    intervals,
    advance: (ms: number) => clock += ms,
    requests,
    reloads: () => reloads,
  };
}
Deno.test("actual filter controls narrow systems by name and access status without a request", () => {
  const f = controlsFixture();
  f.elements.get("query").value = "studio";
  f.elements.get("query").oninput();
  check(f.cards[0].hidden && !f.cards[1].hidden);
  f.elements.get("status").value = "healthy";
  f.elements.get("status").onchange();
  check(f.cards.every((c) => c.hidden) && !f.elements.get("empty").hidden);
  check(f.requests.length === 0);
});
Deno.test("actual age timer marks stale counters and updates totals without running checks", () => {
  const f = controlsFixture();
  f.advance(1900000);
  f.intervals[0]();
  check(f.cards[0].dataset.health === "stale");
  check(
    f.elements.get("healthy").textContent === 0 &&
      f.elements.get("scanned").textContent === 0,
  );
  check(f.requests.length === 0);
});
Deno.test("actual refresh button invokes one fixed input-free route and reloads after completion", async () => {
  const f = controlsFixture();
  await f.elements.get("refresh").onclick();
  check(f.requests.length === 1 && f.reloads() === 1);
  const [url, request] = f.requests[0] as [
    string,
    { method: string; body: string },
  ];
  check(
    url === "/fleet/refresh" && request.method === "POST" &&
      request.body === undefined,
  );
});

Deno.test("switching transport methods uses the latest attempt rather than unrelated resource versions", () => {
  const old = {
    ...transport(),
    name: "run-script-example-host",
    version: 99,
    attributes: {
      ...transport().attributes,
      startedAt: new Date(now - 10000).toISOString(),
    },
  };
  const fresh = { ...transport(), name: "run-exec-example-host", version: 1 };
  check(latestResult([old, fresh], "example-host") === fresh);
  check(
    normalize(target, latestResult([old, fresh], "example-host"), cycle, now)
      .state === "observed",
  );
});

Deno.test("missing memory counters cannot hide known disk exhaustion", () => {
  const r = row();
  r.sample = { ...sample, memoryAvailableBytes: null, diskAvailableBytes: 0 };
  const result = assess(projectObservation(r), policy, now);
  check(
    result.health === "attention" &&
      result.issues.includes("Low startup-data disk space"),
  );
});
Deno.test("concurrent workflow evidence cannot be attributed to the latest unrelated scan", () => {
  const r = normalize(target, transport(), {
    ...cycle,
    workflowRunId: "different-run",
  }, now);
  check(r.state === "unavailable" && r.sample === null);
});

Deno.test("an unavailable product version remains a coverage gap in both state and the actual age controls", () => {
  const f = controlsFixture(true);
  check(
    f.elements.get("scanned").textContent === 0 &&
      f.elements.get("healthy").textContent === 0,
  );
});
