import {
  createReportHandler,
  model,
  renderReport,
  SnapshotSchema,
} from "./dashboard_report_view.ts";
import { runInNewContext } from "node:vm";
function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}
const snapshot = {
  schemaVersion: 1 as const,
  title: "Fleet health",
  observedAt: "2026-11-08T12:00:00.000Z",
  sections: [{
    title: "mac-mini",
    rows: [{
      label: "Memory",
      value: 0,
      state: "healthy" as const,
      evidence: "run-example / summary v2",
    }, { label: "Disk", value: null, state: "stale" as const }],
  }],
};
function setup(
  overrides: Partial<Parameters<typeof createReportHandler>[0]> = {},
) {
  let runs = 0;
  const handler = createReportHandler({
    reportUrl: "https://reports.example.com/fleet",
    authorize: async () => true,
    readSnapshot: async () => snapshot,
    refresh: async () => {
      runs++;
      return { workflowRunId: "run-example" };
    },
    ...overrides,
  });
  const request = (path = "/fleet/refresh", init: RequestInit = {}) =>
    new Request("https://reports.example.com" + path, {
      method: "POST",
      headers: {
        Origin: "https://reports.example.com",
        "X-Report-Action": "refresh",
      },
      ...init,
    });
  return { handler, request, runs: () => runs };
}
Deno.test("canonical state rejects wrong version, infinity, invalid time and unknown fields", () => {
  for (
    const value of [
      { ...snapshot, schemaVersion: 2 },
      { ...snapshot, observedAt: "yesterday" },
      { ...snapshot, token: "forbidden" },
      {
        ...snapshot,
        sections: [{
          title: "Fleet",
          rows: [{ label: "Load", value: Infinity, state: "healthy" }],
        }],
      },
    ]
  ) assert(!SnapshotSchema.safeParse(value).success);
});
Deno.test("escaping prevents data from adding markup or scripts; unavailable differs from zero", () => {
  const html = renderReport({
    ...snapshot,
    title: "</script><img src=x onerror=alert(1)>",
    sections: [{
      title: "<script>",
      rows: [
        {
          label: "<svg/onload=alert(1)>",
          value: "<iframe>",
          state: "unknown",
          evidence: '" & <script>',
        },
        { label: "Zero", value: 0, state: "healthy" },
        { label: "Missing", value: null, state: "unknown" },
      ],
    }],
  });
  assert(!html.includes("<img"));
  assert(!html.includes("<iframe>"));
  assert(html.includes("&lt;svg"));
  assert(html.includes("<td>0</td>"));
  assert(html.includes("Unavailable"));
  assert((html.match(/<script>/g) ?? []).length === 1);
});
Deno.test("render method persists snapshot and versioned HTML using Swamp writer", async () => {
  const writes: unknown[] = [];
  const result = await model.methods.render.execute({}, {
    globalArgs: { snapshot },
    logger: { info: () => {} },
    writeResource: async (kind, name, value) => {
      writes.push({ kind, name, value });
      return "state-handle";
    },
    createFileWriter: (kind, name) => ({
      writeText: async (html) => {
        writes.push({ kind, name, html });
        return "html-handle";
      },
    }),
  });
  assert(
    JSON.stringify(result.dataHandles) === '["state-handle","html-handle"]',
  );
  assert(writes.length === 2);
  assert((writes[1] as { html: string }).html.startsWith("<!doctype html>"));
});
Deno.test("host serves real HTML with CSP and no-store; successful refresh returns evidence", async () => {
  const { handler, request, runs } = setup();
  const page = await handler(request("/fleet", { method: "GET" }));
  assert(page.status === 200);
  assert(page.headers.get("content-type")?.startsWith("text/html"));
  assert(page.headers.get("cache-control") === "no-store");
  assert(
    page.headers.get("content-security-policy")?.includes(
      "frame-ancestors 'none'",
    ),
  );
  assert((await page.text()).includes("Fleet health"));
  const response = await handler(request());
  assert(response.status === 200);
  assert((await response.json()).workflowRunId === "run-example");
  assert(runs() === 1);
});
Deno.test("read and refresh authorization denials never read or run", async () => {
  let reads = 0;
  const { handler, request, runs } = setup({
    authorize: async () => false,
    readSnapshot: async () => {
      reads++;
      return snapshot;
    },
  });
  assert((await handler(request("/fleet", { method: "GET" }))).status === 403);
  assert((await handler(request())).status === 403);
  assert(reads === 0 && runs() === 0);
});
Deno.test("refuses cross-origin, missing custom header, query, bodies, arbitrary routes/methods", async () => {
  const { handler, request, runs } = setup();
  for (
    const req of [
      request("/fleet/refresh", {
        headers: {
          Origin: "https://other.example.com",
          "X-Report-Action": "refresh",
        },
      }),
      request("/fleet/refresh", {
        headers: { Origin: "https://reports.example.com" },
      }),
      request("/fleet/refresh?workflow=other"),
      request("/fleet/refresh", { body: "{}" }),
      new Request("https://other.example.com/fleet/refresh", {
        method: "POST",
      }),
      request("/fleet/run-shell"),
      request("/fleet/refresh", { method: "GET" }),
    ]
  ) assert((await handler(req)).status >= 400);
  assert(runs() === 0);
});
Deno.test("concurrent refresh is refused and failure releases lock without leaking details", async () => {
  let release!: () => void;
  const pending = new Promise<void>((r) => release = r);
  const { handler, request } = setup({
    refresh: async () => {
      await pending;
      throw new Error("private diagnostic");
    },
  });
  const first = handler(request());
  await new Promise((r) => setTimeout(r, 0));
  assert((await handler(request())).status === 409);
  release();
  const failed = await first;
  assert(failed.status === 503);
  assert(!(await failed.text()).includes("private diagnostic"));
  assert((await handler(request())).status === 503);
});
Deno.test("invalid snapshot and missing workflow run evidence fail visibly", async () => {
  const a = setup({ readSnapshot: async () => ({}) });
  assert(
    (await a.handler(a.request("/fleet", { method: "GET" }))).status === 503,
  );
  const b = setup({ refresh: async () => ({ workflowRunId: "" }) });
  assert((await b.handler(b.request())).status === 503);
});
Deno.test("host rejects credential-bearing and non-HTTP canonical URL configurations", () => {
  for (
    const reportUrl of [
      "file:/fleet",
      "http://reports.example.com/fleet",
      "https://reports.example.com/fleet/",
      "https://reports.example.com/fleet?q=1",
      "https://name:pass@reports.example.com/fleet",
    ]
  ) {
    let failed = false;
    try {
      setup({ reportUrl });
    } catch {
      failed = true;
    }
    assert(failed);
  }
});
Deno.test("filters and refresh controls handle success, failure and offline snapshots", async () => {
  const script =
    renderReport(snapshot).split("<script>")[1].split("</script>")[0];
  for (const mode of ["success", "failure", "offline"]) {
    const listeners: Record<string, Record<string, () => unknown>> = {};
    const elements: Record<
      string,
      {
        value: string;
        disabled: boolean;
        textContent: string;
        addEventListener: (event: string, fn: () => unknown) => void;
      }
    > = {};
    for (const id of ["search", "state", "refresh", "feedback"]) {
      elements[id] = {
        value: id === "state" ? "all" : "",
        disabled: false,
        textContent: "",
        addEventListener: (event, fn) => {
          (listeners[id] ??= {})[event] = fn;
        },
      };
    }
    const rows = [{
      textContent: "Memory healthy",
      dataset: { state: "healthy" },
      hidden: false,
    }, {
      textContent: "Disk stale",
      dataset: { state: "stale" },
      hidden: false,
    }];
    let reloads = 0, calls = 0;
    runInNewContext(script, {
      document: {
        getElementById: (id: string) => elements[id],
        querySelectorAll: () => rows,
      },
      location: {
        protocol: mode === "offline" ? "file:" : "https:",
        href: "https://reports.example.com/fleet",
        reload: () => reloads++,
      },
      URL,
      fetch: async (url: URL, init: RequestInit) => {
        calls++;
        assert(url.pathname === "/fleet/refresh");
        assert(init.method === "POST");
        return { ok: mode === "success", json: async () => ({ ok: true }) };
      },
      Error,
    });
    elements.search.value = "disk";
    listeners.search.input();
    assert(rows[0].hidden && !rows[1].hidden);
    elements.search.value = "";
    elements.state.value = "healthy";
    listeners.state.change();
    assert(!rows[0].hidden && rows[1].hidden);
    await listeners.refresh.click();
    if (mode === "success") assert(reloads === 1 && calls === 1);
    else {
      assert(reloads === 0 && !elements.refresh.disabled);
      assert(elements.feedback.textContent.includes("unavailable"));
      if (mode === "offline") assert(calls === 0);
    }
  }
});
