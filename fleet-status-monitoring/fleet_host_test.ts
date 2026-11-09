import { createFleetHandler, type FleetHost } from "./fleet_host.ts";
import { renderFleet } from "./fleet_view.ts";
import { fixtureState } from "./test_fixtures.ts";
const check = (ok: unknown) => {
  if (!ok) throw Error("Assertion failed");
};
const base = "https://example.com/reports/fleet";
const req = (options: RequestInit = {}) =>
  new Request(base + "/refresh", {
    method: "POST",
    headers: { origin: "https://example.com", "X-Fleet-Action": "refresh" },
    ...options,
  });
const host = (extra: Partial<FleetHost> = {}): FleetHost => ({
  reportUrl: base,
  authorize: async () => true,
  readState: async () => fixtureState(),
  refresh: async () => ({
    workflowRunId: "00000000-0000-4000-8000-000000000002",
  }),
  ...extra,
});
Deno.test("report navigation and refresh path are configurable; Quest is absent by default", () => {
  const state = fixtureState(),
    html = renderFleet(state, {
      reportPath: "/reports/fleet",
      dashboardPath: "/console",
    });
  check(html.includes('href="/console"') && !html.includes('href="/quest"'));
  check(html.includes("/reports/fleet/refresh"));
  check(
    renderFleet(state, { questPath: "/reports/quest" }).includes(
      'href="/reports/quest"',
    ),
  );
});
Deno.test("same-origin route validation rejects external, encoded and ambiguous paths", () => {
  for (
    const path of [
      "//example.com",
      "https://example.com",
      "/fleet?other",
      "/../fleet",
      "/fleet/",
      "/fleet//part",
    ]
  ) {
    let failed = false;
    try {
      renderFleet(fixtureState(), { reportPath: path });
    } catch {
      failed = true;
    }
    check(failed);
  }
});
Deno.test("host serves readable HTML with security headers and authorizes every read", async () => {
  let calls = 0;
  const h = createFleetHandler(host({
    authorize: async () => {
      calls++;
      return true;
    },
  }));
  for (let i = 0; i < 2; i++) {
    const r = await h(new Request(base));
    check(
      r.status === 200 &&
        r.headers.get("content-type")?.includes("text/html") &&
        r.headers.get("content-security-policy")?.includes(
          "connect-src 'self'",
        ),
    );
    check((await r.text()).includes("Fleet Status Monitoring"));
  }
  check(calls === 2);
});
Deno.test("anonymous requests never read state or start workflows", async () => {
  let calls = 0;
  const h = createFleetHandler(
    host({
      authorize: async () => false,
      readState: async () => {
        calls++;
        return fixtureState();
      },
      refresh: async () => {
        calls++;
        throw Error();
      },
    }),
  );
  check((await h(new Request(base))).status === 403);
  check((await h(req())).status === 403 && calls === 0);
});
Deno.test("pre-aborted reads and refreshes return 503 without callbacks or unhandled rejections", async () => {
  let calls = 0;
  const controller = new AbortController();
  controller.abort();
  const h = createFleetHandler(host({
    authorize: async () => {
      calls++;
      return true;
    },
    readState: async () => {
      calls++;
      return fixtureState();
    },
    refresh: async () => {
      calls++;
      throw Error("Must not refresh");
    },
  }));
  for (
    const r of [
      new Request(base, { signal: controller.signal }),
      req({ signal: controller.signal }),
    ]
  ) check((await h(r)).status === 503);
  await new Promise((resolve) => setTimeout(resolve, 0));
  check(calls === 0);
  check((await h(new Request(base))).status === 200);
});
Deno.test("refresh rejects foreign origins, body inputs, selectors, wrong methods and missing action header", async () => {
  let calls = 0;
  const h = createFleetHandler(host({
    refresh: async () => {
      calls++;
      throw Error();
    },
  }));
  for (
    const r of [
      req({
        headers: {
          origin: "https://other.example.com",
          "X-Fleet-Action": "refresh",
        },
      }),
      req({ body: "{}" }),
      req({ headers: { origin: "https://example.com" } }),
      new Request(base + "/refresh?workflow=other", { method: "POST" }),
      new Request(base + "/refresh", { method: "GET" }),
      new Request("https://other.example.com/reports/fleet/refresh", {
        method: "POST",
      }),
    ]
  ) check((await h(r)).status >= 400);
  check(calls === 0);
});
Deno.test("accepted refresh returns only a validated workflow ID", async () => {
  let calls = 0;
  const h = createFleetHandler(host({
    refresh: async (r) => {
      check(r.body === null);
      calls++;
      return { workflowRunId: "00000000-0000-4000-8000-000000000002" };
    },
  }));
  const r = await h(req()), v = await r.json();
  check(r.status === 200 && v.ok === true && calls === 1);
});
Deno.test("overlapping refresh is refused and the lock releases after completion", async () => {
  let release!: (v: { workflowRunId: string }) => void;
  let started!: () => void;
  const ready = new Promise<void>((r) => started = r);
  const h = createFleetHandler(host({
    refresh: () => {
      started();
      return new Promise((r) => release = r);
    },
  }));
  const first = h(req());
  await ready;
  check((await h(req())).status === 409);
  release({ workflowRunId: "00000000-0000-4000-8000-000000000002" });
  check((await first).status === 200);
});
Deno.test("errors and invalid callback evidence do not leak internal details", async () => {
  for (
    const h of [
      createFleetHandler(host({
        refresh: async () => {
          throw Error("private internal detail");
        },
      })),
      createFleetHandler(
        host({ refresh: async () => ({ workflowRunId: "invalid" }) }),
      ),
    ]
  ) {
    const r = await h(req());
    check(
      r.status === 503 && !(await r.text()).includes("private internal detail"),
    );
  }
});
Deno.test("a hung callback times out and receives cancellation without starting an extra refresh", async () => {
  let signal: AbortSignal | undefined;
  const h = createFleetHandler(host({
    timeoutMs: 20,
    refresh: async (r) => {
      signal = r.signal;
      return await new Promise(() => {});
    },
  }));
  check((await h(req())).status === 503 && signal?.aborted);
  check((await h(req())).status === 409);
});
Deno.test("insecure and credential-bearing host URLs are rejected before serving", () => {
  for (
    const url of [
      "http://example.com/fleet",
      "https://user:pass@example.com/fleet",
      "https://example.com/fleet?x=1",
      "https://example.com/fleet#x",
    ]
  ) {
    let failed = false;
    try {
      createFleetHandler(host({ reportUrl: url }));
    } catch {
      failed = true;
    }
    check(failed);
  }
});

Deno.test("existing-host journey returns from dashboard and Quest, refreshes once, then reads the new snapshot", async () => {
  let current = fixtureState(), runs = 0;
  const h = createFleetHandler(host({
    view: { questPath: "/reports/quest" },
    readState: async () => current,
    refresh: async () => {
      runs++;
      current = { ...fixtureState(), sourceVersion: 2 };
      return { workflowRunId: current.workflowRunId! };
    },
  }));
  const existing = async (path: string) =>
    path === "/dashboard"
      ? new Response('<a href="/reports/fleet">Fleet</a>')
      : path === "/reports/quest"
      ? new Response('<a href="/reports/fleet">Fleet</a>')
      : await h(new Request("https://example.com" + path));
  check((await existing("/dashboard")).status === 200);
  let page = await (await existing("/reports/fleet")).text();
  check(
    page.includes('href="/dashboard"') &&
      page.includes('href="/reports/quest"'),
  );
  check((await existing("/reports/quest")).status === 200);
  check((await existing("/reports/fleet")).status === 200);
  check((await h(req())).status === 200 && runs === 1);
  page = await (await existing("/reports/fleet")).text();
  const state = JSON.parse(
    page.match(
      /<script id="fleet-state" type="application\/json">(.*?)<\/script>/s,
    )![1],
  );
  check(state.sourceVersion === 2);
});
