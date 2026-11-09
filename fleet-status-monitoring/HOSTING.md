# Use an existing host

The exported `createFleetHandler` factory returns a fetch handler. It starts no
server and stores no token. Import it from `fleet_status_monitoring.ts` in the
pulled package's model sources. It uses the same caller-authorized callback
pattern as `@jpisgeek/dashboard-report-view`, with a fleet-specific state schema
and renderer.

Supply one exact HTTPS report URL, plus these callbacks:

- `authorize(request, action)` authenticates and authorizes every read or
  refresh.
- `readState(request)` reads only the caller-authorized latest versioned fleet
  state; it does not run probes.
- `refresh(request)` runs one host-configured, input-free Swamp workflow as the
  authorized caller and returns its actual `workflowRunId`.

Callbacks must honor `request.signal` and scope the backend calls. Never forward
request data as workflow inputs or allow the browser to select a model,
workflow, command, credential, or target. No callback may use unrestricted
provider access on behalf of an unprivileged caller. Mount the handler only
after implementing real authentication and these permission checks.

```ts
const handler = createFleetHandler({
  reportUrl: "https://example.com/reports/fleet",
  view: { dashboardPath: "/dashboard", questPath: null },
  authorize: authorizeFleetCaller,
  readState: readAuthorizedFleetState,
  refresh: runNamedFleetWorkflow,
});
```

The function names above are callbacks your existing host supplies, not
functions implemented by this package. The report URL determines its refresh
path. The browser sends a bodyless POST to `/reports/fleet/refresh` with
`X-Fleet-Action: refresh`. The handler rejects a foreign origin, missing action
header, request body, query selector, or wrong method. A second refresh receives
409 while the first is pending. Callback errors and invalid completion evidence
return a generic 503 without internal details. The overall deadline defaults to
90 seconds and is configurable up to two minutes. A timed-out refresh remains
locked until its callback settles; a timeout is not proof a backend run stopped.

Each HTML response disables caching, restricts connections to the same origin,
and prevents framing. Data strings are escaped and embedded JSON cannot
terminate its script element. The host should serve this report as a separate
page and keep credentials in its own server-side storage. Native Swamp dashboard
page registration remains an upstream feature proposal, not an installation
performed by this package.

`view.reportPath` controls offline snapshot refresh links; the host factory
derives it from `reportUrl` for hosted reads. `dashboardPath` and `questPath`
are optional same-origin navigation links. Quest is absent by default. Local
filters and freshness display work in a snapshot; live refresh requires the
authenticated host. No browser interaction starts a background polling workflow.

Mount only the report path and its derived refresh path. Keep other dashboard
pages, assets, APIs and WebSocket upgrades with the existing host. The fleet
handler returns 404 outside its two routes; it is not a replacement for your
host's router. Add a stable same-tab report link in the host's navigation.
Installing this package does not inject that link into native Swamp UI.

The stored `fleet-report.html` file has no response headers of its own. If you
serve it without `createFleetHandler`, authorize each viewer and apply the same
Content-Security-Policy (including `frame-ancestors 'none'`),
`Cache-Control: no-store`, content type, `nosniff` and no-referrer headers as
the handler.

Before deployment, test the whole journey: dashboard and assets, report,
optional Quest page, dashboard, report, refresh, and report reload. Verify the
refreshed snapshot has new versioned evidence and the native dashboard's
authenticated WebSocket still works. A successful report GET alone is
insufficient.
