# Host an interactive report

This package exports `renderReport(snapshot)` and `createReportHandler(host)`.
The handler is a function for an **existing** HTTP host. Importing the module
starts no listener, reads no credentials and performs no network request. Native
Swamp dashboard discovery and registration are not currently installed by this
package.

The behavior's `render` method persists the canonical `snapshot` resource and a
versioned `report.html` file. Serve the latter as `text/html`, or let the
handler render the authorized snapshot directly. A data viewer displaying source
text is not the report view.

## Adapter contract

Supply an exact operator-configured HTTPS `reportUrl` with no trailing slash,
query or fragment. GET at that URL reads a snapshot. POST at that path plus
`/refresh` runs the selected refresh. Connect the handler only to those routes
in an existing host; it does not proxy other dashboard or API routes.

```ts
import { createReportHandler } from "./dashboard_report_view.ts";

// These callbacks are supplied by your existing authenticated host.
const handler = createReportHandler({
  reportUrl: configuredReportUrl,
  authorize: authorizeCurrentCaller,
  readSnapshot: readAuthorizedSwampSnapshot,
  refresh: runConfiguredSwampRefresh,
});
```

- `authorize(request, action)` validates the caller's session and read/run
  permission for the exact data/workflow. Each call must be checked anew.
- `readSnapshot(request)` reads one authorized versioned Swamp snapshot.
  Preserve producer observation time and run/version evidence. Do not stamp old
  data as freshly collected. The renderer does not calculate freshness.
- `refresh(request)` calls Swamp Server for **one operator-selected, input-free
  workflow** under the caller's scoped authority. The request never selects a
  workflow, arguments, shell or provider. Await successful completion and the
  updated snapshot before returning `{ workflowRunId }`. A refused, failed,
  cancelled or suspended run must not be reported as a successful refresh.
- Keep credentials in the host's vault-backed session/client. The page contains
  no token. A shared service principal is a separate operator decision and must
  not widen the caller's permissions.

Refresh requires the canonical Origin and `X-Report-Action: refresh`, rejects
bodies and query strings, and allows one in-flight refresh per handler instance.
A concurrent attempt gets 409. This is not cross-process deduplication: use
Swamp's idempotency mechanism when the host can retry or has multiple instances.
GET and POST responses use `no-store`; errors reveal no internal messages. The
host still owns rate limits, body/header limits, request deadlines and audit
logs. Do not log credentials. These callbacks are the integration seam, not an
included Swamp client implementation.

The HTML response sets a restrictive CSP and denies framing. Local inline code
implements filters and refresh. A native dashboard integration should replace
this hosting policy with a supported isolated view and a narrow action bridge;
never render arbitrary user HTML in the authenticated dashboard's origin.

## Validation and limits

Tests use synthetic report rows, mocked host callbacks and a DOM harness. They
cover escaping, validation, filter and refresh behavior, read/run denial,
cross-origin and body rejection, concurrent refresh, failures and run evidence.
No provider, account or machine address is in the fixtures. This package has not
been visually tested in a real browser. The original deployment's report route
and Swamp refresh were exercised end to end; this generalized adapter requires
host-specific integration testing before deployment.
