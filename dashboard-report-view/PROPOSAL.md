# Native interactive report views in the Swamp dashboard

## Problem and working example

Swamp behaviors and workflows already produce useful versioned state and HTML,
but opening an HTML artifact in the dashboard data viewer can present a block of
source text rather than a readable report. A person using the dashboard from a
phone wants to inspect observations, filter them, and press a named refresh
button without handling an admin token or deploying a separate web application.

Our working Swamp Quest flow is the proving example: scheduled lightweight
system checks, public leaderboard ranks (all-time, week, day and streak), actual
schedule state, recent workflow outcomes and run/version evidence in one report.
The report includes filters and a Refresh live status button that runs an
input-free Swamp workflow and then reloads the new snapshot. It also displays a
bounded season window; the workflows pause when that window ends. Points are
observations, not attributed to individual runs without evidence.

The deployed prototype uses a small adapter beside the existing dashboard. That
proved the report and refresh flow, but native support would remove the need for
users to maintain hosting glue. No machine addresses, tokens or household
configuration are part of the proposed extension contract.

## Proposal

Add an opt-in, versioned report-view registration surface for extensions:

1. An extension declares a view ID, title, supported schema version, and the
   exact Swamp resource/report supplying its data. The dashboard discovers only
   installed declarations and data the viewer can read.
2. Render structured data through a supported component contract, or render an
   HTML artifact in an explicitly isolated view. Keep a source/download view
   available. Never execute arbitrary extension HTML in the privileged dashboard
   origin.
3. Allow local filters without starting workflows. Show producer observation
   time, stale/unavailable state, data versions and workflow run IDs.
4. Register optional named actions, such as Refresh live status, bound by the
   operator to an exact workflow with fixed, validated inputs. Buttons do not
   select arbitrary commands, shells, provider operations or workflows.
5. Use the existing authenticated session and enforce read/run grants on every
   request. A view-only user may read; a user with the exact refresh grant may
   press that button. Neither requires admin, vault-read or token-management
   access. Keep server credentials out of the page.
6. Return real workflow evidence and status, including failure, cancellation,
   refusal, suspension and approval requirements. Reload data only after the
   refreshed snapshot is available. Add duplicate-click/idempotency handling.

The package `@jpisgeek/dashboard-report-view` provides a portable renderer,
structured snapshot schema, filters, refresh button, and a fetch-handler factory
for an existing host. It starts no server, creates no schedules and does not
claim that native dashboard registration already exists. Its host callbacks must
implement authenticated Swamp reads and the one configured refresh workflow. It
is a reference for the proposed contract, not a core patch.

## Practical uses beyond Quest

- Fleet monitoring: Swamp Server runs system-check behaviors for `mac-mini`,
  `mac-studio` and other configured workers; reports show observed memory, disk,
  service state, stale checks and run evidence. Worker routing and thresholds
  belong to the operator's workflows.
- Maintenance readiness and rebuild prerequisites.
- Backup-verification evidence and missing or stale proof.
- Workflow outcome and exception reports with a controlled refresh action.

A future replacement server can reuse the same report contract. No future server
rebuild, migration or fleet enrollment is part of this feature request.

## Acceptance checks

A phone user can open a readable report, filter it locally, run an authorized
refresh and see its evidence. A read-only viewer cannot refresh. Unrelated
workflows, admin APIs and credentials remain inaccessible. Missing/stale data
never appears healthy or freshly observed. Scripts cannot escape the view's
isolation. An extension without a view keeps existing dashboard behavior.

## Duplicate and related work check

Searched the Lab for dashboard, HTML, rendered, interactive report, dashboard
extension, custom dashboard, HTML report, interactive, preview and custom view.
No matching generic registration feature was found in the returned results.
Related work reviewed:

- [#2595](https://swamp-club.com/lab/2595): shipped data/report deep links;
  addresses navigation, not reusable interactive view registration.
- [#4154](https://swamp-club.com/lab/4154) and
  [#4155](https://swamp-club.com/lab/4155): a specific agent-sessions contract
  and dashboard page; useful precedent for data-driven view discovery.
- [#4459](https://swamp-club.com/lab/4459) and
  [#4474](https://swamp-club.com/lab/4474): integration workflow actions; reuse
  those authorization/audit primitives rather than inventing another action
  permission system.

This requests a Swamp CLI/serve/dashboard capability, not a fix to this locally
owned extension and not a Swamp Club website feature.
