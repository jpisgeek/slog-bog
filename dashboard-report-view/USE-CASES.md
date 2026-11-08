# Useful reports from real Swamp workflows

## Swamp Quest: the proving flow

The original flow runs lightweight machine checks on a Swamp Server schedule,
observes public Swamp Quest leaderboard standings, and writes a versioned state
report plus HTML. Its report shows:

- machine health observations, freshness and exceptions;
- public all-time, weekly, daily and streak rankings, preserving unavailable or
  unranked values;
- schedule state, recent workflow outcomes, run IDs and data versions;
- local filters and a **Refresh live status** button that runs a named Swamp
  workflow and reloads the resulting snapshot;
- a bounded season window, after which the scheduled Quest activity pauses.

This is a useful reason to run checks repeatedly, rather than dummy runs to
inflate activity. Public score changes are observations, not proof that a
particular workflow earned points. The reusable view has no account name,
leaderboard scraper, season cutoff or household setup baked in. Supply those
observations from the user's own authorized workflows.

A Quest report can use sections such as `Machine checks`, `Leaderboard`,
`Schedules` and `Recent runs`. Rows preserve the observed value, state and an
explicit evidence label. For example, `Weekly rank` may have a null value and
`unknown` state until the first successful observation; zero must never stand in
for missing data.

## Fleet monitoring: the everyday use

A Swamp Server orchestrates system-check behaviors for machines such as
`mac-mini` and `mac-studio`. Producers report memory pressure, available disk,
service state or other checks within the operator's authorized scope. Swamp
retains observations and workflow run evidence. A fleet report groups rows by
machine and shows fresh, stale, unknown and attention states explicitly.

The refresh workflow gathers only the configured checks, then publishes a new
snapshot. The browser filters existing observations and invokes that named
workflow; it has no remote shell or provider credentials. System-check
collectors are separate behaviors; this package provides their reusable report
view. Operators choose targets, thresholds, cadence, retention and optional
runtime inference.

## Other useful compositions

- Maintenance readiness: checks before a rebuild, with unresolved prerequisites
  and run evidence visible in one view.
- Workflow outcome report: failed or suspended runs and the last verified
  result, without showing a failure as a fresh success.
- Backup verification: age and evidence of verification, with absent proof shown
  as unknown rather than assumed successful.
- Service overview: explicit observed state and stale observations across a
  small fleet, using the same filters and controlled refresh action.

The common feature is an evidence-backed view over Swamp data, not a new
monitoring daemon. Native dashboard registration and isolated report embedding
are proposed upstream; the included handler is an adapter for an existing host.

## Future reuse

A future replacement Swamp Server can reuse this report contract with its own
validated check behaviors and workflows. That future deployment, worker routing,
migration and startup configuration are outside this release. The current
proving example remains the running Swamp Quest flow.
