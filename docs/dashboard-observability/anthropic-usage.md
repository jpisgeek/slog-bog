# Anthropic Organization Usage — Task 10 Evidence

## Decision

Task 10 retains the local `@jpisgeek/anthropic-usage` package. The Swamp
registry was searched again before implementation. Neither `@webframp/ai-usage`
nor `@webframp/anthropic/analytics` satisfies the approved local profile, so
neither was installed or added as a dependency.

The package follows Swamp's `design/models.md` and `design/reports.md`: one
typed model observes an external Anthropic organization, and one method-scope
report normalizes the snapshot into dashboard bundle v1.

## Product and API boundaries

Anthropic documents two non-interchangeable reporting products:

- `accountKind: platform` uses the Claude Platform organization endpoints
  `/v1/organizations/usage_report/messages` and `/v1/organizations/cost_report`.
  It accepts an Admin API key or an `org:admin` OAuth bearer token. Individual
  accounts and Claude Platform on AWS do not expose these reports.
- `accountKind: enterprise` uses the Claude Enterprise Analytics endpoints
  `/v1/organizations/analytics/usage_report` and
  `/v1/organizations/analytics/cost_report`. It requires an Analytics API key
  with `read:analytics`; OAuth mode is rejected before any request.

Platform usage does not publish a request count, so that metric is unsupported
rather than zero. Enterprise usage and cost can be unavailable based on plan
eligibility. Enterprise data starts on 2026-01-01, can lag, and can be revised
for 30 days. The API's `data_refreshed_at` is retained when present.

## Accuracy and coverage

- Usage and cost paginate and fail independently.
- Authorization, unsupported capability, rate limiting, timeout, unreachable
  service, malformed response, and general HTTP failures remain distinct.
- Later-page failure preserves accepted rows but marks the dimension partial.
- Token classes remain separate: uncached input, both cache-creation TTLs, cache
  reads, and output.
- Costs remain exact provider decimal strings in reported minor units and are
  never calculated from a mutable price table.
- Enterprise grouped endpoints have a documented top-100 groups-per-bucket cap
  with no remainder row, so grouped results are visibly partial.
- Missing cost currency, request count, or resources never becomes numeric zero
  or healthy coverage.

## Verification evidence

The focused Deno suite contains 14 tests covering Platform and Enterprise
endpoint routing, Admin-key and OAuth headers, incompatible credential modes,
pagination, partial reads, rate limits, authorization, unsupported capability,
malformed dimensions, exact token and minor-unit totals, refresh timestamps,
grouped coverage caps, missing currency, and canonical bundle conformance.

The package passed formatting, type checking, linting, generated README checks,
Swamp manifest formatting, extension quality, the generic identifier scan, and
`swamp extension push --dry-run`. The dry run's missing exact-hash adversarial
review remains intentionally deferred to REVIEW. No real organization was
queried and nothing was installed or published.

## Official references

- [Anthropic Usage and Cost API](https://platform.claude.com/docs/en/manage-claude/usage-cost-api)
- [Anthropic Analytics APIs](https://platform.claude.com/docs/en/manage-claude/analytics-api)
- [Claude Enterprise token usage](https://platform.claude.com/docs/en/api/http/admin/analytics/usage/list)
- [Claude Enterprise cost](https://platform.claude.com/docs/en/api/http/admin/analytics/cost/list)
