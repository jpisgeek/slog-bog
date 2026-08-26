# OpenAI Organization Usage — Task 9 Evidence

## Decision

Task 9 retains the local `@jpisgeek/openai-usage` package. The registry was
searched again before implementation. `@dougschaefer/openai-usage` remains a
useful domain reference, but its registry contract does not expose enough
runtime detail to satisfy the approved compatibility profile. It was not
installed and is not a dependency.

The package uses a Swamp model for the external API observation and a
method-scope report for normalization, following the model/report split routed
by the Swamp architecture guide and `design/models.md` plus `design/reports.md`.

## Official API boundary

The collector uses only these documented OpenAI organization endpoints:

- `GET /v1/organization/usage/completions`;
- `GET /v1/organization/costs`.

Both receive an explicit inclusive `start_time`, exclusive `end_time`, daily
buckets, and independent cursor pagination. Completion usage is grouped by
project and model. Costs are grouped by project and line item. The Admin API key
is a sensitive global argument intended for a vault expression.

This scope deliberately excludes other OpenAI usage endpoint families. Usage and
billed cost remain separate because OpenAI documents that usage may not
reconcile perfectly with costs and recommends the Costs endpoint for financial
accounting. Subscription plans and remaining quota are not inferred.

## Accuracy and failure behavior

- Each endpoint has its own complete, partial, or unavailable status.
- A later failed page retains earlier records but marks the dimension partial.
- Authorization, rate limiting, timeout, unreachable service, malformed JSON,
  invalid records, and general HTTP failure are distinct classifications.
- A missing usage or currency dimension becomes an unavailable metric without a
  numeric value. Missing never becomes zero.
- Cost totals remain separated by lowercase ISO-4217 currency. The adapter does
  not combine unlike currencies.
- Caller cancellation aborts the operation and writes no snapshot.
- Response bodies and error text are discarded. The API key appears only in the
  Authorization header, and requests are fixed to the official HTTPS API origin.

## Verification evidence

The focused Deno suite contains 14 passing tests. It covers independent cursor
pagination, exact token/request/currency totals, later-page rate limiting,
partial preservation, authorization, malformed records, invalid JSON,
cancellation, requested coverage windows, grouping dimensions, bundle
conformance, missing snapshots, and unknown currency.

The package also passed:

- Deno formatting, type checking, and linting;
- generated README freshness;
- Swamp manifest formatting;
- Swamp extension quality at 100 percent of client-earnable points;
- the generic public identifier scan with zero findings;
- `swamp extension push --dry-run`.

The dry run reported only the expected pre-publication conditions: no previous
registry version and no adversarial review for this new exact content hash. That
review remains intentionally deferred to the lifecycle REVIEW gate. No package
was published, pushed, installed, or run against a real organization.

## Official references

- [OpenAI Usage API reference](https://platform.openai.com/docs/api-reference/usage)
- [OpenAI Admin API keys reference](https://platform.openai.com/docs/api-reference/admin-api-keys)
