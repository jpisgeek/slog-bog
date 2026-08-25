# Subscription Metadata — Task 11 Evidence

## Decision

Task 11 adds the independent `@jpisgeek/subscription-metadata` package. A live
registry and local-type search found no generic subscription-plan metadata
model; the results were unrelated infrastructure subscription resources.

The package follows Swamp's `design/models.md` and `design/reports.md`: a
no-network model persists typed operator declarations, and a method-scope report
normalizes them into a dedicated informational bundle section.

## Contract

The model accepts optional plan name, billing cadence, price in currency minor
units, currency, renewal window, seats, declared limits, and a stable source
reference. Every snapshot carries `operator-config` provenance and capture time.
Source references reject credentials, query parameters, and fragments.

Accuracy rules are enforced in schemas and normalization:

- missing optional facts remain absent;
- explicit numeric zero remains an observed zero;
- price and currency must be declared together;
- declared limits named as remaining, available, left, per-token price, or token
  price are rejected;
- renewal windows must be ordered;
- the bundle identifies this data as `subscription-metadata`, sets
  `apiMetering: false`, and declares that remaining quota and per-token cost
  were not derived;
- recurring subscription price uses a `subscription-price-*` identifier and
  never becomes hosted API usage cost.

No personal plan dashboard is scraped. No network, process, environment, vault,
or provider API is accessed.

## Verification evidence

Eleven focused Deno tests cover canonical bundle conformance, unknown fields,
explicit zeroes, price/currency pairing, forbidden derived limits, ordered
renewal windows, informational missing state, and separation from API usage
cost.

The package passed formatting, type checking, linting, generated README checks,
Swamp manifest formatting, extension quality, the generic identifier scan, and
`swamp extension push --dry-run`. Exact-hash adversarial review remains deferred
to REVIEW. Nothing was installed or published.
