# Security

## Reporting

Open a private security advisory on this repository (GitHub → Security →
Report a vulnerability). Do not open a public issue for anything that could
expose a user's credentials or environment. You will get an acknowledgement
within a week.

## What these extensions touch

Every extension here talks to something that holds credentials or describes a
private environment: a monitoring agent, a NAS, a firewall, a password
manager, a local LLM server. The design rules below exist because of that.

- **Secrets are never published.** No credential, hostname, IP, vault item
  path, or local path from the author's environment appears in this repo. Every
  example uses obvious placeholders (`<your-host>`, `YOUR_API_KEY`,
  `203.0.113.0/24`).
- **Secrets are never logged or written.** Arguments that carry a secret are
  marked sensitive in their schema and do not appear in observations, error
  messages, resource attributes, or instance names.
- **Encrypted transport by default.** Any cleartext opt-out is documented as a
  risk in that extension's README, and never defaults on.
- **Strict input validation.** API responses are parsed with strict schemas;
  missing data is reported as missing, not backfilled to look healthy.

## Release gates

Nothing is published to the swamp registry until, in order:

1. `swamp extension fmt --check`, tests, `swamp extension quality`
2. `scripts/gen-readme.ts --check`: the committed README equals the one
   generated from the code
3. `scripts/scan-identifiers.sh`: mechanical scan for private identifiers
   and secret-shaped strings over the full published surface
4. A **secrets & security review** by a frontier model using the fixed prompt in
   `review/secrets-security-pass.md`. The verdict is committed under
   `reviews/<extension>/<content-hash>.md` and is valid only for that exact
   content hash. No PASS, no publish.
5. `swamp extension push --dry-run`, then explicit operator approval.

CI runs the tests and the identifier scan, and verifies a PASS verdict exists
for the current content hash of every extension. The swamp-side gates (fmt,
quality, README generation, dry-run) and the review itself run locally through
`scripts/publish.sh`, so neither the registry credentials nor a model API key
lives in CI.
