# Secrets & Security Review
extension: documentation-evidence            version: 2026.10.14.1
content-hash: 5deeefdea47c0bb4aad7d9faf5cfe97669fdb5d3a70f48fc212c7ec02c248da1
reviewer: GPT-5 Codex   date: 2026-10-14
verdict: PASS

## Findings
| # | severity | file:line | what | evidence | fix |
|---|----------|-----------|------|----------|-----|
| 1 | operator-decision | README.md:9-10,102-110; documentation_evidence.ts:204-210,277-295; infrastructure_guide.ts:77-84 | Arbitrary allowlisted scalar values and labels can contain credentials, personal data, or private infrastructure identifiers. They are persisted in the snapshot and reproduced in both report formats without secret detection. This is explicitly documented and intrinsic to the generic projection feature. | `a selected scalar credential WILL be copied into the snapshot and both report formats` | Accept that one mistaken selector or label can expose sensitive data in stored snapshots and reports, or redesign the feature around schema-declared non-secret fields and reject secret-bearing labels and values. |
| 2 | fix | README.md:73; documentation_evidence.ts:46 | The documented 500-character string limit does not precisely match the implementation for non-BMP Unicode. Zod's limit counts UTF-16 code units, so 500 emoji characters exceed the implemented limit. | `strings over 500 characters` versus `z.string().max(500)` | Document the limit as 500 UTF-16 code units, as done for labels, or implement code-point/grapheme counting. |

severity: block (must fix before publish) · fix (should fix; not a publish
blocker on its own) · note (informational) · operator-decision (trade-off the
operator must rule on)
a documented, deliberate design choice whose only fix is to give up the
feature is operator-decision, not block. See "Assigning severity" above.
verdict is FAIL if any finding is block, or if input was incomplete.

## Checked and clean
Section 1 — Checked every supplied file for credentials, identities, infrastructure names and domains, IP addresses, secret-store names, local paths, hidden controls, and realistic examples; clean apart from the explicitly accepted publisher, license, and public-repository identities.

Section 2 — See finding 1; otherwise no secret-bearing arguments, credential-bearing URLs, secret logging, unredacted repository errors, or incidental secret persistence paths were found.

Section 3 — No network calls exist, so TLS, hostname, redirect, scheme, and network-timeout risks are absent; abort checks cover repository and persistence boundaries.

Section 4 — Repository content and snapshots are validated before use, selected values are restricted to bounded scalars, Markdown metacharacters and controls are encoded, no shell/SQL/path sink exists, identifiers do not control resource names, and missing or failed reads are not represented as healthy.

Section 5 — `npm:zod@4` is the sanctioned platform-provided exception; the only other import is local, and there is no dynamic import, remote execution, `eval`, or undeclared dependency.

Section 6 — See finding 2; otherwise manifest, README, model, report, version, type and method names, arguments, resource behavior, example configuration, and failure semantics agree.

Section 7 — See finding 1; the README explicitly warns that selected values may be private operational data and that credentials will be copied if selected.

## Data written by this extension
- `snapshot` resource, retained for 30 days with at most 30 versions: `collectedAt`; each observation's `label`, `version`, `observedAt`, `available`, allowlisted `values`, and `missingFields`; plus duplicated rendered content in `markdown` and `sections`. Labels and selected values may contain personal or operational identifiers such as usernames, email addresses, hostnames, IP/MAC addresses, device identifiers, or serial numbers. They can also contain credentials if misconfigured.
- `@jpisgeek/infrastructure-guide` report output: Markdown and JSON containing `collectedAt`, `observations`, and regenerated `sections`. It repeats the same potentially personal or sensitive data but does not add the configured source model type, model UUID, or data name.