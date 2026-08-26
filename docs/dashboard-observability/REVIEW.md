# Dashboard and Observability Extension Family — REVIEW

## Status

- **Phase:** REVIEW complete — awaiting explicit SHIP approval
- **Policy:** deterministic per-package gates plus one external release review
- **Independent model review:** required once per release set; reviewer-agnostic
- **SHIP:** not authorized
- **Blockers:** none before the explicit SHIP gate
- **Last updated:** 2026-08-25

## Review policy

The release gate is evidence, not the number of model calls. Every package must
pass formatting, tests, Swamp quality, generated README consistency, the generic
and private identifier scans, and a registry dry run. The final release record
binds that evidence to each package's exact publication content hash.

One capable independent external model reviews the final release set across
package boundaries, credential and transport handling, untrusted input, accuracy
and coverage semantics, documentation, and all prior findings. The reviewer need
not be Fable. The review is required once for the release set, not once per
package. If one provider's quota is unavailable, another independent reviewer
may complete the same review without restarting completed deterministic work.
Additional model review is reserved for unresolved material questions.

Changing a published byte invalidates the recorded hash and requires rerunning
that package's deterministic gates plus any relevant risk checks.

## Preserved partial independent-review evidence

| Package                 | Exact hash                                                         | Result                             |
| ----------------------- | ------------------------------------------------------------------ | ---------------------------------- |
| `dashboard`             | `4454be456c313ce959848bae22cb9e949f4396939ffe9859c9b7f6879d646e1e` | FAIL; findings require disposition |
| `dashboard-homelab`     | `a61498145a3c423744bd35bd796ac7f5df21d028bdf65dfca9656f55c17467fe` | PASS with findings                 |
| `dashboard-lmstudio`    | `8e5466284c93ec1cea7fedbbc6ee81eff27254e2a0173e8fbaf69206ace18e3a` | PASS with findings                 |
| `dashboard-swamp`       | `20bd5b91460ba3200a5f298d84628b937b6e7c589414bf90245f5ee200b28fb1` | FAIL; findings require disposition |
| `openai-usage`          | `ba0392b90503886d2622c2c7552d87be9a108b5d27b19b63499421aa65416dfd` | PASS with findings                 |
| `anthropic-usage`       | `85c4d1a216a2d8a3bc771eb877e6f556846c808d41ddd1798dc4a5fe7a94a85d` | PASS with findings                 |
| `subscription-metadata` | `15e31f1802630fe0ec1f3b14719e70ced92c4c7998ced2139685661fde4f2fae` | PASS with findings                 |
| `lmstudio`              | `5976c35e7d59fae5f39a483dbd9ca37fc6db793f2c84e047d67d79a9870695a7` | incomplete; no verdict             |
| `dashboard-compose`     | `457fcfc7d4e6d31ca927f0264f7efb4c0eda4129f5e87239a7bee8d52b40195f` | incomplete; no verdict             |

Incomplete `.tmp` output is not a verdict. Existing PASS and FAIL artifacts are
retained as useful evidence. A PASS does not waive its findings, and the revised
policy does not erase the two FAIL results.

## Remediation and current exact hashes

The prior blocking findings and substantive accuracy/security findings were
remediated. The full repository suite passes 223 tests. Deno lint and
formatting, generated README consistency, all nine Swamp manifest format checks,
and all nine Swamp quality checks pass; every package scored 12/12. Generic
identifier scans found zero hits across every exact publication payload.

| Package                 | Version        | Current exact hash                                                 |
| ----------------------- | -------------- | ------------------------------------------------------------------ |
| `dashboard`             | `2026.08.25.2` | `80f209c57a3dfbf24701a46d4d165c5cead271b9c2dfd325a6decc09e582f2fd` |
| `dashboard-homelab`     | `2026.08.25.2` | `de6f14ca95ed0a6f7d4b5d483f3d81928e9d7a5a67f191b57b85329d219d1191` |
| `dashboard-lmstudio`    | `2026.08.25.3` | `f2aa88cd2eb56bd22740a2d84b1c712f1321670ce72925e6719db051113160a1` |
| `dashboard-swamp`       | `2026.08.25.2` | `b7b4a260d21f6b009a007a9ee0363b53e024a031fb10e310585080a847bf223c` |
| `openai-usage`          | `2026.08.25.2` | `0c60e0cfb7e5ca3b69b60ee64006d1c3d23dfb30dc0f3deddec016d2d97c269c` |
| `anthropic-usage`       | `2026.08.25.2` | `8e9aad96fa0c8b6642662999fba915ce91ba9853dc1c3f3506b39628fff195d0` |
| `subscription-metadata` | `2026.08.25.2` | `1d48764cb79725ef43f31b058c65210ef5ceb6f3f4df6b8e57de20ef04c12567` |
| `lmstudio`              | `2026.08.25.1` | `c913e4bae39b18f65c2912ecb3b55f4b87cfd10af42f343f902c26070591bbe0` |
| `dashboard-compose`     | `2026.08.25.1` | `457fcfc7d4e6d31ca927f0264f7efb4c0eda4129f5e87239a7bee8d52b40195f` |

The recovered external private denylist scan passed against all nine exact
publication payloads with zero hits. Its private entries and storage location
are not copied into this public repository.

## Daybreak release review disposition

The authorized Codex Daybreak Blue reviewer returned **FAIL** for the release
set before the hashes above were produced. No reviewer edits were allowed or
made. The release remains blocked until the same reviewer checks the remediated
bytes.

| Finding                                                                                            | Disposition                                                                                                                                                                              |
| -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Healthy state could coexist with stale or incomplete required evidence                             | Fixed in the canonical contract and every published contract copy; adversarial contract and renderer tests added                                                                         |
| Colon-concatenated exception identities could collide                                              | Replaced with length-prefixed tuple encoding; collision regression added                                                                                                                 |
| Swamp server URLs could carry query or fragment credentials in argv                                | Query and fragment are rejected and tested                                                                                                                                               |
| Malformed OpenAI buckets could silently become complete zero totals                                | Malformed buckets and results now invalidate the page; regression added                                                                                                                  |
| Later-page OpenAI and Anthropic authorization/capability failures became generic partial state     | Underlying state and critical authorization exceptions are preserved and tested                                                                                                          |
| LM Studio accepted malformed inventory or vector data and invented missing reasoning usage as zero | Model inventory and embeddings validate strictly, parser errors are sanitized, and absent reasoning usage remains unknown                                                                |
| Homelab summary reconciliation omitted health counters                                             | Netdata and TrueNAS health, alert, certificate, and disk counters are reconciled                                                                                                         |
| Subscription values could inject Markdown or HTML                                                  | Operator-controlled title, summary, provider, and plan text is escaped and tested                                                                                                        |
| `npm:zod@4` was considered an unpinned dependency                                                  | Not changed: repository Swamp security guidance identifies this exact specifier as the runtime-provided platform exception; patch pinning would violate the supported packaging contract |

The first remediation re-review also returned **FAIL** with four additional
blockers. All four were returned to BUILD and remediated:

| Re-review finding                                                                                                            | Disposition                                                                                                                    |
| ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Synthetic renderer coverage IDs could still collide, and duplicate bundle IDs were accepted                                  | Every synthetic ID now uses tuple encoding; duplicate bundle IDs fail visibly; both cases have regressions                     |
| Swamp history and stored-report adapters silently filtered malformed entries and defaulted missing diagnostic counts to zero | Containers and records are validated, rejected counts force partial coverage, and every absent diagnostic count is unavailable |
| A malformed LM Studio completion choice could become healthy with exact usage                                                | The completion envelope, choice, message, finish reason, and internally consistent usage are required before success           |
| LM Studio base URLs accepted queries and fragments                                                                           | Both public model schemas reject userinfo, queries, and fragments; regressions cover both models                               |

The second remediation re-review returned **FAIL** on four deeper edge cases.
They were also returned to BUILD and remediated:

| Second re-review finding                                            | Disposition                                                                                                                                             |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Synthetic IDs could collide between the input and coverage families | Every renderer-generated ID now begins with an explicit renderer family path; cross-family and three-duplicate regressions prove distinct identities    |
| Object-shaped malformed Swamp records were accepted                 | History records require a non-empty documented status field; report records require a documented identifier or status; every schema failure is rejected |
| An empty LM Studio finish reason could become successful            | Completion success requires a supported non-empty finish reason; the empty-value regression fails closed                                                |
| Bare `?` and `#` delimiters survived URL normalization              | Raw delimiters are rejected before URL parsing; both bare cases are tested on both public model schemas                                                 |

The third remediation re-review found one final whitespace-status edge in stored
reports. Status fields are now trimmed and empty values are skipped, so an
identified report without a real status remains partial and unavailable. The
exact regression is included in the 221-test suite.

The final narrow Daybreak re-review returned **PASS**. The reviewer
independently confirmed the final `dashboard-swamp` hash, the whitespace-status
behavior and regression, and found no source blockers or narrow regressions. No
reviewer changed workspace files. The release may advance to operator gates, but
PASS is not publication authorization.

All nine registry dry runs completed with `status: dry_run`; nothing was
published. The published LM Studio baseline is `2026.08.23.1`, and its endpoint
and probe argument schemas are unchanged. Both now declare no-op migrations to
the registry-required `2026.08.25.1`. The new daemon model correctly has no
prior-instance migration. The remaining dry-run notices are documented review
cache, shared-test-file, intentional `Deno.Command` for `lms ps`, and
first-publication warnings rather than push failures.

The final migration-only Daybreak re-review also returned **PASS** and
independently confirmed the `lmstudio` hash, aligned versions, pure endpoint and
probe migrations, new-daemon treatment, and migration regressions. No source
blockers remain.

## Next action

Stop at explicit SHIP approval. Do not publish, push, or deploy before approval.
