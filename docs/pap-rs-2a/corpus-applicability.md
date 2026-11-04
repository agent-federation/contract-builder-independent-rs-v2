# Phase 2a corpus applicability matrix

Authoritative sources: the normative corpus `pap/fixtures/pap-v0.1/cases.json`
(RFC §12) and the published Phase 2a comparison scope
`pap/fixtures/pap-v0.1/cases-phase2a.json` (experiment metadata; `cases.json`
stays normative). The comparison profiles are:

- **full** — required Phase 2a acceptance: compare exit code, verdict, the
  applicable diagnostic-code subset (`pap.check.*` codes are exempt in 2a),
  the corpus-constrained `integrity.package`/`integrity.artifacts` statuses,
  and the exact `packageIdentity`.
- **identityOnly** — compare only the exact `packageIdentity` literal.
- **excluded** — later-phase case; not claimed as Phase 2a acceptance.

Legend for "applicable 2a behavior": which Phase 2a surface the case exercises.

| Case | Profile | Applicable 2a behavior | Tested now | Deferred to |
|---|---|---|---|---|
| F01-unchanged | identityOnly | manifest parse + JCS + identity computation | identity | verdict/dimensions (needs §8 checks, Phase 2b) |
| F02-artifact-byte | identityOnly | artifact digest recomputation (mismatch detection exists at identity level) | identity | `DI` check record (2b) |
| F03-source-byte | identityOnly | raw source digest recomputation | identity | `DI` (2b) |
| F04-input-byte | identityOnly | per-input + set digest recomputation, claim compare | identity | `DI` (2b) |
| F05-quote-span | identityOnly | capture: span check is 2b | identity | `SQ` (2b) |
| F06-relation-edge | identityOnly | capture: relation check is 2b | identity | `RC` (2b) |
| F07-unknown-check | full | unknown check id ⇒ `UNSUPPORTED` (§7.2, §13.1), verdict precedence, `integrity.*` PASS | exit/verdict/codes/dims/identity | check-record detail (2b) |
| F08-critical-extension | full | unknown critical extension ⇒ `UNSUPPORTED` | all compared fields | — |
| F09-newer-check | full | newer `(id,version)` ⇒ `UNSUPPORTED` verdict | all compared fields | check records (2b) |
| F10-newer-minor | full | newer minor ⇒ `UNSUPPORTED`, checks `NOT_EVALUATED` | all compared fields | — |
| F11-untrusted-role | identityOnly | signature/trust evaluation is 2d | identity | envelope semantics (2d) |
| F12-invalid-signature | identityOnly | signature verification is 2d | identity | 2d |
| F13-trusted-signature | identityOnly | signature verification is 2d | identity | 2d |
| F14-no-policy | identityOnly | policy absent ⇒ `policy.state: ABSENT` | identity | trust dims (2d/2c) |
| F15-stale-policy | identityOnly | freshness window | identity | trust dims (2d/2c) |
| F16-unknown-signer | identityOnly | envelope handling is 2d | identity | 2d |
| F17-package-not-allowed | identityOnly | signer authorization is 2d | identity | 2d |
| F18-two-envelopes | identityOnly | envelope handling is 2d | identity | 2d |
| F19-required-signature-absent | identityOnly | mode-required signature semantics | identity | 2d |
| F20-producer-mismatch | identityOnly | producer-claim comparison is 2b | identity | `producerClaims` (2b) |
| F21-truncated-manifest | full | invalid JSON ⇒ `pap.package.manifest-json`, identity null, `integrity.package: FAIL`, artifacts `NOT_EVALUATED` | all compared fields | — |
| F22-path-traversal | full | path grammar ⇒ `pap.package.path-invalid`, `integrity.*: FAIL` | all compared fields | — |
| F23-symlink | full | symlink rejection ⇒ `pap.package.symlink` | all compared fields | — |
| F24-case-duplicate | full | case-fold duplicate ⇒ `pap.package.path-duplicate` | all compared fields | — |
| F25-archive | excluded | `PACKAGE` as non-directory ⇒ usage error exit 64 — implemented incidentally, owned by 2c CLI | — | 2c owns the CLI surface case |
| F26-missing-artifact | full | missing declared file ⇒ `pap.package.declared-file-missing` | all compared fields | `pap.check.not-evaluated` check row detail (2b) |
| F27-referenced-source | identityOnly | referenced-only source model | identity | `sources.*` dimension assertions (2b, SQ-dependent) |
| F28-review-missing | identityOnly | human review is a later phase | identity | review evaluation (2c/2d) |
| F29-duplicate-key | full | duplicate JSON key ⇒ `pap.package.duplicate-key` | all compared fields | — |
| F30-unknown-field | full | unknown core field ⇒ `pap.package.unknown-field` | all compared fields | — |
| F31-undeclared-file | identityOnly | undeclared-file scan (`pap.package.undeclared-file`) | identity | warning-code assertion is inside the full profile only in 2a scope |
| F32-optional-extension | identityOnly | ignored extension reporting | identity | same as F31 note |
| F33-required-feature | full | unsupported requiredFeature ⇒ `UNSUPPORTED` | all compared fields | — |
| F34-noncanonical | identityOnly | canonicalization over the JSON value, not the bytes | identity | verdict assertions (2b) |
| F35-manifest-limit | full | manifest byte limit ⇒ `pap.package.limit-exceeded`, identity null, FAIL | all compared fields | — |
| F36-determinism | identityOnly | byte-identical reruns under fixed `--now` (tested in the corpus harness for every full case) | identity+rerun determinism | — |
| F37-inspect-usage | excluded | `inspect` is 2c (usage errors apply to the 2a interface too) | — | 2c |
| F38-explain-usage | excluded | `explain` is 2c | — | 2c |
| F39-explain-unknown | excluded | `explain --check` is 2c | — | 2c |
| F40-producer-free | identityOnly | no producer runtime exists (pure-binary verifier); network never opened | identity | sentinel-shim environment is the 2c/3 corpus harness |
| F41-invalid-policy | excluded | fail-closed policy validation is 2c (the 2a minimal subset already rejects this fixture) | — | 2c |
| F42-explain-positive | excluded | `explain` is 2c/2d | — | 2c/2d |
| F43-profile-mismatch | identityOnly | profile recognition compared against pins | identity | recognition assertions (2d/2c) |
| F44-no-provenance | identityOnly | absent claim file semantics | identity | `SQ` NOT_EVALUATED row (2b) |
| F45-no-relations | identityOnly | same | identity | `RC` row (2b) |
| F46-inverse-not-reciprocal | identityOnly | relation check is 2b | identity | 2b |
| F47-policy-boundary-expiry | identityOnly | closed policy window (`expiresAt` inclusive) | identity | trust dims (2c/2d) |
| F48-policy-boundary-issued | identityOnly | `issuedAt` inclusive | identity | trust dims (2c/2d) |
| F49-policy-one-second-after | identityOnly | one second outside ⇒ `STALE` | identity | trust dims (2c/2d) |
| F50-bom | full | BOM rejection ⇒ `pap.package.manifest-json` | all compared fields | — |
| F51-exponent-number | full | non-integer number token ⇒ `pap.package.manifest-json` | all compared fields | — |
| F52-lowered-limits | identityOnly | fileBytes lowering, per-file cap, `effectiveLimits` | identity | dim/verdict assertions (2b) |
| F53-check-version | full | `checkSpecs` version suffix invariant ⇒ `pap.package.schema` | all compared fields | — |
| F54-all-optional | full | empty required set ⇒ `INCOMPLETE` + `pap.package.empty-check-specs` | all compared fields | — |
| F55-review-approved | identityOnly | human review not evaluated in 2a | identity | review evaluation (2c/2d) |
| F56-optional-mixed | identityOnly | envelope handling is 2d | identity | 2d |
| F57-major-version | full | different major ⇒ `pap.compat.version-unsupported` | all compared fields | — |
| F58-undeclared-source | identityOnly | claim cross-field source reference (§4.7.1) | identity | claim validation, `pap.package.claim-invalid` (2b) |
| F59-relation-duplicate | identityOnly | relation-name uniqueness (§8.6) | identity | 2b |
| F60-missing-manifest | full | missing manifest ⇒ `pap.package.io`, identity null, FAIL | all compared fields | — |
| F61-relations-only-lowered | identityOnly | limit stops payload reading even when the dimension is not required | identity | dim/verdict assertions (2b) |

Executed Phase 2a comparison: **55/61 cases** (19 full-profile cases compared
on all their compared fields, 36 identityOnly cases compared on the exact
identity literal), all passing; 6 cases are excluded as later-phase and are
documented with their owning phase above. The full-profile cases are run
twice by the corpus harness; stdout bytes are identical both times when
`--now` is fixed (verified per case).
