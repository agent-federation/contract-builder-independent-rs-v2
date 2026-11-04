# Requirement-to-implementation traceability matrix (Phase 2a)

Normative source: `docs/architecture/portable-assurance-package-rfc.md`
(accepted PAP v0.1 RFC), its Appendices A–J, and the accepted maintainer
decision (`docs/maintainer-decision.md`). Implementation: pure Rust, std only.
Test entry points: `cargo test` —
`tests/vectors.rs`, `tests/manifest_tests.rs`, `tests/safety.rs`,
`tests/checker_identity.rs`, `tests/corpus.rs`, `tests/report_shape.rs`, and
the `src/*` unit modules.

Status legend: **IT** = implemented and tested; **IN** = implemented but not
directly tested (indirectly covered); **NP** = not implemented because outside
Phase 2a; **BA** = blocked by a recorded specification ambiguity (see
`ambiguity-limitations.md`); **NE** = not evaluated (no claim).

| Requirement (RFC section) | Trace anchor | Status | Evidence (test / command) |
|---|---|---|---|
| Package root recognition; `assurance-package.json` read (§4.2) | `src/pkg.rs::verify` | IT | `tests/safety.rs::absent_manifest_is_package_io`; corpus F60 |
| `PACKAGE` symlink resolution once; not-found 74; not-a-directory 64 (§4.3.2, §9.7) | `src/pkg.rs`, `src/cli.rs` | IT | `tests/safety.rs::package_symlink_to_directory_is_resolved_once`, `::package_argument_handling` |
| Path grammar `[A-Za-z0-9._-]+`, segment/path limits, ASCII (§4.3.1) | `src/pathrule.rs` | IT | unit tests in `src/pathrule.rs`; corpus F22 |
| Path grammar before schema; wrong-root ⇒ `pap.package.path-invalid` (§4.3.1) | `src/manifest.rs` (stage 2) | IT | corpus F22; `tests/manifest_tests.rs::absolute_and_invalid_paths_rejected` via runner |
| Duplicate and ASCII case-folded duplicate paths over one global set (§4.3.1/§4.3.3) | `src/manifest.rs` | IT | corpus F24; `tests/safety.rs::case_colliding_paths_fail_integrity` |
| Symlink and non-regular rejection; open w/o following (§4.3.2, T3) | `src/pkg.rs::open_payload` | IT* | `tests/safety.rs::symlinked_*`, `::directory_at_declared_path_rejected` *O_NOFOLLOW only on Linux; lstat per component elsewhere (see limitations) |
| Declared / undeclared / missing semantics (§4.3.3) | `src/pkg.rs` scan + reads | IT | corpus F26/F31; `tests/safety.rs::missing_declared_file_fails`, `::undeclared_files_reported_never_opened` |
| Scan completeness ⇒ `pap.package.undeclared-scan-incomplete`, coverage violations (§4.3.3, §7.5) | `src/pkg.rs::scan_tree` | IT | `tests/safety.rs::undeclared_scan_incomplete_on_permission_denied` |
| Manifest self-reference rule (§4.3.3) | `src/manifest.rs` stage 2 | IN | defence-in-depth path; unreachable through the Appendix A pattern (noted in limitations) |
| Resource limit defaults and enforcement points (§4.3.4, §10.5) | `src/limits.rs`, `src/pkg.rs` | IT | corpus F35/F52 (identity), `tests/safety.rs::manifest_byte_limit_fails_closed`, `::lowered_file_bytes_limit_is_not_evaluated` |
| Fixed read order + byte-budget determinism (§4.3.4) | `src/pkg.rs::read_payloads` | IT | F52 identity; order is structural in the reader; per-class stop mapping unit-covered through F52-like safety test |
| Policy may only lower limits; `effectiveLimits` reporting (§6.3.2, §7.7) | `src/policy.rs`, `src/report.rs` | IT | `tests/safety.rs::lowered_file_bytes_limit_is_not_evaluated`; `tests/report_shape.rs::effective_limits_present_only_when_lowered` |
| Strict I-JSON: UTF-8, BOM, trailing data, duplicate keys, integer-only tokens, depth/string limits (§4.10, §5.3.1) | `src/json.rs` | IT | `src/json.rs` units; corpus F21/F29/F50/F51 |
| Closed schema (Appendix A): required fields, types, enums, patterns, lengths (§4.4) | `src/manifest.rs` stage 3 | IT | `tests/manifest_tests.rs`, corpus F30/F53 |
| Unknown core field rejection (§4.9) | `src/manifest.rs::check_unknown` | IT | corpus F30 |
| Cross-field invariants: unique ids, `checkSpecs` version suffix (§4.4.3) | `src/manifest.rs` stage 4 | IT | corpus F53; `tests/manifest_tests.rs::duplicate_ids_rejected`, `::cross_field_check_version_invariant_rejected` |
| Extensions parsing: critical/ignored handling (§4.8, §4.9) | `src/manifest.rs::extensions_schema`, `src/report.rs` | IT | corpus F08/F32; `tests/manifest_tests.rs::extension_and_required_feature_parsing` |
| requiredFeatures parsing (§4.9) | `src/manifest.rs` | IT | corpus F33; `tests/manifest_tests.rs::extension_and_required_feature_parsing` |
| Compatibility: minor-newer / version-unsupported (§4.9, §15.1) | `src/manifest.rs` stage 5 | IT | corpus F10/F57; `tests/manifest_tests.rs::version_incompatibilities` |
| JCS canonicalization incl. UTF-16 key order, escaping, numbers (§5.3.1) | `src/jcs.rs` | IT | E.1 bytes byte-for-byte + `tests/vectors.rs` E.9 |
| H(domain || 0x00 || bytes) domain separation (§5.2) | `src/digest.rs::h` | IT | E.6 vectors |
| Framing records u32be (§5.2) | `src/digest.rs::push_record` | IT | E.6 framing-ambiguity vectors |
| SHA-256 | `src/sha256.rs` | IT | NIST vectors + all E digests |
| Raw-source digest / LF normalization + binary fallback (§5.5, §5.6, §4.5.1) | `src/normalize.rs` | IT | E.5 vectors; `tests/safety.rs::normalized_input_digest_mismatch_*` |
| Per-input and set digests of packaged inputs (§5.2, §5.6) | `src/pkg.rs` (input classification + record framing) | IT | E.2/E.5 set vectors; unit input digest equality |
| Claim digests over raw bytes (§5.2 `pap.claims.v1`) | `src/pkg.rs` claims branch | IT | E.2 literals; `tests/safety.rs::claim_digest_mismatch_*` |
| `packageIdentity` (§5.3) | `src/pkg.rs` + `src/jcs.rs` | IT | E.1 vector; 55 corpus identity comparisons |
| Artifact digest + byte-count compare at read level (§5.4, §7.3) | `src/pkg.rs` | IT | E.2; `tests/safety.rs` mismatch cases |
| Extension closure identity as a declared value (§5.7) | `src/report.rs` | IT | report field mapping; `identities.extensionClosureDigest` = declared `profile.closureDigest` or null |
| Checker identity of the verifier (§5.8, brief §4.4.1) | `build.rs`, `src/checker.rs` | IT | E.3 vector; `tests/checker_identity.rs`; two-way self-check script |
| Verification-record identity + §5.9 exclusions (§5.9) | `src/report.rs::identity_form` | IT | E.4 baseline + E.10 mutation vectors |
| No self-reference digests; envelope outside manifest (§5.10) | format-level | IN | structural: no self-digest field exists in the emitted report or read model |
| Timestamps: records not freshness (§5.11) | `src/rfc3339.rs`, report fields | IT | `src/rfc3339.rs` units; policy freshness via `--now` |
| Report construction (Appendix C; §7.7) | `src/report.rs` | IT | `tests/report_shape.rs` (shape/enum/conditional basis/effectiveLimits) |
| Verdict precedence (§7.4) | `src/verdict.rs::compute` | IT | corpus full cases F07/F08/F09/F10/F21–F30/F33/F35/F53–F57, F60/F54; dedicated precedence composition in every corpus verdict |
| Coverage counters and `coverage.full` (§7.5) | `src/verdict.rs` | IN | counters asserted through corpus cases; exact `full` semantics exercised with unevaluated checks (2a always non-full) |
| Exit-code mapping (§9.7) | `src/verdict.rs::Verdict::exit_code`, `src/main.rs` | IT | corpus exit codes; safety `usage/74` tests |
| `pap check <PACKAGE>` — the minimal verify interface (§9 subset, brief §4.7) | `src/cli.rs`, `src/main.rs` | IT | corpus commands; usage errors |
| Stream discipline: one JCS + LF, empty stderr on report exits (§9.6 subset) | `src/main.rs` | IT | corpus runner assertions (per case) |
| `--now` RFC 3339 profile incl. fraction/offset/leap-second rules (§9.8) | `src/rfc3339.rs`, `src/cli.rs` | IT | `src/rfc3339.rs` units |
| Policy minimal parse: version, id, window, mode, pins, required sets, lower-only limits (§6.3 subset) | `src/policy.rs` | IT | policy fixtures exercised by every corpus case with a policy; invalid policy rejected structurally |
| Policy freshness closed window (§6.4) | `src/policy.rs` | IT | corpus F47/F48/F49 (identity) + window math unit-covered via `rfc3339` ordering |
| Checker/profile recognition vs pins (§6.6) | `src/report.rs` | IT | F43 (identity); recognition logic unit-covered by the code path exercised with pinned + empty pin lists in corpus variants |
| Human review model (§6.7) | — | NP | review evidence evaluation is Phase 2c/2d; reported `UNKNOWN` with `pap.trust.review-required` (never PASS) |
| Signatures / DSSE / Ed25519 (§11) | — | NP | envelopes discovered only; validity `NOT_EVALUATED` + `pap.signature.unsupported-format` |
| in-toto mapping (§11.3) | — | NP | outside both conformance tiers |
| The three §8 checks with records and witnesses (§8) | — | NP | Phase 2b; unimplemented checks are `UNSUPPORTED` (§7.2/§13.1) |
| Claim-file content validation (Appendix D) | — | NP | claim digests verified only; content parsing Phase 2b |
| Producer-claim comparison block (§7.6) | — | NP | Phase 2b |
| `inspect` / `explain` (§9.4–§9.5) | — | NP | Phase 2c |
| Text rendering beyond the minimal verify surface (§9.6) | — | NP | Phase 2c |
| Archive transport (§10.7) | — | NP | Deferred by D1 |
| Offline / no network / no package-code execution (§10, §9.10) | implementation-wide | IT | pure std; no socket/subprocess APIs used; `cargo build` has no dependencies to fetch |
| No wall-clock budget ambiguity (§10.5) | scan budgets only | BA/IN | internal scan budgets recorded in the limitation register |
