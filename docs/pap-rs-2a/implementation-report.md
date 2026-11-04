# Phase 2a implementation report — PAP v0.1 independent verifier (Rust)

**Experiment:** `PAP-RS-P2A-003`
**Brief:** `AGENT_BRIEF.md` (Phase 2a — Minimal Standalone Verifier)
**Normative source:** `docs/architecture/portable-assurance-package-rfc.md`
(accepted PAP v0.1 RFC, maintainer decision 2026-11-02, `docs/maintainer-decision.md`)
**Implementation language:** Rust (brief §0: `IMPLEMENTATION_LANGUAGE = rust`)
**Status:** complete for the Phase 2a scope; Phase 2b/2c/2d items deliberately
not implemented (see §7 scope separation).

---

## 1. Executive summary

The Phase 2a functionality described by RFC §14 step 2a is implemented
natively in Rust with **zero third-party dependencies**, verified by an
independent test suite of **84 automated tests** (`cargo test`: units,
Appendix E vectors, parsing/schema, package safety, checker identity, the
published Phase 2a corpus comparison set, and report-shape conformance) plus
a two-way checker-identity closure self-check script.

* All applicable Appendix E vectors pass (E.1 canonical bytes byte-for-byte,
  E.2 digests, E.3 both values, E.5, E.6 both vector families, E.4 baseline +
  E.10 mutation vector, E.9 all cases).
* The published Phase 2a comparison set passes 55/61: all 19 `full`-profile
  cases agree on exit code, verdict, applicable diagnostic codes, the
  constrained `integrity.package`/`integrity.artifacts` statuses and the
  exact `packageIdentity`; all 36 `identityOnly` cases agree on the exact
  `packageIdentity`; 6 cases are later-phase and are not claimed.
* The verifier's own identity record (§5.8, brief §4.4.1) is computed from
  the build-time source closure and reproduces the Appendix E.3 vector
  construction on independent inputs; the two-way closure self-check passes
  in both directions with before/after digests recorded.

## 2. Input bundle integrity record

Recorded before implementation began (brief §3).

| Item | Value |
|---|---|
| Input bundle identifier | Frozen snapshot in `snapshot/` (bundle v2) |
| Source repository / commit | `agent-federation/contract-builder` @ `c21907890ceb45c5d3c4d72a0a736102b984815a` |
| Bundle manifest | `snapshot/manifest.json` |
| SHA-256 of the bundle manifest | `0855f5663ddce3b74a8d55045fc2147ae20d3c50e571e3a682e352f0158db8a9` |
| SHA-256 verification result | **all 436 files verified OK** (`sha256sum -c snapshot/SHA256SUMS`); manifest self-hash matches the experiment metadata |
| Failed checks | none |

Re-established after implementation (final re-run): 436/436 OK,
manifest SHA-256 unchanged. The snapshot was never modified
(`git status` clean on the snapshot paths; verification command recorded in §9).

## 3. Toolchain and environment

| Item | Value |
|---|---|
| OS / architecture | Debian GNU/Linux 13 (trixie), kernel 6.12.101+deb13-cloud-amd64, x86_64 |
| Rust compiler | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` |
| Cargo | `cargo 1.99.1 (5f94df478 2026-08-27)` |
| Rust edition | 2021 |
| Third-party dependencies | **none** (pure `std`; see §5) |

## 4. Dependency and toolchain inventory

| Dependency | Version | Affects | Conformance evidence |
|---|---|---|---|
| Rust standard library | rustc 1.99.1 | filesystem (`OpenOptions`, `symlink_metadata`), `io` streams, `SystemTime` | platform notes in `security-boundary.md` |
| Inline SHA-256 (`src/sha256.rs`) | in-tree | hashing | NIST vectors + all Appendix E digests |
| Inline I-JSON parser (`src/json.rs`) | in-tree | parsing | E.9, F21/F29/F50/F51 |
| Inline JCS canonicalizer (`src/jcs.rs`) | in-tree | canonicalization | E.1 byte-for-byte, E.9 |
| Inline RFC 3339 (`src/rfc3339.rs`) | in-tree | timestamps | unit vectors |

No third-party crate is fetched, vendored or linked; `Cargo.lock` contains
only the root package with no checksum entries, so the checker-closure
pinned-dependency record list is empty by construction (brief §4.4.1).

## 5. Verifier identity record (brief §4.4.1, §10)

| Item | Value |
|---|---|
| `verifier.id` / every check-record `checker.id` | `pap.verifier.rust` (brief: `pap.verifier.<language>`) |
| `verifier.version` | `0.1.0` |
| `implementationDigest` | `sha256:e5d6ab21a1ea94d17e0ed60f1873ca622db03b2fac70ebda0f172f24c4c1454d` |
| `checkerIdentity` = `identities.checkerIdentity` = `verifier.checkerIdentities[0]` | `sha256:262a5114b0cf79040d5f7891f07769f42f884b212e017f19da5a8d2a06d09ce0` |
| closure files (21, repo-relative POSIX, ascending UTF-8 order) | `Cargo.lock`, `Cargo.toml`, `build.rs`, `src/checker.rs`, `src/cli.rs`, `src/diag.rs`, `src/digest.rs`, `src/jcs.rs`, `src/json.rs`, `src/lib.rs`, `src/limits.rs`, `src/main.rs`, `src/manifest.rs`, `src/normalize.rs`, `src/pathrule.rs`, `src/pkg.rs`, `src/policy.rs`, `src/report.rs`, `src/rfc3339.rs`, `src/sha256.rs`, `src/verdict.rs` |
| excluded from closure | tests/, fixtures, docs, generated files, `.cargo/` sandbox state |
| pinned dependency records | none (no third-party dependencies; `Cargo.lock` has no checksummed packages) |
| computation time | build time (`build.rs` hashes the closure from checkout bytes; `cargo:rerun-if-changed` watches exactly the closure files) |
| E.3 reproduction | both published values (`73f738b733b177c0…`, `15a0b0149dc95f7b…`) reproduced from the vector's closure inputs by independent tests (`tests/vectors.rs::e3_*`, `tests/checker_identity.rs::e3_*`) |

### Closure self-check (both directions, with digests)

Recorded from `scripts/checker-identity-selfcheck.sh` (runs on a copy of the
checkout; working tree untouched):

| Direction | Mutation | Digest before | Digest after | Result |
|---|---|---|---|---|
| (a) included file | one byte appended to closure member `src/jcs.rs`; rebuild; recompute | `sha256:77fa91431d079c0cb39e08dc22707ef2292aa87d7e5e1d84ab72700a3cdfeb1c` | `sha256:fe1f021e2c2537d03dfa0f9c7b10b90aeb0fc75f6c8c10aa834e87f48e87d1e4` | **changed (MUST change): PASS** |
| (b) outside the closure | two extra lines to a non-closure file (`README-selfcheck.md`); rebuild; recompute | `sha256:fe1f021e2c2537d03dfa0f9c7b10b90aeb0fc75f6c8c10aa834e87f48e87d1e4` | `sha256:fe1f021e2c2537d03dfa0f9c7b10b90aeb0fc75f6c8c10aa834e87f48e87d1e4` | **unchanged (MUST NOT change): PASS** |

## 6. Execution interface (temporary, documented per brief §4.7)

```text
pap verify PACKAGE [--trust-policy FILE] [--format text|json] [--now RFC3339]
```

- Only the `verify` command is implemented (Phase 2c owns `inspect`/`explain`
  and the remaining §9 surface); anything else is `pap.cli.usage`, exit 64.
- `--flag value` and `--flag=value` are accepted; repeated single-valued
  options, unknown options/values, missing values, extra positionals and an
  empty `PACKAGE` are usage errors with no report (F-family compatible).
- `pap` alone prints the synopsis to stderr and exits 64.
- Output: `--format json` writes exactly one JCS document + one LF on stdout
  (verified byte-level by the corpus runner); `--format text` writes a minimal
  §9.6-style rendering (not compared; full layout is Phase 2c).
- Exit codes (§9.7 exact mapping): PASS 0, FAIL 1, INCOMPLETE/NOT_EVALUATED 2,
  UNTRUSTED 3, UNSUPPORTED 4, usage 64, internal 70, I/O 74. Exit 0 iff
  verdict PASS. Stderr is empty for exit 0–4 runs (corpus-verified).

## 7. Scope discipline (implemented vs not)

| Category | Items |
|---|---|
| **Implemented and tested** | package reading with §4.3 safety (grammar, symlinks, duplicates, missing/undeclared, scan completeness, limits, root confinement, `PACKAGE` handling); strict I-JSON parse; closed Appendix A schema + §4.4.3 cross-field rules; §4.9 unknown fields/extensions/requiredFeatures/compat; RFC 8785 JCS + I-JSON; §5 digest primitives, payloads, identities, claim digests; checker identity (§5.8) incl. E.3 + two-way self-check; Appendix C report construction + §5.9 record identity (E.4/E.10); §7.4 verdict precedence; §7.5 coverage counters; §9.7 exit codes; minimal verify interface; report-shape validation |
| **Implemented, not directly tested** | `--format text` rendering beyond the compared corpus rows (exists; §9.6-subset rendering; not normative in 2a); internal scan budgets reaching the boundary (logic implemented; the hostile deep-tree unit uses a shallow tree) |
| **Not implemented because outside Phase 2a** | three §8 checks (2b); claim content validation (2b); producer-claim comparison block (2b); human-review evaluation (2c/2d); DSSE/PAE/Ed25519/signer trust/in-toto (2d); `inspect`/`explain` and the full CLI contract incl. published document schemas (2c); archive transport (deferred by D1) |
| **Blocked by specification ambiguity** | none blocking; interpretation decisions and 5 open questions recorded in `ambiguity-limitations.md` (all leave the compared corpus fields unaffected) |
| **Not evaluated** | cross-implementation interoperability; Gate 3; Tier A/B conformance claims — explicitly NOT claimed (§12 completion criteria) |

## 8. Test results (actual)

### 8.1 Test suite — `cargo test` (code commit `c8b8c16`, §10)

| Suite | Tests | Result |
|---|---|---|
| lib units (`src/*` embedded) | 31 | ok, 0 failed |
| `tests/checker_identity.rs` | 4 | ok, 0 failed |
| `tests/corpus.rs` (Phase 2a corpus runner) | 3 | ok, 0 failed |
| `tests/manifest_tests.rs` (parsing/schema, brief §7.2) | 14 | ok, 0 failed |
| `tests/report_shape.rs` (Appendix C shape conformance) | 3 | ok, 0 failed |
| `tests/safety.rs` (brief §7.3, full binary in temp packages) | 20 | ok, 0 failed |
| `tests/vectors.rs` (Appendix E normative vectors) | 9 | ok, 0 failed |
| bin/doc targets | 0 | — |
| **Total** | **84** | **all ok** |

### 8.2 Clean-checkout reproduction (brief §10)

A fresh `git clone` of code commit `c8b8c16`, then `cargo test`:

```text
running 31 tests  →  ok. 31 passed; 0 failed
running 4 tests   →  ok. 4 passed; 0 failed
running 3 tests   →  ok. 3 passed; 0 failed
running 14 tests  →  ok. 14 passed; 0 failed
running 3 tests   →  ok. 3 passed; 0 failed
running 20 tests  →  ok. 20 passed; 0 failed
running 9 tests   →  ok. 9 passed; 0 failed
```

84 passed, 0 failed. The clean-checkout binary reproduces
`implementationDigest sha256:77fa91431d079c0b…` exactly (the identity is content-derived) and the F01 normative `packageIdentity`.

### 8.3 Appendix E vector results

| Vector family | Cases | Result |
|---|---|---|
| E.1 canonical manifest bytes + `packageIdentity` | byte-for-byte transcription + digest | PASS |
| E.2 payload digests (artifact 80 B, source 127 B, quote span [24,76), per-input, set, 3 claims) | 8 | PASS |
| E.3 checker identity (`implementationDigest`, `checkerIdentity`) | 2 | PASS |
| E.4 record identity baseline | 1 | PASS |
| E.5 LF normalization (raw hex, normalized hex, per-file, set) | 4 | PASS |
| E.6 domain separation (`hello` × 3 domains) | 3 | PASS |
| E.6 framing ambiguity (`("ab","c")` vs `("a","bc")`) | 2 | PASS |
| E.9 UTF-16 key order (36 bytes + SHA), escaping (28 bytes + SHA), number rules | 6 | PASS |
| E.10 record identity mutations (incl. presentation-exclusion non-mutations) | 7 | PASS |
| E.7 (DSSE PAE) | — | not in the Phase 2a applicable set (PAE is Phase 2d material; not claimed here) |

### 8.4 Phase 2a corpus comparison — 55/61 compared, all passing

Command per case: the normative `cases.json` `command` with the verifier
binary, executed inside the case directory. Result table (condensed; the
harness asserts everything listed in §2):

| Outcome class | Count | Detail |
|---|---|---|
| `full` profile | 19 | F07,F08,F09,F10,F21,F22,F23,F24,F26,F29,F30,F33,F35,F50,F51,F53,F54,F57,F60 — exit code, verdict, applicable code subset, constrained integrity statuses, exact identity: all matched; each ran twice with byte-identical stdout (fixed `--now`) |
| `identityOnly` profile | 36 | F01–F06, F11–F20, F27,F28,F31,F32,F34,F36,F40,F43–F49,F52,F55,F56,F58,F59,F61 — exact `packageIdentity` matched in all |
| excluded (later phase) | 6 | F25, F37, F38, F39, F41, F42 — not claimed |

Verdict outcomes observed in Phase 2a are honest: e.g. F01 reports
`UNSUPPORTED`/exit 4 because no §8 check is implemented yet — no false
`PASS` is possible (`identities` match the normative literals):
`F01 packageIdentity = sha256:77a8d1d0882428efdfa5bfc38faa1ff7ba772aff9373b9e6135a8bb744119020` ✓.

Spot-check (F22-path-traversal, exact corpus command):
exit 1, verdict `FAIL`, codes `pap.package.path-invalid` ⊇ expected subset,
`integrity.package=FAIL`, `integrity.artifacts=FAIL`,
`packageIdentity = sha256:c59d3b6d584009d51e0f6bca3e8a132844e6e1d3ae03c6e99591a8c33151b104` (normative literal) ✓.

## 9. Reproduction commands (exact)

```bash
# 0) integrity of the frozen bundle (run from the repository root)
sha256sum -c snapshot/SHA256SUMS          # 436 files: all OK
sha256sum snapshot/manifest.json          # 0855f5663dd…db8a9

# 1) build + full test suite
cargo build
cargo test                                # 84 tests, 0 failures (§8.1)

# 2) checker-identity two-way self-check
scripts/checker-identity-selfcheck.sh     # PASS both directions (§5)

# 3) one verification (canonical example, F01 = base)
./target/debug/pap verify pap/fixtures/pap-v0.1/base \
    --trust-policy pap/fixtures/pap-v0.1/trust-policy/unsigned-valid.json \
    --format json --now 2026-11-02T00:00:00Z | python3 -m json.tool | head -5

# 4) run any corpus case exactly as published, e.g. F22
(cd pap/fixtures/pap-v0.1/F22-path-traversal && \
 $PWD/../../../target/debug/pap verify . --trust-policy \
 ../trust-policy/unsigned-valid.json --format json --now 2026-11-02T00:00:00Z)

# 5) clean checkout reproduction
git clone . /tmp/clean-checkout && (cd /tmp/clean-checkout && cargo test)
```

Actual outputs: §8.1–§8.4 above; the E-vector values are printed by
`cargo test --test vectors -- --nocapture` (not required as evidence: the
assertions are the evidence).

## 10. Commit and cleanliness

| Item | Value |
|---|---|
| Starting commit | `d84e4c3bd98a398a9deea3793d9cebefa381a7a4` (HEAD at experiment start) |
| Code commit (implementation + independent tests) | `c8b8c16` |
| Report commit | recorded on this file's own commit (the working tree is clean both at the code commit and after adding the docs) |
| Working-tree cleanliness | `git status --short` empty at both recorded commits, apart from the `.cargo/` sandbox state (CARGO_HOME; untracked and ignored) |

The implementation is committed; the final state is reproducible from the
clean checkout per §8.2.

## 11. §12 completion-criteria mapping

| Criterion (brief §12) | State |
|---|---|
| Phase 2a RFC §14 functionality implemented | yes (§7 “implemented and tested”) |
| Applicable Appendix E vectors pass | yes (§8.3) |
| §12 parsing/digest/safety cases agree on the Phase 2a comparison scope | yes — 55/61 with the published profile (§8.4); 6 documented as later-phase (not claimed) |
| Report and exit-code foundations follow the normative contract | yes (report-shape tests; §9.7 mapping) |
| No required unevaluated scope can yield false `PASS` | by construction: unimplemented checks are `UNSUPPORTED`; unevaluable dimensions block PASS; `coverage.full` false whenever any scope was skipped; corpus-confirmed |
| Independent tests reproducible | yes (clean-checkout run per §8.2) |
| Unresolved issues explicitly recorded | yes — `ambiguity-limitations.md` (4 interpretation decisions with RFC anchors + platform limits + 5 open questions) |
| Frozen input bundle unchanged | yes — re-verified (§2) |
| Committed, final state reproducible | yes (§10) |

Completion of this phase does **not** establish: Phase 2b/2c/2d completion,
full PAP v0.1 conformance, Tier A or Tier B conformance, Gate 3 completion,
interoperability with another verifier, or semantic truth of any package.
