# PAP v0.1 — Phase 2a Independent Verifier (Rust)

Implementation documentation for the Phase 2a experiment `PAP-RS-P2A-003`
(brief: `AGENT_BRIEF.md`; normative RFC:
`docs/architecture/portable-assurance-package-rfc.md`; snapshot: `snapshot/`).

| Document | Contents |
|---|---|
| [`implementation-report.md`](implementation-report.md) | Implementation report with actual executed results, verification-record identity, experiment record, and completion criteria |
| [`traceability.md`](traceability.md) | Requirement-to-implementation traceability matrix (normative RFC sections → code/tests) |
| [`corpus-applicability.md`](corpus-applicability.md) | F01–F61 corpus applicability matrix for Phase 2a |
| [`ambiguity-limitations.md`](ambiguity-limitations.md) | Ambiguity and limitation register (spec ambiguities, interpretation decisions, platform notes, deferred requirements) |
| [`security-boundary.md`](security-boundary.md) | Security boundary documentation and hostile-input posture |

## Quick start (reproduce)

```bash
# toolchain: Rust 1.99.1, pure std (no third-party dependencies)
cargo build
cargo test                       # 84 tests: units + E-vectors + safety + corpus + shapes
scripts/checker-identity-selfcheck.sh   # two-way closure self-check
# single package verification
./target/debug/pap verify pap/fixtures/pap-v0.1/base \
    --trust-policy pap/fixtures/pap-v0.1/trust-policy/unsigned-valid.json \
    --format json --now 2026-11-02T00:00:00Z
```

## What is implemented (Phase 2a scope)

- Package directory reader with the full §4.3 safety contract (path grammar,
  symlinks/non-regular rejection, duplicate/case-collide rules, declared /
  undeclared / missing-file semantics, scan completeness, resource limits,
  root confinement, `PACKAGE` symlink resolution).
- Strict manifest parsing and closed schema validation with the normative
  diagnostic mapping (§4.10, §5.3.1, §4.3.1, §13.8, Appendix A) including the
  strict I-JSON subset (BOM/UTF-8/trailing-data/duplicate-key/integer-only).
- RFC 8785 JCS canonicalization over the I-JSON subset, validated against
  Appendix E.1/E.9 vectors.
- Digest primitives with exact domains, framing, LF normalization and binary
  fallback (§5.2; E.2/E.5/E.6 vectors); package, artifact, raw source,
  per-input file and normalized-input *set* identities, claim digests.
- Checker identity of the verifier itself (§5.8, brief §4.4.1) computed at
  build time from the source closure, tested against E.3 and by a two-way
  self-check of the closure rules.
- Appendix C report construction for every supported execution path — with
  report-shape conformance tests — including the verification-record identity
  (§5.9; E.4/E.10 mutation vectors).
- Verdict precedence, coverage counters, exit-code mapping and the minimal
  `pap verify PACKAGE` execution interface (§7.4, §7.5, §9.7 subset).

## What is deliberately NOT implemented (later phases)

- The three §8 checks: `pap.check.digest-integrity/1` (recomputation as a
  *check record*), `pap.check.source-quote/1`, `pap.check.relation-consistency/1`.
  Digest *primitives and identities* are implemented, per the brief §5
  boundary note; the checks are Phase 2b. Their absence is reported as
  `UNSUPPORTED` (§7.2/§13.1 rule) for any declared check, so no false `PASS`
  is possible.
- Claim-file content validation (Appendix D) — claim *digests only*.
- Producer-claim comparison block (`producerClaims`).
- Human-review evidence evaluation (§6.7) — reported `UNKNOWN` when required.
- DSSE/Ed25519 signature verification, signer trust, in-toto (§11).
- The full public CLI contract: `inspect`, `explain`, text/JSON stream
  behaviour beyond `--format json|text` on `verify` (§9; the implemented
  surface is documented in `implementation-report.md` §6).
