# Security boundary documentation (Phase 2a)

Hostile-input posture per RFC §10 for the Phase 2a implementation.

## What the verifier does

- Reads exactly the package directory named by `PACKAGE` (resolved once), the
  fixed manifest file, declared payloads, claim digests, and the explicitly
  named trust-policy file. Nothing else.
- Never executes, imports, templates, or evaluates package content. Media
  types are advisory; payloads are opaque octets. No subprocesses, no network
  sockets, no producer tooling, no dynamic libraries from the package.
- Never reads package files outside the validated declared set: every payload
  open goes through the validated relative path, resolved per component
  beneath the resolved package root with symlink rejection at every
  component, and — on Linux — a non-following final open.
- Enforces every §4.3.4 limit while reading (manifest byte cap before
  buffering; per-file and running-total caps during streaming; declaration
  count caps before opening; nesting/string caps inside the parser;
  claimsFiles and signatureEnvelopes caps).
- Fails closed: malformed or ambiguous input yields an explicit diagnostic
  and a FAIL/INCOMPLETE/UNSUPPORTED verdict — never a `PASS`.

## Trust base and residual risks (out of scope, per §10.6)

- The verifier binary and its dependency-free toolchain: a compromised build
  or host defeats every local guarantee. Guaranteed through reproducible
  structure and the recorded checker identity — not through attestation.
- The local trust-policy file: unsigned in v0.1 and operator-supplied (§6.3);
  an attacker with write access to it, or to the binary, changes outcomes —
  out of scope.
- Local attacker (same-privilege write access, TOCTOU racing, clock
  manipulation): out of scope. The clock (`--now` or system clock) is trusted
  per §9.8's statement of the residual risk.
- SHA-256 collision resistance and hardware faults: outside the format.

## Implementation-level guarantees

| Property | Mechanism |
|---|---|
| No path escape | ASCII segment grammar; no `.`/`..`; per-component lstat; Linux `O_NOFOLLOW`; resolved root only |
| No unbounded allocation | Limits enforced during parse/read (`manifestBytes`, `jsonNesting`/`jsonStringBytes`, `payloadFiles`, `fileBytes`, `totalPayloadBytes`, `claimsFiles`, `signatureEnvelopes`); fixed chunk sizes |
| No false success | Required checks unimplemented ⇒ `UNSUPPORTED`; any unevaluable required dimension blocks `PASS` (§7.4); `coverage.full` false whenever any scope was limited or the scan is incomplete |
| Duplicate-key safety | Strict parser rejects duplicates everywhere (never last-wins), including policy and report documents |
| Determinism | Sorted diagnostics/limitations, explicit read order, no hash-map iteration ordering in output; byte-identical reruns under fixed `--now` (tested) |
| Integrity-safe claim handling | Claim files parsed only after declared digest matches (parsing itself deferred to Phase 2b) |
| No producer run | No producer code exists in the dependency set at all (pure std); no vendored code |
| Read-only package | No lock files, caches, or writes inside the package tree; only stdout/stderr are written |

## Platform-specific limits (documented, not stronger than implemented)

- `O_NOFOLLOW` final open: Linux only. On other Unix platforms the
  per-component lstat chain is the symlink boundary; see
  `ambiguity-limitations.md` C1.
- Non-Unix platforms are untested and unclaimed.
- Hard links cannot be detected portably (§4.3.2 residual).
- No wall-clock budget (§10.5 residual; internal scan budgets documented).

## Diagnostics by severity (Appendix J conformance)

- `error` — a required property was disproved or a required input is unusable
  (integrity failures, malformed manifest, path defects, limits that stop
  required evaluation).
- `warning` — required evaluation incomplete or evidence not established
  (undeclared files, unsupported-version compat, check family codes,
  envelope-not-evaluated).
- `info` — observational (policy absent, ignored extension, lowered limits).

The verdict is computed from dimensions/coverage, never from severity alone
(§9.7/Appendix J closing note).
