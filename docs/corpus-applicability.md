# Phase 2a corpus applicability matrix

Source: `pap/fixtures/pap-v0.1/cases-phase2a.json` (experiment metadata; `cases.json` remains normative).

- Full profile: 19 cases (package parsing/digest/safety/compatibility surface).
- Identity-only profile: 36 cases (packageIdentity comparison).
- Excluded (Phase 2c): F25, F37, F38, F39, F41, F42.

Phase 2a verifier implements parsing, digests, safety and report foundations. Checks are not implemented; required checks are reported `UNSUPPORTED`, yielding `UNSUPPORTED` verdict where applicable. Later-phase assertions (signature, inspect/explain, trust policy) are deferred.
