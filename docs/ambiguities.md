# Ambiguity and limitation register

1. Phase 2a does not implement the three PAP checks; required checks are reported `UNSUPPORTED`. This is intended per Phase 2a scope.
2. Trust policy parsing/evaluation is not implemented; `--trust-policy` is accepted but policy state reported `ABSENT`.
3. `inspect`/`explain` commands are not implemented.
4. DSSE/signature verification is not implemented.
5. Checker identity closure is computed at runtime from `CARGO_MANIFEST_DIR`; binary relocation would break closure computation.
6. Undeclared-file scan uses filesystem enumeration; internal robustness budget not implemented (scan may traverse large trees).
7. Claim file schema validation is limited to JSON parsing and digest comparison; full Appendix D schema validation may be incomplete.
8. Text output format is JSON only (minimal interface).
