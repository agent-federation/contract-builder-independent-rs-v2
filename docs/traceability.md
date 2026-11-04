# Requirement-to-implementation traceability (Phase 2a)

| RFC section | Implemented in | Notes |
|---|---|---|
| §4.2 directory layout | src/package.rs | Directory-only reader |
| §4.3.1 path grammar | src/path.rs | validate_path_grammar |
| §4.3.2 file types/reading | src/package.rs | symlink/non-regular rejection, root confinement |
| §4.3.3 declared/undeclared/missing | src/package.rs | undeclared scan, missing declared files |
| §4.3.4 resource limits | src/package.rs | manifest byte limit etc. |
| §4.4 manifest parsing | src/json.rs, src/package.rs | strict JSON, schema validation |
| §4.9 compatibility/extensions/features | src/package.rs | version/extension/feature handling |
| §5.2 JCS/digests/framing | src/jcs.rs, src/digest.rs | RFC 8785, domain hashing, framing |
| §5.3 package identity | src/package.rs | H(pap.package.v1, JCS(manifest)) |
| §5.4 artifact digest | src/package.rs | H(pap.artifact.v1, bytes) |
| §5.5 raw source digest | src/package.rs | H(pap.source.raw.v1, bytes) |
| §5.6 normalized input digest | src/package.rs | LF normalization |
| §5.8 checker identity | src/checker.rs, src/digest.rs | implementationDigest + checkerIdentity |
| §7 verdict/coverage | src/package.rs | precedence implemented for 2a |
| §7.5 coverage | src/package.rs | coverage object |
| §9.7 exit codes | src/main.rs, src/package.rs | mapping |
| Appendix E vectors | tests/vectors.rs | digest/JCS/checker identity |
| Appendix A schema | src/package.rs via jsonschema | manifest schema validation |
| Appendix C report | src/report.rs | report struct |
