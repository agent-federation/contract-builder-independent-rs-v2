# Ambiguity and limitation register (Phase 2a)

Every entry records either a normative ambiguity encountered during the
independent implementation (with the chosen reading and its RFC-clause
anchor, in conformance with brief §11 "do not silently amend"), or an
implementation boundary/limitation.

## A. Specification ambiguities / interpretation decisions

| # | Area | Reading chosen | Anchor | Effect (none on compared corpus fields) |
|---|---|---|---|---|
| A1 | Nesting-limit fail classification for the manifest | Whenever the manifest cannot be *read or parsed* (byte limit, nesting, string limit), the diagnostic is `pap.package.limit-exceeded` for the byte limit and for nesting/string overflows (resource-limit family). `pap.package.manifest-json` covers BOM/UTF-8/trailing data/invalid JSON/non-integer tokens/duplicate-key-classification as listed in the §13.8 mapping table. | §4.3.4, §10.5, §13.8 (mapping row reads "per the first failing rule") | F35 hits the byte limit (`limit-exceeded`); no corpus case nests or overflows strings, so no compared field depends on this split. |
| A2 | Depth counting convention | "JSON nesting depth" counts *container openings* (a bare leaf value contributes no level); the root document is level 1. | §4.3.4 | No corpus case reaches deep nesting. |
| A3 | `payloadFiles` count-limit scope | Applied to each binary-payload class independently (artifacts / embedded sources / inputs); exceeding stops the *whole class* with none read. `claimsFiles` handles claims. | §4.3.4 (text says "in one payload class ... its count limit") | Defaults never bind in the corpus; only lowered-limit behavior in F52/F61, which are identity-compared. |
| A4 | `fileBytes`/`totalPayloadBytes` applicability to claims | Claim files are exempt from the per-file cap (bounded by the running `totalPayloadBytes` and the `claimsFiles` count), following the corpus README's authoritative limit note ("claim files are bounded by the JSON document limits"); v0.1 defers full claim parsing. | §4.3.4 fixture README (authorized corpus documentation) | F52/F61 remain consistent: artifact/source/input stops do not touch package integrity (F52 expects `integrity.package: PASS`). |
| A5 | Undeclared non-regular entries (symlinks/fifos/devices) found by the scan | Reported as `pap.package.symlink` with severity `warning` (an observation), not as an integrity failure — only *declared* paths can disprove a required property. J.1 lists the code with default severity `error` in the declared-path context. | §4.3.3 ("never opened"), Appendix J.1 | No corpus case contains an undeclared symlink. |
| A6 | Undeclared-file scan vs unparseable manifest | The scan runs whenever the manifest *parsed* (even if schema-invalid). When the manifest is missing or unparseable there is no declaration set to be measured against; the report is already `FAIL` by §7.4 rule 1, and the scan outcome is irrelevant to the verdict. | §4.3.3 | F21/F29/F35/F50/F51/F60 are identity-null FAIL paths either way. |
| A7 | Unsupported-version payload reading | For a schema-valid manifest whose `papVersion` is unsupported, payloads are NOT read (unknown semantics): `integrity.package: PASS` per §4.9 ("structurally readable"), payload dimensions `NOT_EVALUATED`, verdict `UNSUPPORTED` (§7.4 rule 3). | §4.9, §12.4.1 F10/F57 note | F10/F57 compared fields: `integrity.package: PASS` + verdict — both satisfied. |
| A8 | Rule 5 (`NOT_EVALUATED` aggregate) | Implemented for completeness; unreachable in practice because rule 4 catches `NOT_EVALUATED` required checks and undecided dimensions first. | §7.4 | None observed. |
| A9 | Set-digest second traversal | The `normalizedInputDigest` set digest is computed over a second, sorted re-traversal of the declared input paths (each re-open replays the same lstat safety chain). The §4.3.4 budget was enforced during the first traversal; the set digest hashes exactly the admitted bytes. Both §4.3.2 ("reads the bytes once") — fulfilled per purpose — and §10.4 T16 ("opened once and hashed from the same descriptor") are honored per file; the *sorted order* required by §5.2 necessitates the second traversal without buffering whole payloads. | §5.2, §4.3.4, §10.4 T16 | None: E.2 set vector matches exactly. |
| A10 | checkSpecs suffix normalization | ID suffixes like `/01` satisfy the id pattern but can never equal a canonical `version` value ⇒ reported as the §4.4.3 schema mismatch (`pap.package.schema`). | §4.4.3 | None (corpus pins `/1` vs `"2"`). |
| A11 | `pap.check.unsupported` severity for *optional* unimplemented declared checks | Emitted with `warning` severity for all declared checks that are not implemented (2a registry is empty); required ones additionally gate the verdict. | §7.2, J.3 | `pap.check.*` codes are exempt from the 2a comparison. |
| A12 | Human-review status when required but evaluation absent | `UNKNOWN` (§7.3: "a policy-relevant review decision could not be made") with `pap.trust.review-required` (warning) as the diagnostic and a limitation. Never `PASS`; §7.4 rule 4 keeps the aggregate verdict `INCOMPLETE` whenever review is required and evaluation is absent. | §6.7, §7.3 | F28/F55 identity-compared. |
| A13 | `sources.availability` for required-source-check presence | "Source-dependent check required" = the required set contains a `pap.check.source-quote/*` id. With none required ⇒ `NOT_APPLICABLE`. | §7.3 | F27 identity-compared. |
| A14 | Wrong-root declarations in the global duplicate rule | A declaration whose path violates the grammar or class root still participates in the global duplicate/case-fold rule (§4.3.1: "the duplicate rule is still evaluated over the same declaration set"). | §4.3.1 | F24 compared fields unaffected. |

## B. Known non-evaluated and later-phase items (from brief §5, RFC §13–§14)

- The three §8 checks (digest-integrity, source-quote, relation-consistency) —
  Phase 2b. Unimplemented ⇒ declared checks are `UNSUPPORTED`; a Phase 2a
  verdict can therefore never be `PASS`, which also means `coverage.full` is
  false wherever a required check exists (§7.5).
- Claim-file content validation per Appendix D (delayed with the checks);
  only raw-byte digests are verified in 2a.
- `producerClaims` comparison block (§7.6) — absent in 2a, documented.
- Human-review evidence evaluation (§6.7) — `UNKNOWN` when required.
- Signatures: DSSE, PAE, Ed25519, trust dimensions, in-toto (§11) — envelope
  discovery only, `NOT_EVALUATED`, `pap.signature.unsupported-format`.
- Full CLI contract: `inspect`, `explain`, `--version` line set, text-render
  requirements — the implemented interface is `pap verify PACKAGE
  [--trust-policy FILE] [--format text|json] [--now RFC3339]` (brief §4.7
  "minimal internal interface"); unknown commands/flags are usage errors.
- Archive transport (§10.7) — not implemented (D1).
- Network: no outbound network API is used or reachable from the verifier
  binary; the pure-std dependency closure eliminates registry fetches.

## C. Implementation limitations / platform notes

| # | Limitation | Detail |
|---|---|---|
| C1 | Linux hardening | Final-component `O_NOFOLLOW` is applied on Linux only; on other Unix systems the per-component lstat chain provides the symlink rejection (a TOCTOU window remains; local filesystem racing is out of scope per §10.4 T16). Windows is not tested or claimed. |
| C2 | Hard links | Not detectable portably; unchanged from the RFC's own §4.3.2 boundary. |
| C3 | Scan budgets | Internal robustness budgets: 1 000 000 entries / 16 384 directories. Reaching a budget reports the §4.3.3 scan-incomplete condition (`pap.package.undeclared-scan-incomplete`, `coverage.full: false`, verdict ≤ `INCOMPLETE`), never `pap.package.limit-exceeded`. Wall-clock budget: not implemented (§10.5 residual). |
| C4 | Streaming hashing | Payload bytes are hashed incrementally in 64 KiB chunks; file *contents* are never fully buffered except in memory of the manifest (bounded by `manifestBytes`). Input normalization is streaming with cross-chunk CR carry. |
| C5 | `diagnostics[].message` wording | Messages are deterministic within a build but are not normative (§7.7). |
| C6 | Text rendering | Rendering exists (`--format text`) but only the §9.6-required lines are approximated; full layout is Phase 2c. Not compared anywhere. |
| C7 | JCS key ordering cost | Object member sorting is O(n·log n) with UTF-16 keys; manifest bound 1 MiB makes this bounded. |
| C8 | Claim JSON limits (jsonNesting/jsonStringBytes) | Not yet enforced against claim files in 2a (claims are not parsed); Phase 2b applies them when claims parse (§4.3.4 claim row). |
| C9 | Global duplicate rule memory | Path duplicate detection holds an in-memory map of declared paths; bounded by the payloadPdeclaration limits (≤ 4096+16 entries). |

## D. Open questions for the maintainer (none blocking Phase 2a)

1. **Nesting/string-limit classification for the manifest** — confirm the
   diagnostic split choice in A1 (candidate: emit `pap.package.manifest-json`
   for nesting/string overflows as an alternate reading of the §13.8 row).
2. **Rule 5 disambiguation** — §7.4's rule 5 (`NOT_EVALUATED` aggregate) is
   unreachable after rule 4 as written; confirm the intended precedence.
3. **`payloadFiles` per-class vs total** — confirm the A3 reading before a
   fixture with > 4096 declared payloads exists.
4. **Claim `fileBytes` exemption** — confirm the A4 reading (follows the
   corpus README) before any lowered-`fileBytes` claim case exists.
5. **Human-review UNKNOWN** — confirm A12 as the correct 2a bridge state for
   `humanReview.required: true` policies.
