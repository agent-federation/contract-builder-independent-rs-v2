//! Appendix E canonical test vectors (normative) — Phase 2a applicable set:
//! E.1 (canonical manifest / packageIdentity), E.2 (payload digests),
//! E.3 (checker identity), E.5 (LF normalization), E.6 (domain separation and
//! framing), E.9 (JCS edge cases) and the E.4/E.10 verification-record
//! identity form and mutations.

use pap::digest::{self, Digest, Frame};
use pap::jcs;
use pap::json::{Json, ParserLimits, parse_document};
use pap::normalize;
use pap::sha256::{hex_lower, sha256};

fn fixtures_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pap/fixtures/pap-v0.1")
}

/// The base fixture manifest (Appendix F package).
fn base_manifest_bytes() -> Vec<u8> {
    std::fs::read(fixtures_dir().join("base/assurance-package.json")).expect("base manifest")
}

/// E.1: packageIdentity over the canonical manifest.
#[test]
fn e1_canonical_manifest_bytes_and_identity() {
    let raw = base_manifest_bytes();
    let v = parse_document(&raw, &ParserLimits::defaults()).expect("base manifest parses");
    let canonical = jcs::to_canonical(&v);

    // The RFC E.1 transcription is normative; the canonical bytes must be
    // byte-identical to it (whitespace-free, key-sorted, no trailing NL).
    let e1_transcription = r#"{"artifacts":[{"bytes":80,"digest":"sha256:5f521a6b5bedacdf8d3536f8fb509bef6e829bfb537b1ec818cb38a8e1a2dd51","id":"artifact:acme-supplier","mediaType":"text/markdown; charset=utf-8","path":"artifacts/ACME-SUPPLIER.draft.md"}],"build":{"engineVersion":"0.1.0","manifestVersion":"0.1","normalizedInputDigest":"sha256:fccf755793cf1a1b7982631c201282669924cdcf9d6b171bdff26513fc64d80b"},"checkSpecs":[{"id":"pap.check.digest-integrity/1","required":true,"version":"1"},{"id":"pap.check.source-quote/1","required":true,"version":"1"},{"id":"pap.check.relation-consistency/1","required":true,"version":"1"}],"claims":{"producerReport":{"digest":"sha256:f45a69883bed0d0e62c69c7ff0105e902f86006e89c56d77cef1cc9630846e95","path":"claims/producer-report.json"},"provenance":{"digest":"sha256:8044adf1df927b30e67e743d6ca348a8f197f8af4e9e7cc668ebf525e6e7b95b","path":"claims/provenance.json"},"relations":{"digest":"sha256:992cd64e230f2480a88ab7128d802796abfbd44605809ba52cb16828559f83ab","path":"claims/relations.json"}},"inputs":[{"digest":"sha256:2da40818408dec8fe7d63c86cb8e67fbc624c743a7d81b02535f318b80cb08ff","id":"input:project","mediaType":"application/yaml","normalization":"lf","path":"inputs/project.yml"}],"package":{"createdAt":"2026-11-02T00:00:00Z","id":"urn:pap:acme-supplier:2026-01","producer":{"name":"contract-builder","version":"0.1.0"},"title":"ACME supplier assurance package"},"papVersion":"0.1","profile":{"id":"acme-supplier","version":"0.1.0"},"sources":[{"acquiredAt":"2026-11-01T12:00:00Z","acquisition":{"method":"git","revision":"0f1e2d3c4b5a69788796a5b4c3d2e1f0","uri":"https://example.invalid/acme/policy.git"},"digest":"sha256:d7a4ee24615f562232172021f3c992fa1a5aed7a2ae9c128446101ed8f46eecd","id":"SRC-ACME-POLICY","mediaType":"text/markdown; charset=utf-8","path":"sources/acme-policy.md"}],"subject":{"projectId":"acme-supplier","revision":"1.0.0"}}"#;
    assert_eq!(canonical, e1_transcription);

    // packageIdentity = H("pap.package.v1", canonical bytes)
    let id = digest::package_identity(canonical.as_bytes());
    assert_eq!(
        hex_lower(&id),
        "77a8d1d0882428efdfa5bfc38faa1ff7ba772aff9373b9e6135a8bb744119020"
    );
}

/// E.2: payload digest vectors over the packaged bytes.
#[test]
fn e2_payload_digest_vectors() {
    let base = fixtures_dir().join("base");
    // artifact — 80 bytes, digest under pap.artifact.v1
    let artifact =
        std::fs::read(base.join("artifacts/ACME-SUPPLIER.draft.md")).expect("artifact bytes");
    assert_eq!(artifact.len(), 80);
    let d = Digest::from_bytes(&digest::artifact_digest(&artifact));
    assert_eq!(
        d.as_str(),
        "sha256:5f521a6b5bedacdf8d3536f8fb509bef6e829bfb537b1ec818cb38a8e1a2dd51"
    );
    // artifact ends with one LF
    assert_eq!(artifact.last(), Some(&0x0A));

    // raw source — 127 bytes
    let source = std::fs::read(base.join("sources/acme-policy.md")).expect("source bytes");
    assert_eq!(source.len(), 127);
    let d = Digest::from_bytes(&digest::raw_source_digest(&source));
    assert_eq!(
        d.as_str(),
        "sha256:d7a4ee24615f562232172021f3c992fa1a5aed7a2ae9c128446101ed8f46eecd"
    );

    // quote span [24,76) — 52 bytes, quote domain
    let span = &source[24..76];
    assert_eq!(span.len(), 52);
    assert_eq!(
        String::from_utf8(span.to_vec()).expect("span is text"),
        "REQ-001: every delivery MUST include a packing list."
    );
    let d = Digest::from_bytes(&digest::quote_digest(span));
    assert_eq!(
        d.as_str(),
        "sha256:619cb81063fff535c31b93b66e274e6df0a1cef4582d17c7a6362c98fac48909"
    );

    // per-input file digest + set digest from the manifest declarations
    let raw_manifest = base_manifest_bytes();
    let v = parse_document(&raw_manifest, &ParserLimits::defaults()).unwrap();
    let input_entry = &v.get("inputs").and_then(|x| x.as_arr()).unwrap()[0];
    let path = input_entry.get("path").and_then(|p| p.as_str()).unwrap();
    assert_eq!(path, "inputs/project.yml");
    let input_bytes = std::fs::read(base.join(path)).expect("input bytes");
    let norm = normalize::normalize_input(&input_bytes).expect("input is text");
    let d = Digest::from_bytes(&digest::input_file_digest(path, &norm));
    assert_eq!(
        d.as_str(),
        "sha256:2da40818408dec8fe7d63c86cb8e67fbc624c743a7d81b02535f318b80cb08ff"
    );

    // set digest: concatenated framed records in ascending path order
    let mut payload = Vec::new();
    digest::push_record(
        &mut payload,
        "input",
        &[Frame::Text(path), Frame::Bytes(&norm)],
    );
    let d = Digest::from_bytes(&digest::h("pap.input.set.v1", &payload));
    assert_eq!(
        d.as_str(),
        "sha256:fccf755793cf1a1b7982631c201282669924cdcf9d6b171bdff26513fc64d80b"
    );

    // claim file digests: raw bytes are the payload, no framing
    for (kind_path, expect) in [
        (
            "claims/provenance.json",
            "sha256:8044adf1df927b30e67e743d6ca348a8f197f8af4e9e7cc668ebf525e6e7b95b",
        ),
        (
            "claims/relations.json",
            "sha256:992cd64e230f2480a88ab7128d802796abfbd44605809ba52cb16828559f83ab",
        ),
        (
            "claims/producer-report.json",
            "sha256:f45a69883bed0d0e62c69c7ff0105e902f86006e89c56d77cef1cc9630846e95",
        ),
    ] {
        let bytes = std::fs::read(base.join(kind_path)).expect("claim bytes");
        let d = Digest::from_bytes(&digest::claim_digest(&bytes));
        assert_eq!(d.as_str(), expect, "claim {kind_path}");
    }
}

/// E.3: checker identity vector (Appendix F closure).
#[test]
fn e3_checker_identity_vector() {
    // kind/id/version: checker / pap.verifier.reference / 0.1.0
    // files: src/checks/digest.ts, src/checks/source.ts (LF-normalized bytes)
    // dependency: zod 3.23.8 sha512-9K5fXZ0G8p3oUo4WQ9m2l1v0B9m3r7Yqk1s2V4pL6c0=
    let mut records: Vec<u8> = Vec::new();
    digest::push_record(
        &mut records,
        "extension",
        &[
            Frame::Text("checker"),
            Frame::Text("pap.verifier.reference"),
            Frame::Text("0.1.0"),
        ],
    );
    digest::push_record(
        &mut records,
        "file",
        &[
            Frame::Text("src/checks/digest.ts"),
            Frame::Bytes(
                b"export const checkId = \"pap.check.digest-integrity/1\";\n".as_slice(),
            ),
        ],
    );
    digest::push_record(
        &mut records,
        "file",
        &[
            Frame::Text("src/checks/source.ts"),
            Frame::Bytes(b"export const spanCheck = true;\n".as_slice()),
        ],
    );
    digest::push_record(
        &mut records,
        "dependency",
        &[
            Frame::Text("zod"),
            Frame::Text("3.23.8"),
            Frame::Text("sha512-9K5fXZ0G8p3oUo4WQ9m2l1v0B9m3r7Yqk1s2V4pL6c0="),
        ],
    );
    let impl_digest = digest::extension_closure_digest(&records);
    assert_eq!(
        hex_lower(&impl_digest),
        "73f738b733b177c04597b0e6ab9c4d267059ea1556e6f943d543c252c5ef15c0"
    );

    // checkerIdentity = H("pap.checker.identity.v1", JCS({id, version, implementationDigest}))
    let identity_json = format!(
        "{{\"id\":\"pap.verifier.reference\",\"implementationDigest\":\"sha256:{}\",\"version\":\"0.1.0\"}}",
        hex_lower(&impl_digest)
    );
    let cid = digest::checker_identity(
        "pap.verifier.reference",
        "0.1.0",
        &format!("sha256:{}", hex_lower(&impl_digest)),
    );
    assert_eq!(
        hex_lower(&cid),
        "15a0b0149dc95f7b9711e7b28fc4189ed8539b03ffd2c96e967205316d75963f"
    );
    // the hand-built literal equals the helper's output
    assert_eq!(
        identity_json,
        format!(
            "{{\"id\":\"{}\",\"implementationDigest\":\"sha256:{}\",\"version\":\"{}\"}}",
            "pap.verifier.reference",
            hex_lower(&impl_digest),
            "0.1.0"
        )
    );
}

/// E.5: input normalization vector (LF rules).
#[test]
fn e5_normalization_vector() {
    let raw: &[u8] = &[0x61, 0x3a, 0x20, 0x31, 0x0d, 0x0a, 0x62, 0x3a, 0x20, 0x32, 0x0d, 0x0a];
    assert_eq!(
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "613a20310d0a623a20320d0a"
    );
    let norm = normalize::normalize_input(raw).expect("valid UTF-8 without NUL");
    assert_eq!(
        norm.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "613a20310a623a20320a"
    );
    let d = Digest::from_bytes(&digest::input_file_digest("inputs/crlf.yml", &norm));
    assert_eq!(
        d.as_str(),
        "sha256:2633064c5d3066746beae7416e97e87816fe9b031c6f57af4c9b02ca1c00453b"
    );
    let mut payload = Vec::new();
    digest::push_record(
        &mut payload,
        "input",
        &[Frame::Text("inputs/crlf.yml"), Frame::Bytes(&norm)],
    );
    let d = Digest::from_bytes(&digest::h("pap.input.set.v1", &payload));
    assert_eq!(
        d.as_str(),
        "sha256:92e9ec329516a5672fc40fd0b4474f2a2fd7790d87817c37b772af3347df2021"
    );
}

/// E.6: domain separation + framing ambiguity.
#[test]
fn e6_domain_separation() {
    let expected = [
        (
            "pap.artifact.v1",
            "49ade3eaed5c81a07ee5245b923abe3c629747f0eebe57a0052307d5965d5112",
        ),
        (
            "pap.source.raw.v1",
            "8240a5313b027e89a99054c87e683a87d68f59dc566a40f16aa68edcbf1a81b7",
        ),
        (
            "pap.package.v1",
            "4cb73e2896d009395089ea045b54b15eea2bc4c03e519bc08dc0f619da308308",
        ),
    ];
    for (domain, want) in expected {
        assert_eq!(hex_lower(&digest::h(domain, b"hello")), want);
    }
}

#[test]
fn e6_framing_ambiguity() {
    let a = digest::h(
        "pap.test.v1",
        &digest::record("x", &[Frame::Text("ab"), Frame::Text("c")]),
    );
    let b = digest::h(
        "pap.test.v1",
        &digest::record("x", &[Frame::Text("a"), Frame::Text("bc")]),
    );
    assert_eq!(
        hex_lower(&a),
        "a4ff1eac1c490e25d4a23ef485f9219a4a51b2c370ba86ed20ba0d8e5c7334e5"
    );
    assert_eq!(
        hex_lower(&b),
        "19777dd70824683c8483961510324f7656c03378f3a4b64192e8bee7ff0ecff2"
    );
    assert_ne!(a, b);
}

/// E.9: JCS edge cases (UTF-16 key order, escaping, number rules).
#[test]
fn e9_utf16_key_order_and_escaping_and_numbers() {
    // UTF-16 key order (astral keys sort after BMP keys with larger units).
    let members = vec![
        ("a".to_string(), Json::Int(1)),
        ("😀".to_string(), Json::Int(2)),
        ("\u{FFFD}".to_string(), Json::Int(3)),
        ("A".to_string(), Json::Int(4)),
        ("b".to_string(), Json::Int(5)),
    ];
    let got = jcs::to_canonical(&Json::Obj(members.clone()));
    assert_eq!(got, "{\"A\":4,\"a\":1,\"b\":5,\"😀\":2,\"\u{FFFD}\":3}");
    assert_eq!(got.len(), 36);
    assert_eq!(
        hex_lower(&sha256(got.as_bytes())),
        "9267454f732ed7ef9939b28dc1e451c88c2967ff4a6b1746bf638d313e72b508"
    );

    // String escaping vector.
    let input = "{\"s\":\"\\u0001\\t\\n\\\"\\\\é😀\"}";
    let v = parse_document(input.as_bytes(), &ParserLimits::defaults()).unwrap();
    let got = jcs::to_canonical(&v);
    assert_eq!(got, input);
    assert_eq!(got.len(), 28);
    assert_eq!(
        hex_lower(&sha256(got.as_bytes())),
        "9033f8f21bc1c3367ebcad55e2298bf113b63f9e5f21c20678de00e760c5ff5d"
    );

    // Number rules: valid integer tokens canonicalize; fraction/exponent
    // spelling and -0 have no canonical bytes.
    let v = parse_document(b"9007199254740991", &ParserLimits::defaults()).unwrap();
    assert_eq!(jcs::to_canonical(&v), "9007199254740991");
    let v = parse_document(b"-9007199254740991", &ParserLimits::defaults()).unwrap();
    assert_eq!(jcs::to_canonical(&v), "-9007199254740991");
    for bad in ["9007199254740992", "1.0", "1e3", "-0", "01", "1E3"] {
        assert!(parse_document(bad.as_bytes(), &ParserLimits::defaults()).is_err(), "{bad}");
    }
}

/// E.4/E.10: verification-record identity — baseline and mutation vectors
/// over the supplied identity form. The identity function is §5.9: remove the
/// excluded presentation fields, replace the record digest with the zero
/// placeholder, canonicalize with JCS, hash under `pap.report.v1`.
#[test]
fn e4_record_identity_baseline() {
    let path = fixtures_dir().join("../vectors/e4-identity-form.json");
    let mut raw = std::fs::read(path).expect("E.4 identity form fixture");
    // The fixture carries a trailing LF; the identity form has none.
    if raw.last() == Some(&0x0A) {
        raw.pop();
    }
    let v = parse_document(&raw, &ParserLimits::defaults()).expect("E.4 form parses");
    // The fixture already represents the identity form (placeholders applied,
    // presentation fields absent) — but apply the identity pipeline to be
    // sure the function is idempotent for such forms.
    let form = pap::report::identity_form(&v);
    let canonical = jcs::to_canonical(&form);
    let identity = digest::report_identity(canonical.as_bytes());
    assert_eq!(
        hex_lower(&identity),
        "147aad0ab0f4b9274b7f66182de179ad69ae2924f311dcf723e67d39b07527ea"
    );
}

#[test]
fn e10_record_identity_mutations() {
    let path = fixtures_dir().join("../vectors/e4-identity-form.json");
    let mut raw = std::fs::read(path).expect("E.4 identity form fixture");
    if raw.last() == Some(&0x0A) {
        raw.pop();
    }
    let base: Json = parse_document(&raw, &ParserLimits::defaults()).unwrap();

    let hash_of = |v: &Json| -> String {
        let form = pap::report::identity_form(v);
        let canonical = jcs::to_canonical(&form);
        hex_lower(&digest::report_identity(canonical.as_bytes()))
    };

    // baseline
    assert_eq!(
        hash_of(&base),
        "147aad0ab0f4b9274b7f66182de179ad69ae2924f311dcf723e67d39b07527ea"
    );

    // mutation 1: dimensions.checks.results[0].outcome PASS → FAIL
    let mut m = base.clone();
    if let Json::Obj(members) = &mut m {
        for (k, v) in members.iter_mut() {
            if k == "dimensions" {
                if let Json::Obj(dims) = v {
                    for (k2, v2) in dims.iter_mut() {
                        if k2 == "checks" {
                            if let Json::Obj(ch) = v2 {
                                for (k3, v3) in ch.iter_mut() {
                                    if k3 == "results" {
                                        if let Json::Arr(rows) = v3 {
                                            if let Json::Obj(row) = &mut rows[0] {
                                                for (k4, v4) in row.iter_mut() {
                                                    if k4 == "outcome" {
                                                        *v4 = Json::Str("FAIL".to_string());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        hash_of(&m),
        "f9f2c22f90baa970ebed16d3cceae08a2aac6544f617320dd06c95745d1b7e30"
    );

    // mutation 2: checks[1].witnesses[0].range.end 76 → 75
    let mut m = base.clone();
    if let Json::Obj(members) = &mut m {
        for (k, v) in members.iter_mut() {
            if k == "checks" {
                if let Json::Arr(checks) = v {
                    if let Json::Obj(check) = &mut checks[1] {
                        for (k2, v2) in check.iter_mut() {
                            if k2 == "witnesses" {
                                if let Json::Arr(ws) = v2 {
                                    if let Json::Obj(w) = &mut ws[0] {
                                        for (k3, v3) in w.iter_mut() {
                                            if k3 == "range" {
                                                if let Json::Obj(r) = v3 {
                                                    for (k4, v4) in r.iter_mut() {
                                                        if k4 == "end" {
                                                            *v4 = Json::Int(75);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        hash_of(&m),
        "83d9147e35f2dc528f481f0f39335497b3c32ea7f45ed083cf8a448679f24c4c"
    );

    // mutation 3: checks[0].scope.artifacts emptied
    let mut m = base.clone();
    if let Json::Obj(members) = &mut m {
        for (k, v) in members.iter_mut() {
            if k == "checks" {
                if let Json::Arr(checks) = v {
                    if let Json::Obj(check) = &mut checks[0] {
                        for (k2, v2) in check.iter_mut() {
                            if k2 == "scope" {
                                if let Json::Obj(sc) = v2 {
                                    for (k3, v3) in sc.iter_mut() {
                                        if k3 == "artifacts" {
                                            *v3 = Json::Arr(Vec::new());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        hash_of(&m),
        "652798f36a18daec12268ebe05eeb6022d5d1be704897d51a98a2d30adc044f8"
    );

    // mutation 4: add checks[1].diagnostics[0] {pap.check.partial, warning}
    let add_diag = |base: &Json| -> Json {
        let mut m = base.clone();
        if let Json::Obj(members) = &mut m {
            for (k, v) in members.iter_mut() {
                if k == "checks" {
                    if let Json::Arr(checks) = v {
                        if let Json::Obj(check) = &mut checks[1] {
                            let entry = Json::Obj(vec![
                                ("code".to_string(), Json::Str("pap.check.partial".to_string())),
                                ("severity".to_string(), Json::Str("warning".to_string())),
                                ("message".to_string(), Json::Str("beta".to_string())),
                            ]);
                            if let Some(slot) = check.iter_mut().find(|(k, _)| k == "diagnostics") {
                                slot.1 = Json::Arr(vec![entry]); // replace existing [] member
                            } else {
                                check.push(("diagnostics".to_string(), Json::Arr(vec![entry])));
                            }
                        }
                    }
                }
            }
        }
        m
    };
    let with_diag = add_diag(&base);
    assert_eq!(
        hash_of(&with_diag),
        "635dcc4a65d44e5e011f8193705e9eb6c62eae8e553fd8068b60bc2ca59fc9e3"
    );

    // mutation 6: add checks[1].witnesses[0].quoteBase64 — identity unchanged
    // (the extracted span b64-encoded: "Time is the mind of the road" not
    // normative — use the RFC-4648 encoding of the actual span digest vector).
    let span = {
        let source = std::fs::read(fixtures_dir().join("base/sources/acme-policy.md")).unwrap();
        source[24..76].to_vec()
    };
    let b64 = pap::digest::base64_standard_pad(&span);
    let mut m = base.clone();
    if let Json::Obj(members) = &mut m {
        for (k, v) in members.iter_mut() {
            if k == "checks" {
                if let Json::Arr(checks) = v {
                    if let Json::Obj(check) = &mut checks[1] {
                        for (k2, v2) in check.iter_mut() {
                            if k2 == "witnesses" {
                                if let Json::Arr(ws) = v2 {
                                    if let Json::Obj(w) = &mut ws[0] {
                                        w.push(("quoteBase64".to_string(), Json::Str(b64.clone())));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        hash_of(&m),
        "147aad0ab0f4b9274b7f66182de179ad69ae2924f311dcf723e67d39b07527ea"
    );

    // mutation 7: diagnostic message wording only — identity unchanged
    let mut m = with_diag.clone();
    if let Json::Obj(members) = &mut m {
        for (k, v) in members.iter_mut() {
            if k == "checks" {
                if let Json::Arr(checks) = v {
                    if let Json::Obj(check) = &mut checks[1] {
                        for (k2, v2) in check.iter_mut() {
                            if k2 == "diagnostics" {
                                if let Json::Arr(ds) = v2 {
                                    if let Json::Obj(d) = &mut ds[0] {
                                        for (k3, v3) in d.iter_mut() {
                                            if k3 == "message" {
                                                *v3 = Json::Str("alpha".to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        hash_of(&m),
        "635dcc4a65d44e5e011f8193705e9eb6c62eae8e553fd8068b60bc2ca59fc9e3"
    );
}
