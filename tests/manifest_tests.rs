//! Manifest parsing and schema tests (brief §7.2) exercised through the
//! verifier module API on synthetic manifest values.

use pap::json::{Json, ParserLimits, parse_document};
use pap::limits::LimitSet;
use pap::manifest;

/// Build a valid 0.1 manifest (base-shaped) with field overrides via JSON text.
fn manifest_with(patch: &str) -> Json {
    let base = r#"{
        "papVersion": "0.1",
        "package": {"id": "urn:pap:t", "createdAt": "2026-11-02T00:00:00Z",
                     "producer": {"name": "x", "version": "1"}},
        "artifacts": [{"id": "artifact:a", "path": "artifacts/a.md",
                        "mediaType": "text/markdown; charset=utf-8", "bytes": 0,
                        "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
        "checkSpecs": [{"id": "pap.check.digest-integrity/1", "version": "1", "required": true}],
        "subject": {"projectId": "t"}
    }"#;
    let v = parse_document(base.as_bytes(), &ParserLimits::defaults()).unwrap();
    if patch.is_empty() {
        return v;
    }
    apply_patch(v, &parse_document(patch.as_bytes(), &ParserLimits::defaults()).unwrap())
}

fn apply_patch(base: Json, patch: &Json) -> Json {
    // Top-level member replacement (key present in patch replaces the value).
    match (base, patch) {
        (Json::Obj(mut bm), Json::Obj(p)) => {
            for (k, pv) in p.clone() {
                match bm.iter().position(|(bk, _)| *bk == k) {
                    Some(i) => bm[i].1 = pv,
                    None => bm.push((k.clone(), pv)),
                }
            }
            Json::Obj(bm)
        }
        (b, _) => b,
    }
}

fn validate_of(v: &Json) -> manifest::ManifestOutcome {
    manifest::validate(v, &LimitSet::defaults())
}

fn codes(out: &manifest::ManifestOutcome) -> Vec<&'static str> {
    out.diagnostics.iter().map(|d| d.code).collect()
}

#[test]
fn valid_manifest_passes() {
    let out = validate_of(&manifest_with(""));
    assert!(out.manifest.is_some(), "diagnostics: {:?}", codes(&out));
    assert_eq!(out.compat, manifest::Compat::Supported);
    assert!(codes(&out).is_empty());
    assert!(!out.fatal());
}

#[test]
fn invalid_json_is_rejected_at_the_document_layer() {
    // invalid JSON handled by the strict parser (pap.package.manifest-json)
    let err = parse_document(b"{\"a\":", &ParserLimits::defaults()).unwrap_err();
    assert_eq!(err.kind, pap::json::ParseErrorKind::InvalidJson);
    // same for truncated mid-object (F21 shape)
    assert!(parse_document(b"{\n  \"papVersion\": \"0.1\",\n  \"package\": {\n    \"id\": \"x\",",
                           &ParserLimits::defaults()).is_err());
}

#[test]
fn invalid_utf8_and_bom_rejected() {
    assert_eq!(
        parse_document(&[0x7B, 0xC3, 0x28, 0x7D], &ParserLimits::defaults()).unwrap_err().kind,
        pap::json::ParseErrorKind::NotUtf8
    );
    assert_eq!(
        parse_document("\u{FEFF}{}".as_bytes(), &ParserLimits::defaults()).unwrap_err().kind,
        pap::json::ParseErrorKind::Bom
    );
}

#[test]
fn duplicate_keys_rejected_not_last_wins() {
    let err = parse_document(b"{\"package\":{\"id\":\"a\",\"id\":\"b\"}}", &ParserLimits::defaults())
        .unwrap_err();
    assert_eq!(err.kind, pap::json::ParseErrorKind::DuplicateKey);
    // duplicate inside the package object (F29 shape)
    let err = parse_document(
        br#"{"papVersion":"0.1","package":{"id":"a","id":"b"},"artifacts":[{"id":"a","path":"artifacts/a","mediaType":"text/x","bytes":0,"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],"checkSpecs":[{"id":"pap.check.digest-integrity/1","version":"1"}]}"#,
        &ParserLimits::defaults(),
    )
    .unwrap_err();
    assert_eq!(err.kind, pap::json::ParseErrorKind::DuplicateKey);
}

#[test]
fn non_integer_number_tokens_rejected() {
    for bad in ["{\"bytes\":1e2}", "{\"bytes\":1.0}", "{\"bytes\":-0}", "{\"bytes\":01}"] {
        assert!(parse_document(bad.as_bytes(), &ParserLimits::defaults()).is_err(), "{bad}");
    }
}

#[test]
fn unknown_core_fields_rejected() {
    let out = validate_of(&manifest_with(
        r#"{"artifacts": [{"id": "artifact:a", "path": "artifacts/a.md", "mediaType": "text/x", "bytes": 0, "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.unknown-field"));
    assert!(out.structure_invalid);
}

#[test]
fn missing_required_fields_rejected() {
    // no artifacts
    let out = validate_of(&manifest_with(r#"{"artifacts": []}"#));
    assert!(codes(&out).contains(&"pap.package.schema"));
    // package missing id
    let out = validate_of(&manifest_with(r#"{"package": {"title": "x"}}"#));
    assert!(codes(&out).contains(&"pap.package.schema"));
    // artifact missing digest
    let out = validate_of(&manifest_with(
        r#"{"artifacts": [{"id": "artifact:a", "path": "artifacts/a.md", "mediaType": "text/x", "bytes": 0}]}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.schema"));
    // missing checkSpecs entirely
    let v = parse_document(
        r#"{"papVersion":"0.1","package":{"id":"a"},"artifacts":[{"id":"artifact:a","path":"artifacts/a.md","mediaType":"text/x","bytes":0,"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}"#.as_bytes(),
        &ParserLimits::defaults()).unwrap();
    let out = validate_of(&v);
    assert!(codes(&out).contains(&"pap.package.schema"));
}

#[test]
fn invalid_enums_and_patterns_rejected() {
    // bad normalization enum
    let out = validate_of(&manifest_with(
        r#"{"inputs": [{"id": "input:1", "path": "inputs/a.yml", "mediaType": "application/yaml", "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "normalization": "crlf"}]}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.schema"));
    // bad digest pattern (uppercase hex)
    let out = validate_of(&manifest_with(
        r#"{"artifacts": [{"id": "artifact:a", "path": "artifacts/a.md", "mediaType": "text/x", "bytes": 0, "digest": "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"}]}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.schema"));
    // unknown build extension kind
    let out = validate_of(&manifest_with(
        r#"{"build": {"extensions": [{"kind": "plugin", "id": "x", "version": "1"}]}}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.schema"));
}

#[test]
fn duplicate_ids_rejected() {
    let out = validate_of(&manifest_with(
        r#"{"artifacts": [{"id": "artifact:a", "path": "artifacts/a.md", "mediaType": "text/x", "bytes": 0, "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                            {"id": "artifact:a", "path": "artifacts/b.md", "mediaType": "text/x", "bytes": 0, "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.duplicate-id"));
    assert!(out.structure_invalid);
}

#[test]
fn duplicate_and_case_colliding_paths_rejected() {
    // exact duplicates across classes
    let out = validate_of(&manifest_with(
        r#"{"inputs": [{"id": "input:1", "path": "artifacts/a.md", "mediaType": "application/yaml", "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "normalization": "lf"}]}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.path-duplicate"));
    // case collision within artifacts (F24 shape)
    let out = validate_of(&manifest_with(
        r#"{"artifacts": [{"id": "artifact:upper", "path": "artifacts/A.md", "mediaType": "text/x", "bytes": 0, "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                            {"id": "artifact:lower", "path": "artifacts/a.md", "mediaType": "text/x", "bytes": 0, "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.path-duplicate"));
    assert_eq!(out.class_defect.artifacts, true);
}

#[test]
fn cross_field_check_version_invariant_rejected() {
    // version mismatch (F53 shape)
    let out = validate_of(&manifest_with(
        r#"{"checkSpecs": [{"id": "pap.check.digest-integrity/1", "version": "2", "required": true}]}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.schema"));
    assert!(out.structure_invalid);
    // version suffix with leading zero: id "…/01" is a valid id pattern but
    // version cannot spell it — mismatch is pap.package.schema
    let out = validate_of(&manifest_with(
        r#"{"checkSpecs": [{"id": "pap.check.digest-integrity/01", "version": "1", "required": true}]}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.schema"));
}

#[test]
fn version_incompatibilities() {
    // newer minor (F10 shape): structurally readable → NOT a schema defect
    let out = validate_of(&manifest_with(r#"{"papVersion": "0.2"}"#));
    assert_eq!(out.compat, manifest::Compat::MinorNewer);
    assert!(!codes(&out).contains(&"pap.package.schema"));
    assert!(out.manifest.is_some());
    // different major (F57 shape)
    let out = validate_of(&manifest_with(r#"{"papVersion": "1.0"}"#));
    assert_eq!(out.compat, manifest::Compat::VersionUnsupported);
    assert!(out.manifest.is_some());
    // older minor of supported major
    let out = validate_of(&manifest_with(r#"{"papVersion": "0.0"}"#));
    assert_eq!(out.compat, manifest::Compat::VersionUnsupported);
    // leading zero components are schema defects, not compat states
    let out = validate_of(&manifest_with(r#"{"papVersion": "0.01"}"#));
    assert!(codes(&out).contains(&"pap.package.schema"));
    // missing version field
    let v = parse_document(r#"{"package":{"id":"a"},"artifacts":[],"checkSpecs":[]}"#.as_bytes(),
                           &ParserLimits::defaults()).unwrap();
    let out = validate_of(&v);
    assert!(out.pap_version.is_none());
    assert!(codes(&out).contains(&"pap.package.schema"));
}

#[test]
fn extension_and_required_feature_parsing() {
    // critical extension recorded as critical-unsupported
    let out = validate_of(&manifest_with(
        r#"{"extensions": {"com.example.future": {"version": "1", "critical": true}}}"#,
    ));
    assert_eq!(out.extensions.len(), 1);
    assert!(out.extensions[0].critical_unsupported);
    // non-critical extension ignored but reported
    let out = validate_of(&manifest_with(
        r#"{"extensions": {"com.example.optional": {"version": "1", "critical": false}}}"#,
    ));
    assert_eq!(out.extensions.len(), 1);
    assert!(out.extensions[0].ignored);
    // extension key pattern enforced
    let out = validate_of(&manifest_with(
        r#"{"extensions": {"COM.Example": {"version": "1", "critical": false}}}"#,
    ));
    assert!(codes(&out).contains(&"pap.package.schema"));
    // requiredFeatures captured
    let out = validate_of(&manifest_with(r#"{"requiredFeatures": ["pap.feature.future"]}"#));
    assert_eq!(out.required_features, vec!["pap.feature.future".to_string()]);
}

#[test]
fn nesting_and_string_limits() {
    // Depth: parser counter; root object counts as 1 (§4.3.4 jsonNesting 64).
    let deep = r#"{"a":{"a":{"a":{"a":1}}}}"#; // depth 4
    let err = parse_document(
        deep.as_bytes(),
        &ParserLimits {
            depth: 3,
            string_bytes: usize::MAX,
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, pap::json::ParseErrorKind::DepthLimit);
    // depth exactly at the limit is fine
    assert!(parse_document(
        deep.as_bytes(),
        &ParserLimits {
            depth: 4,
            string_bytes: usize::MAX
        }
    )
    .is_ok());
    // string over limit
    let err = parse_document(
        br#"{"a":"abcdefghi"}"#,
        &ParserLimits {
            depth: 64,
            string_bytes: 8,
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, pap::json::ParseErrorKind::StringLimit);
    // default limits: 64-deep nesting is acceptable at the boundary
    assert!(parse_document(
        format!("{}{}{}", "[".repeat(64), "0", "]".repeat(64)).as_bytes(),
        &ParserLimits::defaults()
    )
    .is_ok());
    assert!(parse_document(
        format!("{}{}{}", "[".repeat(65), "0", "]".repeat(65)).as_bytes(),
        &ParserLimits::defaults()
    )
    .is_err());
}

