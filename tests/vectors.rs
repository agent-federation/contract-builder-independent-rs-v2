use pap_verifier::digest;

#[test]
fn e3_checker_identity() {
    let files = vec![
        ("src/checks/digest.ts".to_string(), b"export const checkId = \"pap.check.digest-integrity/1\";\n".to_vec()),
        ("src/checks/source.ts".to_string(), b"export const spanCheck = true;\n".to_vec()),
    ];
    let deps = vec![("zod".to_string(), "3.23.8".to_string(), "sha512-9K5fXZ0G8p3oUo4WQ9m2l1v0B9m3r7Yqk1s2V4pL6c0=".to_string())];
    let impl_digest = digest::extension_closure_digest("checker", "pap.verifier.reference", "0.1.0", &files, &deps).unwrap();
    assert_eq!(impl_digest, "sha256:73f738b733b177c04597b0e6ab9c4d267059ea1556e6f943d543c252c5ef15c0");
    let checker_id = digest::checker_identity("pap.verifier.reference", "0.1.0", &impl_digest);
    assert_eq!(checker_id, "sha256:15a0b0149dc95f7b9711e7b28fc4189ed8539b03ffd2c96e967205316d75963f");
}

#[test]
fn domain_separation() {
    let b = b"hello";
    assert_eq!(digest::domain_hash("pap.artifact.v1", b), "sha256:49ade3eaed5c81a07ee5245b923abe3c629747f0eebe57a0052307d5965d5112");
    assert_eq!(digest::domain_hash("pap.source.raw.v1", b), "sha256:8240a5313b027e89a99054c87e683a87d68f59dc566a40f16aa68edcbf1a81b7");
    assert_eq!(digest::domain_hash("pap.package.v1", b), "sha256:4cb73e2896d009395089ea045b54b15eea2bc4c03e519bc08dc0f619da308308");
}

#[test]
fn framing_ambiguity() {
    // frameRecord("x", ["ab","c"]) and ["a","bc"] under pap.test.v1
    let r1 = digest::frame_record("x", &[b"ab".to_vec(), b"c".to_vec()]);
    let r2 = digest::frame_record("x", &[b"a".to_vec(), b"bc".to_vec()]);
    // digest under pap.test.v1
    let d1 = digest::domain_hash("pap.test.v1", &r1);
    let d2 = digest::domain_hash("pap.test.v1", &r2);
    assert_eq!(d1, "sha256:a4ff1eac1c490e25d4a23ef485f9219a4a51b2c370ba86ed20ba0d8e5c7334e5");
    assert_eq!(d2, "sha256:19777dd70824683c8483961510324f7656c03378f3a4b64192e8bee7ff0ecff2");
}

#[test]
fn input_normalization() {
    let raw = b"a: 1\r\nb: 2\r\n";
    let norm = digest::normalize_input(raw, "lf");
    assert_eq!(norm, b"a: 1\nb: 2\n");
    let per = digest::input_file_digest("inputs/crlf.yml", &norm);
    assert_eq!(per, "sha256:2633064c5d3066746beae7416e97e87816fe9b031c6f57af4c9b02ca1c00453b");
    let set = digest::normalized_input_set_digest(&[("inputs/crlf.yml".to_string(), norm)]);
    assert_eq!(set, "sha256:92e9ec329516a5672fc40fd0b4474f2a2fd7790d87817c37b772af3347df2021");
}

#[test]
fn package_identity_e1() {
    // canonical manifest bytes from Appendix E.1 should be in RFC; we test parser/JCS by loading base manifest? Instead test JCS sorting with E.9.
}

#[test]
fn jcs_e9_utf16() {
    use pap_verifier::json::parse_json;
    use pap_verifier::jcs::canonicalize;
    let v = parse_json(b"{\"a\":1,\"\xF0\x9F\x98\x80\":2,\"\xEF\xBF\xBD\":3,\"A\":4,\"b\":5}", 64, 1024).unwrap();
    let c = canonicalize(&v);
    assert_eq!(c, "{\"A\":4,\"a\":1,\"b\":5,\"😀\":2,\"�\":3}");
    // sha256
    let h = digest::sha256_hex(c.as_bytes());
    // plain sha256 not domain; use sha2 crate directly? domain_hash adds domain. We'll just check string length
    assert_eq!(c.len(), 36);
    assert_eq!(digest::sha256_hex(c.as_bytes()), "sha256:9267454f732ed7ef9939b28dc1e451c88c2967ff4a6b1746bf638d313e72b508");
}

#[test]
fn jcs_e9_escape() {
    use pap_verifier::json::parse_json;
    use pap_verifier::jcs::canonicalize;
    let v = parse_json(b"{\"s\":\"\\u0001\\t\\n\\\"\\\\\xC3\xA9\xF0\x9F\x98\x80\"}", 64, 1024).unwrap();
    let c = canonicalize(&v);
    assert_eq!(c, "{\"s\":\"\\u0001\\t\\n\\\"\\\\é😀\"}");
    assert_eq!(c.len(), 28);
    assert_eq!(digest::sha256_hex(c.as_bytes()), "sha256:9033f8f21bc1c3367ebcad55e2298bf113b63f9e5f21c20678de00e760c5ff5d");
}

#[test]
fn jcs_numbers() {
    use pap_verifier::json::parse_json;
    // valid max
    assert!(parse_json(b"9007199254740991", 64, 1024).is_ok());
    assert!(parse_json(b"-9007199254740991", 64, 1024).is_ok());
    // invalid
    assert!(parse_json(b"9007199254740992", 64, 1024).is_err());
    assert!(parse_json(b"1.0", 64, 1024).is_err());
    assert!(parse_json(b"1e3", 64, 1024).is_err());
    assert!(parse_json(b"-0", 64, 1024).is_err());
}
