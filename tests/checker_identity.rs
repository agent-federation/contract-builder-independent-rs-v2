//! Checker identity tests (brief §4.4.1): Appendix E.3 constants, the
//! in-binary identity construction, and the closure contents rules (tracked
//! text files only; tests/fixtures/docs excluded).

use pap::checker;
use pap::digest;
use pap::sha256::hex_lower;

#[test]
fn e3_vector_values_are_reproducible_without_the_binary_closure() {
    // The Appendix E.3 closure (digest.ts/source.ts/zod) reproduces both
    // published values with this implementation's digest primitives (also
    // asserted in tests/vectors.rs; repeated here as part of the checker
    // identity contract).
    let mut records: Vec<u8> = Vec::new();
    digest::push_record(
        &mut records,
        "extension",
        &[
            digest::Frame::Text("checker"),
            digest::Frame::Text("pap.verifier.reference"),
            digest::Frame::Text("0.1.0"),
        ],
    );
    digest::push_record(
        &mut records,
        "file",
        &[
            digest::Frame::Text("src/checks/digest.ts"),
            digest::Frame::Bytes(
                b"export const checkId = \"pap.check.digest-integrity/1\";\n".as_slice(),
            ),
        ],
    );
    digest::push_record(
        &mut records,
        "file",
        &[
            digest::Frame::Text("src/checks/source.ts"),
            digest::Frame::Bytes(b"export const spanCheck = true;\n".as_slice()),
        ],
    );
    digest::push_record(
        &mut records,
        "dependency",
        &[
            digest::Frame::Text("zod"),
            digest::Frame::Text("3.23.8"),
            digest::Frame::Text("sha512-9K5fXZ0G8p3oUo4WQ9m2l1v0B9m3r7Yqk1s2V4pL6c0="),
        ],
    );
    let impl_digest = digest::extension_closure_digest(&records);
    assert_eq!(
        hex_lower(&impl_digest),
        "73f738b733b177c04597b0e6ab9c4d267059ea1556e6f943d543c252c5ef15c0"
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
}

#[test]
fn binary_identity_well_formed_and_deterministic() {
    assert_eq!(checker::verifier_id(), "pap.verifier.rust");
    assert_eq!(checker::verifier_version(), "0.1.0");
    let impl_digest = checker::implementation_digest();
    assert!(
        impl_digest.0.iter().any(|b| *b != 0),
        "build.rs must embed a real digest"
    );
    // checkerIdentity == H("pap.checker.identity.v1", JCS({id, version, implementationDigest}))
    let expected = digest::checker_identity(
        checker::verifier_id(),
        checker::verifier_version(),
        checker::IMPLEMENTATION_DIGEST,
    );
    assert_eq!(expected, checker::checker_identity().0);
    // Deterministic across repeated calls within the same build.
    assert_eq!(checker::implementation_digest(), checker::implementation_digest());
}

#[test]
fn closure_contents_follow_the_tracked_rules() {
    let files = checker::closure_files();
    // Included: build manifests, lockfile, build script, all src files.
    assert!(files.contains(&"Cargo.toml"));
    assert!(files.contains(&"Cargo.lock"));
    assert!(files.contains(&"build.rs"));
    assert!(files.iter().all(|f| *f != "README.md"));
    assert!(files.iter().all(|f| !f.starts_with("tests/")));
    assert!(files.iter().all(|f| !f.starts_with("docs/")));
    for f in files {
        assert!(
            f.starts_with("src/")
                || f.ends_with(".rs")
                || f.ends_with(".toml")
                || *f == "Cargo.lock",
            "unexpected closure member {f}"
        );
        // sorted ascending by UTF-8 byte order
    }
    let mut sorted: Vec<&str> = files.to_vec();
    sorted.sort();
    assert_eq!(files, sorted.as_slice(), "closure files must be sorted");
    // No third-party dependencies are in scope for this pure-std build.
    assert!(checker::closure_dependencies().is_empty());
}

#[test]
fn identifier_fields_match_the_report_contract() {
    // verifier.id/version must be the same constants the report uses
    // (RFC §5.8; brief §4.4.1).
    assert!(checker::VERIFIER_ID.starts_with("pap.verifier."));
    assert_eq!(checker::VERIFIER_VERSION, "0.1.0");
    assert_eq!(checker::IMPLEMENTATION_DIGEST.len(), 71); // "sha256:" + 64
    assert!(checker::IMPLEMENTATION_DIGEST.starts_with("sha256:"));
    assert!(checker::CHECKER_IDENTITY.starts_with("sha256:"));
}
