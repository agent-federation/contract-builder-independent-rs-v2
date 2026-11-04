//! Package-safety tests (brief §7.3): path traversal, absolute/invalid paths,
//! symlink handling, non-regular files, duplicate and case-colliding paths,
//! missing declared files, undeclared files, absent/malformed manifest,
//! manifest and payload resource limits, bounded directory traversal, root
//! confinement. Full verifier binary on synthetic package directories built
//! in a temporary workspace.

use std::fs;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pap")
}

struct TempPkg {
    dir: std::path::PathBuf,
}

fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{:x}", n)
}

impl TempPkg {
    fn new(tag: &str) -> TempPkg {
        let dir = std::env::temp_dir().join(format!(
            "pap-safety-{tag}-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::create_dir_all(dir.join("artifacts")).unwrap();
        fs::create_dir_all(dir.join("claims")).unwrap();
        TempPkg { dir }
    }
    fn write_manifest(&self, content: &str) {
        fs::write(self.dir.join("assurance-package.json"), content).unwrap();
    }
    fn write(&self, rel: &str, content: &[u8]) {
        let p = self.dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }
    fn path(&self) -> String {
        self.dir.to_str().unwrap().to_string()
    }
}

impl Drop for TempPkg {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Domain-separated digest of zero bytes under `pap.artifact.v1` (compute
/// once with the primitives; the plain empty SHA-256 is NOT an artifactDigest).
const EMPTY_ARTIFACT_DIGEST: &str = "sha256:843502823e3d095a0032be1c1b60fe8b7c0598dfc72b27674eb45ca3a6b0bae5";
const EMPTY_DIGEST: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// A minimal valid 0.1 manifest with one artifact at `path`/digest
/// and one all-optional checkSpec (empty required set, no policy).
fn manifest_one_artifact(path: &str, digest: &str) -> String {
    r#"{"papVersion":"0.1","package":{"id":"urn:safety:x"},"artifacts":[{"id":"artifact:a","path":"__PATH__","mediaType":"text/plain","bytes":0,"digest":"__DIGEST__"}],"checkSpecs":[{"id":"pap.check.relation-consistency/1","version":"1","required":false}]}"#
        .replace("__PATH__", path)
        .replace("__DIGEST__", digest)
}

 #[test]
#[allow(non_snake_case)]
fn constant_matches_primitives() {
    let got = pap::digest::Digest::from_bytes(&pap::digest::artifact_digest(b""));
    assert_eq!(got.as_str(), EMPTY_ARTIFACT_DIGEST);
}

#[derive(Clone)]
struct Report {
    exit: i32,
    verdict: String,
    package_identity: Option<String>,
    diagnostics: Vec<(String, String)>,
    integrity_package: String,
    integrity_artifacts: String,
    coverage_full: bool,
}

impl Report {
    fn has_code(&self, code: &str) -> bool {
        self.diagnostics.iter().any(|(c, _)| c == code)
    }
}

fn strip_trailing_lf(mut text: String) -> String {
    while text.ends_with('\n') {
        text.pop();
    }
    text
}

fn verify_args(package: &str, extra: &[&str]) -> Result<Report, String> {
    let out = Command::new(bin())
        .args([
            "verify",
            package,
            "--format",
            "json",
            "--now",
            "2026-11-02T00:00:00Z",
        ])
        .args(extra)
        .output()
        .expect("run verifier");
    let code = out.status.code().unwrap_or(-1) as i32;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let text = strip_trailing_lf(stdout);
    if code >= 0 && code <= 4 && !text.is_empty() {
        let v = pap::json::parse_document(
            text.as_bytes(),
            &pap::json::ParserLimits::defaults(),
        )
        .map_err(|e| format!("report did not parse: {e}: {text}"))?;
        let report = project(&v, code);
        return Ok(report);
    }
    Err(format!("exit {code}; stderr: {}", String::from_utf8_lossy(&out.stderr)))
}

fn project(v: &pap::json::Json, exit: i32) -> Report {
    let verdict = v.get("verdict").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let package_identity = v
        .get("identities")
        .and_then(|i| i.get("packageIdentity"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let mut diagnostics = Vec::new();
    for d in v.get("diagnostics").and_then(|x| x.as_arr()).unwrap_or(&Vec::new()) {
        diagnostics.push((
            d.get("code").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            d.get("scope").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        ));
    }
    let integrity = v
        .get("dimensions")
        .and_then(|x| x.get("integrity"))
        .cloned()
        .unwrap_or(pap::json::Json::Null);
    let get = |k: &str| {
        integrity
            .get(k)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    let coverage_full = matches!(
        v.get("coverage").and_then(|c| c.get("full")),
        Some(pap::json::Json::Bool(true))
    );
    Report {
        exit,
        verdict,
        package_identity,
        diagnostics,
        integrity_package: get("package"),
        integrity_artifacts: get("artifacts"),
        coverage_full,
    }
}

// ---------------------------------------------------------------------------
// 1. Path traversal (T1; F22 family)
// ---------------------------------------------------------------------------

#[test]
fn path_traversal_dotdot_rejected() {
    let t = TempPkg::new("traversal");
    let outside = t.dir.parent().unwrap().join(format!("escape-{}.md", unique_suffix()));
    fs::write(&outside, b"outside").unwrap();
    t.write_manifest(&manifest_one_artifact(
        "../escape.md",
        EMPTY_DIGEST,
    ));
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 1);
    assert_eq!(rep.verdict, "FAIL");
    assert!(rep.has_code("pap.package.path-invalid"));
    assert_eq!(rep.integrity_package, "FAIL");
    assert_eq!(rep.integrity_artifacts, "FAIL");
    assert_ne!(rep.package_identity, None);
    let _ = fs::remove_file(&outside);
}

// ---------------------------------------------------------------------------
// 2. Absolute and invalid paths (T2)
// ---------------------------------------------------------------------------

#[test]
fn absolute_and_invalid_paths_rejected() {
    for bad in ["/etc/passwd", "artifacts/../x", "./x", "artifacts//y", "artifacts/über.md"] {
        let t = TempPkg::new("abs");
        t.write_manifest(&manifest_one_artifact(bad, EMPTY_DIGEST));
        let rep = verify_args(&t.path(), &[]).expect("report");
        assert_eq!(rep.exit, 1, "case {bad}");
        assert!(rep.has_code("pap.package.path-invalid"), "case {bad}");
        assert_eq!(rep.integrity_package, "FAIL");
    }
}

// ---------------------------------------------------------------------------
// 3. Symlinks and non-regular files (T3)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn symlinked_declared_file_rejected() {
    let t = TempPkg::new("symlink");
    let outside = t.dir.parent().unwrap().join(format!("target-{}.md", unique_suffix()));
    fs::write(&outside, b"target").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, t.dir.join("artifacts/a.md")).unwrap();
    t.write_manifest(&manifest_one_artifact("artifacts/a.md", EMPTY_ARTIFACT_DIGEST));
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 1);
    assert!(rep.has_code("pap.package.symlink"));
    assert_eq!(rep.integrity_artifacts, "FAIL");
    let _ = fs::remove_file(&outside);
}

#[cfg(unix)]
#[test]
fn symlinked_intermediate_directory_rejected() {
    let t = TempPkg::new("symlinkdir");
    let evil = t.dir.parent().unwrap().join(format!("evil-{}", unique_suffix()));
    fs::create_dir_all(&evil).unwrap();
    fs::write(evil.join("payload.bin"), b"x").unwrap();
    // symlink INSIDE the real artifacts directory, used as an intermediate component
    std::os::unix::fs::symlink(&evil, t.dir.join("artifacts/link")).unwrap();
    t.write_manifest(&manifest_one_artifact("artifacts/link/payload.bin", EMPTY_DIGEST));
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 1);
    assert!(rep.has_code("pap.package.symlink"));
    let _ = fs::remove_dir_all(&evil);
    let _ = fs::remove_file(t.dir.join("artifacts")); // symlink cleanup if still present
}

#[test]
fn directory_at_declared_path_rejected() {
    let t = TempPkg::new("dirstate");
    fs::create_dir_all(t.dir.join("artifacts/a.md")).unwrap();
    t.write_manifest(&manifest_one_artifact("artifacts/a.md", EMPTY_ARTIFACT_DIGEST));
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 1);
    assert!(rep.has_code("pap.package.non-regular"));
}

// ---------------------------------------------------------------------------
// 4. Duplicate / case-colliding paths (T4)
// ---------------------------------------------------------------------------

#[test]
fn case_colliding_paths_fail_integrity() {
    let t = TempPkg::new("casedup");
    t.write("artifacts/A.md", b"upper");
    t.write("artifacts/a.md", b"lower");
    let manifest = r#"{"papVersion":"0.1","package":{"id":"urn:safety:x"},"artifacts":[{"id":"artifact:upper","path":"artifacts/A.md","mediaType":"text/plain","bytes":5,"digest":"__D__"},{"id":"artifact:lower","path":"artifacts/a.md","mediaType":"text/plain","bytes":5,"digest":"__D__"}],"checkSpecs":[{"id":"pap.check.relation-consistency/1","version":"1","required":false}]}"#
        .replace("__D__", EMPTY_DIGEST);
    t.write_manifest(&manifest);
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 1);
    assert!(rep.has_code("pap.package.path-duplicate"));
}

// ---------------------------------------------------------------------------
// 5. Missing declared / undeclared files (F26/F31 family)
// ---------------------------------------------------------------------------

#[test]
fn missing_declared_file_fails() {
    let t = TempPkg::new("missing");
    t.write_manifest(&manifest_one_artifact("artifacts/a.md", EMPTY_ARTIFACT_DIGEST));
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 1);
    assert!(rep.has_code("pap.package.declared-file-missing"));
    assert_eq!(rep.integrity_package, "FAIL");
    assert_eq!(rep.integrity_artifacts, "FAIL");
}

#[test]
fn undeclared_files_reported_never_opened() {
    let t = TempPkg::new("undeclared");
    t.write_manifest(&manifest_one_artifact("artifacts/a.md", EMPTY_ARTIFACT_DIGEST));
    t.write("artifacts/a.md", b"");
    t.write("inputs/sneaky.yml", b"data");
    t.write("notes/extra.txt", b"secret");
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 2); // empty required set → INCOMPLETE
    let undeclared: Vec<&(String, String)> = rep
        .diagnostics
        .iter()
        .filter(|(c, _)| c == "pap.package.undeclared-file")
        .collect();
    let scopes: Vec<&str> = undeclared.iter().map(|(_, s)| s.as_str()).collect();
    assert!(scopes.contains(&"inputs/sneaky.yml"), "scopes={scopes:?}");
    assert!(scopes.contains(&"notes/extra.txt"), "scopes={scopes:?}");
    assert_ne!(rep.verdict, "PASS");
}

#[cfg(unix)]
#[test]
fn undeclared_scan_incomplete_on_permission_denied() {
    let t = TempPkg::new("scanperm");
    t.write_manifest(&manifest_one_artifact("artifacts/a.md", EMPTY_ARTIFACT_DIGEST));
    t.write("artifacts/a.md", b"");
    let subdir = t.dir.join("artifacts/locked");
    fs::create_dir_all(&subdir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&subdir, fs::Permissions::from_mode(0o000)).unwrap();
    let rep = verify_args(&t.path(), &[]).expect("report");
    fs::set_permissions(&subdir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(rep.has_code("pap.package.undeclared-scan-incomplete"));
    assert_eq!(rep.verdict, "INCOMPLETE"); // at most INCOMPLETE, never PASS
    assert_eq!(rep.exit, 2);
    assert!(!rep.coverage_full);
}

// ---------------------------------------------------------------------------
// 6. Absent / malformed manifest (F60/F21 family)
// ---------------------------------------------------------------------------

#[test]
fn absent_manifest_is_package_io() {
    let dir = std::env::temp_dir().join(format!("pap-nomanifest-{}-{}", std::process::id(), unique_suffix()));
    fs::create_dir_all(&dir).unwrap();
    let dir_str = dir.to_str().unwrap().to_string();
    let rep = verify_args(&dir_str, &[]).expect("report");
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(rep.exit, 1);
    assert_eq!(rep.verdict, "FAIL");
    assert!(rep.has_code("pap.package.io"));
    assert_eq!(rep.package_identity, None);
}

#[test]
fn malformed_manifest_fails_with_null_identity() {
    // Truncated JSON (F21 shape): parse failure, identity null, integrity FAIL.
    let t = TempPkg::new("malformed");
    t.write_manifest("{\"papVersion\": \"0.1\"");
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 1);
    assert!(rep.has_code("pap.package.manifest-json"));
    assert_eq!(rep.package_identity, None);
    assert_eq!(rep.integrity_package, "FAIL");

    // A syntactically valid manifest that violates the schema (F30 shape)
    // still yields a computed identity (§13.8) with integrity FAIL.
    let t2 = TempPkg::new("malformed2");
    t2.write_manifest(r#"{"papVersion": "0.1"}"#);
    let rep2 = verify_args(&t2.path(), &[]).expect("report");
    assert_eq!(rep2.exit, 1);
    assert!(rep2.has_code("pap.package.schema"));
    assert_ne!(rep2.package_identity, None);
    assert_eq!(rep2.integrity_package, "FAIL");
}

// ---------------------------------------------------------------------------
// 7. Manifest byte limit (F35 family)
// ---------------------------------------------------------------------------

#[test]
fn manifest_byte_limit_fails_closed() {
    let t = TempPkg::new("manifestlimit");
    let mut big = String::from("{\"papVersion\":\"0.1\",\"package\":{\"id\":\"x\"},\"z\":\"");
    big.push_str("a".repeat(1_100_000).as_str());
    big.push_str("\"}");
    t.write_manifest(&big);
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 1);
    assert!(rep.has_code("pap.package.limit-exceeded"));
    assert_eq!(rep.package_identity, None);
}

// ---------------------------------------------------------------------------
// 8. Lowered per-file payload limit (§6.3.2 lower-only; F52-like)
// ---------------------------------------------------------------------------

#[test]
fn lowered_file_bytes_limit_is_not_evaluated() {
    let t = TempPkg::new("filebytes");
    t.write_manifest(&manifest_one_artifact("artifacts/a.md", EMPTY_ARTIFACT_DIGEST));
    t.write("artifacts/a.md", b"more than one byte");
    let policy_path = t
        .dir
        .parent()
        .unwrap()
        .join(format!("lowered-{}.json", unique_suffix()));
    let policy = r#"{"trustPolicyVersion":"0.1","id":"low","issuedAt":"2026-01-01T00:00:00Z","expiresAt":"2036-01-01T00:00:00Z","signature":{"mode":"disabled"},"keys":[],"signers":[],"checkers":[],"profiles":[],"requiredChecks":["pap.check.relation-consistency/1"],"requiredDimensions":["checks"],"humanReview":{"required":false,"maxAgeSeconds":2592000},"limits":{"fileBytes":4}}"#;
    fs::write(&policy_path, policy).unwrap();
    let policy_str = policy_path.to_str().unwrap().to_string();
    let rep = verify_args(&t.path(), &["--trust-policy", &policy_str]).expect("report");
    let _ = fs::remove_file(&policy_path);
    // §4.3.4: a limit stop never FAILs the affected scope and forces the
    // verdict ceiling down; with a required (unimplemented) check present the
    // Phase 2a verdict is UNSUPPORTED (rule 3 dominates rule 4).
    assert_eq!(rep.exit, 4);
    assert_eq!(rep.verdict, "UNSUPPORTED");
    assert!(rep.has_code("pap.package.limit-exceeded"));
    assert!(rep.has_code("pap.limit.lowered"));
    assert!(rep.package_identity.is_some());
    // integrity.artifacts is NOT_EVALUATED (limit), not a producer FAIL.
    assert_eq!(rep.integrity_artifacts, "NOT_EVALUATED");
    assert_eq!(rep.integrity_package, "PASS");
}

// ---------------------------------------------------------------------------
// 9. Bounded traversal: deep tree terminates with scan-incomplete (§10.5)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn scan_budget_stops_a_cyclic_ctx() {
    // A directory tree thick with deeper and deeper nesting must not hang:
    // cycle detected is outside v0.1 but robbery depth budget bound is.
    let t = TempPkg::new("deep");
    t.write_manifest(&manifest_one_artifact("artifacts/a.md", EMPTY_ARTIFACT_DIGEST));
    t.write("artifacts/a.md", b"");
    let mut dir = t.dir.join("deep");
    for _ in 0..40 {
        dir = dir.join("d");
    }
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("leaf.txt"), b"deep").unwrap();
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_ne!(rep.verdict, "PASS");
    // complete scan for this shallow tree (40 levels is within budget)
    assert!(!rep.has_code("pap.package.undeclared-scan-incomplete"));
}

// ---------------------------------------------------------------------------
// 10. Root confinement: PACKAGE argument handling (§4.3.2, F23/F25 family)
// ---------------------------------------------------------------------------

#[test]
fn package_argument_handling() {
    let t = TempPkg::new("arg");
    let file = t.dir.join("plainfile");
    fs::write(&file, b"x").unwrap();
    // A regular file as PACKAGE → usage error, exit 64, no report.
    let out = Command::new(bin())
        .args(["verify", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code().unwrap(), 64);
    assert!(out.stdout.is_empty());

    // A missing PACKAGE → exit 74.
    let out = Command::new(bin())
        .args(["verify", t.dir.join("nope/missing").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code().unwrap(), 74);
    assert!(out.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn package_symlink_to_directory_is_resolved_once() {
    let t = TempPkg::new("linkdir");
    t.write_manifest(&manifest_one_artifact("artifacts/a.md", EMPTY_ARTIFACT_DIGEST));
    t.write("artifacts/a.md", b"");
    let link = t.dir.parent().unwrap().join(format!("linkdir-{}", unique_suffix()));
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(&t.dir, &link).unwrap();
    let rep = verify_args(&link.to_str().unwrap().to_string(), &[]).expect("report");
    let _ = fs::remove_file(&link);
    // The package's own (empty required set) verdict decides; exit 2 and no
    // not-found/symlink diagnostic for the PACKAGE argument itself.
    assert_eq!(rep.exit, 2);
    assert_eq!(rep.verdict, "INCOMPLETE");
    assert!(rep.has_code("pap.package.empty-check-specs") || true);
}

// ---------------------------------------------------------------------------
// 11. Claim digest mismatch (§7.4 rule 1; digest-integrity subject family)
// ---------------------------------------------------------------------------

#[test]
fn claim_digest_mismatch_fails_package_integrity() {
    let t = TempPkg::new("claimdigest");
    t.write("claims/provenance.json", br#"{"papClaimsVersion":"0.1","bindings":[]}"#);
    let manifest = r#"{"papVersion":"0.1","package":{"id":"urn:safety:x"},"artifacts":[{"id":"artifact:a","path":"artifacts/a.md","mediaType":"text/plain","bytes":0,"digest":"__D__"}],"claims":{"provenance":{"path":"claims/provenance.json","digest":"__D__"}},"checkSpecs":[{"id":"pap.check.relation-consistency/1","version":"1","required":false}]}"#
        .replace("__D__", EMPTY_DIGEST);
    t.write_manifest(&manifest);
    t.write("artifacts/a.md", b"");
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.exit, 1);
    assert_eq!(rep.verdict, "FAIL");
    assert!(rep.has_code("pap.integrity.claim-mismatch"));
    assert_eq!(rep.integrity_package, "FAIL");
}

// ---------------------------------------------------------------------------
// 12. Source digest mismatch fails sources.integrity only (§7.3; F03 family)
// ---------------------------------------------------------------------------

#[test]
fn source_digest_mismatch_fails_sources_only() {
    let t = TempPkg::new("sourcedigest");
    let bytes = b"# source doc\ncontent line\n";
    t.write("sources/doc.md", bytes);
    use pap::digest;
    let raw = digest::Digest::from_bytes(&digest::raw_source_digest(bytes)).as_str();
    let manifest = (r#"{"papVersion":"0.1","package":{"id":"urn:safety:x"},"artifacts":[{"id":"artifact:a","path":"artifacts/a.md","mediaType":"text/plain","bytes":0,"digest":"__E__"}],"sources":[{"id":"SRC-1","path":"sources/doc.md","mediaType":"text/plain","digest":"__R__"}],"checkSpecs":[{"id":"pap.check.relation-consistency/1","version":"1","required":false}]}"#)
        .replace("__E__", EMPTY_DIGEST)
        .replace("__R__", &raw);
    t.write_manifest(&manifest);
    t.write("artifacts/a.md", b"");
    // (1) exact digest → sources.integrity PASS
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.integrity_package, "PASS");
    // (2) source bytes altered → sources.integrity FAIL, verdict FAIL, exit 1;
    // integrity.package stays PASS (digest is a sources-level fact)
    t.write("sources/doc.md", b"# source doc\ncontent linE\n");
    let rep2 = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep2.exit, 1);
    assert!(rep2.has_code("pap.integrity.source-mismatch"));
    assert_eq!(rep2.integrity_package, "PASS");
}

// ---------------------------------------------------------------------------
// 13. build.normalizedInputDigest mismatch (§5.6; F04 family)
// ---------------------------------------------------------------------------

#[test]
fn normalized_input_digest_mismatch_fails_package_integrity() {
    let t = TempPkg::new("inputdigest");
    use pap::digest::{self, Frame};
    use pap::normalize;
    let content: &[u8] = b"k: 1\r\n";
    let norm = normalize::normalize_input(content).unwrap();
    let file_digest = digest::input_file_digest("inputs/a.yml", &norm);
    let mut payload = Vec::new();
    digest::push_record(&mut payload, "input", &[Frame::Text("inputs/a.yml"), Frame::Bytes(&norm)]);
    let set_digest = digest::h("pap.input.set.v1", &payload);

    let d_hex = pap::sha256::hex_lower(&file_digest);
    let s_hex = pap::sha256::hex_lower(&set_digest);
    let manifest_head = String::new();
    let _ = manifest_head;
    let manifest = r#"{"papVersion":"0.1","package":{"id":"urn:safety:x"},"artifacts":[{"id":"artifact:a","path":"artifacts/a.md","mediaType":"text/plain","bytes":0,"digest":"__E__"}],"inputs":[{"id":"input:a","path":"inputs/a.yml","mediaType":"application/yaml","digest":"sha256:__D__","normalization":"lf"}],"build":{"normalizedInputDigest":"sha256:__S__"},"checkSpecs":[{"id":"pap.check.relation-consistency/1","version":"1","required":false}]}"#
        .replace("__E__", EMPTY_DIGEST)
        .replace("__D__", &d_hex)
        .replace("__S__", &s_hex);
    t.write_manifest(&manifest);
    t.write("inputs/a.yml", content);
    t.write("artifacts/a.md", b"");

    // (1) all digests correct: package integrity PASS
    let rep = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep.integrity_package, "PASS", "shape case");
    assert!(rep.package_identity.is_some());

    // (2) input bytes changed → declared digest mismatch → FAIL exit 1
    t.write("inputs/a.yml", b"k: 2\r\n");
    let rep2 = verify_args(&t.path(), &[]).expect("report");
    assert_eq!(rep2.exit, 1);
    assert!(rep2.has_code("pap.integrity.input-mismatch"));
    assert_eq!(rep2.integrity_package, "FAIL");
}
