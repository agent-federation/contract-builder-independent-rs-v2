//! Report-shape conformance checks (Appendix C) over emitted reports on the
//! base fixture and on the identity-null execution paths. The emitted JSON is
//! validated with the crate's own strict parser plus a structural walk — an
//! independent test of §4.5 "structurally valid report for supported paths".

use std::process::Command;

fn fixture_dir(p: &str) -> String {
    format!("{}/pap/fixtures/pap-v0.1/{p}", env!("CARGO_MANIFEST_DIR"))
}

fn run(cwd: &str, extra: &[&str]) -> pap::json::Json {
    let out = Command::new(env!("CARGO_BIN_EXE_pap"))
        .args(["verify", ".", "--format", "json", "--now", "2026-11-02T00:00:00Z"])
        .args(extra)
        .current_dir(cwd)
        .output()
        .expect("verifier runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    pap::json::parse_document(
        stdout.trim_end_matches('\n').as_bytes(),
        &pap::json::ParserLimits::defaults(),
    )
    .expect("report parses")
}

fn assert_digest_or_null(v: &pap::json::Json, what: &str) {
    match v {
        pap::json::Json::Null => {}
        pap::json::Json::Str(s) => {
            assert!(s.starts_with("sha256:") && s.len() == 71, "{what} format");
        }
        _ => panic!("{what} must be a digest or null"),
    }
}

/// Required top-level members (Appendix C).
const REQUIRED_TOP: &[&str] = &[
    "reportVersion",
    "verifier",
    "package",
    "policy",
    "evaluatedAt",
    "identities",
    "dimensions",
    "checks",
    "coverage",
    "limitations",
    "verdict",
    "diagnostics",
];

const REQUIRED_IDENTITIES: &[&str] = &[
    "packageIdentity",
    "artifacts",
    "sources",
    "normalizedInputDigest",
    "extensionClosureDigest",
    "checkerIdentity",
    "verificationRecordIdentity",
];

const REQUIRED_COVERAGE: &[&str] = &[
    "requiredChecks",
    "checksEvaluated",
    "checksPassed",
    "checksFailed",
    "checksUnsupported",
    "checksNotEvaluated",
    "requiredDimensions",
    "dimensionsEvaluated",
    "full",
];

const VERDICTS: &[&str] = &[
    "PASS",
    "FAIL",
    "UNTRUSTED",
    "UNSUPPORTED",
    "INCOMPLETE",
    "NOT_EVALUATED",
];

const CHECK_OUTCOMES: &[&str] = &["PASS", "FAIL", "UNSUPPORTED", "NOT_EVALUATED"];

#[test]
fn base_report_validates_against_appendix_c_shape() {
    let report = run(
        &fixture_dir("base"),
        &["--trust-policy", &format!("{}/trust-policy/unsigned-valid.json", fixture_dir(""))],
    );
    // reportVersion const
    assert_eq!(
        report.get("reportVersion").and_then(|v| v.as_str()),
        Some("0.1")
    );
    // required top-level members, no unknown top-level members
    let top = report.keys();
    for req in REQUIRED_TOP {
        assert!(top.contains(req), "missing top-level {req}");
    }
    for k in &top {
        assert!(
            *k == "effectiveLimits" || *k == "durationMs" || REQUIRED_TOP.contains(&k),
            "unknown top-level field {k}"
        );
    }
    // verifier block
    let verifier = report.get("verifier").unwrap();
    for req in ["id", "version", "implementationDigest", "checkerIdentities"] {
        assert!(verifier.has(req), "verifier.{req} missing");
    }
    let checker_ids = verifier
        .get("checkerIdentities")
        .and_then(|v| v.as_arr())
        .unwrap();
    assert_eq!(checker_ids.len(), 1, "one-binary verifier has one checker identity");
    assert_digest_or_null(&verifier.get("implementationDigest").unwrap(), "implementationDigest");
    // package block
    let package = report.get("package").unwrap();
    assert!(package.has("identity") && package.has("papVersion"));
    assert_digest_or_null(package.get("identity").unwrap(), "package.identity");
    // policy block: state enum
    let policy = report.get("policy").unwrap();
    assert!(policy.has("state"));
    let state = policy.get("state").and_then(|s| s.as_str()).unwrap();
    assert!(
        state == "FRESH" || state == "STALE" || state == "ABSENT",
        "policy.state enum: {state}"
    );
    // evaluatedAt present
    assert!(report.get("evaluatedAt").and_then(|v| v.as_str()).is_some());
    // identities
    let identities = report.get("identities").unwrap();
    for req in REQUIRED_IDENTITIES {
        assert!(identities.has(req), "identities.{req} missing");
    }
    assert_digest_or_null(identities.get("checkerIdentity").unwrap(), "checkerIdentity");
    assert_digest_or_null(
        identities.get("verificationRecordIdentity").unwrap(),
        "verificationRecordIdentity",
    );
    assert_digest_or_null(identities.get("normalizedInputDigest").unwrap(), "normalizedInput");
    // dimensions: all eight, exact status vocabularies
    let dims = report.get("dimensions").unwrap();
    for req in [
        "integrity",
        "sources",
        "signature",
        "trust",
        "checks",
        "humanReview",
        "semanticTruth",
        "legalEnforceability",
    ] {
        assert!(dims.has(req), "dimensions.{req} missing");
    }
    assert_eq!(
        dims.get("semanticTruth").and_then(|v| v.as_str()),
        Some("NOT_EVALUATED")
    );
    assert_eq!(
        dims.get("legalEnforceability").and_then(|v| v.as_str()),
        Some("NOT_EVALUATED")
    );
    let ip = dims
        .get("integrity")
        .and_then(|i| i.get("package"))
        .and_then(|s| s.as_str())
        .unwrap();
    assert!(ip == "PASS" || ip == "FAIL" || ip == "NOT_EVALUATED", "integrity.package {ip}");
    let sv = dims
        .get("signature")
        .and_then(|s| s.get("validity"))
        .and_then(|s| s.as_str())
        .unwrap();
    assert!(
        sv == "VALID" || sv == "INVALID" || sv == "NOT_EVALUATED" || sv == "NOT_APPLICABLE",
        "signature.validity {sv}"
    );
    let tr = dims.get("trust").unwrap();
    for req in [
        "signerIdentity",
        "policyDecision",
        "checkerRecognition",
        "profileRecognition",
    ] {
        assert!(tr.has(req), "trust.{req} missing");
    }
    let hr = dims.get("humanReview").unwrap();
    let hr_status = hr.get("status").and_then(|s| s.as_str()).unwrap();
    assert!(
        hr_status == "PASS"
            || hr_status == "INCOMPLETE"
            || hr_status == "UNKNOWN"
            || hr_status == "NOT_APPLICABLE"
    );
    // humanReview.basis conditional: required exactly when status is PASS
    if hr_status == "PASS" {
        assert_eq!(hr.get("basis").and_then(|b| b.as_str()), Some("unbound-claim"));
    } else {
        assert!(hr.get("basis").is_none(), "basis must be absent unless PASS");
    }
    // checks rows: enum outcomes with required flag
    for row in dims
        .get("checks")
        .and_then(|c| c.get("results"))
        .and_then(|r| r.as_arr())
        .unwrap_or(&Vec::new())
    {
        let outcome = row.get("outcome").and_then(|o| o.as_str()).unwrap();
        assert!(
            CHECK_OUTCOMES.contains(&outcome),
            "check outcome enum: {outcome}"
        );
        let id = row.get("checkId").and_then(|c| c.as_str()).unwrap();
        assert!(id.starts_with("pap.check."), "checkId shape: {id}");
        assert!(row.has("required"));
    }
    // coverage members and counters
    let coverage = report.get("coverage").unwrap();
    for req in REQUIRED_COVERAGE {
        assert!(coverage.has(req), "coverage.{req} missing");
    }
    let counts: Vec<i64> = [
        "checksEvaluated",
        "checksPassed",
        "checksFailed",
        "checksUnsupported",
        "checksNotEvaluated",
    ]
    .iter()
    .map(|k| coverage.get(k).and_then(|v| v.as_int()).unwrap())
    .collect();
    // partition property of the required-check counters (§7.5)
    assert_eq!(counts[1] + counts[2] + counts[3] + counts[4] > 0, true, "counters partition");
    assert!(matches!(coverage.get("full"), Some(pap::json::Json::Bool(_))));
    // verdict enum
    let verdict = report.get("verdict").and_then(|v| v.as_str()).unwrap();
    assert!(VERDICTS.contains(&verdict), "verdict enum: {verdict}");
    // diagnostics: shape + code pattern + severity enum
    for d in report.get("diagnostics").and_then(|x| x.as_arr()).unwrap_or(&Vec::new()) {
        assert!(d.has("code") && d.has("severity") && d.has("scope") && d.has("message"));
        let code = d.get("code").and_then(|c| c.as_str()).unwrap();
        assert!(code.starts_with("pap."), "diagnostic code {code}");
        let sev = d.get("severity").and_then(|s| s.as_str()).unwrap();
        assert!(sev == "error" || sev == "warning" || sev == "info");
    }
    // limitations: {code, detail}
    for l in report.get("limitations").and_then(|x| x.as_arr()).unwrap_or(&Vec::new()) {
        assert!(l.has("code") && l.has("detail"));
    }
    // checks[] (records) obeys the Phase 2a shape: an unimplemented check has
    // no checker implementation, so no record may exist yet (§8.2).
    assert!(report.get("checks").and_then(|c| c.as_arr()).unwrap().is_empty());
}

#[test]
fn identity_null_report_paths() {
    // F21 (truncated manifest): identity null, verdict FAIL.
    let report = run(&fixture_dir("F21-truncated-manifest"), &[]);
    assert_eq!(report.get("verdict").and_then(|v| v.as_str()), Some("FAIL"));
    assert!(matches!(
        report.get("package").and_then(|p| p.get("identity")),
        Some(pap::json::Json::Null)
    ));
    assert!(matches!(
        report
            .get("identities")
            .and_then(|i| i.get("packageIdentity")),
        Some(pap::json::Json::Null)
    ));
    assert_eq!(
        report
            .get("package")
            .and_then(|p| p.get("papVersion"))
            .map(|v| matches!(v, pap::json::Json::Null))
            .unwrap(),
        true
    );
    // artifacts listed as empty (no reads)
    assert!(matches!(
        report
            .get("identities")
            .and_then(|i| i.get("artifacts"))
            .and_then(|a| a.as_arr()),
        Some(v) if v.is_empty()
    ));
    // dimensions.checks.results empty AND coverage has no required checks (§8.2)
    assert_eq!(
        report
            .get("dimensions")
            .and_then(|d| d.get("checks"))
            .and_then(|c| c.get("results"))
            .and_then(|r| r.as_arr())
            .map(|a| a.is_empty())
            .unwrap(),
        true
    );
    assert_eq!(
        report
            .get("coverage")
            .and_then(|c| c.get("requiredChecks"))
            .and_then(|c| c.as_arr())
            .map(|a| a.is_empty())
            .unwrap(),
        true
    );
    // F60 (missing manifest file)
    let report = run(&fixture_dir("F60-missing-manifest"), &[]);
    assert_eq!(report.get("verdict").and_then(|v| v.as_str()), Some("FAIL"));
    assert!(matches!(
        report.get("package").and_then(|p| p.get("identity")),
        Some(pap::json::Json::Null)
    ));
}

#[test]
fn effective_limits_present_only_when_lowered() {
    // Default limits → absent.
    let report = run(
        &fixture_dir("base"),
        &["--trust-policy", &format!("{}/trust-policy/unsigned-valid.json", fixture_dir(""))],
    );
    assert!(report.get("effectiveLimits").is_none());
    // Lowered limits → object present, integer valued (F52-like; §7.7).
    let report = run(
        &fixture_dir("base"),
        &[
            "--trust-policy",
            &format!("{}/trust-policy/lowered-limits.json", fixture_dir("")),
        ],
    );
    let el = report.get("effectiveLimits").unwrap();
    assert_eq!(el.get("fileBytes").and_then(|v| v.as_int()), Some(64));
    // evaluation limit that is lowered shows in diagnostics as pap.limit.lowered
    let codes: Vec<&str> = report
        .get("diagnostics")
        .and_then(|d| d.as_arr())
        .unwrap()
        .iter()
        .filter_map(|d| d.get("code").and_then(|c| c.as_str()))
        .collect();
    assert!(codes.contains(&"pap.limit.lowered"));
}
