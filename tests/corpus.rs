//! RFC §12 corpus runner scoped to the Phase 2a comparison set
//! (`pap/fixtures/pap-v0.1/cases-phase2a.json`).
//!
//! Profiles (from the published Phase 2a scope document):
//! - `full`     — compares exit code, verdict, the applicable diagnostic-code
//!                subset (`pap.check.*` codes exempt), the constrained
//!                `integrity.package`/`integrity.artifacts` statuses from the
//!                normative `cases.json` corpus, and the exact packageIdentity.
//! - `identityOnly` — compares only the exact packageIdentity literal.
//! - `excluded` — later-phase cases (F25/F37–F39/F41/F42); not claimed here.
//!
//! Every report-producing command must emit exactly one JCS document plus one
//! LF with empty stderr; the full-profile cases are run twice to confirm
//! byte-identical determinism under a fixed `--now` (F36 rule).

use std::process::Command;

fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pap/fixtures/pap-v0.1")
}

struct CaseSelection {
    id: String,
    profile: String,
    command: Vec<String>,
    phase2a: pap::json::Json,
    cases_expect: pap::json::Json,
}

fn load_cases() -> Vec<CaseSelection> {
    let corpus = std::fs::read(fixture_dir().join("cases.json")).expect("cases.json");
    let cases: pap::json::Json =
        pap::json::parse_document(&corpus, &pap::json::ParserLimits::defaults()).unwrap();
    let phase = std::fs::read(fixture_dir().join("cases-phase2a.json")).expect("cases-phase2a.json");
    let phase2a: pap::json::Json =
        pap::json::parse_document(&phase, &pap::json::ParserLimits::defaults()).unwrap();

    let mut out = Vec::new();
    for c in cases.get("cases").and_then(|v| v.as_arr()).unwrap() {
        let id = c.get("caseId").and_then(|v| v.as_str()).unwrap().to_string();
        let entry = match c.get("expect") {
            Some(e) => e.clone(),
            None => pap::json::Json::Null,
        };
        let command: Vec<String> = c
            .get("command")
            .and_then(|v| v.as_arr())
            .map(|arr| {
                arr.iter()
                    .map(|x| x.as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default();
        out.push(CaseSelection {
            id: id.clone(),
            profile: phase2a_case_profile(&phase2a, &id),
            command,
            phase2a: phase2a_case_entry(&phase2a, &id),
            cases_expect: entry,
        });
    }
    out
}

fn phase2a_case_entry(phase2a: &pap::json::Json, id: &str) -> pap::json::Json {
    phase2a
        .get("cases")
        .and_then(|m| m.get(id))
        .cloned()
        .unwrap_or(pap::json::Json::Null)
}

fn phase2a_case_profile(phase2a: &pap::json::Json, id: &str) -> String {
    phase2a_case_entry(phase2a, id)
        .get("profile")
        .and_then(|p| p.as_str())
        .unwrap_or("excluded")
        .to_string()
}

fn run_case(sel: &CaseSelection) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_pap"))
        .args(&sel.command)
        .current_dir(fixture_dir().join(&sel.id))
        .output()
        .expect("spawn verifier");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn round(run: &CaseSelection) {
    let profile = run.profile.as_str();
    assert!(
        profile == "full" || profile == "identityOnly",
        "{} excluded from Phase 2a (later phase); not tested here",
        run.id
    );

    let (code, stdout, stderr) = run_case(run);

    // Stream discipline for report-producing exits: stdout is exactly one
    // JCS document + one LF; stderr empty (§9.6/§9.7 subset; the compared
    // commands all declare --format json).
    assert_eq!(stderr, "", "{}: stderr must be empty on report exits", run.id);
    assert!(
        stdout.ends_with('\n') && !stdout.ends_with("\n\n"),
        "{}: stdout must end with exactly one LF",
        run.id
    );
    let body = stdout.trim_end_matches('\n');
    let report: pap::json::Json = pap::json::parse_document(
        body.as_bytes(),
        &pap::json::ParserLimits::defaults(),
    )
    .unwrap_or_else(|e| panic!("{}: report did not parse: {e}: {body}", run.id));
    // JCS-canonical bytes: re-canonicalizing the parsed report is a fixed
    // point (RFC §9.6: exactly one JCS document).
    let recanon = pap::jcs::to_canonical(&report);
    assert_eq!(recanon, body, "{}: stdout is not JCS-canonical", run.id);

    // packageIdentity comparison (both profiles)
    let identity_field = "packageIdentity";
    let expect_ident = run
        .phase2a
        .get(identity_field)
        .map(|v| match v {
            pap::json::Json::Str(s) => Some(s.clone()),
            pap::json::Json::Null => None,
            _ => None,
        })
        .flatten();
    let got_package_level = report
        .get("package")
        .and_then(|p| p.get("identity"))
        .map(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or(None);
    let got_identities_level = report
        .get("identities")
        .and_then(|i| i.get(identity_field))
        .map(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or(None);
    assert_eq!(
        got_package_level, got_identities_level,
        "{}: package.identity and identities.packageIdentity disagree",
        run.id
    );
    match expect_ident {
        Some(want) => assert_eq!(
            got_package_level,
            Some(want.clone()),
            "{}: packageIdentity differs from the normative literal",
            run.id
        ),
        None => assert!(
            got_package_level.is_none(),
            "{}: expected a null packageIdentity, got {got_package_level:?}",
            run.id
        ),
    }

    // Diagnostic-code subset (full profile; pap.check.* exempt)
    if profile == "full" {
        let applicable: Vec<String> = run
            .phase2a
            .get("applicableDiagnosticCodes")
            .and_then(|v| v.as_arr())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let emitted: Vec<String> = report
            .get("diagnostics")
            .and_then(|d| d.as_arr())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| d.get("code").and_then(|c| c.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        for want in &applicable {
            assert!(
                emitted.contains(want),
                "{}: expected diagnostic code {want} in {emitted:?}",
                run.id
            );
        }

        // verdict + exit code per the normative RFC §12.4 corpus row
        let expect_verdict = run
            .cases_expect
            .get("verdict")
            .and_then(|v| v.as_str())
            .expect("corpus verdict");
        let expect_exit = run
            .cases_expect
            .get("exitCode")
            .and_then(|v| v.as_int())
            .expect("corpus exitCode");
        assert_eq!(
            code, expect_exit as i32,
            "{}: exit code differs (expected {expect_exit})",
            run.id
        );
        assert_eq!(
            report
                .get("verdict")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            expect_verdict,
            "{}: verdict differs",
            run.id
        );

        // constrained integrity dimensions from the corpus row
        let dims = run
            .cases_expect
            .get("dimensions")
            .and_then(|d| d.as_obj())
            .cloned()
            .unwrap_or_default();
        for (name, want) in dims {
            match name.as_str() {
                "integrity.package" => {
                    let got = report
                        .get("dimensions")
                        .and_then(|d| d.get("integrity"))
                        .and_then(|i| i.get("package"))
                        .and_then(|s| s.as_str())
                        .unwrap_or_default();
                    assert_eq!(
                        got,
                        want.as_str().unwrap_or_default(),
                        "{}: integrity.package differs",
                        run.id
                    );
                }
                "integrity.artifacts" => {
                    let got = report
                        .get("dimensions")
                        .and_then(|d| d.get("integrity"))
                        .and_then(|i| i.get("artifacts"))
                        .and_then(|s| s.as_str())
                        .unwrap_or_default();
                    assert_eq!(
                        got,
                        want.as_str().unwrap_or_default(),
                        "{}: integrity.artifacts differs",
                        run.id
                    );
                }
                // other fields (checks, trust, signature, humanReview) are
                // outside the Phase 2a comparison scope
                _ => {}
            }
        }

        // determinism: run twice, byte-identical stdout under fixed --now
        let (code2, stdout2, stderr2) = run_case(run);
        assert_eq!(code2, code, "{}: nondeterministic exit", run.id);
        assert_eq!(stdout2, stdout, "{}: nondeterministic stdout", run.id);
        assert_eq!(stderr2, stderr, "{}: nondeterministic stderr", run.id);
    }
}

#[test]
fn corpus_phase2a_selection() {
    let cases = load_cases();
    let mut full = 0usize;
    let mut identity_only = 0usize;
    let mut excluded = 0usize;
    for c in &cases {
        match c.profile.as_str() {
            "full" => full += 1,
            "identityOnly" => identity_only += 1,
            _ => excluded += 1,
        }
    }
    assert_eq!(full, 19, "full-profile count");
    assert_eq!(identity_only, 36, "identityOnly count");
    assert_eq!(excluded, 6, "excluded count");
}

#[test]
fn corpus_full_and_identity_cases() {
    let cases = load_cases();
    assert_eq!(cases.len(), 61, "the normative corpus has 61 cases");
    let mut ran = 0usize;
    for sel in &cases {
        // F36-determinism is the same command as F01; it is covered by the
        // double-run inside every full case, and compared identity-only here.
        if sel.profile == "excluded" {
            continue; // later-phase cases are not claimed as 2a acceptance
        }
        round(sel);
        ran += 1;
    }
    assert_eq!(ran, 55, "55 Phase 2a-comparable cases ran");
}

#[test]
fn corpus_excluded_later_phase_cases() {
    let cases = load_cases();
    let excluded: Vec<&CaseSelection> = cases
        .iter()
        .filter(|c| c.profile == "excluded")
        .collect();
    let ids: Vec<String> = excluded.iter().map(|c| c.id.clone()).collect();
    assert_eq!(
        ids,
        vec![
            "F25-archive",
            "F37-inspect-usage",
            "F38-explain-usage",
            "F39-explain-unknown",
            "F41-invalid-policy",
            "F42-explain-positive"
        ]
    );
    // All excluded cases name their owning phase in the scope document.
    for e in &excluded {
        assert!(
            e.phase2a.get("owningPhase").is_some(),
            "{}: excluded case without owningPhase",
            e.id
        );
    }
}
