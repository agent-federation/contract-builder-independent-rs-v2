//! Appendix C report construction, verification-record identity (§5.9) and
//! Phase 2a report foundations.
//!
//! The Phase 2a report is a structurally valid Appendix C document for the
//! supported execution paths. Check evaluation (three §8 checks), claim-file
//! content validation, producer-claim comparison and signature verification
//! are later-phase scope: every unimplemented capability is reported as
//! `UNSUPPORTED` (required) or `NOT_EVALUATED`/`NOT_APPLICABLE` (optional or
//! absent) — never as a positive result, so no false `PASS` is possible
//! (§7.4, §13.1).

use crate::checker;
use crate::diag::{self, Diagnostic, Limitation, Severity};
use crate::digest::{self, Digest};
use crate::json::{Json, ParseErrorKind};
use crate::limits::DEFAULT as DEFAULT_LIMITS;
use crate::manifest::{CheckSpec, Compat};
use crate::pkg::{PackageState, PayloadKind, PayloadResult, TerminalError, VerifyInput};
use crate::policy::PolicyState;
use crate::verdict::{
    self, CheckResult, Dim3, DimensionStatuses, HumanReview, Recognition,
    SigValidity, SourcesAvailability, SourcesIntegrity, TrustPolicyDecision, TrustSigner,
    VerdictContext,
};
use crate::rfc3339;

const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Digest of a report identity form (§5.9).
pub struct ReportIdentity(pub Digest);

/// Compute the identity form of a report (§5.9): the report with the excluded
/// fields removed and `identities.verificationRecordIdentity` replaced by the
/// zero placeholder, canonicalized with JCS.
pub fn identity_form(report: &Json) -> Json {
    let mut form = report.clone();
    exclude_identity_fields(&mut form);
    form
}

fn exclude_identity_fields(form: &mut Json) {
    let top_remove = ["evaluatedAt", "durationMs", "producerClaims"];
    if let Json::Obj(m) = form {
        m.retain(|(k, _)| !top_remove.contains(&k.as_str()));
        for (k, v) in m.iter_mut() {
            match k.as_str() {
                "package" | "policy" => {
                    if let Json::Obj(inner) = v {
                        inner.retain(|(ik, _)| ik != "path");
                    }
                }
                "diagnostics" => {
                    if let Json::Arr(items) = v {
                        for it in items.iter_mut() {
                            if let Json::Obj(dm) = it {
                                dm.retain(|(ik, _)| ik != "message");
                            }
                        }
                    }
                }
                "checks" => {
                    // checks[].diagnostics[].message and
                    // checks[].witnesses[].quoteBase64
                    if let Json::Arr(items) = v {
                        for it in items.iter_mut() {
                            if let Json::Obj(cr) = it {
                                for (ck, cv) in cr.iter_mut() {
                                    match ck.as_str() {
                                        "diagnostics" => {
                                            if let Json::Arr(ds) = cv {
                                                for d in ds.iter_mut() {
                                                    if let Json::Obj(do_) = d {
                                                        do_.retain(|(ik, _)| ik != "message");
                                                    }
                                                }
                                            }
                                        }
                                        "witnesses" => {
                                            if let Json::Arr(ws) = cv {
                                                for w in ws.iter_mut() {
                                                    if let Json::Obj(wo) = w {
                                                        wo.retain(|(ik, _)| ik != "quoteBase64");
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // The record cannot contain its own hash: replace the field with the
    // fixed zero placeholder (§5.9 step 3).
    if let Json::Obj(m) = form {
        for (k, v) in m.iter_mut() {
            if k == "identities" {
                if let Json::Obj(im) = v {
                    if let Some(slot) = im
                        .iter_mut()
                        .find(|(ik, _)| ik == "verificationRecordIdentity")
                    {
                        slot.1 = Json::Str(ZERO_DIGEST.to_string());
                    } else {
                        im.push((
                            "verificationRecordIdentity".to_string(),
                            Json::Str(ZERO_DIGEST.to_string()),
                        ));
                    }
                }
            }
        }
    }
}

/// Build the full Phase 2a report and exit-code decision.
pub fn build_report(state: &PackageState, input: &VerifyInput) -> Result<crate::pkg::VerifyOutput, TerminalError> {
    // ------------------------------------------------------------------
    // Part 1 — gather everything that determines statuses and diagnostics.
    // ------------------------------------------------------------------
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut limitations: Vec<Limitation> = Vec::new();

    let outcome = state.outcome.as_ref();
    let manifest_valid = outcome.and_then(|o| o.manifest.as_ref());

    // ---- manifest read/parse errors ----
    if let Some((code, message)) = &state.manifest_error {
        diagnostics.push(Diagnostic::new(
            if *code == "pap.package.limit-exceeded" {
                "pap.package.limit-exceeded"
            } else {
                "pap.package.io"
            },
            Severity::Error,
            "assurance-package.json",
            message.clone(),
        ));
    }
    if let Some(kind) = &state.parse_error {
        let code = match kind {
            ParseErrorKind::DuplicateKey => "pap.package.duplicate-key",
            ParseErrorKind::DepthLimit | ParseErrorKind::StringLimit => "pap.package.limit-exceeded",
            _ => "pap.package.manifest-json",
        };
        // A note on the same inner scope for human messages.
        let detail = match kind {
            ParseErrorKind::Bom => "manifest begins with a byte-order mark",
            ParseErrorKind::NotUtf8 => "manifest is not valid UTF-8",
            ParseErrorKind::TrailingData => "manifest has trailing data after the JSON value",
            ParseErrorKind::InvalidJson => "manifest is not valid I-JSON",
            ParseErrorKind::DuplicateKey => "manifest repeats an object member name",
            ParseErrorKind::DepthLimit => "manifest nesting exceeds the jsonNesting limit",
            ParseErrorKind::StringLimit => "manifest string exceeds the jsonStringBytes limit",
        };
        diagnostics.push(Diagnostic::new(
            code,
            Severity::Error,
            "assurance-package.json",
            detail.to_string(),
        ));
    }

    // ---- manifest validation diagnostics ----
    if let Some(outcome) = &state.outcome {
        diagnostics.extend(outcome.diagnostics.iter().cloned());
    }

    // ---- payload-level diagnostics ----
    for res in &state.payload_results {
        if let Some(f) = &res.failure {
            let (code, message) = match f {
                crate::pkg::FileFailure::Missing => (
                    "pap.package.declared-file-missing",
                    format!("declared file is missing: {}", res.path),
                ),
                crate::pkg::FileFailure::Io => (
                    "pap.package.io",
                    format!("cannot read declared file: {}", res.path),
                ),
                crate::pkg::FileFailure::Symlink => (
                    "pap.package.symlink",
                    format!("declared path is a symbolic link: {}", res.path),
                ),
                crate::pkg::FileFailure::NonRegular => (
                    "pap.package.non-regular",
                    format!("declared path is not a regular file: {}", res.path),
                ),
            };
            diagnostics.push(Diagnostic::new(code, Severity::Error, &res.path, message));
        }
        if let Some(code) = &res.mismatch {
            diagnostics.push(Diagnostic::new(
                code,
                Severity::Error,
                &res.id,
                format!("declared digest does not match recomputed bytes ({})", res.path),
            ));
        }
        if res.unread_by_limit {
            // The per-stop diagnostics are emitted from state.limit_stops.
        }
    }

    // ---- limit stops ----
    for stop in &state.limit_stops {
        diagnostics.push(Diagnostic::new(
            "pap.package.limit-exceeded",
            Severity::Error,
            stop.classes,
            format!(
                "limit {name} exceeded; observed {observed}; affected scope: {classes}",
                name = stop.limit_name,
                observed = stop.observed,
                classes = stop.classes
            ),
        ));
    }

    // ---- undeclared-file scan ----
    let mut scan_completed = true;
    if let Some(scan) = &state.scan {
        scan_completed = scan.completed;
        for path in &scan.undeclared {
            diagnostics.push(Diagnostic::new(
                "pap.package.undeclared-file",
                Severity::Warning,
                path,
                format!("undeclared file is present and was not read: {path}"),
            ));
        }
        for path in &scan.undeclared_links {
            diagnostics.push(Diagnostic::new(
                "pap.package.symlink",
                Severity::Warning,
                path,
                format!("undeclared non-regular entry is present: {path}"),
            ));
        }
        if !scan.completed {
            diagnostics.push(Diagnostic::new(
                "pap.package.undeclared-scan-incomplete",
                Severity::Warning,
                "package",
                "undeclared-file scan could not complete; coverage.full is false".to_string(),
            ));
            limitations.push(Limitation {
                code: "pap.package.undeclared-scan-incomplete",
                detail: "undeclared-file scan incomplete".to_string(),
            });
        }
    }

    // ---- policy presence ----
    let mut policy_stale = false;
    let policy_block = match &input.policy {
        None => {
            diagnostics.push(Diagnostic::new(
                "pap.trust.policy-absent",
                Severity::Info,
                "policy",
                "no trust policy supplied; trust dimensions are NOT_EVALUATED".to_string(),
            ));
            limitations.push(Limitation {
                code: "pap.trust.policy-absent",
                detail: "no trust policy supplied".to_string(),
            });
            ("ABSENT", None as Option<String>, None as Option<String>)
        }
        Some(p) => {
            if let Some(code) = p.stale_code {
                policy_stale = true;
                diagnostics.push(Diagnostic::new(
                    code,
                    Severity::Warning,
                    "policy",
                    "trust policy snapshot is outside its validity window".to_string(),
                ));
            }
            match p.state {
                PolicyState::Fresh => ("FRESH", Some(p.id.clone()), Some(p.digest.as_str())),
                PolicyState::Stale => ("STALE", Some(p.id.clone()), Some(p.digest.as_str())),
            }
        }
    };

    // ---- compatibility ----
    let compat_unsupported = outcome
        .map(|o| o.compat != Compat::Supported)
        .unwrap_or(false);
    if let Some(outcome) = &state.outcome {
        match outcome.compat {
            Compat::MinorNewer => {
                diagnostics.push(Diagnostic::new(
                    "pap.compat.minor-newer",
                    Severity::Warning,
                    "papVersion",
                    format!(
                        "package declares newer minor version {}",
                        outcome.pap_version.as_deref().unwrap_or("?")
                    ),
                ));
            }
            Compat::VersionUnsupported => {
                if outcome.pap_version.is_some() {
                    diagnostics.push(Diagnostic::new(
                        "pap.compat.version-unsupported",
                        Severity::Warning,
                        "papVersion",
                        format!(
                            "package declares unsupported version {}",
                            outcome.pap_version.as_deref().unwrap_or("?")
                        ),
                    ));
                }
            }
            Compat::Supported => {}
        }
    }

    // ---- extensions/features ----
    let mut critical_extension_unsupported = false;
    let mut feature_unsupported = false;
    if let Some(outcome) = &state.outcome {
        for ext in &outcome.extensions {
            if ext.critical_unsupported {
                critical_extension_unsupported = true;
                diagnostics.push(Diagnostic::new(
                    "pap.extension.critical-unsupported",
                    Severity::Warning,
                    &ext.name,
                    format!("unknown critical extension {name} version {v}", name = ext.name, v = ext.version),
                ));
                limitations.push(Limitation {
                    code: "pap.extension.critical-unsupported",
                    detail: format!("{}@{}", ext.name, ext.version),
                });
            } else {
                diagnostics.push(Diagnostic::new(
                    "pap.extension.ignored",
                    Severity::Info,
                    &ext.name,
                    format!("unknown non-critical extension ignored: {name}", name = ext.name),
                ));
                limitations.push(Limitation {
                    code: "pap.extension.ignored",
                    detail: format!("{}@{}", ext.name, ext.version),
                });
            }
        }
        if !outcome.required_features.is_empty() {
            feature_unsupported = true;
            for f in &outcome.required_features {
                diagnostics.push(Diagnostic::new(
                    "pap.feature.unsupported",
                    Severity::Warning,
                    f,
                    format!("required feature is not supported: {f}"),
                ));
                limitations.push(Limitation {
                    code: "pap.feature.unsupported",
                    detail: f.clone(),
                });
            }
        }
    }

    // ---- lowered limits ----
    let lowered = {
        let mut pairs: Vec<(&'static str, usize)> = Vec::new();
        for (i, name) in crate::limits::LIMIT_NAMES.iter().enumerate() {
            if input.limits.value(i) != DEFAULT_LIMITS.value(i) {
                pairs.push((name, input.limits.value(i)));
            }
        }
        pairs
    };
    if !lowered.is_empty() {
        diagnostics.push(Diagnostic::new(
            "pap.limit.lowered",
            Severity::Info,
            "limits",
            format!(
                "operator lowered resource limits: {}",
                lowered
                    .iter()
                    .map(|(n, v)| format!("{n}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
        limitations.push(Limitation {
            code: "pap.limit.lowered",
            detail: lowered
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join(","),
        });
    }

    // ---- integrity dimension statuses ----
    // A manifest that could not be read or parsed also leaves payloads
    // unread: integrity.artifacts is NOT_EVALUATED while integrity.package
    // is FAIL (§7.3, §7.7).
    let structurally_invalid =
        outcome.is_none() || outcome.map(|o| o.fatal()).unwrap_or(false);
    let class_defect = outcome
        .map(|o| o.class_defect)
        .unwrap_or_else(else_default_class);

    let artifact_results: Vec<&PayloadResult> = state
        .payload_results
        .iter()
        .filter(|r| r.kind == PayloadKind::Artifact)
        .collect();
    let source_results: Vec<&PayloadResult> = state
        .payload_results
        .iter()
        .filter(|r| r.kind == PayloadKind::Source)
        .collect();
    let (input_results, claim_results): (Vec<&PayloadResult>, Vec<&PayloadResult>) = {
        let mut i = Vec::new();
        let mut c = Vec::new();
        for r in &state.payload_results {
            match r.kind {
                PayloadKind::Input => i.push(r),
                PayloadKind::Claim => c.push(r),
                _ => {}
            }
        }
        (i, c)
    };

    let artifact_fail = class_defect.artifacts
        || artifact_results.iter().any(|r| r.failure.is_some() || r.mismatch.is_some());
    let artifacts_unreadable_by_limit = state.artifacts_scope_limit;
    let integrity_artifacts = if artifact_fail {
        Dim3::Fail
    } else if structurally_invalid || artifacts_unreadable_by_limit {
        Dim3::NotEvaluated
    } else {
        Dim3::Pass
    };

    let sources_fail = class_defect.sources
        || source_results.iter().any(|r| r.failure.is_some() || r.mismatch.is_some());
    let sources_unavailable = manifest_valid
        .map(|m| {
            source_quote_required(&required_check_ids_for(m, input))
                && m.sources.iter().any(|s| s.path.is_none())
        })
        .unwrap_or(false);
    let sources_integrity = if sources_fail {
        SourcesIntegrity::Fail
    } else if sources_unavailable {
        SourcesIntegrity::Unavailable
    } else if structurally_invalid || state.sources_scope_limit {
        SourcesIntegrity::NotEvaluated
    } else {
        let any_embedded = manifest_valid
            .map(|m| m.sources.iter().any(|s| s.path.is_some()))
            .unwrap_or(false);
        if any_embedded {
            SourcesIntegrity::Pass
        } else {
            SourcesIntegrity::NotEvaluated
        }
    };

    let input_fail = class_defect.inputs
        || input_results.iter().any(|r| r.failure.is_some() || r.mismatch.is_some());
    let claim_fail = claim_results.iter().any(|r| r.failure.is_some() || r.mismatch.is_some());
    // build.normalizedInputDigest claim comparison (§5.6)
    let normalized_claim_fail = {
        let declared = manifest_valid.and_then(|m| m.build.as_ref()).and_then(|b| b.normalized_input_digest.clone());
        match (declared, &state.normalized_input_digest) {
            (Some(decl), Some(comp)) if *comp != decl => true,
            _ => false,
        }
    };
    // §7.3 integrity.package: PASS requires every declared file to exist and
    // be a regular file — a file-level failure of ANY payload class fails
    // package integrity; digest mismatches map onto the owning dimension.
    let payload_file_failures = state
        .payload_results
        .iter()
        .any(|r| r.failure.is_some());
    let package_fail = if state.manifest_error.is_some()
        || state.parse_error.is_some()
        || structurally_invalid
        || class_defect.any()
        || payload_file_failures
        || input_fail
        || claim_fail
        || normalized_claim_fail
    {
        true
    } else {
        false
    };
    let package_scope_limit = state.inputs_scope_limit || state.claims_scope_limit || state.package_scope_limit;
    let integrity_package = if package_fail {
        Dim3::Fail
    } else if structurally_invalid {
        Dim3::NotEvaluated
    } else if package_scope_limit {
        Dim3::NotEvaluated
    } else {
        Dim3::Pass
    };

    let sources_availability = if !source_quote_required(&required_check_ids_all(manifest_valid, input)) {
        SourcesAvailability::NotApplicable
    } else if manifest_valid
        .map(|m| m.sources.iter().any(|s| s.path.is_none()))
        .unwrap_or(false)
    {
        SourcesAvailability::Unavailable
    } else {
        SourcesAvailability::Pass
    };

    // ---- signature dimension (Phase 2a: never verified) ----
    let policy_mode = input.policy.as_ref().map(|p| p.signature_mode);
    let envelopes_present = !state.envelopes.is_empty();
    let mut signature_entries: Vec<Json> = Vec::new();
    let signature_validity = if envelopes_present {
        // Phase 2a never verifies envelopes (Tier-A-consistent unevaluated).
        for path in &state.envelopes {
            signature_entries.push(Json::Obj(vec![(
                "path".to_string(),
                Json::Str(path.clone()),
            )]));
        }
        if !state.envelopes_scope_limit {
            diagnostics.push(Diagnostic::new(
                "pap.signature.unsupported-format",
                Severity::Warning,
                "signatures",
                "signature envelopes exist but the verifier does not verify signatures in this phase; validity NOT_EVALUATED".to_string(),
            ));
            limitations.push(Limitation {
                code: "pap.signature.unsupported-format",
                detail: "signature verification is outside the Phase 2a scope".to_string(),
            });
        }
        SigValidity::NotEvaluated
    } else {
        match policy_mode {
            Some(crate::policy::SigMode::Required) => {
                diagnostics.push(Diagnostic::new(
                    "pap.signature.absent",
                    Severity::Warning,
                    "signatures",
                    "signature mode is required but no envelope is present".to_string(),
                ));
                limitations.push(Limitation {
                    code: "pap.signature.absent",
                    detail: "required signature is absent".to_string(),
                });
                SigValidity::NotEvaluated
            }
            Some(crate::policy::SigMode::Optional) => {
                diagnostics.push(Diagnostic::new(
                    "pap.signature.absent",
                    Severity::Info,
                    "signatures",
                    "no signature envelope present; optional signature".to_string(),
                ));
                limitations.push(Limitation {
                    code: "pap.signature.absent",
                    detail: "no signature envelope present".to_string(),
                });
                SigValidity::NotApplicable
            }
            _ => SigValidity::NotApplicable,
        }
    };

    // ---- trust dimension ----
    let trust_signer_identity = if envelopes_present {
        TrustSigner::NotEvaluated
    } else {
        TrustSigner::NotApplicable
    };
    let trust_policy_decision = if policy_stale {
        TrustPolicyDecision::Stale
    } else {
        TrustPolicyDecision::NotEvaluated
    };

    // checker/profile recognition (§6.6) — implementable in Phase 2a.
    let (checker_recognition, profile_recognition) = match &input.policy {
        None => (Recognition::NotEvaluated, Recognition::NotEvaluated),
        Some(p) => {
            let checker_recognition = if p.checkers.is_empty() {
                Recognition::NotApplicable
            } else {
                let ver = checker::verifier_id();
                let verver = checker::verifier_version();
                let my_digest = checker::IMPLEMENTATION_DIGEST;
                let mut status = Recognition::Unsupported;
                let mut unknown_code_emitted = false;
                for pin in &p.checkers {
                    if pin.id == ver && pin.version == verver {
                        if pin.implementation_digest == my_digest {
                            status = Recognition::Pass;
                            break;
                        } else {
                            status = Recognition::Untrusted;
                        }
                    }
                }
                match status {
                    Recognition::Untrusted => {
                        diagnostics.push(Diagnostic::new(
                            "pap.trust.checker-untrusted",
                            Severity::Warning,
                            "checker",
                            "checker identity matched id/version but not the pinned implementationDigest".to_string(),
                        ));
                        limitations.push(Limitation {
                            code: "pap.trust.checker-untrusted",
                            detail: format!("{ver}@{verver}"),
                        });
                    }
                    Recognition::Unsupported => {
                        unknown_code_emitted = true;
                        diagnostics.push(Diagnostic::new(
                            "pap.trust.checker-unknown",
                            Severity::Warning,
                            "checker",
                            "checker identity is not in the policy allowlist".to_string(),
                        ));
                        limitations.push(Limitation {
                            code: "pap.trust.checker-unknown",
                            detail: format!("{ver}@{verver}"),
                        });
                    }
                    _ => {}
                }
                let _ = unknown_code_emitted;
                status
            };
            let profile_recognition = {
                let prof = manifest_valid.and_then(|m| m.profile.clone());
                if p.profiles.is_empty() {
                    Recognition::NotApplicable
                } else {
                    match prof {
                        None => Recognition::NotApplicable,
                        Some(prof) => {
                            let mut status = Recognition::Unsupported;
                            for pin in &p.profiles {
                                if pin.id == prof.id && pin.version == prof.version {
                                    match (&pin.closure_digest, &prof.closure_digest) {
                                        (None, _) => {
                                            status = Recognition::Pass;
                                            break;
                                        }
                                        (Some(_), None) => {
                                            // pinned digest but none declared → UNSUPPORTED
                                            status = Recognition::Unsupported;
                                        }
                                        (Some(pd), Some(cd)) => {
                                            if pd == cd {
                                                status = Recognition::Pass;
                                                break;
                                            } else {
                                                status = Recognition::Untrusted;
                                            }
                                        }
                                    }
                                }
                            }
                            match status {
                                Recognition::Untrusted => {
                                    diagnostics.push(Diagnostic::new(
                                        "pap.trust.profile-untrusted",
                                        Severity::Warning,
                                        &prof.id,
                                        "declared profile closureDigest contradicts the policy pin".to_string(),
                                    ));
                                    limitations.push(Limitation {
                                        code: "pap.trust.profile-untrusted",
                                        detail: format!("{}@{}", prof.id, prof.version),
                                    });
                                }
                                Recognition::Unsupported => {
                                    diagnostics.push(Diagnostic::new(
                                        "pap.trust.profile-unknown",
                                        Severity::Warning,
                                        &prof.id,
                                        format!("profile identity is not in the policy allowlist: {}@{}", prof.id, prof.version),
                                    ));
                                    limitations.push(Limitation {
                                        code: "pap.trust.profile-unknown",
                                        detail: format!("{}@{}", prof.id, prof.version),
                                    });
                                }
                                _ => {}
                            }
                            status
                        }
                    }
                }
            };
            (checker_recognition, profile_recognition)
        }
    };

    // ---- human review (Phase 2a: evaluation is later-phase) ----
    let human_review_required = input.policy.as_ref().map(|p| p.human_review_required).unwrap_or(false);
    let human_review = if human_review_required {
        diagnostics.push(Diagnostic::new(
            "pap.trust.review-required",
            Severity::Warning,
            "humanReview",
            "policy requires human approval; review evidence evaluation is outside the Phase 2a scope".to_string(),
        ));
        limitations.push(Limitation {
            code: "pap.trust.review-required",
            detail: "human-review evaluation is not implemented in this Phase 2a verifier".to_string(),
        });
        HumanReview::Unknown
    } else {
        HumanReview::NotApplicable
    };

    // ---- check rows (Phase 2a: the verifier's check registry is empty) ----
    let mut check_rows: Vec<(CheckSpec, CheckResult)> = Vec::new();
    let mut checks_declared_ids: Vec<String> = Vec::new();
    match (&state.manifest_json, manifest_valid) {
        // manifest unreadable or unparseable: no check set at all (§8.2)
        (None, _) => {}
        // parsed but structurally invalid: declared checks NOT_EVALUATED (§8.2)
        (Some(_), None) => {
            if let Some(outcome) = &state.outcome {
                for spec in &outcome.declared_specs {
                    check_rows.push((spec.clone(), CheckResult::NotEvaluated));
                    checks_declared_ids.push(spec.id.clone());
                }
                for spec in &check_rows {
                    diagnostics.push(Diagnostic::new(
                        "pap.check.not-evaluated",
                        Severity::Warning,
                        &spec.0.id,
                        "required check could not run: the manifest failed validation".to_string(),
                    ));
                }
            }
        }
        // structurally valid: check every declared/policy check (all
        // unimplemented in Phase 2a → UNSUPPORTED, or NOT_EVALUATED for an
        // unsupported package version)
        (Some(_), Some(m)) => {
            let mut union_ids: Vec<String> = Vec::new();
            for spec in &m.check_specs {
                union_ids.push(spec.id.clone());
            }
            if let Some(p) = &input.policy {
                for pid in &p.required_checks {
                    if !union_ids.contains(pid) {
                        union_ids.push(pid.clone());
                    }
                }
            }
            union_ids.sort();
            // rows: declared specs in order, then policy-only by id
            for spec in &m.check_specs {
                check_rows.push((spec.clone(), check_outcome_for(spec)));
            }
            for pid in &union_ids {
                if !m.check_specs.iter().any(|s| &s.id == pid) {
                    let suffix = crate::manifest::parse_check_id(pid).unwrap_or("1").to_string();
                    check_rows.push((
                        CheckSpec {
                            id: pid.clone(),
                            version: suffix,
                            required: true,
                        },
                        CheckResult::Unsupported,
                    ));
                }
            }
            for (spec, _) in &check_rows {
                checks_declared_ids.push(spec.id.clone());
            }
            // diagnostics
            for (spec, outcome_) in &check_rows {
                match outcome_ {
                    CheckResult::Unsupported => {
                        if input.policy.as_ref().map(|p| p.required_checks.contains(&spec.id)).unwrap_or(false)
                            || spec.required
                        {
                            diagnostics.push(Diagnostic::new(
                                "pap.check.unsupported",
                                Severity::Warning,
                                &spec.id,
                                "the verifier does not implement this check specification".to_string(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn check_outcome_for(_spec: &CheckSpec) -> CheckResult {
        // The Phase 2a check registry is empty: no check specification is
        // implemented, so every declared check is UNSUPPORTED (§13.1).
        CheckResult::Unsupported
    }

    // empty-required-set diagnostic (§4.4.3, §7.4 rule 4)
    let required_rows: Vec<&(CheckSpec, CheckResult)> = check_rows
        .iter()
        .filter(|(spec, _)| {
            spec.required
                || input
                    .policy
                    .as_ref()
                    .map(|p| p.required_checks.contains(&spec.id))
                    .unwrap_or(false)
        })
        .collect();
    if !checks_declared_ids.is_empty() && required_rows.is_empty() {
        diagnostics.push(Diagnostic::new(
            "pap.package.empty-check-specs",
            Severity::Warning,
            "checkSpecs",
            "no required check remains; the required set is empty".to_string(),
        ));
        limitations.push(Limitation {
            code: "pap.package.empty-check-specs",
            detail: "required check set is empty".to_string(),
        });
    }

    // ------------------------------------------------------------------
    // Part 2 — verdict and coverage
    // ------------------------------------------------------------------
    let recognition_required = input
        .policy
        .as_ref()
        .map(|p| {
            p.required_dimensions
                .iter()
                .any(|d| d == "trust" || d == "trust.checkerRecognition" || d == "trust.profileRecognition")
        })
        .unwrap_or(false);

    let dims = DimensionStatuses {
        integrity_package,
        integrity_artifacts,
        sources_integrity,
        sources_availability,
        signature_validity,
        trust_signer_identity,
        trust_policy_decision,
        trust_checker_recognition: checker_recognition,
        trust_profile_recognition: profile_recognition,
        human_review,
    };

    let policy_required_dims: Vec<String> = input
        .policy
        .as_ref()
        .map(|p| p.required_dimensions.clone())
        .unwrap_or_default();

    // required rows in the required order (declared required in order, then
    // policy-only ids ascending)
    let mut required_results: Vec<(String, CheckResult)> = Vec::new();
    for (spec, r) in &check_rows {
        if (spec.required
            || input
                .policy
                .as_ref()
                .map(|p| p.required_checks.contains(&spec.id))
                .unwrap_or(false))
            && !required_results.iter().any(|(id, _)| *id == spec.id)
        {
            required_results.push((spec.id.clone(), *r));
        }
    }
    if let Some(p) = &input.policy {
        let mut extra: Vec<String> = p
            .required_checks
            .iter()
            .filter(|id| !required_results.iter().any(|(x, _)| x == *id))
            .cloned()
            .collect();
        extra.sort();
        for id in extra {
            required_results.push((id.clone(), CheckResult::Unsupported));
        }
    }

    let limit_stopped_scope = !state.limit_stops.is_empty();

    let ctx = VerdictContext {
        signature_mode_required: matches!(policy_mode, Some(crate::policy::SigMode::Required)),
        compat_unsupported,
        feature_unsupported,
        critical_extension_unsupported,
    };
    let vinput = verdict::VerdictInput {
        required_check_results: required_results.clone(),
        policy_only_check_ids: Vec::new(),
        dims,
        scan_completed,
        limit_stopped_scope,
        policy_stale,
        recognition_required,
        human_review_required_by_policy: human_review_required,
    };
    let (verdict, coverage) = verdict::compute(&vinput, &ctx, &policy_required_dims);

    // ------------------------------------------------------------------
    // Part 3 — report assembly
    // ------------------------------------------------------------------
    diag::sort_diagnostics(&mut diagnostics);
    diag::sort_limitations(&mut limitations);

    let evaluated_at = rfc3339::format(input.now);
    let pap_version_reported = state
        .manifest_json
        .as_ref()
        .and_then(|v| v.get("papVersion"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let identity_package = state.package_identity.as_ref().map(|d| d.as_str());
    let artifacts_json = manifest_valid
        .map(|m| {
            Json::Arr(
                m.artifacts
                    .iter()
                    .map(|a| {
                        let computed = artifact_results
                            .iter()
                            .find(|r| r.id == a.id && r.path == a.path)
                            .and_then(|r| r.computed.as_ref());
                        Json::Obj(vec![
                            ("id".to_string(), Json::Str(a.id.clone())),
                            ("declared".to_string(), Json::Str(a.digest.as_str())),
                            (
                                "computed".to_string(),
                                match computed {
                                    Some(d) => Json::Str(d.as_str()),
                                    None => Json::Null,
                                },
                            ),
                        ])
                    })
                    .collect(),
            )
        })
        .unwrap_or(Json::Arr(Vec::new()));
    let sources_json = manifest_valid
        .map(|m| {
            Json::Arr(
                m.sources
                    .iter()
                    .map(|s| {
                        let computed = source_results
                            .iter()
                            .find(|r| r.id == s.id)
                            .and_then(|r| r.computed.as_ref());
                        Json::Obj(vec![
                            ("id".to_string(), Json::Str(s.id.clone())),
                            ("declared".to_string(), Json::Str(s.digest.as_str())),
                            (
                                "computed".to_string(),
                                match computed {
                                    Some(d) => Json::Str(d.as_str()),
                                    None => Json::Null,
                                },
                            ),
                        ])
                    })
                    .collect(),
            )
        })
        .unwrap_or(Json::Arr(Vec::new()));
    let normalized_id = state.normalized_input_digest.as_ref().map(|d| d.as_str());
    let extension_closure = manifest_valid
        .and_then(|m| m.profile.as_ref())
        .and_then(|p| p.closure_digest.as_ref())
        .map(|d| d.as_str());

    let mut checks_results: Vec<Json> = Vec::new();
    for (spec, r) in &check_rows {
        checks_results.push(Json::Obj(vec![
            ("checkId".to_string(), Json::Str(spec.id.clone())),
            (
                "outcome".to_string(),
                Json::Str(
                    match r {
                        CheckResult::Pass => "PASS",
                        CheckResult::Fail => "FAIL",
                        CheckResult::Unsupported => "UNSUPPORTED",
                        CheckResult::NotEvaluated => "NOT_EVALUATED",
                    }
                    .to_string(),
                ),
            ),
            ("required".to_string(), Json::Bool(spec_required(spec, input))),
        ]));
    }

    let signatures_json = Json::Arr(signature_entries.clone());

    let report = Json::Obj(vec![
        ("reportVersion".to_string(), Json::Str("0.1".to_string())),
        (
            "verifier".to_string(),
            Json::Obj(vec![
                ("id".to_string(), Json::Str(checker::VERIFIER_ID.to_string())),
                ("version".to_string(), Json::Str(checker::VERIFIER_VERSION.to_string())),
                (
                    "implementationDigest".to_string(),
                    Json::Str(checker::IMPLEMENTATION_DIGEST.to_string()),
                ),
                (
                    "checkerIdentities".to_string(),
                    Json::Arr(vec![Json::Str(checker::CHECKER_IDENTITY.to_string())]),
                ),
            ]),
        ),
        (
            "package".to_string(),
            Json::Obj(vec![
                (
                    "identity".to_string(),
                    match &identity_package {
                        Some(s) => Json::Str(s.clone()),
                        None => Json::Null,
                    },
                ),
                (
                    "papVersion".to_string(),
                    match pap_version_reported {
                        Some(s) => Json::Str(s),
                        None => Json::Null,
                    },
                ),
                (
                    "path".to_string(),
                    Json::Str(input.package_arg.clone()),
                ),
            ]),
        ),
        (
            "policy".to_string(),
            Json::Obj(vec![
                (
                    "id".to_string(),
                    match &policy_block.1 {
                        Some(s) => Json::Str(s.clone()),
                        None => Json::Null,
                    },
                ),
                (
                    "digest".to_string(),
                    match &policy_block.2 {
                        Some(s) => Json::Str(s.clone()),
                        None => Json::Null,
                    },
                ),
                ("state".to_string(), Json::Str(policy_block.0.to_string())),
                (
                    "path".to_string(),
                    match &input.policy_path {
                        Some(p) => Json::Str(p.clone()),
                        None => Json::Null,
                    },
                ),
            ]),
        ),
        ("evaluatedAt".to_string(), Json::Str(evaluated_at)),
        (
            "effectiveLimits".to_string(), {
                if lowered.is_empty() {
                    Json::Null // omitted bellow (removed before output)
                } else {
                    Json::Obj(
                        lowered
                            .iter()
                            .map(|(n, v)| (n.to_string(), Json::Int(*v as i64)))
                            .collect(),
                    )
                }
            },
        ),
        (
            "identities".to_string(),
            Json::Obj(vec![
                (
                    "packageIdentity".to_string(),
                    match &identity_package {
                        Some(s) => Json::Str(s.clone()),
                        None => Json::Null,
                    },
                ),
                ("artifacts".to_string(), artifacts_json),
                ("sources".to_string(), sources_json),
                (
                    "normalizedInputDigest".to_string(),
                    match normalized_id {
                        Some(s) => Json::Str(s.to_string()),
                        None => Json::Null,
                    },
                ),
                (
                    "extensionClosureDigest".to_string(),
                    match extension_closure {
                        Some(s) => Json::Str(s.to_string()),
                        None => Json::Null,
                    },
                ),
                (
                    "checkerIdentity".to_string(),
                    Json::Str(checker::CHECKER_IDENTITY.to_string()),
                ),
                (
                    "verificationRecordIdentity".to_string(),
                    Json::Str(ZERO_DIGEST.to_string()),
                ),
            ]),
        ),
        (
            "dimensions".to_string(),
            Json::Obj(vec![
                (
                    "integrity".to_string(),
                    Json::Obj(vec![
                        (
                            "package".to_string(),
                            Json::Str(dim3_str(integrity_package).to_string()),
                        ),
                        (
                            "artifacts".to_string(),
                            Json::Str(dim3_str(integrity_artifacts).to_string()),
                        ),
                    ]),
                ),
                (
                    "sources".to_string(),
                    Json::Obj(vec![
                        (
                            "integrity".to_string(),
                            Json::Str(sources_integrity_str(sources_integrity).to_string()),
                        ),
                        (
                            "availability".to_string(),
                            Json::Str(sources_availability_str(sources_availability).to_string()),
                        ),
                    ]),
                ),
                (
                    "signature".to_string(),
                    Json::Obj(vec![
                        (
                            "validity".to_string(),
                            Json::Str(sig_str(signature_validity).to_string()),
                        ),
                        ("signatures".to_string(), signatures_json.clone()),
                    ]),
                ),
                (
                    "trust".to_string(),
                    Json::Obj(vec![
                        (
                            "signerIdentity".to_string(),
                            Json::Str(signer_str(trust_signer_identity).to_string()),
                        ),
                        (
                            "policyDecision".to_string(),
                            Json::Str(policy_decision_str(trust_policy_decision).to_string()),
                        ),
                        (
                            "checkerRecognition".to_string(),
                            Json::Str(recognition_str(checker_recognition).to_string()),
                        ),
                        (
                            "profileRecognition".to_string(),
                            Json::Str(recognition_str(profile_recognition).to_string()),
                        ),
                    ]),
                ),
                (
                    "checks".to_string(),
                    Json::Obj(vec![("results".to_string(), Json::Arr(checks_results.clone()))]),
                ),
                (
                    "humanReview".to_string(),
                    {
                        let mut hr = vec![(
                            "status".to_string(),
                            Json::Str(human_review_str(human_review).to_string()),
                        )];
                        if human_review == HumanReview::Pass {
                            // unreachable in Phase 2a; kept for schema fidelity
                            hr.push(("basis".to_string(), Json::Str("unbound-claim".to_string())));
                        }
                        Json::Obj(hr)
                    },
                ),
                ("semanticTruth".to_string(), Json::Str("NOT_EVALUATED".to_string())),
                (
                    "legalEnforceability".to_string(),
                    Json::Str("NOT_EVALUATED".to_string()),
                ),
            ]),
        ),
        ("checks".to_string(), Json::Arr(Vec::new())),
        (
            "coverage".to_string(),
            Json::Obj(vec![
                (
                    "requiredChecks".to_string(),
                    Json::Arr(
                        coverage
                            .required_checks
                            .iter()
                            .map(|c| Json::Str(c.clone()))
                            .collect(),
                    ),
                ),
                ("checksEvaluated".to_string(), Json::Int(coverage.checks_evaluated() as i64)),
                ("checksPassed".to_string(), Json::Int(coverage.checks_passed as i64)),
                ("checksFailed".to_string(), Json::Int(coverage.checks_failed as i64)),
                (
                    "checksUnsupported".to_string(),
                    Json::Int(coverage.checks_unsupported as i64),
                ),
                (
                    "checksNotEvaluated".to_string(),
                    Json::Int(coverage.checks_not_evaluated as i64),
                ),
                (
                    "requiredDimensions".to_string(),
                    Json::Arr(
                        coverage
                            .required_dimensions
                            .iter()
                            .map(|d| Json::Str(d.clone()))
                            .collect(),
                    ),
                ),
                (
                    "dimensionsEvaluated".to_string(),
                    Json::Int(coverage.dimensions_evaluated as i64),
                ),
                ("full".to_string(), Json::Bool(coverage.full)),
            ]),
        ),
        (
            "limitations".to_string(),
            Json::Arr(
                limitations
                    .iter()
                    .map(|l| {
                        Json::Obj(vec![
                            ("code".to_string(), Json::Str(l.code.to_string())),
                            ("detail".to_string(), Json::Str(l.detail.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("verdict".to_string(), Json::Str(verdict.as_str().to_string())),
        (
            "diagnostics".to_string(),
            Json::Arr(
                diagnostics
                    .iter()
                    .map(|d| {
                        Json::Obj(vec![
                            ("code".to_string(), Json::Str(d.code.to_string())),
                            ("severity".to_string(), Json::Str(d.severity.as_str().to_string())),
                            ("scope".to_string(), Json::Str(d.scope.clone())),
                            ("message".to_string(), Json::Str(d.message.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);

    // Remove the optional effectiveLimits when nothing was lowered.
    let mut report = report;
    if lowered.is_empty() {
        if let Json::Obj(m) = &mut report {
            m.retain(|(k, _)| k != "effectiveLimits");
        }
    }

    // verificationRecordIdentity (§5.9)
    let form = identity_form(&report);
    let canonical_form = crate::jcs::to_canonical(&form);
    let vid = digest::report_identity(canonical_form.as_bytes());
    if let Json::Obj(m) = &mut report {
        for (k, v) in m.iter_mut() {
            if k == "identities" {
                if let Json::Obj(im) = v {
                    if let Some(slot) = im
                        .iter_mut()
                        .find(|(ik, _)| ik == "verificationRecordIdentity")
                    {
                        slot.1 = Json::Str(digest::format_digest(&vid));
                    }
                }
            }
        }
    }

    Ok(crate::pkg::VerifyOutput {
        report_json: report,
        exit_code: verdict.exit_code(),
    })
}

fn spec_required(spec: &CheckSpec, input: &VerifyInput) -> bool {
    spec.required
        || input
            .policy
            .as_ref()
            .map(|p| p.required_checks.contains(&spec.id))
            .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn source_quote_required(check_ids: &[String]) -> bool {
    check_ids.iter().any(|c| c.starts_with("pap.check.source-quote/"))
}

fn required_check_ids_for(m: &crate::manifest::Manifest, input: &VerifyInput) -> Vec<String> {
    required_check_ids_all(Some(m), input)
}

fn required_check_ids_all(
    m: Option<&crate::manifest::Manifest>,
    input: &VerifyInput,
) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    if let Some(m) = m {
        for spec in &m.check_specs {
            if spec.required {
                ids.push(spec.id.clone());
            }
        }
    }
    if let Some(p) = &input.policy {
        for pid in &p.required_checks {
            if !ids.contains(pid) {
                ids.push(pid.clone());
            }
        }
    }
    ids
}

fn dim3_str(d: Dim3) -> &'static str {
    match d {
        Dim3::Pass => "PASS",
        Dim3::Fail => "FAIL",
        Dim3::NotEvaluated => "NOT_EVALUATED",
    }
}

fn sources_integrity_str(s: SourcesIntegrity) -> &'static str {
    match s {
        SourcesIntegrity::Pass => "PASS",
        SourcesIntegrity::Fail => "FAIL",
        SourcesIntegrity::Unavailable => "UNAVAILABLE",
        SourcesIntegrity::NotEvaluated => "NOT_EVALUATED",
    }
}

fn sources_availability_str(s: SourcesAvailability) -> &'static str {
    match s {
        SourcesAvailability::Pass => "PASS",
        SourcesAvailability::Unavailable => "UNAVAILABLE",
        SourcesAvailability::NotApplicable => "NOT_APPLICABLE",
    }
}

fn sig_str(s: SigValidity) -> &'static str {
    match s {
        SigValidity::Valid => "VALID",
        SigValidity::Invalid => "INVALID",
        SigValidity::NotEvaluated => "NOT_EVALUATED",
        SigValidity::NotApplicable => "NOT_APPLICABLE",
    }
}

fn signer_str(s: TrustSigner) -> &'static str {
    match s {
        TrustSigner::Trusted => "TRUSTED",
        TrustSigner::Untrusted => "UNTRUSTED",
        TrustSigner::Unknown => "UNKNOWN",
        TrustSigner::NotEvaluated => "NOT_EVALUATED",
        TrustSigner::NotApplicable => "NOT_APPLICABLE",
    }
}

fn policy_decision_str(s: TrustPolicyDecision) -> &'static str {
    match s {
        TrustPolicyDecision::Accepted => "ACCEPTED",
        TrustPolicyDecision::Rejected => "REJECTED",
        TrustPolicyDecision::Stale => "STALE",
        TrustPolicyDecision::NotEvaluated => "NOT_EVALUATED",
    }
}

fn recognition_str(s: Recognition) -> &'static str {
    match s {
        Recognition::Pass => "PASS",
        Recognition::Unsupported => "UNSUPPORTED",
        Recognition::Untrusted => "UNTRUSTED",
        Recognition::NotEvaluated => "NOT_EVALUATED",
        Recognition::NotApplicable => "NOT_APPLICABLE",
    }
}

fn human_review_str(s: HumanReview) -> &'static str {
    match s {
        HumanReview::Pass => "PASS",
        HumanReview::Incomplete => "INCOMPLETE",
        HumanReview::Unknown => "UNKNOWN",
        HumanReview::NotApplicable => "NOT_APPLICABLE",
    }
}

fn else_default_class() -> crate::manifest::ClassDefect {
    crate::manifest::ClassDefect::default()
}
