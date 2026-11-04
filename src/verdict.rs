//! Verdict precedence, required-set union and coverage counters
//! (RFC §7.4, §7.5; §4.4.3).
//!
//! Verdict precedence is `FAIL > UNTRUSTED > UNSUPPORTED > INCOMPLETE > PASS`,
//! first matching rule wins, with `NOT_EVALUATED` for the degenerate case.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckResult {
    Pass,
    Fail,
    Unsupported,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Untrusted,
    Unsupported,
    Incomplete,
    NotEvaluated,
}

impl Verdict {
    /// Exit-code mapping (RFC §9.7): exhaustive and exact.
    pub fn exit_code(&self) -> u32 {
        match self {
            Verdict::Pass => 0,
            Verdict::Fail => 1,
            Verdict::Incomplete | Verdict::NotEvaluated => 2,
            Verdict::Untrusted => 3,
            Verdict::Unsupported => 4,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Untrusted => "UNTRUSTED",
            Verdict::Unsupported => "UNSUPPORTED",
            Verdict::Incomplete => "INCOMPLETE",
            Verdict::NotEvaluated => "NOT_EVALUATED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DimensionStatuses {
    pub integrity_package: Dim3,
    pub integrity_artifacts: Dim3,
    pub sources_integrity: SourcesIntegrity,
    pub sources_availability: SourcesAvailability,
    pub signature_validity: SigValidity,
    pub trust_signer_identity: TrustSigner,
    pub trust_policy_decision: TrustPolicyDecision,
    pub trust_checker_recognition: Recognition,
    pub trust_profile_recognition: Recognition,
    pub human_review: HumanReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dim3 {
    Pass,
    Fail,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcesIntegrity {
    Pass,
    Fail,
    Unavailable,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcesAvailability {
    Pass,
    Unavailable,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigValidity {
    Valid,
    Invalid,
    NotEvaluated,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSigner {
    Trusted,
    Untrusted,
    Unknown,
    NotEvaluated,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPolicyDecision {
    Accepted,
    Rejected,
    Stale,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recognition {
    Pass,
    Unsupported,
    Untrusted,
    NotEvaluated,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanReview {
    Pass,
    Incomplete,
    Unknown,
    NotApplicable,
}

/// Implied dimensions per required check (§7.4 table).
fn implied_dimensions(check_id: &str) -> &'static [&'static str] {
    if check_id.starts_with("pap.check.digest-integrity/") {
        &["integrity", "checks"]
    } else if check_id.starts_with("pap.check.source-quote/") {
        &["sources", "checks"]
    } else if check_id.starts_with("pap.check.relation-consistency/") {
        &["checks"]
    } else {
        &["checks"]
    }
}

const ENUMERABLE_ORDER: [&str; 15] = [
    "integrity",
    "integrity.package",
    "integrity.artifacts",
    "sources",
    "sources.integrity",
    "sources.availability",
    "signature",
    "signature.validity",
    "trust",
    "trust.signerIdentity",
    "trust.policyDecision",
    "trust.checkerRecognition",
    "trust.profileRecognition",
    "checks",
    "humanReview",
];

/// coverage.requiredDimensions: union of the implied dimensions of required
/// checks with the policy's requiredDimensions, in Appendix B enumerable
/// order (§7.5).
pub fn required_dimensions_union(
    required_check_ids: &[String],
    policy_required: &[String],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in ENUMERABLE_ORDER {
        let implicit = required_check_ids.iter().any(|c| implied_dimensions(c).contains(&name));
        let explicit = policy_required.iter().any(|d| d == name);
        if implicit || explicit {
            out.push(name.to_string());
        }
    }
    out
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VerdictContext {
    /// The policy's signature mode is `required`.
    pub signature_mode_required: bool,
    /// The package declares a newer/unsupported papVersion (§7.4 rule 3).
    pub compat_unsupported: bool,
    /// A requiredFeatures entry the verifier does not support (§7.4 rule 3).
    pub feature_unsupported: bool,
    /// An unknown `critical: true` extension exists (§7.4 rule 3).
    pub critical_extension_unsupported: bool,
}

pub struct VerdictInput {
    /// Required check rows in required order (declared required checks in
    /// checkSpecs order, then policy-only required checks by checkId).
    pub required_check_results: Vec<(String, CheckResult)>,
    /// Policy-required checks not present in the package's checkSpecs —
    /// these are appended with a NOT_EVALUATED outcome in Phase 2a (no check
    /// implementations exist yet).
    pub policy_only_check_ids: Vec<String>,
    pub dims: DimensionStatuses,
    pub scan_completed: bool,
    pub limit_stopped_scope: bool,
    pub policy_stale: bool,
    /// True when the policy requires checker and/or profile recognition
    /// (requiredDimensions contains `trust` or a recognition sub-dimension).
    pub recognition_required: bool,
    pub human_review_required_by_policy: bool,
}

pub struct Coverage {
    pub required_checks: Vec<String>,
    pub checks_passed: usize,
    pub checks_failed: usize,
    pub checks_unsupported: usize,
    pub checks_not_evaluated: usize,
    pub required_dimensions: Vec<String>,
    pub dimensions_evaluated: usize,
    pub full: bool,
}

impl Coverage {
    pub fn checks_evaluated(&self) -> usize {
        self.checks_passed + self.checks_failed
    }
}

fn check_decided(r: CheckResult) -> bool {
    matches!(r, CheckResult::Pass | CheckResult::Fail)
}

fn decided_dim3(s: Dim3) -> bool {
    matches!(s, Dim3::Pass | Dim3::Fail)
}

fn decided_sources_integrity(s: SourcesIntegrity) -> bool {
    matches!(s, SourcesIntegrity::Pass | SourcesIntegrity::Fail)
}

fn decided_sig(s: SigValidity) -> bool {
    matches!(s, SigValidity::Valid | SigValidity::Invalid | SigValidity::NotApplicable)
}

fn decided_trust_signer(s: TrustSigner) -> bool {
    !matches!(s, TrustSigner::NotEvaluated)
}

fn decided_policy_decision(s: TrustPolicyDecision) -> bool {
    !matches!(s, TrustPolicyDecision::NotEvaluated)
}

fn decided_recognition(s: Recognition) -> bool {
    !matches!(s, Recognition::NotEvaluated)
}

fn decided_human(s: HumanReview) -> bool {
    matches!(s, HumanReview::Pass | HumanReview::NotApplicable)
}

/// Compute the verdict and coverage from the required set (§7.4).
/// `policy_required_dims` is the trust policy's requiredDimensions list.
pub fn compute(
    input: &VerdictInput,
    ctx: &VerdictContext,
    policy_required_dims: &[String],
) -> (Verdict, Coverage) {
    // Required checks: declared required rows plus policy-only required ids
    // (both already ordered).
    let mut required_checks: Vec<String> = input
        .required_check_results
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    required_checks.extend(input.policy_only_check_ids.iter().cloned());
    let empty_required = required_checks.is_empty();

    let mut passed = 0;
    let mut failed = 0;
    let mut unsupported = 0;
    let mut not_evaluated = 0;
    for (_, r) in &input.required_check_results {
        match r {
            CheckResult::Pass => passed += 1,
            CheckResult::Fail => failed += 1,
            CheckResult::Unsupported => unsupported += 1,
            CheckResult::NotEvaluated => not_evaluated += 1,
        }
    }
    not_evaluated += input.policy_only_check_ids.len();

    let required_dims = required_dimensions_union(&required_checks, policy_required_dims);

    // Compute decidedness for each enumerable order entry.
    let dims = &input.dims;
    let decided_flags: Vec<bool> = ENUMERABLE_ORDER
        .iter()
        .map(|name| {
            if !required_dims.contains(&name.to_string()) {
                return true; // not required: decided trivially
            }
            match *name {
                "integrity" => {
                    decided_dim3(dims.integrity_package) && decided_dim3(dims.integrity_artifacts)
                }
                "integrity.package" => decided_dim3(dims.integrity_package),
                "integrity.artifacts" => decided_dim3(dims.integrity_artifacts),
                "sources" => {
                    decided_sources_integrity(dims.sources_integrity)
                        // all three availability values are decided
                }
                "sources.integrity" => decided_sources_integrity(dims.sources_integrity),
                "sources.availability" => true,
                "signature" => decided_sig(dims.signature_validity),
                "signature.validity" => decided_sig(dims.signature_validity),
                "trust" => {
                    decided_trust_signer(dims.trust_signer_identity)
                        && decided_policy_decision(dims.trust_policy_decision)
                        && decided_recognition(dims.trust_checker_recognition)
                        && decided_recognition(dims.trust_profile_recognition)
                }
                "trust.signerIdentity" => decided_trust_signer(dims.trust_signer_identity),
                "trust.policyDecision" => decided_policy_decision(dims.trust_policy_decision),
                "trust.checkerRecognition" => decided_recognition(dims.trust_checker_recognition),
                "trust.profileRecognition" => decided_recognition(dims.trust_profile_recognition),
                "checks" => input
                    .required_check_results
                    .iter()
                    .all(|(_, r)| check_decided(*r)),
                "humanReview" => decided_human(dims.human_review),
                _ => true,
            }
        })
        .collect();

    let required_idx: Vec<usize> = ENUMERABLE_ORDER
        .iter()
        .enumerate()
        .filter(|(_, n)| required_dims.contains(&n.to_string()))
        .map(|(i, _)| i)
        .collect();
    let dimensions_evaluated = required_idx.iter().filter(|&&i| decided_flags[i]).count();

    let full = !empty_required
        && unsupported == 0
        && not_evaluated == 0
        && dimensions_evaluated == required_dims.len()
        && input.scan_completed
        && !input.limit_stopped_scope;

    let coverage = Coverage {
        required_checks,
        checks_passed: passed,
        checks_failed: failed,
        checks_unsupported: unsupported,
        checks_not_evaluated: not_evaluated,
        required_dimensions: required_dims.clone(),
        dimensions_evaluated,
        full,
    };

    // ---- Rule 1: FAIL ----
    if failed > 0
        || dims.integrity_package == Dim3::Fail
        || dims.integrity_artifacts == Dim3::Fail
        || dims.sources_integrity == SourcesIntegrity::Fail
        || (ctx.signature_mode_required && dims.signature_validity == SigValidity::Invalid)
    {
        return (Verdict::Fail, coverage);
    }

    // ---- Rule 2: UNTRUSTED ----
    if dims.trust_signer_identity == TrustSigner::Untrusted
        || dims.trust_policy_decision == TrustPolicyDecision::Rejected
        || (input.recognition_required
            && (dims.trust_checker_recognition == Recognition::Untrusted
                || dims.trust_profile_recognition == Recognition::Untrusted))
    {
        return (Verdict::Untrusted, coverage);
    }

    // ---- Rule 3: UNSUPPORTED ----
    if unsupported > 0
        || ctx.compat_unsupported
        || ctx.feature_unsupported
        || ctx.critical_extension_unsupported
        || (input.recognition_required
            && (dims.trust_checker_recognition == Recognition::Unsupported
                || dims.trust_profile_recognition == Recognition::Unsupported))
    {
        return (Verdict::Unsupported, coverage);
    }

    // ---- Rule 4: INCOMPLETE ----
    if not_evaluated > 0
        || dimensions_evaluated < coverage.required_dimensions.len()
        || (ctx.signature_mode_required && dims.signature_validity == SigValidity::NotEvaluated)
        || (input.human_review_required_by_policy && dims.human_review != HumanReview::Pass)
        || !input.scan_completed
        || input.limit_stopped_scope
        || input.policy_stale
        || empty_required
    {
        return (Verdict::Incomplete, coverage);
    }

    // ---- Rule 5: NOT_EVALUATED (degenerate; "no required check could be
    // evaluated at all") — unreachable when rule 4 runs (it catches the same
    // condition first); retained for completeness. ----
    if not_evaluated == input.required_check_results.len()
        && input.policy_only_check_ids.is_empty()
        && !empty_required
        && passed == 0
        && failed == 0
        && unsupported == 0
    {
        // Rule 4 already returns Incomplete for not_evaluated > 0; this branch
        // mirrors the RFC's listed form and is defensive.
        return (Verdict::NotEvaluated, coverage);
    }

    // ---- Rule 6: PASS ----
    let positive_dims = dims.integrity_package == Dim3::Pass
        && dims.integrity_artifacts == Dim3::Pass
        && dims.sources_integrity == SourcesIntegrity::Pass
        && matches!(
            dims.sources_availability,
            SourcesAvailability::Pass | SourcesAvailability::NotApplicable
        )
        && matches!(
            dims.signature_validity,
            SigValidity::Valid | SigValidity::NotApplicable
        )
        && matches!(
            dims.trust_signer_identity,
            TrustSigner::Trusted | TrustSigner::NotApplicable
        )
        && matches!(
            dims.trust_policy_decision,
            TrustPolicyDecision::Accepted | TrustPolicyDecision::NotEvaluated
        )
        && matches!(
            dims.trust_checker_recognition,
            Recognition::Pass | Recognition::NotApplicable
        )
        && matches!(
            dims.trust_profile_recognition,
            Recognition::Pass | Recognition::NotApplicable
        )
        && matches!(dims.human_review, HumanReview::Pass | HumanReview::NotApplicable);

    if passed == coverage.required_checks.len() && full && positive_dims {
        return (Verdict::Pass, coverage);
    }

    // Defensive fallback: a fully decided evaluation with a non-positive
    // dimension that rules 1–4 should have classified. Report INCOMPLETE.
    (Verdict::Incomplete, coverage)
}
