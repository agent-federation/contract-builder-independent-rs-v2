use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct Diagnostic {
    pub code: String,
    pub severity: String,
    pub scope: String,
    pub message: String,
}

#[derive(Serialize, Clone)]
pub struct Limitation {
    pub code: String,
    pub detail: String,
}

#[derive(Serialize, Clone)]
pub struct Identities {
    #[serde(rename = "packageIdentity")]
    pub package_identity: Option<String>,
    pub artifacts: Vec<ArtifactIdentity>,
    pub sources: Vec<SourceIdentity>,
    #[serde(rename = "normalizedInputDigest")]
    pub normalized_input_digest: Option<String>,
    #[serde(rename = "extensionClosureDigest")]
    pub extension_closure_digest: Option<String>,
    #[serde(rename = "checkerIdentity")]
    pub checker_identity: String,
    #[serde(rename = "verificationRecordIdentity")]
    pub verification_record_identity: String,
}

#[derive(Serialize, Clone)]
pub struct ArtifactIdentity {
    pub id: String,
    pub declared: String,
    pub computed: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct SourceIdentity {
    pub id: String,
    pub declared: String,
    pub computed: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct Verifier {
    pub id: String,
    pub version: String,
    #[serde(rename = "implementationDigest")]
    pub implementation_digest: String,
    #[serde(rename = "checkerIdentities")]
    pub checker_identities: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct Package {
    pub identity: Option<String>,
    #[serde(rename = "papVersion")]
    pub pap_version: Option<String>,
    pub path: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct Policy {
    pub id: Option<String>,
    pub digest: Option<String>,
    pub state: String,
    pub path: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct IntegrityDims {
    pub package: String,
    pub artifacts: String,
}

#[derive(Serialize, Clone)]
pub struct SourcesDims {
    pub integrity: String,
    pub availability: String,
}

#[derive(Serialize, Clone)]
pub struct SignatureDims {
    pub validity: String,
}

#[derive(Serialize, Clone)]
pub struct TrustDims {
    #[serde(rename = "signerIdentity")]
    pub signer_identity: String,
    #[serde(rename = "policyDecision")]
    pub policy_decision: String,
    #[serde(rename = "checkerRecognition")]
    pub checker_recognition: String,
    #[serde(rename = "profileRecognition")]
    pub profile_recognition: String,
}

#[derive(Serialize, Clone)]
pub struct CheckResult {
    #[serde(rename = "checkId")]
    pub check_id: String,
    pub required: bool,
    pub outcome: String,
}

#[derive(Serialize, Clone)]
pub struct ChecksDim {
    pub results: Vec<CheckResult>,
}

#[derive(Serialize, Clone)]
pub struct HumanReview {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct Dimensions {
    pub integrity: IntegrityDims,
    pub sources: SourcesDims,
    pub signature: SignatureDims,
    pub trust: TrustDims,
    pub checks: ChecksDim,
    #[serde(rename = "humanReview")]
    pub human_review: HumanReview,
    #[serde(rename = "semanticTruth")]
    pub semantic_truth: String,
    #[serde(rename = "legalEnforceability")]
    pub legal_enforceability: String,
}

#[derive(Serialize, Clone)]
pub struct Coverage {
    #[serde(rename = "requiredChecks")]
    pub required_checks: Vec<String>,
    #[serde(rename = "checksEvaluated")]
    pub checks_evaluated: usize,
    #[serde(rename = "checksPassed")]
    pub checks_passed: usize,
    #[serde(rename = "checksFailed")]
    pub checks_failed: usize,
    #[serde(rename = "checksUnsupported")]
    pub checks_unsupported: usize,
    #[serde(rename = "checksNotEvaluated")]
    pub checks_not_evaluated: usize,
    #[serde(rename = "requiredDimensions")]
    pub required_dimensions: Vec<String>,
    #[serde(rename = "dimensionsEvaluated")]
    pub dimensions_evaluated: usize,
    pub full: bool,
}

#[derive(Serialize, Clone)]
pub struct Report {
    #[serde(rename = "reportVersion")]
    pub report_version: String,
    pub verifier: Verifier,
    pub package: Package,
    pub policy: Policy,
    #[serde(rename = "evaluatedAt")]
    pub evaluated_at: String,
    pub identities: Identities,
    pub dimensions: Dimensions,
    pub checks: Vec<serde_json::Value>,
    pub coverage: Coverage,
    pub limitations: Vec<Limitation>,
    pub verdict: String,
    pub diagnostics: Vec<Diagnostic>,
}
