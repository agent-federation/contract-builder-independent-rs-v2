//! Minimal strict trust-policy reader (RFC §6.3, Appendix B).
//!
//! Phase 2a implements the subset of Appendix B parsing and validation
//! needed for the report/verdict foundations: version, id, validity window
//! and freshness, signature mode, checkers/profiles pins, required checks
//! and dimensions, limits lowering, humanReview requirement, and the
//! fail-closed structural validation of the fields it consumes. Full policy
//! evaluation (keys/se signer authorization, quorum, human-review evidence)
//! is later-phase scope; what Phase 2a does not evaluate is reported as
//! NOT_EVALUATED, never as a positive result.

use crate::digest::Digest;
use crate::json::{Json, ParserLimits};
use crate::pkg::TerminalError;
use crate::rfc3339::{self, Instant};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigMode {
    Disabled,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    Fresh,
    Stale,
}

pub struct CheckerPin {
    pub id: String,
    pub version: String,
    pub implementation_digest: String,
}

pub struct ProfilePin {
    pub id: String,
    pub version: String,
    pub closure_digest: Option<Digest>,
}

pub struct LoadedPolicy {
    pub id: String,
    /// Digest over the JCS canonical policy bytes.
    pub digest: Digest,
    pub state: PolicyState,
    /// `pap.trust.policy-stale` when expired, `pap.trust.policy-not-yet-valid`
    /// when not yet issued.
    pub stale_code: Option<&'static str>,
    pub signature_mode: SigMode,
    pub required_checks: Vec<String>,
    pub required_dimensions: Vec<String>,
    pub checkers: Vec<CheckerPin>,
    pub profiles: Vec<ProfilePin>,
    pub human_review_required: bool,
    /// Lowered limits as (canonical name, effective value).
    pub lowered_limits: Vec<(&'static str, usize)>,
}

impl LoadedPolicy {
    pub fn lowered_limits(&self) -> &[(&'static str, usize)] {
        &self.lowered_limits
    }
}

/// Default limit value for a named limit (same defaults as §4.3.4).
fn default_limit(name: &str) -> Result<usize, &'static str> {
    Ok(crate::limits::DEFAULT.value(crate::limits::LimitSet::index_of(name).ok_or("unknown limit")?))
}

const DIMENSIONS: &[&str] = &[
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

fn policy_invalid(reason: String) -> TerminalError {
    TerminalError::Usage("pap.trust.policy-invalid", reason)
}

/// Load and validate a trust policy file, computing freshness against `now`.
pub fn load(path: &Path, now: Instant) -> Result<LoadedPolicy, TerminalError> {
    let bytes = std::fs::read(path).map_err(|e| policy_invalid(format!("cannot read policy file: {e}")))?;
    let parser_limits = ParserLimits::defaults();
    let parsed =
        crate::json::parse_document(&bytes, &parser_limits).map_err(|e| policy_invalid(format!("policy is not valid I-JSON: {e}")))?;
    let canonical = crate::jcs::to_canonical(&parsed);
    let digest = Digest::from_bytes(&crate::digest::trust_policy_digest(canonical.as_bytes()));

    let obj = parsed
        .as_obj()
        .ok_or_else(|| policy_invalid("policy must be a JSON object".to_string()))?;

    // Required fields (closed schema): unknown fields are policy errors.
    const REQUIRED: [&str; 12] = [
        "trustPolicyVersion",
        "id",
        "issuedAt",
        "expiresAt",
        "signature",
        "keys",
        "signers",
        "checkers",
        "profiles",
        "requiredChecks",
        "requiredDimensions",
        "humanReview",
    ];
    const OPTIONAL: [&str; 1] = ["limits"];
    for (k, _) in obj {
        if !REQUIRED.contains(&k.as_str()) && !OPTIONAL.contains(&k.as_str()) {
            return Err(policy_invalid(format!("unknown policy field: {k}")));
        }
    }
    for req in REQUIRED {
        if parsed.get(req).is_none() {
            return Err(policy_invalid(format!("required policy field missing: {req}")));
        }
    }

    let version = parsed.get("trustPolicyVersion").and_then(|v| v.as_str());
    if version != Some("0.1") {
        return Err(policy_invalid("trustPolicyVersion must be \"0.1\"".to_string()));
    }

    let id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| policy_invalid("id must be a string".to_string()))?;
    if id.is_empty() || id.len() > 128 {
        return Err(policy_invalid("id length out of range".to_string()));
    }

    let issued = parse_field(parsed.get("issuedAt"), "issuedAt")?;
    let expires = parse_field(parsed.get("expiresAt"), "expiresAt")?;
    if issued > expires {
        return Err(policy_invalid(
            "validity window is unusable (issuedAt after expiresAt)".to_string(),
        ));
    }
    let (state, stale_code) = if now < issued {
        (PolicyState::Stale, Some("pap.trust.policy-not-yet-valid"))
    } else if now > expires {
        (PolicyState::Stale, Some("pap.trust.policy-stale"))
    } else {
        (PolicyState::Fresh, None)
    };

    // signature
    let sig = parsed
        .get("signature")
        .and_then(|v| v.as_obj())
        .ok_or_else(|| policy_invalid("signature must be an object".to_string()))?;
    if sig.iter().any(|(k, _)| k != "mode" && k != "minimumValidSigners") {
        return Err(policy_invalid("unknown signature field".to_string()));
    }
    let mode_str = sig
        .iter()
        .find(|(k, _)| k == "mode")
        .and_then(|(_, v)| v.as_str())
        .ok_or_else(|| policy_invalid("signature.mode must be a string".to_string()))?;
    let mode = match mode_str {
        "disabled" => SigMode::Disabled,
        "optional" => SigMode::Optional,
        "required" => SigMode::Required,
        _ => return Err(policy_invalid(format!("unknown signature mode: {mode_str}"))),
    };
    let mut minimum_valid_signers = 1usize;
    if let Some(v) = sig.iter().find(|(k, _)| k == "minimumValidSigners").map(|(_, v)| v) {
        let n = v.as_int().ok_or_else(|| policy_invalid("minimumValidSigners must be an integer".to_string()))?;
        if n < 1 || n > 64 {
            return Err(policy_invalid("minimumValidSigners out of range".to_string()));
        }
        minimum_valid_signers = n as usize;
    }

    // keys
    let keys = parsed
        .get("keys")
        .and_then(|v| v.as_arr())
        .ok_or_else(|| policy_invalid("keys must be an array".to_string()))?;
    if keys.len() > 64 {
        return Err(policy_invalid("keys exceeds 64 entries".to_string()));
    }
    let mut key_ids: Vec<&str> = Vec::new();
    for k in keys {
        let o = k
            .as_obj()
            .ok_or_else(|| policy_invalid("key entry must be an object".to_string()))?;
        if o.iter().any(|(k, _)| k != "keyId" && k != "algorithm" && k != "publicKey") {
            return Err(policy_invalid("unknown key field".to_string()));
        }
        let kid = o
            .iter()
            .find(|(k, _)| k == "keyId")
            .and_then(|(_, v)| v.as_str())
            .ok_or_else(|| policy_invalid("keyId missing".to_string()))?;
        if kid.is_empty() || kid.len() > 64 {
            return Err(policy_invalid("keyId length out of range".to_string()));
        }
        let alg = o
            .iter()
            .find(|(k, _)| k == "algorithm")
            .and_then(|(_, v)| v.as_str())
            .ok_or_else(|| policy_invalid("algorithm missing".to_string()))?;
        if alg != "ed25519" {
            return Err(policy_invalid(format!("unsupported key algorithm: {alg}")));
        }
        let pk = o
            .iter()
            .find(|(k, _)| k == "publicKey")
            .and_then(|(_, v)| v.as_str())
            .ok_or_else(|| policy_invalid("publicKey missing".to_string()))?;
        if pk.len() != 43 || !pk.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return Err(policy_invalid("publicKey must be canonical base64url of 32 bytes".to_string()));
        }
        if key_ids.contains(&kid) {
            return Err(policy_invalid(format!("duplicate keyId: {kid}")));
        }
        key_ids.push(kid);
    }

    // signers
    let signers = parsed
        .get("signers")
        .and_then(|v| v.as_arr())
        .ok_or_else(|| policy_invalid("signers must be an array".to_string()))?;
    if signers.len() > 64 {
        return Err(policy_invalid("signers exceeds 64 entries".to_string()));
    }
    for s in signers {
        let o = s
            .as_obj()
            .ok_or_else(|| policy_invalid("signer entry must be an object".to_string()))?;
        if o.iter().any(|(k, _)| {
            !matches!(k.as_str(), "keyIds" | "identity" | "allowedRoles" | "allowedPackageIds" | "allowedPackageIdentities")
        }) {
            return Err(policy_invalid("unknown signer field".to_string()));
        }
        let kids = o
            .iter()
            .find(|(k, _)| k == "keyIds")
            .and_then(|(_, v)| v.as_arr())
            .ok_or_else(|| policy_invalid("signer.keyIds must be an array".to_string()))?;
        if kids.is_empty() || kids.len() > 8 {
            return Err(policy_invalid("signer.keyIds size out of range".to_string()));
        }
        for kid in kids {
            let kid_s = kid
                .as_str()
                .ok_or_else(|| policy_invalid("keyIds entries must be strings".to_string()))?;
            if !key_ids.contains(&kid_s) {
                return Err(policy_invalid(format!(
                    "signer keyIds entry {kid_s} is not in keys[]"
                )));
            }
        }
        let _ = o.iter().find(|(k, _)| k == "identity").and_then(|(_, v)| v.as_str()).ok_or_else(|| {
            policy_invalid("signer.identity missing".to_string())
        })?;
        let roles = o
            .iter()
            .find(|(k, _)| k == "allowedRoles")
            .and_then(|(_, v)| v.as_arr())
            .ok_or_else(|| policy_invalid("allowedRoles must be an array".to_string()))?;
        if roles.is_empty() || roles.len() > 2 {
            return Err(policy_invalid("allowedRoles size out of range".to_string()));
        }
        for r in roles {
            match r.as_str() {
                Some("producer") | Some("reviewer") => {}
                _ => return Err(policy_invalid("allowedRoles must be producer or reviewer".to_string())),
            }
        }
        if let Some(pack) = o.iter().find(|(k, _)| k == "allowedPackageIds").map(|(_, v)| v) {
            pack.as_arr()
                .ok_or_else(|| policy_invalid("allowedPackageIds must be an array".to_string()))?;
        }
        if let Some(pids) = o.iter().find(|(k, _)| k == "allowedPackageIdentities").map(|(_, v)| v) {
            let arr = pids
                .as_arr()
                .ok_or_else(|| policy_invalid("allowedPackageIdentities must be an array".to_string()))?;
            for d in arr {
                let s = d
                    .as_str()
                    .ok_or_else(|| policy_invalid("allowedPackageIdentities entries must be strings".to_string()))?;
                if Digest::parse(s).is_none() {
                    return Err(policy_invalid("allowedPackageIdentities entries must be sha256 digests".to_string()));
                }
            }
        }
    }

    // mode==required invariants (Appendix B allOf + §6.3.2)
    if mode == SigMode::Required {
        if keys.is_empty() {
            return Err(policy_invalid(
                "signature.mode required requires at least one key".to_string(),
            ));
        }
        if signers.is_empty() {
            return Err(policy_invalid(
                "signature.mode required requires at least one signer".to_string(),
            ));
        }
        if minimum_valid_signers > signers.len() {
            return Err(policy_invalid(
                "minimumValidSigners exceeds the number of enrolled signers".to_string(),
            ));
        }
    }

    // checkers/profiles pins
    let mut checkers = Vec::new();
    let checkers_arr = parsed
        .get("checkers")
        .and_then(|v| v.as_arr())
        .ok_or_else(|| policy_invalid("checkers must be an array".to_string()))?;
    if checkers_arr.len() > 64 {
        return Err(policy_invalid("checkers exceeds 64 entries".to_string()));
    }
    for c in checkers_arr {
        let o = c
            .as_obj()
            .ok_or_else(|| policy_invalid("checker pin must be an object".to_string()))?;
        if o.iter().any(|(k, _)| k != "id" && k != "version" && k != "implementationDigest") {
            return Err(policy_invalid("unknown checker field".to_string()));
        }
        let id = o
            .iter()
            .find(|(k, _)| k == "id")
            .and_then(|(_, v)| v.as_str())
            .ok_or_else(|| policy_invalid("checker id missing".to_string()))?;
        let version = o
            .iter()
            .find(|(k, _)| k == "version")
            .and_then(|(_, v)| v.as_str())
            .ok_or_else(|| policy_invalid("checker version missing".to_string()))?;
        let dig = o
            .iter()
            .find(|(k, _)| k == "implementationDigest")
            .and_then(|(_, v)| v.as_str())
            .ok_or_else(|| policy_invalid("checker implementationDigest missing".to_string()))?;
        if Digest::parse(dig).is_none() {
            return Err(policy_invalid("checker implementationDigest is not a sha256 digest".to_string()));
        }
        checkers.push(CheckerPin {
            id: id.to_string(),
            version: version.to_string(),
            implementation_digest: dig.to_string(),
        });
    }

    let mut profiles = Vec::new();
    let profiles_arr = parsed
        .get("profiles")
        .and_then(|v| v.as_arr())
        .ok_or_else(|| policy_invalid("profiles must be an array".to_string()))?;
    if profiles_arr.len() > 64 {
        return Err(policy_invalid("profiles exceeds 64 entries".to_string()));
    }
    for p in profiles_arr {
        let o = p
            .as_obj()
            .ok_or_else(|| policy_invalid("profile pin must be an object".to_string()))?;
        if o.iter().any(|(k, _)| !matches!(k.as_str(), "id" | "version" | "closureDigest")) {
            return Err(policy_invalid("unknown profile pin field".to_string()));
        }
        let id = o
            .iter()
            .find(|(k, _)| k == "id")
            .and_then(|(_, v)| v.as_str())
            .ok_or_else(|| policy_invalid("profile id missing".to_string()))?;
        let version = o
            .iter()
            .find(|(k, _)| k == "version")
            .and_then(|(_, v)| v.as_str())
            .ok_or_else(|| policy_invalid("profile version missing".to_string()))?;
        let closure = o
            .iter()
            .find(|(k, _)| k == "closureDigest")
            .and_then(|(_, v)| v.as_str())
            .and_then(Digest::parse);
        profiles.push(ProfilePin {
            id: id.to_string(),
            version: version.to_string(),
            closure_digest: closure,
        });
    }

    // requiredChecks
    let required_checks_v = parsed
        .get("requiredChecks")
        .and_then(|v| v.as_arr())
        .ok_or_else(|| policy_invalid("requiredChecks must be an array".to_string()))?;
    if required_checks_v.is_empty() || required_checks_v.len() > 32 {
        return Err(policy_invalid("requiredChecks size out of range".to_string()));
    }
    let mut required_checks = Vec::new();
    for c in required_checks_v {
        let cid = c
            .as_str()
            .ok_or_else(|| policy_invalid("requiredChecks entries must be strings".to_string()))?;
        if crate::manifest::parse_check_id(cid).is_none() {
            return Err(policy_invalid(format!("requiredChecks entry is not a check id: {cid}")));
        }
        if required_checks.contains(&cid.to_string()) {
            return Err(policy_invalid(format!("duplicate requiredChecks entry: {cid}")));
        }
        required_checks.push(cid.to_string());
    }

    // requiredDimensions
    let req_dims_v = parsed
        .get("requiredDimensions")
        .and_then(|v| v.as_arr())
        .ok_or_else(|| policy_invalid("requiredDimensions must be an array".to_string()))?;
    if req_dims_v.is_empty() || req_dims_v.len() > 16 {
        return Err(policy_invalid("requiredDimensions size out of range".to_string()));
    }
    let mut required_dimensions = Vec::new();
    for dv in req_dims_v {
        let dname = dv
            .as_str()
            .ok_or_else(|| policy_invalid("requiredDimensions entries must be strings".to_string()))?;
        if !DIMENSIONS.contains(&dname) {
            return Err(policy_invalid(format!(
                "requiredDimensions entry is not from the evaluable set: {dname}"
            )));
        }
        if required_dimensions.contains(&dname.to_string()) {
            return Err(policy_invalid(format!("duplicate requiredDimensions entry: {dname}")));
        }
        required_dimensions.push(dname.to_string());
    }

    // humanReview
    let hr = parsed
        .get("humanReview")
        .and_then(|v| v.as_obj())
        .ok_or_else(|| policy_invalid("humanReview must be an object".to_string()))?;
    if hr.iter().any(|(k, _)| k != "required" && k != "maxAgeSeconds") {
        return Err(policy_invalid("unknown humanReview field".to_string()));
    }
    let review_required = hr
        .iter()
        .find(|(k, _)| k == "required")
        .and_then(|(_, v)| v.as_bool_v())
        .ok_or_else(|| policy_invalid("humanReview.required missing".to_string()))?;
    let max_age = hr
        .iter()
        .find(|(k, _)| k == "maxAgeSeconds")
        .and_then(|(_, v)| v.as_int())
        .ok_or_else(|| policy_invalid("humanReview.maxAgeSeconds missing".to_string()))?;
    if max_age < 1 || max_age > 31_536_000 {
        return Err(policy_invalid("humanReview.maxAgeSeconds out of range".to_string()));
    }
    let human_review_required = review_required;

    // limits (lower-only)
    let mut lowered_pairs: Vec<(&'static str, usize)> = Vec::new();
    if let Some(lv) = parsed.get("limits") {
        let lo = lv
            .as_obj()
            .ok_or_else(|| policy_invalid("limits must be an object".to_string()))?;
        if lo.is_empty() {
            return Err(policy_invalid("limits must have at least one entry".to_string()));
        }
        for (name, val) in lo {
            let idx = crate::limits::LimitSet::index_of(name)
                .ok_or_else(|| policy_invalid(format!("unknown limits key: {name}")))?;
            let n = val
                .as_int()
                .ok_or_else(|| policy_invalid(format!("limit {name} must be an integer")))?;
            if n < 1 {
                return Err(policy_invalid(format!("limit {name} must be >= 1")));
            }
            let def = default_limit(name).unwrap_or(0);
            if n as u64 > def as u64 {
                return Err(policy_invalid(format!(
                    "limit {name}={n} exceeds the verifier default {def}"
                )));
            }
            lowered_pairs.push((crate::limits::LimitSet::name_of(idx), n as usize));
        }
    }

    Ok(LoadedPolicy {
        id: id.to_string(),
        digest,
        state,
        stale_code,
        signature_mode: mode,
        required_checks,
        required_dimensions,
        checkers,
        profiles,
        human_review_required,
        lowered_limits: lowered_pairs,
    })
}

fn parse_field(v: Option<&Json>, name: &str) -> Result<Instant, TerminalError> {
    let s = v
        .and_then(|v| v.as_str())
        .ok_or_else(|| policy_invalid(format!("{name} must be a string")))?;
    rfc3339::parse(s).ok_or_else(|| policy_invalid(format!("{name} must be RFC 3339 date-time")))
}

impl Json {
    pub fn as_bool_v(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
}
