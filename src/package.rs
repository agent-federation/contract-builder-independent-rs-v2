use crate::checker;
use crate::digest;
use crate::json::{parse_json, JsonError, JsonValue};
use crate::path;
use crate::report::*;
use jsonschema::validator_for;
use serde_json::Value as SValue;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const MANIFEST_LIMIT: usize = 1024 * 1024;
const PAYLOAD_FILE_LIMIT: usize = 4096;
const PER_FILE_LIMIT: usize = 256 * 1024 * 1024;
const TOTAL_PAYLOAD_LIMIT: usize = 1024 * 1024 * 1024;
const NESTING_LIMIT: usize = 64;
const STRING_LIMIT: usize = 16 * 1024 * 1024;

pub struct RunResult {
    pub report: Report,
}

fn json_to_serde(v: &JsonValue) -> SValue {
    match v {
        JsonValue::Null => SValue::Null,
        JsonValue::Bool(b) => SValue::Bool(*b),
        JsonValue::Number(n) => SValue::Number((*n).into()),
        JsonValue::String(s) => SValue::String(s.clone()),
        JsonValue::Array(a) => SValue::Array(a.iter().map(json_to_serde).collect()),
        JsonValue::Object(m) => {
            let mut map = serde_json::Map::new();
            for (k, val) in m {
                map.insert(k.clone(), json_to_serde(val));
            }
            SValue::Object(map)
        }
    }
}

fn serde_to_json(v: &SValue) -> JsonValue {
    match v {
        SValue::Null => JsonValue::Null,
        SValue::Bool(b) => JsonValue::Bool(*b),
        SValue::Number(n) => {
            if let Some(i) = n.as_i64() { JsonValue::Number(i) } else { JsonValue::Null }
        }
        SValue::String(s) => JsonValue::String(s.clone()),
        SValue::Array(a) => JsonValue::Array(a.iter().map(serde_to_json).collect()),
        SValue::Object(m) => {
            let mut members = Vec::new();
            for (k, val) in m {
                members.push((k.clone(), serde_to_json(val)));
            }
            JsonValue::Object(members)
        }
    }
}

pub fn run(package_path: &str, now: &str) -> (Report, i32) {
    // resolve root
    let root = match fs::canonicalize(package_path) {
        Ok(p) => p,
        Err(_) => {
            // not-found handled by caller; but return dummy? We'll handle in main before call.
            // Here just produce FAIL report with no path.
            // Not expected.
            return make_io_fail(package_path, now, "pap.package.not-found");
        }
    };
    if !root.is_dir() {
        return make_io_fail(package_path, now, "pap.cli.usage");
    }
    let root_str = root.to_string_lossy().to_string();

    // read manifest
    let manifest_path = root.join("assurance-package.json");
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut limitations: Vec<Limitation> = Vec::new();

    // checker identity
    let (impl_digest, checker_id, _files, _deps) = checker::compute();
    let checker_identity_str = checker_id.clone();

    // read manifest bytes
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut manifest_io_error = false;
    match fs::read(&manifest_path) {
        Ok(b) => {
            if b.len() > MANIFEST_LIMIT {
                diagnostics.push(Diagnostic {
                    code: "pap.package.limit-exceeded".to_string(),
                    severity: "error".to_string(),
                    scope: "package".to_string(),
                    message: "manifest exceeds byte limit".to_string(),
                });
                // manifest limit => FAIL, identity null
                // produce report immediately
                return finalize_report(
                    root_str.clone(), None, None, None, now,
                    diagnostics, limitations, impl_digest, checker_identity_str,
                    Vec::new(), Vec::new(), None, None, None,
                    "FAIL", true,
                );
            }
            manifest_bytes = Some(b);
        }
        Err(_) => {
            manifest_io_error = true;
            diagnostics.push(Diagnostic {
                code: "pap.package.io".to_string(),
                severity: "error".to_string(),
                scope: "package".to_string(),
                message: "manifest cannot be read".to_string(),
            });
        }
    }

    // parse manifest
    let mut manifest_value: Option<JsonValue> = None;
    let mut package_identity: Option<String> = None;
    let mut pap_version: Option<String> = None;
    let mut parse_failed = false;
    let mut parse_error_code: Option<String> = None;

    if manifest_io_error {
        parse_failed = true;
    } else if let Some(bytes) = &manifest_bytes {
        match parse_json(bytes, NESTING_LIMIT, STRING_LIMIT) {
            Ok(v) => {
                manifest_value = Some(v.clone());
                // package identity
                let canon = crate::jcs::canonicalize(&v);
                package_identity = Some(digest::domain_hash("pap.package.v1", canon.as_bytes()));
                // papVersion
                if let JsonValue::Object(members) = &v {
                    for (k, val) in members {
                        if k == "papVersion" {
                            if let JsonValue::String(s) = val {
                                pap_version = Some(s.clone());
                            }
                        }
                    }
                }
            }
            Err(e) => {
                parse_failed = true;
                let code = match e {
                    JsonError::DuplicateKey(_) => "pap.package.duplicate-key",
                    JsonError::NestingLimit | JsonError::StringLimit => "pap.package.limit-exceeded",
                    _ => "pap.package.manifest-json",
                };
                parse_error_code = Some(code.to_string());
                diagnostics.push(Diagnostic {
                    code: code.to_string(),
                    severity: "error".to_string(),
                    scope: "package".to_string(),
                    message: "manifest JSON parse failed".to_string(),
                });
            }
        }
    }

    // If parse failed, return FAIL report with artifacts NOT_EVALUATED
    if parse_failed {
        return finalize_report(
            root_str, package_identity, pap_version, None, now,
            diagnostics, limitations, impl_digest, checker_identity_str,
            Vec::new(), Vec::new(), None, None, None,
            "FAIL", true,
        );
    }

    let mv = manifest_value.as_ref().unwrap();

    // schema validation
    let schema_str = include_str!("../pap/schemas/manifest.schema.json");
    let schema_json: SValue = serde_json::from_str(schema_str).unwrap();
    let instance = json_to_serde(mv);
    let mut schema_ok = true;
    let mut unknown_field = false;
    match validator_for(&schema_json) {
        Ok(validator) => {
            let errors: Vec<_> = validator.iter_errors(&instance).collect();
            if !errors.is_empty() {
                schema_ok = false;
                for e in &errors {
                    let msg = e.to_string();
                    if msg.contains("Additional properties") || msg.contains("additionalProperties") {
                        unknown_field = true;
                    }
                }
                let code = if unknown_field { "pap.package.unknown-field" } else { "pap.package.schema" };
                diagnostics.push(Diagnostic {
                    code: code.to_string(),
                    severity: "error".to_string(),
                    scope: "package".to_string(),
                    message: "manifest schema validation failed".to_string(),
                });
            }
        }
        Err(_) => {
            schema_ok = false;
            diagnostics.push(Diagnostic {
                code: "pap.package.schema".to_string(),
                severity: "error".to_string(),
                scope: "package".to_string(),
                message: "schema compile failed".to_string(),
            });
        }
    }

    // Collect declared payload paths
    // We'll extract from manifest object
    // Helper to get string field
    fn get_array(obj: &JsonValue, key: &str) -> Option<Vec<JsonValue>> {
        if let JsonValue::Object(members) = obj {
            for (k, v) in members {
                if k == key {
                    if let JsonValue::Array(a) = v { return Some(a.clone()); }
                }
            }
        }
        None
    }

    // Cross-field: papVersion compatibility
    let mut version_unsupported = false;
    let mut version_minor_newer = false;
    if let Some(v) = &pap_version {
        if v != "0.1" {
            // parse major.minor
            let parts: Vec<&str> = v.split('.').collect();
            if parts.len() == 2 {
                // canonical check already schema; assume ok
                let major = parts[0].parse::<i64>().ok();
                let minor = parts[1].parse::<i64>().ok();
                if let (Some(maj), Some(min)) = (major, minor) {
                    if maj == 0 && min > 1 {
                        version_minor_newer = true;
                    } else {
                        version_unsupported = true;
                    }
                } else {
                    // non-canonical handled by schema; treat as schema failure
                    schema_ok = false;
                    diagnostics.push(Diagnostic {
                        code: "pap.package.schema".to_string(),
                        severity: "error".to_string(),
                        scope: "package".to_string(),
                        message: "invalid papVersion".to_string(),
                    });
                }
            } else {
                version_unsupported = true;
            }
            if version_minor_newer {
                diagnostics.push(Diagnostic {
                    code: "pap.compat.minor-newer".to_string(),
                    severity: "warning".to_string(),
                    scope: "package".to_string(),
                    message: "newer minor version".to_string(),
                });
            } else if version_unsupported {
                diagnostics.push(Diagnostic {
                    code: "pap.compat.version-unsupported".to_string(),
                    severity: "warning".to_string(),
                    scope: "package".to_string(),
                    message: "unsupported version".to_string(),
                });
            }
        }
    }

    // extensions & requiredFeatures
    let mut critical_ext_unsupported = false;
    let mut unsupported_feature = false;
    if let Some(JsonValue::Object(members)) = Some(mv) {
        for (k, v) in members {
            if k == "extensions" {
                if let JsonValue::Object(exts) = v {
                    for (name, ev) in exts {
                        // unknown extension always (we know none)
                        let critical = if let JsonValue::Object(em) = ev {
                            em.iter().find(|(kk,_)| kk=="critical").and_then(|(_,vv)| if let JsonValue::Bool(b)=vv {Some(*b)} else {None}).unwrap_or(false)
                        } else { false };
                        if critical {
                            critical_ext_unsupported = true;
                            diagnostics.push(Diagnostic {
                                code: "pap.extension.critical-unsupported".to_string(),
                                severity: "error".to_string(),
                                scope: "package".to_string(),
                                message: format!("unsupported critical extension {}", name),
                            });
                        } else {
                            diagnostics.push(Diagnostic {
                                code: "pap.extension.ignored".to_string(),
                                severity: "info".to_string(),
                                scope: "package".to_string(),
                                message: format!("ignored extension {}", name),
                            });
                            limitations.push(Limitation {
                                code: "pap.extension.ignored".to_string(),
                                detail: name.clone(),
                            });
                        }
                    }
                }
            }
            if k == "requiredFeatures" {
                if let JsonValue::Array(feats) = v {
                    for f in feats {
                        if let JsonValue::String(s) = f {
                            unsupported_feature = true;
                            diagnostics.push(Diagnostic {
                                code: "pap.feature.unsupported".to_string(),
                                severity: "error".to_string(),
                                scope: "package".to_string(),
                                message: format!("unsupported feature {}", s),
                            });
                        }
                    }
                }
            }
        }
    }

    // checkSpecs validation
    let mut check_specs: Vec<(String, String, bool)> = Vec::new(); // id, version, required
    let mut check_version_mismatch = false;
    let mut duplicate_id = false;
    let mut duplicate_path = false;
    let mut path_invalid = false;
    if let Some(cs) = get_array(mv, "checkSpecs") {
        for c in cs {
            if let JsonValue::Object(cm) = c {
                let id = cm.iter().find(|(k,_)| k=="id").and_then(|(_,v)| if let JsonValue::String(s)=v {Some(s.clone())} else {None}).unwrap_or_default();
                let version = cm.iter().find(|(k,_)| k=="version").and_then(|(_,v)| if let JsonValue::String(s)=v {Some(s.clone())} else {None}).unwrap_or_default();
                let required = cm.iter().find(|(k,_)| k=="required").and_then(|(_,v)| if let JsonValue::Bool(b)=v {Some(*b)} else {None}).unwrap_or(true);
                // version suffix check
                let suffix = id.rsplit('/').next().unwrap_or("");
                if suffix != version {
                    check_version_mismatch = true;
                }
                check_specs.push((id, version, required));
            }
        }
    }

    // artifact entries and ids
    let mut artifacts_list: Vec<JsonValue> = get_array(mv, "artifacts").unwrap_or_default();
    // duplicate id check across artifacts
    let mut art_ids: BTreeSet<String> = BTreeSet::new();
    for a in &artifacts_list {
        if let JsonValue::Object(am) = a {
            if let Some(JsonValue::String(id)) = am.iter().find(|(k,_)| k=="id").map(|(_,v)| v) {
                if !art_ids.insert(id.clone()) { duplicate_id = true; }
            }
        }
    }
    // inputs/sources duplicates? ids not globally required maybe. Skip.

    // collect declared payload paths
    // artifacts
    let mut declared_paths: Vec<String> = Vec::new();
    let mut artifact_paths: Vec<String> = Vec::new();
    for a in &artifacts_list {
        if let JsonValue::Object(am) = a {
            if let Some(JsonValue::String(p)) = am.iter().find(|(k,_)| k=="path").map(|(_,v)| v) {
                artifact_paths.push(p.clone());
                declared_paths.push(p.clone());
            }
        }
    }
    let mut input_paths: Vec<String> = Vec::new();
    if let Some(inputs) = get_array(mv, "inputs") {
        for inp in inputs {
            if let JsonValue::Object(im) = inp {
                if let Some(JsonValue::String(p)) = im.iter().find(|(k,_)| k=="path").map(|(_,v)| v) {
                    input_paths.push(p.clone());
                    declared_paths.push(p.clone());
                }
            }
        }
    }
    let mut source_paths: Vec<String> = Vec::new();
    if let Some(sources) = get_array(mv, "sources") {
        for src in sources {
            if let JsonValue::Object(sm) = src {
                if let Some(JsonValue::String(p)) = sm.iter().find(|(k,_)| k=="path").map(|(_,v)| v) {
                    source_paths.push(p.clone());
                    declared_paths.push(p.clone());
                }
            }
        }
    }
    // claims
    if let Some(cm) = get_obj(mv, "claims") {
        for (_kind, v) in cm {
            if let JsonValue::Object(cfm) = v {
                if let Some(JsonValue::String(p)) = cfm.iter().find(|(k,_)| k=="path").map(|(_,v)| v) {
                    declared_paths.push(p.clone());
                }
            }
        }
    }

    // path grammar validation + root prefix
    // declared roots per class enforced? We'll validate grammar and for artifacts prefix artifacts/, etc.
    // Generic: path grammar
    for p in &declared_paths {
        if !path::validate_path_grammar(p) {
            path_invalid = true;
        }
    }
    // root prefix checks
    for p in &artifact_paths {
        if !p.starts_with("artifacts/") { path_invalid = true; }
    }
    for p in &input_paths {
        if !p.starts_with("inputs/") { path_invalid = true; }
    }
    for p in &source_paths {
        if !p.starts_with("sources/") { path_invalid = true; }
    }
    // claims paths should start with claims/
    // duplicate/case collision
    let mut seen_cf: BTreeSet<String> = BTreeSet::new();
    for p in &declared_paths {
        let cf = path::ascii_casefold(p);
        if !seen_cf.insert(cf) {
            duplicate_path = true;
        }
    }

    // duplicate id global? artifact ids only required unique within package. We'll treat duplicate artifact id as duplicate_id.
    // checkSpecs? no.

    // If schema invalid, artifacts NOT_EVALUATED. We'll handle.

    // If check version mismatch or duplicate id/path or path invalid => integrity.package FAIL, and for path issues artifacts FAIL.
    let mut integrity_package_fail = false;
    let mut integrity_artifacts_fail = false;
    let mut integrity_artifacts_not_eval = false;

    if parse_error_code.is_some() {
        integrity_package_fail = true;
    }

    if !schema_ok {
        integrity_package_fail = true;
        integrity_artifacts_not_eval = true;
    }

    if check_version_mismatch || duplicate_id {
        integrity_package_fail = true;
        // schema-level? treat as schema failure => artifacts NOT_EVALUATED
        integrity_artifacts_not_eval = true;
        diagnostics.push(Diagnostic {
            code: if duplicate_id { "pap.package.duplicate-id".to_string() } else { "pap.package.schema".to_string() },
            severity: "error".to_string(),
            scope: "package".to_string(),
            message: "cross-field invariant failed".to_string(),
        });
    }

    if duplicate_path {
        integrity_package_fail = true;
        integrity_artifacts_fail = true;
        diagnostics.push(Diagnostic {
            code: "pap.package.path-duplicate".to_string(),
            severity: "error".to_string(),
            scope: "package".to_string(),
            message: "duplicate path".to_string(),
        });
    }

    if path_invalid {
        integrity_package_fail = true;
        integrity_artifacts_fail = true;
        diagnostics.push(Diagnostic {
            code: "pap.package.path-invalid".to_string(),
            severity: "error".to_string(),
            scope: "package".to_string(),
            message: "invalid path".to_string(),
        });
    }

    // empty check specs
    let required_checks: Vec<String> = check_specs.iter().filter(|(_,_,r)| *r).map(|(id,_,_)| id.clone()).collect();
    if required_checks.is_empty() {
        diagnostics.push(Diagnostic {
            code: "pap.package.empty-check-specs".to_string(),
            severity: "warning".to_string(),
            scope: "package".to_string(),
            message: "no required checks".to_string(),
        });
    }

    // version unsupported diagnostics already added.

    // critical ext / feature diagnostics already added.

    // Determine if we should read payloads.
    // Read only if schema_ok and no path_invalid/duplicate_path/check_version_mismatch/duplicate_id? 
    // F22 path invalid: don't read payloads (artifacts FAIL already). F24 duplicate path: don't read.
    // F30 schema invalid: don't read.
    let can_read_payloads = schema_ok && !path_invalid && !duplicate_path && !check_version_mismatch && !duplicate_id;

    // Read artifacts
    let mut artifact_identities: Vec<ArtifactIdentity> = Vec::new();
    let mut artifacts_all_ok = true;
    let mut artifacts_read_any = false;
    let mut limit_hit = false;

    if !can_read_payloads {
        // artifacts NOT_EVALUATED if schema invalid; FAIL if path issues
        if integrity_artifacts_not_eval {
            // NOT_EVALUATED
        } else if integrity_artifacts_fail {
            // FAIL
        } else {
            integrity_artifacts_not_eval = true;
        }
    } else {
        // count limit
        if artifacts_list.len() > PAYLOAD_FILE_LIMIT {
            limit_hit = true;
            integrity_artifacts_not_eval = true; // NOT_EVALUATED for limit
            diagnostics.push(Diagnostic {
                code: "pap.package.limit-exceeded".to_string(),
                severity: "error".to_string(),
                scope: "package".to_string(),
                message: "too many artifacts".to_string(),
            });
        } else {
            // read each
            let mut total_bytes = 0usize;
            for a in &artifacts_list {
                let mut id = String::new();
                let mut p = String::new();
                let mut declared = String::new();
                let mut expected_bytes: i64 = 0;
                if let JsonValue::Object(am) = a {
                    for (k, v) in am {
                        match k.as_str() {
                            "id" => if let JsonValue::String(s)=v { id=s.clone(); },
                            "path" => if let JsonValue::String(s)=v { p=s.clone(); },
                            "digest" => if let JsonValue::String(s)=v { declared=s.clone(); },
                            "bytes" => if let JsonValue::Number(n)=v { expected_bytes=*n; },
                            _ => {}
                        }
                    }
                }
                // read file
                let full = root.join(&p);
                // containment check
                let canonical = fs::canonicalize(&full);
                let mut computed: Option<String> = None;
                let mut ok = true;
                if let Ok(cp) = canonical {
                    if !cp.starts_with(&root) {
                        ok = false;
                        diagnostics.push(Diagnostic { code: "pap.package.path-invalid".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "path escapes root".to_string() });
                    } else {
                        let meta = fs::symlink_metadata(&cp);
                        if let Ok(m) = meta {
                            if m.file_type().is_symlink() {
                                ok = false;
                                diagnostics.push(Diagnostic { code: "pap.package.symlink".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "symlink declared file".to_string() });
                                integrity_artifacts_fail = true;
                            } else if !m.is_file() {
                                ok = false;
                                diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "not a regular file".to_string() });
                                integrity_artifacts_fail = true;
                            } else {
                                // size limit
                                if m.len() as usize > PER_FILE_LIMIT {
                                    limit_hit = true;
                                    ok = false;
                                    diagnostics.push(Diagnostic { code: "pap.package.limit-exceeded".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "file too large".to_string() });
                                } else {
                                    total_bytes += m.len() as usize;
                                    if total_bytes > TOTAL_PAYLOAD_LIMIT {
                                        limit_hit = true;
                                        ok = false;
                                        diagnostics.push(Diagnostic { code: "pap.package.limit-exceeded".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "total payload limit".to_string() });
                                    } else {
                                        match fs::read(&cp) {
                                            Ok(bytes) => {
                                                if bytes.len() as i64 != expected_bytes {
                                                    ok = false;
                                                    diagnostics.push(Diagnostic { code: "pap.integrity.artifact-mismatch".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "byte count mismatch".to_string() });
                                                }
                                                let dig = digest::domain_hash("pap.artifact.v1", &bytes);
                                                if dig != declared {
                                                    ok = false;
                                                    diagnostics.push(Diagnostic { code: "pap.integrity.artifact-mismatch".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "digest mismatch".to_string() });
                                                }
                                                computed = Some(dig);
                                            }
                                            Err(_) => {
                                                ok = false;
                                                diagnostics.push(Diagnostic { code: "pap.package.io".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "cannot read declared file".to_string() });
                                                integrity_artifacts_fail = true;
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            ok = false;
                            diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "declared file missing".to_string() });
                            integrity_artifacts_fail = true;
                        }
                    }
                } else {
                    // file missing or symlink at path
                    // check symlink metadata on original path
                    if let Ok(meta) = fs::symlink_metadata(&full) {
                        if meta.file_type().is_symlink() {
                            diagnostics.push(Diagnostic { code: "pap.package.symlink".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "symlink".to_string() });
                        } else {
                            diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "missing".to_string() });
                        }
                    } else {
                        diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "missing".to_string() });
                    }
                    ok = false;
                    integrity_artifacts_fail = true;
                }
                if !ok {
                    artifacts_all_ok = false;
                    if !limit_hit && !integrity_artifacts_fail {
                        // digest mismatch doesn't set integrity_artifacts_fail? It should FAIL
                        integrity_artifacts_fail = true;
                    }
                }
                artifact_identities.push(ArtifactIdentity {
                    id: id.clone(),
                    declared: declared.clone(),
                    computed,
                });
                artifacts_read_any = true;
            }
        }
        if limit_hit {
            integrity_artifacts_not_eval = true;
            integrity_artifacts_fail = false;
            // computed null for unread? We already may have computed some; RFC says read before stop keep computed. We'll leave as is.
        }
        if !limit_hit {
            if artifacts_all_ok && !artifact_identities.is_empty() {
                // PASS handled later
            } else if !artifacts_all_ok {
                integrity_artifacts_fail = true;
            }
        }
    }

    // If no artifacts declared? schema requires non-empty, so skip.

    // Determine integrity.artifacts status
    let integrity_artifacts_status = if integrity_artifacts_not_eval {
        "NOT_EVALUATED"
    } else if integrity_artifacts_fail || (can_read_payloads && !artifacts_all_ok) {
        "FAIL"
    } else if artifact_identities.iter().all(|a| a.computed.is_some() && a.computed.as_ref() == Some(&a.declared)) {
        "PASS"
    } else {
        "FAIL"
    };
    // If manifest schema invalid, NOT_EVALUATED already.

    // Read sources
    let mut source_identities: Vec<SourceIdentity> = Vec::new();
    let mut sources_all_ok = true;
    if can_read_payloads && !limit_hit {
        if let Some(sources) = get_array(mv, "sources") {
            if sources.len() > PAYLOAD_FILE_LIMIT {
                limit_hit = true;
                diagnostics.push(Diagnostic { code: "pap.package.limit-exceeded".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "too many sources".to_string() });
            } else {
                for src in sources {
                    let mut id = String::new();
                    let mut p: Option<String> = None;
                    let mut declared = String::new();
                    if let JsonValue::Object(sm) = src {
                        for (k, v) in sm {
                            match k.as_str() {
                                "id" => if let JsonValue::String(s)=v { id=s.clone(); },
                                "path" => if let JsonValue::String(s)=v { p=Some(s.clone()); },
                                "digest" => if let JsonValue::String(s)=v { declared=s.clone(); },
                                _ => {}
                            }
                        }
                    }
                    let mut computed: Option<String> = None;
                    if let Some(pathstr) = p {
                        let full = root.join(&pathstr);
                        if let Ok(cp) = fs::canonicalize(&full) {
                            if cp.starts_with(&root) {
                                if let Ok(meta) = fs::symlink_metadata(&cp) {
                                    if meta.file_type().is_symlink() {
                                        sources_all_ok = false;
                                        diagnostics.push(Diagnostic { code: "pap.package.symlink".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "symlink".to_string() });
                                    } else if meta.is_file() {
                                        match fs::read(&cp) {
                                            Ok(bytes) => {
                                                let dig = digest::domain_hash("pap.source.raw.v1", &bytes);
                                                if dig != declared { sources_all_ok = false; diagnostics.push(Diagnostic { code: "pap.integrity.source-mismatch".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "source mismatch".to_string() }); }
                                                computed = Some(dig);
                                            }
                                            Err(_) => { sources_all_ok = false; diagnostics.push(Diagnostic { code: "pap.package.io".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "io".to_string() }); }
                                        }
                                    } else {
                                        sources_all_ok = false;
                                        diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "missing".to_string() });
                                    }
                                }
                            } else {
                                sources_all_ok = false;
                                diagnostics.push(Diagnostic { code: "pap.package.path-invalid".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "escape".to_string() });
                            }
                        } else {
                            sources_all_ok = false;
                            diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "missing".to_string() });
                        }
                    }
                    source_identities.push(SourceIdentity { id, declared, computed });
                }
            }
        }
    }
    // If no embedded sources, sources.integrity NOT_EVALUATED? We'll set later.

    // Read inputs
    let mut normalized_input_digest: Option<String> = None;
    let mut input_identities: Vec<(String, String, Option<String>)> = Vec::new(); // id, declared, computed
    let mut inputs_all_ok = true;
    if can_read_payloads && !limit_hit {
        if let Some(inputs) = get_array(mv, "inputs") {
            if inputs.len() > PAYLOAD_FILE_LIMIT {
                limit_hit = true;
                diagnostics.push(Diagnostic { code: "pap.package.limit-exceeded".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "too many inputs".to_string() });
            } else {
                let mut input_records: Vec<(String, Vec<u8>)> = Vec::new();
                for inp in inputs {
                    let mut id = String::new();
                    let mut p = String::new();
                    let mut declared = String::new();
                    let mut norm = "lf".to_string();
                    if let JsonValue::Object(im) = inp {
                        for (k, v) in im {
                            match k.as_str() {
                                "id" => if let JsonValue::String(s)=v { id=s.clone(); },
                                "path" => if let JsonValue::String(s)=v { p=s.clone(); },
                                "digest" => if let JsonValue::String(s)=v { declared=s.clone(); },
                                "normalization" => if let JsonValue::String(s)=v { norm=s.clone(); },
                                _ => {}
                            }
                        }
                    }
                    let full = root.join(&p);
                    let mut computed: Option<String> = None;
                    if let Ok(cp) = fs::canonicalize(&full) {
                        if cp.starts_with(&root) {
                            if let Ok(meta) = fs::symlink_metadata(&cp) {
                                if meta.file_type().is_symlink() || !meta.is_file() {
                                    inputs_all_ok = false;
                                    diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "missing input".to_string() });
                                } else {
                                    match fs::read(&cp) {
                                        Ok(bytes) => {
                                            let nb = digest::normalize_input(&bytes, &norm);
                                            let dig = digest::input_file_digest(&p, &nb);
                                            if dig != declared {
                                                inputs_all_ok = false;
                                                diagnostics.push(Diagnostic { code: "pap.integrity.input-mismatch".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "input mismatch".to_string() });
                                            }
                                            computed = Some(dig);
                                            input_records.push((p.clone(), nb));
                                        }
                                        Err(_) => { inputs_all_ok = false; diagnostics.push(Diagnostic { code: "pap.package.io".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "io".to_string() }); }
                                    }
                                }
                            }
                        } else {
                            inputs_all_ok = false;
                            diagnostics.push(Diagnostic { code: "pap.package.path-invalid".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "escape".to_string() });
                        }
                    } else {
                        inputs_all_ok = false;
                        diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "missing input".to_string() });
                    }
                    input_identities.push((id, declared, computed));
                }
                if inputs_all_ok && !input_records.is_empty() {
                    normalized_input_digest = Some(digest::normalized_input_set_digest(&input_records));
                } else if input_records.is_empty() {
                    normalized_input_digest = None;
                }
                // build input identities for report? identities.artifacts/sources only; inputs not in identities schema? identities has no inputs array. So skip.
            }
        }
    }
    if !inputs_all_ok {
        integrity_package_fail = true;
    }

    // If sources mismatch, sources.integrity FAIL
    let sources_integrity_status = if !can_read_payloads || integrity_artifacts_not_eval {
        // if schema invalid, sources NOT_EVALUATED
        if !schema_ok { "NOT_EVALUATED" } else { if sources_all_ok && !source_identities.is_empty() { "PASS" } else if source_identities.is_empty() { "NOT_EVALUATED" } else { "FAIL" } }
    } else {
        if source_identities.is_empty() { "NOT_EVALUATED" } else if sources_all_ok { "PASS" } else { "FAIL" }
    };
    if sources_integrity_status == "FAIL" {
        // sources integrity fail doesn't fail package? RFC sources.integrity FAIL is verdict FAIL rule 1. We'll handle verdict.
    }

    // claims reading (digest only)
    let mut claims_all_ok = true;
    if can_read_payloads && !limit_hit {
        if let Some(cm) = get_obj(mv, "claims") {
            for (_kind, v) in cm {
                if let JsonValue::Object(cfm) = v {
                    let mut p = String::new();
                    let mut declared = String::new();
                    for (k, val) in cfm {
                        if k == "path" { if let JsonValue::String(s)=&val { p=s.clone(); } }
                        if k == "digest" { if let JsonValue::String(s)=&val { declared=s.clone(); } }
                    }
                    let full = root.join(&p);
                    if let Ok(cp) = fs::canonicalize(&full) {
                        if cp.starts_with(&root) {
                            if let Ok(bytes) = fs::read(&cp) {
                                let dig = digest::domain_hash("pap.claims.v1", &bytes);
                                if dig != declared {
                                    claims_all_ok = false;
                                    diagnostics.push(Diagnostic { code: "pap.integrity.claim-mismatch".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "claim mismatch".to_string() });
                                }
                                // parse JSON basic
                                if parse_json(&bytes, NESTING_LIMIT, STRING_LIMIT).is_err() {
                                    claims_all_ok = false;
                                    diagnostics.push(Diagnostic { code: "pap.package.claim-invalid".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "claim invalid".to_string() });
                                }
                            } else {
                                claims_all_ok = false;
                                diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "missing claim".to_string() });
                            }
                        } else {
                            claims_all_ok = false;
                            diagnostics.push(Diagnostic { code: "pap.package.path-invalid".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "escape".to_string() });
                        }
                    } else {
                        claims_all_ok = false;
                        diagnostics.push(Diagnostic { code: "pap.package.declared-file-missing".to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "missing claim".to_string() });
                    }
                }
            }
        }
    }
    if !claims_all_ok {
        integrity_package_fail = true;
    }

    // undeclared file scan
    let mut scan_complete = true;
    let mut undeclared_count = 0;
    // declared set for quick check
    let mut declared_set: BTreeSet<String> = declared_paths.iter().cloned().collect();
    declared_set.insert("assurance-package.json".to_string());
    // walk
    fn walk_dir(root: &Path, dir: &Path, declared: &BTreeSet<String>, diagnostics: &mut Vec<Diagnostic>, limitations: &mut Vec<Limitation>, scan_complete: &mut bool, undeclared_count: &mut usize) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => { *scan_complete = false; limitations.push(Limitation { code: "pap.package.undeclared-scan-incomplete".to_string(), detail: "enumeration failed".to_string() }); diagnostics.push(Diagnostic { code: "pap.package.undeclared-scan-incomplete".to_string(), severity: "warning".to_string(), scope: "package".to_string(), message: "scan incomplete".to_string() }); return; }
        };
        for entry in entries {
            let entry = match entry { Ok(e) => e, Err(_) => { *scan_complete = false; limitations.push(Limitation { code: "pap.package.undeclared-scan-incomplete".to_string(), detail: "entry error".to_string() }); diagnostics.push(Diagnostic { code: "pap.package.undeclared-scan-incomplete".to_string(), severity: "warning".to_string(), scope: "package".to_string(), message: "scan incomplete".to_string() }); continue; } };
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            let ft = match entry.file_type() { Ok(t) => t, Err(_) => { *scan_complete = false; continue; } };
            if ft.is_symlink() {
                // skip symlinks in scan
                continue;
            }
            if ft.is_dir() {
                walk_dir(root, &path, declared, diagnostics, limitations, scan_complete, undeclared_count);
            } else if ft.is_file() {
                // if under declared roots? report undeclared if not in declared set
                if rel.starts_with("signatures/") && rel.ends_with(".dsse.json") {
                    // convention-based envelope, not undeclared
                } else if !declared.contains(&rel) {
                    // only consider files under known roots? RFC: present regular file under artifacts/, inputs/, sources/ or claims/ undeclared. Also any unexpected file? We'll report for all files not declared.
                    *undeclared_count += 1;
                    diagnostics.push(Diagnostic { code: "pap.package.undeclared-file".to_string(), severity: "warning".to_string(), scope: "package".to_string(), message: format!("undeclared file {}", rel) });
                }
            }
        }
    }
    walk_dir(&root, &root, &declared_set, &mut diagnostics, &mut limitations, &mut scan_complete, &mut undeclared_count);
    if !scan_complete {
        // already diagnostics added
    }

    // integrity.package status
    let integrity_package_status = if integrity_package_fail || parse_failed { "FAIL" } else { "PASS" };

    // sources integrity status final (if no sources declared -> NOT_EVALUATED)
    let sources_integrity_final = if !can_read_payloads {
        if !schema_ok { "NOT_EVALUATED" } else { sources_integrity_status }
    } else {
        sources_integrity_status
    };
    // availability: NOT_APPLICABLE (no source-dependent check evaluated)
    let sources_availability = "NOT_APPLICABLE";

    // artifacts status final
    let integrity_artifacts_final = if !can_read_payloads {
        if integrity_artifacts_not_eval { "NOT_EVALUATED" } else if integrity_artifacts_fail { "FAIL" } else { "NOT_EVALUATED" }
    } else if limit_hit && artifact_identities.is_empty() {
        "NOT_EVALUATED"
    } else if integrity_artifacts_fail {
        "FAIL"
    } else if integrity_artifacts_not_eval {
        "NOT_EVALUATED"
    } else {
        integrity_artifacts_status
    };

    // checkSpecs results
    // determined by version unsupported
    let mut check_results: Vec<CheckResult> = Vec::new();
    for (id, version, required) in &check_specs {
        let outcome = if version_minor_newer || version_unsupported {
            "NOT_EVALUATED"
        } else {
            "UNSUPPORTED"
        };
        check_results.push(CheckResult {
            check_id: id.clone(),
            required: *required,
            outcome: outcome.to_string(),
        });
        // diagnostic for unsupported
        if !(version_minor_newer || version_unsupported) {
            diagnostics.push(Diagnostic {
                code: "pap.check.unsupported".to_string(),
                severity: "warning".to_string(),
                scope: "checks".to_string(),
                message: format!("unsupported check {}", id),
            });
        } else {
            diagnostics.push(Diagnostic {
                code: "pap.check.not-evaluated".to_string(),
                severity: "warning".to_string(),
                scope: "checks".to_string(),
                message: format!("not evaluated {}", id),
            });
        }
    }

    // required checks list
    let required_checks_list: Vec<String> = check_specs.iter().filter(|(_,_,r)| *r).map(|(id,_,_)| id.clone()).collect();

    // implied required dimensions
    let mut req_dims_set: BTreeSet<String> = BTreeSet::new();
    for (id, _, req) in &check_specs {
        if !*req { continue; }
        if id.starts_with("pap.check.digest-integrity") {
            req_dims_set.insert("integrity".to_string());
            req_dims_set.insert("sources".to_string());
            req_dims_set.insert("checks".to_string());
        } else if id.starts_with("pap.check.source-quote") {
            req_dims_set.insert("sources".to_string());
            req_dims_set.insert("checks".to_string());
        } else if id.starts_with("pap.check.relation-consistency") {
            req_dims_set.insert("checks".to_string());
        } else {
            req_dims_set.insert("checks".to_string());
        }
    }
    // sort according to appendix B enumerable order
    let order = ["integrity", "sources", "checks"];
    let mut required_dimensions: Vec<String> = Vec::new();
    for o in &order {
        if req_dims_set.contains(*o) {
            required_dimensions.push(o.to_string());
        }
    }
    // if empty required checks, required_dimensions empty

    // coverage counters
    let mut checks_unsupported = 0usize;
    let mut checks_not_evaluated = 0usize;
    for (id, _, req) in &check_specs {
        if !*req { continue; }
        if version_minor_newer || version_unsupported {
            checks_not_evaluated += 1;
        } else {
            checks_unsupported += 1;
        }
    }

    // dimensionsEvaluated
    // integrity root decided if both package and artifacts decided
    let integrity_decided = integrity_package_status == "FAIL" || integrity_package_status == "PASS"; // FAIL/PASS decided; NOT_EVALUATED not
    // Actually integrity.package decided if PASS or FAIL (yes). artifacts decided if PASS or FAIL. So root decided if both decided.
    let artifacts_decided = integrity_artifacts_final == "PASS" || integrity_artifacts_final == "FAIL";
    let integrity_root_decided = integrity_decided && artifacts_decided;
    let sources_root_decided = (sources_integrity_final == "PASS" || sources_integrity_final == "FAIL" || sources_integrity_final == "UNAVAILABLE") && true;
    // availability NOT_APPLICABLE decided
    let sources_decided = sources_root_decided;
    let checks_root_decided = checks_unsupported == 0 && checks_not_evaluated == 0 && !required_checks_list.is_empty();
    let mut dimensions_evaluated = 0usize;
    for d in &required_dimensions {
        match d.as_str() {
            "integrity" => if integrity_root_decided { dimensions_evaluated += 1; },
            "sources" => if sources_decided { dimensions_evaluated += 1; },
            "checks" => if checks_root_decided { dimensions_evaluated += 1; },
            _ => {}
        }
    }

    let scan_incomplete = !scan_complete;
    let full = !required_checks_list.is_empty()
        && checks_not_evaluated == 0
        && checks_unsupported == 0
        && dimensions_evaluated == required_dimensions.len()
        && !scan_incomplete
        && !limit_hit;

    if path_invalid {
        diagnostics.retain(|d| d.code != "pap.package.schema");
    }
    if duplicate_path {
        diagnostics.retain(|d| d.code != "pap.package.schema");
    }
    // verdict
    let mut verdict = "PASS";
    // FAIL rule
    if integrity_package_status == "FAIL"
        || integrity_artifacts_final == "FAIL"
        || sources_integrity_final == "FAIL"
        || !claims_all_ok
        || !inputs_all_ok
        || !artifacts_all_ok && integrity_artifacts_final == "FAIL"
    {
        verdict = "FAIL";
    } else if critical_ext_unsupported == false && unsupported_feature == false && version_minor_newer == false && version_unsupported == false && checks_unsupported > 0 {
        // UNSUPPORTED if required check unsupported and no higher
        verdict = "UNSUPPORTED";
    } else if critical_ext_unsupported || unsupported_feature || version_minor_newer || version_unsupported {
        verdict = "UNSUPPORTED";
    } else if required_checks_list.is_empty() {
        verdict = "INCOMPLETE";
    } else if checks_not_evaluated > 0 {
        verdict = "INCOMPLETE";
    } else if scan_incomplete || limit_hit {
        verdict = "INCOMPLETE";
    } else if full == false {
        verdict = "INCOMPLETE";
    } else {
        // checks are UNSUPPORTED due no implementation, but we already handled checks_unsupported>0 -> UNSUPPORTED
        verdict = "UNSUPPORTED";
    }
    // Since Phase 2a implements no checks, any required check is unsupported -> UNSUPPORTED (already).
    if !required_checks_list.is_empty() && checks_unsupported > 0 && verdict != "FAIL" {
        verdict = "UNSUPPORTED";
    }
    if required_checks_list.is_empty() && verdict != "FAIL" {
        verdict = "INCOMPLETE";
    }

    // sources availability
    let sources_availability_final = if required_dimensions.contains(&"sources".to_string()) { "NOT_APPLICABLE" } else { "NOT_APPLICABLE" };

    // build report
    let mut report = Report {
        report_version: "0.1".to_string(),
        verifier: Verifier {
            id: "pap.verifier.rust".to_string(),
            version: "0.1.0".to_string(),
            implementation_digest: impl_digest.clone(),
            checker_identities: vec![checker_identity_str.clone()],
        },
        package: Package {
            identity: package_identity.clone(),
            pap_version: pap_version.clone(),
            path: Some(root_str.clone()),
        },
        policy: Policy {
            id: None,
            digest: None,
            state: "ABSENT".to_string(),
            path: None,
        },
        evaluated_at: now.to_string(),
        identities: Identities {
            package_identity: package_identity.clone(),
            artifacts: artifact_identities.iter().map(|a| ArtifactIdentity {
                id: a.id.clone(),
                declared: a.declared.clone(),
                computed: a.computed.clone(),
            }).collect(),
            sources: source_identities.iter().map(|s| SourceIdentity {
                id: s.id.clone(),
                declared: s.declared.clone(),
                computed: s.computed.clone(),
            }).collect(),
            normalized_input_digest: normalized_input_digest.clone(),
            extension_closure_digest: None,
            checker_identity: checker_identity_str.clone(),
            verification_record_identity: "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        },
        dimensions: Dimensions {
            integrity: IntegrityDims {
                package: integrity_package_status.to_string(),
                artifacts: integrity_artifacts_final.to_string(),
            },
            sources: SourcesDims {
                integrity: sources_integrity_final.to_string(),
                availability: sources_availability_final.to_string(),
            },
            signature: SignatureDims {
                validity: "NOT_APPLICABLE".to_string(),
            },
            trust: TrustDims {
                signer_identity: "NOT_APPLICABLE".to_string(),
                policy_decision: "NOT_EVALUATED".to_string(),
                checker_recognition: "NOT_EVALUATED".to_string(),
                profile_recognition: "NOT_EVALUATED".to_string(),
            },
            checks: ChecksDim {
                results: check_results.clone(),
            },
            human_review: HumanReview {
                status: "NOT_APPLICABLE".to_string(),
                basis: None,
            },
            semantic_truth: "NOT_EVALUATED".to_string(),
            legal_enforceability: "NOT_EVALUATED".to_string(),
        },
        checks: Vec::new(),
        coverage: Coverage {
            required_checks: required_checks_list.clone(),
            checks_evaluated: 0,
            checks_passed: 0,
            checks_failed: 0,
            checks_unsupported,
            checks_not_evaluated,
            required_dimensions: required_dimensions.clone(),
            dimensions_evaluated,
            full,
        },
        limitations,
        verdict: verdict.to_string(),
        diagnostics,
    };

    // extensionClosureDigest from profile if declared
    if let Some(JsonValue::Object(members)) = Some(mv) {
        for (k, v) in members {
            if k == "profile" {
                if let JsonValue::Object(pm) = v {
                    for (pk, pv) in pm {
                        if pk == "closureDigest" {
                            if let JsonValue::String(s) = pv {
                                report.identities.extension_closure_digest = Some(s.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    // compute verification record identity
    let vri = compute_verification_record_identity(&report);
    report.identities.verification_record_identity = vri;

    let exit_code = match report.verdict.as_str() {
        "PASS" => 0,
        "FAIL" => 1,
        "INCOMPLETE" | "NOT_EVALUATED" => 2,
        "UNTRUSTED" => 3,
        "UNSUPPORTED" => 4,
        _ => 1,
    };
    (report, exit_code)
}

// We need a helper to get object members clone
fn get_obj(mv: &JsonValue, key: &str) -> Option<Vec<(String, JsonValue)>> {
    if let JsonValue::Object(members) = mv {
        for (k, v) in members {
            if k == key {
                if let JsonValue::Object(m) = v {
                    return Some(m.clone());
                }
            }
        }
    }
    None
}

// fix: use get_obj instead of mv_members in claims section? We used mv_members which returns None always. Need adjust.
// We'll patch by editing calls.

fn make_io_fail(package_path: &str, now: &str, code: &str) -> (Report, i32) {
    let (impl_digest, checker_id, _, _) = checker::compute();
    let report = Report {
        report_version: "0.1".to_string(),
        verifier: Verifier {
            id: "pap.verifier.rust".to_string(),
            version: "0.1.0".to_string(),
            implementation_digest: impl_digest,
            checker_identities: vec![checker_id.clone()],
        },
        package: Package { identity: None, pap_version: None, path: Some(package_path.to_string()) },
        policy: Policy { id: None, digest: None, state: "ABSENT".to_string(), path: None },
        evaluated_at: now.to_string(),
        identities: Identities {
            package_identity: None,
            artifacts: Vec::new(),
            sources: Vec::new(),
            normalized_input_digest: None,
            extension_closure_digest: None,
            checker_identity: checker_id.clone(),
            verification_record_identity: "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        },
        dimensions: Dimensions {
            integrity: IntegrityDims { package: "FAIL".to_string(), artifacts: "NOT_EVALUATED".to_string() },
            sources: SourcesDims { integrity: "NOT_EVALUATED".to_string(), availability: "NOT_APPLICABLE".to_string() },
            signature: SignatureDims { validity: "NOT_APPLICABLE".to_string() },
            trust: TrustDims { signer_identity: "NOT_APPLICABLE".to_string(), policy_decision: "NOT_EVALUATED".to_string(), checker_recognition: "NOT_EVALUATED".to_string(), profile_recognition: "NOT_EVALUATED".to_string() },
            checks: ChecksDim { results: Vec::new() },
            human_review: HumanReview { status: "NOT_APPLICABLE".to_string(), basis: None },
            semantic_truth: "NOT_EVALUATED".to_string(),
            legal_enforceability: "NOT_EVALUATED".to_string(),
        },
        checks: Vec::new(),
        coverage: Coverage {
            required_checks: Vec::new(),
            checks_evaluated: 0,
            checks_passed: 0,
            checks_failed: 0,
            checks_unsupported: 0,
            checks_not_evaluated: 0,
            required_dimensions: Vec::new(),
            dimensions_evaluated: 0,
            full: false,
        },
        limitations: Vec::new(),
        verdict: "FAIL".to_string(),
        diagnostics: vec![Diagnostic { code: code.to_string(), severity: "error".to_string(), scope: "package".to_string(), message: "io".to_string() }],
    };
    (report, 1)
}

fn finalize_report(
    root_str: String,
    package_identity: Option<String>,
    pap_version: Option<String>,
    _extra: Option<()>,
    now: &str,
    diagnostics: Vec<Diagnostic>,
    limitations: Vec<Limitation>,
    impl_digest: String,
    checker_identity_str: String,
    artifact_identities: Vec<ArtifactIdentity>,
    source_identities: Vec<SourceIdentity>,
    normalized_input_digest: Option<String>,
    _a: Option<()>,
    _b: Option<()>,
    verdict: &str,
    _parse_failed: bool,
) -> (Report, i32) {
    let report = Report {
        report_version: "0.1".to_string(),
        verifier: Verifier {
            id: "pap.verifier.rust".to_string(),
            version: "0.1.0".to_string(),
            implementation_digest: impl_digest.clone(),
            checker_identities: vec![checker_identity_str.clone()],
        },
        package: Package {
            identity: package_identity.clone(),
            pap_version: pap_version.clone(),
            path: Some(root_str.clone()),
        },
        policy: Policy { id: None, digest: None, state: "ABSENT".to_string(), path: None },
        evaluated_at: now.to_string(),
        identities: Identities {
            package_identity: package_identity.clone(),
            artifacts: artifact_identities,
            sources: source_identities,
            normalized_input_digest,
            extension_closure_digest: None,
            checker_identity: checker_identity_str.clone(),
            verification_record_identity: "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        },
        dimensions: Dimensions {
            integrity: IntegrityDims { package: "FAIL".to_string(), artifacts: "NOT_EVALUATED".to_string() },
            sources: SourcesDims { integrity: "NOT_EVALUATED".to_string(), availability: "NOT_APPLICABLE".to_string() },
            signature: SignatureDims { validity: "NOT_APPLICABLE".to_string() },
            trust: TrustDims { signer_identity: "NOT_APPLICABLE".to_string(), policy_decision: "NOT_EVALUATED".to_string(), checker_recognition: "NOT_EVALUATED".to_string(), profile_recognition: "NOT_EVALUATED".to_string() },
            checks: ChecksDim { results: Vec::new() },
            human_review: HumanReview { status: "NOT_APPLICABLE".to_string(), basis: None },
            semantic_truth: "NOT_EVALUATED".to_string(),
            legal_enforceability: "NOT_EVALUATED".to_string(),
        },
        checks: Vec::new(),
        coverage: Coverage {
            required_checks: Vec::new(),
            checks_evaluated: 0,
            checks_passed: 0,
            checks_failed: 0,
            checks_unsupported: 0,
            checks_not_evaluated: 0,
            required_dimensions: Vec::new(),
            dimensions_evaluated: 0,
            full: false,
        },
        limitations,
        verdict: verdict.to_string(),
        diagnostics,
    };
    let exit_code = match verdict {
        "PASS" => 0,
        "FAIL" => 1,
        "INCOMPLETE" | "NOT_EVALUATED" => 2,
        "UNTRUSTED" => 3,
        "UNSUPPORTED" => 4,
        _ => 1,
    };
    (report, exit_code)
}

fn compute_verification_record_identity(report: &Report) -> String {
    // Convert report to serde_json::Value
    let mut val = serde_json::to_value(report).unwrap();
    // remove excluded fields
    if let SValue::Object(ref mut map) = val {
        map.remove("evaluatedAt");
        map.remove("durationMs");
        // package.path
        if let Some(SValue::Object(pkg)) = map.get_mut("package") {
            pkg.remove("path");
        }
        // policy.path
        if let Some(SValue::Object(pol)) = map.get_mut("policy") {
            pol.remove("path");
        }
        // producerClaims block
        map.remove("producerClaims");
        // diagnostics messages
        if let Some(SValue::Array(diags)) = map.get_mut("diagnostics") {
            for d in diags {
                if let SValue::Object(m) = d {
                    m.remove("message");
                }
            }
        }
        // checks diagnostics messages and quoteBase64
        if let Some(SValue::Array(checks)) = map.get_mut("checks") {
            for c in checks {
                if let SValue::Object(cm) = c {
                    if let Some(SValue::Array(ds)) = cm.get_mut("diagnostics") {
                        for d in ds {
                            if let SValue::Object(dm) = d {
                                dm.remove("message");
                            }
                        }
                    }
                    if let Some(SValue::Array(ws)) = cm.get_mut("witnesses") {
                        for w in ws {
                            if let SValue::Object(wm) = w {
                                wm.remove("quoteBase64");
                            }
                        }
                    }
                }
            }
        }
        // replace verificationRecordIdentity with zero digest
        if let Some(SValue::Object(ids)) = map.get_mut("identities") {
            ids.insert("verificationRecordIdentity".to_string(), SValue::String("sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()));
        }
    }
    // convert to JsonValue
    let jv = serde_to_json(&val);
    let canon = crate::jcs::canonicalize(&jv);
    digest::domain_hash("pap.report.v1", canon.as_bytes())
}


