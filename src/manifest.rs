//! Manifest parsing and validation (RFC §4.4, §4.9, Appendix A; F21-F35,
//! F50-F53, F57, F58).
//!
//! Validation order and diagnostic classes (RFC §4.3.1, §13.8 mapping):
//! 1. (caller) strict I-JSON parse — `pap.package.manifest-json`,
//!    `pap.package.duplicate-key` or `pap.package.limit-exceeded`;
//! 2. path grammar for every declared payload path — `pap.package.path-invalid`
//!    (class-root prefix, segment limits, ASCII), `pap.package.path-duplicate`
//!    (exact or ASCII case-folded duplicates over one global set),
//!    `pap.package.manifest-self-reference`;
//! 3. closed schema validation — `pap.package.schema` or
//!    `pap.package.unknown-field`;
//! 4. cross-field invariants — duplicate ids (`pap.package.duplicate-id`),
//!    `checkSpecs` version suffix mismatch (`pap.package.schema`).
//!
//! A path-grammar violation is reported as `pap.package.path-invalid`, never
//! additionally as `pap.package.schema` for the same string (§4.3.1). Identity
//! is still computed whenever the manifest can be canonicalized (§13.8), even
//! for a schema-invalid manifest.

use crate::diag::{Diagnostic, Severity};
use crate::digest::Digest;
use crate::json::Json;
use crate::limits::LimitSet;
use crate::pathrule;
use crate::rfc3339::{self, Instant};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Version compatibility classification (RFC §4.9, §15.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compat {
    Supported,
    /// Newer minor within major 0 (e.g. `0.2`).
    MinorNewer,
    /// Older minor of the supported major (`0.0`) or a different major (`1.0+`).
    VersionUnsupported,
}

/// Class-level structural defects that map to specific payload dimensions.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClassDefect {
    /// Any artifacts[] declaration has a path-grammar or duplicate-path defect.
    pub artifacts: bool,
    /// Same for sources[].
    pub sources: bool,
    /// Same for inputs[].
    pub inputs: bool,
    /// Same for claims (affects package integrity only).
    pub claims: bool,
}

impl ClassDefect {
    pub fn any(&self) -> bool {
        self.artifacts || self.sources || self.inputs || self.claims
    }
}

/// Validation outcome.
pub struct ManifestOutcome {
    /// Typed manifest — `None` when a schema/cross-field defect exists.
    pub manifest: Option<Manifest>,
    /// Best-effort declared check set from the raw JSON (survives schema
    /// defects; only used to report `NOT_EVALUATED` rows, §8.2).
    pub declared_specs: Vec<CheckSpec>,
    /// Declared version string, when the manifest parsed (even if invalid).
    pub pap_version: Option<String>,
    pub compat: Compat,
    /// Status of each payload path class found during stage 2.
    pub class_defect: ClassDefect,
    /// True when stage 3/4 found a manifest-level (schema/cross-field) defect.
    pub structure_invalid: bool,
    pub diagnostics: Vec<Diagnostic>,
    /// Extension reports: ignored/critical-unsupported; never interpreted.
    pub extensions: Vec<ExtensionOutcome>,
    pub required_features: Vec<String>,
    pub profile: Option<Profile>,
}

impl ManifestOutcome {
    pub fn fatal(&self) -> bool {
        self.structure_invalid || self.class_defect.any()
    }
}

/// One unknown extension's handling (§4.9).
pub struct ExtensionOutcome {
    pub name: String,
    pub version: String,
    pub critical: bool,
    pub critical_unsupported: bool,
    pub ignored: bool,
}

// ---------------------------------------------------------------------------
// Manifest data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub id: String,
    pub title: Option<String>,
    pub created_at: Option<Instant>,
    pub producer: Option<Producer>,
}

#[derive(Debug, Clone)]
pub struct Producer {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct Subject {
    pub project_id: String,
    pub revision: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Build {
    pub engine_version: Option<String>,
    pub manifest_version: Option<String>,
    pub input_digest: Option<Digest>,
    pub normalized_input_digest: Option<Digest>,
}

#[derive(Debug, Clone)]
pub struct ArtifactDecl {
    pub id: String,
    pub path: String,
    pub media_type: String,
    pub bytes: i64,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Normalization {
    Lf,
    None,
}

#[derive(Debug, Clone)]
pub struct InputDecl {
    pub id: String,
    pub path: String,
    pub media_type: String,
    pub digest: Digest,
    pub normalization: Normalization,
}

#[derive(Debug, Clone)]
pub struct SourceDecl {
    pub id: String,
    pub path: Option<String>,
    pub media_type: String,
    pub digest: Digest,
    pub acquired_at: Option<Instant>,
    pub acquisition: Option<Acquisition>,
}

#[derive(Debug, Clone)]
pub struct Acquisition {
    pub method: String,
    pub uri: Option<String>,
    pub revision: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClaimRef {
    pub kind: &'static str,
    pub path: String,
    pub digest: Digest,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub version: String,
    pub closure_digest: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckSpec {
    pub id: String,
    pub version: String,
    pub required: bool,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub pap_version: String,
    pub package: PackageInfo,
    pub subject: Option<Subject>,
    pub build: Option<Build>,
    pub artifacts: Vec<ArtifactDecl>,
    pub inputs: Vec<InputDecl>,
    pub sources: Vec<SourceDecl>,
    pub claims: Vec<ClaimRef>,
    pub profile: Option<Profile>,
    pub check_specs: Vec<CheckSpec>,
}

impl Manifest {
    /// Global declared payload path set (artifacts, inputs, sources, claims)
    /// for duplicate detection and the undeclared-file scan.
    pub fn declared_paths(&self) -> impl Iterator<Item = &str> {
        self.artifacts
            .iter()
            .map(|a| a.path.as_str())
            .chain(self.inputs.iter().map(|i| i.path.as_str()))
            .chain(self.sources.iter().filter_map(|s| s.path.as_deref()))
            .chain(self.claims.iter().map(|c| c.path.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

pub fn validate(raw: &Json, limits: &LimitSet) -> ManifestOutcome {
    let mut d = DiagCollector {
        diagnostics: Vec::new(),
        limits,
    };
    let mut outcome = ManifestOutcome {
        manifest: None,
        declared_specs: Vec::new(),
        pap_version: None,
        compat: Compat::Supported,
        class_defect: ClassDefect::default(),
        structure_invalid: false,
        diagnostics: Vec::new(),
        extensions: Vec::new(),
        required_features: Vec::new(),
        profile: None,
    };
    let obj = match raw.as_obj() {
        Some(o) => o,
        None => {
            outcome.structure_invalid = true;
            d.error(
                "pap.package.schema",
                "assurance-package.json",
                "manifest is not a JSON object".to_string(),
            );
            outcome.diagnostics = d.diagnostics;
            return outcome;
        }
    };



    // ---- deterministic stage 0: papVersion + closed top-level ---------------
    // papVersion: string with a canonical major.minor pattern (§4.9; leading
    // zeros are a schema error; `format` violations are separate).
    let mut pap_version: Option<(u64, u64, String)> = None;
    {
        let v = obj.iter().find(|(k, _)| k == "papVersion").map(|(_, v)| v);
        match v {
            None => {
                outcome.structure_invalid = true;
                d.schema_missing_field("papVersion");
            }
            Some(val) => match parse_version_string(val, &mut d) {
                Some((maj, min, text)) => {
                    outcome.pap_version = Some(text.clone());
                    pap_version = Some((maj, min, text));
                }
                None => {
                    outcome.structure_invalid = true;
                }
            },
        }
    }

    // ---- stage 2: path grammar over declared payload paths ------------------
    // Collect every declared path with its class; this runs before stage 3 and
    // over the whole declaration set (§4.3.1: one global set, not per class).
    struct PathDecl<'a> {
        class: &'static str,
        index: usize,
        /// Diagnostic scope for this declaration.
        scope: String,
        raw: Option<&'a str>,
        malformed: bool, // field not even a string
    }
    let mut path_decls: Vec<PathDecl> = Vec::new();

    let artifacts_raw = raw.get("artifacts");
    let sources_raw = raw.get("sources");
    let inputs_raw = raw.get("inputs");
    let claims_raw = raw.get("claims");

    for (class, arr, optional) in [
        ("artifacts", artifacts_raw, false),
        ("inputs", inputs_raw, false),
        ("sources", sources_raw, true),
    ] {
        if let Some(Json::Arr(items)) = arr {
            for (i, item) in items.iter().enumerate() {
                match item.get("path") {
                    None if optional => {
                        // referenced-only source: no path declared; fine.
                    }
                    None => {
                        // required field absent: schema-level defect (no read).
                        d.error(
                            "pap.package.schema",
                            &format!("{class}[{i}].path"),
                            "required field path is missing".to_string(),
                        );
                        path_decls.push(PathDecl {
                            class,
                            index: i,
                            scope: format!("{class}[{i}].path"),
                            raw: None,
                            malformed: true,
                        });
                    }
                    Some(rawv) => match rawv.as_str() {
                        Some(s) => path_decls.push(PathDecl {
                            class,
                            index: i,
                            scope: format!("{class}[{i}].path"),
                            raw: Some(s),
                            malformed: false,
                        }),
                        None => {
                            d.error(
                                "pap.package.schema",
                                &format!("{class}[{i}].path"),
                                "path must be a string".to_string(),
                            );
                            path_decls.push(PathDecl {
                                class,
                                index: i,
                                scope: format!("{class}[{i}].path"),
                                raw: None,
                                malformed: true,
                            });
                        }
                    },
                }
            }
        }
    }
    if let Some(Json::Obj(m)) = claims_raw {
        for (kind, val) in m {
            if claim_kind_field(kind).is_none() {
                // unknown claim kind is a schema defect (claims_schema)
                continue;
            }
            match val.get("path").and_then(|p| p.as_str()) {
                Some(s) => path_decls.push(PathDecl {
                    class: "claims",
                    index: 0,
                    scope: format!("claims.{kind}.path"),
                    raw: Some(s),
                    malformed: false,
                }),
                None => {
                    d.error(
                        "pap.package.schema",
                        &format!("claims.{kind}.path"),
                        "claim reference requires path and digest".to_string(),
                    );
                }
            }
        }
    }

    // Grammar validation, then global duplicate/case detection.
    let mut ok_paths: Vec<(String, String, &'static str, usize)> = Vec::new(); // (path, scope, class, idx)
    for decl in &path_decls {
        let scope = decl.scope.clone();
        match decl.raw {
            None => {
                if decl.malformed {
                    // not a string at all: schema handles this; no grammar code
                }
            }
            Some(p) => match pathrule::validate(p, limits) {
                Err(_) => {
                    mark_class_defect(&mut outcome.class_defect, decl.class);
                    d.error(
                        "pap.package.path-invalid",
                        &scope,
                        format!("declared path violates the §4.3.1 grammar: {p}"),
                    );
                }
                Ok(()) => {
                    let expected_root = class_root(decl.class);
                    if !starts_with_root(p, expected_root) {
                        mark_class_defect(&mut outcome.class_defect, decl.class);
                        d.error(
                            "pap.package.path-invalid",
                            &scope,
                            format!(
                                "declared path does not start with its class root {expected_root}/: {p}"
                            ),
                        );
                        ok_paths.push((p.to_string(), scope.clone(), decl.class, decl.index));
                        continue;
                    }
                    // Manifest self-reference (fixed file name, §4.3.3). The
                    // grammar's class-root rule prevents the root name itself;
                    // the check is defence in depth.
                    if p == "assurance-package.json" {
                        outcome.structure_invalid = true;
                        d.error(
                            "pap.package.manifest-self-reference",
                            &scope,
                            "the manifest must not declare itself as a payload".to_string(),
                        );
                        continue;
                    }
                    ok_paths.push((p.to_string(), scope.clone(), decl.class, decl.index));
                }
            },
        }
    }
    // Global duplicate / case-collide over the whole declaration set (§4.3.1:
    // one global set, not per class). Every string-valued declaration
    // participates, including grammar-failed and wrong-root paths.
    {
        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, (path, scope, class, _index)) in ok_paths.iter().enumerate() {
            let folded = pathrule::case_fold(path);
            if let Some(prev_i) = seen.get(&folded) {
                let (prev_path, prev_scope, prev_class, _prev_index) = &ok_paths[*prev_i];
                let exact = prev_path == path;
                mark_class_defect(&mut outcome.class_defect, class);
                if *prev_class != *class {
                    mark_class_defect(&mut outcome.class_defect, prev_class);
                }
                if exact {
                    d.error(
                        "pap.package.path-duplicate",
                        scope,
                        format!("path {path} is declared again (see {prev_scope})"),
                    );
                } else {
                    d.error(
                        "pap.package.path-duplicate",
                        scope,
                        format!("case collision with {prev_path} ({prev_scope})"),
                    );
                }
            } else {
                seen.insert(folded, i);
            }
        }
    }

    // ---- stage 3: closed schema per Appendix A ------------------------------
    schema_stage(obj, &mut d, &mut outcome);

    // ---- stage 4: cross-field invariants ------------------------------------
    cross_field_stage(raw, &mut d, &mut outcome, &limits);

    // ---- requiredFeatures capture (§4.9; every entry is required) ---------
    if let Some(Json::Arr(items)) = raw.get("requiredFeatures") {
        for it in items {
            if let Some(f) = it.as_str() {
                outcome.required_features.push(f.to_string());
            }
        }
    }

    // ---- stage 5: compatibility classification ------------------------------
    if let Some((maj, min, _)) = pap_version {
        outcome.compat = if maj == 0 && min == 1 {
            Compat::Supported
        } else if maj == 0 && min > 1 {
            Compat::MinorNewer
        } else {
            Compat::VersionUnsupported
        };
    } else {
        // missing/invalid version string already a schema defect
        outcome.compat = Compat::VersionUnsupported;
    }

    // ---- structural-defect classification ----------------------------------
    // Any stage 3/4 defect (schema, unknown field, duplicate id, self
    // reference) invalidates the manifest structure: payloads are not read
    // (§7.3 artifacts NOT_EVALUATED) and §7.4 rule 1 forces FAIL. Path-code
    // defects live in class_defect instead.
    if d.diagnostics.iter().any(|diag| {
        matches!(
            diag.code,
            "pap.package.schema"
                | "pap.package.unknown-field"
                | "pap.package.duplicate-id"
                | "pap.package.manifest-self-reference"
        )
    }) {
        outcome.structure_invalid = true;
    }

    // ---- manifest value assembly -------------------------------------------
    if !outcome.structure_invalid && !outcome.class_defect.any() {
        if let Some(m) = extract_manifest(raw, &mut d) {
            outcome.manifest = Some(m);
        }
    }

    // Check spec set should still be best-effort captured for reports even
    // when the manifest cannot be assembled (NOT_EVALUATED rows, §8.2).
    if outcome.manifest.is_none() {
        outcome.declared_specs = best_effort_specs(raw);
    }
    outcome.diagnostics = d.diagnostics;
    outcome
}

// ---------------------------------------------------------------------------
// diagnostics helper
// ---------------------------------------------------------------------------

struct DiagCollector<'d> {
    diagnostics: Vec<Diagnostic>,
    #[allow(dead_code)]
    limits: &'d LimitSet,
}

impl<'d> DiagCollector<'d> {
    fn error(&mut self, code: &'static str, scope: &str, message: String) {
        self.diagnostics.push(Diagnostic::new(
            code,
            Severity::Error,
            scope,
            message,
        ));
    }
    fn schema_missing_field(&mut self, field: &str) {
        self.error(
            "pap.package.schema",
            field,
            format!("required field {field} is missing"),
        );
    }
}

fn mark_class_defect(defects: &mut ClassDefect, class: &str) {
    match class {
        "artifacts" => defects.artifacts = true,
        "sources" => defects.sources = true,
        "inputs" => defects.inputs = true,
        "claims" => defects.claims = true,
        _ => {}
    }
}

fn class_root(class: &str) -> &'static str {
    match class {
        "artifacts" => "artifacts",
        "inputs" => "inputs",
        "sources" => "sources",
        "claims" => "claims",
        _ => "",
    }
}

fn starts_with_root(path: &str, root: &str) -> bool {
    pathrule::starts_with_root(path, root)
}

pub fn claim_kind_field(kind: &str) -> Option<&'static str> {
    // The four claim kinds of v0.1 (§4.7.1).
    match kind {
        "provenance" | "relations" | "producerReport" | "reviews" => {
            Some(match kind {
                "provenance" => "provenance",
                "relations" => "relations",
                "producerReport" => "producerReport",
                _ => "reviews",
            })
        }
        _ => None,
    }
}

/// `^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`, returning (major, minor, text).
fn parse_version_string(v: &Json, d: &mut DiagCollector) -> Option<(u64, u64, String)> {
    let s = match v.as_str() {
        Some(s) => s,
        None => {
            d.error(
                "pap.package.schema",
                "papVersion",
                "papVersion must be a string".to_string(),
            );
            return None;
        }
    };
    fn reject(d: &mut DiagCollector, reason: &str, s: &str) {
        d.error(
            "pap.package.schema",
            "papVersion",
            format!("papVersion is not a canonical major.minor value ({reason}): {s}"),
        );
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 2 {
        reject(d, "wrong shape", s);
        return None;
    }
    let ok_component = |c: &str| -> Option<u64> {
        if c.is_empty() {
            return None;
        }
        if c == "0" {
            return Some(0);
        }
        if c.as_bytes()[0] == b'0' {
            return None; // leading zero
        }
        if !c.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        c.parse::<u64>().ok()
    };
    let maj = ok_component(parts[0]);
    let min = ok_component(parts[1]);
    let (maj, min) = match (maj, min) {
        (Some(m1), Some(m2)) => (m1, m2),
        _ => {
            reject(d, "components must be canonical integers", s);
            return None;
        }
    };
    Some((maj, min, s.to_string()))
}

// ---------------------------------------------------------------------------
// Closed schema stage (Appendix A)
// ---------------------------------------------------------------------------

/// Allowed top-level members of the manifest.
const TOP_LEVEL: &[&str] = &[
    "papVersion",
    "package",
    "subject",
    "build",
    "artifacts",
    "inputs",
    "sources",
    "claims",
    "profile",
    "checkSpecs",
    "extensions",
    "requiredFeatures",
];

fn check_unknown(obj: &[(String, Json)], allowed: &[&str], scope_base: &str, d: &mut DiagCollector) {
    for (k, _) in obj {
        if !allowed.contains(&k.as_str()) {
            d.error(
                "pap.package.unknown-field",
                &format!("{scope_base}.{k}"),
                format!("unknown field: {k}"),
            );
        }
    }
}

fn schema_stage(obj: &[(String, Json)], d: &mut DiagCollector, outcome: &mut ManifestOutcome) {
    check_unknown(obj, TOP_LEVEL, "$", d);

    // package: required id; optional title/createdAt/producer
    match lookup(obj, "package") {
        Some(v) => schema_package(v, d),
        None => {
            outcome.structure_invalid = true;
            d.schema_missing_field("package");
        }
    }

    if let Some(v) = lookup(obj, "subject") {
        schema_subject(v, d);
    }
    if let Some(v) = lookup(obj, "build") {
        schema_build(v, d);
    }

    artifacts_schema(lookup(obj, "artifacts"), d);
    inputs_schema(lookup(obj, "inputs"), d);
    sources_schema(lookup(obj, "sources"), d);
    claims_schema(lookup(obj, "claims"), d);
    profile_schema(lookup(obj, "profile"), d);
    check_specs_schema(lookup(obj, "checkSpecs"), d);
    extensions_schema(lookup(obj, "extensions"), d, outcome);
    required_features_schema(lookup(obj, "requiredFeatures"), d);
}

fn lookup<'a>(obj: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// JSON Schema `maxLength` counts UTF-16 code units.
fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Common field access helper: ensure string with length bounds.
fn req_string<'a>(
    v: Option<&'a Json>,
    field: &str,
    scope: &str,
    max: usize,
    d: &mut DiagCollector,
) -> Option<&'a str> {
    match v {
        Some(Json::Str(s)) => {
            if utf16_len(s) > max {
                d.error(
                    "pap.package.schema",
                    scope,
                    format!("{field} exceeds maxLength {max}"),
                );
                return None;
            }
            Some(s.as_str())
        }
        Some(_) => {
            d.error(
                "pap.package.schema",
                scope,
                format!("{field} must be a string"),
            );
            None
        }
        None => {
            outcome_missing(d, field, scope);
            None
        }
    }
}

fn outcome_missing(d: &mut DiagCollector, _field: &str, scope: &str) {
    d.error(
        "pap.package.schema",
        scope,
        "required field is missing".to_string(),
    );
}

fn opt_string(
    v: Option<&Json>,
    field: &str,
    scope: &str,
    max: usize,
    d: &mut DiagCollector,
) -> Option<String> {
    match v {
        None => None,
        Some(Json::Str(s)) => {
            if utf16_len(s) > max {
                d.error(
                    "pap.package.schema",
                    scope,
                    format!("{field} exceeds maxLength {max}"),
                );
                return None;
            }
            Some(s.clone())
        }
        Some(_) => {
            d.error(
                "pap.package.schema",
                scope,
                format!("{field} must be a string"),
            );
            None
        }
    }
}

fn schema_package(v: &Json, d: &mut DiagCollector) {
    let obj = match v.as_obj() {
        Some(o) => o,
        None => {
            d.error("pap.package.schema", "package","package must be an object".to_string());
            return;
        }
    };
    check_unknown(obj, &["id", "title", "createdAt", "producer"], "package", d);
    req_string(lookup(obj, "id"), "id", "package.id", 512, d);
    opt_string(lookup(obj, "title"), "title", "package.title", 512, d);
    if let Some(c) = lookup(obj, "createdAt") {
        req_rfc3339(Some(c), "createdAt", "package.createdAt", d);
    }
    if let Some(pv) = lookup(obj, "producer") {
        match pv.as_obj() {
            Some(p) => {
                check_unknown(p, &["name", "version"], "package.producer", d);
                req_string(lookup(p, "name"), "name", "package.producer.name", 256, d);
                req_string(
                    lookup(p, "version"),
                    "version",
                    "package.producer.version",
                    128,
                    d,
                );
            }
            None => {
                d.error(
                    "pap.package.schema",
                    "package.producer",
                    "producer must be an object".to_string());
            }
        }
    }
}

fn schema_subject(v: &Json, d: &mut DiagCollector) {
    let obj = match v.as_obj() {
        Some(o) => o,
        None => {
            d.error("pap.package.schema", "subject","subject must be an object".to_string());
            return;
        }
    };
    check_unknown(obj, &["projectId", "revision"], "subject", d);
    req_string(lookup(obj, "projectId"), "projectId", "subject.projectId", 512, d);
    opt_string(lookup(obj, "revision"), "revision", "subject.revision", 256, d);
}

fn schema_build(v: &Json, d: &mut DiagCollector) {
    let obj = match v.as_obj() {
        Some(o) => o,
        None => {
            d.error("pap.package.schema", "build","build must be an object".to_string());
            return;
        }
    };
    check_unknown(
        obj,
        &["engineVersion", "manifestVersion", "inputDigest", "normalizedInputDigest", "extensions"],
        "build",
        d,
    );
    opt_string(lookup(obj, "engineVersion"), "engineVersion", "build.engineVersion", 128, d);
    opt_string(
        lookup(obj, "manifestVersion"),
        "manifestVersion",
        "build.manifestVersion",
        64,
        d,
    );
    opt_digest(lookup(obj, "inputDigest"), "inputDigest", "build.inputDigest", d);
    opt_digest(
        lookup(obj, "normalizedInputDigest"),
        "normalizedInputDigest",
        "build.normalizedInputDigest",
        d,
    );
    if let Some(Json::Arr(exts)) = lookup(obj, "extensions") {
        for (i, e) in exts.iter().enumerate() {
            let scope = format!("build.extensions[{i}]");
            match e.as_obj() {
                Some(o) => {
                    check_unknown(o, &["kind", "id", "version"], &scope, d);
                    let kind = req_string(lookup(o, "kind"), "kind", &format!("{scope}.kind"), 256, d);
                    if let Some(k) = kind {
                        if !matches!(
                            k,
                            "profile" | "adapter" | "renderer" | "checker"
                        ) {
                            d.error(
                                "pap.package.schema",
                                &format!("{scope}.kind"),
                                format!("build extension kind must be a declared enum value: {k}"),
                            );
                        }
                    }
                    req_string(lookup(o, "id"), "id", &format!("{scope}.id"), 256, d);
                    req_string(
                        lookup(o, "version"),
                        "version",
                        &format!("{scope}.version"),
                        128,
                        d,
                    );
                }
                None => {
                    d.error("pap.package.schema", &scope,"build extension must be an object".to_string());
                }
            }
        }
    } else if lookup(obj, "extensions").is_some() {
        d.error(
            "pap.package.schema",
            "build.extensions",
            "build.extensions must be an array".to_string());
    }
}

fn req_digest(v: Option<&Json>, _field: &str, scope: &str, d: &mut DiagCollector) {
    match v {
        Some(Json::Str(s)) => {
            if Digest::parse(s).is_none() {
                d.error(
                    "pap.package.schema",
                    scope,
                    format!("digest field must be sha256:<64 lowercase hex>: {s}"),
                );
            }
        }
        Some(_) => {
            d.error("pap.package.schema", scope,"digest field must be a string".to_string());
        }
        None => outcome_missing(d, "", scope),
    }
}

fn opt_digest(v: Option<&Json>, _field: &str, scope: &str, d: &mut DiagCollector) {
    if let Some(v) = v {
        req_digest(Some(v), "", scope, d);
    }
}

fn req_rfc3339(v: Option<&Json>, _field: &str, scope: &str, d: &mut DiagCollector) {
    match v {
        Some(Json::Str(s)) => {
            if rfc3339::parse(s).is_none() {
                d.error(
                    "pap.package.schema",
                    scope,
                    format!("date-time string must be RFC 3339: {s}"),
                );
            }
        }
        Some(_) => {
            d.error("pap.package.schema", scope,"date-time field must be a string".to_string());
        }
        None => outcome_missing(d, "", scope),
    }
}

fn opt_rfc3339(v: Option<&Json>, _field: &str, scope: &str, d: &mut DiagCollector) {
    if let Some(v) = v {
        req_rfc3339(Some(v), "", scope, d);
    }
}

fn artifacts_schema(v: Option<&Json>, d: &mut DiagCollector) {
    match v {
        None => {
            d.schema_missing_field("artifacts");
        }
        Some(Json::Arr(items)) => {
            if items.is_empty() {
                d.error(
                    "pap.package.schema",
                    "artifacts",
                    "artifacts must not be empty (at least one declared artifact)".to_string());
            }
            for (i, it) in items.iter().enumerate() {
                let scope = format!("artifacts[{i}]");
                match it.as_obj() {
                    Some(o) => {
                        check_unknown(o, &["id", "path", "mediaType", "bytes", "digest"], &scope, d);
                        req_string(lookup(o, "id"), "id", &format!("{scope}.id"), 256, d);
                        req_string(
                            lookup(o, "mediaType"),
                            "mediaType",
                            &format!("{scope}.mediaType"),
                            256,
                            d,
                        );
                        req_digest(lookup(o, "digest"), "digest", &format!("{scope}.digest"), d);
                        // bytes: integer, minimum 0 (I-JSON integer tokens are
                        // already enforced by the parser).
                        match lookup(o, "bytes") {
                            Some(Json::Int(n)) => {
                                if *n < 0 {
                                    d.error(
                                        "pap.package.schema",
                                        &format!("{scope}.bytes"),
                                        "bytes must be an integer >= 0".to_string(),
                                    );
                                }
                            }
                            Some(_) => {
                                d.error(
                                    "pap.package.schema",
                                    &format!("{scope}.bytes"),
                                    "bytes must be an integer".to_string());
                            }
                            None => outcome_missing(d, "bytes", &format!("{scope}.bytes")),
                        }
                    }
                    None => {
                        d.error("pap.package.schema", &scope,"artifact entry must be an object".to_string());
                    }
                }
            }
        }
        Some(_) => {
            d.error("pap.package.schema", "artifacts","artifacts must be an array".to_string());
        }
    }
}

fn inputs_schema(v: Option<&Json>, d: &mut DiagCollector) {
    let Some(Json::Arr(items)) = v else {
        if v.is_none() {
            return; // inputs optional
        }
        d.error("pap.package.schema", "inputs","inputs must be an array".to_string());
        return;
    };
    for (i, it) in items.iter().enumerate() {
        let scope = format!("inputs[{i}]");
        match it.as_obj() {
            Some(o) => {
                check_unknown(o, &["id", "path", "mediaType", "digest", "normalization"], &scope, d);
                req_string(lookup(o, "id"), "id", &format!("{scope}.id"), 256, d);
                req_string(
                    lookup(o, "mediaType"),
                    "mediaType",
                    &format!("{scope}.mediaType"),
                    256,
                    d,
                );
                req_digest(lookup(o, "digest"), "digest", &format!("{scope}.digest"), d);
                match lookup(o, "normalization") {
                    Some(Json::Str(s)) => {
                        if s != "lf" && s != "none" {
                            d.error(
                                "pap.package.schema",
                                &format!("{scope}.normalization"),
                                format!("normalization must be \"lf\" or \"none\": {s}"),
                            );
                        }
                    }
                    Some(_) => {
                        d.error(
                            "pap.package.schema",
                            &format!("{scope}.normalization"),
                            "normalization must be a string".to_string());
                    }
                    None => outcome_missing(
                        d,
                        "normalization",
                        &format!("{scope}.normalization"),
                    ),
                }
            }
            None => {
                d.error("pap.package.schema", &scope,"input entry must be an object".to_string());
            }
        }
    }
}

fn sources_schema(v: Option<&Json>, d: &mut DiagCollector) {
    let Some(Json::Arr(items)) = v else {
        if v.is_none() {
            return;
        }
        d.error("pap.package.schema", "sources","sources must be an array".to_string());
        return;
    };
    for (i, it) in items.iter().enumerate() {
        let scope = format!("sources[{i}]");
        match it.as_obj() {
            Some(o) => {
                check_unknown(
                    o,
                    &["id", "path", "mediaType", "digest", "acquiredAt", "acquisition"],
                    &scope,
                    d,
                );
                req_string(lookup(o, "id"), "id", &format!("{scope}.id"), 256, d);
                req_string(
                    lookup(o, "mediaType"),
                    "mediaType",
                    &format!("{scope}.mediaType"),
                    256,
                    d,
                );
                req_digest(lookup(o, "digest"), "digest", &format!("{scope}.digest"), d);
                opt_rfc3339(lookup(o, "acquiredAt"), "acquiredAt", &format!("{scope}.acquiredAt"), d);
                if let Some(a) = lookup(o, "acquisition") {
                    if let Some(ao) = a.as_obj() {
                        check_unknown(ao, &["method", "uri", "revision"], &format!("{scope}.acquisition"), d);
                        req_string(
                            lookup(ao, "method"),
                            "method",
                            &format!("{scope}.acquisition.method"),
                            128,
                            d,
                        );
                        opt_string(
                            lookup(ao, "uri"),
                            "uri",
                            &format!("{scope}.acquisition.uri"),
                            2048,
                            d,
                        );
                        opt_string(
                            lookup(ao, "revision"),
                            "revision",
                            &format!("{scope}.acquisition.revision"),
                            512,
                            d,
                        );
                    } else {
                        d.error(
                            "pap.package.schema",
                            &format!("{scope}.acquisition"),
                            "acquisition must be an object".to_string());
                    }
                }
            }
            None => {
                d.error("pap.package.schema", &scope,"source entry must be an object".to_string());
            }
        }
    }
}

/// Optional object whose properties are claim refs (§4.7, Appendix A).
fn claims_schema(v: Option<&Json>, d: &mut DiagCollector) {
    let Some(o) = v else { return };
    let obj = match o.as_obj() {
        Some(obj) => obj,
        None => {
            d.error("pap.package.schema", "claims","claims must be an object".to_string());
            return;
        }
    };
    for (k, val) in obj {
        let kind = match claim_kind_field(k) {
            Some(k) => k,
            None => {
                d.error(
                    "pap.package.unknown-field",
                    &format!("claims.{k}"),
                    format!("unknown claim kind: {k}"),
                );
                continue;
            }
        };
        let scope = format!("claims.{kind}");
        match val.as_obj() {
            Some(cr) => {
                check_unknown(cr, &["path", "digest"], &scope, d);
                req_string(lookup(cr, "path"), "path", &format!("{scope}.path"), 255, d);
                req_digest(lookup(cr, "digest"), "digest", &format!("{scope}.digest"), d);
            }
            None => {
                d.error("pap.package.schema", &scope,"claim reference must be an object".to_string());
            }
        }
    }
}

fn profile_schema(v: Option<&Json>, d: &mut DiagCollector) {
    let Some(o) = v else { return };
    let obj = match o.as_obj() {
        Some(obj) => obj,
        None => {
            d.error("pap.package.schema", "profile","profile must be an object".to_string());
            return;
        }
    };
    check_unknown(obj, &["id", "version", "closureDigest"], "profile", d);
    req_string(lookup(obj, "id"), "id", "profile.id", 256, d);
    req_string(lookup(obj, "version"), "version", "profile.version", 128, d);
    opt_digest(lookup(obj, "closureDigest"), "closureDigest", "profile.closureDigest", d);
}

fn check_specs_schema(v: Option<&Json>, d: &mut DiagCollector) {
    match v {
        None => {
            d.schema_missing_field("checkSpecs");
        }
        Some(Json::Arr(items)) => {
            if items.is_empty() {
                d.error(
                    "pap.package.schema",
                    "checkSpecs",
                    "checkSpecs must not be empty".to_string());
            }
            for (i, it) in items.iter().enumerate() {
                let scope = format!("checkSpecs[{i}]");
                match it.as_obj() {
                    Some(o) => {
                        check_unknown(o, &["id", "version", "required"], &scope, d);
                        match lookup(o, "id").and_then(|v| v.as_str()) {
                            Some(id) => {
                                if let Some(suffix) = parse_check_id(id) {
                                    // version must equal the id suffix (§4.4.3)
                                    let version = lookup(o, "version").and_then(|v| v.as_str());
                                    match version {
                                        Some(ver) => {
                                            if !is_canonical_integer(ver) {
                                                d.error(
                                                    "pap.package.schema",
                                                    &format!("{scope}.version"),
                                                    format!(
                                                        "checkSpecs version must be a canonical integer: {ver}"
                                                    ),
                                                );
                                            } else if suffix != ver {
                                                d.error(
                                                    "pap.package.schema",
                                                    &format!("{scope}.version"),
                                                    format!(
                                                        "checkSpecs version {ver} does not match the version suffix of id {id}"
                                                    ),
                                                );
                                            }
                                        }
                                        None => {
                                            outcome_missing(d, "version", &format!("{scope}.version"))
                                        }
                                    }
                                }
                            }
                            None => {
                                outcome_missing(d, "id", &format!("{scope}.id"));
                            }
                        }
                        if let Some(r) = lookup(o, "required") {
                            if !matches!(r, Json::Bool(_)) {
                                d.error(
                                    "pap.package.schema",
                                    &format!("{scope}.required"),
                                    "required must be a boolean".to_string());
                            }
                        }
                    }
                    None => {
                        d.error("pap.package.schema", &scope,"checkSpecs entry must be an object".to_string());
                    }
                }
            }
        }
        Some(_) => {
            d.error("pap.package.schema", "checkSpecs","checkSpecs must be an array".to_string());
        }
    }
}

/// `^pap\.check\.[a-z0-9-]+/[0-9]+$` — returns the version suffix.
pub fn parse_check_id(id: &str) -> Option<&str> {
    let rest = id.strip_prefix("pap.check.")?;
    let idx = rest.rfind('/')?;
    let name = &rest[..idx];
    let suffix = &rest[idx + 1..];
    if name.is_empty() {
        return None;
    }
    if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return None;
    }
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(suffix)
}

fn is_canonical_integer(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s == "0" {
        return true;
    }
    if s.as_bytes()[0] == b'0' {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_digit())
}

fn extensions_schema(v: Option<&Json>, d: &mut DiagCollector, outcome: &mut ManifestOutcome) {
    let Some(o) = v else { return };
    let obj = match o.as_obj() {
        Some(obj) => obj,
        None => {
            d.error("pap.package.schema", "extensions","extensions must be an object".to_string());
            return;
        }
    };
    for (name, val) in obj {
        // key pattern: ^[a-z0-9]+(\.[a-z0-9-]+)+$
        if !extension_key_ok(name) {
            d.error(
                "pap.package.schema",
                &format!("extensions.{name}"),
                format!("extension key must match ^[a-z0-9]+(\\.[a-z0-9-]+)+$: {name}"),
            );
            continue;
        }
        let scope = format!("extensions.{name}");
        match val.as_obj() {
            Some(eo) => {
                check_unknown(eo, &["version", "critical", "data"], &scope, d);
                req_string(lookup(eo, "version"), "version", &format!("{scope}.version"), 128, d);
                match lookup(eo, "critical") {
                    Some(Json::Bool(_)) => {}
                    Some(_) => {
                        d.error(
                            "pap.package.schema",
                            &format!("{scope}.critical"),
                            "critical must be a boolean".to_string());
                    }
                    None => outcome_missing(d, "critical", &format!("{scope}.critical")),
                }
                if let Some(data) = lookup(eo, "data") {
                    if data.as_obj().is_none() {
                        d.error(
                            "pap.package.schema",
                            &format!("{scope}.data"),
                            "data must be an object".to_string());
                    }
                    // data content is opaque; unknown keys inside are allowed
                }
                let critical = matches!(lookup(eo, "critical"), Some(Json::Bool(true)));
                let version = lookup(eo, "version").and_then(|x| x.as_str()).unwrap_or("");
                outcome.extensions.push(ExtensionOutcome {
                    name: name.clone(),
                    version: version.to_string(),
                    critical,
                    critical_unsupported: critical,
                    ignored: !critical,
                });
            }
            None => {
                d.error(
                    "pap.package.schema",
                    &scope,
                    "extension value must be an object".to_string());
            }
        }
    }
}

fn extension_key_ok(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let first_ok = parts[0]
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !parts[0].is_empty();
    let rest_ok = parts[1..]
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
    first_ok && rest_ok
}

fn required_features_schema(v: Option<&Json>, d: &mut DiagCollector) {
    let Some(Json::Arr(items)) = v else {
        if v.is_none() {
            return;
        }
        d.error(
            "pap.package.schema",
            "requiredFeatures",
            "requiredFeatures must be an array".to_string());
        return;
    };
    for (i, it) in items.iter().enumerate() {
        match it.as_str() {
            Some(f) => {
                if !(f.starts_with("pap.")
                    && !f.is_empty()
                    && f[4..]
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
                    && f.len() > 4)
                {
                    d.error(
                        "pap.package.schema",
                        &format!("requiredFeatures[{i}]"),
                        format!("requiredFeatures entry must match ^pap\\.[a-z0-9.-]+$: {f}"),
                    );
                }
            }
            None => {
                d.error(
                    "pap.package.schema",
                    &format!("requiredFeatures[{i}]"),
                    "requiredFeatures entries must be strings".to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-field stage
// ---------------------------------------------------------------------------

fn cross_field_stage(raw: &Json, d: &mut DiagCollector, _outcome: &mut ManifestOutcome, _limits: &LimitSet) {
    // duplicate ids within each declaration type
    for (class, key) in [("artifacts", "artifacts"), ("inputs", "inputs"), ("sources", "sources")] {
        if let Some(Json::Arr(items)) = raw.get(key) {
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for (i, it) in items.iter().enumerate() {
                if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
                    if !seen.insert(id.to_string()) {
                        d.error(
                            "pap.package.duplicate-id",
                            &format!("{class}[{i}].id"),
                            format!("duplicate {class} id: {id}"),
                        );
                    }
                }
            }
        }
    }
    // duplicate check specifications (id equal)
    if let Some(Json::Arr(items)) = raw.get("checkSpecs") {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (i, it) in items.iter().enumerate() {
            if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
                if !seen.insert(id.to_string()) {
                    d.error(
                        "pap.package.duplicate-id",
                        &format!("checkSpecs[{i}].id"),
                        format!("duplicate check specification: {id}"),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Typed extraction
// ---------------------------------------------------------------------------

fn extract_manifest(raw: &Json, d: &mut DiagCollector) -> Option<Manifest> {
    let pap_version = raw.get("papVersion").and_then(|v| v.as_str())?.to_string();
    let package_obj = raw.get("package")?;
    let package = PackageInfo {
        id: package_obj.get("id").and_then(|v| v.as_str())?.to_string(),
        title: package_obj.get("title").and_then(|v| v.as_str()).map(str::to_string),
        created_at: package_obj
            .get("createdAt")
            .and_then(|v| v.as_str())
            .and_then(rfc3339::parse),
        producer: package_obj.get("producer").map(|p| Producer {
            name: p.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            version: p.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        }),
    };
    let subject = raw.get("subject").map(|s| Subject {
        project_id: s.get("projectId").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        revision: s.get("revision").and_then(|v| v.as_str()).map(str::to_string),
    });
    let build = raw.get("build").map(|b| Build {
        engine_version: b.get("engineVersion").and_then(|v| v.as_str()).map(str::to_string),
        manifest_version: b
            .get("manifestVersion")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        input_digest: b
            .get("inputDigest")
            .and_then(|v| v.as_str())
            .and_then(Digest::parse),
        normalized_input_digest: b
            .get("normalizedInputDigest")
            .and_then(|v| v.as_str())
            .and_then(Digest::parse),
    });
    let mut artifacts = Vec::new();
    if let Some(Json::Arr(items)) = raw.get("artifacts") {
        for it in items {
            artifacts.push(ArtifactDecl {
                id: it.get("id").and_then(|v| v.as_str())?.to_string(),
                path: it.get("path").and_then(|v| v.as_str())?.to_string(),
                media_type: it.get("mediaType").and_then(|v| v.as_str())?.to_string(),
                bytes: it.get("bytes").and_then(|v| v.as_int())?,
                digest: it.get("digest").and_then(|v| v.as_str()).and_then(Digest::parse)?,
            });
        }
    }
    let mut inputs = Vec::new();
    if let Some(Json::Arr(items)) = raw.get("inputs") {
        for it in items {
            let norm = match it.get("normalization").and_then(|v| v.as_str())? {
                "lf" => Normalization::Lf,
                _ => Normalization::None,
            };
            inputs.push(InputDecl {
                id: it.get("id").and_then(|v| v.as_str())?.to_string(),
                path: it.get("path").and_then(|v| v.as_str())?.to_string(),
                media_type: it.get("mediaType").and_then(|v| v.as_str())?.to_string(),
                digest: it.get("digest").and_then(|v| v.as_str()).and_then(Digest::parse)?,
                normalization: norm,
            });
        }
    }
    let mut sources = Vec::new();
    if let Some(Json::Arr(items)) = raw.get("sources") {
        for it in items {
            sources.push(SourceDecl {
                id: it.get("id").and_then(|v| v.as_str())?.to_string(),
                path: it.get("path").and_then(|v| v.as_str()).map(str::to_string),
                media_type: it.get("mediaType").and_then(|v| v.as_str())?.to_string(),
                digest: it.get("digest").and_then(|v| v.as_str()).and_then(Digest::parse)?,
                acquired_at: it
                    .get("acquiredAt")
                    .and_then(|v| v.as_str())
                    .and_then(rfc3339::parse),
                acquisition: it.get("acquisition").map(|a| Acquisition {
                    method: a.get("method").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    uri: a.get("uri").and_then(|v| v.as_str()).map(str::to_string),
                    revision: a.get("revision").and_then(|v| v.as_str()).map(str::to_string),
                }),
            });
        }
    }
    let mut claims = Vec::new();
    if let Some(Json::Obj(m)) = raw.get("claims") {
        for (kind, val) in m {
            claims.push(ClaimRef {
                kind: claim_kind_field(kind).ok_or(()).ok()?,
                path: val.get("path").and_then(|v| v.as_str())?.to_string(),
                digest: val.get("digest").and_then(|v| v.as_str()).and_then(Digest::parse)?,
            });
        }
    }
    let profile = raw.get("profile").map(|p| Profile {
        id: p.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        version: p.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        closure_digest: p
            .get("closureDigest")
            .and_then(|v| v.as_str())
            .and_then(Digest::parse),
    });
    let mut check_specs = Vec::new();
    if let Some(Json::Arr(items)) = raw.get("checkSpecs") {
        for it in items {
            check_specs.push(CheckSpec {
                id: it.get("id").and_then(|v| v.as_str())?.to_string(),
                version: it.get("version").and_then(|v| v.as_str())?.to_string(),
                required: match it.get("required") {
                    Some(Json::Bool(b)) => *b,
                    None => true,
                    _ => true,
                },
            });
        }
    }
    let _ = d;
    Some(Manifest {
        pap_version,
        package,
        subject,
        build,
        artifacts,
        inputs,
        sources,
        claims,
        profile,
        check_specs,
    })
}

/// Best-effort declared check set extracted from raw JSON (survives schema
/// defects to populate NOT_EVALUATED rows, §8.2).
fn best_effort_specs(raw: &Json) -> Vec<CheckSpec> {
    let mut specs = Vec::new();
    if let Some(Json::Arr(items)) = raw.get("checkSpecs") {
        for it in items {
            let id = match it.get("id").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => continue,
            };
            let version = match it.get("version").and_then(|v| v.as_str()) {
                Some(v) => v.to_string(),
                None => {
                    // derive from id suffix when possible
                    match parse_check_id(&id) {
                        Some(s) => s.to_string(),
                        None => continue,
                    }
                }
            };
            let required = match it.get("required") {
                Some(Json::Bool(b)) => *b,
                _ => true,
            };
            // Only well-formed ids that carry a version equal to the suffix are
            // reportable as specs; otherwise skip (records need id+version).
            if parse_check_id(&id).is_none() || parse_check_id(&id) != Some(version.as_str()) {
                continue;
            }
            specs.push(CheckSpec { id, version, required });
        }
    }
    specs
}

