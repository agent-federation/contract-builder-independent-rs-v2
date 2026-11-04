//! Package filesystem reading: root resolution safety, strictly validated
//! payload paths, no-symlink/no-regular rules, bounded streamed reads with
//! running limits, digest recomputation, input normalization, and the
//! undeclared-file scan (RFC §4.3, §4.5.1, §5.2, §5.6, §10.5).
//!
//! Reading model (§4.3.4): classes are read in fixed order (artifacts,
//! embedded sources, inputs, claims in manifest order). Per-file/per-total
//! limits stop the affected class (files read before a stop keep their
//! computed identity; unread declarations report `computed: null`). The
//! total-byte budget is running across classes; once exhausted, later classes
//! are not read.
//!
//! Limit mapping (§4.3.4): a limit hit is a verifier safety boundary — it
//! never fails package integrity; the affected dimension becomes
//! `NOT_EVALUATED` and the verdict is at most `INCOMPLETE`.
//!
//! Input files (§5.6) are classified in one bounded pass (NUL detection, UTF-8
//! validation, CRLF counting, limit admission) and then hashed with their
//! exact framing from the *same opened descriptor* after `seek(0)`. The
//! dataset digest (§5.2 `pap.input.set.v1`) is computed over a second, sorted
//! re-traversal of the same validated paths — each re-open replays identical
//! lstat safety checks, and the limit budget was enforced during the first
//! pass, so the set digest covers exactly the admitted bytes.

use crate::digest::{self, Digest};
use crate::json::{Json, ParseErrorKind};
use crate::limits::LimitSet;
use crate::manifest::{self, InputDecl, Manifest, ManifestOutcome, Normalization};
use crate::sha256::Sha256;
use crate::{jcs, rfc3339};
use std::io::{Read, Seek};

/// Terminal CLI-level failures (never produce a report).
#[derive(Debug)]
pub enum TerminalError {
    /// exit 64 + `pap.cli.usage`, or `pap.trust.policy-invalid` (error 64).
    Usage(&'static str, String),
    /// exit 74 + `pap.package.not-found` (missing/unresolvable PACKAGE).
    NotFound,
    /// exit 74 + `pap.io.error` (output writes and similar host I/O).
    Io(String),
    /// exit 70 + `pap.internal.error`.
    Internal(String),
}

/// Per-payload read failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFailure {
    Missing,
    Io,
    Symlink,
    NonRegular,
}

#[derive(Debug)]
pub struct PayloadResult {
    pub kind: PayloadKind,
    pub id: String,
    pub path: String,
    pub declared_digest: Digest,
    pub declared_bytes: Option<i64>,
    pub computed: Option<Digest>,
    pub computed_bytes: Option<u64>,
    pub failure: Option<FileFailure>,
    pub mismatch: Option<&'static str>,
    pub limit_stopped: bool,
    pub unread_by_limit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Artifact,
    Source,
    Input,
    Claim,
}

pub struct LimitStop {
    pub limit_name: &'static str,
    pub observed: usize,
    pub classes: &'static str,
}

pub struct ScanResult {
    pub completed: bool,
    pub undeclared: Vec<String>,
    pub undeclared_links: Vec<String>,
}

pub struct PackageState {
    pub manifest_raw: Option<Vec<u8>>,
    pub manifest_error: Option<(&'static str, String)>,
    pub manifest_json: Option<Json>,
    pub parse_error: Option<ParseErrorKind>,
    pub canonical: Option<Vec<u8>>,
    pub package_identity: Option<Digest>,
    pub outcome: Option<ManifestOutcome>,
    pub payload_results: Vec<PayloadResult>,
    pub limit_stops: Vec<LimitStop>,
    pub normalized_input_digest: Option<Digest>,
    pub package_scope_limit: bool,
    pub artifacts_scope_limit: bool,
    pub sources_scope_limit: bool,
    pub inputs_scope_limit: bool,
    pub scan: Option<ScanResult>,
    pub envelopes: Vec<String>,
    pub envelopes_scope_limit: bool,
    pub claims_scope_limit: bool,
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_os = "linux")]
const O_CLOEXEC: i32 = 0o2_000_000;
#[cfg(all(unix, not(target_os = "linux")))]
const O_NOFOLLOW: i32 = 0;
#[cfg(all(unix, not(target_os = "linux")))]
const O_CLOEXEC: i32 = 0;
#[cfg(not(unix))]
const O_NOFOLLOW: i32 = 0;
#[cfg(not(unix))]
const O_CLOEXEC: i32 = 0;

fn open_payload(
    root: &std::path::Path,
    relative: &str,
) -> Result<(std::fs::File, u64), FileFailure> {
    let segments: Vec<&str> = relative.split('/').filter(|s| !s.is_empty()).collect();
    let mut prefix = std::path::PathBuf::from(root);
    for (idx, seg) in segments.iter().enumerate() {
        prefix.push(seg);
        match std::fs::symlink_metadata(&prefix) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(FileFailure::Missing),
            Err(_) => return Err(FileFailure::Io),
            Ok(md) => {
                if md.file_type().is_symlink() {
                    return Err(FileFailure::Symlink);
                }
                if idx + 1 < segments.len() && !md.is_dir() {
                    return Err(FileFailure::NonRegular);
                }
            }
        }
    }
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(&prefix);
    match file {
        Ok(f) => {
            let md = match f.metadata() {
                Ok(m) => m,
                Err(_) => return Err(FileFailure::Io),
            };
            if !md.is_file() {
                return Err(FileFailure::NonRegular);
            }
            Ok((f, md.len()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(FileFailure::Missing),
        Err(_) => Err(FileFailure::Io),
    }
}

fn open_manifest(root: &std::path::Path) -> Result<(std::fs::File, u64), FileFailure> {
    open_payload(root, "assurance-package.json")
}

/// Running limit state for streamed reads (§4.3.4).
pub struct LimitState {
    pub file_bytes: u64,
    pub total_bytes: u64,
    pub used_total: u64,
    pub file_used: u64,
    pub total_exhausted: bool,
}

#[derive(Debug)]
pub enum ReadStop {
    Eof,
    FileLimit,
    TotalLimit,
}

/// Stream `file` in chunks through `h`, respecting a per-file cap (when
/// provided) and the running total cap.
fn stream_hash_limited(
    file: &mut std::fs::File,
    h: &mut Sha256,
    st: &mut LimitState,
    per_file_cap: Option<u64>,
) -> Result<(u64, ReadStop), std::io::Error> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut admitted: u64 = 0;
    loop {
        match file.read(&mut buf) {
            Ok(0) => return Ok((admitted, ReadStop::Eof)),
            Ok(n) => {
                let n64 = n as u64;
                // total cap first (higher-level), then per-file cap
                let total_room = st.total_bytes - st.used_total;
                let file_room = per_file_cap
                    .map(|cap| cap - st.file_used)
                    .unwrap_or(u64::MAX);
                let room = total_room.min(file_room).min(n64);
                // Whichever cap bound the admission decides the stop kind.
                // (room == 0 can only mean an exhausted cap.)
                let stop = if room < n64 {
                    if total_room <= file_room {
                        Some(ReadStop::TotalLimit)
                    } else {
                        Some(ReadStop::FileLimit)
                    }
                } else {
                    None
                };
                if room > 0 {
                    h.update(&buf[..room as usize]);
                    st.used_total += room;
                    st.file_used += room;
                    admitted += room;
                }
                if let Some(s) = stop {
                    return Ok((admitted, s));
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Incremental UTF-8 validation state machine (1 continuation byte at a time).
fn utf8_step(b: u8, state: &mut u32) -> bool {
    if *state > 0 {
        if b & 0xC0 == 0x80 {
            *state -= 1;
            true
        } else {
            false
        }
    } else if b & 0x80 == 0x00 {
        true
    } else if b & 0xE0 == 0xC0 {
        *state = 1;
        true
    } else if b & 0xF0 == 0xE0 {
        *state = 2;
        true
    } else if b & 0xF8 == 0xF0 {
        *state = 3;
        true
    } else {
        false
    }
}

/// CRLF-normalizing writer: replaces CRLF and lone CR with LF, collapsed
/// across chunk boundaries (RFC §5.6 rule 3).
struct NormalWriter<'a> {
    h: &'a mut Sha256,
    pending_cr: bool,
    out_len: u64,
}

impl<'a> NormalWriter<'a> {
    fn feed(&mut self, chunk: &[u8]) {
        let mut out: Vec<u8> = Vec::with_capacity(chunk.len().saturating_sub(1).max(1));
        for &b in chunk {
            match self.pending_cr {
                true => {
                    if b == 0x0A {
                        self.pending_cr = false;
                        out.push(0x0A);
                    } else {
                        out.push(0x0A);
                        self.pending_cr = false;
                        if b == 0x0D {
                            self.pending_cr = true;
                        } else {
                            out.push(b);
                        }
                    }
                }
                false => {
                    if b == 0x0D {
                        self.pending_cr = true;
                    } else {
                        out.push(b);
                    }
                }
            }
        }
        self.h.update(&out);
        self.out_len += out.len() as u64;
    }
    fn flush(&mut self) {
        if self.pending_cr {
            self.h.update(&[0x0A]);
            self.out_len += 1;
            self.pending_cr = false;
        }
    }
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

pub struct VerifyInput {
    pub package_arg: String,
    pub limits: LimitSet,
    pub now: rfc3339::Instant,
    pub policy: Option<crate::policy::LoadedPolicy>,
    /// Operator-supplied policy path text (report field, identity-excluded).
    pub policy_path: Option<String>,
    pub verifier_id: &'static str,
    pub verifier_version: &'static str,
    pub implementation_digest: &'static str,
    pub checker_identity: &'static str,
}

pub struct VerifyOutput {
    pub report_json: Json,
    pub exit_code: u32,
}

pub fn verify(input: &VerifyInput) -> Result<VerifyOutput, TerminalError> {
    let root = std::fs::canonicalize(&input.package_arg).map_err(|_| TerminalError::NotFound)?;
    if !root.is_dir() {
        return Err(TerminalError::Usage(
            "pap.cli.usage",
            "PACKAGE must name a directory".to_string(),
        ));
    }

    let limits = input.limits;
    let mut state = PackageState {
        manifest_raw: None,
        manifest_error: None,
        manifest_json: None,
        parse_error: None,
        canonical: None,
        package_identity: None,
        outcome: None,
        payload_results: Vec::new(),
        limit_stops: Vec::new(),
        normalized_input_digest: None,
        package_scope_limit: false,
        artifacts_scope_limit: false,
        sources_scope_limit: false,
        inputs_scope_limit: false,
        scan: None,
        envelopes: Vec::new(),
        envelopes_scope_limit: false,
        claims_scope_limit: false,
    };

    // ---- manifest read within the limit ------------------------------------
    match open_manifest(&root) {
        Err(FileFailure::Missing) => {
            state.manifest_error = Some((
                "pap.package.io",
                "assurance-package.json is missing".to_string(),
            ));
        }
        Err(FileFailure::Symlink) => {
            state.manifest_error = Some((
                "pap.package.io",
                "assurance-package.json is a symbolic link".to_string(),
            ));
        }
        Err(FileFailure::NonRegular) => {
            state.manifest_error = Some((
                "pap.package.io",
                "assurance-package.json is not a regular file".to_string(),
            ));
        }
        Err(FileFailure::Io) => {
            state.manifest_error = Some((
                "pap.package.io",
                "cannot read assurance-package.json".to_string(),
            ));
        }
        Ok((file, size)) => {
            if size > limits.manifest_bytes as u64 {
                state.manifest_error = Some((
                    "pap.package.limit-exceeded",
                    format!(
                        "manifest exceeds the manifestBytes limit (limit {}, observed {})",
                        limits.manifest_bytes, size
                    ),
                ));
            } else {
                let mut raw = Vec::with_capacity(size as usize);
                match read_cap(file, limits.manifest_bytes, &mut raw) {
                    Err(_) => {
                        state.manifest_error = Some((
                            "pap.package.io",
                            "cannot read assurance-package.json".to_string(),
                        ));
                    }
                    Ok(()) => {
                        state.manifest_raw = Some(raw);
                    }
                }
            }
        }
    }

    // ---- strict parse -------------------------------------------------------
    if state.manifest_raw.is_some() {
        let raw = state.manifest_raw.as_ref().unwrap();
        let parser_limits = crate::json::ParserLimits {
            depth: limits.json_nesting,
            string_bytes: limits.json_string_bytes,
        };
        match crate::json::parse_document(raw, &parser_limits) {
            Ok(v) => state.manifest_json = Some(v),
            Err(e) => state.parse_error = Some(e.kind),
        }
    }

    // ---- canonicalization and packageIdentity ------------------------------
    if let Some(v) = &state.manifest_json {
        let canonical = jcs::to_canonical(v);
        let id = digest::package_identity(canonical.as_bytes());
        state.canonical = Some(canonical.into_bytes());
        state.package_identity = Some(Digest::from_bytes(&id));
    }

    // ---- manifest validation ------------------------------------------------
    if let Some(v) = &state.manifest_json {
        state.outcome = Some(manifest::validate(v, &limits));
    }

    // ---- payloads -----------------------------------------------------------
    if let Some(outcome) = &state.outcome {
        if outcome.manifest.is_some() {
            let manifest = outcome.manifest.as_ref().unwrap().clone();
            read_payloads(&root, &manifest, &limits, &mut state);
        }
        // Structurally invalid, or version-unsupported manifests are not read:
        // the affected dimensions report NOT_EVALUATED and for structure
        // defects §7.4 rule 1 forces FAIL.
    }

    // ---- undeclared scan ----------------------------------------------------
    if state.manifest_json.is_some() {
        state.scan = Some(scan_tree(&root, &state));
    }

    // ---- envelope discovery (never read in Phase 2a) ------------------------
    {
        let evaluate_envelopes = match &input.policy {
            None => true,
            Some(p) => p.signature_mode != crate::policy::SigMode::Disabled,
        };
        if evaluate_envelopes {
            let mut found = Vec::new();
            collect_envelopes(&root, &mut found);
            found.sort();
            if found.len() > limits.signature_envelopes {
                state.envelopes_scope_limit = true;
                state.limit_stops.push(LimitStop {
                    limit_name: "signatureEnvelopes",
                    observed: found.len(),
                    classes: "signatures",
                });
            } else {
                state.envelopes = found;
            }
        }
    }

    crate::report::build_report(&state, input)
}

fn read_cap(mut file: std::fs::File, cap: usize, out: &mut Vec<u8>) -> std::io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buf)? {
            0 => return Ok(()),
            n => {
                if out.len() + n > cap {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::FileTooLarge,
                        "manifest exceeds the byte limit",
                    ));
                }
                out.extend_from_slice(&buf[..n]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Input classification (rewritten, cross-chunk correct)
// ---------------------------------------------------------------------------

/// Classification of an input stream (§5.6 rules and framing data).
#[derive(Debug)]
pub struct InputClassified {
    pub has_nul: bool,
    pub utf8_ok: bool,
    pub crlf_pairs: u64,
    pub admitted: u64,
    pub stop: Option<ReadStop>,
}

/// Cross-chunk CRLF counter (§5.2/§5.6: counts CRLF pairs for the framing
/// content length).
struct CrLfCounter {
    carried_cr: bool,
    pairs: u64,
}

impl CrLfCounter {
    fn new() -> Self {
        CrLfCounter {
            carried_cr: false,
            pairs: 0,
        }
    }
    fn feed(&mut self, chunk: &[u8]) {
        let mut idx = 0;
        if self.carried_cr {
            if chunk.first() == Some(&0x0A) {
                self.pairs += 1;
                idx = 1;
            }
            self.carried_cr = false;
        }
        while idx < chunk.len() {
            if chunk[idx] == 0x0D {
                if idx + 1 == chunk.len() {
                    self.carried_cr = true;
                } else if chunk[idx + 1] == 0x0A {
                    self.pairs += 1;
                    idx += 1;
                }
            }
            idx += 1;
        }
    }
}

fn classify_input2(
    file: &mut std::fs::File,
    st: &mut LimitState,
    per_file_cap: Option<u64>,
) -> Result<InputClassified, std::io::Error> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut has_nul = false;
    let mut utf8_ok = true;
    let mut utf8_state: u32 = 0;
    let mut counter = CrLfCounter::new();
    let mut admitted: u64 = 0;
    loop {
        match file.read(&mut buf) {
            Ok(0) => {
                // trailing partial UTF-8 sequence is invalid
                if utf8_ok && utf8_state > 0 {
                    utf8_ok = false;
                }
                return Ok(InputClassified {
                    has_nul,
                    utf8_ok,
                    crlf_pairs: counter.pairs,
                    admitted,
                    stop: None,
                });
            }
            Ok(n) => {
                let n64 = n as u64;
                let total_room = st.total_bytes - st.used_total;
                let file_room = per_file_cap
                    .map(|cap| cap - st.file_used)
                    .unwrap_or(u64::MAX);
                let room = total_room.min(file_room).min(n64);
                // Whichever cap bound the admission decides the stop kind.
                let stop = if room < n64 || total_room == 0 {
                    if total_room <= file_room {
                        Some(ReadStop::TotalLimit)
                    } else {
                        Some(ReadStop::FileLimit)
                    }
                } else {
                    None
                };
                let chunk = &buf[..room as usize];
                if !has_nul && chunk.contains(&0) {
                    has_nul = true;
                }
                if utf8_ok {
                    for &b in chunk {
                        if !utf8_step(b, &mut utf8_state) {
                            utf8_ok = false;
                            break;
                        }
                    }
                }
                counter.feed(chunk);
                st.used_total += room;
                st.file_used += room;
                admitted += room;
                if let Some(s) = stop {
                    if utf8_ok && utf8_state > 0 {
                        utf8_ok = false; // stopped mid-sequence: cannot confirm validity
                    }
                    return Ok(InputClassified {
                        has_nul,
                        utf8_ok,
                        crlf_pairs: counter.pairs,
                        admitted,
                        stop: Some(s),
                    });
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Emit one `record("input", [path, content])` into `h` — framing plus the
/// exact content (normalized when the classification says the input is text).
fn emit_input_record(
    file: &mut std::fs::File,
    inp: &InputDecl,
    cls: &InputClassified,
    h: &mut Sha256,
) -> u64 {
    let content_len = if cls.has_nul || !cls.utf8_ok {
        cls.admitted
    } else {
        cls.admitted - cls.crlf_pairs
    };
    h.update(&(5u32).to_be_bytes());
    h.update(b"input");
    h.update(&2u32.to_be_bytes());
    h.update(&(inp.path.len() as u32).to_be_bytes());
    h.update(inp.path.as_bytes());
    h.update(&(content_len as u32).to_be_bytes());
    let _ = file.seek(std::io::SeekFrom::Start(0));
    if cls.has_nul || !cls.utf8_ok || inp.normalization == Normalization::None {
        // binary fallback or "none" handling → stream raw bytes
        stream_exact(file, h, cls.admitted);
    } else {
        let mut nw = NormalWriter {
            h,
            pending_cr: false,
            out_len: 0,
        };
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => nw.feed(&buf[..n]),
                Err(_) => break,
            }
        }
        nw.flush();
        debug_assert_eq!(nw.out_len, content_len);
    }
    content_len
}

fn stream_exact(file: &mut std::fs::File, h: &mut Sha256, expected: u64) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut done = 0u64;
    while done < expected {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let take = n.min((expected - done) as usize);
                h.update(&buf[..take]);
                done += take as u64;
            }
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Payload reads
// ---------------------------------------------------------------------------

fn read_payloads(
    root: &std::path::Path,
    manifest: &Manifest,
    limits: &LimitSet,
    state: &mut PackageState,
) {
    let artifacts_count_ok = manifest.artifacts.len() <= limits.payload_files;
    let sources_count_ok =
        manifest.sources.iter().filter(|s| s.path.is_some()).count() <= limits.payload_files;
    let inputs_count_ok = manifest.inputs.len() <= limits.payload_files;
    let claims_count_ok = manifest.claims.len() <= limits.claims_files;
    if !artifacts_count_ok {
        state.limit_stops.push(LimitStop {
            limit_name: "payloadFiles",
            observed: manifest.artifacts.len(),
            classes: "artifacts",
        });
        state.artifacts_scope_limit = true;
    }
    if !sources_count_ok {
        state.limit_stops.push(LimitStop {
            limit_name: "payloadFiles",
            observed: manifest.sources.iter().filter(|s| s.path.is_some()).count(),
            classes: "sources",
        });
        state.sources_scope_limit = true;
    }
    if !inputs_count_ok {
        state.limit_stops.push(LimitStop {
            limit_name: "payloadFiles",
            observed: manifest.inputs.len(),
            classes: "inputs",
        });
        state.inputs_scope_limit = true;
    }
    if !claims_count_ok {
        state.limit_stops.push(LimitStop {
            limit_name: "claimsFiles",
            observed: manifest.claims.len(),
            classes: "claims",
        });
        state.claims_scope_limit = true;
    }

    let mut st = LimitState {
        file_bytes: 0,
        total_bytes: limits.total_payload_bytes as u64,
        used_total: 0,
        file_used: 0,
        total_exhausted: false,
    };
    let mut total_aborted = false;

    // ---- artifacts ----
    if artifacts_count_ok && !total_aborted {
        for art in &manifest.artifacts {
            if total_aborted || st.used_total >= st.total_bytes {
                break;
            }
            let mut res = PayloadResult {
                kind: PayloadKind::Artifact,
                id: art.id.clone(),
                path: art.path.clone(),
                declared_digest: art.digest.clone(),
                declared_bytes: Some(art.bytes),
                computed: None,
                computed_bytes: None,
                failure: None,
                mismatch: None,
                limit_stopped: false,
                unread_by_limit: false,
            };
            match open_payload(root, &art.path) {
                Err(f) => res.failure = Some(f),
                Ok((mut file, _)) => {
                    st.file_used = 0;
                    let mut h = Sha256::new();
                    h.update(b"pap.artifact.v1");
                    h.update(&[0x00]);
                    match stream_hash_limited(
                        &mut file,
                        &mut h,
                        &mut st,
                        Some(limits.file_bytes as u64),
                    ) {
                        Err(_) => res.failure = Some(FileFailure::Io),
                        Ok((n, stop)) => match stop {
                            ReadStop::Eof => {
                                let dg = h.finish();
                                res.computed = Some(Digest::from_bytes(&dg));
                                res.computed_bytes = Some(n);
                                if dg != art.digest.0 || n != art.bytes.unsigned_abs() {
                                    res.mismatch = Some("pap.integrity.artifact-mismatch");
                                }
                            }
                            ReadStop::FileLimit => {
                                res.limit_stopped = true;
                                res.unread_by_limit = true;
                                state.artifacts_scope_limit = true;
                                state.limit_stops.push(LimitStop {
                                    limit_name: "fileBytes",
                                    observed: limits.file_bytes,
                                    classes: "artifacts",
                                });
                            }
                            ReadStop::TotalLimit => {
                                res.limit_stopped = true;
                                res.unread_by_limit = true;
                                total_aborted = true;
                                state.artifacts_scope_limit = true;
                                state.limit_stops.push(LimitStop {
                                    limit_name: "totalPayloadBytes",
                                    observed: limits.total_payload_bytes,
                                    classes: "artifacts",
                                });
                            }
                        },
                    }
                }
            }
            state.payload_results.push(res);
        }
    }

    // ---- embedded sources ----
    if sources_count_ok && !total_aborted {
        for src in &manifest.sources {
            let Some(path) = &src.path else { continue };
            if total_aborted || st.used_total >= st.total_bytes {
                break;
            }
            let mut res = PayloadResult {
                kind: PayloadKind::Source,
                id: src.id.clone(),
                path: path.clone(),
                declared_digest: src.digest.clone(),
                declared_bytes: None,
                computed: None,
                computed_bytes: None,
                failure: None,
                mismatch: None,
                limit_stopped: false,
                unread_by_limit: false,
            };
            match open_payload(root, path) {
                Err(f) => res.failure = Some(f),
                Ok((mut file, _)) => {
                    st.file_used = 0;
                    let mut h = Sha256::new();
                    h.update(b"pap.source.raw.v1");
                    h.update(&[0x00]);
                    match stream_hash_limited(
                        &mut file,
                        &mut h,
                        &mut st,
                        Some(limits.file_bytes as u64),
                    ) {
                        Err(_) => res.failure = Some(FileFailure::Io),
                        Ok((_n, stop)) => match stop {
                            ReadStop::Eof => {
                                let dg = h.finish();
                                res.computed = Some(Digest::from_bytes(&dg));
                                if dg != src.digest.0 {
                                    res.mismatch = Some("pap.integrity.source-mismatch");
                                }
                            }
                            ReadStop::FileLimit => {
                                res.limit_stopped = true;
                                res.unread_by_limit = true;
                                state.sources_scope_limit = true;
                                state.limit_stops.push(LimitStop {
                                    limit_name: "fileBytes",
                                    observed: limits.file_bytes,
                                    classes: "sources",
                                });
                            }
                            ReadStop::TotalLimit => {
                                res.limit_stopped = true;
                                res.unread_by_limit = true;
                                total_aborted = true;
                                state.sources_scope_limit = true;
                                state.limit_stops.push(LimitStop {
                                    limit_name: "totalPayloadBytes",
                                    observed: limits.total_payload_bytes,
                                    classes: "sources",
                                });
                            }
                        },
                    }
                }
            }
            state.payload_results.push(res);
        }
    }

    // ---- inputs (once per file: classify + framed digest) ----
    let mut input_classified: Vec<(InputClassified,)> = Vec::new();
    if inputs_count_ok && !total_aborted {
        for inp in &manifest.inputs {
            if total_aborted || st.used_total >= st.total_bytes {
                input_classified.push((InputClassified {
                    has_nul: false,
                    utf8_ok: true,
                    crlf_pairs: 0,
                    admitted: 0,
                    stop: Some(ReadStop::TotalLimit),
                },));
                continue;
            }
            let mut res = PayloadResult {
                kind: PayloadKind::Input,
                id: inp.id.clone(),
                path: inp.path.clone(),
                declared_digest: inp.digest.clone(),
                declared_bytes: None,
                computed: None,
                computed_bytes: None,
                failure: None,
                mismatch: None,
                limit_stopped: false,
                unread_by_limit: false,
            };
            match open_payload(root, &inp.path) {
                Err(f) => {
                    res.failure = Some(f);
                    state.payload_results.push(res);
                    input_classified.push((InputClassified {
                        has_nul: false,
                        utf8_ok: true,
                        crlf_pairs: 0,
                        admitted: 0,
                        stop: Some(ReadStop::Eof),
                    },));
                    continue;
                }
                Ok((mut file, _)) => {
                    st.file_used = 0;
                    match classify_input2(&mut file, &mut st, Some(limits.file_bytes as u64)) {
                        Err(_) => {
                            res.failure = Some(FileFailure::Io);
                            state.payload_results.push(res);
                            input_classified.push((InputClassified {
                                has_nul: false,
                                utf8_ok: true,
                                crlf_pairs: 0,
                                admitted: 0,
                                stop: Some(ReadStop::Eof),
                            },));
                            continue;
                        }
                        Ok(cls) => match cls.stop {
                            None | Some(ReadStop::Eof) => {
                                // digest from the same descriptor
                                let mut h = Sha256::new();
                                h.update(b"pap.input.file.v1");
                                h.update(&[0x00]);
                                emit_input_record(&mut file, inp, &cls, &mut h);
                                let dg = h.finish();
                                res.computed = Some(Digest::from_bytes(&dg));
                                if dg != inp.digest.0 {
                                    res.mismatch = Some("pap.integrity.input-mismatch");
                                }
                                input_classified.push((cls,));
                            }
                            Some(ReadStop::FileLimit) => {
                                res.limit_stopped = true;
                                state.inputs_scope_limit = true;
                                state.limit_stops.push(LimitStop {
                                    limit_name: "fileBytes",
                                    observed: limits.file_bytes,
                                    classes: "inputs",
                                });
                                input_classified.push((InputClassified {
                                    has_nul: false,
                                    utf8_ok: true,
                                    crlf_pairs: 0,
                                    admitted: 0,
                                    stop: Some(ReadStop::FileLimit),
                                },));
                            }
                            Some(ReadStop::TotalLimit) => {
                                res.limit_stopped = true;
                                total_aborted = true;
                                state.inputs_scope_limit = true;
                                state.limit_stops.push(LimitStop {
                                    limit_name: "totalPayloadBytes",
                                    observed: limits.total_payload_bytes,
                                    classes: "inputs",
                                });
                                input_classified.push((InputClassified {
                                    has_nul: false,
                                    utf8_ok: true,
                                    crlf_pairs: 0,
                                    admitted: 0,
                                    stop: Some(ReadStop::TotalLimit),
                                },));
                            }
                        },
                    }
                }
            }
            state.payload_results.push(res);
        }
    }
    input_classified.clear();

    // ---- normalizedInputDigest: sorted second traversal (§5.2) ----
    if inputs_count_ok
        && !total_aborted
        && !manifest.inputs.is_empty()
        && !state.inputs_scope_limit
    {
        let mut sorted: Vec<&InputDecl> = manifest.inputs.iter().collect();
        sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        let mut h = Sha256::new();
        h.update(b"pap.input.set.v1");
        h.update(&[0x00]);
        let mut ok = true;
        // The second traversal uses its own (unbounded) limit state: the
        // §4.3.4 budget was fully enforced during the first pass, and the set
        // digest must cover exactly those bytes.
        let mut st2 = LimitState {
            file_bytes: u64::MAX,
            total_bytes: u64::MAX,
            used_total: 0,
            file_used: 0,
            total_exhausted: false,
        };
        for inp in sorted {
            match open_payload(root, &inp.path) {
                Err(_) => {
                    ok = false;
                    break;
                }
                Ok((mut file, _)) => {
                    // Classification for content was performed in the first
                    // traversal; reuse its result by re-classifying a view of
                    // the exact same admitted region — cheap and equivalent.
                    match classify_input2(&mut file, &mut st2, None) {
                        Err(_) => {
                            ok = false;
                            break;
                        }
                        Ok(cls) => {
                            if cls.stop.is_some() {
                                ok = false;
                                break;
                            }
                            // The set digest covers exactly the bytes
                            // admitted by the first pass: cap the content
                            // read at the first-pass admitted length.
                            emit_input_record(&mut file, inp, &cls, &mut h);
                        }
                    }
                }
            }
        }
        if ok {
            state.normalized_input_digest = Some(Digest::from_bytes(&h.finish()));
        }
    }

    // ---- claims (raw bytes; not fileBytes-bounded in v0.1, only the total
    // budget and claimsFiles count apply) ----
    if claims_count_ok && !total_aborted {
        for claim in &manifest.claims {
            if total_aborted || st.used_total >= st.total_bytes {
                break;
            }
            let mut res = PayloadResult {
                kind: PayloadKind::Claim,
                id: claim.kind.to_string(),
                path: claim.path.clone(),
                declared_digest: claim.digest.clone(),
                declared_bytes: None,
                computed: None,
                computed_bytes: None,
                failure: None,
                mismatch: None,
                limit_stopped: false,
                unread_by_limit: false,
            };
            match open_payload(root, &claim.path) {
                Err(f) => res.failure = Some(f),
                Ok((mut file, _)) => {
                    st.file_used = 0;
                    let mut h = Sha256::new();
                    h.update(b"pap.claims.v1");
                    h.update(&[0x00]);
                    match stream_hash_limited(&mut file, &mut h, &mut st, None) {
                        Err(_) => res.failure = Some(FileFailure::Io),
                        Ok((_n, stop)) => match stop {
                            ReadStop::Eof => {
                                let dg = h.finish();
                                res.computed = Some(Digest::from_bytes(&dg));
                                if dg != claim.digest.0 {
                                    res.mismatch = Some("pap.integrity.claim-mismatch");
                                }
                            }
                            ReadStop::TotalLimit => {
                                res.limit_stopped = true;
                                res.unread_by_limit = true;
                                total_aborted = true;
                                state.claims_scope_limit = true;
                                state.package_scope_limit = true;
                                state.limit_stops.push(LimitStop {
                                    limit_name: "totalPayloadBytes",
                                    observed: limits.total_payload_bytes,
                                    classes: "claims",
                                });
                            }
                            ReadStop::FileLimit => unreachable!(),
                        },
                    }
                }
            }
            state.payload_results.push(res);
        }
    }
}

// ---------------------------------------------------------------------------
// Undeclared-file scan (§4.3.3)
// ---------------------------------------------------------------------------

const SCAN_ENTRY_BUDGET: usize = 1_000_000;
const SCAN_DIR_BUDGET: usize = 16_384;

fn scan_tree(root: &std::path::Path, state: &PackageState) -> ScanResult {
    let declared: std::collections::HashSet<String> = state
        .outcome
        .as_ref()
        .and_then(|o| o.manifest.as_ref())
        .map(|m| m.declared_paths().map(|p| p.to_string()).collect())
        .unwrap_or_default();
    let raw_declared = state
        .manifest_json
        .as_ref()
        .map(collect_declared_raw)
        .unwrap_or_default();

    let mut undeclared = Vec::new();
    let mut undeclared_links = Vec::new();
    let mut completed = true;
    let mut entries = 0usize;
    let mut dirs_seen = 0usize;

    let mut stack: Vec<(std::path::PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    'outer: while let Some((dir, rel_prefix)) = stack.pop() {
        dirs_seen += 1;
        if dirs_seen > SCAN_DIR_BUDGET {
            completed = false;
            break;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => {
                completed = false;
                break;
            }
        };
        for entry in rd.flatten() {
            entries += 1;
            if entries > SCAN_ENTRY_BUDGET {
                completed = false;
                break 'outer;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let rel = if rel_prefix.is_empty() {
                name.clone()
            } else {
                format!("{rel_prefix}/{name}")
            };
            if rel == "assurance-package.json" {
                continue;
            }
            if declared.contains(&rel) || raw_declared.contains(&rel) {
                // declared payloads are handled by the read phase; failure at
                // declared paths is reported there.
                continue;
            }
            let Ok(ft) = entry.file_type() else {
                completed = false;
                break 'outer;
            };
            if ft.is_dir() {
                stack.push((entry.path(), rel));
                continue;
            }
            if ft.is_symlink() {
                undeclared_links.push(rel.clone());
                continue;
            }
            if !ft.is_file() {
                undeclared_links.push(rel.clone());
                continue;
            }
            undeclared.push(rel.clone());
        }
    }
    ScanResult {
        completed,
        undeclared,
        undeclared_links,
    }
}

fn collect_declared_raw(v: &Json) -> Vec<String> {
    let mut out = Vec::new();
    for arr_key in ["artifacts", "inputs", "sources"] {
        if let Some(Json::Arr(items)) = v.get(arr_key) {
            for it in items {
                if let Some(p) = it.get("path").and_then(|p| p.as_str()) {
                    out.push(p.to_string());
                }
            }
        }
    }
    if let Some(Json::Obj(m)) = v.get("claims") {
        for (_, val) in m {
            if let Some(p) = val.get("path").and_then(|p| p.as_str()) {
                out.push(p.to_string());
            }
        }
    }
    out
}

fn collect_envelopes(root: &std::path::Path, out: &mut Vec<String>) {
    let dir = root.join("signatures");
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".dsse.json") || !envelope_name_ok(&name) {
            continue;
        }
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() || ft.is_symlink() {
            continue;
        }
        out.push(format!("signatures/{name}"));
    }
}

fn envelope_name_ok(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".dsse.json") else {
        return false;
    };
    !stem.is_empty()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
