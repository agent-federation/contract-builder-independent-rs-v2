//! Diagnostics and limitations (RFC §7.7, Appendix J).
//!
//! Codes are stable `pap.*` identifiers from Appendix J; messages never are.
//! Severity: `error` (a required property was disproved or a required
//! input/tool is unusable), `warning` (a required evaluation is incomplete or
//! evidence is not established), `info` (observational).

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    /// Severity rank for deterministic ordering in `diagnostics[]`:
    /// error < warning < info (RFC §9.9).
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Error => 0,
            Severity::Warning => 1,
            Severity::Info => 2,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: Severity,
    /// Scope string (e.g. package-relative path, artifact id, check id).
    pub scope: String,
    pub message: String,
}

impl Diagnostic {
    pub fn new(code: &'static str, severity: Severity, scope: &str, message: String) -> Self {
        Diagnostic {
            code,
            severity,
            scope: scope.to_string(),
            message,
        }
    }

    /// Deterministic ordering key: severity rank, then code, then scope.
    fn key(&self) -> (u8, &'static str, &String) {
        (self.severity.rank(), self.code, &self.scope)
    }
}

pub fn sort_diagnostics(list: &mut Vec<Diagnostic>) {
    list.sort_by(|a, b| a.key().cmp(&b.key()).then_with(|| a.message.cmp(&b.message)));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limitation {
    pub code: &'static str,
    pub detail: String,
}

/// Deterministic ordering: by code then detail (RFC §9.9).
pub fn sort_limitations(list: &mut Vec<Limitation>) {
    list.sort_by(|a, b| a.code.cmp(&b.code).then_with(|| a.detail.cmp(&b.detail)));
}

/// Dedup limitations keeping the first detail for a (code, detail) pair,
/// then sort deterministically.
pub fn dedup_limitations(mut list: Vec<Limitation>) -> Vec<Limitation> {
    sort_limitations(&mut list);
    list.dedup_by_key(|l| (l.code.to_string(), l.detail.clone()));
    list
}
