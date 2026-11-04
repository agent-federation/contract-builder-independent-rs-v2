//! Resource limits (RFC §4.3.4, §6.3.2, §10.5). Defaults are normative; the
//! operator's trust policy may lower them (never raise). Lowered limits are
//! reported in the report's `effectiveLimits`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitSet {
    /// Manifest bytes (1 MiB).
    pub manifest_bytes: usize,
    /// Payload files, 4096 (total declared artifact+source+input count).
    pub payload_files: usize,
    /// Bytes per payload file (256 MiB).
    pub file_bytes: usize,
    /// Total declared payload bytes (1 GiB).
    pub total_payload_bytes: usize,
    /// Path segments (16).
    pub path_segments: usize,
    /// Path bytes (255).
    pub path_bytes: usize,
    /// Segment bytes (255).
    pub segment_bytes: usize,
    /// JSON nesting depth (64).
    pub json_nesting: usize,
    /// JSON string bytes (16 MiB).
    pub json_string_bytes: usize,
    /// Claim files (16).
    pub claims_files: usize,
    /// Provenance bindings (100 000) — enforced when claims are parsed.
    pub provenance_bindings: usize,
    /// Relation entities (100 000).
    pub relation_entities: usize,
    /// Relation edges (1 000 000).
    pub relation_edges: usize,
    /// Signature envelopes (32).
    pub signature_envelopes: usize,
}

pub const DEFAULT: LimitSet = LimitSet {
    manifest_bytes: 1_048_576,
    payload_files: 4_096,
    file_bytes: 268_435_456,
    total_payload_bytes: 1_073_741_824,
    path_segments: 16,
    path_bytes: 255,
    segment_bytes: 255,
    json_nesting: 64,
    json_string_bytes: 16_777_216,
    claims_files: 16,
    provenance_bindings: 100_000,
    relation_entities: 100_000,
    relation_edges: 1_000_000,
    signature_envelopes: 32,
};

/// Names of limits in the canonical (Appendix C `effectiveLimits`) order.
pub const LIMIT_NAMES: [&str; 14] = [
    "manifestBytes",
    "payloadFiles",
    "fileBytes",
    "totalPayloadBytes",
    "pathSegments",
    "pathBytes",
    "segmentBytes",
    "jsonNesting",
    "jsonStringBytes",
    "claimsFiles",
    "provenanceBindings",
    "relationEntities",
    "relationEdges",
    "signatureEnvelopes",
];

impl LimitSet {
    pub fn defaults() -> LimitSet {
        DEFAULT
    }

    /// A name recognized by the policy `limits` object (§4.3.4).
    pub fn index_of(name: &str) -> Option<usize> {
        LIMIT_NAMES.iter().position(|n| *n == name)
    }

    /// Name for an index in canonical order.
    pub fn name_of(index: usize) -> &'static str {
        LIMIT_NAMES[index]
    }

    /// Effective value for limit `index`.
    pub fn value(&self, index: usize) -> usize {
        match index {
            0 => self.manifest_bytes,
            1 => self.payload_files,
            2 => self.file_bytes,
            3 => self.total_payload_bytes,
            4 => self.path_segments,
            5 => self.path_bytes,
            6 => self.segment_bytes,
            7 => self.json_nesting,
            8 => self.json_string_bytes,
            9 => self.claims_files,
            10 => self.provenance_bindings,
            11 => self.relation_entities,
            12 => self.relation_edges,
            13 => self.signature_envelopes,
            _ => 0,
        }
    }

    /// Apply a lowered value for limit `index` (policy side). Raising is
    /// rejected by the caller (§6.3.2).
    pub fn set(&mut self, index: usize, value: usize) {
        match index {
            0 => self.manifest_bytes = value,
            1 => self.payload_files = value,
            2 => self.file_bytes = value,
            3 => self.total_payload_bytes = value,
            4 => self.path_segments = value,
            5 => self.path_bytes = value,
            6 => self.segment_bytes = value,
            7 => self.json_nesting = value,
            8 => self.json_string_bytes = value,
            9 => self.claims_files = value,
            10 => self.provenance_bindings = value,
            11 => self.relation_entities = value,
            12 => self.relation_edges = value,
            13 => self.signature_envelopes = value,
            _ => {}
        }
    }

    /// Names/values for every limit the operator lowered below the default.
    /// Output ordered by the canonical name order of Appendix C.
    pub fn lowered(&self) -> Vec<(&'static str, usize)> {
        let mut lowered = Vec::new();
        for (i, name) in LIMIT_NAMES.iter().enumerate() {
            let v = self.value(i);
            if v != DEFAULT.value(i) {
                lowered.push((*name, v));
            }
        }
        lowered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_rfc_4_3_4() {
        assert_eq!(DEFAULT.manifest_bytes, 1_048_576);
        assert_eq!(DEFAULT.payload_files, 4_096);
        assert_eq!(DEFAULT.file_bytes, 268_435_456);
        assert_eq!(DEFAULT.total_payload_bytes, 1_073_741_824);
        assert_eq!(DEFAULT.path_segments, 16);
        assert_eq!(DEFAULT.path_bytes, 255);
        assert_eq!(DEFAULT.segment_bytes, 255);
        assert_eq!(DEFAULT.json_nesting, 64);
        assert_eq!(DEFAULT.json_string_bytes, 16_777_216);
        assert_eq!(DEFAULT.claims_files, 16);
        assert_eq!(DEFAULT.provenance_bindings, 100_000);
        assert_eq!(DEFAULT.relation_entities, 100_000);
        assert_eq!(DEFAULT.relation_edges, 1_000_000);
        assert_eq!(DEFAULT.signature_envelopes, 32);
    }

    #[test]
    fn lowered_reports_only_changed() {
        let mut ls = LimitSet::defaults();
        ls.set(LimitSet::index_of("fileBytes").unwrap(), 64);
        let lowered = ls.lowered();
        assert_eq!(lowered, vec![("fileBytes", 64)]);
    }
}
