//! Domain-separated SHA-256 digest primitives and framing (RFC §5.2).
//!
//! H(domain, octets) = SHA-256( ASCII(domain) || 0x00 || octets )
//!
//! Framing (length-prefixed records):
//! ```text
//! record := u32be tagLength, tag (UTF-8), u32be partCount,
//!           partCount × ( u32be partLength, part[partLength] )
//! ```

use crate::sha256::Sha256;
use crate::sha256::hex_lower;

/// Files claimed file: raw bytes are the payload (no framing).
/// Digest strings: `sha256:` + 64 lowercase hex digits.

/// One framed part of a record.
pub enum Frame<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
}

impl<'a> Frame<'a> {
    fn bytes(&self) -> &[u8] {
        match self {
            Frame::Text(t) => t.as_bytes(),
            Frame::Bytes(b) => b,
        }
    }
}

/// Append one length-prefixed record with `tag` and `parts` to `out`.
pub fn push_record(out: &mut Vec<u8>, tag: &str, parts: &[Frame]) {
    out.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&(parts.len() as u32).to_be_bytes());
    for part in parts {
        let b = part.bytes();
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
}

/// Convenience: framed byte stream for one record.
pub fn record(tag: &str, parts: &[Frame]) -> Vec<u8> {
    let mut v = Vec::new();
    push_record(&mut v, tag, parts);
    v
}

/// H(domain, octets) = SHA-256(ASCII(domain) ‖ 0x00 ‖ octets).
pub fn h(domain: &str, payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(&[0x00]);
    h.update(payload);
    h.finish()
}

/// One-shot one-byte-array alias for tests and callers that want a plain array.
pub fn h_bytes(domain: &str, payload: &[u8]) -> Vec<u8> {
    h(domain, payload).to_vec()
}

/// Format a raw digest as the normative `sha256:<64 lowercase hex>` string.
pub fn format_digest(bytes: &[u8; 32]) -> String {
    format!("sha256:{}", hex_lower(bytes))
}

/// Parsed representation of a declared digest string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Parse and validate `sha256:<64 lowercase hex>` (RFC §5.2). Any other
    /// algorithm identifier or formatting is invalid.
    pub fn parse(s: &str) -> Option<Digest> {
        let hexpart = s.strip_prefix("sha256:")?;
        if hexpart.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, pair) in hexpart.as_bytes().chunks(2).enumerate() {
            let hi = hex_val(pair[0])?;
            let lo = hex_val(pair[1])?;
            out[i] = (hi << 4) | lo;
        }
        Some(Digest(out))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Digest {
        Digest(*bytes)
    }

    pub fn as_str(&self) -> String {
        format_digest(&self.0)
    }

    /// Case-sensitive comparison helper (byte-level identity, never string).
    pub fn eq_digest(&self, other: &Digest) -> bool {
        self.0 == other.0 // constant-length array compare
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        // Uppercase hex is NOT permitted: digests are lowercase only.
        _ => None,
    }
}

/// Digest of the canonical manifest value bytes (§5.3).
pub fn package_identity(canonical_manifest: &[u8]) -> [u8; 32] {
    h("pap.package.v1", canonical_manifest)
}

/// Digest of raw artifact bytes (§5.4).
pub fn artifact_digest(raw: &[u8]) -> [u8; 32] {
    h("pap.artifact.v1", raw)
}

/// Digest of raw source bytes (§5.5).
pub fn raw_source_digest(raw: &[u8]) -> [u8; 32] {
    h("pap.source.raw.v1", raw)
}

/// Per-input file digest: H("pap.input.file.v1", record("input",[path,normalized])) (§5.2).
pub fn input_file_digest(path: &str, normalized: &[u8]) -> [u8; 32] {
    let rec = record("input", &[Frame::Text(path), Frame::Bytes(normalized)]);
    h("pap.input.file.v1", &rec)
}

/// Per-claim-file digest: raw file bytes are the payload, no framing (§5.2).
pub fn claim_digest(raw: &[u8]) -> [u8; 32] {
    h("pap.claims.v1", raw)
}

/// Trust policy digest: H("pap.trust-policy.v1", JCS(policy)) (§6.3).
pub fn trust_policy_digest(canonical_policy: &[u8]) -> [u8; 32] {
    h("pap.trust-policy.v1", canonical_policy)
}

/// Checker identity: H("pap.checker.identity.v1", JCS({id,version,implementationDigest})) (§5.8).
pub fn checker_identity(id: &str, version: &str, implementation_digest: &str) -> [u8; 32] {
    let mut canonical = String::new();
    // Members sorted by UTF-16 order: "id" < "implementationDigest" < "version".
    canonical.push_str("{\"id\":");
    canonical.push_str(&crate::json::Json::Str(id.to_string()).static_json_str());
    canonical.push_str(",\"implementationDigest\":");
    canonical.push_str(&crate::json::Json::Str(implementation_digest.to_string()).static_json_str());
    canonical.push_str(",\"version\":");
    canonical.push_str(&crate::json::Json::Str(version.to_string()).static_json_str());
    canonical.push('}');
    h("pap.checker.identity.v1", canonical.as_bytes())
}

impl crate::json::Json {
    /// Minimal JCS string serializer helper for identifier strings in
    /// hand-built canonical literals. Keys here are fixed ASCII literals, so
    /// only the value needs generic escaping.
    pub fn static_json_str(&self) -> String {
        match self {
            crate::json::Json::Str(s) => {
                let mut out = String::with_capacity(s.len() + 2);
                out.push('"');
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        c if (c as u32) < 0x20 => {
                            out.push_str(&format!("\\u{:04x}", c as u32));
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
                out
            }
            _ => String::new(),
        }
    }
}

/// Standard base64 (RFC 4648 §4, with padding) of the extracted span —
/// the optional `quoteBase64` witness convenience field (§8.3).
pub fn base64_standard_pad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).map(|v| *v as u32);
        let b2 = chunk.get(2).map(|v| *v as u32);
        let n = (b0 << 16) | (b1.unwrap_or(0) << 8) | b2.unwrap_or(0);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Verification-report identity: H("pap.report.v1", canonical identity form).
pub fn report_identity(canonical_identity_form: &[u8]) -> [u8; 32] {
    h("pap.report.v1", canonical_identity_form)
}

/// Quote digest: H("pap.quote.v1", exact quote bytes) (§5.2, §8.5).
pub fn quote_digest(raw: &[u8]) -> [u8; 32] {
    h("pap.quote.v1", raw)
}

/// Extension closure digest over framed records (§5.2, §5.7, §5.8).
pub fn extension_closure_digest(records: &[u8]) -> [u8; 32] {
    h("pap.extension.closure.v1", records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::hex_lower;

    #[test]
    fn e6_domain_separation() {
        let expected = [
            ("pap.artifact.v1", "49ade3eaed5c81a07ee5245b923abe3c629747f0eebe57a0052307d5965d5112"),
            ("pap.source.raw.v1", "8240a5313b027e89a99054c87e683a87d68f59dc566a40f16aa68edcbf1a81b7"),
            ("pap.package.v1", "4cb73e2896d009395089ea045b54b15eea2bc4c03e519bc08dc0f619da308308"),
        ];
        for (domain, want) in expected {
            assert_eq!(hex_lower(&h(domain, b"hello")), want, "domain {domain}");
        }
    }

    #[test]
    fn e6_framing_ambiguity() {
        let a = h("pap.test.v1", &record("x", &[Frame::Text("ab"), Frame::Text("c")]));
        assert_eq!(
            hex_lower(&a),
            "a4ff1eac1c490e25d4a23ef485f9219a4a51b2c370ba86ed20ba0d8e5c7334e5"
        );
        let b = h("pap.test.v1", &record("x", &[Frame::Text("a"), Frame::Text("bc")]));
        assert_eq!(
            hex_lower(&b),
            "19777dd70824683c8483961510324f7656c03378f3a4b64192e8bee7ff0ecff2"
        );
        assert_ne!(a, b);
    }

    #[test]
    fn digest_string_parsing() {
        let d = Digest::parse(
            "sha256:5f521a6b5bedacdf8d3536f8fb509bef6e829bfb537b1ec818cb38a8e1a2dd51",
        )
        .unwrap();
        assert_eq!(d.as_str(), "sha256:5f521a6b5bedacdf8d3536f8fb509bef6e829bfb537b1ec818cb38a8e1a2dd51");
        // wrong algorithm identifier
        assert!(Digest::parse("md5:5f521a6b5bedacdf8d3536f8fb509bef6e829bfb537b1ec818cb38a8e1a2dd51").is_none());
        // uppercase hex rejected (normative lowercase)
        assert!(Digest::parse("sha256:5F521A6B5BEDACDF8D3536F8FB509BEF6E829BFB537B1EC818CB38A8E1A2DD51").is_none());
        // wrong length
        assert!(Digest::parse("sha256:5f52").is_none());
        // non-hex
        assert!(Digest::parse("sha256:zz521a6b5bedacdf8d3536f8fb509bef6e829bfb537b1ec818cb38a8e1a2dd5").is_none());
    }

    #[test]
    fn e2_artifact_digest_from_reference_bytes() {
        // 80-byte Appendix F artifact; expected digest from E.2.
        let artifact = b"# ACME supplier assurance\n\nREQ-001: every delivery MUST include a packing list.\n";
        assert_eq!(artifact.len(), 80);
        assert_eq!(
            hex_lower(&artifact_digest(artifact)),
            "5f521a6b5bedacdf8d3536f8fb509bef6e829bfb537b1ec818cb38a8e1a2dd51"
        );
    }

    #[test]
    fn e2_quote_span_digest() {
        let source = b"# ACME delivery policy\n\nREQ-001: every delivery MUST include a packing list.\n\nREQ-002: incomplete deliveries MUST be reported.\n";
        assert_eq!(source.len(), 127);
        let span = &source[24..76];
        assert_eq!(span.len(), 52);
        assert_eq!(
            hex_lower(&quote_digest(span)),
            "619cb81063fff535c31b93b66e274e6df0a1cef4582d17c7a6362c98fac48909"
        );
    }

    #[test]
    fn e2_raw_source_digest() {
        let source = b"# ACME delivery policy\n\nREQ-001: every delivery MUST include a packing list.\n\nREQ-002: incomplete deliveries MUST be reported.\n";
        assert_eq!(
            hex_lower(&raw_source_digest(source)),
            "d7a4ee24615f562232172021f3c992fa1a5aed7a2ae9c128446101ed8f46eecd"
        );
    }

    #[test]
    fn e5_input_normalization_vectors() {
        use crate::normalize;
        let raw = [0x61u8, 0x3a, 0x20, 0x31, 0x0d, 0x0a, 0x62, 0x3a, 0x20, 0x32, 0x0d, 0x0a];
        let norm = normalize::normalize_input(&raw).expect("normalizable");
        assert_eq!(norm, vec![0x61, 0x3a, 0x20, 0x31, 0x0a, 0x62, 0x3a, 0x20, 0x32, 0x0a]);
        assert_eq!(
            hex_lower(&input_file_digest("inputs/crlf.yml", &norm)),
            "2633064c5d3066746beae7416e97e87816fe9b031c6f57af4c9b02ca1c00453b"
        );
        // set digest uses the same framed record under the set domain
        let rec = record("input", &[Frame::Text("inputs/crlf.yml"), Frame::Bytes(&norm)]);
        assert_eq!(
            hex_lower(&h("pap.input.set.v1", &rec)),
            "92e9ec329516a5672fc40fd0b4474f2a2fd7790d87817c37b772af3347df2021"
        );
    }
}
