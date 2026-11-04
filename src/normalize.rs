//! Declared normalization rules (RFC §4.5.1, §5.6).
//!
//! Input normalization (`normalization: "lf"`):
//! 1. if the bytes contain a NUL octet: binary fallback (raw bytes);
//! 2. else decode as UTF-8 with fatal errors; on failure: binary fallback;
//! 3. else replace every CRLF and lone CR with LF and re-encode as UTF-8.
//!
//! `normalization: "none"` uses the raw bytes in place of step 3's output.

/// LF-normalize `raw` per §5.6. Returns `None` only when the binary fallback
/// applies (NUL present or invalid UTF-8); callers then hash raw bytes.
pub fn normalize_input(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.contains(&0x00) {
        return None;
    }
    match std::str::from_utf8(raw) {
        Err(_) => None,
        Ok(_text) => Some(lf_normalize_bytes(raw)),
    }
}

/// Replace every CRLF and lone CR with LF (§5.2 framing applies to the
/// re-encoded UTF-8 bytes).
pub fn lf_normalize_bytes(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            0x0D => {
                if raw.get(i + 1) == Some(&0x0A) {
                    i += 2;
                } else {
                    i += 1;
                }
                out.push(0x0A);
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Text used inside extension/checker closure file records (§5.2): UTF-8,
/// CRLF/CR → LF. A binary file in the closure is an error for the closure
/// author; helper returns the normalized text when valid.
pub fn normalize_closure_text(raw: &[u8]) -> Option<String> {
    let norm = lf_normalize_bytes(raw);
    String::from_utf8(norm).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_and_cr_to_lf() {
        assert_eq!(lf_normalize_bytes(b"a\r\nb\rc\nd"), b"a\nb\nc\nd".to_vec());
        // CR at end
        assert_eq!(lf_normalize_bytes(b"x\r"), b"x\n".to_vec());
        // lone LF unchanged
        assert_eq!(lf_normalize_bytes(b"x\ny"), b"x\ny".to_vec());
    }

    #[test]
    fn binary_fallback_conditions() {
        // NUL anywhere ⇒ binary fallback (raw)
        assert_eq!(normalize_input(b"a\x00b"), None);
        // invalid UTF-8 ⇒ binary fallback
        assert_eq!(normalize_input(&[0x22, 0xC3, 0x28, 0x22]), None);
        assert_eq!(normalize_input(b"plain"), Some(b"plain".to_vec()));
    }
}
