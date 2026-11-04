//! RFC 8785 JSON Canonicalization Scheme over the PAP I-JSON subset
//! (RFC §5.3.1, Appendix E.9 vectors).
//!
//! Mapping from a [`Json`] value:
//! - object members sorted by UTF-16 code-unit order of their names;
//! - arrays preserve order;
//! - numbers are canonical decimal integers (the PAP integer profile
//!   guarantees the parse step already accepted `-?(0|[1-9][0-9]*)` tokens
//!   inside the I-JSON range, so the decimal rendering is canonical);
//! - strings emit literals for non-ASCII, short escapes for C0 `\b\t\n\f\r`,
//!   lowercase-hex `\u00xx` for the remaining C0 controls, `\"` and `\\`;
//! - no insignificant whitespace anywhere; no trailing newline.

use crate::json::Json;

/// Serialize to canonical JSON text. The canonical bytes are the UTF-8
/// encoding of the returned `String`.
pub fn to_canonical(v: &Json) -> String {
    let mut out = String::new();
    write_value(&mut out, v);
    out
}

fn write_value(out: &mut String, v: &Json) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(n) => out.push_str(&n.to_string()),
        Json::Str(s) => write_string(out, s),
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Json::Obj(members) => {
            out.push('{');
            let mut sorted: Vec<(&str, &Json)> =
                members.iter().map(|(k, v)| (k.as_str(), v)).collect();
            sorted.sort_by(|a, b| utf16_key(a.0).cmp(&utf16_key(b.0)));
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, val);
            }
            out.push('}');
        }
    }
}

/// Sort key: the UTF-16 code units of the string (RFC 8785 §3.2.3). Using
/// UTF-16 units rather than code points puts astral keys (whose UTF-16
/// surrogates start at 0xD800..0xDFFF) *after* BMP keys in E000..FFFF,
/// exactly as RFC 8785 requires and as Appendix E.9 pins.
fn utf16_key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::ParserLimits;
    use crate::json::parse_document;
    use crate::sha256::{hex_lower, sha256};

    fn canon(s: &str) -> String {
        to_canonical(&parse_document(s.as_bytes(), &ParserLimits::defaults()).unwrap())
    }

    #[test]
    fn e9_utf16_key_order() {
        // E.9 UTF-16 key-order vector: {"a":1,"😀":2,U+FFFD:3,"A":4,"b":5}
        let mut members: Vec<(String, Json)> = Vec::new();
        members.push(("a".to_string(), Json::Int(1)));
        members.push(("😀".to_string(), Json::Int(2)));
        members.push(("\u{FFFD}".to_string(), Json::Int(3)));
        members.push(("A".to_string(), Json::Int(4)));
        members.push(("b".to_string(), Json::Int(5)));
        let got = to_canonical(&Json::Obj(members));
// Order: A(0x41) < a(0x61) < b(0x62) < U+1F600(D83D DE00) < U+FFFD(FFFD).
        let want = "{\"A\":4,\"a\":1,\"b\":5,\"😀\":2,\"\u{FFFD}\":3}";
        assert_eq!(got, want);
        assert_eq!(got.len(), 36); // 36 UTF-8 bytes exactly
        // E.9 published plain SHA-256 of these 36 bytes:
        assert_eq!(
            hex_lower(&sha256(got.as_bytes())),
            "9267454f732ed7ef9939b28dc1e451c88c2967ff4a6b1746bf638d313e72b508"
        );
    }

    #[test]
    fn e9_string_escaping() {
        // E.9 escaping vector: U+0001, tab, LF, quote, backslash, é, 😀
        let input = "{\"s\":\"\\u0001\\t\\n\\\"\\\\é😀\"}";
        let got = canon(input);
        assert_eq!(got, input); // already canonical
        assert_eq!(got.len(), 28);
        // E.9 published plain SHA-256 of these 28 bytes:
        let plain = crate::sha256::sha256(got.as_bytes());
        assert_eq!(
            hex_lower(&plain),
            "9033f8f21bc1c3367ebcad55e2298bf113b63f9e5f21c20678de00e760c5ff5d"
        );
    }

    #[test]
    fn e9_number_rules() {
        assert_eq!(canon("9007199254740991"), "9007199254740991");
        assert_eq!(canon("-9007199254740991"), "-9007199254740991");
        // Invalid tokens have no canonical bytes; the parse step rejects them.
        use crate::json::ParseErrorKind;
        for bad in ["9007199254740992", "1.0", "1e3", "-0", "01", "1E3"] {
            let err = parse_document(bad.as_bytes(), &ParserLimits::defaults()).unwrap_err();
            assert_eq!(err.kind, ParseErrorKind::InvalidJson, "case {bad}");
        }
    }

    #[test]
    fn basic_canonicalization() {
        // key order, arrays untouched, no whitespace
        let got = canon(r#"{ "b" : [1, 2] , "a" : {"x": true, "y": null} , "z" : 3 }"#);
        assert_eq!(got, r#"{"a":{"x":true,"y":null},"b":[1,2],"z":3}"#);
        // negative bound
        assert_eq!(canon("-5"), "-5");
        // lower-case hex escapes for control chars other than \b\t\n\f\r
        // Lower-case hex escape for a control character other than \b\t\n\f\r.
        let got = canon("\"\\u0017\"");
        assert_eq!(got, "\"\\u0017\"");
    }
}
