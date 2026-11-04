//! Strict I-JSON value model and parser (RFC §4.10, §5.3.1, F21-F29/F50/F51).
//!
//! Accepted subset:
//! - UTF-8 without a byte-order mark; trailing data is invalid.
//! - Object member names must be unique (duplicate keys are a distinct error
//!   kind, never last-wins).
//! - Numbers are integer tokens only: `-?(0|[1-9][0-9]*)`, value within
//!   `[-(2^53-1), 2^53-1]`; `-0`, `1.0`, `1e3` and out-of-range values are
//!   invalid even when mathematically integral.
//! - Strings are Unicode scalar sequences; lone surrogates are invalid; no
//!   Unicode normalization is applied.
//! - Nesting depth and per-string decoded byte length are bounded by the
//!   active limit set (parser-level counters).

use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn as_obj(&self) -> Option<&Vec<(String, Json)>> {
        match self {
            Json::Obj(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Json::Int(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    /// True when the member is present.
    pub fn has(&self, key: &str) -> bool {
        matches!(self, Json::Obj(m) if m.iter().any(|(k, _)| k == key))
    }
    /// Property names of an object (insertion order).
    pub fn keys(&self) -> Vec<&str> {
        match self {
            Json::Obj(m) => m.iter().map(|(k, _)| k.as_str()).collect(),
            _ => Vec::new(),
        }
    }
}

/// Parser failure classification. Each variant maps to exactly one normative
/// diagnostic class (RFC §13.8 malformed-input mapping).
#[derive(Debug, Clone, PartialEq)]
pub enum ParseErrorKind {
    /// Input starts with a byte-order mark.
    Bom,
    /// Input is not valid UTF-8.
    NotUtf8,
    /// Data after the top-level value (still non-whitespace).
    TrailingData,
    /// Syntactic/lexical error (bad token, control char, lone surrogate,
    /// non-integer number token, I-JSON range violation, empty input).
    InvalidJson,
    /// An object repeats a member name.
    DuplicateKey,
    /// Nesting depth exceeds the configured limit.
    DepthLimit,
    /// A decoded string exceeds the configured byte limit.
    StringLimit,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    /// Byte offset of the failure (informative).
    pub offset: usize,
    /// Short descriptive text (message layer only).
    pub detail: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at byte {}: {}", self.kind, self.offset, self.detail)
    }
}

pub struct ParserLimits {
    /// Maximum object/array nesting depth (root counts as 1).
    pub depth: usize,
    /// Maximum decoded UTF-8 byte length of one string value.
    pub string_bytes: usize,
}

impl ParserLimits {
    pub const fn defaults() -> Self {
        ParserLimits {
            depth: 64,
            string_bytes: 16 * 1024 * 1024,
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    limits: ParserLimits,
}

/// Parse one complete JSON document from `bytes` under `limits`.
pub fn parse_document(bytes: &[u8], limits: &ParserLimits) -> Result<Json, ParseError> {
    // UTF-8 validation and BOM rejection happen before tokenization.
    let text = std::str::from_utf8(bytes).map_err(|e| ParseError {
        kind: ParseErrorKind::NotUtf8,
        offset: e.valid_up_to(),
        detail: "input is not valid UTF-8".to_string(),
    })?;
    if text.starts_with('\u{FEFF}') {
        return Err(ParseError {
            kind: ParseErrorKind::Bom,
            offset: 0,
            detail: "byte-order mark is not allowed".to_string(),
        });
    }
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
        limits: ParserLimits {
            depth: limits.depth,
            string_bytes: limits.string_bytes,
        },
    };
    p.skip_ws();
    let value = p.value(1)?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(ParseError {
            kind: ParseErrorKind::TrailingData,
            offset: p.i,
            detail: "data after the top-level JSON value".to_string(),
        });
    }

    // Duplicate-key detection over the whole tree (post-order). Parsing never
    // applies last-wins semantics: duplicates are a document error.
    fn check_dups(v: &Json, at: usize) -> Result<(), ParseError> {
        match v {
            Json::Obj(members) => {
                let mut seen: HashMap<&str, ()> = HashMap::with_capacity(members.len());
                for (k, val) in members {
                    if seen.insert(k.as_str(), ()).is_some() {
                        return Err(ParseError {
                            kind: ParseErrorKind::DuplicateKey,
                            offset: at,
                            detail: format!("duplicate object member name: {k}"),
                        });
                    }
                    check_dups(val, at)?;
                }
                Ok(())
            }
            Json::Arr(items) => {
                for it in items {
                    check_dups(it, at)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    check_dups(&value, 0)?;
    Ok(value)
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.b.get(self.i) {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("unexpected token")),
            None => Err(self.err("unexpected end of input")),
        }
    }

    fn err(&self, detail: &str) -> ParseError {
        ParseError {
            kind: ParseErrorKind::InvalidJson,
            offset: self.i,
            detail: detail.to_string(),
        }
    }

    fn literal(&mut self, word: &[u8], value: Json) -> Result<Json, ParseError> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(value)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, ParseError> {
        // Container depth: this opening brace counts as nesting level
        // `depth` (the root value is level 1).
        if depth > self.limits.depth {
            return Err(ParseError {
                kind: ParseErrorKind::DepthLimit,
                offset: self.i,
                detail: format!("JSON nesting depth exceeds {}", self.limits.depth),
            });
        }
        self.i += 1; // '{'
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(Vec::new()));
        }
        let mut members: Vec<(String, Json)> = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected object member name"));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':' after member name"));
            }
            self.i += 1;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(members));
                }
                _ => return Err(self.err("expected ',' or '}' in object")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > self.limits.depth {
            return Err(ParseError {
                kind: ParseErrorKind::DepthLimit,
                offset: self.i,
                detail: format!("JSON nesting depth exceeds {}", self.limits.depth),
            });
        }
        self.i += 1; // '['
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(Vec::new()));
        }
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            let value = self.value(depth + 1)?;
            items.push(value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(self.err("expected ',' or ']' in array")),
            }
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        let start = self.i;
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let b = match self.peek() {
                Some(b) => b,
                None => return Err(self.err("unterminated string")),
            };
            match b {
                b'"' => {
                    self.i += 1;
                    if out.len() > self.limits.string_bytes {
                        return Err(ParseError {
                            kind: ParseErrorKind::StringLimit,
                            offset: start,
                            detail: format!(
                                "decoded string exceeds {} bytes",
                                self.limits.string_bytes
                            ),
                        });
                    }
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let esc = match self.peek() {
                        Some(e) => e,
                        None => return Err(self.err("unterminated escape")),
                    };
                    self.i += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let hi32 = hi as u32;
                            let scalar: u32 = if (0xD800u32..0xDC00).contains(&hi32) {
                                // high surrogate must be followed by a low one
                                if self.peek() == Some(b'\\')
                                    && self.b.get(self.i + 1) == Some(&b'u')
                                {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return Err(self.err("invalid low surrogate"));
                                    }
                                    let combined = 0x10000u32
                                        + (((hi as u32) - 0xD800) << 10)
                                        + ((lo as u32) - 0xDC00);
                                    combined
                                } else {
                                    return Err(self.err("lone high surrogate"));
                                }
                            } else if (0xDC00u32..0xE000).contains(&hi32) {
                                return Err(self.err("lone low surrogate"));
                            } else {
                                hi32
                            };
                            match char::from_u32(scalar) {
                                Some(c) => out.push(c),
                                None => return Err(self.err("invalid Unicode scalar value")),
                            }
                        }
                        _ => {
                            return Err(self.err("invalid escape character"));
                        }
                    }
                }
                0x00..=0x1F => {
                    return Err(self.err("unescaped control character in string"));
                }
                _ => {
                    // Copy one UTF-8 sequence directly from the input.
                    let len = utf8_len(b);
                    if len == 0 || self.i + len > self.b.len() {
                        return Err(self.err("invalid UTF-8 sequence"));
                    }
                    // Input was pre-validated as UTF-8; slices are valid here.
                    let s = std::str::from_utf8(&self.b[self.i..self.i + len])
                        .map_err(|_| self.err("invalid UTF-8 sequence"))?;
                    out.push_str(s);
                    self.i += len;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, ParseError> {
        if self.i + 4 > self.b.len() {
            return Err(self.err("truncated \\u escape"));
        }
        let mut v: u16 = 0;
        for k in 0..4 {
            let c = self.b[self.i + k];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => {
                    self.i += k;
                    return Err(self.err("invalid hex digit in \\u escape"));
                }
            };
            v = (v << 4) | d as u16;
        }
        self.i += 4;
        Ok(v)
    }

    /// Integer-only number tokens (RFC §5.3.1):
    /// `-?(0|[1-9][0-9]*)` with value in `[-(2^53-1), 2^53-1]`.
    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
            // `-0` is invalid in this profile (even though mathematically integral).
            if self.peek() == Some(b'0') && !matches!(self.b.get(self.i + 1), Some(b'0'..=b'9')) {
                return Err(self.err("number -0 is not allowed"));
            }
        }
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                    return Err(self.err("leading zero in number"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("invalid number")),
        }
        // Fraction or exponent spelling is invalid even when integral.
        if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E') | Some(b'+')) {
            return Err(self.err("number tokens must be integer literals"));
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).expect("digits are ASCII");
        let digits = text.trim_start_matches('-');
        // Range: |value| <= 2^53 - 1 (2_147_483_647 * ...); parse with i64 but
        // reject beyond the I-JSON integer bound before overflow matters.
        const MAX: i64 = 9_007_199_254_740_991;
        let mut value: i64 = 0;
        for c in digits.bytes() {
            let d = (c - b'0') as i64;
            if value > (i64::MAX - d) / 10 {
                return Err(self.err("integer out of I-JSON range"));
            }
            value = value * 10 + d;
            if value > MAX {
                return Err(self.err("integer exceeds 2^53-1"));
            }
        }
        if text.starts_with('-') {
            value = -value;
            // (-0) already rejected above via the "-0 then non-digit" rule;
            // "-0" followed by digits would be a leading-zero error anyway.
        }
        Ok(Json::Int(value))
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Json, ParseError> {
        parse_document(s.as_bytes(), &ParserLimits::defaults())
    }

    #[test]
    fn integers_only() {
        assert_eq!(parse("0").unwrap(), Json::Int(0));
        assert_eq!(parse("-1").unwrap(), Json::Int(-1));
        assert_eq!(parse("9007199254740991").unwrap(), Json::Int(9007199254740991));
        assert_eq!(
            parse("-9007199254740991").unwrap(),
            Json::Int(-9007199254740991)
        );
        assert!(parse("9007199254740992").is_err());
        assert!(parse("-9007199254740992").is_err());
        assert!(parse("1.0").is_err());
        assert!(parse("1e3").is_err());
        assert!(parse("1E3").is_err());
        assert!(parse("-0").is_err());
        assert!(parse("01").is_err());
        assert!(parse("+1").is_err());
        assert!(parse(".5").is_err());
        assert!(parse("1.").is_err());
        assert!(parse("00").is_err());
    }

    #[test]
    fn duplicates_rejected() {
        assert_eq!(
            parse(r#"{"a":1,"a":2}"#).err().unwrap().kind,
            ParseErrorKind::DuplicateKey
        );
        assert_eq!(
            parse(r#"{"a":{"b":1,"b":2}}"#).err().unwrap().kind,
            ParseErrorKind::DuplicateKey
        );
        // Nested duplicate inside arrays too.
        assert_eq!(
            parse(r#"[{"k":1},{"k":2,"k":3}]"#).err().unwrap().kind,
            ParseErrorKind::DuplicateKey
        );
    }

    #[test]
    fn bom_and_trailing_and_utf8() {
        let bom = "\u{FEFF}{}".as_bytes();
        assert_eq!(parse_document(bom, &ParserLimits::defaults()).err().unwrap().kind, ParseErrorKind::Bom);
        assert_eq!(
            parse("{}x").err().unwrap().kind,
            ParseErrorKind::TrailingData
        );
        // 0xC3 alone is invalid UTF-8
        assert_eq!(
            parse_document(&[0x22, 0xC3, 0x22], &ParserLimits::defaults())
                .err()
                .unwrap()
                .kind,
            ParseErrorKind::NotUtf8
        );
        assert!(parse("").is_err());
    }

    #[test]
    fn lone_surrogates_and_escapes() {
        assert!(parse(r#""\ud800""#).is_err());
        assert!(parse(r#""\udc00""#).is_err());
        assert!(parse(r#""\ud800\ud800""#).is_err());
        // valid surrogate pair for U+1F600
        assert_eq!(parse(r#""\ud83d\ude00""#).unwrap(), Json::Str("😀".to_string()));
        // Valid surrogate pair decodes to U+1F600
        assert_eq!(parse(r#""😀""#).unwrap(), Json::Str("😀".to_string()));
        assert_eq!(parse(r#""😀""#).unwrap(), Json::Str("😀".to_string()));
        assert_eq!(
            parse(r#""😀""#).unwrap(),
            Json::Str("\u{1F600}".to_string())
        );
        // control characters are invalid unescaped
        assert!(parse("\"a\u{1}b\"").is_err());
        // escaped control characters are fine
        assert_eq!(parse(r#""a\u0001b""#).unwrap(), Json::Str("a\u{1}b".to_string()));
    }

    #[test]
    fn depth_and_string_limits() {
        let deep = "[".repeat(65) + &"]".repeat(65);
        let e = parse_document(deep.as_bytes(), &ParserLimits::defaults()).unwrap_err();
        assert_eq!(e.kind, ParseErrorKind::DepthLimit);
        let big = format!("\"{}\"", "a".repeat(17 * 1024 * 1024));
        let e = parse_document(big.as_bytes(), &ParserLimits::defaults()).unwrap_err();
        assert_eq!(e.kind, ParseErrorKind::StringLimit);
    }
}
