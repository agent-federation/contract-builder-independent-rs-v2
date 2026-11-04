use std::fmt;

pub const DEFAULT_JSON_NESTING: usize = 64;
pub const DEFAULT_JSON_STRING_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    InvalidUtf8,
    Bom,
    TrailingData,
    UnexpectedEof,
    UnexpectedChar(char),
    DuplicateKey(String),
    InvalidNumber,
    NumberOutOfRange,
    InvalidEscape,
    LoneSurrogate,
    NestingLimit,
    StringLimit,
    TrailingComma,
    Empty,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
    max_depth: usize,
    max_string_bytes: usize,
}

impl<'a> Parser<'a> {
    pub fn new(bytes: &'a [u8], max_depth: usize, max_string_bytes: usize) -> Self {
        Self { bytes, pos: 0, depth: 0, max_depth, max_string_bytes }
    }

    pub fn parse(mut self) -> Result<JsonValue, JsonError> {
        // BOM check
        if self.bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Err(JsonError::Bom);
        }
        // UTF-8 validation
        if std::str::from_utf8(self.bytes).is_err() {
            return Err(JsonError::InvalidUtf8);
        }
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            return Err(JsonError::Empty);
        }
        let v = self.parse_value()?;
        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err(JsonError::TrailingData);
        }
        Ok(v)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            return Err(JsonError::UnexpectedEof);
        }
        match self.bytes[self.pos] {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => self.parse_string().map(JsonValue::String),
            b't' => self.parse_literal(b"true", JsonValue::Bool(true)),
            b'f' => self.parse_literal(b"false", JsonValue::Bool(false)),
            b'n' => self.parse_literal(b"null", JsonValue::Null),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(JsonError::UnexpectedChar(self.bytes[self.pos] as char)),
        }
    }

    fn parse_literal(&mut self, lit: &[u8], val: JsonValue) -> Result<JsonValue, JsonError> {
        if self.bytes[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(val)
        } else {
            Err(JsonError::UnexpectedChar(self.bytes[self.pos] as char))
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.pos;
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'-' {
            self.pos += 1;
        }
        if self.pos >= self.bytes.len() || !self.bytes[self.pos].is_ascii_digit() {
            return Err(JsonError::InvalidNumber);
        }
        // reject leading zero with more digits
        if self.bytes[self.pos] == b'0' {
            self.pos += 1;
            if self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                return Err(JsonError::InvalidNumber);
            }
        } else {
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }
        // reject fraction/exponent
        if self.pos < self.bytes.len() && (self.bytes[self.pos] == b'.' || self.bytes[self.pos] == b'e' || self.bytes[self.pos] == b'E') {
            return Err(JsonError::InvalidNumber);
        }
        // -0 check
        let token = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
        if token == "-0" {
            return Err(JsonError::InvalidNumber);
        }
        // range check
        let n: i64 = token.parse().map_err(|_| JsonError::NumberOutOfRange)?;
        // 2^53 range
        const MAX: i64 = 9007199254740991;
        if n < -MAX || n > MAX {
            return Err(JsonError::NumberOutOfRange);
        }
        Ok(JsonValue::Number(n))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        // assume pos at quote
        self.pos += 1; // opening quote
        let mut out = String::new();
        let mut byte_len = 0usize;
        loop {
            if self.pos >= self.bytes.len() {
                return Err(JsonError::UnexpectedEof);
            }
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                break;
            }
            if b < 0x20 {
                return Err(JsonError::InvalidEscape);
            }
            if b == b'\\' {
                self.pos += 1;
                if self.pos >= self.bytes.len() {
                    return Err(JsonError::UnexpectedEof);
                }
                let esc = self.bytes[self.pos];
                self.pos += 1;
                let ch = match esc {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{0008}',
                    b'f' => '\u{000C}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => {
                        // parse 4 hex
                        if self.pos + 4 > self.bytes.len() {
                            return Err(JsonError::InvalidEscape);
                        }
                        let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos+4]).map_err(|_| JsonError::InvalidEscape)?;
                        let cp = u32::from_str_radix(hex, 16).map_err(|_| JsonError::InvalidEscape)?;
                        self.pos += 4;
                        // handle surrogate
                        if (0xD800..=0xDBFF).contains(&cp) {
                            // need low surrogate
                            if self.pos + 6 <= self.bytes.len() && self.bytes[self.pos] == b'\\' && self.bytes[self.pos+1] == b'u' {
                                let hex2 = std::str::from_utf8(&self.bytes[self.pos+2..self.pos+6]).map_err(|_| JsonError::InvalidEscape)?;
                                let cp2 = u32::from_str_radix(hex2, 16).map_err(|_| JsonError::InvalidEscape)?;
                                if (0xDC00..=0xDFFF).contains(&cp2) {
                                    self.pos += 6;
                                    let high = cp - 0xD800;
                                    let low = cp2 - 0xDC00;
                                    let scalar = 0x10000 + (high << 10) + low;
                                    char::from_u32(scalar).unwrap()
                                } else {
                                    return Err(JsonError::LoneSurrogate);
                                }
                            } else {
                                return Err(JsonError::LoneSurrogate);
                            }
                        } else if (0xDC00..=0xDFFF).contains(&cp) {
                            return Err(JsonError::LoneSurrogate);
                        } else {
                            char::from_u32(cp).unwrap_or('\u{FFFD}')
                        }
                    }
                    _ => return Err(JsonError::InvalidEscape),
                };
                out.push(ch);
                byte_len += ch.len_utf8();
            } else {
                // UTF-8 char
                // determine length
                let ch_len = if b < 0x80 { 1 } else if b < 0xE0 { 2 } else if b < 0xF0 { 3 } else { 4 };
                if self.pos + ch_len > self.bytes.len() {
                    return Err(JsonError::InvalidUtf8);
                }
                let ch_str = std::str::from_utf8(&self.bytes[self.pos..self.pos+ch_len]).map_err(|_| JsonError::InvalidUtf8)?;
                let ch = ch_str.chars().next().unwrap();
                out.push(ch);
                self.pos += ch_len;
                byte_len += ch_len;
            }
            if byte_len > self.max_string_bytes {
                return Err(JsonError::StringLimit);
            }
        }
        Ok(out)
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        self.depth += 1;
        if self.depth > self.max_depth {
            return Err(JsonError::NestingLimit);
        }
        self.pos += 1; // [
        self.skip_ws();
        let mut items = Vec::new();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b']' {
            self.pos += 1;
            self.depth -= 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            let v = self.parse_value()?;
            items.push(v);
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return Err(JsonError::UnexpectedEof);
            }
            if self.bytes[self.pos] == b',' {
                self.pos += 1;
                self.skip_ws();
                // reject trailing comma
                if self.pos < self.bytes.len() && self.bytes[self.pos] == b']' {
                    return Err(JsonError::TrailingComma);
                }
            } else if self.bytes[self.pos] == b']' {
                self.pos += 1;
                break;
            } else {
                return Err(JsonError::UnexpectedChar(self.bytes[self.pos] as char));
            }
        }
        self.depth -= 1;
        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        self.depth += 1;
        if self.depth > self.max_depth {
            return Err(JsonError::NestingLimit);
        }
        self.pos += 1; // {
        self.skip_ws();
        let mut members = Vec::new();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'}' {
            self.pos += 1;
            self.depth -= 1;
            return Ok(JsonValue::Object(members));
        }
        loop {
            self.skip_ws();
            if self.pos >= self.bytes.len() || self.bytes[self.pos] != b'"' {
                return Err(JsonError::UnexpectedChar(if self.pos < self.bytes.len() { self.bytes[self.pos] as char } else { '\0' }));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.pos >= self.bytes.len() || self.bytes[self.pos] != b':' {
                return Err(JsonError::UnexpectedChar(if self.pos < self.bytes.len() { self.bytes[self.pos] as char } else { '\0' }));
            }
            self.pos += 1;
            // duplicate key check
            if members.iter().any(|(k, _)| k == &key) {
                return Err(JsonError::DuplicateKey(key));
            }
            let val = self.parse_value()?;
            members.push((key, val));
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return Err(JsonError::UnexpectedEof);
            }
            if self.bytes[self.pos] == b',' {
                self.pos += 1;
                self.skip_ws();
                if self.pos < self.bytes.len() && self.bytes[self.pos] == b'}' {
                    return Err(JsonError::TrailingComma);
                }
            } else if self.bytes[self.pos] == b'}' {
                self.pos += 1;
                break;
            } else {
                return Err(JsonError::UnexpectedChar(self.bytes[self.pos] as char));
            }
        }
        self.depth -= 1;
        Ok(JsonValue::Object(members))
    }
}

pub fn parse_json(bytes: &[u8], max_depth: usize, max_string_bytes: usize) -> Result<JsonValue, JsonError> {
    Parser::new(bytes, max_depth, max_string_bytes).parse()
}
