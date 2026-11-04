use crate::json::JsonValue;

fn utf16_code_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

pub fn canonicalize(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::String(s) => encode_string(s),
        JsonValue::Array(arr) => {
            let mut out = String::from("[");
            for (i, v) in arr.iter().enumerate() {
                if i > 0 { out.push(','); }
                out.push_str(&canonicalize(v));
            }
            out.push(']');
            out
        }
        JsonValue::Object(members) => {
            // sort by UTF-16 code units
            let mut sorted: Vec<&(String, JsonValue)> = members.iter().collect();
            sorted.sort_by(|a, b| utf16_code_units(&a.0).cmp(&utf16_code_units(&b.0)));
            let mut out = String::from("{");
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 { out.push(','); }
                out.push_str(&encode_string(k));
                out.push(':');
                out.push_str(&canonicalize(v));
            }
            out.push('}');
            out
        }
    }
}

fn encode_string(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn canonical_bytes(value: &JsonValue) -> Vec<u8> {
    canonicalize(value).into_bytes()
}
