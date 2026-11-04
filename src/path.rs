pub fn validate_path_grammar(path: &str) -> bool {
    if path.is_empty() { return false; }
    if path.starts_with('/') || path.ends_with('/') { return false; }
    if path.contains("//") { return false; }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() > 16 { return false; }
    for seg in &segments {
        if seg.is_empty() { return false; }
        if *seg == "." || *seg == ".." { return false; }
        if seg.len() > 255 { return false; }
        for b in seg.bytes() {
            if !(b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
                return false;
            }
        }
    }
    if path.len() > 255 { return false; } // max 255 bytes per path? Actually path max 255 bytes total? RFC says maximum 255 bytes per path and per segment. We'll enforce path <=255.
    true
}

pub fn ascii_casefold(s: &str) -> String {
    s.bytes().map(|b| b.to_ascii_lowercase()).map(char::from).collect()
}
