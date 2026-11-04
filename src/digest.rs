use crate::jcs::canonicalize;
use crate::json::JsonValue;
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("sha256:{}", hex::encode(h.finalize()))
}

// hex encode helper (avoid extra dep)
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        const LUT: &[u8; 16] = b"0123456789abcdef";
        let b = bytes.as_ref();
        let mut s = String::with_capacity(b.len() * 2);
        for &byte in b {
            s.push(LUT[(byte >> 4) as usize] as char);
            s.push(LUT[(byte & 0x0f) as usize] as char);
        }
        s
    }
}

pub fn domain_hash(domain: &str, octets: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(octets);
    format!("sha256:{}", hex::encode(h.finalize()))
}

pub fn frame_record(tag: &str, parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    // tag length
    out.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&(parts.len() as u32).to_be_bytes());
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

pub fn normalize_input(bytes: &[u8], normalization: &str) -> Vec<u8> {
    if normalization == "none" {
        return bytes.to_vec();
    }
    // lf
    if bytes.contains(&0u8) {
        return bytes.to_vec();
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => {
            let mut out = String::new();
            let mut chars = s.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\r' {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    out.push('\n');
                } else {
                    out.push(c);
                }
            }
            out.into_bytes()
        }
        Err(_) => bytes.to_vec(),
    }
}

pub fn input_file_digest(path: &str, normalized: &[u8]) -> String {
    let record = frame_record("input", &[path.as_bytes().to_vec(), normalized.to_vec()]);
    domain_hash("pap.input.file.v1", &record)
}

pub fn normalized_input_set_digest(inputs: &[(String, Vec<u8>)]) -> String {
    // sort by path
    let mut sorted: Vec<&(String, Vec<u8>)> = inputs.iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut payload = Vec::new();
    for (path, nb) in sorted {
        let rec = frame_record("input", &[path.as_bytes().to_vec(), nb.clone()]);
        payload.extend_from_slice(&rec);
    }
    domain_hash("pap.input.set.v1", &payload)
}

pub fn normalize_text_lf(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let s = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    Ok(out.into_bytes())
}

pub fn extension_closure_digest(
    kind: &str,
    id: &str,
    version: &str,
    files: &[(String, Vec<u8>)], // path, raw bytes (will normalize)
    deps: &[(String, String, String)], // name, version, integrity
) -> Result<String, String> {
    // normalize files
    let mut norm_files: Vec<(String, Vec<u8>)> = Vec::new();
    for (p, b) in files {
        let nb = normalize_text_lf(b).map_err(|_| format!("binary file in closure: {}", p))?;
        norm_files.push((p.clone(), nb));
    }
    norm_files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut sorted_deps: Vec<&(String, String, String)> = deps.iter().collect();
    sorted_deps.sort_by(|a, b| {
        a.0.as_bytes().cmp(b.0.as_bytes()).then(a.1.as_bytes().cmp(b.1.as_bytes()))
    });

    let mut payload = Vec::new();
    // extension record
    let ext_rec = frame_record("extension", &[kind.as_bytes().to_vec(), id.as_bytes().to_vec(), version.as_bytes().to_vec()]);
    payload.extend_from_slice(&ext_rec);
    for (p, nb) in &norm_files {
        let file_rec = frame_record("file", &[p.as_bytes().to_vec(), nb.clone()]);
        payload.extend_from_slice(&file_rec);
    }
    for (name, ver, integ) in sorted_deps {
        let dep_rec = frame_record("dependency", &[name.as_bytes().to_vec(), ver.as_bytes().to_vec(), integ.as_bytes().to_vec()]);
        payload.extend_from_slice(&dep_rec);
    }
    Ok(domain_hash("pap.extension.closure.v1", &payload))
}

pub fn checker_identity(
    id: &str,
    version: &str,
    implementation_digest: &str,
) -> String {
    // JCS({"id":..., "version":..., "implementationDigest":...})
    let jv = JsonValue::Object(vec![
        ("id".to_string(), JsonValue::String(id.to_string())),
        ("version".to_string(), JsonValue::String(version.to_string())),
        ("implementationDigest".to_string(), JsonValue::String(implementation_digest.to_string())),
    ]);
    let bytes = canonicalize(&jv).into_bytes();
    domain_hash("pap.checker.identity.v1", &bytes)
}

