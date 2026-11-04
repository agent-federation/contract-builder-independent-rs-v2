use crate::digest;
use std::fs;
use std::path::Path;

pub fn compute() -> (String, String, Vec<(String, Vec<u8>)>, Vec<(String, String, String)>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    // collect files
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    collect_files(root, root, &mut files);
    files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    // dependencies from Cargo.lock
    let mut deps: Vec<(String, String, String)> = Vec::new();
    let lock_path = root.join("Cargo.lock");
    if let Ok(content) = fs::read_to_string(&lock_path) {
        parse_cargo_lock(&content, &mut deps);
    }
    deps.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()).then(a.1.as_bytes().cmp(b.1.as_bytes())));
    // dedup exact
    deps.dedup();

    let impl_digest = digest::extension_closure_digest(
        "checker",
        "pap.verifier.rust",
        "0.1.0",
        &files,
        &deps,
    ).expect("checker closure");
    let checker_id = digest::checker_identity("pap.verifier.rust", "0.1.0", &impl_digest);
    (impl_digest, checker_id, files, deps)
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_symlink() { continue; }
        if ft.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "target" || name == ".git" || name == "tests" || name == "examples" || name == "docs" || name == "pap" || name == "snapshot" {
                continue;
            }
            collect_files(root, &path, out);
        } else if ft.is_file() {
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            let include = rel == "Cargo.toml" || rel == "Cargo.lock" || rel == "build.rs" || rel.starts_with("src/");
            if !include { continue; }
            if rel.starts_with("src/") && rel.contains("/tests") { continue; }
            if let Ok(bytes) = fs::read(&path) {
                // ensure UTF-8
                if std::str::from_utf8(&bytes).is_err() {
                    panic!("binary file in closure: {}", rel);
                }
                out.push((rel, bytes));
            }
        }
    }
}

fn parse_cargo_lock(content: &str, deps: &mut Vec<(String, String, String)>) {
    // Parse [[package]] blocks
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_checksum: Option<String> = None;
    let mut in_package = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if in_package {
                if let (Some(n), Some(v), Some(c)) = (current_name.take(), current_version.take(), current_checksum.take()) {
                    // skip workspace root package? It may have no checksum; checksum present ensures third-party
                    deps.push((n, v, c));
                } else {
                    current_name = None; current_version = None; current_checksum = None;
                }
            }
            in_package = true;
            current_name = None;
            current_version = None;
            current_checksum = None;
            continue;
        }
        if in_package {
            if trimmed.starts_with("name = ") {
                current_name = Some(trimmed.trim_start_matches("name = ").trim_matches('"').to_string());
            } else if trimmed.starts_with("version = ") {
                current_version = Some(trimmed.trim_start_matches("version = ").trim_matches('"').to_string());
            } else if trimmed.starts_with("checksum = ") {
                current_checksum = Some(trimmed.trim_start_matches("checksum = ").trim_matches('"').to_string());
            } else if trimmed.starts_with('[') {
                // section end
                if let (Some(n), Some(v), Some(c)) = (current_name.take(), current_version.take(), current_checksum.take()) {
                    deps.push((n, v, c));
                }
                in_package = false;
            }
        }
    }
    if in_package {
        if let (Some(n), Some(v), Some(c)) = (current_name.take(), current_version.take(), current_checksum.take()) {
            deps.push((n, v, c));
        }
    }
}
