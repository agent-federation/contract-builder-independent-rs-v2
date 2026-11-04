//! Package path grammar and duplicate/case rules (RFC §4.3.1, §4.3.3).
//!
//! Grammar (ASCII only in v0.1):
//! ```text
//! path := segment ("/" segment)*
//! segment := [A-Za-z0-9._-]+
//! ```
//! with segment limits: at most `path_segments` segments, at most `path_bytes`
//! bytes per path, at most `segment_bytes` bytes per segment, no `.`/`..`
//! segments, no leading/trailing slash, no empty segment.

use crate::limits::LimitSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// Empty segment, `.`, `..`, leading or trailing `/`.
    BadSegment,
    /// Character outside `[A-Za-z0-9._-]` (or non-ASCII byte).
    BadCharacter,
    /// Too many segments.
    TooManySegments,
    /// Path longer than the path-byte limit.
    TooLongPath,
    /// Segment longer than the segment-byte limit.
    TooLongSegment,
}

/// Validate one package-relative declared path against the grammar.
pub fn validate(path: &str, limits: &LimitSet) -> Result<(), PathError> {
    if path.is_empty() {
        return Err(PathError::BadSegment);
    }
    if path.as_bytes().len() > limits.path_bytes {
        return Err(PathError::TooLongPath);
    }
    let segments: Vec<&str> = path.split('/').collect();
    for seg in &segments {
        if seg.is_empty() {
            return Err(PathError::BadSegment);
        }
        if *seg == "." || *seg == ".." {
            return Err(PathError::BadSegment);
        }
        let seg_bytes = seg.as_bytes();
        if seg_bytes.len() > limits.segment_bytes {
            return Err(PathError::TooLongSegment);
        }
        for &b in seg_bytes {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {}
                _ => return Err(PathError::BadCharacter),
            }
        }
    }
    if segments.len() > limits.path_segments {
        return Err(PathError::TooManySegments);
    }
    Ok(())
}

/// ASCII case-folded form used for duplicate detection (§4.3.1: paths that
/// differ only by case collide).
pub fn case_fold(path: &str) -> String {
    path.to_ascii_lowercase()
}

/// Does the declared path start with the fixed class root (and have a
/// non-empty file name after it)?
pub fn starts_with_root(path: &str, root: &str) -> bool {
    // root is e.g. "artifacts"; require exactly root/...
    path.len() > root.len()
        && path.as_bytes().get(root.len()) == Some(&b'/')
        && path.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::DEFAULT;

    fn ok(p: &str) -> bool {
        validate(p, &DEFAULT).is_ok()
    }

    #[test]
    fn accepts_valid() {
        assert!(ok("artifacts/ACME-SUPPLIER.draft.md"));
        assert!(ok("inputs/project.yml"));
        assert!(ok("a/b/c/d/e/f/g"));
        assert!(ok("single-segment"));
    }

    #[test]
    fn rejects_traversal_and_junk() {
        assert!(!ok("../outside.md"));
        assert!(!ok("artifacts/../outside.md"));
        assert!(!ok("a//b"));
        assert!(!ok("/etc/passwd"));
        assert!(!ok("a/b/"));
        assert!(!ok("./rel"));
        assert!(!ok("a b/c"));
        assert!(!ok("artifacts/über.md")); // non-ASCII
        assert!(!ok("artifacts/a\\b")); // backslash
        assert!(!ok("artifacts/a:b")); // colon
        // limits
        let long = "x".repeat(256);
        assert!(!ok(&long));
        let many: String = (0..17).map(|i| format!("s{i}")).collect::<Vec<_>>().join("/");
        assert!(!ok(&many));
        let seglen = format!("a/{}", "y".repeat(256));
        assert!(!ok(&seglen));
    }

    #[test]
    fn case_folding() {
        assert_eq!(case_fold("artifacts/A.md"), "artifacts/a.md");
        // non-ASCII bytes are preserved verbatim (stability of the fold rule)
        assert_ne!(case_fold("A"), "a\u{0}");
    }

    #[test]
    fn class_root_prefix() {
        assert!(starts_with_root("artifacts/x.md", "artifacts"));
        assert!(!starts_with_root("artifacts", "artifacts"));
        assert!(!starts_with_root("inputs/x", "artifacts"));
        assert!(!starts_with_root("artifactsx/y", "artifacts"));
    }
}
