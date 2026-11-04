# Security boundary documentation

- No network access.
- No execution of package content.
- Paths validated against grammar before filesystem access.
- Package root resolved once; root confinement enforced.
- Symlinks and non-regular files rejected for declared payloads.
- Resource limits enforced (manifest bytes, payload counts/bytes, JSON nesting/string sizes).
- Undeclared files never opened.
- Filesystem enumeration errors reported as scan-incomplete, never pass.
- Verification is read-only.
