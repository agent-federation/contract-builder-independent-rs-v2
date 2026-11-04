# PAP Phase 2a experimental — Rust release

- crate: `pap-verifier` `0.1.0-alpha.3`; binary `pap`
- experiment: `PAP-RS-P2A-003` (glm-5.3-flash); Gate 3 result commit: `0b31dac`
- scope: Phase 2a only; not full PAP/Tier B conformance
- license: MIT

## Build

```bash
cargo build --release
```

## Evidence

- 19/19 full + 36/36 identity, zero comparison findings;
- external Gate 3 audit: APPROVED UNCONDITIONALLY (Phase 2a);
- `Cargo.toml`/`Cargo.lock` are in the checker closure, so this metadata release has a new checker
  identity; the Gate 3 tag remains `pap-rs-p2a-003-result`.
