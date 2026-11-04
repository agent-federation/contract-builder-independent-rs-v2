//! Independent Phase 2a verifier for Portable Assurance Package (PAP) v0.1.
//!
//! Written natively in Rust from the accepted PAP v0.1 RFC, its published JSON
//! schemas, the Appendix E vectors and the static fixture corpus. No third
//! party dependencies; a strict I-JSON parser, RFC 8785 JCS canonicalization,
//! domain-separated SHA-256 identities, package filesystem safety, minimal
//! trust-policy reading, report construction and verdict/exit-code
//! foundations are implemented, exactly as scoped by the Phase 2a brief.
//!
//! Cryptographic signature verification (DSSE/Ed25519), the three §8 checks,
//! claim-file content validation, human-review evaluation and the full public
//! CLI contract (inspect/explain) are later-phase scope and are deliberately
//! NOT implemented here.

pub mod checker;
pub mod diag;
pub mod digest;
pub mod json;
pub mod jcs;
pub mod limits;
pub mod normalize;
pub mod pathrule;
pub mod rfc3339;
pub mod sha256;

pub mod cli;
pub mod manifest;
pub mod pkg;
pub mod policy;
pub mod report;
pub mod verdict;
