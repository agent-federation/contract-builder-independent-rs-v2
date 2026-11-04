//! Verifier/checker identity of this build (RFC §5.8; brief §4.4.1).
//!
//! `implementationDigest` = extensionClosureDigest(kind="checker",
//! id=<verifier-id>, version=<verifier-version>, files=<this build's source
//! closure>, dependencies=<pinned dependency closure>)
//! computed by `build.rs` from the checkout contents at build time and
//! embedded here. Dependencies: none (pure std crate).
//!
//! `checkerIdentity` = H("pap.checker.identity.v1", JCS({id, version,
//! implementationDigest})).

include!(concat!(env!("OUT_DIR"), "/pap_build_identity.rs"));

use crate::digest::Digest;

pub fn verifier_id() -> &'static str {
    VERIFIER_ID
}

pub fn verifier_version() -> &'static str {
    VERIFIER_VERSION
}

pub fn implementation_digest() -> Digest {
    Digest::parse(IMPLEMENTATION_DIGEST).expect("build.rs emits a canonical digest")
}

pub fn checker_identity() -> Digest {
    Digest::parse(CHECKER_IDENTITY).expect("build.rs emits a canonical digest")
}

/// The closure file list (repo-relative POSIX paths, ascending).
pub fn closure_files() -> &'static [&'static str] {
    CLOSURE_FILES
}

/// The pinned dependency records (name, version, integrity) — empty for this
/// pure-std implementation.
pub fn closure_dependencies() -> &'static [(&'static str, &'static str, &'static str)] {
    CLOSURE_DEPENDENCIES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest;
    use crate::sha256::hex_lower;

    #[test]
    fn identity_is_well_formed() {
        assert_eq!(verifier_id(), "pap.verifier.rust");
        assert_eq!(verifier_version(), "0.1.0");
        let digest = implementation_digest();
        assert!(digest.0 != [0u8; 32]);
        // checkerIdentity == H("pap.checker.identity.v1", JCS({...}))
        let expected = digest::checker_identity(
            verifier_id(),
            verifier_version(),
            IMPLEMENTATION_DIGEST,
        );
        assert_eq!(
            hex_lower(&expected),
            hex_lower(&checker_identity().0)
        );
        // The checker identity literal matches the two-step computation.
        let identity_json = format!(
            "{{\"id\":\"pap.verifier.rust\",\"implementationDigest\":\"sha256:{}\",\"version\":\"0.1.0\"}}",
            hex_lower(&digest.0)
        );
        assert_eq!(
            hex_lower(&digest::h("pap.checker.identity.v1", identity_json.as_bytes())),
            hex_lower(&checker_identity().0)
        );
    }

}
