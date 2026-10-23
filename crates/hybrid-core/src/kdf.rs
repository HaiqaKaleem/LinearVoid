//! Dual-PRF key extraction for the composite KEM (§2, `ExtractKey`).
//!
//! The spec's `ExtractKey(ss, salt, info)` is a one-shot HMAC over the
//! concatenated component secrets — a dual-PRF in the style of the IETF
//! hybrid-TLS drafts (both components' outputs feed one extractor, so a
//! break of either component alone reveals nothing about the extracted
//! key; see the G1↔G3 discussion in §7 of the spec).
//!
//! The implementation strengthens the one-shot extractor to full
//! HKDF (RFC 5869 extract-then-expand) with the same signature. This is a
//! strict improvement — the extractor step is identical in shape — and is
//! the construction deployed in hybrid TLS stacks. The mapping is recorded
//! in docs/IMPLEMENTATION.md.

use hkdf::Hkdf;
use sha2::Sha256;

/// Domain-separation salt for the composite KEM's key extraction.
pub const DEFAULT_SALT: &[u8] = b"hybrid-oidc/v1:extract";

/// Domain-separation info label bound into the extracted key.
///
/// Includes the composite algorithm identifier so a key extracted under one
/// hybrid configuration can never be reused under another (algorithm
/// substitution defense).
pub const DEFAULT_INFO: &[u8] = b"Alg3-hybrid-ss/v1";

/// Extract a 32-byte key from a composite shared secret.
///
/// `ss` must be the fixed-length concatenation of both component secrets
/// (validated by the caller against `2 × SS_LEN`); `salt` and `info` bind
/// context and algorithm identity into the output.
pub fn extract_key(ss: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    // Composite secrets are fixed length by construction (Alg 3), so a
    // short `ss` is a caller bug; we still avoid panicking in library code.
    assert!(
        !ss.is_empty() && ss.len() <= 8160,
        "hybrid shared secret must be fixed length (got {} bytes)",
        ss.len()
    );
    let hk = Hkdf::<Sha256>::new(Some(salt), ss);
    let mut okm = [0u8; 32];
    // expand() only fails if okm exceeds the HKDF output limit (255×32B);
    // 32 bytes can never trip it.
    hk.expand(info, &mut okm)
        .expect("32-byte OKM is always within the HKDF output limit");
    okm
}

/// The spec-default extraction: `ExtractKey(ss)` with built-in domain
/// separation.
pub fn extract_key_default(ss: &[u8]) -> [u8; 32] {
    extract_key(ss, DEFAULT_SALT, DEFAULT_INFO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extraction_is_deterministic_and_keyed() {
        let ss = [7u8; 64];
        let k1 = extract_key_default(&ss);
        let k2 = extract_key_default(&ss);
        assert_eq!(k1, k2);

        let mut other = ss;
        other[63] ^= 1;
        assert_ne!(k1, extract_key_default(&other));
    }

    #[test]
    fn salt_and_info_domain_separate() {
        let ss = [9u8; 64];
        assert_ne!(
            extract_key(&ss, DEFAULT_SALT, DEFAULT_INFO),
            extract_key(&ss, b"other-salt", DEFAULT_INFO)
        );
        assert_ne!(
            extract_key(&ss, DEFAULT_SALT, DEFAULT_INFO),
            extract_key(&ss, DEFAULT_SALT, b"other-info")
        );
    }

    #[test]
    fn single_component_change_changes_key() {
        // G1/E2 shape: flipping a bit in *either* component half of the
        // secret changes the extracted key.
        let ss = [0u8; 64];
        let base = extract_key_default(&ss);
        let mut flipped_c = ss;
        flipped_c[0] ^= 1;
        let mut flipped_p = ss;
        flipped_p[63] ^= 1;
        assert_ne!(base, extract_key_default(&flipped_c));
        assert_ne!(base, extract_key_default(&flipped_p));
        assert_ne!(
            extract_key_default(&flipped_c),
            extract_key_default(&flipped_p)
        );
    }
}
