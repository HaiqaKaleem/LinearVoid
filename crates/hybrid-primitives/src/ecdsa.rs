//! ECDSA over NIST P-256 with SHA-256 (the classical half of the hybrid
//! signature; the "ES256" of JWA).
//!
//! Serializations:
//! - verification key: 33-byte compressed SEC1 point,
//! - signing key: 32-byte scalar,
//! - signature: 64 bytes `r ‖ s` (fixed-width, not ASN.1 DER — JWA's raw
//!   format).
//!
//! Signing is RFC 6979 deterministic ECDSA: no RNG is involved, which
//! makes signatures reproducible for the KAT vectors and removes nonce
//! reuse as a failure mode. Verification low-S normalizes per SEC1/RFC 6979
//! policy inside the `p256` crate.

use crate::entropy::rand32;
use hybrid_core::error::{Error, Result};
use hybrid_core::traits::Sig;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// ECDSA P-256 / SHA-256 ("ES256").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EcdsaP256Sig;

impl Sig for EcdsaP256Sig {
    const VK_LEN: usize = 33; // compressed SEC1
    const SK_LEN: usize = 32; // scalar
    const SIG_LEN: usize = 64; // r ‖ s

    fn skgen(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // A uniformly random 32-byte string is a valid P-256 scalar with
        // overwhelming probability (~2^-224 failure); retry on the
        // astronomically unlikely miss.
        loop {
            let sk_bytes = rand32();
            if let Ok(sk) = SigningKey::from_slice(&sk_bytes) {
                let vk = VerifyingKey::from(&sk);
                let vk_bytes = vk.to_encoded_point(true).as_bytes().to_vec();
                return Ok((vk_bytes, sk_bytes.to_vec()));
            }
        }
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        hybrid_core::encoding::check_len(sk, Self::SK_LEN, Error::InvalidSecretKeyLength)?;
        let signing = SigningKey::from_slice(sk).map_err(|_| Error::CryptoFailure)?;
        let sig: Signature = signing.sign(msg);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        hybrid_core::encoding::check_len(vk, Self::VK_LEN, Error::InvalidVerificationKeyLength)?;
        hybrid_core::encoding::check_len(sig, Self::SIG_LEN, Error::InvalidSignatureLength)?;
        let verifying =
            VerifyingKey::from_sec1_bytes(vk).map_err(|_| Error::InvalidVerificationKeyLength)?;
        let signature = Signature::from_slice(sig).map_err(|_| Error::InvalidSignatureLength)?;
        Ok(verifying.verify(msg, &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybrid_core::Sig;

    #[test]
    fn roundtrip_and_message_binding() {
        let s = EcdsaP256Sig;
        let (vk, sk) = s.skgen().unwrap();
        assert_eq!(vk.len(), 33);
        assert_eq!(sk.len(), 32);
        let sig = s.sign(&sk, b"hello").unwrap();
        assert_eq!(sig.len(), 64);
        assert!(s.verify(&vk, b"hello", &sig).unwrap());
        assert!(!s.verify(&vk, b"hellO", &sig).unwrap());
    }

    #[test]
    fn cross_key_rejection() {
        let s = EcdsaP256Sig;
        let (_vk1, sk1) = s.skgen().unwrap();
        let (vk2, _sk2) = s.skgen().unwrap();
        let sig = s.sign(&sk1, b"msg").unwrap();
        assert!(!s.verify(&vk2, b"msg", &sig).unwrap());
    }

    #[test]
    fn deterministic_signing() {
        let s = EcdsaP256Sig;
        let (vk, sk) = s.skgen().unwrap();
        let a = s.sign(&sk, b"msg").unwrap();
        let b = s.sign(&sk, b"msg").unwrap();
        assert_eq!(a, b, "RFC 6979 signing must be deterministic");
        assert!(s.verify(&vk, b"msg", &a).unwrap());
    }

    #[test]
    fn signature_bit_flip_rejected() {
        let s = EcdsaP256Sig;
        let (vk, sk) = s.skgen().unwrap();
        let mut sig = s.sign(&sk, b"msg").unwrap();
        sig[63] ^= 1;
        assert!(!s.verify(&vk, b"msg", &sig).unwrap());
    }

    #[test]
    fn malformed_inputs_are_typed_errors() {
        let s = EcdsaP256Sig;
        let (vk, sk) = s.skgen().unwrap();
        let sig = s.sign(&sk, b"msg").unwrap();
        // Wrong-size but well-formed-length-checked inputs fail with typed
        // errors, not panics or bools.
        assert!(matches!(
            s.verify(&vk, b"msg", &sig[..63]),
            Err(Error::InvalidSignatureLength)
        ));
        assert!(matches!(
            s.verify(&vk[..32], b"msg", &sig),
            Err(Error::InvalidVerificationKeyLength)
        ));
        // Well-formed but invalid contents (33 bytes of garbage point) →
        // typed error from the point parser.
        assert!(matches!(
            s.verify(&[0xFFu8; 33], b"msg", &sig),
            Err(Error::InvalidVerificationKeyLength)
        ));
    }
}
