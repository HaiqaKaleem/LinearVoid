//! ML-DSA-87 (FIPS 204) — the pq half of the hybrid signature.
//!
//! Serializations (all fixed length):
//! - verification key: 2592 bytes,
//! - signing key: the 32-byte FIPS 204 `Seed` (the crate's preferred
//!   representation; the 4896-byte expanded encoding is deliberately not
//!   used),
//! - signature: 4627 bytes.
//!
//! Signing uses the crate's deterministic variant with an empty context
//! (FIPS 204 §4.1: deterministic signing is standard-conformant; the
//! randomized "hedged" variant is optional). Determinism makes the KAT
//! vectors reproducible. The RustCrypto implementation is constant-time in
//! its verification path.
//!
// Note: the // on this line ends the //! module doc block

use crate::entropy::rand32;
use hybrid_array::Array;
use hybrid_core::error::{Error, Result};
use hybrid_core::traits::Sig;
use ml_dsa::Keypair;
use ml_dsa::VerifyingKey;
use ml_dsa::signature::{SignatureEncoding, Signer, Verifier};
use ml_dsa::{MlDsa87, Seed, Signature, SigningKey};

/** ML-DSA-87 (FIPS 204, security category 5). */
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MlDsa87Sig;

impl Sig for MlDsa87Sig {
    const VK_LEN: usize = 2592;
    const SK_LEN: usize = 32; // FIPS 204 seed
    const SIG_LEN: usize = 4627;

    fn skgen(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let seed = rand32();
        let signing = SigningKey::<MlDsa87>::from_seed(&Seed::from(seed));
        let vk = signing.verifying_key().encode().to_vec();
        Ok((vk, seed.to_vec()))
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        hybrid_core::encoding::check_len(sk, Self::SK_LEN, Error::InvalidSecretKeyLength)?;
        let seed = Seed::from(<[u8; 32]>::try_from(sk).expect("length checked"));
        let signing = SigningKey::<MlDsa87>::from_seed(&seed);
        let sig = signing.sign(msg);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        hybrid_core::encoding::check_len(vk, Self::VK_LEN, Error::InvalidVerificationKeyLength)?;
        hybrid_core::encoding::check_len(sig, Self::SIG_LEN, Error::InvalidSignatureLength)?;
        let encoded_vk: Array<u8, _> = Array::try_from(vk).map_err(|_| {
            // Only reachable if the length check above were wrong.
            Error::InvalidVerificationKeyLength
        })?;
        let verifying = VerifyingKey::<MlDsa87>::decode(&encoded_vk);
        let signature =
            Signature::<MlDsa87>::try_from(sig).map_err(|_| Error::InvalidSignatureLength)?;
        Ok(verifying.verify(msg, &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybrid_core::Sig;

    #[test]
    fn roundtrip_and_message_binding() {
        let s = MlDsa87Sig;
        let (vk, sk) = s.skgen().unwrap();
        assert_eq!(vk.len(), 2592);
        assert_eq!(sk.len(), 32);
        let sig = s.sign(&sk, b"hello").unwrap();
        assert_eq!(sig.len(), 4627);
        assert!(s.verify(&vk, b"hello", &sig).unwrap());
        assert!(!s.verify(&vk, b"hellO", &sig).unwrap());
    }

    #[test]
    fn cross_key_rejection() {
        let s = MlDsa87Sig;
        let (_vk1, sk1) = s.skgen().unwrap();
        let (vk2, _sk2) = s.skgen().unwrap();
        let sig = s.sign(&sk1, b"msg").unwrap();
        assert!(!s.verify(&vk2, b"msg", &sig).unwrap());
    }

    #[test]
    fn deterministic_signing() {
        let s = MlDsa87Sig;
        let (vk, sk) = s.skgen().unwrap();
        let a = s.sign(&sk, b"msg").unwrap();
        let b = s.sign(&sk, b"msg").unwrap();
        assert_eq!(a, b, "deterministic ML-DSA signing must be reproducible");
        assert!(s.verify(&vk, b"msg", &a).unwrap());
    }

    #[test]
    fn signature_bit_flip_rejected() {
        let s = MlDsa87Sig;
        let (vk, sk) = s.skgen().unwrap();
        let sig = s.sign(&sk, b"msg").unwrap();
        // ML-DSA-87 signatures are ~4627 bytes. Tampered signature must be
        // rejected (verify returns Ok(false) for a valid sig payload).
        let mut tampered = sig.clone();
        tampered[0] ^= 1;
        let result = s.verify(&vk, b"msg", &tampered);
        assert!(
            result.is_ok() && !result.unwrap(),
            "tampered sig must be rejected"
        );
    }

    #[test]
    fn malformed_inputs_are_typed_errors() {
        let s = MlDsa87Sig;
        let (vk, sk) = s.skgen().unwrap();
        let sig = s.sign(&sk, b"msg").unwrap();
        assert!(matches!(
            s.verify(&vk, b"msg", &sig[..4626]),
            Err(Error::InvalidSignatureLength)
        ));
        assert!(matches!(
            s.verify(&vk[..2591], b"msg", &sig),
            Err(Error::InvalidVerificationKeyLength)
        ));
    }
}
