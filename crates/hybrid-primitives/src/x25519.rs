//! X25519 modeled as a KEM (the classical half of the hybrid KEM).
//!
//! Construction (the standard DH-KEM idiom, as in TLS 1.3 key exchange):
//! - `kgen`:  uniformly random 32-byte scalar; `pk = x25519(sk, B)`.
//! - `encapsulate(pk)`: fresh ephemeral scalar `esk`; `ct = esk·B`;
//!   `ss = x25519(esk, pk)`.
//! - `decapsulate(sk, ct)`: `ss = x25519(sk, ct)`.
//!
//! The raw DH output is run through a domain-separated HKDF rather than
//! used directly — raw DH outputs are not uniformly random and the FIPS
//! 186-style "KDF the DH" discipline applies to X25519 too. Non-contributory
//! (all-zero) results — low-order points — are rejected outright.

use crate::entropy::rand32;
use hkdf::Hkdf;
use hybrid_core::error::{Error, Result};
use hybrid_core::traits::Kem;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Domain-separation salt for the X25519 component KDF.
const X25519_SS_LABEL: &[u8] = b"hybrid-oidc/v1:x25519-ss";

/// X25519 as a 32/32/32/32 KEM component.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct X25519Kem;

fn component_kdf(dh: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(X25519_SS_LABEL), dh);
    let mut okm = [0u8; 32];
    hk.expand(b"", &mut okm)
        .expect("32-byte OKM is within the HKDF output limit");
    okm
}

impl Kem for X25519Kem {
    const PK_LEN: usize = 32;
    const SK_LEN: usize = 32;
    const CT_LEN: usize = 32;
    const SS_LEN: usize = 32;

    fn kgen(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let sk_bytes = rand32();
        let sk = StaticSecret::from(sk_bytes);
        let pk = PublicKey::from(&sk);
        Ok((pk.to_bytes().to_vec(), sk_bytes.to_vec()))
    }

    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        hybrid_core::encoding::check_len(pk, Self::PK_LEN, Error::InvalidPublicKeyLength)?;
        let their_pk = PublicKey::from(<[u8; 32]>::try_from(pk).expect("length checked"));
        let eph_bytes = rand32();
        let eph = StaticSecret::from(eph_bytes);
        let eph_pk = PublicKey::from(&eph);
        let shared = eph.diffie_hellman(&their_pk);
        if !shared.was_contributory() {
            return Err(Error::NonContributorySharedSecret);
        }
        let ss = component_kdf(&shared.to_bytes());
        Ok((ss.to_vec(), eph_pk.to_bytes().to_vec()))
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        hybrid_core::encoding::check_len(sk, Self::SK_LEN, Error::InvalidSecretKeyLength)?;
        hybrid_core::encoding::check_len(ct, Self::CT_LEN, Error::InvalidCiphertextLength)?;
        let secret = StaticSecret::from(<[u8; 32]>::try_from(sk).expect("length checked"));
        let eph_pk = PublicKey::from(<[u8; 32]>::try_from(ct).expect("length checked"));
        let shared = secret.diffie_hellman(&eph_pk);
        if !shared.was_contributory() {
            return Err(Error::NonContributorySharedSecret);
        }
        Ok(component_kdf(&shared.to_bytes()).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybrid_core::Kem;

    #[test]
    fn roundtrip() {
        let k = X25519Kem;
        let (pk, sk) = k.kgen().unwrap();
        let (ss1, ct) = k.encapsulate(&pk).unwrap();
        let ss2 = k.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1, ss2);
        assert_eq!(ss1.len(), 32);
    }

    #[test]
    fn low_order_point_rejected() {
        let k = X25519Kem;
        let (_pk, sk) = k.kgen().unwrap();
        // The all-zero point is small-order: DH against it is non-contributory.
        let zero_point = [0u8; 32];
        assert_eq!(
            k.decapsulate(&sk, &zero_point),
            Err(Error::NonContributorySharedSecret)
        );
    }

    #[test]
    fn wrong_lengths_rejected() {
        let k = X25519Kem;
        assert!(matches!(
            k.encapsulate(&[0u8; 31]),
            Err(Error::InvalidPublicKeyLength)
        ));
        let (pk, sk) = k.kgen().unwrap();
        let (_ss, ct) = k.encapsulate(&pk).unwrap();
        assert!(matches!(
            k.decapsulate(&sk, &ct[..31]),
            Err(Error::InvalidCiphertextLength)
        ));
    }

    #[test]
    fn keys_are_independent() {
        let k = X25519Kem;
        let (pk1, sk1) = k.kgen().unwrap();
        let (pk2, sk2) = k.kgen().unwrap();
        assert_ne!(pk1, pk2);
        assert_ne!(sk1, sk2);
    }
}
