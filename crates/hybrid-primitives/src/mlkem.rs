//! ML-KEM-768 (FIPS 203) as the pq half of the hybrid KEM.
//!
//! Serializations (all fixed length, per §2 of the spec):
//! - public key (encapsulation key): 1184 bytes,
//! - secret key: the 64-byte FIPS 203 `Seed` (the crate's preferred
//!   private-key representation; the 2400-byte expanded encoding is
//!   deliberately not used),
//! - ciphertext: 1088 bytes, shared secret: 32 bytes.
//!
//! Key material enters only through seed constructors, and encapsulation
//! uses the crate's system-RNG path (`getrandom` feature) — no RNG trait
//! plumbing crosses the `rand_core` version boundary. Decapsulation of a
//! tampered ciphertext yields a pseudorandom secret (FIPS 203 implicit
//! rejection) rather than an error; the composite KEM's dual-PRF
//! extraction turns that into a key mismatch at the record layer (the G2
//! argument, §5 of the spec).

use crate::entropy::rand64;
use hybrid_core::error::{Error, Result};
use hybrid_core::traits::Kem;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, Seed};

/** ML-KEM-768 (FIPS 203, security category 3). */
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MlKem768Kem;

impl Kem for MlKem768Kem {
    const PK_LEN: usize = 1184;
    const SK_LEN: usize = 64; // FIPS 203 seed
    const CT_LEN: usize = 1088;
    const SS_LEN: usize = 32;

    fn kgen(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let seed = Seed::from(rand64());
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let pk = dk.encapsulation_key().to_bytes().to_vec();
        let sk = dk
            .to_seed()
            .expect("seed-initialized key retains its seed")
            .to_vec();
        Ok((pk, sk))
    }

    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        hybrid_core::encoding::check_len(pk, Self::PK_LEN, Error::InvalidPublicKeyLength)?;
        let encoded: Array<u8, _> = Array::try_from(pk).expect("length checked");
        let ek = EncapsulationKey::<MlKem768>::new(&encoded).map_err(|_| Error::CryptoFailure)?;
        let (ct, ss) = ek.encapsulate();
        Ok((ss.to_vec(), ct.to_vec()))
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        hybrid_core::encoding::check_len(sk, Self::SK_LEN, Error::InvalidSecretKeyLength)?;
        hybrid_core::encoding::check_len(ct, Self::CT_LEN, Error::InvalidCiphertextLength)?;
        let seed = Seed::from(<[u8; 64]>::try_from(sk).expect("length checked"));
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let ss = dk
            .decapsulate_slice(ct)
            .map_err(|_| Error::DecapsulationFailure)?;
        Ok(ss.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybrid_core::Kem;

    #[test]
    fn roundtrip() {
        let k = MlKem768Kem;
        let (pk, sk) = k.kgen().unwrap();
        assert_eq!(pk.len(), 1184);
        assert_eq!(sk.len(), 64);
        let (ss1, ct) = k.encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), 1088);
        assert_eq!(ss1.len(), 32);
        let ss2 = k.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn keygen_from_seed_is_deterministic() {
        let _k = MlKem768Kem;
        let seed = Seed::from([7u8; 64]);
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let pk1 = dk.encapsulation_key().to_bytes().to_vec();
        let dk2 = DecapsulationKey::<MlKem768>::from_seed(Seed::from([7u8; 64]));
        let pk2 = dk2.encapsulation_key().to_bytes().to_vec();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn implicit_rejection_of_tampered_ciphertext() {
        let k = MlKem768Kem;
        let (pk, sk) = k.kgen().unwrap();
        let (ss, ct) = k.encapsulate(&pk).unwrap();
        let mut bad = ct.clone();
        bad[0] ^= 1;
        let ss_bad = k.decapsulate(&sk, &bad).unwrap();
        // FIPS 203 implicit rejection: no error, but a *different* secret —
        // never the honest one.
        assert_ne!(ss_bad, ss);
        // And it's not a constant: two different tamper positions give
        // unrelated secrets.
        let mut bad2 = ct.clone();
        bad2[1087] ^= 0x80;
        let ss_bad2 = k.decapsulate(&sk, &bad2).unwrap();
        assert_ne!(ss_bad2, ss);
        assert_ne!(ss_bad2, ss_bad);
    }

    #[test]
    fn wrong_lengths_rejected() {
        let k = MlKem768Kem;
        assert!(matches!(
            k.encapsulate(&[0u8; 10]),
            Err(Error::InvalidPublicKeyLength)
        ));
        let (pk, sk) = k.kgen().unwrap();
        let (_ss, ct) = k.encapsulate(&pk).unwrap();
        assert!(matches!(
            k.decapsulate(&sk, &ct[..1087]),
            Err(Error::InvalidCiphertextLength)
        ));
        assert!(matches!(
            k.decapsulate(&sk[..63], &ct),
            Err(Error::InvalidSecretKeyLength)
        ));
    }
}
