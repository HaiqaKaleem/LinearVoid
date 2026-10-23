//! The executable formal model: idealized random-oracle components with
//! adjustable break flags (§3, §8 of the spec).
//!
//! These backends realize the *model* in which the spec's reductions are
//! proven: `roKEM` and `roSig` are random-oracle constructions whose
//! `is_broken` flag instantiates the E1/E2 primitive restrictions the
//! adversary is granted in the theorems. They let the reductions in §5–§7
//! run to completion as executable tests (`tests/model_games.rs`), exactly
//! as the Go reference model under `model/` does.
//!
//! **These backends are NOT secure and must never be used outside tests.**
//! The production backends live in `hybrid-primitives`.

use crate::error::{Error, Result};
use crate::traits::{Kem, Sig};
use sha2::{Digest, Sha256};

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    getrandom::fill(&mut out).expect("OS RNG unavailable");
    out
}

/// Idealized KEM in the random-oracle model.
///
/// - `pk` is a uniformly random 48-byte ROI seed; `sk := pk` (stand-in for
///   the algebraic sk↔pk relation of a real KEM).
/// - `Enc(pk)`: `ss ← random(32)`, `ct ‖= H(pk ‖ ss)` as a binding tag.
/// - `Dec(sk, ct)`: recompute the tag against `sk`; mismatch → ⊥.
/// - If `broken`: `Dec` recovers `ss` straight from the ciphertext — a
///   total break of the component (models e.g. Shor on ECDH, or a lattice
///   break of ML-KEM).
pub struct RoKem {
    broken: bool,
}

impl RoKem {
    pub fn new() -> Self {
        Self { broken: false }
    }
    /// A totally broken instance (E1/E2 adversary restriction).
    pub fn broken() -> Self {
        Self { broken: true }
    }
}

impl Default for RoKem {
    fn default() -> Self {
        Self::new()
    }
}

const RO_SS_LEN: usize = 32;
const RO_CT_LEN: usize = 96;
const RO_PK_LEN: usize = 48;

fn ro_tag(input1: &[u8], input2: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input1);
    h.update(input2);
    h.finalize().into()
}

impl Kem for RoKem {
    const PK_LEN: usize = RO_PK_LEN;
    const SK_LEN: usize = RO_PK_LEN;
    const CT_LEN: usize = RO_CT_LEN;
    const SS_LEN: usize = RO_SS_LEN;

    fn kgen(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let pk = rand_bytes(RO_PK_LEN);
        Ok((pk.clone(), pk))
    }

    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if pk.len() != RO_PK_LEN {
            return Err(Error::InvalidPublicKeyLength);
        }
        let ss = rand_bytes(RO_SS_LEN);
        let mut ct = vec![0u8; RO_CT_LEN];
        ct[..RO_SS_LEN].copy_from_slice(&ss);
        // Binding tag over (pk ‖ ss) in the tag region; the remaining
        // trailing bytes stay zero, and decapsulate checks them too, so any
        // flipped byte anywhere in the trailing region is caught.
        ct[RO_SS_LEN..RO_SS_LEN + 32].copy_from_slice(&ro_tag(pk, &ss));
        Ok((ss, ct))
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        if sk.len() != RO_PK_LEN {
            return Err(Error::InvalidSecretKeyLength);
        }
        if ct.len() != RO_CT_LEN {
            return Err(Error::InvalidCiphertextLength);
        }
        let ss = &ct[..RO_SS_LEN];
        if self.broken {
            // Total break: the adversary recovers ss from the ciphertext
            // without consulting sk's binding relation at all.
            return Ok(ss.to_vec());
        }
        let want = ro_tag(sk, ss);
        // Compare the full trailing region (tag + zero padding).
        if ct[RO_SS_LEN..RO_SS_LEN + 32] != want || ct[RO_SS_LEN + 32..].iter().any(|&b| b != 0) {
            return Err(Error::DecapsulationFailure);
        }
        Ok(ss.to_vec())
    }

    fn is_broken(&self) -> bool {
        self.broken
    }
}

/// Idealized signature in the random-oracle model.
///
/// - `vk ← random(32)`; `sk := HMAC(k_deriv, vk)` — a stand-in for the
///   algebraic vk↔sk relation (a real vk reveals nothing about sk; the
///   reductions only need verifiability, per §8).
/// - `Sign(sk, m) = HMAC(sk, m)`; `Ver` recomputes via the derived key.
/// - If `broken`: `Ver` accepts everything (total break: adversary can
///   sign any message).
pub struct RoSig {
    broken: bool,
}

impl RoSig {
    pub fn new() -> Self {
        Self { broken: false }
    }
    pub fn broken() -> Self {
        Self { broken: true }
    }
}

impl Default for RoSig {
    fn default() -> Self {
        Self::new()
    }
}

fn ro_derive_sk(vk: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(b"hybridoidc/sk-derivation")
        .expect("HMAC accepts any key length");
    m.update(vk);
    m.finalize().into_bytes().into()
}

fn ro_hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

impl Sig for RoSig {
    const VK_LEN: usize = 32;
    const SK_LEN: usize = 32;
    const SIG_LEN: usize = 32;

    fn skgen(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let vk = rand_bytes(32);
        let sk = ro_derive_sk(&vk).to_vec();
        Ok((vk, sk))
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        if sk.len() != 32 {
            return Err(Error::InvalidSecretKeyLength);
        }
        Ok(ro_hmac(sk, msg).to_vec())
    }

    fn verify(&self, vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        if vk.len() != 32 {
            return Err(Error::InvalidVerificationKeyLength);
        }
        if sig.len() != 32 {
            return Err(Error::InvalidSignatureLength);
        }
        if self.broken {
            return Ok(true);
        }
        let want = ro_hmac(&ro_derive_sk(vk), msg);
        Ok(subtle::ConstantTimeEq::ct_eq(&want[..], sig).into())
    }

    fn is_broken(&self) -> bool {
        self.broken
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_honest_roundtrip_and_tamper() {
        let k = RoKem::new();
        let (pk, sk) = k.kgen().unwrap();
        let (ss1, ct) = k.encapsulate(&pk).unwrap();
        let ss2 = k.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1, ss2);

        let mut bad = ct.clone();
        bad[RO_CT_LEN - 1] ^= 1; // flip a padding-region byte
        assert_eq!(k.decapsulate(&sk, &bad), Err(Error::DecapsulationFailure));

        let mut bad_ss = ct.clone();
        bad_ss[0] ^= 1;
        assert_eq!(
            k.decapsulate(&sk, &bad_ss),
            Err(Error::DecapsulationFailure)
        );
    }

    #[test]
    fn broken_kem_recovers_ss_without_relation() {
        let k = RoKem::broken();
        let honest = RoKem::new();
        let (pk, _sk) = honest.kgen().unwrap();
        let (ss, ct) = honest.encapsulate(&pk).unwrap();
        // Broken component decapsulates someone else's ciphertext with a
        // *wrong* key and still recovers ss (total break).
        let garbage_sk = vec![0u8; RO_PK_LEN];
        assert_eq!(k.decapsulate(&garbage_sk, &ct).unwrap(), ss);
    }

    #[test]
    fn sig_honest_roundtrip_and_cross_key_rejection() {
        let s = RoSig::new();
        let (vk, sk) = s.skgen().unwrap();
        let sig = s.sign(&sk, b"msg").unwrap();
        assert!(s.verify(&vk, b"msg", &sig).unwrap());
        assert!(!s.verify(&vk, b"msg2", &sig).unwrap());

        let (vk2, _) = s.skgen().unwrap();
        assert!(!s.verify(&vk2, b"msg", &sig).unwrap());
    }

    #[test]
    fn broken_sig_accepts_everything() {
        let s = RoSig::broken();
        let (vk, _) = s.skgen().unwrap();
        assert!(s.verify(&vk, b"anything", &[0u8; 32]).unwrap());
    }
}
