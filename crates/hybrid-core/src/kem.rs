//! Alg 3: the composite-hybrid KEM.
//!
//! `pkH = pk_c ‖ pk_p`, `ctH = ct_c ‖ ct_p`, `ssH = ss_c ‖ ss_p`, and
//! decapsulation returns ⊥ if *either* component fails (conjunction).
//! The application-facing key is `extract_key(ssH)`.
//!
//! Construction invariants (spec §2):
//! - every encoding is a fixed-length concatenation, sliced only at the
//!   components' published lengths;
//! - a failure in either half fails the whole operation — there is no
//!   "degraded" mode where one component's secret suffices.

use crate::encoding::{concat, split_at_checked};
use crate::error::{Error, Result};
use crate::kdf::extract_key_default;
use crate::traits::Kem;

/// The composite-hybrid KEM over components `C` (classical) and `P` (PQ).
#[derive(Debug, Clone, Default)]
pub struct HybridKem<C, P> {
    pub classical: C,
    pub pq: P,
}

impl<C: Kem, P: Kem> HybridKem<C, P> {
    /// Total length of a hybrid public key.
    pub const PK_H_LEN: usize = C::PK_LEN + P::PK_LEN;
    /// Total length of a hybrid secret key.
    pub const SK_H_LEN: usize = C::SK_LEN + P::SK_LEN;
    /// Total length of a hybrid ciphertext.
    pub const CT_H_LEN: usize = C::CT_LEN + P::CT_LEN;
    /// Total length of a hybrid (pre-extraction) shared secret.
    pub const SS_H_LEN: usize = C::SS_LEN + P::SS_LEN;

    /// Alg 3 `KgenH`: independent keygen on each component.
    pub fn kgen_h(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (pkc, skc) = self.classical.kgen()?;
        let (pkp, skp) = self.pq.kgen()?;
        debug_assert_eq!(pkc.len(), C::PK_LEN);
        debug_assert_eq!(pkp.len(), P::PK_LEN);
        Ok((concat(&pkc, &pkp), concat(&skc, &skp)))
    }

    /// Alg 3 `EncH`: encapsulate to both components, concatenate.
    pub fn encapsulate_h(&self, pk_h: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (pkc, pkp) = split_at_checked(pk_h, C::PK_LEN, Self::PK_H_LEN)?;
        let (ssc, ctc) = self.classical.encapsulate(pkc)?;
        let (ssp, ctp) = self.pq.encapsulate(pkp)?;
        debug_assert_eq!(ctc.len(), C::CT_LEN);
        debug_assert_eq!(ctp.len(), P::CT_LEN);
        Ok((concat(&ssc, &ssp), concat(&ctc, &ctp)))
    }

    /// Alg 3 `DecH`: decapsulate componentwise; ⊥ if either half fails.
    ///
    /// Note on implicit rejection: a FIPS 203 ML-KEM ciphertext that fails
    /// its binding check decapsulates to a pseudorandom secret rather than
    /// erroring. The composite is still sound — the extracted key then
    /// differs from the sender's with overwhelming probability, and
    /// authentication failure surfaces at the record/AEAD layer. This is
    /// exactly the G2 argument (Games 0–3) in §5 of the spec; length
    /// violations *are* rejected eagerly here.
    pub fn decapsulate_h(&self, sk_h: &[u8], ct_h: &[u8]) -> Result<Vec<u8>> {
        let (skc, skp) = split_at_checked(sk_h, C::SK_LEN, Self::SK_H_LEN)?;
        let (ctc, ctp) = split_at_checked(ct_h, C::CT_LEN, Self::CT_H_LEN)?;
        let ssc = self.classical.decapsulate(skc, ctc)?;
        let ssp = self.pq.decapsulate(skp, ctp)?;
        debug_assert_eq!(ssc.len(), C::SS_LEN);
        debug_assert_eq!(ssp.len(), P::SS_LEN);
        Ok(concat(&ssc, &ssp))
    }

    /// The application-facing key: domain-separated extraction over both
    /// component secrets.
    pub fn session_key(&self, ss_h: &[u8]) -> Result<[u8; 32]> {
        if ss_h.len() != Self::SS_H_LEN {
            return Err(Error::InvalidHybridEncoding);
        }
        Ok(extract_key_default(ss_h))
    }

    /// Full encapsulate + extract convenience (initiator side).
    pub fn encapsulate_key(&self, pk_h: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
        let (ss_h, ct_h) = self.encapsulate_h(pk_h)?;
        Ok((self.session_key(&ss_h)?, ct_h))
    }

    /// Full decapsulate + extract convenience (responder side).
    pub fn decapsulate_key(&self, sk_h: &[u8], ct_h: &[u8]) -> Result<[u8; 32]> {
        let ss_h = self.decapsulate_h(sk_h, ct_h)?;
        self.session_key(&ss_h)
    }
}
