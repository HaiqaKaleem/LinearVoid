//! Alg 4: the composite-hybrid signature.
//!
//! `vkH = vk_c ‖ vk_p`, `sigH = σ_c ‖ σ_p`, and verification is the
//! *conjunction* of both component verifications over the same message:
//! a signature is valid iff the classical half AND the pq half both
//! verify. (G3 in the spec — the conjunction is what forces an adversary
//! to break the strongest component, yielding G4's weakest-link theorem.)

use crate::encoding::{concat, split_at_checked};
use crate::error::Result;
use crate::traits::Sig;

/// The composite-hybrid signature over components `C` (classical) and
/// `P` (PQ).
#[derive(Debug, Clone, Default)]
pub struct HybridSig<C, P> {
    pub classical: C,
    pub pq: P,
}

impl<C: Sig, P: Sig> HybridSig<C, P> {
    /// Total length of a hybrid verification key.
    pub const VK_H_LEN: usize = C::VK_LEN + P::VK_LEN;
    /// Total length of a hybrid signing key.
    pub const SK_H_LEN: usize = C::SK_LEN + P::SK_LEN;
    /// Total length of a hybrid signature.
    pub const SIG_H_LEN: usize = C::SIG_LEN + P::SIG_LEN;

    /// Alg 4 `SkgH`: independent keygen on each component.
    pub fn skgen_h(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (vkc, skc) = self.classical.skgen()?;
        let (vkp, skp) = self.pq.skgen()?;
        debug_assert_eq!(vkc.len(), C::VK_LEN);
        debug_assert_eq!(vkp.len(), P::VK_LEN);
        Ok((concat(&vkc, &vkp), concat(&skc, &skp)))
    }

    /// Alg 4 `SignH`: both components sign the *same* message.
    pub fn sign_h(&self, sk_h: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let (skc, skp) = split_at_checked(sk_h, C::SK_LEN, Self::SK_H_LEN)?;
        let sc = self.classical.sign(skc, msg)?;
        let sp = self.pq.sign(skp, msg)?;
        debug_assert_eq!(sc.len(), C::SIG_LEN);
        debug_assert_eq!(sp.len(), P::SIG_LEN);
        Ok(concat(&sc, &sp))
    }

    /// Alg 4 `VerH`: conjunction — both halves must verify the same msg.
    ///
    /// Both component verifications always run (no short-circuit) so the
    /// operation's wall-clock shape does not reveal which half failed;
    /// length violations are rejected before any crypto runs.
    pub fn verify_h(&self, vk_h: &[u8], msg: &[u8], sig_h: &[u8]) -> Result<bool> {
        let (vkc, vkp) = split_at_checked(vk_h, C::VK_LEN, Self::VK_H_LEN)?;
        let (sc, sp) = split_at_checked(sig_h, C::SIG_LEN, Self::SIG_H_LEN)?;
        // Deliberately non-short-circuiting (see doc comment).
        let ok_c = self.classical.verify(vkc, msg, sc)?;
        let ok_p = self.pq.verify(vkp, msg, sp)?;
        Ok(ok_c & ok_p)
    }
}
