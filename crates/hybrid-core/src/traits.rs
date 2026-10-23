//! Component interfaces (Alg 1 / Alg 2 of the spec).
//!
//! Every backend publishes its encoding lengths as associated constants.
//! The composite layer slices and concatenates *only* through these
//! constants, which is how "fixed-length encodings enforced by
//! construction" (§2) is realized in code: an implementation cannot
//! accidentally accept a variable-length component because the split
//! points are part of the type.

use crate::error::Result;

/// Alg 1: a key encapsulation mechanism with fixed-length encodings.
///
/// `is_broken` exists solely so the formal model (and the proofs' adversary
/// constructions in `model_games`) can *instantiate* a broken component.
/// It is never consulted by the real protocol paths; production backends
/// always return `false`.
pub trait Kem {
    /// Length of an encapsulation key (public key), in bytes.
    const PK_LEN: usize;
    /// Length of a decapsulation key (secret key) *in its serialized form*,
    /// in bytes.
    const SK_LEN: usize;
    /// Length of a ciphertext, in bytes.
    const CT_LEN: usize;
    /// Length of a shared secret, in bytes.
    const SS_LEN: usize;

    /// `(pk, sk)` — fresh keypair.
    fn kgen(&self) -> Result<(Vec<u8>, Vec<u8>)>;

    /// `(ss, ct)` — encapsulate to `pk` (which must be exactly `PK_LEN`
    /// bytes).
    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Recover the shared secret from `ct` under `sk`, or `Err` (⊥).
    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>>;

    /// Model-only hook: reports whether this component instance is fully
    /// broken. Always `false` for real backends.
    fn is_broken(&self) -> bool {
        false
    }
}

/// Alg 2: a signature scheme with fixed-length encodings.
pub trait Sig {
    /// Length of a verification key (public), in bytes.
    const VK_LEN: usize;
    /// Length of a signing key *in its serialized form*, in bytes.
    const SK_LEN: usize;
    /// Length of a signature, in bytes.
    const SIG_LEN: usize;

    /// `(vk, sk)` — fresh keypair.
    fn skgen(&self) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Produce a signature over `msg`.
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>>;

    /// `Ok(true)` iff `sig` is a valid signature by `vk` over `msg`.
    ///
    /// Backends must return `Ok(false)` (not `Err`) for well-formed inputs
    /// that simply fail verification; `Err` is reserved for encoding
    /// violations. Callers must treat both as rejection.
    fn verify(&self, vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool>;

    /// Model-only hook (see [`Kem::is_broken`]).
    fn is_broken(&self) -> bool {
        false
    }
}
