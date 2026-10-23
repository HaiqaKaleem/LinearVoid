//! Error taxonomy shared by every layer of the stack.
//!
//! Errors are deliberately coarse at the API boundary: a caller (or an
//! adversary probing an oracle) learns only *which class* of input was
//! rejected, never internal state. Length errors are distinguished from
//! cryptographic failures because they indicate a caller/conformance bug
//! rather than an attack, and conflating them hides real integration
//! mistakes (this mirrors the fixed-length encoding discipline in §2 of the
//! spec).

/// Errors produced by the hybrid constructions and the primitive backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("public key has the wrong length")]
    InvalidPublicKeyLength,
    #[error("secret key has the wrong length")]
    InvalidSecretKeyLength,
    #[error("verification key has the wrong length")]
    InvalidVerificationKeyLength,
    #[error("ciphertext has the wrong length")]
    InvalidCiphertextLength,
    #[error("signature has the wrong length")]
    InvalidSignatureLength,
    #[error("hybrid ciphertext/key is not the concatenation of both components")]
    InvalidHybridEncoding,
    #[error("decapsulation failed")]
    DecapsulationFailure,
    #[error("shared secret is non-contributory (all-zero / low-order)")]
    NonContributorySharedSecret,
    #[error("primitive operation failed")]
    CryptoFailure,
}

/// Convenience alias used throughout the workspace.
pub type Result<T> = std::result::Result<T, Error>;
