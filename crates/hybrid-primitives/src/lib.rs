//! # hybrid-primitives
//!
//! Real cryptographic backends implementing [`hybrid_core::Kem`] and
//! [`hybrid_core::Sig`]:
//!
//! | Backend | Role | Algorithms | Standards |
//! |---------|------|------------|-----------|
//! | [`X25519Kem`]     | classical KEM half | X25519 (DH-KEM + HKDF) | RFC 7748 |
//! | [`MlKem768Kem`]   | pq KEM half        | ML-KEM-768 | FIPS 203 |
//! | [`EcdsaP256Sig`]  | classical sig half | ECDSA P-256 / SHA-256 (ES256) | FIPS 186-5, RFC 7518 |
//! | [`MlDsa87Sig`]    | pq sig half        | ML-DSA-87 | FIPS 204 |
//!
//! The composite instantiations from the spec's prototype section:
//!
//! - [`x25519_ml_kem_768()`] — Alg 3 hybrid KEM: `X25519 ‖ ML-KEM-768`
//!   (mirrors the X25519MLKEM768 construction deployed in TLS 1.3 hybrids),
//! - [`ecdsa_p256_mldsa_87()`] — Alg 4 hybrid signature:
//!   `ECDSA-P256 ‖ ML-DSA-87`.
//!
//! Every backend enforces its component's fixed encoding lengths
//! ([`hybrid_core::encoding`]) before any cryptographic operation, and all
//! randomness comes from the OS CSPRNG through seed/bytes constructors —
//! see `entropy` for why no RNG traits are plumbed through.

pub mod ecdsa;
pub mod entropy;
pub mod mldsa;
pub mod mlkem;
pub mod x25519;

pub use ecdsa::EcdsaP256Sig;
pub use entropy::{rand_bytes, rand32, rand64};
pub use mldsa::MlDsa87Sig;
pub use mlkem::MlKem768Kem;
pub use x25519::X25519Kem;

use hybrid_core::{HybridKem, HybridSig};

/// The spec's hybrid KEM: `X25519 ‖ ML-KEM-768`.
pub type X25519MlKem768 = HybridKem<X25519Kem, MlKem768Kem>;

/// The spec's hybrid signature: `ECDSA-P-256 ‖ ML-DSA-87`.
pub type EcdsaP256MlDsa87 = HybridSig<EcdsaP256Sig, MlDsa87Sig>;

/// Construct the hybrid KEM `X25519 ‖ ML-KEM-768`.
pub fn x25519_ml_kem_768() -> X25519MlKem768 {
    HybridKem {
        classical: X25519Kem,
        pq: MlKem768Kem,
    }
}

/// Construct the hybrid signature `ECDSA-P-256 ‖ ML-DSA-87`.
pub fn ecdsa_p256_mldsa_87() -> EcdsaP256MlDsa87 {
    HybridSig {
        classical: EcdsaP256Sig,
        pq: MlDsa87Sig,
    }
}

/// Composite encoding sizes, in bytes (the §2 fixed-length table).
pub mod sizes {
    /// `X25519 ‖ ML-KEM-768` public key.
    pub const HYBRID_KEM_PK: usize = 32 + 1184;
    /// `X25519 ‖ ML-KEM-768` secret key (scalar ‖ seed).
    pub const HYBRID_KEM_SK: usize = 32 + 64;
    /// `X25519 ‖ ML-KEM-768` ciphertext.
    pub const HYBRID_KEM_CT: usize = 32 + 1088;
    /// `X25519 ‖ ML-KEM-768` pre-extraction shared secret.
    pub const HYBRID_KEM_SS: usize = 32 + 32;
    /// Extracted session key.
    pub const SESSION_KEY: usize = 32;

    /// `ECDSA-P-256 ‖ ML-DSA-87` verification key.
    pub const HYBRID_SIG_VK: usize = 33 + 2592;
    /// `ECDSA-P-256 ‖ ML-DSA-87` signing key (scalar ‖ seed).
    pub const HYBRID_SIG_SK: usize = 32 + 32;
    /// `ECDSA-P-256 ‖ ML-DSA-87` signature.
    pub const HYBRID_SIG: usize = 64 + 4627;
}
