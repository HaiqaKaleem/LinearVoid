//! # hybrid-core
//!
//! The composite-hybrid constructions from
//! `docs/hybrid-oidc-security-spec.md`, independent of any concrete
//! primitive:
//!
//! - **Alg 3** ([`kem::HybridKem`]) — composite-hybrid KEM: both halves
//!   encapsulate, decapsulation is a conjunction (⊥ if either half fails),
//!   and the session key is a domain-separated dual-PRF extraction over
//!   both component secrets ([`kdf`]).
//! - **Alg 4** ([`sig::HybridSig`]) — composite-hybrid signature:
//!   verification accepts iff the classical half **and** the pq half both
//!   verify the same message (the G3 conjunction behind the G4
//!   weakest-link theorem).
//! - **Fixed-length encodings** ([`encoding`]) — hybrid values are
//!   concatenations sliced only at the components' published lengths.
//! - **The executable formal model** ([`model`]) — idealized random-oracle
//!   KEM/signature with adjustable break flags, in which the spec's
//!   reductions run as tests (`tests/model_games.rs`). The Go reference
//!   model under `model/` is the original; this ports it so the Rust stack
//!   proves its own composite layer against the same games.
//!
//! The component traits ([`traits::Kem`], [`traits::Sig`]) are what
//! `hybrid-primitives` implements with real ML-KEM-768 / ML-DSA-87 /
//! X25519 / ECDSA P-256.

pub mod encoding;
pub mod error;
pub mod kdf;
pub mod kem;
pub mod model;
pub mod sig;
pub mod traits;

pub use error::{Error, Result};
pub use kdf::{DEFAULT_INFO, DEFAULT_SALT, extract_key, extract_key_default};
pub use kem::HybridKem;
pub use sig::HybridSig;
pub use traits::{Kem, Sig};
