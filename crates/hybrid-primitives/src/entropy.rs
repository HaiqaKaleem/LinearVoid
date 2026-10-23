//! OS entropy helper.
//!
//! All backends take their randomness here — raw bytes from the OS CSPRNG —
//! and feed it to the primitives through *seed/bytes* constructors. This is
//! deliberate: `ml-kem`/`ml-dsa` speak `rand_core` 0.10 while
//! `x25519-dalek`/`p256` speak `rand_core` 0.6, and threading two RNG
//! trait generations through one API is exactly the kind of accidental
//! complexity that produces unsafe defaults. Seed-based APIs also make the
//! KAT vectors in `vectors/` reproducible.

/// Fill a vector with `len` bytes from the OS CSPRNG.
pub fn rand_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    getrandom::fill(&mut out).expect("OS RNG unavailable");
    out
}

/// 32 random bytes.
pub fn rand32() -> [u8; 32] {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).expect("OS RNG unavailable");
    out
}

/// 64 random bytes.
pub fn rand64() -> [u8; 64] {
    let mut out = [0u8; 64];
    getrandom::fill(&mut out).expect("OS RNG unavailable");
    out
}
