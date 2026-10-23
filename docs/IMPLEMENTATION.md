# Implementation mapping

This document maps the security model claims (G1–G4, Theorems 1–3,
Corollaries E1–E2) from `hybrid-oidc-security-spec.md` to the Rust
implementation in this crate.

## G1 / Cor. E1: Classical half holds under pq break

**Claim**: If the pq KEM half is broken, the hybrid shared secret remains
unpredictable because the classical half still holds.

**Implementation**: `hybrid-core/src/model.rs`:
- `TestE1ClassicalHoldsUnderPQBreak` in `model_games.rs`
- Uses `HybridKEM{Classical: &roKEM{}, PQ: &roKEM{broken: true}}`
- Verifies that a second encapsulation produces a different classical block,
  proving the pq break alone can't predict the classical block

## G1 / Cor. E2: Hybrid key survives classical break

**Claim**: If the classical KEM half is broken (e.g., Shor on ECDH),
the pq block alone is uniform and the hybrid secret is protected.

**Implementation**: `hybrid-core/tests/model_games.rs`:
- `TestE2HybridKeySurvivesClassicalBreak`
- Uses `HybridKEM{Classical: &roKEM{broken: true}, PQ: &roKEM{}}`
- Verifies that a second encapsulation produces a different pq block

## G2: Composite KEM tamper indistinguishability

**Claim**: Tampering with either component ciphertext causes decapsulation
failure (the conjunction property).

**Implementation**: `hybrid-core/tests/model_games.rs`:
- `TestCompositeKEMTamperIndist`
- Flips one byte in classical half → decapsulation fails
- Flips one byte in pq half → decapsulation fails
- Verifies honest decapsulation succeeds

## G3: Hybrid signature conjunction

**Claim**: Verification requires BOTH halves valid on the same message.

**Implementation**: `hybrid-core/src/sig.rs`:
- `verify_h` returns `ok_c & ok_p` (bitwise AND, deliberately non-short-circuiting)

**Tests**: `hybrid-core/tests/model_games.rs`:
- `TestHybridVerifyRejectsEitherHalfMissing`
- Breaks classical half → reject
- Breaks pq half → reject
- Wrong message → reject

## G4: Signature forgery requires fresh ECDSA

**Claim**: Even with pq half fully broken (accepts anything), forging on a
NEW message still requires a fresh classical (ECDSA-model) forgery.

**Implementation**: `hybrid-core/tests/model_games.rs`:
- `TestSignatureForgeryRequiresFreshECDSA`
- pq half broken, tries to forge on fresh message with classical half from a
  different signed message → reject

## G1 <-> G3 binding: Channel-bound JWT rejects replay

**Claim**: A JWT whose signed input includes a TLS channel-binding value
must fail verification when replayed with a different binding.

**Implementation**: `hybrid-jwt/src/lib.rs`:
- `sign_jwt2` signs `header || "." || payload || bound`
- `verify_jwt` with `bound: Some(b)` verifies against `header || "." || payload || b`
- If the bound doesn't match the expected derived value → `ChannelBindingMismatch`

**Tests**: `hybrid-jwt/src/lib.rs`:
- `TestChannelBoundJWTRejectsReplay` in `model_games.rs`
- Signs with binding derived from `exporter-secret-conn-1`
- Verifies on same connection → OK
- Verifies with binding from different exporter → reject

## Theorem 1: Hybrid KEM security

**Claim**: The hybrid KEM is secure as long as at least one component is
secure (dual-PRF extractor argument).

**Implementation**: The conjunction property in `Kem::encapsulate_h` and
`Kem::decapsulate_h` enforces that both halves must work. The fixed-length
encoding ensures the dual-PRF extractor argument applies.

## Theorem 2: Hybrid signature security

**Claim**: The hybrid signature is secure as long as at least one component
is secure.

**Implementation**: The conjunction property in `Sig::verify_h` ensures both
halves must verify. Even if one half is broken, the other half's security
property protects the scheme.

## Theorem 3: Channel binding closes bearer-token gap

**Claim**: Channel-bound tokens can't be replayed on different TLS connections.

**Implementation**: `hybrid-jwt::channel_binding` derives a binding value
from the TLS exporter secret using HMAC-SHA256. The binding is included in
the signed JWT payload, so a token signed on one connection can't be verified
on another (the channel binding derivation will differ).