# Architecture

## Overview

`hybrid-oidc` is a layered Rust implementation of the IETF composite-hybrid
KEM (Alg 3) and signature (Alg 4) schemes, with an OpenID Connect layer
on top. Every crate exposes a small, well-defined API, and the formal security
model lives in `hybrid-core`.

## Crate dependency graph

```
hybrid-core          — low-level trait definitions (Kem, Sig, HybridKem, HybridSig)
hybrid-primitives    — concrete backends (X25519, ML-KEM, ECDSA, ML-DSA) implementing the traits
hybrid-jwt           — JWT layer built on hybrid-core + hybrid-primitives
hybrid-oidc          — OIDC layer built on hybrid-jwt + hybrid-primitives
hybrid-ffi           — C ABI for hybrid-oidc
hybrid-demo          — HTTP demo server using all crates
vector-gen           — KAT vector generator
```

## Flow

### Key establishment (Alg 3)

1. `KgenH()` produces `pkH = pk_c || pk_p` and `skH = sk_c || sk_p`
2. `EncH(pkH)` produces `(ss_c || ss_p, ct_c || ct_p)`
3. `DecH(skH, ctH)` returns `ss_c || ss_p` (conjunction: both must decapsulate)
4. `ExtractKey(ssH, salt, info)` runs HKDF on the concatenated shared secret

### Signature (Alg 4)

1. `SkgH()` produces `vkH = vk_c || vk_p` and `skH = sk_c || sk_p`
2. `SignH(skH, msg)` produces `sig_c || sig_p`
3. `VerH(vkH, msg, sigH)` returns `ok_c && ok_p` (conjunction)

### JWT (hybrid-jwt)

1. `sign_jwt(sig, sk, header, payload, bound)` → `Jwt`
2. `verify_jwt(sig, vk, jwt, bound)` → `Result<(), JwtError>`
3. Channel binding: when `bound` is `Some`, it's appended to the signing input

### OIDC (hybrid-oidc)

1. `discovery(issuer, jwks_uri)` → `Discovery` document
2. `build_jwks(sig, vk)` → `HybridJwkSet`
3. `mint_id_token(sig, sk, jwks, issuer, subject, audience, exp, iat, nonce, exporter_secret, label, context)` → `IdToken`
4. `verify_id_token(sig, vk, token, expected_audience, expected_issuer, exporter_secret, label, context)` → `Result<(), OidcError>`

## Formal model

The security model is encoded as Rust tests in
`hybrid-core/src/model.rs` and `hybrid-core/tests/model_games.rs`. These
use idealized random-oracle components with "break" flags to make the
security reductions executable. The model directly mirrors the games in
`docs/hybrid-oidc-security-spec.md`.

## Fixed-length encodings

All composite encodings enforce fixed-length boundaries. The encoding sizes
are defined in `hybrid-primitives/src/lib.rs` under the `sizes` module:

| Component | Size |
|-----------|------|
| X25519 pk | 32 bytes |
| ML-KEM-768 pk | 1184 bytes |
| Hybrid KEM pk (pkH) | 1216 bytes |
| X25519 sk | 32 bytes |
| ML-KEM-768 seed | 64 bytes |
| Hybrid KEM sk (skH) | 96 bytes |
| ML-KEM-768 ct | 1088 bytes |
| Hybrid KEM ct (ctH) | 1120 bytes |
| ECDSA P-256 vk | 33 bytes (1 + 32) |
| ML-DSA-87 vk | 2592 bytes |
| Hybrid sig vk (vkH) | 2625 bytes |
| ECDSA P-256 sk | 32 bytes |
| ML-DSA-87 seed | 32 bytes |
| Hybrid sig sk (skH) | 64 bytes |
| ML-DSA-87 sig | 4627 bytes |
| Hybrid sig (sigH) | 4691 bytes |

## Why no RNG trait plumbing

`ml-kem`/`ml-dsa` use `rand_core` 0.10 while `x25519-dalek`/`p256` use
`rand_core` 0.6. Threading two different RNG trait versions through one API
is fragile. Instead, all key material is derived from raw OS entropy via
`getrandom` and fed to primitives through seed/bytes constructors. This
also makes KAT vectors reproducible.