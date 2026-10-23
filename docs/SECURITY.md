# Security considerations

## Post-quantum readiness

This crate implements composite-hybrid cryptography combining classical and
post-quantum algorithms. The security guarantee is that the hybrid scheme
is at least as strong as the strongest component:

- If the classical component (X25519, ECDSA-P256) is broken by a quantum
  computer, the post-quantum component (ML-KEM-768, ML-DSA-87) still
  protects the scheme.
- If the post-quantum component has unknown weaknesses, the classical
  component still protects the scheme.

## Algorithm choices

| Component | Algorithm | Standard | Security claim |
|-----------|-----------|----------|----------------|
| Classical KEM | X25519 (DH-KEM) | RFC 7748 | ~128-bit (classical) |
| PQ KEM | ML-KEM-768 | FIPS 203 | NIST Level 1 (post-quantum) |
| Classical sig | ECDSA P-256 (ES256) | FIPS 186-5, RFC 7518 | ~128-bit (classical) |
| PQ sig | ML-DSA-87 | FIPS 204 | NIST Level 1 (post-quantum) |

## Threat model

The formal model in `hybrid-core` assumes the random-oracle model for the
idealized components. When swapping in real primitives (ECDH, ECDSA, ML-KEM,
ML-DSA), the security reduction holds assuming:

1. The underlying primitives are secure in the standard model (or ROM where
   applicable)
2. The HKDF extractor (dual-PRF) behaves like a random function
3. The fixed-length encodings prevent malleability attacks at component
   boundaries

## Channel binding

The JWT implementation supports TLS channel binding via RFC 9266. When
channel binding is used:

- The token is bound to a specific TLS connection
- Replaying the token on a different TLS connection fails verification
- This closes the bearer-token replay gap between the transport layer and
  token claims

**Important**: Channel binding requires access to the TLS exporter master
secret, which is only available from within the TLS stack. Applications must
pass the correct exporter secret, label, and context to the signing/verification
functions.

## Fixed-length encodings

All composite encodings enforce strict fixed-length boundaries. This:

- Prevents component confusion attacks
- Ensures the dual-PRF extractor argument applies correctly
- Catches malformed inputs before any cryptographic operation

## Known limitations

1. **No side-channel mitigation**: The implementation is not protected against
   timing or other side-channel attacks. Constant-time guarantees are only
   provided where explicitly noted (e.g., the `subtle` crate for comparisons).

2. **Randomness**: Key generation uses the OS CSPRNG via `getrandom`. No
   deterministic key derivation is provided by default (use the seed-based
   constructors for reproducible testing only).

3. **No attestation**: The crate doesn't verify certificates or provide any
   identity binding beyond the raw cryptographic operations.

4. **JWT claims**: The implementation doesn't validate standard JWT claims
   like `exp`, `iat`, `nbf` automatically. Applications must validate these
   claims themselves.

## Auditing

The formal model in `hybrid-core/tests/model_games.rs` provides executable
tests that mirror the security games. These tests can be run as part of CI
to catch regressions in the security properties.