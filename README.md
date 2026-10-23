# hybrid-oidc

A Rust implementation of composite-hybrid KEM (Alg 3) and signature (Alg 4)
from the IETF hybrid draft, with an OpenID Connect layer on top.

## Crates

| Crate | Description |
|-------|-------------|
| `hybrid-core` | Composite-hybrid KEM (Alg 3) and signature (Alg 4) construction, fixed-length encodings, dual-PRF key extraction, and the executable formal model |
| `hybrid-primitives` | Real cryptographic backends: ML-KEM-768 (FIPS 203), ML-DSA-87 (FIPS 204), X25519, ECDSA P-256 |
| `hybrid-jwt` | JWS/JWT with composite-hybrid signatures, strict parsing, and RFC 9266-style TLS channel binding |
| `hybrid-oidc` | OpenID Connect layer: ID token minting/verification, discovery document, JWKS with composite keys, explicit downgrade policy |
| `hybrid-ffi` | C ABI (cdylib + staticlib) for hybrid-oidc |
| `hybrid-demo` | HTTP demo server (OIDC discovery, hybrid JWKS, ID token mint/verify, channel-binding replay demo) |
| `vector-gen` | Deterministic known-answer-test (KAT) vector generator |

## Quick start

```bash
cargo test
cargo run -p vector-gen
```

For the demo server:

```bash
cargo run -p hybrid-demo
# Then visit http://localhost:3000/discovery
```

## Standards

- **Alg 3 (Hybrid KEM)**: X25519 ‖ ML-KEM-768 (TLS 1.3 hybrid construction)
- **Alg 4 (Hybrid Signature)**: ECDSA-P256 ‖ ML-DSA-87
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
- RFC 7748 (X25519), FIPS 186-5 / RFC 7518 (ECDSA P-256 / ES256)
- RFC 9266 (TLS channel binding)

## Security model

The crate `hybrid-core` contains an executable formal model that mirrors the
games in `docs/hybrid-oidc-security-spec.md`. Run the model tests:

```bash
cargo test -p hybrid-core --test model_games
```

These tests encode the security arguments (G1–G4, Thm 1–3) as executabe
Rust code using idealized random-oracle components with adjustable "break"
flags.

## License

MIT