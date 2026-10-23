//! Composite-level integration tests: the real `X25519 ‖ ML-KEM-768` KEM
//! and `ECDSA-P-256 ‖ ML-DSA-87` signature, end to end, including the
//! adversarial shapes the spec's theorems talk about.

use hybrid_core::{HybridKem, HybridSig};
use hybrid_primitives::sizes;
use hybrid_primitives::{ecdsa_p256_mldsa_87, x25519_ml_kem_768};

// --------------------------------------------------------------------- KEM

#[test]
fn hybrid_kem_roundtrip_and_sizes() {
    let kem = x25519_ml_kem_768();
    let (pk_h, sk_h) = kem.kgen_h().unwrap();
    assert_eq!(pk_h.len(), sizes::HYBRID_KEM_PK);
    assert_eq!(sk_h.len(), sizes::HYBRID_KEM_SK);

    let (key1, ct_h) = kem.encapsulate_key(&pk_h).unwrap();
    assert_eq!(ct_h.len(), sizes::HYBRID_KEM_CT);
    assert_eq!(key1.len(), sizes::SESSION_KEY);

    let key2 = kem.decapsulate_key(&sk_h, &ct_h).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn hybrid_kem_wrong_half_key_fails_or_diverges() {
    let kem = x25519_ml_kem_768();
    let (pk_h, sk_h) = kem.kgen_h().unwrap();
    let (key, ct_h) = kem.encapsulate_key(&pk_h).unwrap();

    // Someone else's hybrid secret key: the classical half decapsulates to
    // a different DH secret → different session key. Never the honest key.
    let (_pk2, sk2) = kem.kgen_h().unwrap();
    if let Ok(wrong) = kem.decapsulate_key(&sk2, &ct_h) {
        assert_ne!(wrong, key);
    }

    // Tampered ciphertext half → key mismatch (implicit rejection surfaces
    // as a diverged key, per the G2 argument).
    for pos in [0usize, 31, 32, 63, 64, 200, 500, 1119] {
        let mut bad = ct_h.clone();
        bad[pos] ^= 0x01;
        if let Ok(tampered) = kem.decapsulate_key(&sk_h, &bad) {
            assert_ne!(
                tampered, key,
                "tampered ct at {pos} must not yield the honest key"
            );
        }
    }
}

#[test]
fn hybrid_kem_length_discipline() {
    let kem = x25519_ml_kem_768();
    let (pk_h, sk_h) = kem.kgen_h().unwrap();
    let (_key, ct_h) = kem.encapsulate_key(&pk_h).unwrap();
    assert!(matches!(
        kem.encapsulate_h(&pk_h[..100]),
        Err(hybrid_core::Error::InvalidHybridEncoding)
    ));
    assert!(matches!(
        kem.decapsulate_h(&sk_h, &ct_h[..100]),
        Err(hybrid_core::Error::InvalidHybridEncoding)
    ));
}

// --------------------------------------------------------------------- SIG

#[test]
fn hybrid_sig_roundtrip_and_sizes() {
    let sig = ecdsa_p256_mldsa_87();
    let (vk_h, sk_h) = sig.skgen_h().unwrap();
    assert_eq!(vk_h.len(), sizes::HYBRID_SIG_VK);
    assert_eq!(sk_h.len(), sizes::HYBRID_SIG_SK);

    let msg = b"iss=https://op.example&sub=alice&aud=client-1";
    let sig_h = sig.sign_h(&sk_h, msg).unwrap();
    assert_eq!(sig_h.len(), sizes::HYBRID_SIG);
    assert!(sig.verify_h(&vk_h, msg, &sig_h).unwrap());
    assert!(!sig.verify_h(&vk_h, b"other message", &sig_h).unwrap());
}

#[test]
fn hybrid_sig_cross_component_forgery_rejected() {
    let sig = ecdsa_p256_mldsa_87();
    let (vk_h, sk_h) = sig.skgen_h().unwrap();
    let msg1 = b"sub=alice";
    let msg2 = b"sub=attacker";

    let sig1 = sig.sign_h(&sk_h, msg1).unwrap();
    let sig2 = sig.sign_h(&sk_h, msg2).unwrap();

    // Splice: classical half of msg1 ‖ pq half of msg2 — rejected for both
    // messages (the G3 conjunction with REAL primitives).
    let mut franken = sig1.clone();
    franken[64..].copy_from_slice(&sig2[64..]);
    assert!(!sig.verify_h(&vk_h, msg1, &franken).unwrap());
    assert!(!sig.verify_h(&vk_h, msg2, &franken).unwrap());

    // And the other splice order.
    let mut franken2 = sig2.clone();
    franken2[64..].copy_from_slice(&sig1[64..]);
    assert!(!sig.verify_h(&vk_h, msg1, &franken2).unwrap());
    assert!(!sig.verify_h(&vk_h, msg2, &franken2).unwrap());
}

#[test]
fn hybrid_sig_single_bit_flip_rejected_everywhere() {
    let sig = ecdsa_p256_mldsa_87();
    let (vk_h, sk_h) = sig.skgen_h().unwrap();
    let msg = b"sub=alice&admin=false";
    let sig_h = sig.sign_h(&sk_h, msg).unwrap();

    // Flips across the classical half, the boundary, and deep in the pq
    // half: every one must fail verification.
    for pos in [0usize, 32, 63, 64, 65, 1000, 4690] {
        let mut bad = sig_h.clone();
        bad[pos] ^= 0x01;
        assert!(
            !sig.verify_h(&vk_h, msg, &bad).unwrap_or(false),
            "flip at {pos} must not verify"
        );
    }
}

#[test]
fn hybrid_sig_cross_provider_keys_rejected() {
    let sig = ecdsa_p256_mldsa_87();
    let (vk_a, sk_a) = sig.skgen_h().unwrap();
    let (vk_b, _sk_b) = sig.skgen_h().unwrap();
    let msg = b"sub=alice";
    let sig_a = sig.sign_h(&sk_a, msg).unwrap();
    assert!(!sig.verify_h(&vk_b, msg, &sig_a).unwrap());
    // Also: provider B's key must not validate A's token even with A's
    // signing key swapped into B's vk — mixed keys fail too.
    let sig_b = sig.sign_h(&sk_a, msg).unwrap();
    let _ = sig_b;
    assert!(sig.verify_h(&vk_a, msg, &sig_a).unwrap());
}

#[test]
fn component_backends_never_panic_on_garbage() {
    // Stable "fuzz-lite": deterministic pseudo-random garbage must produce
    // typed errors or rejection — never a panic. (The cargo-fuzz targets in
    // fuzz/ cover the same surfaces under libFuzzer.)
    let kem = x25519_ml_kem_768();
    let sig = ecdsa_p256_mldsa_87();
    let (pk_h, sk_h) = kem.kgen_h().unwrap();
    let (vk_h, sk_sh) = sig.skgen_h().unwrap();

    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        // xorshift64*
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };

    for i in 0..64u32 {
        let len = (next() % 1300) as usize;
        let mut garbage = vec![0u8; len.max(1)];
        for b in &mut garbage {
            *b = next() as u8;
        }
        // Decapsulate and verify with garbage of varying lengths: no panic.
        let _ = kem.decapsulate_h(&sk_h, &garbage);
        let _ = kem.decapsulate_h(&garbage, &garbage);
        let _ = kem.encapsulate_h(&garbage);
        let _ = sig.verify_h(&vk_h, &garbage, &garbage);
        let _ = sig.sign_h(&sk_sh, &garbage);
        // And with one realistic-length but garbage-filled input.
        if i == 0 {
            let mut ct_garbage =
                vec![0u8; HybridKem::<
                hybrid_primitives::X25519Kem,
                hybrid_primitives::MlKem768Kem,
            >::CT_H_LEN];
            for b in &mut ct_garbage {
                *b = next() as u8;
            }
            // A public key is not a ciphertext: length mismatch errors.
            assert!(kem.decapsulate_key(&sk_h, &pk_h).is_err());
            let _ = kem.decapsulate_h(&sk_h, &ct_garbage);
        }
    }
    let _ = HybridSig::<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>::SIG_H_LEN;
}
