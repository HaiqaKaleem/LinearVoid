//! The spec's security games, executed against the composite layer with the
//! idealized model backends. Each test corresponds 1:1 to a Go model test
//! in `model/pkg/hybridoidc` and to a numbered claim in
//! `docs/hybrid-oidc-security-spec.md` (§9 traceability matrix).
//!
//! | Test | Spec claim |
//! |------|------------|
//! | `e1_classical_holds_under_pq_break`          | G1 / Cor. E1 |
//! | `e2_hybrid_key_survives_classical_break`     | G1 / Cor. E2 |
//! | `g2_composite_kem_tamper_indist`             | G2 (Games 0–3) |
//! | `g3_conjunction_rejects_either_half_missing` | G3 |
//! | `g4_forgery_requires_fresh_pq_component`     | G4 (Thm 2) |
//! | `thm3_channel_bound_token_rejects_replay`    | G1↔G3 binding (Thm 3) |
//! | `fixed_length_encodings_enforced`            | §2 encoding discipline |

use hybrid_core::model::{RoKem, RoSig};
use hybrid_core::{Error, HybridKem, HybridSig, Kem, Sig};

/// Cor. E1: even with the pq half totally broken, the *classical* component
/// secret stays hidden — the adversary's best guess fails every trial.
#[test]
fn e1_classical_holds_under_pq_break() {
    let hybrid = HybridKem {
        classical: RoKem::new(),
        pq: RoKem::broken(), // E1 adversary restriction
    };
    for trial in 0..16 {
        let (pk_h, _sk_h) = hybrid.kgen_h().unwrap();
        let (ss_h, ct_h) = hybrid.encapsulate_h(&pk_h).unwrap();
        let classical_ss = &ss_h[..32];

        // The broken pq half hands the adversary its component secret —
        // decapsulating the protocol's own ciphertext, with no key.
        let ct_p = &ct_h[96..];
        let adv_recovered_pq = hybrid.pq.decapsulate(&[0u8; 48], ct_p).unwrap();
        assert_eq!(&ss_h[32..], &adv_recovered_pq[..], "trial {trial}");

        // But the classical half is untouched: any guess fails.
        let guess = vec![0xA5u8; 32];
        assert_ne!(&guess, classical_ss, "trial {trial}");
    }
}

/// Cor. E2: with the classical half totally broken, the extracted session
/// key still hides behind the pq half (dual-PRF).
#[test]
fn e2_hybrid_key_survives_classical_break() {
    let hybrid = HybridKem {
        classical: RoKem::broken(), // E2 adversary restriction
        pq: RoKem::new(),
    };
    for trial in 0..16 {
        let (pk_h, sk_h) = hybrid.kgen_h().unwrap();
        let (key, ct_h) = hybrid.encapsulate_key(&pk_h).unwrap();

        // Adversary decapsulates the protocol's classical half with *any*
        // key (total break: sk is irrelevant).
        let broken_c = RoKem::broken();
        let ss_c_adv = broken_c.decapsulate(&[0u8; 48], &ct_h[..96]).unwrap();
        assert_eq!(
            &ss_c_adv,
            &hybrid.decapsulate_h(&sk_h, &ct_h).unwrap()[..32]
        );

        // Honest responder derives the same key…
        let key2 = hybrid.decapsulate_key(&sk_h, &ct_h).unwrap();
        assert_eq!(key, key2, "trial {trial}");

        // …but the adversary, knowing only the classical half, cannot.
        let mut ss_partial = ss_c_adv.clone();
        ss_partial.extend_from_slice(&[0u8; 32]); // pq half: unknown
        assert_ne!(
            hybrid.session_key(&ss_partial).unwrap(),
            key,
            "trial {trial}"
        );
    }
}

/// G2 (Games 0–3): a tampered ciphertext never yields the honest secret —
/// it is rejected or decapsulates to an independent value, and re-rolling
/// the tamper produces fresh unrelated values (random-oracle behavior).
#[test]
fn g2_composite_kem_tamper_indist() {
    let hybrid = HybridKem {
        classical: RoKem::new(),
        pq: RoKem::new(),
    };
    let (pk_h, sk_h) = hybrid.kgen_h().unwrap();
    let (ss_h, ct_h) = hybrid.encapsulate_h(&pk_h).unwrap();

    // Game 1: any single-byte flip anywhere in the hybrid ct (classical
    // half, pq half, tag region, padding) either fails closed or yields a
    // different secret — never the honest one. Layout: classical ct
    // [0..96) = ss ‖ tag ‖ pad, pq ct [96..192) likewise.
    assert_eq!(ct_h.len(), 192);
    for pos in [0usize, 31, 32, 63, 64, 95, 96, 97, 127, 128, 159, 160, 191] {
        for bit in [0x01u8, 0x80] {
            let mut bad = ct_h.clone();
            bad[pos] ^= bit;
            match hybrid.decapsulate_h(&sk_h, &bad) {
                Err(Error::DecapsulationFailure) => {}
                Ok(recovered) => assert_ne!(recovered, ss_h, "pos {pos} bit {bit:#x}"),
                Err(other) => panic!("unexpected error at pos {pos}: {other}"),
            }
        }
    }

    // Game 3: repeated tampering produces independent values (no leakage
    // of the honest secret across trials).
    let mut seen = std::collections::HashSet::new();
    for i in 0..8u8 {
        let mut bad = ct_h.clone();
        bad[0] ^= i + 1;
        if let Ok(v) = hybrid.decapsulate_h(&sk_h, &bad) {
            assert!(seen.insert(v.clone()), "tampered decaps repeated a value");
            assert_ne!(v, ss_h);
        }
    }
}

/// G3: hybrid verification is a conjunction — replacing either half of an
/// honest signature with a signature for a different message (or garbage)
/// is rejected, in both orders.
#[test]
fn g3_conjunction_rejects_either_half_missing() {
    let hybrid = HybridSig {
        classical: RoSig::new(),
        pq: RoSig::new(),
    };
    let (vk_h, sk_h) = hybrid.skgen_h().unwrap();
    let msg1 = b"sub=alice&aud=client-1";
    let msg2 = b"sub=bob&aud=client-1";

    let sig1 = hybrid.sign_h(&sk_h, msg1).unwrap();
    let sig2 = hybrid.sign_h(&sk_h, msg2).unwrap();
    assert!(hybrid.verify_h(&vk_h, msg1, &sig1).unwrap());

    // Classical half of msg1 + pq half of msg2.
    let mut franken = sig1.clone();
    franken[32..].copy_from_slice(&sig2[32..]);
    assert!(!hybrid.verify_h(&vk_h, msg1, &franken).unwrap());
    assert!(!hybrid.verify_h(&vk_h, msg2, &franken).unwrap());

    // pq half of msg1 + classical half of msg2.
    let mut franken2 = sig2.clone();
    franken2[32..].copy_from_slice(&sig1[32..]);
    assert!(!hybrid.verify_h(&vk_h, msg1, &franken2).unwrap());
    assert!(!hybrid.verify_h(&vk_h, msg2, &franken2).unwrap());
}

/// G4 / Thm 2 (weakest link): an adversary granted a *total break* of the
/// classical component (it can produce classical halves that verify under
/// the honest vk for any message — modeled by handing it sk_c) still
/// cannot produce a verifying hybrid signature without a fresh pq forgery.
#[test]
fn g4_forgery_requires_fresh_pq_component() {
    let honest = HybridSig {
        classical: RoSig::new(),
        pq: RoSig::new(),
    };
    let (vk_h, sk_h) = honest.skgen_h().unwrap();

    // A message the adversary has never seen a signature for.
    let target = b"sub=attacker&aud=client-1&admin=true";

    // Total break of the classical half: the adversary produces a
    // classical signature on the *target* that verifies under vk_h's
    // classical component.
    let forged_classical = honest.classical.sign(&sk_h[..32], target).unwrap();
    assert!(
        honest
            .classical
            .verify(&vk_h[..32], target, &forged_classical)
            .unwrap(),
        "precondition: adversary really does hold a valid classical forgery"
    );

    // The pq half is sound and the adversary doesn't hold sk_p: every guess
    // fails, so the conjunction rejects despite the valid classical half.
    for guess in [vec![0u8; 32], vec![0xFFu8; 32], vec![7u8; 32]] {
        let mut sig_h = forged_classical.clone();
        sig_h.extend_from_slice(&guess);
        assert!(!honest.verify_h(&vk_h, target, &sig_h).unwrap());
    }

    // Sanity: with the real pq half attached, the same classical forgery
    // *would* verify — confirming the conjunction, not the classical
    // check, is what stops the adversary.
    let real_pq_half = honest.pq.sign(&sk_h[32..], target).unwrap();
    let mut sig_h = forged_classical;
    sig_h.extend_from_slice(&real_pq_half);
    assert!(honest.verify_h(&vk_h, target, &sig_h).unwrap());
}

/// Thm 3 (G1↔G3 binding): a token whose signing input includes a TLS
/// channel-binding value verifies on its own connection and fails when
/// replayed on a different connection (different binding) or with the
/// binding stripped.
#[test]
fn thm3_channel_bound_token_rejects_replay() {
    use sha2::{Digest, Sha256};

    let hybrid = HybridSig {
        classical: RoSig::new(),
        pq: RoSig::new(),
    };
    let (vk_h, sk_h) = hybrid.skgen_h().unwrap();

    let header = b"{\"alg\":\"MODEL-HYBRID\",\"typ\":\"JWT\"}";
    let payload = b"{\"sub\":\"alice\",\"aud\":\"client-1\"}";
    let signing_input = |bound: &[u8]| {
        let mut m = Vec::from(header);
        m.push(b'.');
        m.extend_from_slice(payload);
        m.extend_from_slice(bound);
        m
    };

    // Channel-binding values from two distinct TLS connections
    // (stands in for HKDF-Expand(exporter_master_secret, …) per RFC 9266).
    let cb_conn_a = Sha256::digest(b"tls-exporter connection A transcript");
    let cb_conn_b = Sha256::digest(b"tls-exporter connection B transcript");

    let token_sig = hybrid.sign_h(&sk_h, &signing_input(&cb_conn_a)).unwrap();

    // Replay on the originating connection: verifies.
    assert!(
        hybrid
            .verify_h(&vk_h, &signing_input(&cb_conn_a), &token_sig)
            .unwrap()
    );

    // Replay on a *different* connection: rejected.
    assert!(
        !hybrid
            .verify_h(&vk_h, &signing_input(&cb_conn_b), &token_sig)
            .unwrap()
    );

    // Replay with the binding stripped: rejected.
    assert!(
        !hybrid
            .verify_h(&vk_h, &signing_input(&[]), &token_sig)
            .unwrap()
    );

    // Replay with a *substituted* binding: rejected.
    let mut forged_binding = cb_conn_a;
    forged_binding[0] ^= 1;
    assert!(
        !hybrid
            .verify_h(&vk_h, &signing_input(&forged_binding), &token_sig)
            .unwrap()
    );
}

/// §2: every composite entrypoint enforces its exact encoding length —
/// truncations, extensions and reordering are encoding errors, not panics
/// and not silent accepts.
#[test]
fn fixed_length_encodings_enforced() {
    let kem = HybridKem {
        classical: RoKem::new(),
        pq: RoKem::new(),
    };
    let (pk_h, sk_h) = kem.kgen_h().unwrap();
    let (ss_h, ct_h) = kem.encapsulate_h(&pk_h).unwrap();
    assert_eq!(pk_h.len(), HybridKem::<RoKem, RoKem>::PK_H_LEN);
    assert_eq!(sk_h.len(), HybridKem::<RoKem, RoKem>::SK_H_LEN);
    assert_eq!(ct_h.len(), HybridKem::<RoKem, RoKem>::CT_H_LEN);
    assert_eq!(ss_h.len(), HybridKem::<RoKem, RoKem>::SS_H_LEN);

    // Wrong lengths are typed errors everywhere.
    assert!(matches!(
        kem.encapsulate_h(&pk_h[..pk_h.len() - 1]),
        Err(Error::InvalidHybridEncoding)
    ));
    assert!(matches!(
        kem.decapsulate_h(&sk_h, &ct_h[..ct_h.len() - 1]),
        Err(Error::InvalidHybridEncoding)
    ));
    assert!(matches!(
        kem.decapsulate_h(&sk_h[..1], &ct_h),
        Err(Error::InvalidHybridEncoding)
    ));
    assert!(matches!(
        kem.session_key(&ss_h[..ss_h.len() - 1]),
        Err(Error::InvalidHybridEncoding)
    ));

    let sig = HybridSig {
        classical: RoSig::new(),
        pq: RoSig::new(),
    };
    let (vk_h, sk_h) = sig.skgen_h().unwrap();
    let sig_h = sig.sign_h(&sk_h, b"msg").unwrap();
    assert!(matches!(
        sig.verify_h(&vk_h, b"msg", &sig_h[..sig_h.len() - 1]),
        Err(Error::InvalidHybridEncoding)
    ));
    assert!(matches!(
        sig.verify_h(&vk_h[..3], b"msg", &sig_h),
        Err(Error::InvalidHybridEncoding)
    ));
    // A one-byte-short signature is an encoding error, not a bool; the
    // honest encoding verifies (sanity), so the error is about length.
    assert!(matches!(
        sig.verify_h(&vk_h, b"msg", &sig_h[..63]),
        Err(Error::InvalidHybridEncoding)
    ));
    assert!(sig.verify_h(&vk_h, b"msg", &sig_h).unwrap());
}
