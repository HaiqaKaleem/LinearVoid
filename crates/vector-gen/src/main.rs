use hex::encode;
use hybrid_oidc::{build_jwks, discovery};
use hybrid_primitives::{ecdsa_p256_mldsa_87, sizes};
use hybrid_primitives::x25519_ml_kem_768;

fn main() {
    println!("=== hybrid-oidc Known-Answer-Test (KAT) Vectors ===\n");

    println!("Using deterministic default constructors for KAT vectors");

    // --- KEM ---

    let kem = x25519_ml_kem_768();

    println!("\n--- Alg 3: Hybrid KEM (X25519 || ML-KEM-768) ---");
    println!("pk length: {} bytes", sizes::HYBRID_KEM_PK);
    println!("sk length: {} bytes", sizes::HYBRID_KEM_SK);
    println!("ct length: {} bytes", sizes::HYBRID_KEM_CT);
    println!("ss length: {} bytes", sizes::HYBRID_KEM_SS);

    // Use the default keygen (seeded internally for determinism via hash)
    let (pk, sk) = kem.kgen_h().unwrap();
    println!("\n[KeyGen]");
    println!("pk: {}", encode(&pk));
    println!("sk: {}", encode(&sk));

    let (ss, ct) = kem.encapsulate_h(&pk).unwrap();
    println!("\n[Encapsulate]");
    println!("ss: {}", encode(&ss));
    println!("ct: {}", encode(&ct));

    let ss2 = kem.decapsulate_h(&sk, &ct).unwrap();
    println!("\n[Decapsulate]");
    println!("ss (recovered): {}", encode(&ss2));
    println!("ss match: {}", ss == ss2);

    // --- Signature ---

    let sig = ecdsa_p256_mldsa_87();
    let msg = b"Hello, hybrid-oidc!";
    println!("\n--- Alg 4: Hybrid Signature (ECDSA-P256 || ML-DSA-87) ---");
    println!("vk length: {} bytes", sizes::HYBRID_SIG_VK);
    println!("sk length: {} bytes", sizes::HYBRID_SIG_SK);
    println!("sig length: {} bytes", sizes::HYBRID_SIG);

    let (vk, sk) = sig.skgen_h().unwrap();
    println!("\n[KeyGen]");
    println!("vk: {}", encode(&vk));
    println!("sk: {}", encode(&sk));

    let sig_bytes = sig.sign_h(&sk, msg).unwrap();
    println!("\n[Sign]");
    println!("message: \"{}\"", String::from_utf8_lossy(msg));
    println!("signature: {}", encode(&sig_bytes));

    let valid = sig.verify_h(&vk, msg, &sig_bytes).unwrap();
    println!("\n[Verify]");
    println!("valid: {}", valid);

    let msg2 = b"A different message.";
    let valid2 = sig.verify_h(&vk, msg2, &sig_bytes).unwrap();
    println!("verify wrong msg: {}", valid2);

    // --- JWKS ---

    let jwks = build_jwks(&sig, &vk).unwrap();
    println!("\n--- JWKS ---");
    println!("{}", serde_json::to_string_pretty(&jwks).unwrap());

    // --- Discovery ---

    let disc = discovery(
        "https://demo.hybrid-oidc.local",
        "https://demo.hybrid-oidc.local/.well-known/jwks.json",
    );
    println!("\n--- Discovery Document ---");
    println!("{}", serde_json::to_string_pretty(&disc).unwrap());

    println!("\n=== End of KAT Vectors ===");
}
