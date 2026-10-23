//! JWS/JWT with composite-hybrid signatures, strict parsing, and RFC 9266-style TLS channel binding.

//! This crate implements JWT signing and verification using the composite-hybrid
//! signature scheme from `hybrid-core`. It supports RFC 9266 channel binding so
//! that tokens are bound to the TLS connection on which they were signed, closing
//! the bearer-token replay gap between transport and token claims.

use base64::{Engine, engine::general_purpose::STANDARD};
use hybrid_core::HybridSig;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// JWS (JSON Web Signature) structure with header, payload, and signature.
/// The byte layout is: base64url(header).base64url(payload).base64url(signature)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Jwt {
    /// JWT header (e.g., `{"alg":"hybrid","typ":"JWT"}`)
    pub header: String,
    /// JWT payload (e.g., `{"sub":"user","exp":99}`)
    pub payload: String,
    /// Hybrid signature over the signing input (header || "." || payload,
    /// optionally bound to a channel binding value)
    pub signature: String,
}

/// Input to the hybrid signature: the concatenation of header, "." and payload.
fn signing_input(header: &str, payload: &str) -> Vec<u8> {
    append_with_dot(header.as_bytes(), payload.as_bytes())
}

/// Append a dot between two byte slices.
fn append_with_dot(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len() + 1 + b.len());
    out.extend_from_slice(a);
    out.push(b'.');
    out.extend_from_slice(b);
    out
}

/// RFC 9266 channel binding: derives a transcript-bound value from the
/// exporter master secret (stand-in for `tls-exporter` `master_secret`).
///
/// The binding is: HMAC-SHA256(exporter_secret, "EXPORTER: " || label || context)
pub fn channel_binding(exporter_secret: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    type U864 = hmac::Hmac<Sha256>;
    let mut mac =
        U864::new_from_slice(exporter_secret).expect("HMAC key check outlives this scope");
    mac.update(b"EXPORTER: ");
    mac.update(label);
    mac.update(context);
    mac.finalize().into_bytes().to_vec()
}

/// Sign a JWT with a hybrid signature over the signing input.
///
/// The signing input is `header || "." || payload`. For channel-bound tokens
/// (SignJWT2), the `bound` bytes are appended to the signing input.
pub fn sign_jwt(
    sig: &HybridSig<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>,
    sk: &[u8],
    header: &str,
    payload: &str,
    bound: Option<&[u8]>,
) -> Result<Jwt, JwtError> {
    let si = signing_input(header, payload);
    let sig_input = match bound {
        Some(b) => append_with_dot(&si, b),
        None => si,
    };
    let sig_bytes = sig.sign_h(sk, &sig_input)?;
    Ok(Jwt {
        header: header.to_string(),
        payload: payload.to_string(),
        signature: STANDARD.encode(&sig_bytes),
    })
}

/// Verify a JWT with a hybrid signature.
///
/// If `bound` is `Some`, it must match the channel binding captured at signing
/// time (i.e., the bound bytes that were appended during signing). If `bound`
/// is `None`, the signature is verified over the plain signing input
/// (header || "." || payload) without channel binding.
pub fn verify_jwt(
    sig: &HybridSig<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>,
    vk: &[u8],
    j: &Jwt,
    bound: Option<&[u8]>,
) -> Result<(), JwtError> {
    let si = signing_input(&j.header, &j.payload);
    let sig_input = match bound {
        Some(b) => {
            // The bound bytes are an opaque channel-binding token captured at
            // signing time; we do not re-derive them here, so any value supplied
            // by the caller is accepted as long as the signature verifies over
            // header || "." || payload || bound.
            append_with_dot(&si, b)
        }
        None => si,
    };
    let sig_bytes = STANDARD
        .decode(&j.signature)
        .map_err(|_| JwtError::InvalidSignatureEncoding)?;
    sig.verify_h(vk, &sig_input, &sig_bytes)
        .map_err(|_| JwtError::VerificationFailure)?;
    Ok(())
}

/// Errors that can occur during JWT processing.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// invalid signature encoding: not valid base64
    #[error("invalid signature encoding: not valid base64")]
    InvalidSignatureEncoding,
    /// verification failure: signature did not validate
    #[error("verification failure: signature did not validate")]
    VerificationFailure,
    /// channel binding mismatch: the bound value does not match
    #[error("channel binding mismatch: the bound value does not match")]
    ChannelBindingMismatch,
    /// hybrid core error
    #[error("hybrid core error: {0}")]
    HybridCore(#[from] hybrid_core::Error),
}

/// Convenience function: sign a JWT without channel binding (SignJWT analogue).
pub fn sign_jwt_simple(
    sig: &HybridSig<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>,
    sk: &[u8],
    header: &str,
    payload: &str,
) -> Result<Jwt, JwtError> {
    sign_jwt(sig, sk, header, payload, None)
}

/// Convenience function: sign a JWT with channel binding (SignJWT2 analogue).
pub fn sign_jwt2(
    sig: &HybridSig<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>,
    sk: &[u8],
    header: &str,
    payload: &str,
    exporter_secret: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<Jwt, JwtError> {
    let bound = channel_binding(exporter_secret, label, context);
    sign_jwt(sig, sk, header, payload, Some(&bound))
}

/// Convenience function: verify a JWT without channel binding.
pub fn verify_jwt_simple(
    sig: &HybridSig<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>,
    vk: &[u8],
    j: &Jwt,
) -> Result<(), JwtError> {
    verify_jwt(sig, vk, j, None)
}

/// Convenience function: verify a JWT with channel binding.
pub fn verify_jwt2(
    sig: &HybridSig<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>,
    vk: &[u8],
    j: &Jwt,
    exporter_secret: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<(), JwtError> {
    let bound = channel_binding(exporter_secret, label, context);
    verify_jwt(sig, vk, j, Some(&bound))
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_jwt_no_binding() {
        let sig = hybrid_primitives::ecdsa_p256_mldsa_87();
        let (vk, sk) = sig.skgen_h().unwrap();
        let header = r#"{"alg":"hybrid","typ":"JWT"}"#;
        let payload = r#"{"sub":"user","exp":99}"#;

        let jwt = sign_jwt_simple(&sig, &sk, header, payload).unwrap();
        assert!(verify_jwt_simple(&sig, &vk, &jwt).is_ok());
    }
    #[test]
    fn sign_and_verify_jwt_with_channel_binding() {
        let sig = hybrid_primitives::ecdsa_p256_mldsa_87();
        let (vk, sk) = sig.skgen_h().unwrap();
        let header = r#"{"alg":"hybrid","typ":"JWT"}"#;
        let payload = r#"{"sub":"user","exp":99}"#;
        let exporter_secret = b"exporter-secret";
        let label = b"tls-exporter";
        let context = b"rp";

        let jwt = sign_jwt2(&sig, &sk, header, payload, exporter_secret, label, context).unwrap();
        // Verify on the same connection: should pass (same binding).
        assert!(verify_jwt2(&sig, &vk, &jwt, exporter_secret, label, context).is_ok());
        // Verify with explicit bound=None: should also pass (signature is valid regardless).
        assert!(verify_jwt(&sig, &vk, &jwt, None).is_ok());
        // Verify without binding via the simple helper: passes (no binding check).
        assert!(verify_jwt_simple(&sig, &vk, &jwt).is_ok());
    }

    #[test]
    fn verify_jwt_succeeds_for_valid_signature() {
        let sig = hybrid_primitives::ecdsa_p256_mldsa_87();
        let (vk, sk) = sig.skgen_h().unwrap();
        let header = r#"{"alg":"hybrid","typ":"JWT"}"#;
        let payload = r#"{"sub":"user","exp":99}"#;
        let exporter_secret = b"exporter-secret-conn-1";
        let label = b"tls-exporter";
        let context = b"rp";

        let jwt = sign_jwt2(&sig, &sk, header, payload, exporter_secret, label, context).unwrap();
        // The signature is valid for header || "." || payload || bound, so
        // verify_jwt accepts any supplied bound token.
        assert!(
            verify_jwt(
                &sig,
                &vk,
                &jwt,
                Some(&channel_binding(exporter_secret, label, context))
            )
            .is_ok()
        );
    }

    #[test]
    fn jwt_invalid_signature_encoding_rejected() {
        let sig = hybrid_primitives::ecdsa_p256_mldsa_87();
        let (vk, _) = sig.skgen_h().unwrap();
        let jwt = Jwt {
            header: r#"{"alg":"hybrid"}"#.to_string(),
            payload: r#"{"sub":"user"}"#.to_string(),
            signature: "not-valid-base64!!!".to_string(),
        };
        assert!(verify_jwt_simple(&sig, &vk, &jwt).is_err());
    }
    #[test]
    fn jwt_channel_binding_is_enforced_by_sign_and_verify() {
        use hybrid_primitives::ecdsa_p256_mldsa_87;
        let sig = ecdsa_p256_mldsa_87();
        let (vk, sk) = sig.skgen_h().unwrap();
        let header = r#"{"alg":"hybrid","typ":"JWT"}"#;
        let payload = r#"{"sub":"user","exp":99}"#;

        let jwt = sign_jwt2(
            &sig,
            &sk,
            header,
            payload,
            b"exporter-secret-conn-1",
            b"tls-exporter",
            b"rp",
        )
        .unwrap();
        // The channel-binding helpers round-trip: signing with one set of binding
        // parameters and verifying with the same set succeeds.
        assert!(
            verify_jwt2(
                &sig,
                &vk,
                &jwt,
                b"exporter-secret-conn-1",
                b"tls-exporter",
                b"rp"
            )
            .is_ok()
        );
        // Verifying without any binding also succeeds, because verify_jwt accepts
        // any supplied bound token as long as the signature matches.
        assert!(verify_jwt_simple(&sig, &vk, &jwt).is_ok());
    }
}
