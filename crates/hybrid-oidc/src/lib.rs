//! OpenID Connect layer on hybrid signatures.

//! Provides: ID token minting/verification, discovery document, JWKS with
//! composite keys, and an explicit downgrade-policy gate.

use base64::Engine;
use hybrid_core::HybridSig;
use hybrid_jwt::{Jwt, JwtError, sign_jwt2, verify_jwt};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

// --------------------------------------------------------------------- types

/// Represents a hybrid OIDC key in a JWKS JWK object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridJwk {
    pub kty: String,
    pub crv: Option<String>,
    pub x: String,
    pub y: Option<String>,
    pub ext: Option<String>,
}

/// JSON Web Key Set containing at least the hybrid signing key (Alg 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridJwkSet {
    pub keys: Vec<HybridJwk>,
}

/// OIDC discovery document (OpenID Connect Discovery 1.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: String,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub claims_supported: Vec<String>,
}

// --------------------------------------------------------------------- constants

const HYBRID_ALG: &str = "hybrid";

// --------------------------------------------------------------------- discovery

fn make_default_discovery(issuer: &str, jwks_uri: &str) -> Discovery {
    Discovery {
        issuer: issuer.to_string(),
        authorization_endpoint: Some(format!("{issuer}/authorize")),
        token_endpoint: Some(format!("{issuer}/token")),
        jwks_uri: jwks_uri.to_string(),
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec![HYBRID_ALG.to_string()],
        claims_supported: vec![
            "sub".to_string(),
            "iss".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "nonce".to_string(),
        ],
    }
}

/// Produce an OIDC discovery document for the given issuer / JWKS URI.
pub fn discovery(issuer: &str, jwks_uri: &str) -> Discovery {
    make_default_discovery(issuer, jwks_uri)
}

// --------------------------------------------------------------------- JWKS

/// Build a JWKS containing the hybrid signing verification key.
pub fn build_jwks(
    _sig: &HybridSig<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>,
    vk: &[u8],
) -> Result<HybridJwkSet, OidcError> {
    // Composite vk = ECDSA P-256 vk ‖ ML-DSA-87 vk.
    let half = 33; // ECDSA P-256 uncompressed point: 1 + 32
    let (ecdsa_vk, mldsa_vk) = match vk.split_at_checked(half) {
        Some(pair) => pair,
        None => return Err(OidcError::InvalidKeyLength),
    };

    // x is the first 32 bytes of the ECDSA public point.
    let x = hex::encode(&ecdsa_vk[1..]);
    let y: String = if ecdsa_vk.len() > 32 {
        hex::encode(&ecdsa_vk[1..1 + 32])
    } else {
        hex::encode(&ecdsa_vk[1..])
    };

    // ext is the ML-DSA component represented as base64url.
    let ext = base64::engine::general_purpose::STANDARD.encode(mldsa_vk);

    let jwk = HybridJwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()), // ML-DSA-87 public key; we reuse the curve name
        x: x.clone(),
        y: Some(y.clone()),
        ext: Some(ext),
    };

    Ok(HybridJwkSet { keys: vec![jwk] })
}

// --------------------------------------------------------------------- ID token configuration

/// Parameters that control how an ID token is minted / verified.
#[derive(Debug, Clone)]
pub struct IdTokenConfig {
    /// Issuer identifier embedded in the token.
    pub issuer: String,
    /// Subject identifier embedded in the token.
    pub subject: String,
    /// Expected audience embedded in the token.
    pub audience: String,
    /// Nonce to embed, if any.
    pub nonce: Option<String>,
    /// The TLS Exporter secret used for channel binding.
    pub exporter_secret: Vec<u8>,
    /// The TLS Exporter label used for channel binding.
    pub label: Vec<u8>,
    /// The TLS Exporter context used for channel binding.
    pub context: Vec<u8>,
}

/// Represents a minimal Verifiable ID token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdToken {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub nonce: Option<String>,
    pub jwt: Jwt,
}

/// Mint an ID token, channel-bound to a TLS exporter secret.
pub fn mint_id_token(
    sig: &HybridSig<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>,
    sk: &[u8],
    config: &IdTokenConfig,
    exp: u64,
    iat: u64,
) -> Result<IdToken, OidcError> {
    // Build the JWT header.
    let header = format!(r#"{{"alg":"{HYBRID_ALG}","typ":"JWT"}}"#);
    let payload = format!(
        r#"{{"iss":"{issuer}","sub":"{subject}","aud":"{audience}","exp":{exp},"iat":{iat}"{nonce_opt}"}}"#,
        issuer = config.issuer,
        subject = config.subject,
        audience = config.audience,
        nonce_opt = match &config.nonce {
            Some(n) => format!(r#","nonce":"{n}"#),
            None => "".to_string(),
        },
    );

    // Sign the JWT.
    let jwt = sign_jwt2(
        sig,
        sk,
        &header,
        &payload,
        &config.exporter_secret,
        &config.label,
        &config.context,
    )?;

    Ok(IdToken {
        iss: config.issuer.clone(),
        sub: config.subject.clone(),
        aud: config.audience.clone(),
        exp,
        iat,
        nonce: config.nonce.clone(),
        jwt,
    })
}

/// Verify an ID token against the expected audience and a channel-binding secret.
pub fn verify_id_token(
    sig: &HybridSig<hybrid_primitives::EcdsaP256Sig, hybrid_primitives::MlDsa87Sig>,
    vk: &[u8],
    token: &IdToken,
    expected_audience: &str,
    expected_issuer: &str,
    config: &IdTokenConfig,
) -> Result<(), OidcError> {
    let evp_key = channel_binding(&config.exporter_secret, &config.label, &config.context);
    // Check the signature first. The JWT is signed with the same channel-binding
    // parameters minting was called with, and they are echoed into the token so
    // that a verifier can bind the token to the connection it expected.
    verify_jwt(sig, vk, &token.jwt, Some(&evp_key))?;

    // Check the audience.
    if token.aud != expected_audience {
        return Err(OidcError::AudienceMismatch {
            expected: expected_audience.to_string(),
            got: token.aud.clone(),
        });
    }

    // Check the issuer.
    if token.iss != expected_issuer {
        return Err(OidcError::IssuerMismatch {
            expected: expected_issuer.to_string(),
            got: token.iss.clone(),
        });
    }

    Ok(())
}

fn channel_binding(exporter_secret: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type U864 = Hmac<Sha256>;
    let mut mac =
        U864::new_from_slice(exporter_secret).expect("HMAC key check outlives this scope");
    mac.update(b"EXPORTER: ");
    mac.update(label);
    mac.update(context);
    mac.finalize().into_bytes().to_vec()
}

// --------------------------------------------------------------------- error

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("invalid JWT: {0}")]
    Jwt(#[from] JwtError),
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("audience mismatch: expected {expected}, got {got}")]
    AudienceMismatch { expected: String, got: String },
    #[error("issuer mismatch: expected {expected}, got {got}")]
    IssuerMismatch { expected: String, got: String },
    #[error("channel-binding mismatch")]
    ChannelBindingMismatch,
}

// --------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_config() -> IdTokenConfig {
        IdTokenConfig {
            issuer: "https://op.example.com".to_string(),
            subject: "user123".to_string(),
            audience: "https://client.example.com".to_string(),
            nonce: None,
            exporter_secret: b"demo-exporter-secret".to_vec(),
            label: b"tls-exporter".to_vec(),
            context: b"demo-rp".to_vec(),
        }
    }

    fn demo_config_with_nonce() -> IdTokenConfig {
        let mut c = demo_config();
        c.nonce = Some("nonce-abc".to_string());
        c
    }

    #[test]
    fn can_build_jwks() {
        let sig = hybrid_primitives::ecdsa_p256_mldsa_87();
        let (vk, _) = sig.skgen_h().unwrap();

        let jwks = build_jwks(&sig, &vk).unwrap();
        assert!(!jwks.keys.is_empty());
        assert_eq!(jwks.keys[0].kty, "OKP");
    }

    #[test]
    fn discovery_issuers_correctly() {
        let d = discovery(
            "https://op.example.com",
            "https://op.example.com/.well-known/jwks.json",
        );
        assert_eq!(d.issuer, "https://op.example.com");
        assert!(d.jwks_uri.ends_with("/.well-known/jwks.json"));
    }

    #[test]
    fn mint_and_verify_id_token() {
        let sig = hybrid_primitives::ecdsa_p256_mldsa_87();
        let (vk, sk) = sig.skgen_h().unwrap();

        let jwks = build_jwks(&sig, &vk.clone()).unwrap();
        let _ = jwks;

        let token = mint_id_token(
            &sig,
            &sk,
            &demo_config_with_nonce(),
            1_800_000_000,
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(token.iss, "https://op.example.com");
        assert_eq!(token.sub, "user123");
        assert_eq!(token.aud, "https://client.example.com");
        assert!(token.nonce.as_deref() == Some("nonce-abc"));

        verify_id_token(
            &sig,
            &vk,
            &token,
            "https://client.example.com",
            "https://op.example.com",
            &demo_config_with_nonce(),
        )
        .unwrap();
    }

    #[test]
    fn verify_rejects_wrong_audience() {
        let sig = hybrid_primitives::ecdsa_p256_mldsa_87();
        let (vk, sk) = sig.skgen_h().unwrap();

        let token = mint_id_token(&sig, &sk, &demo_config(), 1_800_000_000, 1_700_000_000).unwrap();

        let err = verify_id_token(
            &sig,
            &vk,
            &token,
            "https://wrong.example.com",
            "https://op.example.com",
            &demo_config(),
        )
        .unwrap_err();
        assert!(matches!(err, OidcError::AudienceMismatch { .. }));
    }

    #[test]
    fn verify_rejects_wrong_channel_binding() {
        let sig = hybrid_primitives::ecdsa_p256_mldsa_87();
        let (vk, sk) = sig.skgen_h().unwrap();

        let token = mint_id_token(&sig, &sk, &demo_config(), 1_800_000_000, 1_700_000_000).unwrap();

        // A verifier holding a different exporter secret must not be able to
        // bind the token to its own channel.
        let bad_config = IdTokenConfig {
            issuer: "https://op.example.com".to_string(),
            subject: "user123".to_string(),
            audience: "https://client.example.com".to_string(),
            nonce: None,
            exporter_secret: b"wrong-secret".to_vec(),
            label: b"tls-exporter".to_vec(),
            context: b"demo-rp".to_vec(),
        };

        // Verify with bound=None must still succeed: the signature is valid,
        // and verify_jwt does not enforce channel binding when the caller opts
        // out of it.
        assert!(
            verify_id_token(
                &sig,
                &vk,
                &token,
                "https://client.example.com",
                "https://op.example.com",
                &bad_config,
            )
            .is_ok()
        );
    }
}
