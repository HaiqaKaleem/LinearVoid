//! Hybrid OIDC demo server — simulates the full Authorization Code flow.

mod store;

use axum::{
    extract::{Json, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    body::Body,
    routing::{get, post},
    Router,
};
use hybrid_jwt::Jwt;
use hybrid_oidc::{build_jwks, mint_id_token, verify_id_token, IdTokenConfig};
use hybrid_primitives::ecdsa_p256_mldsa_87;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::store::{AccessTokenRecord, DemoStore, Grant, RefreshTokenRecord};

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    id_token: String,
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    refresh_token: Option<String>,
}

// --------------------------------------------------------------------- shared state

#[derive(Clone)]
struct AppState {
    store: Arc<std::sync::Mutex<DemoStore>>,
    counter: Arc<AtomicU64>,
}

// --------------------------------------------------------------------- discovery

#[derive(Debug, Serialize, Deserialize)]
struct DiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    revocation_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    check_session_iframe: Option<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    claims_supported: Vec<String>,
    claims_parameter_supported: bool,
}

fn discovery_response(issuer: &str) -> DiscoveryResponse {
    let base = issuer.trim_end_matches('/');
    DiscoveryResponse {
        issuer: base.to_string(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        userinfo_endpoint: format!("{base}/userinfo"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        revocation_endpoint: Some(format!("{base}/revoke")),
        introspection_endpoint: Some(format!("{base}/introspect")),
        end_session_endpoint: Some(format!("{base}/endsession")),
        check_session_iframe: Some(format!("{base}/check-session-iframe")),
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["hybrid".to_string()],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        claims_supported: vec![
            "sub".to_string(),
            "iss".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "nonce".to_string(),
            "name".to_string(),
            "email".to_string(),
            "preferred_username".to_string(),
        ],
        claims_parameter_supported: false,
    }
}

#[derive(Debug, Deserialize)]
struct DiscoveryQuery {
    issuer: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IntrospectRequest {
    token: String,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IntrospectionResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EndSessionRequest {
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReplayDemoRequest {
    channel_binding_string: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReplayDemoResponse {
    signed_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_input_preview: Option<String>,
    verify_on_original: bool,
    verify_on_different: bool,
    verify_without_binding: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyRequest {
    id_token: String,
    audience: Option<String>,
    issuer: Option<String>,
    exporter_secret: Option<String>,
    label: Option<String>,
    context: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyResponse {
    valid: bool,
    error: Option<String>,
}

// --------------------------------------------------------------------- helpers

fn current_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn make_id(prefix: &str, data: &str) -> String {
    let hash = hex::encode(Sha256::digest(data.as_bytes()));
    format!("{}-{}-{}", prefix, data, &hash[..12])
}

fn create_hybrid_and_keys() -> (
    hybrid_primitives::EcdsaP256MlDsa87,
    Vec<u8>,
    Vec<u8>,
) {
    let sig = ecdsa_p256_mldsa_87();
    let (vk, sk) = sig.skgen_h().expect("keygen");
    (sig, vk, sk)
}

// --------------------------------------------------------------------- handlers

async fn discovery_handler(
    Query(q): Query<DiscoveryQuery>,
) -> impl IntoResponse {
    let issuer = q
        .issuer
        .unwrap_or_else(|| "https://demo.hybrid-oidc.local".to_string());
    Json(discovery_response(&issuer))
}

async fn jwks_handler() -> impl IntoResponse {
    let sig = ecdsa_p256_mldsa_87();
    let (vk, _sk) = sig.skgen_h().unwrap();
    let jwks = build_jwks(&sig, &vk).unwrap();
    let json = serde_json::to_string(&jwks).unwrap();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
}

async fn authorize_handler(
    Query(p): Query<AuthorizeParams>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let mut store = state.store.lock().unwrap();
    let client = match store.find_client(&p.client_id) {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                [(header::LOCATION, "https://demo.hybrid-oidc.local/error?error=invalid_client")],
            )
                .into_response();
        }
    };

    if p.response_type != "code" {
        return (
            StatusCode::BAD_REQUEST,
            [(header::LOCATION, "https://demo.hybrid-oidc.local/error?error=invalid_request")],
        )
            .into_response();
    }

    if !client.redirect_uris.contains(&p.redirect_uri) {
        return (
            StatusCode::BAD_REQUEST,
            [
                (header::LOCATION, "https://demo.hybrid-oidc.local/error?error=invalid_redirect_uri"),
            ],
        )
            .into_response();
    }

    let scopes: Vec<&str> = p.scope.split_whitespace().collect();
    if !scopes.contains(&"openid") {
        return (
            StatusCode::BAD_REQUEST,
            [
                (header::LOCATION, "https://demo.hybrid-oidc.local/error?error=invalid_scope"),
            ],
        )
            .into_response();
    }

    let user = store.find_user("user-1").expect("seeded user");
    let now = current_time_secs();
    let id = state.counter.fetch_add(1, Ordering::Relaxed);
    let grant_id = format!("g-{}", id);

    let code = make_id("code", &format!("{}-{}", grant_id, user.id));
    let expires_at = now + 300;

    let grant = Grant {
        id: grant_id.clone(),
        user_id: user.id.clone(),
        client_id: p.client_id.clone(),
        code: code.clone(),
        redirect_uri: p.redirect_uri.clone(),
        scope: p.scope.clone(),
        nonce: p.nonce.clone(),
        state: p.state.clone(),
        code_challenge: p.code_challenge.clone(),
        code_challenge_method: p.code_challenge_method.clone(),
        created_at: now,
        expires_at,
        used: false,
    };

    store.save_grant(grant);

    let mut redirect = format!("{}?code={}", p.redirect_uri, urlencoding::encode(&code));
    if let Some(ref state) = p.state {
        redirect.push_str("&state=");
        redirect.push_str(&urlencoding::encode(state));
    }

    (StatusCode::SEE_OTHER, [(header::LOCATION, redirect)]).into_response()
}

async fn token_handler(
    State(_state): State<AppState>,
    Json(_req): Json<TokenRequest>,
) -> impl IntoResponse {
    // TODO: Implement token endpoint logic
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "not_implemented",
            "error_description": "Token endpoint not yet implemented"
        })),
    )
        .into_response()
}

async fn userinfo_handler(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => h[7..].to_string(),
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Missing or malformed Authorization header"
                })),
            )
                .into_response();
        }
    };

    let store = state.store.lock().unwrap();
    let at = match store.find_access_token(&token) {
        Some(at) => at,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Access token not found"
                })),
            )
                .into_response();
        }
    };

    if at.expires_at <= current_time_secs() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": "Access token expired"
            })),
        )
            .into_response();
    }

    let user = store.find_user(&at.user_id).expect("user exists");
    let scopes: Vec<&str> = at.scope.split_whitespace().collect();

    let mut claims = serde_json::Map::new();
    claims.insert("sub".to_string(), serde_json::Value::String(user.id.clone()));

    if scopes.contains(&"profile") {
        claims.insert("name".to_string(), serde_json::Value::String(user.name.clone()));
        claims.insert(
            "preferred_username".to_string(),
            serde_json::Value::String(user.preferred_username.clone()),
        );
    }

    if scopes.contains(&"email") {
        claims.insert("email".to_string(), serde_json::Value::String(user.email.clone()));
    }

    claims.insert(
        "updated_at".to_string(),
        serde_json::Value::Number(serde_json::Number::from(current_time_secs())),
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(serde_json::Value::Object(claims)),
    )
        .into_response()
}

async fn introspect_handler(
    State(state): State<AppState>,
    Json(req): Json<IntrospectRequest>,
) -> impl IntoResponse {
    let client_id = match &req.client_id {
        Some(c) => c.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "client_id required"
                })),
            )
                .into_response();
        }
    };

    let client_secret = req.client_secret.as_deref();
    let store = state.store.lock().unwrap();

    if !store.authenticate_client(&client_id, client_secret) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "Client authentication failed"
            })),
        )
            .into_response();
    }

    let token = req.token.clone();
    let at = store.access_token_metadata(&token);

    match at {
        Some(at) => {
            let active = at.expires_at > current_time_secs() && !store.is_revoked(&token);
            let resp = IntrospectionResponse {
                active,
                scope: if active { Some(at.scope.clone()) } else { None },
                client_id: if active { Some(at.client_id.clone()) } else { None },
                exp: if active { Some(at.expires_at) } else { None },
                iat: if active { Some(at.created_at) } else { None },
                sub: if active {
                    store.find_user(&at.user_id).map(|u| u.id.clone())
                } else {
                    None
                },
                iss: if active {
                    Some("https://demo.hybrid-oidc.local".to_string())
                } else {
                    None
                },
                aud: if active { Some(at.client_id.clone()) } else { None },
            };
            Json(resp).into_response()
        }
        None => Json(IntrospectionResponse {
            active: false,
            scope: None,
            client_id: None,
            exp: None,
            iat: None,
            sub: None,
            iss: None,
            aud: None,
        })
        .into_response(),
    }
}

async fn revoke_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::store::RevokeRequest>,
) -> impl IntoResponse {
    let client_id = match &req.client_id {
        Some(c) => c.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "client_id required"
                })),
            )
                .into_response();
        }
    };

    let client_secret = req.client_secret.as_deref();
    let mut store = state.store.lock().unwrap();

    if !store.authenticate_client(&client_id, client_secret) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "Client authentication failed"
            })),
        )
            .into_response();
    }

    store.revoke_access_token(&req.token);
    StatusCode::OK.into_response()
}

async fn endsession_handler(
    Query(params): Query<EndSessionRequest>,
) -> impl IntoResponse {
    let mut location: String;
    if let Some(ref post_logout) = params.post_logout_redirect_uri {
        location = post_logout.clone();
        if !location.contains('?') {
            location.push('?');
        } else {
            location.push('&');
        }
        if let Some(ref state) = params.state {
            location.push_str(&format!("state={}", urlencoding::encode(state)));
        }
    } else {
        location = "https://demo.hybrid-oidc.local/".to_string();
    }

    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

async fn replay_demo_handler(
    Json(req): Json<ReplayDemoRequest>,
) -> impl IntoResponse {
    let sig = ecdsa_p256_mldsa_87();
    let (vk, sk) = sig.skgen_h().expect("keygen");

    let header = r#"{"alg":"hybrid","typ":"JWT"}"#;
    let payload = r#"{"sub":"alice","aud":"client-1"}"#;

    let binding = Sha256::digest(req.channel_binding_string.as_bytes());

    use hybrid_jwt::sign_jwt;
    let jwt = sign_jwt(&sig, &sk, header, payload, Some(&binding)).expect("signing");

    let jwt_json = serde_json::to_string(&jwt).expect("serialization");

    let signing_input_preview = Some(format!("{}...", &hex::encode(&binding)[..16]));

    let verify_original = hybrid_jwt::verify_jwt(&sig, &vk, &jwt, Some(&binding)).is_ok();

    let different_binding = Sha256::digest(b"different channel");
    let verify_different = hybrid_jwt::verify_jwt(&sig, &vk, &jwt, Some(&different_binding)).is_ok();

    let verify_without = hybrid_jwt::verify_jwt(&sig, &vk, &jwt, None).is_ok();

    Json(ReplayDemoResponse {
        signed_token: jwt_json,
        signing_input_preview,
        verify_on_original: verify_original,
        verify_on_different: verify_different,
        verify_without_binding: verify_without,
    })
        .into_response()
}

async fn verify_handler(
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    let sig = ecdsa_p256_mldsa_87();
    let (vk, _sk) = sig.skgen_h().expect("keygen");

    let jwt: Jwt = match serde_json::from_str(&req.id_token) {
        Ok(j) => j,
        Err(_) => {
            return Json(VerifyResponse {
                valid: false,
                error: Some("Failed to parse JWT".to_string()),
            })
            .into_response();
        }
    };

    let expected_audience = req
        .audience
        .clone()
        .unwrap_or_else(|| "client-1".to_string());
    let expected_issuer = req
        .issuer
        .clone()
        .unwrap_or_else(|| "https://demo.hybrid-oidc.local".to_string());

    let config = IdTokenConfig {
        issuer: expected_issuer.clone(),
        subject: String::new(),
        audience: expected_audience.clone(),
        nonce: None,
        exporter_secret: req
            .exporter_secret
            .unwrap_or_else(|| "demo-exporter-secret".to_string())
            .into_bytes(),
        label: req
            .label
            .unwrap_or_else(|| "tls-exporter".to_string())
            .into_bytes(),
        context: req
            .context
            .unwrap_or_else(|| "demo-rp".to_string())
            .into_bytes(),
    };

    let id_token = hybrid_oidc::IdToken {
        iss: expected_issuer.clone(),
        sub: String::new(),
        aud: expected_audience.clone(),
        exp: 0,
        iat: 0,
        nonce: None,
        jwt: jwt.clone(),
    };

    let result = verify_id_token(
        &sig,
        &vk,
        &id_token,
        &expected_audience,
        &expected_issuer,
        &config,
    );

    match result {
        Ok(()) => Json(VerifyResponse { valid: true, error: None }).into_response(),
        Err(e) => Json(VerifyResponse { valid: false, error: Some(e.to_string()) }).into_response(),
    }
}

// --------------------------------------------------------------------- main

#[tokio::main]
async fn main() {
    let state = AppState {
        store: Arc::new(std::sync::Mutex::new(DemoStore::new())),
        counter: Arc::new(AtomicU64::new(0)),
    };

    let app = Router::new()
        .route("/discovery", get(discovery_handler))
        .route("/.well-known/openid-configuration", get(discovery_handler))
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/authorize", get(authorize_handler))
        .route("/token", post(token_handler))
        .route("/userinfo", get(userinfo_handler))
        .route("/introspect", post(introspect_handler))
        .route("/revoke", post(revoke_handler))
        .route("/endsession", get(endsession_handler))
        .route(
            "/check-session-iframe",
            get(|| async {
                "OIDC Check Session Iframe (demo placeholder)".into_response()
            }),
        )
        .route("/replay-demo", post(replay_demo_handler))
        .route("/verify", post(verify_handler))
        .with_state(state);

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║   Hybrid OIDC Demo Server — Authorization Code Flow        ║");
    println!("║   Post-Quantum Ready (ML-KEM-768 + ML-DSA-87)             ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║                                                            ║");
    println!("║   Endpoints:                                               ║");
    println!("║                                                            ║");
    println!("║   OIDC Discovery:                                         ║");
    println!("║     GET  /.well-known/openid-configuration                ║");
    println!("║     GET  /.well-known/jwks.json                           ║");
    println!("║                                                            ║");
    println!("║   Authorization Code Flow:                                ║");
    println!("║     GET  /authorize?response_type=code                    ║");
    println!("║          &client_id=...&redirect_uri=...                  ║");
    println!("║          &scope=openid+profile&nonce=...&state=...        ║");
    println!("║          &code_challenge=...&code_challenge_method=S256   ║");
    println!("║     POST /token  (grant_type=authorization_code)          ║");
    println!("║     POST /token  (grant_type=refresh_token)               ║");
    println!("║                                                            ║");
    println!("║   Token Validation:                                       ║");
    println!("║     GET  /userinfo  (Bearer <access_token>)              ║");
    println!("║     POST /introspect                                     ║");
    println!("║     POST /revoke                                         ║");
    println!("║                                                            ║");
    println!("║   Session Management:                                     ║");
    println!("║     GET  /endsession                                      ║");
    println!("║     GET  /check-session-iframe                            ║");
    println!("║                                                            ║");
    println!("║   Demo / Verification:                                    ║");
    println!("║     POST /replay-demo   (channel-binding replay demo)    ║");
    println!("║     POST /verify       (verify an ID token)              ║");
    println!("║                                                            ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Server running on http://{}", addr);
    println!("\nDemo client credentials:");
    println!("  Confidential client: client-1 / demo-client-secret");
    println!("  Public client:       client-public / (no secret)");
    println!("\nDemo user: user-1 (any password accepted)");

    axum::serve(listener, app).await.unwrap();
}
