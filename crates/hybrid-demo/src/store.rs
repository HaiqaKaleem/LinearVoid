//! Demo user/resource database for simulating OIDC resource owners, clients, and grants.
//! For demo purposes only — in-memory, no persistence.

use getrandom::fill;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A resource owner (end-user) in the demo OP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub preferred_username: String,
}

/// A registered OIDC client (RP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub scope: String,
    pub token_endpoint_auth_method: String,
}

/// An authorization grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub code: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub used: bool,
}

/// An access token record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenRecord {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: u64,
    pub scope: String,
    pub client_id: String,
    pub user_id: String,
    pub created_at: u64,
}

/// A refresh token record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    pub refresh_token: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub expires_at: u64,
    pub used: bool,
}

/// Request type for token revocation.
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    /// Parsed per RFC 7009's request shape; not yet consulted by the demo.
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// In-memory store.
pub struct DemoStore {
    users: HashMap<String, User>,
    clients: HashMap<String, Client>,
    grants: HashMap<String, Grant>,
    access_tokens: HashMap<String, AccessTokenRecord>,
    /// Written by `save_refresh_token` and read by `take_refresh_token`, both
    /// used by the not-yet-implemented `/token` endpoint (see `token_handler`).
    #[allow(dead_code)]
    refresh_tokens: HashMap<String, RefreshTokenRecord>,
    revocation_list: Vec<String>,
}

impl DemoStore {
    pub fn new() -> Self {
        let mut store = Self {
            users: HashMap::new(),
            clients: HashMap::new(),
            grants: HashMap::new(),
            access_tokens: HashMap::new(),
            refresh_tokens: HashMap::new(),
            revocation_list: Vec::new(),
        };
        store.seed_demo_data();
        store
    }

    fn seed_demo_data(&mut self) {
        self.users.insert(
            "user-1".to_string(),
            User {
                id: "user-1".to_string(),
                email: "alice@example.com".to_string(),
                name: "Alice Example".to_string(),
                preferred_username: "alice".to_string(),
            },
        );
        self.clients.insert(
            "client-1".to_string(),
            Client {
                client_id: "client-1".to_string(),
                client_secret: Some("demo-client-secret".to_string()),
                redirect_uris: vec!["https://client.example.com/callback".to_string()],
                scope: "openid profile email".to_string(),
                token_endpoint_auth_method: "client_secret_post".to_string(),
            },
        );
        self.clients.insert(
            "client-public".to_string(),
            Client {
                client_id: "client-public".to_string(),
                client_secret: None,
                redirect_uris: vec!["https://spa.example.com/callback".to_string()],
                scope: "openid profile".to_string(),
                token_endpoint_auth_method: "none".to_string(),
            },
        );
    }

    pub fn find_user(&self, id: &str) -> Option<&User> {
        self.users.get(id)
    }

    pub fn find_client(&self, client_id: &str) -> Option<&Client> {
        self.clients.get(client_id)
    }

    pub fn authenticate_client(&self, client_id: &str, client_secret: Option<&str>) -> bool {
        match self.clients.get(client_id) {
            Some(client) => match client.token_endpoint_auth_method.as_str() {
                "none" => client_secret.is_none(),
                _ => match (client.client_secret.as_deref(), client_secret) {
                    (Some(expected), Some(given)) => expected == given,
                    _ => false,
                },
            },
            None => false,
        }
    }

    pub fn save_grant(&mut self, grant: Grant) {
        self.grants.insert(grant.id.clone(), grant);
    }

    /// Redeems an authorization code; used by the not-yet-implemented
    /// `/token` endpoint (see `token_handler`).
    #[allow(dead_code)]
    pub fn take_grant(&mut self, id: &str) -> Option<Grant> {
        self.grants.remove(id)
    }

    /// Records a freshly minted access token; used by the not-yet-implemented
    /// `/token` endpoint (see `token_handler`).
    #[allow(dead_code)]
    pub fn save_access_token(&mut self, at: AccessTokenRecord) {
        self.access_tokens.insert(at.access_token.clone(), at);
    }

    pub fn find_access_token(&self, token: &str) -> Option<&AccessTokenRecord> {
        self.access_tokens.get(token)
    }

    pub fn revoke_access_token(&mut self, token: &str) {
        self.revocation_list.push(token.to_string());
        self.access_tokens.remove(token);
    }

    pub fn is_revoked(&self, token: &str) -> bool {
        self.revocation_list.iter().any(|t| t == token)
    }

    pub fn access_token_metadata(&self, token: &str) -> Option<AccessTokenRecord> {
        self.access_tokens.get(token).cloned()
    }

    /// Records a freshly minted refresh token; used by the not-yet-implemented
    /// `/token` endpoint (see `token_handler`).
    #[allow(dead_code)]
    pub fn save_refresh_token(&mut self, rt: RefreshTokenRecord) {
        self.refresh_tokens.insert(rt.refresh_token.clone(), rt);
    }

    /// Consumes a refresh token (rotation); used by the not-yet-implemented
    /// `/token` endpoint (see `token_handler`).
    #[allow(dead_code)]
    pub fn take_refresh_token(&mut self, token: &str) -> Option<RefreshTokenRecord> {
        self.refresh_tokens.remove(token)
    }
}

/// Wall-clock helper for the not-yet-implemented `/token` endpoint; `main.rs`
/// keeps its own copy for the handlers that are wired up today.
#[allow(dead_code)]
fn current_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Generate a nonce string.
///
/// Used by the not-yet-implemented `/token` endpoint (see `token_handler`).
#[allow(dead_code)]
pub fn demo_nonce() -> String {
    let mut buf = [0u8; 32];
    fill(&mut buf).expect("os rng");
    let digest = Sha256::digest(buf);
    hex::encode(digest)[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_seeded_user_and_clients() {
        let store = DemoStore::new();
        assert!(store.find_user("user-1").is_some());
        assert!(store.find_client("client-1").is_some());
        assert!(store.find_client("client-public").is_some());
    }

    #[test]
    fn confidential_client_auth_with_secret() {
        let store = DemoStore::new();
        assert!(store.authenticate_client("client-1", Some("demo-client-secret")));
        assert!(!store.authenticate_client("client-1", Some("wrong")));
    }

    #[test]
    fn public_client_auth_without_secret() {
        let store = DemoStore::new();
        assert!(store.authenticate_client("client-public", None));
        assert!(!store.authenticate_client("client-public", Some("x")));
    }
}
