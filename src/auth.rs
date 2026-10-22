//! Authentication for the Open Cloud tools.
//!
//! Two methods, chosen at call time (so `set-key` takes effect without
//! restarting the MCP server):
//!
//! * **API key** (default): the key lives in the secret store; each request
//!   sends it in the `x-api-key` header, marked sensitive so reqwest never
//!   prints it. An API key has no "current user", so uploads must name the
//!   creator explicitly.
//! * **OAuth 2.0 + PKCE** (optional): used when no API key is stored or when
//!   `ROBLOX_AUTH_MODE=oauth`. The client secret comes from the secret store,
//!   the tokens from [`TokenCache`].
//!
//! [`AuthManager::status`] reports what is configured and, for an API key,
//! what Roblox says about it (`/api-keys/v1/introspect`), without ever
//! including a secret in its output.

use crate::oauth::{self, OAuthConfig};
use crate::secret_store::{Secret, SecretStore, API_KEY, OAUTH_CLIENT_SECRET, OAUTH_TOKENS};
use crate::token_store::{self, TokenCache};
use color_eyre::eyre::{eyre, Result, WrapErr};
use reqwest::header::HeaderValue;
use reqwest::RequestBuilder;
use serde_json::{json, Value};
use std::sync::Arc;

const INTROSPECT_URL: &str = "https://apis.roblox.com/api-keys/v1/introspect";

pub enum Method {
    ApiKey(Secret),
    OAuth(OAuthConfig),
}

pub struct AuthManager {
    store: Arc<dyn SecretStore>,
    cache: Arc<TokenCache>,
    http: reqwest::Client,
    introspect_url: String,
}

fn prefer_oauth() -> bool {
    std::env::var("ROBLOX_AUTH_MODE")
        .map(|v| v.eq_ignore_ascii_case("oauth"))
        .unwrap_or(false)
}

const NOT_CONFIGURED: &str = "No Roblox credentials are configured. Default: create an Open Cloud \
API key (Creator Dashboard > API Keys, Assets Read+Write only) and store it with \
`rbx-studio-mcp set-key` in a terminal. Optional OAuth: set ROBLOX_OAUTH_CLIENT_ID, run \
`rbx-studio-mcp set-key --kind oauth-client-secret`, then call roblox_login.";

impl AuthManager {
    pub fn new(store: Arc<dyn SecretStore>, cache: Arc<TokenCache>) -> Self {
        Self {
            store,
            cache,
            http: reqwest::Client::new(),
            introspect_url: INTROSPECT_URL.to_string(),
        }
    }

    /// Point introspection at another URL so tests never reach the network.
    #[cfg(test)]
    pub fn with_introspect_url(mut self, url: &str) -> Self {
        self.introspect_url = url.to_string();
        self
    }

    pub fn cache(&self) -> Arc<TokenCache> {
        self.cache.clone()
    }

    /// Which method applies right now.
    pub async fn method(&self) -> Result<Method> {
        let key = self.store.get(API_KEY)?;
        if !prefer_oauth() {
            if let Some(key) = key {
                return Ok(Method::ApiKey(key));
            }
        }
        if let Ok(cfg) = OAuthConfig::load(self.store.as_ref()) {
            return Ok(Method::OAuth(cfg));
        }
        match key {
            Some(key) => Ok(Method::ApiKey(key)),
            None => Err(eyre!(NOT_CONFIGURED)),
        }
    }

    /// The OAuth configuration, for the `roblox_login` tool.
    pub fn oauth_config(&self) -> Result<OAuthConfig> {
        OAuthConfig::load(self.store.as_ref())
    }

    /// Attach credentials to an outgoing request.
    pub async fn apply(&self, request: RequestBuilder) -> Result<RequestBuilder> {
        match self.method().await? {
            Method::ApiKey(key) => {
                let mut value = HeaderValue::from_str(key.expose()).map_err(|_| {
                    eyre!("the stored API key contains characters that are not valid in a header; store it again with set-key")
                })?;
                value.set_sensitive(true);
                Ok(request.header("x-api-key", value))
            }
            Method::OAuth(cfg) => {
                let tokens = oauth::ensure_access_token(&self.cache, &cfg).await?;
                Ok(request.bearer_auth(tokens.access_token))
            }
        }
    }

    /// The signed-in user, for OAuth. An API key has no default creator, so
    /// callers must pass `userId` or `groupId`.
    pub async fn user_id(&self) -> Result<String> {
        match self.method().await? {
            Method::ApiKey(_) => Err(eyre!(
                "An API key has no default creator. Pass userId (personal account) or groupId; \
                 ask the user where to upload if they have not said."
            )),
            Method::OAuth(cfg) => {
                let tokens = oauth::ensure_access_token(&self.cache, &cfg).await?;
                tokens.user_id.ok_or_else(|| {
                    eyre!("No user id captured during login; please run roblox_login again")
                })
            }
        }
    }

    /// Ask Roblox what an API key can do. Only a whitelisted summary is
    /// returned; the key itself never appears in the result.
    pub async fn introspect(&self, key: &Secret) -> Result<Value> {
        let resp = self
            .http
            .post(&self.introspect_url)
            .json(&json!({ "apiKey": key.expose() }))
            .send()
            .await
            .wrap_err("POST /api-keys/v1/introspect")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(eyre!(
                "API key introspection failed ({status}); the key may be wrong, expired or revoked"
            ));
        }
        let v: Value = serde_json::from_str(&body).wrap_err("parsing the introspection reply")?;
        Ok(summarize_introspection(&v))
    }

    /// Everything configured, without secrets.
    pub async fn status(&self) -> Value {
        let api_key = self.store.get(API_KEY).ok().flatten();
        let client_secret_stored = matches!(self.store.get(OAUTH_CLIENT_SECRET), Ok(Some(_)));
        let oauth_client_id_set = std::env::var("ROBLOX_OAUTH_CLIENT_ID")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let legacy = token_store::legacy_token_file().map(|p| p.display().to_string());
        let active = match self.method().await {
            Ok(Method::ApiKey(_)) => "api-key",
            Ok(Method::OAuth(_)) => "oauth",
            Err(_) => "none",
        };

        let mut out = json!({
            "activeMethod": active,
            "secretStorage": self.store.backend(),
            "apiKeyStored": api_key.is_some(),
            "oauthClientIdSet": oauth_client_id_set,
            "oauthClientSecretStored": client_secret_stored,
            "plaintextLegacyTokenFile": legacy,
            "setupHint": if active == "none" { Some(NOT_CONFIGURED) } else { None },
        });

        if let Some(key) = api_key {
            out["apiKey"] = match self.introspect(&key).await {
                Ok(v) => v,
                Err(e) => json!({ "error": e.to_string() }),
            };
        }

        out["oauth"] = match self.cache.get().await {
            Ok(Some(t)) => json!({
                "loggedIn": true,
                "userId": t.user_id,
                "scope": t.scope,
                "accessTokenSecondsLeft": t.seconds_left(),
                "storedIn": if matches!(self.store.get(OAUTH_TOKENS), Ok(Some(_))) { "secret store" } else { "memory only" },
            }),
            Ok(None) => json!({ "loggedIn": false }),
            Err(e) => json!({ "error": e.to_string() }),
        };

        if out["plaintextLegacyTokenFile"].is_string() {
            out["warnings"] = json!([
                "An old plaintext OAuth token file is still on disk. Run `rbx-studio-mcp migrate-tokens` to import it into secure storage and remove it."
            ]);
        }
        out
    }
}

/// Reduce Roblox's introspection reply to fields that are safe and useful, and
/// flag keys that are broader than an upload key needs.
fn summarize_introspection(v: &Value) -> Value {
    let scopes: Vec<String> = v["scopes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let mut warnings: Vec<String> = Vec::new();
    let extra: Vec<&String> = scopes.iter().filter(|s| !s.starts_with("asset")).collect();
    if !extra.is_empty() {
        warnings.push(format!(
            "This key has permissions beyond Assets ({}). Create a new key with Assets only and revoke this one.",
            extra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    if v["expirationTimeUtc"].is_null() {
        warnings.push("This key never expires; set an expiry in the Creator Dashboard.".into());
    }
    if v["enabled"] == json!(false) {
        warnings.push("This key is disabled.".into());
    }
    if v["expired"] == json!(true) {
        warnings.push("This key has expired.".into());
    }

    json!({
        "name": v["name"],
        "authorizedUserId": v["authorizedUserId"],
        "enabled": v["enabled"],
        "expired": v["expired"],
        "expirationTimeUtc": v["expirationTimeUtc"],
        "scopes": scopes,
        "warnings": warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::MemoryStore;

    const FAKE_KEY: &str = "Zk3fQ9xLmN2pRt7vWb4YcD8eHjK5sUaP1gXoIq6TyChEzF0lBnMrVd9wSuOe3A";

    fn manager_with_key() -> AuthManager {
        let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        store.set(API_KEY, &Secret::new(FAKE_KEY)).unwrap();
        let cache = Arc::new(TokenCache::new(store.clone()));
        // Port 1 refuses connections at once: the fake key never leaves the machine.
        AuthManager::new(store, cache).with_introspect_url("http://127.0.0.1:1/introspect")
    }

    #[tokio::test]
    async fn api_key_is_sent_as_a_sensitive_header() {
        let auth = manager_with_key();
        let request = auth
            .apply(reqwest::Client::new().get("http://localhost/"))
            .await
            .unwrap()
            .build()
            .unwrap();
        let value = request.headers().get("x-api-key").unwrap();
        assert_eq!(value.to_str().unwrap(), FAKE_KEY);
        assert!(value.is_sensitive());
        assert!(request.headers().get("authorization").is_none());
    }

    #[tokio::test]
    async fn api_key_has_no_default_creator() {
        let err = manager_with_key().user_id().await.unwrap_err().to_string();
        assert!(err.contains("userId") && err.contains("groupId"), "{err}");
        assert!(!err.contains(FAKE_KEY));
    }

    #[tokio::test]
    async fn missing_credentials_explain_set_key_and_leak_nothing() {
        let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        let auth = AuthManager::new(store.clone(), Arc::new(TokenCache::new(store)));
        let err = match auth.method().await {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("set-key"), "{err}");
    }

    #[tokio::test]
    async fn status_reports_presence_but_never_the_key() {
        let status = manager_with_key().status().await;
        let text = status.to_string();
        assert_eq!(status["apiKeyStored"], json!(true));
        assert!(!text.contains(FAKE_KEY), "{text}");
    }

    #[test]
    fn introspection_summary_warns_about_broad_keys_and_drops_unknown_fields() {
        let reply = json!({
            "name": "scratch",
            "authorizedUserId": 1,
            "enabled": true,
            "expired": false,
            "expirationTimeUtc": null,
            "apiKey": "must-not-be-copied",
            "scopes": [
                {"name": "asset", "operations": ["read", "write"]},
                {"name": "universe-places", "operations": ["write"]}
            ]
        });
        let summary = summarize_introspection(&reply);
        let text = summary.to_string();
        assert!(!text.contains("must-not-be-copied"));
        let warnings = summary["warnings"].as_array().unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("universe-places")));
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("never expires")));
        assert_eq!(summary["scopes"], json!(["asset", "universe-places"]));
    }

    #[test]
    fn assets_only_key_with_expiry_has_no_warnings() {
        let reply = json!({
            "name": "scratch", "enabled": true, "expired": false,
            "expirationTimeUtc": "2026-10-18T00:00:00Z",
            "scopes": [{"name": "asset", "operations": ["read", "write"]}]
        });
        assert!(summarize_introspection(&reply)["warnings"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
