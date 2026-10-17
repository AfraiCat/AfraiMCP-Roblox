//! Persistent storage for Roblox OAuth tokens.
//!
//! Tokens are serialized to JSON and kept in the [`SecretStore`] (Windows
//! DPAPI: encrypted at rest) under the name `OAUTH_TOKENS`. The previous
//! version wrote `oauth-tokens.json` in plaintext under the config directory;
//! that file is never read implicitly any more. [`import_legacy`] copies it
//! into the secure store on request and [`delete_legacy_file`] removes it only
//! when the caller (the CLI, after asking the user) says so.

use crate::secret_store::{Secret, SecretStore, OAUTH_TOKENS};
use color_eyre::eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const APP_DIR: &str = "rbx-studio-mcp";
const LEGACY_TOKEN_FILE: &str = "oauth-tokens.json";

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredTokens {
    pub access_token: String,
    pub refresh_token: String,
    /// Absolute UNIX epoch seconds when access_token expires.
    pub access_token_expires_at: u64,
    /// `sub` claim from the userinfo endpoint, used as the upload creator.
    pub user_id: Option<String>,
    /// Granted scopes, e.g. "asset:read asset:write openid".
    pub scope: Option<String>,
}

impl std::fmt::Debug for StoredTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredTokens")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("access_token_expires_at", &self.access_token_expires_at)
            .field("user_id", &self.user_id)
            .field("scope", &self.scope)
            .finish()
    }
}

impl StoredTokens {
    /// True if the access token has less than `skew` seconds left.
    pub fn is_expired(&self, skew_secs: u64) -> bool {
        // Refresh proactively rather than letting the API return a 401.
        self.access_token_expires_at <= now_secs().saturating_add(skew_secs)
    }

    /// Seconds until the access token expires (0 if already expired).
    pub fn seconds_left(&self) -> u64 {
        self.access_token_expires_at.saturating_sub(now_secs())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Location of the old plaintext token file (may not exist).
pub fn legacy_token_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(APP_DIR).join(LEGACY_TOKEN_FILE))
}

/// The old plaintext token file, if it is still on disk.
pub fn legacy_token_file() -> Option<PathBuf> {
    legacy_token_path().filter(|p| p.exists())
}

/// Copy the legacy plaintext token file into the secure store. Does not
/// delete anything. Returns the file that was imported.
pub fn import_legacy(store: &dyn SecretStore) -> Result<Option<PathBuf>> {
    let Some(path) = legacy_token_file() else {
        return Ok(None);
    };
    let bytes = fs::read(&path).wrap_err("reading the legacy token file")?;
    let tokens: StoredTokens =
        serde_json::from_slice(&bytes).wrap_err("parsing the legacy token file")?;
    store.set(OAUTH_TOKENS, &serialize(&tokens)?)?;
    Ok(Some(path))
}

/// Delete the legacy plaintext token file. Callers must have asked the user.
pub fn delete_legacy_file(path: &std::path::Path) -> Result<()> {
    fs::remove_file(path).wrap_err("removing the legacy token file")
}

fn serialize(tokens: &StoredTokens) -> Result<Secret> {
    Ok(Secret::new(serde_json::to_string(tokens)?))
}

fn parse(secret: &Secret) -> Result<StoredTokens> {
    serde_json::from_str(secret.expose())
        .map_err(|_| eyre!("the stored OAuth tokens are damaged; run roblox_login again"))
}

/// In-memory cache over the secure store so we don't decrypt on every API call.
/// Wrapped in a Mutex because the MCP server is multi-threaded and a token
/// refresh can race with a concurrent read. The lock is held only across store
/// reads/writes; the actual HTTP refresh runs without the lock held.
pub struct TokenCache {
    store: Arc<dyn SecretStore>,
    inner: Mutex<Option<StoredTokens>>,
}

impl TokenCache {
    pub fn new(store: Arc<dyn SecretStore>) -> Self {
        Self {
            store,
            inner: Mutex::new(None),
        }
    }

    /// Get the currently cached tokens, loading from the store on first access.
    pub async fn get(&self) -> Result<Option<StoredTokens>> {
        let mut guard = self.inner.lock().await;
        if guard.is_none() {
            if let Some(secret) = self.store.get(OAUTH_TOKENS)? {
                *guard = Some(parse(&secret)?);
            }
        }
        Ok(guard.clone())
    }

    /// Replace the cached tokens and persist them to the secure store.
    pub async fn set(&self, tokens: StoredTokens) -> Result<()> {
        self.store.set(OAUTH_TOKENS, &serialize(&tokens)?)?;
        let mut guard = self.inner.lock().await;
        *guard = Some(tokens);
        Ok(())
    }

    /// Drop tokens from memory and from the store.
    pub async fn clear(&self) -> Result<()> {
        self.store.delete(OAUTH_TOKENS)?;
        let mut guard = self.inner.lock().await;
        *guard = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::MemoryStore;

    fn sample() -> StoredTokens {
        StoredTokens {
            access_token: "access-token-sample-0001".into(),
            refresh_token: "refresh-token-sample-0002".into(),
            access_token_expires_at: now_secs() + 900,
            user_id: Some("123".into()),
            scope: Some("asset:read asset:write".into()),
        }
    }

    #[test]
    fn debug_output_hides_both_tokens() {
        let text = format!("{:?}", sample());
        assert!(!text.contains("access-token-sample"), "{text}");
        assert!(!text.contains("refresh-token-sample"), "{text}");
        assert!(text.contains("123"));
    }

    #[tokio::test]
    async fn cache_round_trips_through_the_store_and_clears() {
        let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        let cache = TokenCache::new(store.clone());
        assert!(cache.get().await.unwrap().is_none());
        cache.set(sample()).await.unwrap();

        // A fresh cache over the same store sees the persisted tokens.
        let again = TokenCache::new(store.clone());
        let loaded = again.get().await.unwrap().unwrap();
        assert_eq!(loaded.refresh_token, "refresh-token-sample-0002");
        assert!(!loaded.is_expired(60));

        cache.clear().await.unwrap();
        assert!(store.get(OAUTH_TOKENS).unwrap().is_none());
        assert!(cache.get().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn damaged_store_content_gives_a_clean_error() {
        let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        store
            .set(OAUTH_TOKENS, &Secret::new("not json at all"))
            .unwrap();
        let err = TokenCache::new(store).get().await.unwrap_err().to_string();
        assert!(err.contains("roblox_login"), "{err}");
        assert!(!err.contains("not json"), "{err}");
    }

    #[test]
    fn expiry_math() {
        let mut t = sample();
        t.access_token_expires_at = now_secs() + 30;
        assert!(t.is_expired(60));
        assert!(t.seconds_left() <= 30);
        t.access_token_expires_at = 0;
        assert_eq!(t.seconds_left(), 0);
    }
}
