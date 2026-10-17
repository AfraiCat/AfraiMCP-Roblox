//! Persistent storage for Roblox OAuth tokens.
//!
//! Tokens live in a JSON file under the OS-appropriate config directory
//! (Linux: ~/.config/rbx-studio-mcp/, macOS: ~/Library/Application Support/...,
//! Windows: %APPDATA%/rbx-studio-mcp/). On Unix the file is chmod 0600 so
//! other users on the machine can't read it. We never persist the client
//! secret here — that comes from the environment at runtime.

use color_eyre::eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const APP_DIR: &str = "rbx-studio-mcp";
const TOKEN_FILE: &str = "oauth-tokens.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl StoredTokens {
    /// True if the access token has less than `skew` seconds left.
    pub fn is_expired(&self, skew_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Refresh proactively rather than letting the API return a 401.
        self.access_token_expires_at <= now.saturating_add(skew_secs)
    }
}

fn config_dir() -> Result<PathBuf> {
    let base =
        dirs::config_dir().ok_or_else(|| eyre!("Could not determine OS config directory"))?;
    Ok(base.join(APP_DIR))
}

fn token_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(TOKEN_FILE))
}

/// Read tokens from disk. Returns `Ok(None)` if no token file exists yet —
/// callers should interpret that as "user hasn't logged in".
pub fn load() -> Result<Option<StoredTokens>> {
    let path = token_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(&path).wrap_err_with(|| format!("Reading token file at {}", path.display()))?;
    let tokens: StoredTokens = serde_json::from_slice(&bytes)
        .wrap_err_with(|| format!("Parsing token file at {}", path.display()))?;
    Ok(Some(tokens))
}

/// Write tokens atomically (write-to-temp-then-rename) so a crash mid-write
/// can't leave a half-written file that fails to parse.
pub fn save(tokens: &StoredTokens) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir).wrap_err_with(|| format!("Creating config dir {}", dir.display()))?;
    let final_path = dir.join(TOKEN_FILE);
    let tmp_path = dir.join(format!("{TOKEN_FILE}.tmp"));

    let json = serde_json::to_vec_pretty(tokens)?;
    fs::write(&tmp_path, &json)
        .wrap_err_with(|| format!("Writing token file at {}", tmp_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        if let Err(e) = fs::set_permissions(&tmp_path, perms) {
            tracing::warn!("Could not set 0600 perms on token file: {e}");
        }
    }

    fs::rename(&tmp_path, &final_path)
        .wrap_err_with(|| format!("Renaming token file to {}", final_path.display()))?;
    Ok(())
}

/// Remove the token file. Used by `roblox_logout`. Missing file is not an error.
pub fn clear() -> Result<()> {
    let path = token_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).wrap_err_with(|| format!("Removing {}", path.display())),
    }
}

/// In-memory cache so we don't hit the filesystem on every API call.
/// Wrapped in a Mutex because the MCP server is multi-threaded and a token
/// refresh can race with a concurrent read. The lock is held only across
/// disk reads/writes; the actual HTTP refresh runs without the lock held.
pub struct TokenCache {
    inner: Mutex<Option<StoredTokens>>,
}

impl TokenCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// Get the currently cached tokens, loading from disk on first access.
    pub async fn get(&self) -> Result<Option<StoredTokens>> {
        let mut guard = self.inner.lock().await;
        if guard.is_none() {
            *guard = load()?;
        }
        Ok(guard.clone())
    }

    /// Replace the cached tokens and persist to disk.
    pub async fn set(&self, tokens: StoredTokens) -> Result<()> {
        save(&tokens)?;
        let mut guard = self.inner.lock().await;
        *guard = Some(tokens);
        Ok(())
    }

    /// Drop tokens from memory and disk.
    pub async fn clear(&self) -> Result<()> {
        clear()?;
        let mut guard = self.inner.lock().await;
        *guard = None;
        Ok(())
    }
}
