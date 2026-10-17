//! One-time terminal commands for credentials.
//!
//! Secrets are entered through a hidden prompt, never as a command-line
//! argument, environment variable or tool argument, and are stored in the
//! secret store (Windows DPAPI). Output never contains a secret.

use crate::auth::AuthManager;
use crate::secret_store::{redact, Secret, SecretStore, API_KEY, OAUTH_CLIENT_SECRET};
use crate::token_store::{self, TokenCache};
use clap::ValueEnum;
use color_eyre::eyre::{eyre, Result};
use std::io::{BufRead, Write};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum KeyKind {
    /// Open Cloud API key (the default way to authenticate)
    ApiKey,
    /// OAuth app client secret (only needed for the optional OAuth login)
    OauthClientSecret,
}

impl KeyKind {
    fn secret_name(self) -> &'static str {
        match self {
            KeyKind::ApiKey => API_KEY,
            KeyKind::OauthClientSecret => OAUTH_CLIENT_SECRET,
        }
    }

    fn label(self) -> &'static str {
        match self {
            KeyKind::ApiKey => "Open Cloud API key",
            KeyKind::OauthClientSecret => "OAuth client secret",
        }
    }
}

/// Validate and store a pasted secret. Returns its length in characters.
pub fn store_secret(store: &dyn SecretStore, kind: KeyKind, raw: &str) -> Result<usize> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(eyre!("nothing was entered; nothing was stored"));
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(eyre!(
            "the value contains whitespace or control characters; paste only the key itself"
        ));
    }
    let secret = Secret::new(value);
    store.set(kind.secret_name(), &secret)?;
    Ok(secret.len())
}

pub fn set_key(store: &dyn SecretStore, kind: KeyKind) -> Result<()> {
    let value = rpassword::prompt_password(format!("Enter the {} (input hidden): ", kind.label()))?;
    let len = store_secret(store, kind, &value)?;
    println!(
        "Stored the {} ({len} characters) in: {}.",
        kind.label(),
        store.backend()
    );
    println!("Check it with: rbx-studio-mcp auth-status");
    Ok(())
}

pub fn delete_key(store: &dyn SecretStore, kind: KeyKind) -> Result<()> {
    store.delete(kind.secret_name())?;
    println!("Removed the stored {}.", kind.label());
    Ok(())
}

pub async fn auth_status(store: Arc<dyn SecretStore>) -> Result<()> {
    let cache = Arc::new(TokenCache::new(store.clone()));
    let status = AuthManager::new(store, cache).status().await;
    println!("{}", redact(&serde_json::to_string_pretty(&status)?));
    Ok(())
}

/// `y`/`yes` (any case) confirms; anything else, including empty, declines.
pub fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Import the old plaintext token file into secure storage, then ask before
/// deleting it.
pub fn migrate_tokens(
    store: &dyn SecretStore,
    input: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<()> {
    let Some(path) = token_store::import_legacy(store)? else {
        writeln!(
            out,
            "No legacy plaintext token file found; nothing to migrate."
        )?;
        return Ok(());
    };
    writeln!(
        out,
        "Imported the OAuth tokens from {} into: {}.",
        path.display(),
        store.backend()
    )?;
    write!(out, "Delete the old plaintext file now? [y/N] ")?;
    out.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    if is_yes(&answer) {
        token_store::delete_legacy_file(&path)?;
        writeln!(out, "Deleted {}.", path.display())?;
    } else {
        writeln!(
            out,
            "Kept {}. It is still plaintext; delete it yourself when ready.",
            path.display()
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::MemoryStore;

    #[test]
    fn store_secret_trims_and_stores_under_the_right_name() {
        let store = MemoryStore::new();
        let n = store_secret(&store, KeyKind::ApiKey, "  abcDEF123456789  \r\n").unwrap();
        assert_eq!(n, 15);
        assert_eq!(
            store.get(API_KEY).unwrap().unwrap().expose(),
            "abcDEF123456789"
        );
        store_secret(&store, KeyKind::OauthClientSecret, "client-secret-value").unwrap();
        assert!(store.get(OAUTH_CLIENT_SECRET).unwrap().is_some());
    }

    #[test]
    fn store_secret_rejects_empty_and_multiline_values() {
        let store = MemoryStore::new();
        assert!(store_secret(&store, KeyKind::ApiKey, "   ").is_err());
        assert!(store_secret(&store, KeyKind::ApiKey, "abc def").is_err());
        assert!(store_secret(&store, KeyKind::ApiKey, "abc\ndef").is_err());
        assert!(store.get(API_KEY).unwrap().is_none());
    }

    #[test]
    fn errors_never_echo_the_value() {
        let store = MemoryStore::unavailable();
        let err = store_secret(&store, KeyKind::ApiKey, "very-secret-value-123")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("very-secret-value"), "{err}");
    }

    #[test]
    fn only_yes_confirms_deletion() {
        assert!(is_yes("y\n"));
        assert!(is_yes("YES"));
        assert!(!is_yes(""));
        assert!(!is_yes("n"));
        assert!(!is_yes("yep"));
    }
}
