//! One-time terminal commands for credentials.
//!
//! Secrets are entered through a hidden prompt, never as a command-line
//! argument, environment variable or tool argument, and are stored in the
//! secret store (Windows DPAPI). Output never contains a secret.

use crate::audit::AuditLog;
use crate::auth::AuthManager;
use crate::policy::{app_dir, PolicyStore, PolicySummary};
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

/// The policy store at its real location, for the commands in `main`.
pub fn real_policy_store(store: Arc<dyn SecretStore>) -> Result<PolicyStore> {
    Ok(PolicyStore::new(app_dir()?, store))
}

/// Create the upload-policy template (everything off). Never overwrites.
pub fn policy_init(policy: &PolicyStore, out: &mut impl Write) -> Result<()> {
    let path = policy.init_template()?;
    writeln!(out, "Created {}", path.display())?;
    writeln!(out, "Uploads stay off until you edit it and approve it:")?;
    writeln!(
        out,
        "  1. set allowed_roots, creators and \"enabled\": true"
    )?;
    writeln!(out, "  2. run: rbx-studio-mcp policy sign")?;
    Ok(())
}

/// Show the policy and its signature state, without secrets.
pub fn policy_show(policy: &PolicyStore, out: &mut impl Write) -> Result<()> {
    match policy.load_verified() {
        Ok(verified) => writeln!(
            out,
            "Signature OK.\n{}",
            serde_json::to_string_pretty(&PolicySummary::from(&*verified))?
        )?,
        Err(e) => writeln!(out, "Uploads are refused: {e}")?,
    }
    Ok(())
}

/// Review and approve the policy. Needs an interactive terminal and the typed
/// word SIGN, so it can not be done by a program (an agent's shell has no
/// terminal to type into).
pub fn policy_sign(
    policy: &PolicyStore,
    interactive: bool,
    input: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<()> {
    if !interactive {
        return Err(eyre!(
            "policy sign needs an interactive terminal; run it yourself in a terminal window"
        ));
    }
    let summary = policy.preview()?;
    writeln!(
        out,
        "You are about to approve {}:",
        policy.policy_path().display()
    )?;
    writeln!(out, "{}", serde_json::to_string_pretty(&summary)?)?;
    write!(out, "Type SIGN to approve this policy: ")?;
    out.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    if answer.trim() != "SIGN" {
        return Err(eyre!("not approved; the policy was not signed"));
    }
    policy.sign()?;
    writeln!(out, "Signed. Uploads follow this policy until it changes.")?;
    Ok(())
}

/// Check the audit log chain. Fails if it does not verify.
pub fn audit_verify(store: Arc<dyn SecretStore>, out: &mut impl Write) -> Result<()> {
    let status = AuditLog::new(AuditLog::default_path()?, store).verify();
    writeln!(out, "{}", serde_json::to_string_pretty(&status)?)?;
    if status.ok {
        Ok(())
    } else {
        Err(eyre!("the audit log did not verify"))
    }
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

    fn temp_policy(json: &str) -> (PolicyStore, std::path::PathBuf) {
        let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        let dir = std::env::temp_dir().join(format!("rbx-cli-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy = PolicyStore::new(dir.clone(), store);
        std::fs::write(policy.policy_path(), json).unwrap();
        (policy, dir)
    }

    fn sign_with(policy: &PolicyStore, interactive: bool, typed: &str) -> Result<String> {
        let mut out = Vec::new();
        let result = policy_sign(policy, interactive, &mut typed.as_bytes(), &mut out);
        result.map(|()| String::from_utf8(out).unwrap())
    }

    #[test]
    fn signing_is_refused_without_a_terminal_and_without_the_typed_word() {
        let (policy, dir) = temp_policy(r#"{ "enabled": true }"#);
        let err = sign_with(&policy, false, "SIGN\n").unwrap_err().to_string();
        assert!(err.contains("interactive terminal"), "{err}");
        for typed in ["", "sign\n", "yes\n", "SIGNED\n"] {
            assert!(sign_with(&policy, true, typed).is_err(), "{typed:?}");
        }
        assert!(!policy.signature_path().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn typing_sign_in_a_terminal_signs_and_shows_the_policy_first() {
        let (policy, dir) = temp_policy(r#"{ "enabled": true, "max_bytes": 1234 }"#);
        let shown = sign_with(&policy, true, "SIGN\n").unwrap();
        assert!(shown.contains("1234"), "{shown}");
        assert!(policy.load_enabled().is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_invalid_policy_can_not_be_signed_even_with_the_typed_word() {
        let (policy, dir) = temp_policy(r#"{ "enabled": true, "typo_field": 1 }"#);
        assert!(sign_with(&policy, true, "SIGN\n").is_err());
        assert!(!policy.signature_path().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn init_creates_a_disabled_template_once_and_show_reports_unsigned() {
        let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        let dir = std::env::temp_dir().join(format!("rbx-cli-{}", uuid::Uuid::new_v4()));
        let policy = PolicyStore::new(dir.clone(), store);
        let mut out = Vec::new();
        policy_init(&policy, &mut out).unwrap();
        assert!(policy_init(&policy, &mut out).is_err());
        let mut shown = Vec::new();
        policy_show(&policy, &mut shown).unwrap();
        let shown = String::from_utf8(shown).unwrap();
        assert!(shown.contains("Uploads are refused"), "{shown}");
        let _ = std::fs::remove_dir_all(dir);
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
