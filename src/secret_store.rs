//! Secret storage behind a trait, plus the redaction helpers that keep keys
//! and tokens out of logs and error text.
//!
//! * [`Secret`] never prints its value (`Debug` is redacted, there is no
//!   `Display`); use [`Secret::expose`] at the single point of use.
//! * [`SecretStore`] has an in-memory backend (tests) and, on Windows, a DPAPI
//!   backend: values are encrypted with `CryptProtectData` (bound to the
//!   current Windows user) and the ciphertext is written under
//!   `%APPDATA%\rbx-studio-mcp\secrets\`. Nothing is stored in plaintext.
//!   Honest limit: any process running as the same Windows user can ask DPAPI
//!   to decrypt, so this protects against disk theft, backups, logs and config
//!   leaks, not against malicious code running as you.
//! * On other platforms only the in-memory store exists; the cloud tools then
//!   report that secure storage is unavailable instead of falling back to
//!   plaintext.
//! * [`redact`] masks known secrets, `Bearer`/`x-api-key`/`client_secret`
//!   style values, JWTs and long base64-looking runs. It errs on the side of
//!   hiding too much.

use color_eyre::eyre::{eyre, Result};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

/// Names of the secrets this server stores.
pub const API_KEY: &str = "open-cloud-api-key";
pub const OAUTH_CLIENT_SECRET: &str = "oauth-client-secret";
pub const OAUTH_TOKENS: &str = "oauth-tokens";
/// HMAC key that signs the upload policy; created by `policy init`/`policy sign`.
pub const POLICY_KEY: &str = "upload-policy-hmac-key";
/// `seq:hash` of the newest audit line, so a truncated or replaced log is noticed.
pub const AUDIT_HEAD: &str = "audit-head";

const REDACTED: &str = "[REDACTED]";

#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        register_for_redaction(&value);
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in characters (for "stored N characters" messages).
    pub fn len(&self) -> usize {
        self.0.chars().count()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({REDACTED})")
    }
}

pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<Secret>>;
    fn set(&self, name: &str, value: &Secret) -> Result<()>;
    fn delete(&self, name: &str) -> Result<()>;
    /// Human-readable backend name for status output.
    fn backend(&self) -> &'static str;
}

/// Names become file names in the DPAPI backend, so keep them boring.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(eyre!("invalid secret name"));
    }
    Ok(())
}

/// In-memory store: tests, and the fallback when no OS backend exists.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<HashMap<String, String>>,
    unavailable: bool,
}

impl MemoryStore {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that refuses writes and reads nothing; used on platforms
    /// without a secure backend so secrets are never kept in plaintext.
    pub fn unavailable() -> Self {
        Self {
            inner: Mutex::default(),
            unavailable: true,
        }
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, name: &str) -> Result<Option<Secret>> {
        validate_name(name)?;
        if self.unavailable {
            return Ok(None);
        }
        let map = self.inner.lock().map_err(|_| eyre!("store poisoned"))?;
        Ok(map.get(name).cloned().map(Secret::new))
    }

    fn set(&self, name: &str, value: &Secret) -> Result<()> {
        validate_name(name)?;
        if self.unavailable {
            return Err(eyre!(
                "secure secret storage is only implemented for Windows (DPAPI); refusing to \
                 store secrets in plaintext on this platform"
            ));
        }
        let mut map = self.inner.lock().map_err(|_| eyre!("store poisoned"))?;
        map.insert(name.to_string(), value.expose().to_string());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let mut map = self.inner.lock().map_err(|_| eyre!("store poisoned"))?;
        map.remove(name);
        Ok(())
    }

    fn backend(&self) -> &'static str {
        if self.unavailable {
            "unavailable (no secure backend on this platform)"
        } else {
            "memory"
        }
    }
}

/// The store used by the real server and the CLI.
pub fn default_store() -> Arc<dyn SecretStore> {
    #[cfg(windows)]
    {
        match dpapi::DpapiStore::new() {
            Ok(store) => Arc::new(store),
            Err(e) => {
                tracing::error!("DPAPI secret store unavailable: {e}");
                Arc::new(MemoryStore::unavailable())
            }
        }
    }
    #[cfg(not(windows))]
    {
        Arc::new(MemoryStore::unavailable())
    }
}

#[cfg(windows)]
pub mod dpapi {
    use super::{validate_name, Secret, SecretStore};
    use color_eyre::eyre::{eyre, Result, WrapErr};
    use std::fs;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };

    /// Extra entropy so a blob from another application's DPAPI use is not
    /// accepted as ours (not a secret).
    const ENTROPY: &[u8] = b"rbx-studio-mcp/v1";
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    pub struct DpapiStore {
        dir: PathBuf,
    }

    impl DpapiStore {
        pub fn new() -> Result<Self> {
            // `dirs` asks Windows for the Roaming AppData folder; fall back to the
            // APPDATA variable for launchers that start us with a minimal profile.
            let base = dirs::config_dir()
                .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
                .ok_or_else(|| eyre!("no config directory"))?;
            Ok(Self::with_dir(base.join("rbx-studio-mcp").join("secrets")))
        }

        pub fn with_dir(dir: PathBuf) -> Self {
            Self { dir }
        }

        fn path(&self, name: &str) -> Result<PathBuf> {
            validate_name(name)?;
            Ok(self.dir.join(format!("{name}.dpapi")))
        }
    }

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        let input = blob(plain);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: pointers reference live stack/slice data for the call; `out`
        // is filled by the OS and freed with LocalFree below.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(eyre!("CryptProtectData failed"));
        }
        // SAFETY: on success pbData points to cbData bytes allocated by the OS.
        let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        unsafe { LocalFree(out.pbData as _) };
        Ok(bytes)
    }

    fn unprotect(cipher: &[u8]) -> Result<Vec<u8>> {
        let input = blob(cipher);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(eyre!(
                "CryptUnprotectData failed (the secret was stored by a different Windows user, \
                 or the file is damaged)"
            ));
        }
        let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        // Best effort wipe of the OS-allocated plaintext before freeing it.
        unsafe {
            std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
            LocalFree(out.pbData as _);
        }
        Ok(bytes)
    }

    impl SecretStore for DpapiStore {
        fn get(&self, name: &str) -> Result<Option<Secret>> {
            let path = self.path(name)?;
            let cipher = match fs::read(&path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e).wrap_err("reading secret file"),
            };
            let plain = unprotect(&cipher)?;
            let text = String::from_utf8(plain).map_err(|_| eyre!("stored secret is not UTF-8"))?;
            Ok(Some(Secret::new(text)))
        }

        fn set(&self, name: &str, value: &Secret) -> Result<()> {
            let path = self.path(name)?;
            fs::create_dir_all(&self.dir).wrap_err("creating secrets directory")?;
            let cipher = protect(value.expose().as_bytes())?;
            let tmp = path.with_extension("dpapi.tmp");
            fs::write(&tmp, cipher).wrap_err("writing secret file")?;
            fs::rename(&tmp, &path).wrap_err("replacing secret file")?;
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<()> {
            let path = self.path(name)?;
            match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e).wrap_err("removing secret file"),
            }
        }

        fn backend(&self) -> &'static str {
            "Windows DPAPI (per-user encrypted files)"
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trip_is_encrypted_on_disk() {
            let dir = std::env::temp_dir().join(format!("rbx-dpapi-test-{}", uuid::Uuid::new_v4()));
            let store = DpapiStore::with_dir(dir.clone());
            let value = "AbCdEf0123456789+/AbCdEf0123456789+/AbCdEf0123456789+/==";
            store.set("unit-test", &Secret::new(value)).unwrap();
            let on_disk = fs::read(dir.join("unit-test.dpapi")).unwrap();
            assert!(!String::from_utf8_lossy(&on_disk).contains(value));
            assert_eq!(store.get("unit-test").unwrap().unwrap().expose(), value);
            store.delete("unit-test").unwrap();
            assert!(store.get("unit-test").unwrap().is_none());
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn handles_a_key_larger_than_credential_manager_allows() {
            let dir = std::env::temp_dir().join(format!("rbx-dpapi-test-{}", uuid::Uuid::new_v4()));
            let store = DpapiStore::with_dir(dir.clone());
            let value: String = "aB3+".repeat(1500);
            store.set("big", &Secret::new(value.clone())).unwrap();
            assert_eq!(store.get("big").unwrap().unwrap().expose(), value);
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn rejects_path_like_names() {
            let store = DpapiStore::with_dir(std::env::temp_dir());
            assert!(store.get("..\\evil").is_err());
            assert!(store.set("a/b", &Secret::new("x")).is_err());
        }
    }
}

// ---------------------------------------------------------------- redaction

fn known_secrets() -> &'static Mutex<Vec<String>> {
    static KNOWN: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    KNOWN.get_or_init(|| Mutex::new(Vec::new()))
}

/// Remember a secret value so [`redact`] masks it verbatim anywhere it shows
/// up. Values shorter than 8 characters are ignored (too many false hits).
pub fn register_for_redaction(value: &str) {
    if value.chars().count() < 8 {
        return;
    }
    if let Ok(mut known) = known_secrets().lock() {
        if !known.iter().any(|k| k == value) {
            known.push(value.to_string());
        }
    }
}

const MARKERS: [&str; 10] = [
    "x-api-key",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "client_secret",
    "access_token",
    "refresh_token",
    "id_token",
    "code_verifier",
];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-' | '.' | '~')
}

fn is_b64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_')
}

fn starts_with_ci(chars: &[char], at: usize, needle: &str) -> bool {
    let n: Vec<char> = needle.chars().collect();
    at + n.len() <= chars.len()
        && chars[at..at + n.len()]
            .iter()
            .zip(n.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Mask `marker<sep>value` pairs such as `x-api-key: abc`, `"client_secret":"abc"`,
/// `Authorization: Bearer abc`.
fn redact_markers(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        let mut matched = None;
        for m in MARKERS {
            if starts_with_ci(&chars, i, m) {
                matched = Some(m);
                break;
            }
        }
        let Some(marker) = matched else {
            out.push(chars[i]);
            i += 1;
            continue;
        };
        let marker_len = marker.chars().count();
        out.extend(&chars[i..i + marker_len]);
        let mut j = i + marker_len;
        // separators between the marker and its value
        let sep_start = j;
        while j < chars.len() && matches!(chars[j], ' ' | ':' | '=' | '"' | '\'' | '\\' | '\t') {
            j += 1;
        }
        if j == sep_start {
            // no separator: part of a longer word, not a key/value pair
            i += marker_len;
            continue;
        }
        if starts_with_ci(&chars, j, "bearer ") {
            j += "bearer ".len();
        }
        let tok_start = j;
        while j < chars.len() && is_token_char(chars[j]) {
            j += 1;
        }
        out.extend(&chars[sep_start..tok_start]);
        if j - tok_start >= 8 {
            out.push_str(REDACTED);
        } else {
            out.extend(&chars[tok_start..j]);
        }
        i = j;
    }
    out
}

/// Mask JWT-looking values and long mixed-case base64 runs (API keys, tokens).
fn redact_token_shapes(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if !is_token_char(chars[i]) {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_token_char(chars[i]) {
            i += 1;
        }
        let run = &chars[start..i];
        let text: String = run.iter().collect();
        let jwt = text.starts_with("eyJ") && text.len() >= 30;
        let b64 = run.len() >= 40 && run.iter().all(|c| is_b64_char(*c)) && {
            let upper = run.iter().any(|c| c.is_ascii_uppercase());
            let lower = run.iter().any(|c| c.is_ascii_lowercase());
            let digit = run.iter().any(|c| c.is_ascii_digit());
            upper && lower && digit
        };
        if jwt || b64 {
            out.push_str(REDACTED);
        } else {
            out.push_str(&text);
        }
    }
    out
}

/// Mask every secret-looking value in `input`.
pub fn redact(input: &str) -> String {
    let mut text = input.to_string();
    if let Ok(known) = known_secrets().lock() {
        for secret in known.iter() {
            if text.contains(secret.as_str()) {
                text = text.replace(secret.as_str(), REDACTED);
            }
        }
    }
    redact_token_shapes(&redact_markers(&text))
}

/// Writer wrapper that redacts each write; used for the tracing output.
pub struct RedactingWriter<W: Write>(pub W);

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        self.0.write_all(redact(&text).as_bytes())?;
        // Report the input length: callers must not retry a "short" write.
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const API_KEY_SAMPLE: &str =
        "Zk3fQ9xLmN2pRt7vWb4YcD8eHjK5sUaP1gXoIq6/TyCh+EzF0lBnMrVd9wSuOe3A==";

    #[test]
    fn secret_debug_never_prints_the_value() {
        let s = Secret::new("super-secret-value-123");
        assert!(!format!("{s:?}").contains("super-secret"));
    }

    #[test]
    fn known_secret_is_masked_anywhere() {
        let _ = Secret::new("my-registered-secret-0001");
        let out = redact("failed for my-registered-secret-0001 at /x");
        assert!(!out.contains("my-registered-secret-0001"));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn api_key_shaped_values_are_masked_without_registration() {
        let out = redact(&format!(
            "request failed, key {API_KEY_SAMPLE} was rejected"
        ));
        assert!(!out.contains(API_KEY_SAMPLE), "{out}");
    }

    #[test]
    fn header_and_form_markers_are_masked() {
        for input in [
            "x-api-key: abcdef123456",
            "X-API-KEY=abcdef123456",
            "Authorization: Bearer abcdef123456",
            "client_secret=abcdef123456&grant_type=refresh_token",
            "{\"access_token\":\"abcdef123456\",\"refresh_token\":\"zyxwvu987654\"}",
            "refresh_token: zyxwvu987654",
        ] {
            let out = redact(input);
            assert!(!out.contains("abcdef123456"), "{input} -> {out}");
            assert!(!out.contains("zyxwvu987654"), "{input} -> {out}");
        }
    }

    #[test]
    fn jwts_are_masked() {
        let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InNpZy0yMDIxIn0.eyJhdWQiOiJSb2Jsb3hJbnRlcm5hbCJ9.sig_part-123";
        let out = redact(&format!("token {jwt} expired"));
        assert!(!out.contains("eyJhbGci"), "{out}");
    }

    #[test]
    fn ordinary_diagnostics_survive() {
        let input = "Asset upload failed (400 Bad Request): operations/626b8c9d-703a-441a-a6c2-44a99235da2a \
                     for C:\\Main\\AI_Projects\\AfraiWorks-3D\\AfraiWorks-Copper-Fox\\asset\\AfraiWorks-Fox.glb";
        assert_eq!(redact(input), input);
        assert_eq!(redact("asset id 94652918263605"), "asset id 94652918263605");
    }

    #[test]
    fn short_marker_values_and_plain_words_are_kept() {
        assert_eq!(redact("bearer of bad news"), "bearer of bad news");
        assert_eq!(redact("authorization failed"), "authorization failed");
    }

    #[test]
    fn writer_redacts_log_lines() {
        let mut sink = Vec::new();
        {
            let mut w = RedactingWriter(&mut sink);
            w.write_all(format!("INFO sending x-api-key: {API_KEY_SAMPLE}\n").as_bytes())
                .unwrap();
        }
        let text = String::from_utf8(sink).unwrap();
        assert!(!text.contains(API_KEY_SAMPLE), "{text}");
        assert!(text.contains("INFO sending"));
    }

    #[test]
    fn memory_store_round_trip_and_unavailable_store() {
        let store = MemoryStore::new();
        store
            .set(API_KEY, &Secret::new("value-value-value"))
            .unwrap();
        assert_eq!(
            store.get(API_KEY).unwrap().unwrap().expose(),
            "value-value-value"
        );
        store.delete(API_KEY).unwrap();
        assert!(store.get(API_KEY).unwrap().is_none());

        let none = MemoryStore::unavailable();
        assert!(none.set(API_KEY, &Secret::new("x")).is_err());
        assert!(none.get(API_KEY).unwrap().is_none());
    }

    #[test]
    fn invalid_names_are_rejected() {
        let store = MemoryStore::new();
        assert!(store.get("../x").is_err());
        assert!(store.set("UPPER", &Secret::new("x")).is_err());
        assert!(store.get("").is_err());
    }
}
