//! Roblox OAuth 2.0 (Authorization Code + PKCE) for desktop/CLI clients.
//!
//! ### Flow
//!
//! 1. We generate a random `state` and a PKCE `code_verifier`+`code_challenge`.
//! 2. We open the user's browser to Roblox's authorize endpoint with our
//!    `client_id`, the `code_challenge`, our `redirect_uri`, and the requested
//!    scopes (`asset:read asset:write openid profile`).
//! 3. We spin up a tiny loopback HTTP server on the registered redirect port,
//!    wait for the redirect, verify `state`, and capture the auth `code`.
//! 4. We POST `code + client_id + client_secret + code_verifier` to Roblox's
//!    token endpoint, getting back an `access_token`, `refresh_token`,
//!    `expires_in`, and (with the `openid` scope) an `id_token`.
//! 5. We hit `/oauth/v1/userinfo` once to capture the user's `sub` (their
//!    Roblox user ID) so the upload tool can populate `creator.userId`.
//!
//! Token refresh runs the same token endpoint with `grant_type=refresh_token`
//! and writes the new tokens back via the `TokenCache`.
//!
//! ### Redirect URI
//!
//! Roblox does *not* honor RFC 8252 wildcard ports — the redirect URI must
//! be registered exactly in the Creator Dashboard. We use a single fixed
//! port (`OAUTH_CALLBACK_PORT`) so users only need to register one URI.

use crate::secret_store::{Secret, SecretStore, OAUTH_CLIENT_SECRET};
use crate::token_store::{StoredTokens, TokenCache};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use color_eyre::eyre::{eyre, Result, WrapErr};
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tokio::time::timeout;

pub const OAUTH_CALLBACK_PORT: u16 = 44756;
const REDIRECT_URI: &str = "http://localhost:44756/callback";

const AUTHORIZE_URL: &str = "https://apis.roblox.com/oauth/v1/authorize";
const TOKEN_URL: &str = "https://apis.roblox.com/oauth/v1/token";
const USERINFO_URL: &str = "https://apis.roblox.com/oauth/v1/userinfo";

const DEFAULT_SCOPES: &str = "openid profile asset:read asset:write";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes for the user to authorize

/// OAuth app credentials. The client id is not a secret and comes from
/// `ROBLOX_OAUTH_CLIENT_ID`; the client secret is read from the secret store
/// (store it with `rbx-studio-mcp set-key --kind oauth-client-secret`), never
/// from an environment variable or MCP config. `Debug` prints no secret.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: Secret,
}

impl OAuthConfig {
    /// Load the OAuth app credentials. The error says what is missing so the
    /// caller can tell the user how to set it up.
    pub fn load(store: &dyn SecretStore) -> Result<Self> {
        let client_id = std::env::var("ROBLOX_OAUTH_CLIENT_ID")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| eyre!("ROBLOX_OAUTH_CLIENT_ID is not set (OAuth is optional; an API key is the default)"))?;
        let client_secret = store.get(OAUTH_CLIENT_SECRET)?.ok_or_else(|| {
            eyre!(
                "no OAuth client secret is stored; run `rbx-studio-mcp set-key --kind \
                 oauth-client-secret` in a terminal"
            )
        })?;
        Ok(Self {
            client_id,
            client_secret,
        })
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    scope: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    sub: String,
}

/// PKCE helper pair. `verifier` is sent on the token-exchange call; `challenge`
/// is sent on the authorize redirect.
struct PkcePair {
    verifier: String,
    challenge: String,
}

fn generate_pkce() -> PkcePair {
    // RFC 7636 says the verifier must be 43-128 chars of [A-Z / a-z / 0-9 / - / . / _ / ~].
    // 64 chars of alphanumeric stays well inside that grammar.
    let verifier: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    PkcePair {
        verifier,
        challenge,
    }
}

fn random_state() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// HTML payload shown in the browser after a successful callback. Plain text
/// "you can close this tab" so we don't have to ship CSS.
const SUCCESS_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Roblox MCP — Authorized</title></head>
<body style="font-family: -apple-system, sans-serif; padding: 40px; text-align: center;">
<h2>You're signed in.</h2>
<p>You can close this tab and return to your MCP client.</p>
</body></html>"#;

const ERROR_HTML_PREFIX: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Roblox MCP — Error</title></head>
<body style="font-family: -apple-system, sans-serif; padding: 40px; text-align: center;">
<h2>Authorization failed.</h2>
<p>"#;
const ERROR_HTML_SUFFIX: &str = r#"</p></body></html>"#;

/// Result captured from the loopback callback. Either we got a code or
/// Roblox redirected us back with an `error` query param.
struct CallbackResult {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Bind a TCP listener on the fixed callback port, wait for the first request,
/// parse the query string, write back a small HTML page, and return.
async fn await_callback() -> Result<CallbackResult> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = format!("127.0.0.1:{OAUTH_CALLBACK_PORT}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .wrap_err_with(|| {
            format!(
                "Couldn't bind OAuth callback listener on {addr}. Is another login already in \
                 progress, or is something else using port {OAUTH_CALLBACK_PORT}?"
            )
        })?;

    let (mut socket, _) = listener.accept().await?;

    // Read the request line; we only care about the GET path + query string.
    // 8 KB is plenty for any Roblox redirect.
    let mut buf = [0u8; 8192];
    let n = socket.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // First line: "GET /callback?code=...&state=... HTTP/1.1"
    let first_line = request.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let _method = parts.next();
    let path_and_query = parts.next().unwrap_or("");
    let query = path_and_query.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut code = None;
    let mut state = None;
    let mut error = None;
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        let decoded = urlencoding::decode(v)
            .map(|s| s.into_owned())
            .unwrap_or_default();
        match k {
            "code" => code = Some(decoded),
            "state" => state = Some(decoded),
            "error" => error = Some(decoded),
            _ => {}
        }
    }

    let body = if error.is_some() || code.is_none() {
        let msg = error
            .clone()
            .unwrap_or_else(|| "No authorization code in callback".to_string());
        format!("{ERROR_HTML_PREFIX}{msg}{ERROR_HTML_SUFFIX}")
    } else {
        SUCCESS_HTML.to_string()
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    socket.write_all(response.as_bytes()).await.ok();
    socket.shutdown().await.ok();

    Ok(CallbackResult { code, state, error })
}

/// Build the Roblox authorize URL with all required query params.
fn build_authorize_url(config: &OAuthConfig, challenge: &str, state: &str) -> String {
    let scope = urlencoding::encode(DEFAULT_SCOPES);
    let redirect = urlencoding::encode(REDIRECT_URI);
    format!(
        "{AUTHORIZE_URL}?\
         client_id={client_id}&\
         redirect_uri={redirect}&\
         scope={scope}&\
         response_type=code&\
         code_challenge={challenge}&\
         code_challenge_method=S256&\
         state={state}",
        client_id = urlencoding::encode(&config.client_id),
    )
}

/// Exchange an authorization code for tokens, then fetch userinfo to capture
/// the user id. Returns a fully-populated `StoredTokens`.
async fn exchange_code(
    http: &reqwest::Client,
    config: &OAuthConfig,
    code: &str,
    code_verifier: &str,
) -> Result<StoredTokens> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.expose()),
        ("code_verifier", code_verifier),
    ];

    let resp = http
        .post(TOKEN_URL)
        .form(&form)
        .send()
        .await
        .wrap_err("POST to Roblox token endpoint")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(eyre!(
            "Token exchange failed ({status}): {body}. Check that your client_id/client_secret \
             are correct and that {REDIRECT_URI} is registered as a redirect URI in the Creator \
             Dashboard."
        ));
    }
    let parsed: TokenResponse =
        serde_json::from_str(&body).wrap_err_with(|| format!("Parsing token response: {body}"))?;

    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + parsed.expires_in;

    // Best-effort userinfo lookup. If it fails we still return tokens; the
    // upload tool will surface a clearer error if it needs a user id.
    let user_id = fetch_userinfo(http, &parsed.access_token).await.ok();

    Ok(StoredTokens {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        access_token_expires_at: expires_at,
        user_id,
        scope: parsed.scope,
    })
}

async fn fetch_userinfo(http: &reqwest::Client, access_token: &str) -> Result<String> {
    let resp = http
        .get(USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(eyre!("userinfo failed ({status}): {body}"));
    }
    let parsed: UserInfo = serde_json::from_str(&body)?;
    Ok(parsed.sub)
}

/// Run the full interactive login flow. Returns the tokens it just stored.
/// `cache.set()` is called on success so subsequent calls can use them.
pub async fn login(cache: Arc<TokenCache>, config: &OAuthConfig) -> Result<StoredTokens> {
    let pkce = generate_pkce();
    let state = random_state();
    let url = build_authorize_url(config, &pkce.challenge, &state);

    // Spawn the callback listener BEFORE we open the browser so there's no
    // race where the browser hits the port before we're listening.
    let (callback_tx, callback_rx) = oneshot::channel::<Result<CallbackResult>>();
    tokio::spawn(async move {
        let result = await_callback().await;
        let _ = callback_tx.send(result);
    });

    // Best-effort browser open. If it fails, print the URL — the user can
    // copy/paste it into their browser manually.
    if let Err(e) = open::that(&url) {
        tracing::warn!(
            "Could not auto-open browser ({e}). Open this URL manually to authorize: {url}"
        );
        eprintln!(
            "\nCould not auto-open your browser. Open this URL manually to authorize:\n{url}\n"
        );
    }

    let callback = timeout(LOGIN_TIMEOUT, callback_rx)
        .await
        .map_err(|_| eyre!("Login timed out after {} seconds", LOGIN_TIMEOUT.as_secs()))?
        .map_err(|e| eyre!("Callback channel dropped: {e}"))?
        .map_err(|e| eyre!("Callback listener failed: {e}"))?;

    if let Some(err) = callback.error {
        return Err(eyre!("Roblox returned an OAuth error: {err}"));
    }
    let code = callback
        .code
        .ok_or_else(|| eyre!("OAuth callback did not include an authorization code"))?;
    let returned_state = callback.state.unwrap_or_default();
    if returned_state != state {
        return Err(eyre!(
            "OAuth state mismatch (possible CSRF). Expected '{state}', got '{returned_state}'"
        ));
    }

    let http = reqwest::Client::new();
    let tokens = exchange_code(&http, config, &code, &pkce.verifier).await?;
    cache.set(tokens.clone()).await?;
    Ok(tokens)
}

/// Exchange a refresh token for a fresh access token.
async fn refresh(
    http: &reqwest::Client,
    config: &OAuthConfig,
    refresh_token: &str,
) -> Result<TokenResponse> {
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.expose()),
    ];
    let resp = http.post(TOKEN_URL).form(&form).send().await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(eyre!(
            "Refresh token request failed ({status}): {body}. The user may need to log in again."
        ));
    }
    Ok(serde_json::from_str(&body)?)
}

/// Get a valid access token, refreshing on demand. Returns an error if no
/// tokens are stored (user hasn't logged in) or if refresh fails (the user
/// needs to re-authorize).
pub async fn ensure_access_token(cache: &TokenCache, config: &OAuthConfig) -> Result<StoredTokens> {
    let tokens = cache
        .get()
        .await?
        .ok_or_else(|| eyre!("Not logged in. Call roblox_login first."))?;

    // 60s skew so we don't hand out a token that's about to expire mid-request.
    if !tokens.is_expired(60) {
        return Ok(tokens);
    }

    let http = reqwest::Client::new();
    let refreshed = refresh(&http, config, &tokens.refresh_token).await?;
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + refreshed.expires_in;

    let new_tokens = StoredTokens {
        access_token: refreshed.access_token,
        refresh_token: refreshed.refresh_token,
        access_token_expires_at: expires_at,
        user_id: tokens.user_id, // keep the cached user id; sub doesn't change
        scope: refreshed.scope.or(tokens.scope),
    };
    cache.set(new_tokens.clone()).await?;
    Ok(new_tokens)
}
