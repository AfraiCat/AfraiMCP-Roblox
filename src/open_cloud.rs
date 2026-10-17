//! Thin client for the Roblox Open Cloud Assets + Inventory APIs.
//!
//! Uses the OAuth access token managed by `oauth.rs`. Designed to surface
//! useful error messages back to the MCP caller (Roblox's API error bodies
//! are not always self-explanatory) and to handle the asynchronous upload
//! pattern: POST kicks off an operation, then we poll for completion.

use crate::asset_types::{self, AssetKind, ValidatedFile};
use crate::oauth::{ensure_access_token, OAuthConfig};
use crate::token_store::TokenCache;
use color_eyre::eyre::{eyre, Result, WrapErr};
use reqwest::multipart;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;

const ASSETS_BASE: &str = "https://apis.roblox.com/assets/v1";
const CLOUD_V2_BASE: &str = "https://apis.roblox.com/cloud/v2";

#[derive(Debug, Serialize)]
struct Creator {
    /// Either userId or groupId is set, never both.
    #[serde(skip_serializing_if = "Option::is_none", rename = "userId")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "groupId")]
    group_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreationContext {
    creator: Creator,
}

/// JSON metadata that accompanies the file in the multipart upload.
#[derive(Debug, Serialize)]
struct UploadRequest {
    #[serde(rename = "assetType")]
    asset_type: String,
    #[serde(rename = "displayName")]
    display_name: String,
    description: String,
    #[serde(rename = "creationContext")]
    creation_context: CreationContext,
}

#[derive(Debug, Deserialize)]
struct OperationResponse {
    /// Looks like "operations/<id>".
    path: String,
    done: Option<bool>,
    response: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

pub struct OpenCloudClient {
    http: reqwest::Client,
    cache: std::sync::Arc<TokenCache>,
    config: OAuthConfig,
}

impl OpenCloudClient {
    pub fn new(cache: std::sync::Arc<TokenCache>, config: OAuthConfig) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("reqwest client builder is infallible with default settings"),
            cache,
            config,
        }
    }

    /// Get a valid access token (refreshing if needed).
    async fn token(&self) -> Result<String> {
        let tokens = ensure_access_token(&self.cache, &self.config).await?;
        Ok(tokens.access_token)
    }

    async fn user_id(&self) -> Result<String> {
        let tokens = ensure_access_token(&self.cache, &self.config).await?;
        tokens
            .user_id
            .ok_or_else(|| eyre!("No user id captured during login; please run roblox_login again"))
    }

    /// Upload a new asset from a local file. Blocks until the operation
    /// completes (or `poll_timeout` elapses), returning the new asset
    /// metadata.
    pub async fn upload_asset(&self, args: UploadArgs) -> Result<serde_json::Value> {
        let kind = AssetKind::parse(&args.asset_type)?;
        let path = PathBuf::from(&args.file_path);
        let file_meta = tokio::fs::metadata(&path)
            .await
            .wrap_err_with(|| format!("Reading file metadata for {}", path.display()))?;
        asset_types::validate_size(kind, file_meta.len())?;

        let creator = match (args.group_id.as_deref(), args.user_id.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(eyre!(
                    "Pass either userId or groupId, not both. Omit both to upload as the \
                     currently-logged-in user."
                ));
            }
            (Some(g), None) => Creator {
                user_id: None,
                group_id: Some(g.to_string()),
            },
            (None, Some(u)) => Creator {
                user_id: Some(u.to_string()),
                group_id: None,
            },
            (None, None) => Creator {
                user_id: Some(self.user_id().await?),
                group_id: None,
            },
        };

        let request_json = serde_json::to_string(&UploadRequest {
            asset_type: kind.api_name().to_string(),
            display_name: args.display_name.clone(),
            description: args.description.clone().unwrap_or_default(),
            creation_context: CreationContext { creator },
        })?;

        let bytes = tokio::fs::read(&path)
            .await
            .wrap_err_with(|| format!("Reading file {}", path.display()))?;
        let file = asset_types::validate_upload(kind, &path.to_string_lossy(), &bytes)?;

        // Roblox's multipart form expects exactly two fields: "request" (JSON
        // metadata as a plain text part) and "fileContent" (the file).
        let form = multipart::Form::new()
            .text("request", request_json)
            .part("fileContent", file_part(&file, bytes)?);

        let token = self.token().await?;
        let url = format!("{ASSETS_BASE}/assets");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .multipart(form)
            .send()
            .await
            .wrap_err("POST /assets/v1/assets")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(eyre!(
                "Asset upload failed ({status}): {body}. Common causes: missing asset:write \
                 scope, asset_type/file mismatch, or moderation rejection."
            ));
        }
        let op: OperationResponse = serde_json::from_str(&body)
            .wrap_err_with(|| format!("Parsing operation response: {body}"))?;

        self.poll_operation(&op.path, args.poll_timeout_secs.unwrap_or(60))
            .await
    }

    /// Update the binary contents of an existing asset. Used by `update_asset`.
    pub async fn update_asset_content(
        &self,
        asset_id: &str,
        file_path: &Path,
        poll_timeout_secs: u64,
    ) -> Result<serde_json::Value> {
        let meta = tokio::fs::metadata(file_path)
            .await
            .wrap_err_with(|| format!("Reading file metadata for {}", file_path.display()))?;
        asset_types::validate_size(AssetKind::Model, meta.len())?;
        let bytes = tokio::fs::read(file_path)
            .await
            .wrap_err_with(|| format!("Reading file {}", file_path.display()))?;
        let file = asset_types::validate_content_update(&file_path.to_string_lossy(), &bytes)?;

        // Per the Roblox docs, content updates use the same multipart shape
        // (just no creationContext) against PATCH /assets/{id}.
        let request_json = serde_json::json!({}).to_string();
        let form = multipart::Form::new()
            .text("request", request_json)
            .part("fileContent", file_part(&file, bytes)?);

        let token = self.token().await?;
        let url = format!("{ASSETS_BASE}/assets/{asset_id}");
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(&token)
            .multipart(form)
            .send()
            .await
            .wrap_err("PATCH /assets/v1/assets/{id}")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(eyre!(
                "Asset update failed ({status}): {body}. The asset must be owned by the \
                 authorized user/group, and you must hold asset:write."
            ));
        }
        let op: OperationResponse = serde_json::from_str(&body)
            .wrap_err_with(|| format!("Parsing operation response: {body}"))?;
        self.poll_operation(&op.path, poll_timeout_secs).await
    }

    /// Poll the operations endpoint until `done=true`, returning the final
    /// `response` object (or surfacing the `error` object).
    async fn poll_operation(
        &self,
        operation_path: &str,
        timeout_secs: u64,
    ) -> Result<serde_json::Value> {
        let token = self.token().await?;
        let url = format!("{ASSETS_BASE}/{operation_path}");
        let mut waited = 0u64;
        let mut delay_ms: u64 = 500;
        loop {
            let resp = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .await
                .wrap_err("GET /assets/v1/operations/{id}")?;
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                return Err(eyre!("Polling operation failed ({status}): {body}"));
            }
            let op: OperationResponse = serde_json::from_str(&body)
                .wrap_err_with(|| format!("Parsing operation poll response: {body}"))?;

            if let Some(err) = op.error {
                return Err(eyre!("Operation failed: {err}"));
            }
            if op.done.unwrap_or(false) {
                return Ok(op.response.unwrap_or(serde_json::Value::Null));
            }

            sleep(Duration::from_millis(delay_ms)).await;
            waited = waited.saturating_add(delay_ms / 1000);
            // Exponential-ish backoff capped at 4 seconds between polls.
            delay_ms = (delay_ms * 2).min(4_000);
            if waited >= timeout_secs {
                return Err(eyre!(
                    "Operation did not complete within {timeout_secs}s. The upload may still \
                     be processing; check the Creator Dashboard or retry with get_asset_info."
                ));
            }
        }
    }

    /// GET /assets/v1/assets/{id} — return raw JSON as-is.
    pub async fn get_asset_info(&self, asset_id: &str) -> Result<serde_json::Value> {
        let token = self.token().await?;
        let url = format!("{ASSETS_BASE}/assets/{asset_id}");
        let resp = self.http.get(&url).bearer_auth(&token).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(eyre!("get_asset_info failed ({status}): {body}"));
        }
        Ok(serde_json::from_str(&body)?)
    }

    /// GET /cloud/v2/users/{userId}/inventory-items.
    /// Defaults to the currently-logged-in user. `filter` is passed through
    /// verbatim if provided.
    pub async fn list_inventory(
        &self,
        user_id: Option<&str>,
        page_size: Option<u32>,
        page_token: Option<&str>,
        filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        let uid_owned;
        let uid = match user_id {
            Some(u) => u,
            None => {
                uid_owned = self.user_id().await?;
                uid_owned.as_str()
            }
        };
        let token = self.token().await?;
        let mut url = format!("{CLOUD_V2_BASE}/users/{uid}/inventory-items");
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(p) = page_size {
            params.push(("maxPageSize", p.to_string()));
        }
        if let Some(t) = page_token {
            params.push(("pageToken", t.to_string()));
        }
        if let Some(f) = filter {
            params.push(("filter", f.to_string()));
        }
        if !params.is_empty() {
            let q: String = params
                .iter()
                .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&q);
        }
        let resp = self.http.get(&url).bearer_auth(&token).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(eyre!("list_inventory failed ({status}): {body}"));
        }
        Ok(serde_json::from_str(&body)?)
    }
}

/// Build the `fileContent` multipart part with the explicit content type from
/// the validated format (never guessed from the file name).
fn file_part(file: &ValidatedFile, bytes: Vec<u8>) -> Result<multipart::Part> {
    multipart::Part::bytes(bytes)
        .file_name(file.file_name.clone())
        .mime_str(file.content_type)
        .wrap_err("Building multipart file part")
}

pub struct UploadArgs {
    pub file_path: String,
    pub asset_type: String,
    pub display_name: String,
    pub description: Option<String>,
    /// Override creator. Defaults to the logged-in user.
    pub user_id: Option<String>,
    pub group_id: Option<String>,
    pub poll_timeout_secs: Option<u64>,
}
