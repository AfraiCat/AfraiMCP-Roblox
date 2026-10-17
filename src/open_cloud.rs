//! Thin client for the Roblox Open Cloud Assets + Inventory APIs.
//!
//! Credentials come from the [`AuthManager`] (API key by default, OAuth
//! optional) and are attached per request, so a long-running poll never uses
//! an expired token. Designed to surface useful error messages back to the MCP
//! caller (Roblox's API error bodies are not always self-explanatory) and to
//! handle the asynchronous upload pattern: POST kicks off an operation, then we
//! poll for completion.
//!
//! There is deliberately no function here that uploads a file from a path:
//! [`OpenCloudClient::start_upload`] only accepts an [`ApprovedUpload`], which
//! the upload flow creates after the signed policy, the confirmed plan, the
//! rate limit and the file hash all check out.

use crate::asset_types::ValidatedFile;
use crate::auth::AuthManager;
use crate::policy::Creator as PolicyCreator;
use crate::upload_flow::ApprovedUpload;
use color_eyre::eyre::{eyre, Result, WrapErr};
use reqwest::multipart;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

impl From<&PolicyCreator> for Creator {
    fn from(creator: &PolicyCreator) -> Self {
        match creator {
            PolicyCreator::User(id) => Creator {
                user_id: Some(id.clone()),
                group_id: None,
            },
            PolicyCreator::Group(id) => Creator {
                user_id: None,
                group_id: Some(id.clone()),
            },
        }
    }
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
    auth: Arc<AuthManager>,
}

impl OpenCloudClient {
    pub fn new(auth: Arc<AuthManager>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("reqwest client builder is infallible with default settings"),
            auth,
        }
    }

    /// The default creator (OAuth only; an API key has none).
    async fn user_id(&self) -> Result<String> {
        self.auth.user_id().await
    }

    /// Send the create request for an approved upload and return the
    /// operation path (`operations/<id>`). The caller records the path in the
    /// audit log before polling. The create POST is never retried: a retry
    /// could create the asset twice.
    pub async fn start_upload(&self, approved: &ApprovedUpload) -> Result<String> {
        let request_json = serde_json::to_string(&UploadRequest {
            asset_type: approved.kind.api_name().to_string(),
            display_name: approved.display_name.clone(),
            description: approved.description.clone(),
            creation_context: CreationContext {
                creator: Creator::from(&approved.creator.creator),
            },
        })?;

        // Roblox's multipart form expects exactly two fields: "request" (JSON
        // metadata as a plain text part) and "fileContent" (the file).
        let form = multipart::Form::new().text("request", request_json).part(
            "fileContent",
            file_part(&approved.validated, approved.bytes.clone())?,
        );

        let url = format!("{ASSETS_BASE}/assets");
        let resp = self
            .auth
            .apply(self.http.post(&url))
            .await?
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
        Ok(op.path)
    }

    /// Poll the operations endpoint until `done=true`, returning the final
    /// `response` object (or surfacing the `error` object).
    pub async fn finish_operation(
        &self,
        operation_path: &str,
        timeout_secs: u64,
    ) -> Result<serde_json::Value> {
        let url = format!("{ASSETS_BASE}/{operation_path}");
        let mut waited = 0u64;
        let mut delay_ms: u64 = 500;
        loop {
            // Credentials are applied per poll so an OAuth token that expires
            // mid-wait is refreshed.
            let resp = self
                .auth
                .apply(self.http.get(&url))
                .await?
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
        let url = format!("{ASSETS_BASE}/assets/{asset_id}");
        let resp = self.auth.apply(self.http.get(&url)).await?.send().await?;
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
        let resp = self.auth.apply(self.http.get(&url)).await?.send().await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Creator as C;

    #[test]
    fn the_creator_is_serialized_as_exactly_one_id() {
        let user = serde_json::to_value(Creator::from(&C::User("1".into()))).unwrap();
        assert_eq!(user, serde_json::json!({ "userId": "1" }));
        let group = serde_json::to_value(Creator::from(&C::Group("2".into()))).unwrap();
        assert_eq!(group, serde_json::json!({ "groupId": "2" }));
    }

    #[test]
    fn the_request_json_matches_the_documented_shape() {
        let request = UploadRequest {
            asset_type: "Model".into(),
            display_name: "Fox".into(),
            description: String::new(),
            creation_context: CreationContext {
                creator: Creator::from(&C::User("111".into())),
            },
        };
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "assetType": "Model",
                "displayName": "Fox",
                "description": "",
                "creationContext": { "creator": { "userId": "111" } }
            })
        );
    }
}
