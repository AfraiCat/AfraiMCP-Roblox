//! Runs an [`ApprovedBatch`] one file at a time.
//!
//! The executor owns the sequencing and the audit trail; everything that
//! touches the outside world (the rate-limit window, the clock, Open Cloud)
//! sits behind [`BatchBackend`], so tests drive it with a fake and never
//! reach a network.
//!
//! For each file, in sorted order: wait for a rate-limit slot (sleeping until
//! the sliding window has room), re-verify the file, start the upload, record
//! `upload_started`, wait for the operation, record `upload_finished` or
//! `upload_failed`. Files that were never attempted are reported
//! `not_started`.
//!
//! `maxWait` bounds the time spent waiting for the rate limit and the time at
//! which a new file may start: a file is not started if its slot would only
//! open after the budget is used up. An upload that is already running is
//! polled to completion (the client's own 60 second poll limit), so the total
//! can exceed the budget by at most that.

use super::batch::BatchItem;
use super::*;
use std::future::Future;

/// What to do after a file fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OnError {
    Stop,
    Continue,
}

impl OnError {
    /// `"stop"` (default) or `"continue"`.
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            None | Some("stop") => Ok(OnError::Stop),
            Some("continue") => Ok(OnError::Continue),
            Some(other) => Err(eyre!(
                "onError must be \"stop\" or \"continue\", not \"{other}\""
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            OnError::Stop => "stop",
            OnError::Continue => "continue",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Uploaded,
    Failed,
    NotStarted,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemResult {
    pub file: String,
    pub status: ItemStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moderation_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ItemResult {
    fn new(file: &str, status: ItemStatus) -> Self {
        Self {
            file: file.to_string(),
            status,
            asset_id: None,
            operation: None,
            moderation_state: None,
            error: None,
        }
    }
}

/// The outcome of a whole batch.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchResult {
    pub batch_id: String,
    pub on_error: OnError,
    pub items: Vec<ItemResult>,
    pub uploaded: usize,
    pub failed: usize,
    pub not_started: usize,
    pub elapsed_seconds: f64,
    /// Why files were left `not_started`, if any were.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_because: Option<String>,
    /// Audit-log problems met along the way (the log fails closed: a write
    /// failure stops the batch).
    pub audit_warnings: Vec<String>,
}

/// Everything the executor needs from the outside world.
pub trait BatchBackend: Sync {
    /// Take a rate-limit slot, or say how long until one is free.
    fn try_slot(&self) -> Result<(), Duration>;
    /// Re-read and re-verify item `index` right before it is sent.
    fn prepare(&self, index: usize) -> impl Future<Output = Result<ApprovedUpload>> + Send;
    /// Send the create request; returns the operation path.
    fn start(&self, approved: &ApprovedUpload) -> impl Future<Output = Result<String>> + Send;
    /// Wait for the operation; returns the final response.
    fn finish(&self, operation: &str) -> impl Future<Output = Result<serde_json::Value>> + Send;
    fn record(&self, entry: AuditEntry) -> Result<()>;
    /// Time since the batch started.
    fn elapsed(&self) -> Duration;
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
}

fn entry(event: &str, batch: &super::ApprovedBatch, item: &BatchItem) -> AuditEntry {
    AuditEntry {
        event: event.to_string(),
        plan_id: Some(batch.batch_id.clone()),
        path: Some(item.path.display().to_string()),
        sha256: Some(item.sha256.clone()),
        bytes: Some(item.bytes),
        asset_type: Some(item.kind.api_name().to_string()),
        creator: Some(batch.creator.describe()),
        ..Default::default()
    }
}

/// Upload every item of an approved batch, in order. Never panics on a
/// per-file problem; every file ends up in the result.
pub async fn run_batch<B: BatchBackend>(
    backend: &B,
    batch: &super::ApprovedBatch,
    on_error: OnError,
    max_wait: Duration,
) -> BatchResult {
    let mut items: Vec<ItemResult> = Vec::with_capacity(batch.items.len());
    let mut halt: Option<String> = None;
    let mut warnings: Vec<String> = Vec::new();

    // Records an audit step; a failure stops the rest of the batch.
    let note = |result: Result<()>, halt: &mut Option<String>, warnings: &mut Vec<String>| {
        if let Err(e) = result {
            warnings.push(e.to_string());
            halt.get_or_insert_with(|| {
                "the audit log could not be written, so the batch stopped (see auditWarnings)"
                    .to_string()
            });
        }
    };

    for (index, item) in batch.items.iter().enumerate() {
        let file = item.path.display().to_string();
        let not_started = |reason: &str| {
            let mut r = ItemResult::new(&file, ItemStatus::NotStarted);
            r.error = Some(reason.to_string());
            r
        };
        if let Some(reason) = &halt {
            items.push(not_started(reason));
            continue;
        }

        // Wait for a rate-limit slot, within the budget.
        let mut got_slot = false;
        while !got_slot && halt.is_none() {
            if backend.elapsed() >= max_wait {
                halt = Some(format!(
                    "the maxWaitSeconds budget ({}s) is used up",
                    max_wait.as_secs()
                ));
                break;
            }
            match backend.try_slot() {
                Ok(()) => got_slot = true,
                Err(wait) => {
                    if backend.elapsed() + wait > max_wait {
                        halt = Some(format!(
                            "waiting for the rate limit would exceed maxWaitSeconds ({}s)",
                            max_wait.as_secs()
                        ));
                    } else {
                        backend.sleep(wait).await;
                    }
                }
            }
        }
        if let Some(reason) = &halt {
            items.push(not_started(reason));
            continue;
        }

        let mut result = ItemResult::new(&file, ItemStatus::Failed);
        let outcome: Result<(), String> = async {
            let approved = backend
                .prepare(index)
                .await
                .map_err(|e| format!("not sent: {e}"))?;
            let operation = backend.start(&approved).await.map_err(|e| e.to_string())?;
            // The asset may exist from here on, so record the operation before polling.
            result.operation = Some(operation.clone());
            let mut started = entry("upload_started", batch, item);
            started.operation = Some(operation.clone());
            note(backend.record(started), &mut halt, &mut warnings);
            let response = backend.finish(&operation).await.map_err(|e| {
                format!("upload started (operation {operation}) but did not complete: {e}")
            })?;
            result.asset_id = response["assetId"].as_str().map(str::to_string);
            result.moderation_state = response["moderationResult"]["moderationState"]
                .as_str()
                .map(str::to_string);
            Ok(())
        }
        .await;

        match outcome {
            Ok(()) => {
                result.status = ItemStatus::Uploaded;
                let mut finished = entry("upload_finished", batch, item);
                finished.operation = result.operation.clone();
                finished.asset_id = result.asset_id.clone();
                finished.status = result
                    .moderation_state
                    .clone()
                    .or_else(|| Some("done".to_string()));
                note(backend.record(finished), &mut halt, &mut warnings);
            }
            Err(error) => {
                let mut failed = entry("upload_failed", batch, item);
                failed.operation = result.operation.clone();
                failed.detail = Some(error.clone());
                note(backend.record(failed), &mut halt, &mut warnings);
                result.error = Some(error);
                if on_error == OnError::Stop && halt.is_none() {
                    halt = Some(format!("onError is stop and {file} failed"));
                }
            }
        }
        items.push(result);
    }

    let count = |s: ItemStatus| items.iter().filter(|i| i.status == s).count();
    let (uploaded, failed, not_started) = (
        count(ItemStatus::Uploaded),
        count(ItemStatus::Failed),
        count(ItemStatus::NotStarted),
    );
    let elapsed = backend.elapsed();
    let summary = AuditEntry {
        event: "batch_finished".to_string(),
        plan_id: Some(batch.batch_id.clone()),
        sha256: Some(batch.aggregate_sha256.clone()),
        asset_type: Some(batch.kind_counts.clone()),
        creator: Some(batch.creator.describe()),
        status: Some(
            if failed == 0 && not_started == 0 {
                "completed"
            } else if uploaded > 0 {
                "partial"
            } else {
                "failed"
            }
            .to_string(),
        ),
        detail: Some(format!(
            "uploaded={uploaded} failed={failed} not_started={not_started} elapsed={}s onError={}",
            elapsed.as_secs(),
            on_error.label()
        )),
        ..Default::default()
    };
    if let Err(e) = backend.record(summary) {
        warnings.push(e.to_string());
    }

    BatchResult {
        batch_id: batch.batch_id.clone(),
        on_error,
        items,
        uploaded,
        failed,
        not_started,
        elapsed_seconds: (elapsed.as_secs_f64() * 10.0).round() / 10.0,
        stopped_because: halt,
        audit_warnings: warnings,
    }
}
