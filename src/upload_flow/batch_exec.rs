//! Runs an [`ApprovedBatch`] one file at a time.
//!
//! The executor owns the sequencing and the audit trail; everything that
//! touches the outside world (the rate-limit window, the clock, Open Cloud)
//! sits behind [`BatchBackend`], so tests drive it with a fake and never
//! reach a network.
//!
//! For each file, in sorted order: reload the signed policy (a policy or
//! creator problem ends the whole batch), wait for a rate-limit slot
//! (sleeping until the sliding window has room), re-verify the file, write
//! `upload_sending` to the audit log (if that fails the file is not sent), start
//! the upload, record `upload_started`, wait for the operation, record
//! `upload_finished` or `upload_failed`. Files that were never attempted are
//! reported `not_started`.
//!
//! `maxWait` bounds only the time spent **sleeping for the rate limit**: a file
//! is not started if its slot would only open after the sleeping budget is used
//! up. Time spent uploading and polling does not count against it. A cancelled
//! request (`is_cancelled`) stops the batch between files and interrupts the
//! rate-limit sleep; the upload in flight finishes first.

use super::batch::{BatchItem, PrepareError};
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
    /// Time spent sleeping for the rate limit (what maxWaitSeconds caps).
    pub waited_seconds: f64,
    /// Why files were left `not_started`, if any were.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_because: Option<String>,
    /// Audit-log problems met along the way (the log fails closed: a write
    /// failure stops the batch).
    pub audit_warnings: Vec<String>,
}

/// Everything the executor needs from the outside world.
pub trait BatchBackend: Sync {
    /// Reload the signed policy. `Err` is a problem for the whole batch and
    /// ends it; `Ok` is the rate limit now in force.
    fn policy_check(&self) -> Result<u32, String>;
    /// Take a rate-limit slot (`limit` per minute), or say how long until one
    /// is free.
    fn try_slot(&self, limit: u32) -> Result<(), Duration>;
    /// Re-read and re-verify item `index` right before it is sent.
    fn prepare(
        &self,
        index: usize,
    ) -> impl Future<Output = Result<ApprovedUpload, PrepareError>> + Send;
    /// Send the create request; returns the operation path.
    fn start(&self, approved: &ApprovedUpload) -> impl Future<Output = Result<String>> + Send;
    /// Wait for the operation; returns the final response.
    fn finish(&self, operation: &str) -> impl Future<Output = Result<serde_json::Value>> + Send;
    fn record(&self, entry: AuditEntry) -> Result<()>;
    /// Time since the batch started.
    fn elapsed(&self) -> Duration;
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
    /// Has the client cancelled the request?
    fn is_cancelled(&self) -> bool;
    /// Completes when the request is cancelled.
    fn cancelled(&self) -> impl Future<Output = ()> + Send;
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
    let mut waited = Duration::ZERO;

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
        if halt.is_none() && backend.is_cancelled() {
            halt = Some(CANCELLED.to_string());
        }
        if let Some(reason) = &halt {
            items.push(not_started(reason));
            continue;
        }

        // A policy or creator problem ends the batch before a slot is taken.
        let limit = match backend.policy_check() {
            Ok(limit) => limit,
            Err(why) => {
                halt = Some(format!("the batch stopped: {why}"));
                items.push(not_started(halt.as_deref().unwrap_or_default()));
                continue;
            }
        };

        // Wait for a rate-limit slot, within the sleeping budget.
        let mut got_slot = false;
        while !got_slot && halt.is_none() {
            match backend.try_slot(limit) {
                Ok(()) => got_slot = true,
                Err(wait) => {
                    if waited + wait > max_wait {
                        halt = Some(format!(
                            "waiting for the rate limit would exceed maxWaitSeconds ({}s of waiting)",
                            max_wait.as_secs()
                        ));
                    } else {
                        tokio::select! {
                            biased;
                            () = backend.cancelled() => halt = Some(CANCELLED.to_string()),
                            () = backend.sleep(wait) => waited += wait,
                        }
                    }
                }
            }
        }
        if let Some(reason) = &halt {
            items.push(not_started(reason));
            continue;
        }

        let mut result = ItemResult::new(&file, ItemStatus::Failed);
        let mut fatal: Option<String> = None;
        let outcome: Result<(), String> = async {
            let approved = match backend.prepare(index).await {
                Ok(approved) => approved,
                Err(PrepareError::Fatal(why)) => {
                    fatal = Some(why);
                    return Ok(());
                }
                Err(PrepareError::Item(why)) => return Err(format!("not sent: {why}")),
            };
            // Written before the request leaves, so a crash mid-send still
            // leaves a record of which file was going out. Fail closed.
            let mut sending = entry("upload_sending", batch, item);
            sending.detail = Some(format!(
                "displayName={}; descriptionSha256={}",
                item.display_name,
                sha256_hex(item.description.as_bytes())
            ));
            if let Err(e) = backend.record(sending) {
                note(Err(e), &mut halt, &mut warnings);
                return Err("not sent: the audit log could not be written".to_string());
            }
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

        if let Some(why) = fatal {
            halt = Some(format!("the batch stopped: {why}"));
            items.push(not_started(halt.as_deref().unwrap_or_default()));
            continue;
        }
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
            "uploaded={uploaded} failed={failed} not_started={not_started} elapsed={}s waited={}s onError={}{}",
            elapsed.as_secs(),
            waited.as_secs(),
            on_error.label(),
            halt.as_deref()
                .map(|h| format!(" stopped=\"{h}\""))
                .unwrap_or_default()
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
        waited_seconds: (waited.as_secs_f64() * 10.0).round() / 10.0,
        stopped_because: halt,
        audit_warnings: warnings,
    }
}

const CANCELLED: &str = "cancelled: the client cancelled the request";

#[cfg(test)]
mod tests {
    use super::super::batch::test_support::*;
    use super::super::ApprovedBatch;
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A backend with a virtual clock and a virtual rate-limit window: no
    /// network, no real sleeping. Verification and auditing are the real ones.
    struct Fake<'a> {
        flow: &'a UploadFlow,
        batch: &'a ApprovedBatch,
        limit: usize,
        clock: Mutex<Duration>,
        window: Mutex<VecDeque<Duration>>,
        /// Virtual time every upload takes (the clock moves during `start`).
        upload_time: Duration,
        /// Display names whose create request fails.
        fail_start: HashSet<&'static str>,
        /// Display names whose operation fails while polling.
        fail_finish: HashSet<&'static str>,
        /// Audit events that fail to be written.
        fail_record: HashSet<&'static str>,
        /// Polling never completes (for dropping the future mid-upload).
        hang_finish: bool,
        /// The client cancels once this many files were sent.
        cancel_after_sent: Option<usize>,
        /// The client cancels while the batch is sleeping for the rate limit.
        cancel_on_sleep: bool,
        /// Someone turns the policy off once this many files were sent.
        disable_policy_after_sent: Option<usize>,
        cancelled: AtomicBool,
        sent: Mutex<Vec<String>>,
        sleeps: Mutex<Vec<Duration>>,
        limits_seen: Mutex<Vec<u32>>,
    }

    impl<'a> Fake<'a> {
        fn new(flow: &'a UploadFlow, batch: &'a ApprovedBatch, limit: usize) -> Self {
            Self {
                flow,
                batch,
                limit,
                clock: Mutex::new(Duration::ZERO),
                window: Mutex::new(VecDeque::new()),
                upload_time: Duration::ZERO,
                fail_start: HashSet::new(),
                fail_finish: HashSet::new(),
                fail_record: HashSet::new(),
                hang_finish: false,
                cancel_after_sent: None,
                cancel_on_sleep: false,
                disable_policy_after_sent: None,
                cancelled: AtomicBool::new(false),
                sent: Mutex::new(Vec::new()),
                sleeps: Mutex::new(Vec::new()),
                limits_seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl BatchBackend for Fake<'_> {
        fn policy_check(&self) -> Result<u32, String> {
            self.flow.batch_policy_limit(&self.batch.creator)
        }

        fn try_slot(&self, limit: u32) -> Result<(), Duration> {
            self.limits_seen.lock().unwrap().push(limit);
            let now = *self.clock.lock().unwrap();
            let mut w = self.window.lock().unwrap();
            while w.front().is_some_and(|t| now - *t >= RATE_WINDOW) {
                w.pop_front();
            }
            if w.len() >= self.limit {
                return Err(RATE_WINDOW - (now - *w.front().unwrap()));
            }
            w.push_back(now);
            Ok(())
        }

        async fn prepare(&self, index: usize) -> Result<ApprovedUpload, PrepareError> {
            self.flow.load_batch_item(self.batch, index)
        }

        async fn start(&self, approved: &ApprovedUpload) -> Result<String> {
            if self.fail_start.contains(approved.display_name.as_str()) {
                return Err(eyre!("Asset upload failed (400): bad request"));
            }
            let sent = {
                let mut sent = self.sent.lock().unwrap();
                sent.push(approved.display_name.clone());
                sent.len()
            };
            *self.clock.lock().unwrap() += self.upload_time;
            if self.cancel_after_sent == Some(sent) {
                self.cancelled.store(true, Ordering::SeqCst);
            }
            if self.disable_policy_after_sent == Some(sent) {
                fs::write(self.flow.policy.policy_path(), r#"{ "enabled": false }"#).unwrap();
                self.flow.policy.sign().unwrap();
            }
            Ok(format!("operations/{}", approved.display_name))
        }

        async fn finish(&self, operation: &str) -> Result<serde_json::Value> {
            if self.hang_finish {
                std::future::pending::<()>().await;
            }
            let name = operation.trim_start_matches("operations/");
            if self.fail_finish.contains(name) {
                return Err(eyre!("Operation failed: moderation"));
            }
            Ok(serde_json::json!({
                "assetId": format!("id-{name}"),
                "moderationResult": { "moderationState": "Approved" }
            }))
        }

        fn record(&self, entry: AuditEntry) -> Result<()> {
            if self.fail_record.contains(entry.event.as_str()) {
                return Err(eyre!("disk full"));
            }
            self.flow.record(entry)
        }

        fn elapsed(&self) -> Duration {
            *self.clock.lock().unwrap()
        }

        async fn sleep(&self, d: Duration) {
            if self.cancel_on_sleep {
                self.cancelled.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await;
            }
            self.sleeps.lock().unwrap().push(d);
            *self.clock.lock().unwrap() += d;
        }

        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }

        async fn cancelled(&self) {
            while !self.is_cancelled() {
                tokio::task::yield_now().await;
            }
        }
    }

    fn batch_of(f: &BatchFixture, n: usize) -> ApprovedBatch {
        let items = (0..n)
            .map(|i| f.item(&format!("{}.png", (b'a' + i as u8) as char), "Image"))
            .collect();
        f.approved(items)
    }

    fn statuses(r: &BatchResult) -> Vec<ItemStatus> {
        r.items.iter().map(|i| i.status).collect()
    }

    fn events(f: &BatchFixture) -> Vec<String> {
        f.events()
    }

    #[tokio::test]
    async fn uploads_every_file_in_order_and_audits_each_step() {
        let f = fixture("");
        let batch = batch_of(&f, 3);
        let fake = Fake::new(&f.flow, &batch, 10);
        let r = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(600)).await;
        assert_eq!((r.uploaded, r.failed, r.not_started), (3, 0, 0));
        assert_eq!(*fake.sent.lock().unwrap(), ["a", "b", "c"]);
        assert_eq!(r.items[0].asset_id.as_deref(), Some("id-a"));
        assert_eq!(r.items[0].operation.as_deref(), Some("operations/a"));
        assert_eq!(r.items[0].moderation_state.as_deref(), Some("Approved"));
        assert!(r.stopped_because.is_none() && r.audit_warnings.is_empty());
        assert_eq!(
            events(&f),
            [
                "batch_planned",
                "batch_approved",
                "upload_sending",
                "upload_started",
                "upload_finished",
                "upload_sending",
                "upload_started",
                "upload_finished",
                "upload_sending",
                "upload_started",
                "upload_finished",
                "batch_finished",
            ]
        );
        // Every per-item event carries the batch id; the chain still verifies.
        let (records, chain) = f.flow.audit().tail(100).unwrap();
        assert!(chain.ok, "{chain:?}");
        assert!(records
            .iter()
            .all(|rec| rec.entry.plan_id.as_deref() == Some(&batch.batch_id)));
        let last = records.last().unwrap();
        assert_eq!(last.entry.status.as_deref(), Some("completed"));
        assert!(last.entry.detail.as_deref().unwrap().contains("uploaded=3"));
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["items"][0]["status"], "uploaded");
        assert_eq!(json["onError"], "stop");
    }

    #[tokio::test]
    async fn on_error_stop_halts_after_the_first_failure() {
        let f = fixture("");
        let batch = batch_of(&f, 4);
        let mut fake = Fake::new(&f.flow, &batch, 10);
        fake.fail_start.insert("b");
        let r = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(600)).await;
        assert_eq!(
            statuses(&r),
            [
                ItemStatus::Uploaded,
                ItemStatus::Failed,
                ItemStatus::NotStarted,
                ItemStatus::NotStarted
            ]
        );
        assert!(r.items[1].error.as_deref().unwrap().contains("400"));
        assert!(r.items[2]
            .error
            .as_deref()
            .unwrap()
            .contains("onError is stop"));
        assert_eq!(*fake.sent.lock().unwrap(), ["a"]);
        assert!(r.stopped_because.is_some());
        let ev = events(&f);
        assert!(ev.contains(&"upload_failed".to_string()));
        let (records, chain) = f.flow.audit().tail(100).unwrap();
        assert!(chain.ok);
        assert_eq!(
            records.last().unwrap().entry.status.as_deref(),
            Some("partial")
        );
    }

    #[tokio::test]
    async fn on_error_continue_keeps_going_and_reports_each_file() {
        let f = fixture("");
        let batch = batch_of(&f, 4);
        let mut fake = Fake::new(&f.flow, &batch, 10);
        fake.fail_start.insert("b");
        fake.fail_finish.insert("c");
        let r = run_batch(&fake, &batch, OnError::Continue, Duration::from_secs(600)).await;
        assert_eq!(
            statuses(&r),
            [
                ItemStatus::Uploaded,
                ItemStatus::Failed,
                ItemStatus::Failed,
                ItemStatus::Uploaded
            ]
        );
        assert_eq!((r.uploaded, r.failed, r.not_started), (2, 2, 0));
        // A failure after the operation started still reports the operation.
        assert_eq!(r.items[2].operation.as_deref(), Some("operations/c"));
        assert!(r.items[2]
            .error
            .as_deref()
            .unwrap()
            .contains("did not complete"));
        assert!(r.items[1].operation.is_none());
        assert!(f.flow.audit().verify().ok);
    }

    #[tokio::test]
    async fn waits_for_the_rate_limit_by_sleeping_until_the_window_has_room() {
        let f = fixture("");
        let batch = batch_of(&f, 5);
        let fake = Fake::new(&f.flow, &batch, 2);
        let r = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(600)).await;
        assert_eq!(r.uploaded, 5);
        // 2 at t=0, 2 at t=60, 1 at t=120.
        assert_eq!(
            *fake.sleeps.lock().unwrap(),
            [Duration::from_secs(60), Duration::from_secs(60)]
        );
        assert_eq!(r.elapsed_seconds, 120.0);
        assert!(f.flow.audit().verify().ok);
    }

    #[tokio::test]
    async fn the_max_wait_cap_leaves_the_rest_not_started() {
        let f = fixture("");
        let batch = batch_of(&f, 5);
        let fake = Fake::new(&f.flow, &batch, 2);
        let r = run_batch(&fake, &batch, OnError::Continue, Duration::from_secs(90)).await;
        assert_eq!(
            statuses(&r),
            [
                ItemStatus::Uploaded,
                ItemStatus::Uploaded,
                ItemStatus::Uploaded,
                ItemStatus::Uploaded,
                ItemStatus::NotStarted
            ]
        );
        assert!(r
            .stopped_because
            .as_deref()
            .unwrap()
            .contains("maxWaitSeconds"));
        assert!(r.items[4]
            .error
            .as_deref()
            .unwrap()
            .contains("maxWaitSeconds"));
        // It never slept past the budget.
        assert!(r.elapsed_seconds <= 90.0, "{}", r.elapsed_seconds);

        // A budget smaller than the first wait: one file, the rest not started.
        let f = fixture("");
        let batch = batch_of(&f, 3);
        let fake = Fake::new(&f.flow, &batch, 1);
        let r = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(30)).await;
        assert_eq!((r.uploaded, r.failed, r.not_started), (1, 0, 2));
        assert!(fake.sleeps.lock().unwrap().is_empty());
        assert!(f.flow.audit().verify().ok);
    }

    #[tokio::test]
    async fn a_file_changed_after_approval_fails_that_file_only() {
        let f = fixture("");
        let batch = batch_of(&f, 3);
        fs::write(
            f.exports.join("b.png"),
            [PNG, b"changed after approval"].concat(),
        )
        .unwrap();
        let fake = Fake::new(&f.flow, &batch, 10);
        let r = run_batch(&fake, &batch, OnError::Continue, Duration::from_secs(600)).await;
        assert_eq!(
            statuses(&r),
            [
                ItemStatus::Uploaded,
                ItemStatus::Failed,
                ItemStatus::Uploaded
            ]
        );
        assert!(r.items[1].error.as_deref().unwrap().contains("changed"));
        assert_eq!(*fake.sent.lock().unwrap(), ["a", "c"]);
        // Nothing was sent for the changed file.
        assert!(f.flow.audit().verify().ok);
    }

    #[tokio::test]
    async fn an_unwritable_audit_log_stops_the_batch() {
        let f = fixture("");
        let batch = batch_of(&f, 3);
        let mut fake = Fake::new(&f.flow, &batch, 10);
        fake.fail_record.insert("upload_started");
        let r = run_batch(&fake, &batch, OnError::Continue, Duration::from_secs(600)).await;
        // The first file was already sent when the record failed; no more start.
        assert_eq!(*fake.sent.lock().unwrap(), ["a"]);
        assert_eq!(
            statuses(&r),
            [
                ItemStatus::Uploaded,
                ItemStatus::NotStarted,
                ItemStatus::NotStarted
            ]
        );
        assert!(!r.audit_warnings.is_empty());
        assert!(r.stopped_because.as_deref().unwrap().contains("audit log"));
    }

    #[tokio::test]
    async fn the_batch_lock_is_held_until_the_approved_batch_is_dropped() {
        let f = fixture("");
        let batch = batch_of(&f, 1);
        let fake = Fake::new(&f.flow, &batch, 10);
        let r = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(600)).await;
        assert_eq!(r.uploaded, 1);
        let other = f
            .flow
            .plan_batch(f.request(vec![f.item("z.png", "Image")]))
            .unwrap();
        assert!(f
            .flow
            .approve_batch(&other.batch_plan_id, true, &other.confirm_phrase)
            .is_err());
        drop(fake);
        drop(batch);
        let other = f
            .flow
            .plan_batch(f.request(vec![f.item("z.png", "Image")]))
            .unwrap();
        assert!(f
            .flow
            .approve_batch(&other.batch_plan_id, true, &other.confirm_phrase)
            .is_ok());
    }

    #[tokio::test]
    async fn each_file_is_recorded_before_it_is_sent_and_a_failed_write_blocks_the_send() {
        let f = fixture("");
        let batch = batch_of(&f, 2);
        let fake = Fake::new(&f.flow, &batch, 10);
        let r = run_batch(&fake, &batch, OnError::Continue, Duration::from_secs(600)).await;
        assert_eq!(r.uploaded, 2);
        let (records, _) = f.flow.audit().tail(100).unwrap();
        let sending: Vec<_> = records
            .iter()
            .filter(|rec| rec.entry.event == "upload_sending")
            .collect();
        assert_eq!(sending.len(), 2);
        let first = &sending[0].entry;
        assert!(first.path.as_deref().unwrap().ends_with("a.png"));
        assert_eq!(
            first.sha256.as_deref(),
            Some(batch.items[0].sha256.as_str())
        );
        assert_eq!(first.asset_type.as_deref(), Some("Image"));
        assert!(first.detail.as_deref().unwrap().contains("displayName=a"));
        // upload_sending comes right before the request goes out.
        let pos = |ev: &str| records.iter().position(|r| r.entry.event == ev).unwrap();
        assert!(pos("upload_sending") < pos("upload_started"));

        let f = fixture("");
        let batch = batch_of(&f, 3);
        let mut fake = Fake::new(&f.flow, &batch, 10);
        fake.fail_record.insert("upload_sending");
        let r = run_batch(&fake, &batch, OnError::Continue, Duration::from_secs(600)).await;
        assert!(fake.sent.lock().unwrap().is_empty(), "nothing may be sent");
        assert_eq!(r.items[0].status, ItemStatus::Failed);
        assert!(r.items[0].error.as_deref().unwrap().contains("audit log"));
        assert_eq!(r.items[1].status, ItemStatus::NotStarted);
        assert!(!r.audit_warnings.is_empty());
    }

    #[tokio::test]
    async fn cancelling_between_files_stops_the_batch_and_releases_the_lock() {
        let f = fixture("");
        let batch = batch_of(&f, 3);
        let mut fake = Fake::new(&f.flow, &batch, 10);
        fake.cancel_after_sent = Some(1);
        let r = run_batch(&fake, &batch, OnError::Continue, Duration::from_secs(600)).await;
        assert_eq!(
            statuses(&r),
            [
                ItemStatus::Uploaded,
                ItemStatus::NotStarted,
                ItemStatus::NotStarted
            ]
        );
        assert!(r.stopped_because.as_deref().unwrap().contains("cancelled"));
        assert!(r.items[1].error.as_deref().unwrap().contains("cancelled"));
        assert_eq!(*fake.sent.lock().unwrap(), ["a"]);
        // batch_finished is still written and says why.
        let (records, chain) = f.flow.audit().tail(100).unwrap();
        assert!(chain.ok);
        let last = &records.last().unwrap().entry;
        assert_eq!(last.event, "batch_finished");
        assert!(last.detail.as_deref().unwrap().contains("cancelled"));
        // The lock is released once the approved batch is gone.
        drop(fake);
        drop(batch);
        let next = f
            .flow
            .plan_batch(f.request(vec![f.item("z.png", "Image")]))
            .unwrap();
        assert!(f
            .flow
            .approve_batch(&next.batch_plan_id, true, &next.confirm_phrase)
            .is_ok());
    }

    #[tokio::test]
    async fn cancelling_during_the_rate_limit_sleep_stops_the_batch_at_once() {
        let f = fixture("");
        let batch = batch_of(&f, 3);
        let mut fake = Fake::new(&f.flow, &batch, 1);
        fake.cancel_on_sleep = true;
        let r = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(600)).await;
        assert_eq!((r.uploaded, r.failed, r.not_started), (1, 0, 2));
        assert!(r.stopped_because.as_deref().unwrap().contains("cancelled"));
        // The sleep was interrupted, not completed.
        assert!(fake.sleeps.lock().unwrap().is_empty());
        assert_eq!(r.waited_seconds, 0.0);
        assert_eq!(
            f.events().last().map(String::as_str),
            Some("batch_finished")
        );
    }

    #[tokio::test]
    async fn already_cancelled_requests_start_nothing() {
        let f = fixture("");
        let batch = batch_of(&f, 2);
        let fake = Fake::new(&f.flow, &batch, 10);
        fake.cancelled.store(true, Ordering::SeqCst);
        let r = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(600)).await;
        assert_eq!((r.uploaded, r.failed, r.not_started), (0, 0, 2));
        assert!(fake.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_policy_problem_mid_batch_ends_it_even_with_on_error_continue() {
        let f = fixture("");
        let batch = batch_of(&f, 4);
        let mut fake = Fake::new(&f.flow, &batch, 1);
        fake.disable_policy_after_sent = Some(1);
        let r = run_batch(&fake, &batch, OnError::Continue, Duration::from_secs(600)).await;
        assert_eq!(
            statuses(&r),
            [
                ItemStatus::Uploaded,
                ItemStatus::NotStarted,
                ItemStatus::NotStarted,
                ItemStatus::NotStarted
            ]
        );
        assert_eq!(r.failed, 0, "no file is blamed for a policy change");
        assert!(r.stopped_because.as_deref().unwrap().contains("disabled"));
        // No further slot was taken or waited for (the limit is 1 per minute).
        assert_eq!(fake.window.lock().unwrap().len(), 1);
        assert!(fake.sleeps.lock().unwrap().is_empty());
        assert_eq!(fake.limits_seen.lock().unwrap().len(), 1);
        assert!(f.flow.audit().verify().ok);
    }

    #[tokio::test]
    async fn a_creator_the_policy_no_longer_permits_ends_the_batch() {
        let f = fixture("");
        let batch = batch_of(&f, 2);
        let fake = Fake::new(&f.flow, &batch, 10);
        let json = format!(
            r#"{{ "enabled": true, "allowed_roots": ["{}"], "allow_unlisted_creators": false,
                 "creators": {{ "team": {{ "groupId": "222" }} }} }}"#,
            f.root
        );
        fs::write(f.flow.policy.policy_path(), json).unwrap();
        f.flow.policy.sign().unwrap();
        let r = run_batch(&fake, &batch, OnError::Continue, Duration::from_secs(600)).await;
        assert_eq!((r.uploaded, r.failed, r.not_started), (0, 0, 2));
        assert!(r.stopped_because.as_deref().unwrap().contains("creator"));
        assert!(fake.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_rate_limit_comes_from_the_policy_reloaded_for_each_file() {
        let f = fixture("");
        let batch = batch_of(&f, 2);
        let fake = Fake::new(&f.flow, &batch, 10);
        let json = format!(
            r#"{{ "enabled": true, "allowed_roots": ["{}"], "rate_limit_per_minute": 3,
                 "creators": {{ "personal": {{ "userId": "111" }} }} }}"#,
            f.root
        );
        fs::write(f.flow.policy.policy_path(), json).unwrap();
        f.flow.policy.sign().unwrap();
        run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(600)).await;
        assert_eq!(*fake.limits_seen.lock().unwrap(), [3, 3]);
    }

    #[tokio::test]
    async fn upload_time_does_not_count_against_max_wait() {
        // Five uploads of 30 virtual seconds, no rate-limit waiting needed:
        // a 10 second sleeping budget is enough.
        let f = fixture("");
        let batch = batch_of(&f, 5);
        let mut fake = Fake::new(&f.flow, &batch, 10);
        fake.upload_time = Duration::from_secs(30);
        let r = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(10)).await;
        assert_eq!((r.uploaded, r.not_started), (5, 0));
        assert_eq!(r.elapsed_seconds, 150.0);
        assert_eq!(r.waited_seconds, 0.0);
        assert!(r.stopped_because.is_none());

        // With a limit of 1 per minute and 30 second uploads each file waits
        // 30 more seconds: a 29 second budget is not enough, 30 is.
        for (budget, expect_uploaded) in [(29, 1), (30, 2)] {
            let f = fixture("");
            let batch = batch_of(&f, 2);
            let mut fake = Fake::new(&f.flow, &batch, 1);
            fake.upload_time = Duration::from_secs(30);
            let r = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(budget)).await;
            assert_eq!(r.uploaded, expect_uploaded, "budget {budget}");
            if expect_uploaded == 2 {
                assert_eq!(r.waited_seconds, 30.0);
                assert_eq!(r.elapsed_seconds, 90.0);
            }
        }
    }

    #[tokio::test]
    async fn dropping_the_future_mid_upload_releases_the_lock_and_leaves_the_log_consistent() {
        let f = fixture("");
        let batch = batch_of(&f, 2);
        {
            let mut fake = Fake::new(&f.flow, &batch, 10);
            fake.hang_finish = true;
            let run = run_batch(&fake, &batch, OnError::Stop, Duration::from_secs(600));
            let timed = tokio::time::timeout(Duration::from_millis(100), run).await;
            assert!(timed.is_err(), "the upload was meant to hang");
            assert_eq!(*fake.sent.lock().unwrap(), ["a"]);
        }
        // The file was recorded as going out and started; nothing claims more.
        assert_eq!(
            f.events(),
            [
                "batch_planned",
                "batch_approved",
                "upload_sending",
                "upload_started"
            ]
        );
        assert!(f.flow.audit().verify().ok);
        // The lock goes with the approved batch.
        drop(batch);
        let next = f
            .flow
            .plan_batch(f.request(vec![f.item("z.png", "Image")]))
            .unwrap();
        assert!(f
            .flow
            .approve_batch(&next.batch_plan_id, true, &next.confirm_phrase)
            .is_ok());
    }

    #[test]
    fn on_error_parses_stop_continue_and_nothing_else() {
        assert_eq!(OnError::parse(None).unwrap(), OnError::Stop);
        assert_eq!(OnError::parse(Some("Stop")).unwrap(), OnError::Stop);
        assert_eq!(
            OnError::parse(Some(" continue ")).unwrap(),
            OnError::Continue
        );
        assert!(OnError::parse(Some("retry")).is_err());
    }
}
