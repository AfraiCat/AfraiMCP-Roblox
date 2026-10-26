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

#[cfg(test)]
mod tests {
    use super::super::batch::test_support::*;
    use super::super::ApprovedBatch;
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use std::fs;
    use std::sync::Mutex;

    /// A backend with a virtual clock and a virtual rate-limit window: no
    /// network, no real sleeping. Verification and auditing are the real ones.
    struct Fake<'a> {
        flow: &'a UploadFlow,
        batch: &'a ApprovedBatch,
        limit: usize,
        clock: Mutex<Duration>,
        window: Mutex<VecDeque<Duration>>,
        /// Display names whose create request fails.
        fail_start: HashSet<&'static str>,
        /// Display names whose operation fails while polling.
        fail_finish: HashSet<&'static str>,
        /// Audit events that fail to be written.
        fail_record: HashSet<&'static str>,
        sent: Mutex<Vec<String>>,
        sleeps: Mutex<Vec<Duration>>,
    }

    impl<'a> Fake<'a> {
        fn new(flow: &'a UploadFlow, batch: &'a ApprovedBatch, limit: usize) -> Self {
            Self {
                flow,
                batch,
                limit,
                clock: Mutex::new(Duration::ZERO),
                window: Mutex::new(VecDeque::new()),
                fail_start: HashSet::new(),
                fail_finish: HashSet::new(),
                fail_record: HashSet::new(),
                sent: Mutex::new(Vec::new()),
                sleeps: Mutex::new(Vec::new()),
            }
        }
    }

    impl BatchBackend for Fake<'_> {
        fn try_slot(&self) -> Result<(), Duration> {
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

        async fn prepare(&self, index: usize) -> Result<ApprovedUpload> {
            self.flow.load_batch_item(self.batch, index)
        }

        async fn start(&self, approved: &ApprovedUpload) -> Result<String> {
            if self.fail_start.contains(approved.display_name.as_str()) {
                return Err(eyre!("Asset upload failed (400): bad request"));
            }
            self.sent
                .lock()
                .unwrap()
                .push(approved.display_name.clone());
            Ok(format!("operations/{}", approved.display_name))
        }

        async fn finish(&self, operation: &str) -> Result<serde_json::Value> {
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
            self.sleeps.lock().unwrap().push(d);
            *self.clock.lock().unwrap() += d;
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
                "upload_started",
                "upload_finished",
                "upload_started",
                "upload_finished",
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
