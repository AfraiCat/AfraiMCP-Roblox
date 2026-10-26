//! The two-step upload flow: `plan_upload`, then `upload_asset`. Batch mode
//! (`plan_upload_batch`, then `upload_batch`) lives in the `batch` and
//! `batch_exec` sub-modules and reuses the same policy, audit log and rate limit.
//!
//! * [`UploadFlow::plan`] checks the signed policy, the file and the target and
//!   returns a plan (bound to the file's SHA-256, valid for 10 minutes) plus a
//!   `confirm_phrase` that names the file, type, creator and hash prefix. It
//!   uploads nothing.
//! * [`UploadFlow::approve`] consumes the plan (single use), re-checks the
//!   policy and the file, enforces the rate limit and records the approval in
//!   the audit log. Only an [`ApprovedUpload`] can be sent to Roblox.
//!
//! `confirm: true` set by an agent only stops accidental calls. The human gate
//! is the client permission prompt on `upload_asset`, which shows the
//! `confirm_phrase`. Denials are audited. Nothing here touches the network.

use crate::asset_types::{self, AssetKind, ValidatedFile};
use crate::audit::{AuditEntry, AuditLog};
use crate::policy::{Policy, PolicyStore, ResolvedCreator};
use color_eyre::eyre::{eyre, Report, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod batch;
mod batch_exec;

pub use batch::{ApprovedBatch, BatchItemRequest, BatchPlanRequest, PrepareError};
pub use batch_exec::{run_batch, BatchBackend, OnError};

/// How long a plan stays valid.
pub const PLAN_TTL: Duration = Duration::from_secs(600);
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_DISPLAY_NAME: usize = 50;
const MAX_DESCRIPTION: usize = 1000;

pub struct PlanRequest {
    pub file_path: String,
    pub asset_type: String,
    pub display_name: String,
    pub description: Option<String>,
    pub creator: Option<String>,
    pub user_id: Option<String>,
    pub group_id: Option<String>,
}

#[derive(Clone)]
struct Plan {
    path: PathBuf,
    file_name: String,
    kind: AssetKind,
    bytes: u64,
    sha256: String,
    display_name: String,
    description: String,
    creator: ResolvedCreator,
    confirm_phrase: String,
    expires_at: Instant,
}

/// What `plan_upload` returns to the agent.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanSummary {
    pub plan_id: String,
    pub file: String,
    pub asset_type: String,
    pub bytes: u64,
    pub sha256: String,
    pub creator: String,
    pub display_name: String,
    pub confirm_phrase: String,
    pub expires_in_seconds: u64,
    pub next_step: String,
}

/// A plan that passed every check at approval time; the only thing the
/// Open Cloud client will upload.
pub struct ApprovedUpload {
    pub plan_id: String,
    pub path: PathBuf,
    pub kind: AssetKind,
    pub validated: ValidatedFile,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub creator: ResolvedCreator,
    pub display_name: String,
    pub description: String,
    /// Keeps a batch from starting while this upload is in flight. `None` for
    /// the items of a batch (the batch holds its own guard).
    _guard: Option<UploadGuard>,
}

impl std::fmt::Debug for ApprovedUpload {
    /// Never prints the file contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovedUpload")
            .field("plan_id", &self.plan_id)
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field("bytes", &format_args!("{} bytes", self.bytes.len()))
            .field("sha256", &self.sha256)
            .field("creator", &self.creator)
            .field("display_name", &self.display_name)
            .finish()
    }
}

pub struct UploadFlow {
    policy: PolicyStore,
    audit: Arc<AuditLog>,
    plans: Mutex<HashMap<String, Plan>>,
    batch_plans: Mutex<HashMap<String, batch::BatchPlan>>,
    uploads: Mutex<VecDeque<Instant>>,
    activity: Arc<Mutex<Activity>>,
    ttl: Duration,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// What is uploading right now: any number of single uploads, or one batch.
#[derive(Debug, Default)]
struct Activity {
    singles: usize,
    batch: bool,
}

/// Held while an upload (single or batch) is in flight; releases on drop.
#[derive(Debug)]
pub struct UploadGuard {
    activity: Arc<Mutex<Activity>>,
    exclusive: bool,
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        let mut a = self.activity.lock().unwrap_or_else(|e| e.into_inner());
        if self.exclusive {
            a.batch = false;
        } else {
            a.singles = a.singles.saturating_sub(1);
        }
    }
}

/// How long until the sliding window has room for one more upload; zero when
/// it has room now. `uploads` holds the start times, oldest first.
pub(crate) fn window_wait(uploads: &VecDeque<Instant>, now: Instant, limit: u32) -> Duration {
    let live = uploads
        .iter()
        .filter(|t| now.duration_since(**t) < RATE_WINDOW)
        .count();
    if live < limit as usize {
        return Duration::ZERO;
    }
    // The live entries are the newest ones; once the `limit`-th newest one has
    // aged out, one slot is free.
    let blocking = uploads[uploads.len() - limit as usize];
    RATE_WINDOW.saturating_sub(now.duration_since(blocking))
}

/// A file that passed every per-file check. Shared by `plan` and batch
/// planning so both apply exactly the same rules.
pub(crate) struct CheckedFile {
    pub path: PathBuf,
    pub file_name: String,
    pub kind: AssetKind,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub display_name: String,
    pub description: String,
}

/// Type, names, path, size and content checks for one file, in the order
/// `plan_upload` has always applied them. The error is the refusal reason.
pub(crate) fn check_file(
    policy: &Policy,
    file_path: &str,
    asset_type: &str,
    display_name: &str,
    description: Option<String>,
) -> Result<CheckedFile, String> {
    let kind = AssetKind::parse(asset_type).map_err(|e| e.to_string())?;

    let display_name = display_name.trim().to_string();
    if display_name.is_empty()
        || display_name.chars().count() > MAX_DISPLAY_NAME
        || display_name.chars().any(char::is_control)
    {
        return Err(format!(
            "displayName must be 1 to {MAX_DISPLAY_NAME} characters without control characters"
        ));
    }
    let description = description.unwrap_or_default();
    if description.chars().count() > MAX_DESCRIPTION {
        return Err(format!(
            "description is longer than {MAX_DESCRIPTION} characters"
        ));
    }

    let path = policy
        .check_path(Path::new(file_path))
        .map_err(|e| e.to_string())?;
    let len = std::fs::metadata(&path)
        .map_err(|e| format!("cannot read the file ({:?})", e.kind()))?
        .len();
    policy
        .check_kind_and_size(kind, len)
        .map_err(|e| e.to_string())?;
    let bytes =
        std::fs::read(&path).map_err(|e| format!("cannot read the file ({:?})", e.kind()))?;
    policy
        .check_kind_and_size(kind, bytes.len() as u64)
        .map_err(|e| e.to_string())?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "asset".to_string());
    asset_types::validate_upload(kind, &file_name, &bytes).map_err(|e| e.to_string())?;
    let sha256 = sha256_hex(&bytes);
    Ok(CheckedFile {
        path,
        file_name,
        kind,
        bytes,
        sha256,
        display_name,
        description,
    })
}

impl UploadFlow {
    pub fn new(policy: PolicyStore, audit: Arc<AuditLog>) -> Self {
        Self {
            policy,
            audit,
            plans: Mutex::new(HashMap::new()),
            batch_plans: Mutex::new(HashMap::new()),
            uploads: Mutex::new(VecDeque::new()),
            activity: Arc::new(Mutex::new(Activity::default())),
            ttl: PLAN_TTL,
        }
    }

    #[cfg(test)]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Policy state for `cloud_auth_status` (no secrets).
    pub fn policy_status(&self) -> serde_json::Value {
        match self.policy.load_verified() {
            Ok(policy) => serde_json::json!({
                "state": if policy.enabled { "enabled" } else { "disabled" },
                "policy": crate::policy::PolicySummary::from(&*policy),
            }),
            Err(e) => serde_json::json!({ "state": "refusing uploads", "reason": e.to_string() }),
        }
    }

    /// Record a denial (best effort) and build the error the caller returns.
    fn refusal(&self, base: &AuditEntry, reason: impl Display) -> Report {
        let mut entry = base.clone();
        entry.event = "denied".to_string();
        entry.detail = Some(reason.to_string());
        let _ = self.audit.append(entry);
        eyre!("{reason}")
    }

    /// Step 1: check everything and hand back a plan. Uploads nothing.
    pub fn plan(&self, req: PlanRequest) -> Result<PlanSummary> {
        let base = AuditEntry {
            event: "plan".to_string(),
            path: Some(req.file_path.clone()),
            asset_type: Some(req.asset_type.trim().to_string()),
            ..Default::default()
        };
        let policy = self
            .policy
            .load_enabled()
            .map_err(|e| self.refusal(&base, e))?;
        let CheckedFile {
            path,
            file_name,
            kind,
            bytes,
            sha256,
            display_name,
            description,
        } = check_file(
            &policy,
            &req.file_path,
            &req.asset_type,
            &req.display_name,
            req.description,
        )
        .map_err(|e| self.refusal(&base, e))?;

        let creator = policy
            .resolve_creator(
                req.creator.as_deref(),
                req.user_id.as_deref(),
                req.group_id.as_deref(),
            )
            .map_err(|e| self.refusal(&base, e))?;

        let confirm_phrase = format!(
            "UPLOAD {file_name} as {kind} to {} sha:{}",
            creator.creator.label(),
            &sha256[..8]
        );
        let plan_id = uuid::Uuid::new_v4().to_string();

        let mut audit_entry = base.clone();
        audit_entry.plan_id = Some(plan_id.clone());
        audit_entry.path = Some(path.display().to_string());
        audit_entry.sha256 = Some(sha256.clone());
        audit_entry.bytes = Some(bytes.len() as u64);
        audit_entry.creator = Some(creator.describe());
        self.audit.append(audit_entry)?;

        {
            let mut plans = self.plans.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            plans.retain(|_, p| p.expires_at > now);
            plans.insert(
                plan_id.clone(),
                Plan {
                    path,
                    file_name: file_name.clone(),
                    kind,
                    bytes: bytes.len() as u64,
                    sha256: sha256.clone(),
                    display_name: display_name.clone(),
                    description,
                    creator: creator.clone(),
                    confirm_phrase: confirm_phrase.clone(),
                    expires_at: now + self.ttl,
                },
            );
        }

        Ok(PlanSummary {
            plan_id,
            file: file_name,
            asset_type: kind.api_name().to_string(),
            bytes: bytes.len() as u64,
            sha256,
            creator: creator.describe(),
            display_name,
            confirm_phrase,
            expires_in_seconds: self.ttl.as_secs(),
            next_step: "Show this summary to the user. Only after they agree, call upload_asset \
                        with planId, confirm: true and confirmPhrase exactly as given."
                .to_string(),
        })
    }

    /// Take a slot in the sliding one-minute window, or say how long until
    /// one is free. Shared by single uploads and batches.
    pub(crate) fn take_upload_slot(&self, limit: u32) -> Result<(), Duration> {
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        while uploads
            .front()
            .is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW)
        {
            uploads.pop_front();
        }
        let wait = window_wait(&uploads, now, limit);
        if !wait.is_zero() {
            return Err(wait);
        }
        uploads.push_back(now);
        Ok(())
    }

    /// Mark a single upload as in flight, unless a batch is running.
    fn begin_single(&self) -> Result<UploadGuard, Report> {
        let mut a = self.activity.lock().unwrap_or_else(|e| e.into_inner());
        if a.batch {
            return Err(eyre!(
                "a batch upload is running; wait for upload_batch to finish, then plan again"
            ));
        }
        a.singles += 1;
        Ok(UploadGuard {
            activity: self.activity.clone(),
            exclusive: false,
        })
    }

    /// Mark a batch as running, unless anything else is uploading.
    fn begin_batch(&self) -> Result<UploadGuard, Report> {
        let mut a = self.activity.lock().unwrap_or_else(|e| e.into_inner());
        if a.batch {
            return Err(eyre!(
                "another batch upload is already running; wait for it to finish"
            ));
        }
        if a.singles > 0 {
            return Err(eyre!(
                "a single upload is still in progress; wait for it to finish"
            ));
        }
        a.batch = true;
        Ok(UploadGuard {
            activity: self.activity.clone(),
            exclusive: true,
        })
    }

    /// Step 2: consume the plan and re-verify everything. The plan is removed
    /// first, so every failure means asking for a new plan.
    pub fn approve(
        &self,
        plan_id: &str,
        confirm: bool,
        confirm_phrase: &str,
    ) -> Result<ApprovedUpload> {
        if !confirm {
            return Err(eyre!(
                "confirm must be true, and only after the user agreed to this exact upload"
            ));
        }
        let guard = self.begin_single()?;
        let plan = self
            .plans
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(plan_id)
            .ok_or_else(|| {
                eyre!(
                    "unknown or already used plan; call plan_upload again (plans are single use \
                     and expire after {} seconds)",
                    self.ttl.as_secs()
                )
            })?;
        let base = AuditEntry {
            event: "upload_approved".to_string(),
            plan_id: Some(plan_id.to_string()),
            path: Some(plan.path.display().to_string()),
            sha256: Some(plan.sha256.clone()),
            bytes: Some(plan.bytes),
            asset_type: Some(plan.kind.api_name().to_string()),
            creator: Some(plan.creator.describe()),
            ..Default::default()
        };

        if Instant::now() >= plan.expires_at {
            return Err(self.refusal(&base, "the plan expired; call plan_upload again"));
        }
        if confirm_phrase.trim() != plan.confirm_phrase {
            return Err(self.refusal(
                &base,
                "confirmPhrase does not match the plan, so the plan was discarded; call \
                 plan_upload again and pass the phrase exactly",
            ));
        }
        let policy = self
            .policy
            .load_enabled()
            .map_err(|e| self.refusal(&base, e))?;
        policy
            .check_kind_and_size(plan.kind, plan.bytes)
            .map_err(|e| self.refusal(&base, e))?;
        policy
            .check_path(&plan.path)
            .map_err(|e| self.refusal(&base, e))?;
        if !policy.permits_creator(&plan.creator.creator) {
            return Err(self.refusal(&base, "the policy no longer permits this creator"));
        }
        if let Err(wait) = self.take_upload_slot(policy.rate_limit_per_minute) {
            return Err(self.refusal(
                &base,
                format!(
                    "rate limit of {} uploads per minute reached; retry in {} seconds",
                    policy.rate_limit_per_minute,
                    wait.as_secs() + 1
                ),
            ));
        }

        let bytes = std::fs::read(&plan.path)
            .map_err(|e| self.refusal(&base, format!("cannot read the file ({:?})", e.kind())))?;
        if sha256_hex(&bytes) != plan.sha256 {
            return Err(self.refusal(
                &base,
                "the file changed after it was planned; nothing was uploaded, call plan_upload again",
            ));
        }
        let validated = asset_types::validate_upload(plan.kind, &plan.file_name, &bytes)
            .map_err(|e| self.refusal(&base, e))?;

        self.audit.append(base)?;
        Ok(ApprovedUpload {
            plan_id: plan_id.to_string(),
            path: plan.path,
            kind: plan.kind,
            validated,
            bytes,
            sha256: plan.sha256,
            creator: plan.creator,
            display_name: plan.display_name,
            description: plan.description,
            _guard: Some(guard),
        })
    }

    /// Record a later step (`upload_started`, `upload_finished`,
    /// `upload_failed`). Strict: the caller decides whether a failure matters.
    pub fn record(&self, entry: AuditEntry) -> Result<()> {
        self.audit.append(entry).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::test_support::{signed_store, temp_dir};
    use std::fs;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    struct Fixture {
        flow: UploadFlow,
        file: PathBuf,
        dirs: Vec<PathBuf>,
        audit_path: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for d in &self.dirs {
                let _ = fs::remove_dir_all(d);
            }
        }
    }

    fn fixture(extra: &str) -> Fixture {
        fixture_with_ttl(extra, PLAN_TTL)
    }

    fn fixture_with_ttl(extra: &str, ttl: Duration) -> Fixture {
        let dir = temp_dir("flow");
        let exports = dir.join("exports");
        fs::create_dir_all(&exports).unwrap();
        let file = exports.join("pet.png");
        fs::write(&file, PNG).unwrap();
        let root = fs::canonicalize(&exports)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches("//?/")
            .to_string();
        let json = format!(
            r#"{{ "enabled": true, "allowed_roots": ["{root}"],
                 "creators": {{ "personal": {{ "userId": "111" }}, "team": {{ "groupId": "222" }} }} {extra} }}"#
        );
        let (store, policy_dir, secrets) = signed_store(&json);
        let audit_path = dir.join("audit").join("uploads.jsonl");
        let audit = Arc::new(AuditLog::new(audit_path.clone(), secrets));
        Fixture {
            flow: UploadFlow::new(store, audit).with_ttl(ttl),
            file,
            dirs: vec![dir, policy_dir],
            audit_path,
        }
    }

    fn request(f: &Fixture) -> PlanRequest {
        PlanRequest {
            file_path: f.file.to_string_lossy().into_owned(),
            asset_type: "Image".into(),
            display_name: "Pet icon".into(),
            description: None,
            creator: Some("personal".into()),
            user_id: None,
            group_id: None,
        }
    }

    fn events(f: &Fixture) -> Vec<String> {
        f.flow
            .audit()
            .tail(100)
            .unwrap()
            .0
            .into_iter()
            .map(|r| r.entry.event)
            .collect()
    }

    #[test]
    fn plan_then_approve_happy_path() {
        let f = fixture("");
        let plan = f.flow.plan(request(&f)).unwrap();
        assert_eq!(plan.asset_type, "Image");
        assert_eq!(plan.creator, "personal (user 111)");
        assert!(plan
            .confirm_phrase
            .starts_with("UPLOAD pet.png as Image to user 111 sha:"));
        assert!(plan.confirm_phrase.ends_with(&plan.sha256[..8]));

        let approved = f
            .flow
            .approve(&plan.plan_id, true, &plan.confirm_phrase)
            .unwrap();
        assert_eq!(approved.bytes, PNG);
        assert_eq!(approved.validated.content_type, "image/png");
        assert_eq!(approved.display_name, "Pet icon");
        assert_eq!(events(&f), ["plan", "upload_approved"]);
        assert!(f.flow.audit().verify().ok);
    }

    #[test]
    fn a_plan_is_single_use() {
        let f = fixture("");
        let plan = f.flow.plan(request(&f)).unwrap();
        f.flow
            .approve(&plan.plan_id, true, &plan.confirm_phrase)
            .unwrap();
        let err = f
            .flow
            .approve(&plan.plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("single use"), "{err}");
    }

    #[test]
    fn confirm_must_be_true_and_the_phrase_exact_and_a_wrong_phrase_discards_the_plan() {
        let f = fixture("");
        let plan = f.flow.plan(request(&f)).unwrap();
        assert!(f
            .flow
            .approve(&plan.plan_id, false, &plan.confirm_phrase)
            .is_err());
        // confirm=false did not consume the plan
        let err = f
            .flow
            .approve(&plan.plan_id, true, "UPLOAD something else")
            .unwrap_err();
        assert!(err.to_string().contains("confirmPhrase"), "{err}");
        let again = f
            .flow
            .approve(&plan.plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(
            again.to_string().contains("unknown or already used"),
            "{again}"
        );
        assert!(events(&f).contains(&"denied".to_string()));
    }

    #[test]
    fn an_expired_plan_is_refused() {
        let f = fixture_with_ttl("", Duration::ZERO);
        let plan = f.flow.plan(request(&f)).unwrap();
        let err = f
            .flow
            .approve(&plan.plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn a_file_changed_after_planning_is_refused() {
        let f = fixture("");
        let plan = f.flow.plan(request(&f)).unwrap();
        fs::write(&f.file, [PNG, b"tampered"].concat()).unwrap();
        let err = f
            .flow
            .approve(&plan.plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("changed"), "{err}");
    }

    #[test]
    fn a_policy_that_changes_between_plan_and_approve_is_honoured() {
        let f = fixture("");
        let plan = f.flow.plan(request(&f)).unwrap();
        // Someone turns uploads off (and re-signs) after the plan.
        let policy_path = f.flow.policy.policy_path();
        fs::write(&policy_path, r#"{ "enabled": false }"#).unwrap();
        f.flow.policy.sign().unwrap();
        let err = f
            .flow
            .approve(&plan.plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("disabled"), "{err}");

        // An altered, unsigned policy refuses too.
        let plan = {
            fs::write(
                &policy_path,
                format!(r#"{{ "enabled": true, "allowed_roots": ["{}"], "creators": {{ "personal": {{ "userId": "111" }} }} }}"#,
                    f.file.parent().unwrap().to_string_lossy().replace('\\', "/")),
            )
            .unwrap();
            f.flow.policy.sign().unwrap();
            f.flow.plan(request(&f)).unwrap()
        };
        fs::write(
            &policy_path,
            r#"{ "enabled": true, "max_bytes": 99999999 }"#,
        )
        .unwrap();
        let err = f
            .flow
            .approve(&plan.plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("signature"), "{err}");
    }

    #[test]
    fn unsigned_disabled_or_missing_policy_refuses_to_plan() {
        let f = fixture("");
        let policy_path = f.flow.policy.policy_path();
        fs::write(&policy_path, r#"{ "enabled": true }"#).unwrap();
        assert!(f
            .flow
            .plan(request(&f))
            .unwrap_err()
            .to_string()
            .contains("signature"));
        fs::remove_file(&policy_path).unwrap();
        assert!(f
            .flow
            .plan(request(&f))
            .unwrap_err()
            .to_string()
            .contains("No upload policy"));
    }

    #[test]
    fn files_outside_the_roots_and_denied_files_are_refused_and_audited() {
        let f = fixture("");
        let outside = temp_dir("flow-outside").join("pet.png");
        fs::write(&outside, PNG).unwrap();
        let mut req = request(&f);
        req.file_path = outside.to_string_lossy().into_owned();
        assert!(f
            .flow
            .plan(req)
            .unwrap_err()
            .to_string()
            .contains("outside"));

        let reference = f.file.parent().unwrap().join("reference-images");
        fs::create_dir_all(&reference).unwrap();
        fs::write(reference.join("ref.png"), PNG).unwrap();
        let mut req = request(&f);
        req.file_path = reference.join("ref.png").to_string_lossy().into_owned();
        assert!(f
            .flow
            .plan(req)
            .unwrap_err()
            .to_string()
            .contains("deny rule"));

        assert_eq!(events(&f), ["denied", "denied"]);
        let _ = fs::remove_dir_all(outside.parent().unwrap());
    }

    #[test]
    fn content_that_does_not_match_the_type_is_refused() {
        let f = fixture("");
        fs::write(&f.file, b"this is not a png at all, just text").unwrap();
        assert!(f.flow.plan(request(&f)).is_err());
        let mut req = request(&f);
        req.asset_type = "Spaceship".into();
        assert!(f.flow.plan(req).is_err());
    }

    #[test]
    fn the_creator_is_required_and_exactly_one_target_may_be_given() {
        let f = fixture("");
        let mut req = request(&f);
        req.creator = None;
        let err = f.flow.plan(req).unwrap_err().to_string();
        assert!(err.contains("Ask the user"), "{err}");

        let mut req = request(&f);
        req.user_id = Some("5".into());
        assert!(f.flow.plan(req).is_err());

        let mut req = request(&f);
        req.creator = Some("team".into());
        let plan = f.flow.plan(req).unwrap();
        assert!(plan.confirm_phrase.contains("to group 222"));
    }

    #[test]
    fn bad_display_names_and_descriptions_are_refused() {
        let f = fixture("");
        for name in ["", "   ", &"x".repeat(51), "bad\nname"] {
            let mut req = request(&f);
            req.display_name = name.to_string();
            assert!(f.flow.plan(req).is_err(), "{name:?}");
        }
        let mut req = request(&f);
        req.description = Some("d".repeat(1001));
        assert!(f.flow.plan(req).is_err());
    }

    #[test]
    fn the_rate_limit_applies_to_approvals() {
        let f = fixture(r#", "rate_limit_per_minute": 2"#);
        for i in 0..3 {
            let plan = f.flow.plan(request(&f)).unwrap();
            let result = f.flow.approve(&plan.plan_id, true, &plan.confirm_phrase);
            if i < 2 {
                result.unwrap();
            } else {
                assert!(result.unwrap_err().to_string().contains("rate limit"));
            }
        }
    }

    #[test]
    fn a_tampered_audit_log_stops_further_planning() {
        let f = fixture("");
        f.flow.plan(request(&f)).unwrap();
        let text = fs::read_to_string(&f.audit_path).unwrap();
        fs::write(&f.audit_path, text.replace("Image", "Model")).unwrap();
        let err = f.flow.plan(request(&f)).unwrap_err().to_string();
        assert!(err.contains("audit"), "{err}");
    }

    #[test]
    fn policy_status_reports_the_state_without_secrets() {
        let f = fixture("");
        let status = f.flow.policy_status().to_string();
        assert!(status.contains("enabled"), "{status}");
        fs::remove_file(f.flow.policy.policy_path()).unwrap();
        assert!(f
            .flow
            .policy_status()
            .to_string()
            .contains("refusing uploads"));
    }
}
