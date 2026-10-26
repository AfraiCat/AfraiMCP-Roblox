//! Batch planning and approval: `plan_upload_batch`, then `upload_batch`.
//!
//! * [`UploadFlow::plan_batch`] runs the exact per-file checks of
//!   `plan_upload` on every file (policy, path, type, size, content, names),
//!   resolves one creator for the whole batch and returns a plan plus a
//!   `confirm_phrase` that names the file count, the types, the creator and a
//!   hash over every path and file hash. It uploads nothing.
//! * [`UploadFlow::approve_batch`] consumes the plan (single use), reloads the
//!   signed policy and re-checks **every** file (path, type, size, creator,
//!   file re-read, SHA equals the planned one) before returning. One failure
//!   means no upload starts at all.
//!
//! Uploading happens in [`super::batch_exec`]. Nothing here touches the network.

use super::*;
use std::collections::{BTreeMap, HashSet};

/// One file of a batch, as planned and as approved.
#[derive(Debug, Clone)]
pub struct BatchItem {
    pub path: PathBuf,
    pub file_name: String,
    pub kind: AssetKind,
    pub bytes: u64,
    pub sha256: String,
    pub display_name: String,
    pub description: String,
}

#[derive(Clone)]
pub(super) struct BatchPlan {
    items: Vec<BatchItem>,
    creator: ResolvedCreator,
    confirm_phrase: String,
    aggregate_sha: String,
    kind_counts: String,
    expires_at: Instant,
}

/// One entry of the `items` form.
#[derive(Debug, Clone)]
pub struct BatchItemRequest {
    pub file_path: String,
    pub asset_type: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

/// Give either `items`, or `folder` + `glob` + `asset_type`.
#[derive(Debug, Clone, Default)]
pub struct BatchPlanRequest {
    pub items: Option<Vec<BatchItemRequest>>,
    pub folder: Option<String>,
    pub glob: Option<String>,
    pub asset_type: Option<String>,
    pub creator: Option<String>,
    pub user_id: Option<String>,
    pub group_id: Option<String>,
    pub skip_refused: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchItemSummary {
    pub file: String,
    pub asset_type: String,
    pub bytes: u64,
    pub sha8: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchRefusal {
    pub file: String,
    pub reason: String,
}

/// What `plan_upload_batch` returns when a plan was created.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchPlanSummary {
    pub batch_plan_id: String,
    pub items: Vec<BatchItemSummary>,
    /// Files left out because `skipRefused` was set, with the reasons.
    pub refused: Vec<BatchRefusal>,
    pub total_files: usize,
    pub total_bytes: u64,
    pub kind_counts: String,
    pub creator: String,
    pub aggregate_sha256: String,
    pub confirm_phrase: String,
    pub expires_in_seconds: u64,
    pub rate_limit_per_minute: u32,
    /// Time spent only waiting for the rate limit (not upload or moderation time).
    pub estimated_rate_limit_wait_seconds: u64,
    pub estimated_minutes: u64,
    pub next_step: String,
}

/// Why no plan was created, with every per-file refusal.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchPlanFailure {
    pub plan_created: bool,
    pub error: String,
    pub refused: Vec<BatchRefusal>,
}

impl std::fmt::Display for BatchPlanFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        for r in &self.refused {
            write!(f, "\n- {}: {}", r.file, r.reason)?;
        }
        Ok(())
    }
}

impl std::error::Error for BatchPlanFailure {}

/// A batch that passed every check at approval time. Holding it keeps other
/// uploads out; dropping it releases them.
#[derive(Debug)]
pub struct ApprovedBatch {
    pub batch_id: String,
    pub creator: ResolvedCreator,
    pub rate_limit_per_minute: u32,
    pub items: Vec<BatchItem>,
    pub aggregate_sha256: String,
    pub kind_counts: String,
    _guard: UploadGuard,
}

/// SHA-256 over the sorted lines `{canonical path}\0{file sha256}\n`.
pub(crate) fn aggregate_sha256<'a>(items: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut lines: Vec<String> = items
        .into_iter()
        .map(|(path, sha)| format!("{path}\0{sha}\n"))
        .collect();
    lines.sort();
    let mut hasher = Sha256::new();
    for line in &lines {
        hasher.update(line.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn items_aggregate(items: &[BatchItem]) -> String {
    let paths: Vec<String> = items.iter().map(|i| i.path.display().to_string()).collect();
    aggregate_sha256(
        paths
            .iter()
            .map(String::as_str)
            .zip(items.iter().map(|i| i.sha256.as_str())),
    )
}

/// `3 Model, 2 Image`: most files first, ties in alphabetical type order.
fn kind_counts(items: &[BatchItem]) -> String {
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    for item in items {
        let rank = AssetKind::ALL.iter().position(|k| *k == item.kind).unwrap();
        *counts.entry(rank).or_default() += 1;
    }
    let mut counts: Vec<(usize, usize)> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    counts
        .into_iter()
        .map(|(rank, n)| format!("{n} {}", AssetKind::ALL[rank].api_name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// How long the rate limit alone makes `n` uploads take, given the ages of
/// the uploads already in the window. Pure, so it can be tested.
pub(crate) fn estimate_rate_wait(n: usize, limit: u32, ages: &[Duration]) -> Duration {
    let window = RATE_WINDOW.as_millis() as i64;
    let mut times: Vec<i64> = ages.iter().map(|a| -(a.as_millis() as i64)).collect();
    times.sort_unstable();
    let limit = (limit as usize).max(1);
    let mut t = 0i64;
    for _ in 0..n {
        if times.len() >= limit {
            t = t.max(times[times.len() - limit] + window);
        }
        times.push(t);
    }
    Duration::from_millis(t.max(0) as u64)
}

fn normalized_key(raw: &str) -> String {
    raw.trim().replace('\\', "/").to_lowercase()
}

impl UploadFlow {
    /// Record a batch-level refusal (best effort) and build the failure.
    fn batch_failure(&self, base: &AuditEntry, reason: impl Display) -> BatchPlanFailure {
        let mut entry = base.clone();
        entry.event = "denied".to_string();
        entry.detail = Some(reason.to_string());
        let _ = self.audit.append(entry);
        BatchPlanFailure {
            plan_created: false,
            error: reason.to_string(),
            refused: Vec::new(),
        }
    }

    /// Step 1 of a batch: check everything and hand back a plan. Uploads nothing.
    pub fn plan_batch(&self, req: BatchPlanRequest) -> Result<BatchPlanSummary, BatchPlanFailure> {
        let base = AuditEntry {
            event: "batch_plan".to_string(),
            ..Default::default()
        };
        let policy = self
            .policy
            .load_enabled()
            .map_err(|e| self.batch_failure(&base, e))?;

        // Where do the files come from?
        let mut refused: Vec<BatchRefusal> = Vec::new();
        let requests: Vec<BatchItemRequest> = match (req.items, req.folder) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(self.batch_failure(
                    &base,
                    "give either items, or folder + glob + assetType (not both, not neither)",
                ));
            }
            (Some(items), None) => {
                if req.glob.is_some() || req.asset_type.is_some() {
                    return Err(self.batch_failure(
                        &base,
                        "glob and assetType belong to the folder form; with items, give assetType per item",
                    ));
                }
                items
            }
            (None, Some(folder)) => {
                let (Some(glob), Some(asset_type)) = (req.glob, req.asset_type) else {
                    return Err(self
                        .batch_failure(&base, "the folder form needs folder, glob and assetType"));
                };
                let root = policy
                    .check_folder(Path::new(&folder))
                    .map_err(|e| self.batch_failure(&base, e))?;
                let listing = policy
                    .expand_folder(&root, &glob, policy.max_batch_files as usize)
                    .map_err(|e| self.batch_failure(&base, e))?;
                for (file, reason) in listing.skipped {
                    refused.push(BatchRefusal { file, reason });
                }
                listing
                    .files
                    .into_iter()
                    .map(|p| BatchItemRequest {
                        file_path: p.to_string_lossy().into_owned(),
                        asset_type: asset_type.clone(),
                        display_name: None,
                        description: None,
                    })
                    .collect()
            }
        };

        if requests.is_empty() {
            let mut failure =
                self.batch_failure(&base, "the batch is empty: no files were given or matched");
            failure.refused = refused;
            return Err(failure);
        }
        if requests.len() > policy.max_batch_files as usize {
            return Err(self.batch_failure(
                &base,
                format!(
                    "{} files is more than the policy's max_batch_files ({}); split the batch",
                    requests.len(),
                    policy.max_batch_files
                ),
            ));
        }
        let mut seen_raw = HashSet::new();
        let duplicates: Vec<&str> = requests
            .iter()
            .filter(|r| !seen_raw.insert(normalized_key(&r.file_path)))
            .map(|r| r.file_path.as_str())
            .collect();
        if !duplicates.is_empty() {
            return Err(self.batch_failure(
                &base,
                format!("duplicate files in the batch: {}", duplicates.join(", ")),
            ));
        }

        let creator = policy
            .resolve_creator(
                req.creator.as_deref(),
                req.user_id.as_deref(),
                req.group_id.as_deref(),
            )
            .map_err(|e| self.batch_failure(&base, e))?;

        // The same checks as plan_upload, per file. Bytes are dropped right
        // after hashing so a big batch never holds every file in memory.
        let mut items: Vec<BatchItem> = Vec::new();
        for r in requests {
            let display_name = r.display_name.clone().unwrap_or_else(|| {
                Path::new(&r.file_path)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
            match check_file(
                &policy,
                &r.file_path,
                &r.asset_type,
                &display_name,
                r.description.clone(),
            ) {
                Ok(c) => items.push(BatchItem {
                    path: c.path,
                    file_name: c.file_name,
                    kind: c.kind,
                    bytes: c.bytes.len() as u64,
                    sha256: c.sha256,
                    display_name: c.display_name,
                    description: c.description,
                }),
                Err(reason) => {
                    let _ = self.audit.append(AuditEntry {
                        event: "denied".to_string(),
                        path: Some(r.file_path.clone()),
                        asset_type: Some(r.asset_type.trim().to_string()),
                        detail: Some(reason.clone()),
                        ..Default::default()
                    });
                    refused.push(BatchRefusal {
                        file: r.file_path,
                        reason,
                    });
                }
            }
        }

        // Two spellings of one file (relative path, `..`, symlink) resolve to
        // the same canonical path.
        let mut seen = HashSet::new();
        let resolved_duplicates: Vec<String> = items
            .iter()
            .filter(|i| !seen.insert(i.path.clone()))
            .map(|i| i.path.display().to_string())
            .collect();
        if !resolved_duplicates.is_empty() {
            return Err(self.batch_failure(
                &base,
                format!(
                    "duplicate files in the batch (same file under different paths): {}",
                    resolved_duplicates.join(", ")
                ),
            ));
        }

        if !refused.is_empty() && !req.skip_refused {
            return Err(BatchPlanFailure {
                plan_created: false,
                error: format!(
                    "{} of {} files were refused, so no plan was created (nothing is planned unless \
                     every file passes). Fix them, or set skipRefused to plan only the accepted files.",
                    refused.len(),
                    refused.len() + items.len()
                ),
                refused,
            });
        }
        if items.is_empty() {
            return Err(BatchPlanFailure {
                plan_created: false,
                error: "no file passed the checks, so no plan was created".to_string(),
                refused,
            });
        }

        items.sort_by_key(|i| i.path.display().to_string());
        let aggregate = items_aggregate(&items);
        let counts = kind_counts(&items);
        let total_bytes: u64 = items.iter().map(|i| i.bytes).sum();
        let confirm_phrase = format!(
            "UPLOAD BATCH {} files ({counts}) to {} sha:{}",
            items.len(),
            creator.creator.label(),
            &aggregate[..8]
        );
        let batch_plan_id = uuid::Uuid::new_v4().to_string();

        self.audit
            .append(AuditEntry {
                event: "batch_planned".to_string(),
                plan_id: Some(batch_plan_id.clone()),
                sha256: Some(aggregate.clone()),
                bytes: Some(total_bytes),
                asset_type: Some(counts.clone()),
                creator: Some(creator.describe()),
                detail: Some(format!(
                    "{} files planned, {} refused and skipped",
                    items.len(),
                    refused.len()
                )),
                ..Default::default()
            })
            .map_err(|e| BatchPlanFailure {
                plan_created: false,
                error: e.to_string(),
                refused: Vec::new(),
            })?;

        let ages: Vec<Duration> = {
            let uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            uploads.iter().map(|t| now.duration_since(*t)).collect()
        };
        let wait = estimate_rate_wait(items.len(), policy.rate_limit_per_minute, &ages);

        let summary_items: Vec<BatchItemSummary> = items
            .iter()
            .map(|i| BatchItemSummary {
                file: i.path.display().to_string(),
                asset_type: i.kind.api_name().to_string(),
                bytes: i.bytes,
                sha8: i.sha256[..8].to_string(),
                display_name: i.display_name.clone(),
            })
            .collect();
        let total_files = items.len();
        {
            let mut plans = self.batch_plans.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            plans.retain(|_, p| p.expires_at > now);
            plans.insert(
                batch_plan_id.clone(),
                BatchPlan {
                    items,
                    creator: creator.clone(),
                    confirm_phrase: confirm_phrase.clone(),
                    aggregate_sha: aggregate.clone(),
                    kind_counts: counts.clone(),
                    expires_at: now + self.ttl,
                },
            );
        }

        Ok(BatchPlanSummary {
            batch_plan_id,
            items: summary_items,
            refused,
            total_files,
            total_bytes,
            kind_counts: counts,
            creator: creator.describe(),
            aggregate_sha256: aggregate,
            confirm_phrase,
            expires_in_seconds: self.ttl.as_secs(),
            rate_limit_per_minute: policy.rate_limit_per_minute,
            estimated_rate_limit_wait_seconds: wait.as_secs(),
            estimated_minutes: wait.as_secs().div_ceil(60),
            next_step: "Show this table to the user. Only after they agree to this exact batch, \
                        call upload_batch with planId (the batchPlanId), confirm: true and \
                        confirmPhrase exactly as given."
                .to_string(),
        })
    }

    /// A batch-level approval refusal, audited as `batch_denied`.
    fn batch_refusal(&self, base: &AuditEntry, reason: impl Display) -> Report {
        let mut entry = base.clone();
        entry.event = "batch_denied".to_string();
        entry.detail = Some(reason.to_string());
        let _ = self.audit.append(entry);
        eyre!("{reason}")
    }

    /// Step 2 of a batch: consume the plan and re-verify every file before
    /// anything is uploaded. The plan is removed first, so every failure means
    /// asking for a new plan.
    pub fn approve_batch(
        &self,
        plan_id: &str,
        confirm: bool,
        confirm_phrase: &str,
    ) -> Result<ApprovedBatch> {
        if !confirm {
            return Err(eyre!(
                "confirm must be true, and only after the user agreed to this exact batch"
            ));
        }
        // Taken before the plan is consumed, so a refused second call does not
        // burn the plan of the batch that is running.
        let guard = self.begin_batch()?;
        let plan = self
            .batch_plans
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(plan_id)
            .ok_or_else(|| {
                eyre!(
                    "unknown or already used batch plan; call plan_upload_batch again (plans are \
                     single use and expire after {} seconds)",
                    self.ttl.as_secs()
                )
            })?;
        let total_bytes: u64 = plan.items.iter().map(|i| i.bytes).sum();
        let base = AuditEntry {
            event: "batch_approved".to_string(),
            plan_id: Some(plan_id.to_string()),
            sha256: Some(plan.aggregate_sha.clone()),
            bytes: Some(total_bytes),
            asset_type: Some(plan.kind_counts.clone()),
            creator: Some(plan.creator.describe()),
            ..Default::default()
        };

        if Instant::now() >= plan.expires_at {
            return Err(self.batch_refusal(&base, "the plan expired; call plan_upload_batch again"));
        }
        if confirm_phrase.trim() != plan.confirm_phrase {
            return Err(self.batch_refusal(
                &base,
                "confirmPhrase does not match the plan, so the plan was discarded; call \
                 plan_upload_batch again and pass the phrase exactly",
            ));
        }
        let policy = self
            .policy
            .load_enabled()
            .map_err(|e| self.batch_refusal(&base, e))?;
        if plan.items.len() > policy.max_batch_files as usize {
            return Err(self.batch_refusal(
                &base,
                format!(
                    "the policy now allows at most {} files per batch",
                    policy.max_batch_files
                ),
            ));
        }
        if !policy.permits_creator(&plan.creator.creator) {
            return Err(self.batch_refusal(&base, "the policy no longer permits this creator"));
        }
        // Every file, before the first upload: one failure aborts the batch.
        for item in &plan.items {
            let name = &item.file_name;
            let fail = |why: String| self.batch_refusal(&base, format!("{name}: {why}"));
            verify_item(&policy, item).map_err(fail)?;
        }
        if items_aggregate(&plan.items) != plan.aggregate_sha {
            return Err(self.batch_refusal(&base, "the batch no longer matches its plan"));
        }

        self.audit.append(base)?;
        Ok(ApprovedBatch {
            batch_id: plan_id.to_string(),
            creator: plan.creator,
            rate_limit_per_minute: policy.rate_limit_per_minute,
            items: plan.items,
            aggregate_sha256: plan.aggregate_sha,
            kind_counts: plan.kind_counts,
            _guard: guard,
        })
    }

    /// Re-read and re-verify one file of an approved batch right before it is
    /// sent, and build the [`ApprovedUpload`] the Open Cloud client needs.
    /// Reloads the signed policy, so a policy turned off mid-batch stops it.
    pub fn load_batch_item(&self, batch: &ApprovedBatch, index: usize) -> Result<ApprovedUpload> {
        let item = batch
            .items
            .get(index)
            .ok_or_else(|| eyre!("no such batch item"))?;
        let policy = self.policy.load_enabled()?;
        if !policy.permits_creator(&batch.creator.creator) {
            return Err(eyre!("the policy no longer permits this creator"));
        }
        let bytes = verify_item(&policy, item).map_err(|e| eyre!("{e}"))?;
        let validated = asset_types::validate_upload(item.kind, &item.file_name, &bytes)?;
        Ok(ApprovedUpload {
            plan_id: batch.batch_id.clone(),
            path: item.path.clone(),
            kind: item.kind,
            validated,
            bytes,
            sha256: item.sha256.clone(),
            creator: batch.creator.clone(),
            display_name: item.display_name.clone(),
            description: item.description.clone(),
            _guard: None,
        })
    }
}

/// Path, type, size, re-read and SHA checks for one planned file. Returns the
/// bytes it read.
fn verify_item(policy: &Policy, item: &BatchItem) -> Result<Vec<u8>, String> {
    policy
        .check_kind_and_size(item.kind, item.bytes)
        .map_err(|e| e.to_string())?;
    let path = policy.check_path(&item.path).map_err(|e| e.to_string())?;
    if path != item.path {
        return Err("the file now resolves to a different path".to_string());
    }
    let bytes =
        std::fs::read(&path).map_err(|e| format!("cannot read the file ({:?})", e.kind()))?;
    policy
        .check_kind_and_size(item.kind, bytes.len() as u64)
        .map_err(|e| e.to_string())?;
    if sha256_hex(&bytes) != item.sha256 {
        return Err(
            "the file changed after it was planned; nothing was uploaded, call plan_upload_batch again"
                .to_string(),
        );
    }
    asset_types::validate_upload(item.kind, &item.file_name, &bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;
    use crate::policy::test_support::{signed_store, temp_dir};
    use std::fs;

    pub const PNG: &[u8] = b"\x89PNG\r\n\x1a\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    pub const GLB: &[u8] = b"glTF\x02\0\0\0\0\0\0\0";

    pub struct BatchFixture {
        pub flow: UploadFlow,
        pub exports: PathBuf,
        pub root: String,
        pub dirs: Vec<PathBuf>,
    }

    impl Drop for BatchFixture {
        fn drop(&mut self) {
            for d in &self.dirs {
                let _ = fs::remove_dir_all(d);
            }
        }
    }

    pub fn fixture(extra: &str) -> BatchFixture {
        fixture_with_ttl(extra, PLAN_TTL)
    }

    pub fn fixture_with_ttl(extra: &str, ttl: Duration) -> BatchFixture {
        let dir = temp_dir("batch");
        let exports = dir.join("exports");
        fs::create_dir_all(&exports).unwrap();
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
        let audit = Arc::new(AuditLog::new(audit_path, secrets));
        BatchFixture {
            flow: UploadFlow::new(store, audit).with_ttl(ttl),
            exports,
            root,
            dirs: vec![dir, policy_dir],
        }
    }

    impl BatchFixture {
        /// Write `name` under exports; content is unique per name.
        pub fn write(&self, name: &str, kind: &str) -> PathBuf {
            let path = self.exports.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let head = if kind == "Model" { GLB } else { PNG };
            fs::write(&path, [head, name.as_bytes()].concat()).unwrap();
            path
        }

        pub fn item(&self, name: &str, kind: &str) -> BatchItemRequest {
            let path = self.write(name, kind);
            item_for(&path, kind)
        }

        pub fn request(&self, items: Vec<BatchItemRequest>) -> BatchPlanRequest {
            BatchPlanRequest {
                items: Some(items),
                creator: Some("personal".into()),
                ..Default::default()
            }
        }

        pub fn events(&self) -> Vec<String> {
            self.flow
                .audit()
                .tail(500)
                .unwrap()
                .0
                .into_iter()
                .map(|r| r.entry.event)
                .collect()
        }

        /// Plan and approve in one go.
        pub fn approved(&self, items: Vec<BatchItemRequest>) -> ApprovedBatch {
            let plan = self.flow.plan_batch(self.request(items)).unwrap();
            self.flow
                .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
                .unwrap()
        }
    }

    pub fn item_for(path: &Path, kind: &str) -> BatchItemRequest {
        BatchItemRequest {
            file_path: path.to_string_lossy().into_owned(),
            asset_type: kind.to_string(),
            display_name: None,
            description: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use std::fs;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn plans_a_batch_of_n_files_with_the_documented_phrase() {
        let f = fixture("");
        let items = vec![
            f.item("a.png", "Image"),
            f.item("b.glb", "Model"),
            f.item("c.png", "Image"),
            f.item("d.glb", "Model"),
            f.item("e.png", "Image"),
        ];
        let plan = f.flow.plan_batch(f.request(items)).unwrap();
        assert_eq!(plan.total_files, 5);
        assert_eq!(plan.kind_counts, "3 Image, 2 Model");
        assert_eq!(plan.creator, "personal (user 111)");
        assert_eq!(
            plan.confirm_phrase,
            format!(
                "UPLOAD BATCH 5 files (3 Image, 2 Model) to user 111 sha:{}",
                &plan.aggregate_sha256[..8]
            )
        );
        assert!(plan.refused.is_empty());
        let names: Vec<&str> = plan.items.iter().map(|i| i.display_name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c", "d", "e"]);
        let files: Vec<&str> = plan.items.iter().map(|i| i.file.as_str()).collect();
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted);
        assert_eq!(plan.items[0].sha8.len(), 8);
        assert_eq!(
            plan.total_bytes,
            plan.items.iter().map(|i| i.bytes).sum::<u64>()
        );
        assert_eq!(plan.expires_in_seconds, PLAN_TTL.as_secs());
        assert_eq!(plan.estimated_minutes, 0);
        assert!(f.events().contains(&"batch_planned".to_string()));
    }

    #[test]
    fn the_aggregate_hash_covers_sorted_path_and_hash_lines() {
        let a = aggregate_sha256([("/x/a", "11"), ("/x/b", "22")]);
        let b = aggregate_sha256([("/x/b", "22"), ("/x/a", "11")]);
        assert_eq!(a, b, "input order does not matter");
        assert_ne!(a, aggregate_sha256([("/x/a", "11"), ("/x/b", "23")]));
        assert_ne!(a, aggregate_sha256([("/x/a", "11"), ("/x/c", "22")]));
        let mut h = Sha256::new();
        h.update(b"/x/a\x0011\n/x/b\x0022\n");
        assert_eq!(a, hex::encode(h.finalize()));
    }

    #[test]
    fn one_refused_file_means_no_plan_and_every_refusal_is_returned() {
        let f = fixture("");
        let outside_dir = crate::policy::test_support::temp_dir("batch-outside");
        let outside = outside_dir.join("x.png");
        fs::write(&outside, PNG).unwrap();
        let reference = f.exports.join("reference-images");
        fs::create_dir_all(&reference).unwrap();
        fs::write(reference.join("r.png"), PNG).unwrap();
        let items = vec![
            f.item("ok.png", "Image"),
            item_for(&outside, "Image"),
            item_for(&reference.join("r.png"), "Image"),
        ];
        let failure = f.flow.plan_batch(f.request(items)).unwrap_err();
        assert!(!failure.plan_created);
        assert_eq!(failure.refused.len(), 2, "{failure}");
        assert!(failure.refused[0].reason.contains("outside"));
        assert!(failure.refused[1].reason.contains("deny rule"));
        assert!(failure.error.contains("no plan was created"));
        assert!(f.flow.batch_plans.lock().unwrap().is_empty());
        assert!(!f.events().contains(&"batch_planned".to_string()));
        assert!(f.flow.audit().verify().ok);
        let _ = fs::remove_dir_all(outside_dir);
    }

    #[test]
    fn skip_refused_plans_only_the_accepted_files_and_lists_the_rest() {
        let f = fixture("");
        let outside_dir = crate::policy::test_support::temp_dir("batch-outside");
        let outside = outside_dir.join("x.png");
        fs::write(&outside, PNG).unwrap();
        let items = vec![
            f.item("a.png", "Image"),
            item_for(&outside, "Image"),
            f.item("b.png", "Image"),
        ];
        let mut req = f.request(items);
        req.skip_refused = true;
        let plan = f.flow.plan_batch(req).unwrap();
        assert_eq!(plan.total_files, 2);
        assert_eq!(plan.refused.len(), 1);
        assert!(plan.refused[0].reason.contains("outside"));
        assert!(plan.confirm_phrase.contains("BATCH 2 files (2 Image)"));

        // Everything refused: still no plan.
        let mut req = f.request(vec![item_for(&outside, "Image")]);
        req.skip_refused = true;
        let failure = f.flow.plan_batch(req).unwrap_err();
        assert_eq!(failure.refused.len(), 1);
        let _ = fs::remove_dir_all(outside_dir);
    }

    #[test]
    fn per_file_type_and_size_limits_apply() {
        let f = fixture(r#", "allowed_asset_types": ["Image"], "max_bytes": 60"#);
        let small = f.item("small.png", "Image");
        let model = f.item("m.glb", "Model");
        let big = f.exports.join("big.png");
        fs::write(&big, [PNG, &[b'y'; 100][..]].concat()).unwrap();
        let failure = f
            .flow
            .plan_batch(f.request(vec![small, model, item_for(&big, "Image")]))
            .unwrap_err();
        assert_eq!(failure.refused.len(), 2, "{failure}");
        assert!(failure.refused[0].reason.contains("does not allow Model"));
        assert!(failure.refused[1].reason.contains("at most 60"));
    }

    #[test]
    fn display_names_and_content_are_checked_like_plan_upload() {
        let f = fixture("");
        let mut bad_name = f.item("a.png", "Image");
        bad_name.display_name = Some("x".repeat(51));
        let mut not_png = f.item("b.png", "Image");
        fs::write(f.exports.join("b.png"), b"plain text, not a png at all").unwrap();
        not_png.display_name = Some("fine".into());
        let failure = f
            .flow
            .plan_batch(f.request(vec![bad_name, not_png, f.item("c.png", "Spaceship")]))
            .unwrap_err();
        assert_eq!(failure.refused.len(), 3, "{failure}");
    }

    #[test]
    fn refuses_more_files_than_max_batch_files_empty_and_duplicate_batches() {
        let f = fixture(r#", "max_batch_files": 2"#);
        let items = vec![
            f.item("a.png", "Image"),
            f.item("b.png", "Image"),
            f.item("c.png", "Image"),
        ];
        let failure = f.flow.plan_batch(f.request(items.clone())).unwrap_err();
        assert!(failure.error.contains("max_batch_files"), "{failure}");
        // skipRefused does not lift the limit.
        let mut req = f.request(items.clone());
        req.skip_refused = true;
        assert!(f.flow.plan_batch(req).is_err());

        let failure = f.flow.plan_batch(f.request(vec![])).unwrap_err();
        assert!(failure.error.contains("empty"), "{failure}");

        // Same file twice, spelled twice, and through a `..` detour.
        let a = items[0].clone();
        let failure = f
            .flow
            .plan_batch(f.request(vec![a.clone(), a.clone()]))
            .unwrap_err();
        assert!(failure.error.contains("duplicate"), "{failure}");
        let mut detour = a.clone();
        detour.file_path = f
            .exports
            .join("..")
            .join("exports")
            .join("a.png")
            .to_string_lossy()
            .into_owned();
        let mut req = f.request(vec![a, detour]);
        req.skip_refused = true;
        let failure = f.flow.plan_batch(req).unwrap_err();
        assert!(failure.error.contains("duplicate"), "{failure}");
        assert!(f.flow.batch_plans.lock().unwrap().is_empty());
    }

    #[test]
    fn the_default_limit_is_25_files() {
        let f = fixture("");
        let items: Vec<_> = (0..26)
            .map(|i| f.item(&format!("f{i:02}.png"), "Image"))
            .collect();
        let failure = f.flow.plan_batch(f.request(items.clone())).unwrap_err();
        assert!(failure.error.contains("(25)"), "{failure}");
        assert!(f.flow.plan_batch(f.request(items[..25].to_vec())).is_ok());
    }

    #[test]
    fn a_creator_is_needed_for_the_whole_batch() {
        let f = fixture("");
        let mut req = f.request(vec![f.item("a.png", "Image")]);
        req.creator = None;
        let failure = f.flow.plan_batch(req.clone()).unwrap_err();
        assert!(failure.error.contains("Ask the user"), "{failure}");
        req.creator = Some("team".into());
        let plan = f.flow.plan_batch(req).unwrap();
        assert!(plan.confirm_phrase.contains("to group 222"));
    }

    #[test]
    fn approve_batch_happy_path_audits_and_keeps_the_chain_valid() {
        let f = fixture("");
        let plan = f
            .flow
            .plan_batch(f.request(vec![f.item("a.png", "Image"), f.item("b.glb", "Model")]))
            .unwrap();
        let approved = f
            .flow
            .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
            .unwrap();
        assert_eq!(approved.items.len(), 2);
        assert_eq!(approved.batch_id, plan.batch_plan_id);
        assert_eq!(approved.rate_limit_per_minute, 10);
        assert_eq!(f.events(), ["batch_planned", "batch_approved"]);
        assert!(f.flow.audit().verify().ok);
        let one = f.flow.load_batch_item(&approved, 1).unwrap();
        assert_eq!(one.plan_id, plan.batch_plan_id);
        assert_eq!(one.display_name, "b");
    }

    #[test]
    fn a_changed_file_changes_the_hash_and_approval_rejects_it() {
        let f = fixture("");
        let items = vec![f.item("a.png", "Image"), f.item("b.png", "Image")];
        let first = f.flow.plan_batch(f.request(items.clone())).unwrap();
        fs::write(f.exports.join("b.png"), [PNG, b"tampered"].concat()).unwrap();
        let err = f
            .flow
            .approve_batch(&first.batch_plan_id, true, &first.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("b.png"), "{err}");
        assert!(err.to_string().contains("changed"), "{err}");
        // The aggregate of a fresh plan differs, so the old phrase is stale.
        let second = f.flow.plan_batch(f.request(items)).unwrap();
        assert_ne!(first.aggregate_sha256, second.aggregate_sha256);
        assert_ne!(first.confirm_phrase, second.confirm_phrase);
        assert!(f.events().contains(&"batch_denied".to_string()));
    }

    #[test]
    fn one_bad_file_aborts_the_batch_before_the_first_upload() {
        let f = fixture("");
        let plan = f
            .flow
            .plan_batch(f.request(vec![f.item("a.png", "Image"), f.item("b.png", "Image")]))
            .unwrap();
        fs::remove_file(f.exports.join("b.png")).unwrap();
        assert!(f
            .flow
            .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
            .is_err());
        assert!(!f.events().contains(&"batch_approved".to_string()));
        // The plan is gone: no retry with the same id.
        let err = f
            .flow
            .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("unknown or already used"), "{err}");
    }

    #[test]
    fn a_wrong_phrase_discards_the_plan_and_confirm_false_does_not() {
        let f = fixture("");
        let plan = f
            .flow
            .plan_batch(f.request(vec![f.item("a.png", "Image")]))
            .unwrap();
        assert!(f
            .flow
            .approve_batch(&plan.batch_plan_id, false, &plan.confirm_phrase)
            .is_err());
        let err = f
            .flow
            .approve_batch(&plan.batch_plan_id, true, "UPLOAD BATCH 1 files (1 Image)")
            .unwrap_err();
        assert!(err.to_string().contains("confirmPhrase"), "{err}");
        let again = f
            .flow
            .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(
            again.to_string().contains("unknown or already used"),
            "{again}"
        );
    }

    #[test]
    fn a_batch_plan_is_single_use_and_expires() {
        let f = fixture("");
        let plan = f
            .flow
            .plan_batch(f.request(vec![f.item("a.png", "Image")]))
            .unwrap();
        f.flow
            .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
            .unwrap();
        let err = f
            .flow
            .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("single use"), "{err}");

        let f = fixture_with_ttl("", Duration::ZERO);
        let plan = f
            .flow
            .plan_batch(f.request(vec![f.item("a.png", "Image")]))
            .unwrap();
        let err = f
            .flow
            .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn the_policy_is_reloaded_at_approval() {
        let f = fixture("");
        let plan = f
            .flow
            .plan_batch(f.request(vec![f.item("a.png", "Image")]))
            .unwrap();
        fs::write(f.flow.policy.policy_path(), r#"{ "enabled": false }"#).unwrap();
        f.flow.policy.sign().unwrap();
        let err = f
            .flow
            .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("disabled"), "{err}");

        // A tighter limit after planning is honoured too.
        let f = fixture("");
        let plan = f
            .flow
            .plan_batch(f.request(vec![f.item("a.png", "Image"), f.item("b.png", "Image")]))
            .unwrap();
        let json = format!(
            r#"{{ "enabled": true, "allowed_roots": ["{}"], "creators": {{ "personal": {{ "userId": "111" }} }}, "max_batch_files": 1 }}"#,
            f.root
        );
        fs::write(f.flow.policy.policy_path(), json).unwrap();
        f.flow.policy.sign().unwrap();
        let err = f
            .flow
            .approve_batch(&plan.batch_plan_id, true, &plan.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("at most 1"), "{err}");
    }

    #[test]
    fn a_running_batch_blocks_a_second_batch_and_single_uploads_and_vice_versa() {
        let f = fixture("");
        let first = f.approved(vec![f.item("a.png", "Image")]);

        let second = f
            .flow
            .plan_batch(f.request(vec![f.item("b.png", "Image")]))
            .unwrap();
        let err = f
            .flow
            .approve_batch(&second.batch_plan_id, true, &second.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");

        let single = f
            .flow
            .plan(crate::upload_flow::PlanRequest {
                file_path: f.exports.join("b.png").to_string_lossy().into_owned(),
                asset_type: "Image".into(),
                display_name: "b".into(),
                description: None,
                creator: Some("personal".into()),
                user_id: None,
                group_id: None,
            })
            .unwrap();
        let err = f
            .flow
            .approve(&single.plan_id, true, &single.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("batch upload is running"), "{err}");

        // The refused second call did not burn its plan.
        drop(first);
        let held = f
            .flow
            .approve_batch(&second.batch_plan_id, true, &second.confirm_phrase)
            .unwrap();
        drop(held);

        // A single upload in flight blocks a batch.
        let single_up = f
            .flow
            .approve(&single.plan_id, true, &single.confirm_phrase)
            .unwrap();
        let third = f
            .flow
            .plan_batch(f.request(vec![f.item("c.png", "Image")]))
            .unwrap();
        let err = f
            .flow
            .approve_batch(&third.batch_plan_id, true, &third.confirm_phrase)
            .unwrap_err();
        assert!(err.to_string().contains("single upload"), "{err}");
        drop(single_up);
        assert!(f
            .flow
            .approve_batch(&third.batch_plan_id, true, &third.confirm_phrase)
            .is_ok());
    }

    #[test]
    fn a_folder_and_glob_expand_sorted_inside_the_allowed_roots() {
        let f = fixture("");
        for name in ["z.png", "m.png", "sub/n.png", "skip.txt"] {
            f.write(name, "Image");
        }
        let req = BatchPlanRequest {
            folder: Some(f.exports.to_string_lossy().into_owned()),
            glob: Some("*.png".into()),
            asset_type: Some("Image".into()),
            creator: Some("personal".into()),
            ..Default::default()
        };
        let plan = f.flow.plan_batch(req.clone()).unwrap();
        let names: Vec<&str> = plan.items.iter().map(|i| i.display_name.as_str()).collect();
        assert_eq!(names, ["m", "z"]);

        let mut deep = req.clone();
        deep.glob = Some("**/*.png".into());
        assert_eq!(f.flow.plan_batch(deep).unwrap().total_files, 3);

        // The folder itself must be inside the roots.
        let mut outside = req.clone();
        outside.folder = Some(f.exports.parent().unwrap().to_string_lossy().into_owned());
        let failure = f.flow.plan_batch(outside).unwrap_err();
        assert!(failure.error.contains("outside"), "{failure}");

        // Mixed or missing forms are errors.
        let mut both = req.clone();
        both.items = Some(vec![f.item("q.png", "Image")]);
        assert!(f.flow.plan_batch(both).is_err());
        let mut no_type = req.clone();
        no_type.asset_type = None;
        assert!(f.flow.plan_batch(no_type).is_err());
        let mut nothing = req;
        nothing.folder = None;
        nothing.items = None;
        assert!(f.flow.plan_batch(nothing).is_err());

        // A glob that matches more than max_batch_files is refused up front.
        let small = fixture(r#", "max_batch_files": 1"#);
        small.write("a.png", "Image");
        small.write("b.png", "Image");
        let failure = small
            .flow
            .plan_batch(BatchPlanRequest {
                folder: Some(small.exports.to_string_lossy().into_owned()),
                glob: Some("*.png".into()),
                asset_type: Some("Image".into()),
                creator: Some("personal".into()),
                ..Default::default()
            })
            .unwrap_err();
        assert!(failure.error.contains("more than 1"), "{failure}");
    }

    #[test]
    fn the_rate_limit_estimate_accounts_for_the_window() {
        assert_eq!(estimate_rate_wait(0, 10, &[]), secs(0));
        assert_eq!(estimate_rate_wait(10, 10, &[]), secs(0));
        assert_eq!(estimate_rate_wait(11, 10, &[]), secs(60));
        assert_eq!(estimate_rate_wait(26, 10, &[]), secs(120));
        assert_eq!(estimate_rate_wait(1, 1, &[secs(20)]), secs(40));
        assert_eq!(estimate_rate_wait(3, 2, &[secs(50), secs(10)]), secs(70));
    }

    #[test]
    fn the_window_wait_helper_reports_the_time_until_room() {
        let now = Instant::now();
        let at = |age: u64| now - secs(age);
        let mut q: VecDeque<Instant> = VecDeque::new();
        assert_eq!(window_wait(&q, now, 3), Duration::ZERO);
        q.extend([at(30), at(20), at(10)]);
        // room under a bigger limit
        assert_eq!(window_wait(&q, now, 4), Duration::ZERO);
        // full: the oldest (30s old) frees a slot in 30s
        assert_eq!(window_wait(&q, now, 3), secs(30));
        // limit 2 with 3 live: two must age out, the second oldest is 20s old
        assert_eq!(window_wait(&q, now, 2), secs(40));
        // expired entries do not count
        q.push_front(at(70));
        assert_eq!(window_wait(&q, now, 3), secs(30));
        assert_eq!(window_wait(&q, now, 4), Duration::ZERO);
    }
}
