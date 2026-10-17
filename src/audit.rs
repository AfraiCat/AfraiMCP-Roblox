//! Append-only, hash-chained audit log of uploads.
//!
//! One JSON object per line. Every line carries the SHA-256 of the previous
//! line's hash plus its own content, so editing or deleting a middle line is
//! detectable. The newest `seq:hash` is also kept in the secret store (DPAPI),
//! so truncating or replacing the file is detectable too. Nothing secret is
//! logged: no keys, tokens or file contents, and free-text details pass the
//! redactor.
//!
//! The server fails closed: an upload step that cannot be recorded does not
//! happen, and a log that fails verification blocks further uploads until a
//! person looks at it (`rbx-studio-mcp audit-verify`).
//!
//! Honest limit: someone with the same Windows user can still rewrite both the
//! file and the stored head. This catches accidents and an agent editing files.

use crate::policy::app_dir;
use crate::secret_store::{redact, Secret, SecretStore, AUDIT_HEAD};
use color_eyre::eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// `prev_hash` of the first line.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What happened, filled in by the caller. All fields except `event` are optional.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// An entry plus its place in the chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub time: String,
    #[serde(flatten)]
    pub entry: AuditEntry,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditRecord {
    fn compute_hash(&self) -> String {
        let mut body = self.clone();
        body.hash = String::new();
        let json = serde_json::to_string(&body).expect("audit records always serialize");
        let mut hasher = Sha256::new();
        hasher.update(body.prev_hash.as_bytes());
        hasher.update(json.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Result of checking the whole log.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChainStatus {
    pub ok: bool,
    pub records: usize,
    pub problem: Option<String>,
}

pub struct AuditLog {
    path: PathBuf,
    secrets: Arc<dyn SecretStore>,
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(path: PathBuf, secrets: Arc<dyn SecretStore>) -> Self {
        Self {
            path,
            secrets,
            lock: Mutex::new(()),
        }
    }

    pub fn default_path() -> Result<PathBuf> {
        Ok(app_dir()?.join("audit").join("uploads.jsonl"))
    }

    fn read_records(&self) -> Result<Vec<AuditRecord>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).wrap_err("reading the audit log"),
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .enumerate()
            .map(|(i, line)| {
                serde_json::from_str::<AuditRecord>(line)
                    .map_err(|_| eyre!("audit log line {} is not a valid record", i + 1))
            })
            .collect()
    }

    fn head(&self) -> Option<String> {
        self.secrets
            .get(AUDIT_HEAD)
            .ok()
            .flatten()
            .map(|s| s.expose().to_string())
    }

    fn check(&self, records: &[AuditRecord]) -> ChainStatus {
        let fail = |problem: String| ChainStatus {
            ok: false,
            records: records.len(),
            problem: Some(problem),
        };
        let mut prev = GENESIS_HASH.to_string();
        for (i, record) in records.iter().enumerate() {
            let line = i + 1;
            if record.seq != i as u64 + 1 {
                return fail(format!("line {line}: sequence number is {}", record.seq));
            }
            if record.prev_hash != prev {
                return fail(format!("line {line}: does not follow the previous line"));
            }
            if record.compute_hash() != record.hash {
                return fail(format!("line {line}: content was changed"));
            }
            prev = record.hash.clone();
        }
        match (self.head(), records.last()) {
            (Some(head), Some(last)) if head != format!("{}:{}", last.seq, last.hash) => {
                return fail(
                    "the log is shorter than, or different from, what was last recorded \
                     (lines were removed or the file was replaced)"
                        .to_string(),
                );
            }
            (Some(_), None) => {
                return fail("the log is empty but entries were recorded before".to_string());
            }
            _ => {}
        }
        ChainStatus {
            ok: true,
            records: records.len(),
            problem: None,
        }
    }

    /// Verify the whole chain and the stored head.
    pub fn verify(&self) -> ChainStatus {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        match self.read_records() {
            Ok(records) => self.check(&records),
            Err(e) => ChainStatus {
                ok: false,
                records: 0,
                problem: Some(e.to_string()),
            },
        }
    }

    /// Add a line. Fails (so the caller must not proceed) if the log is
    /// unreadable, fails verification, or cannot be written.
    pub fn append(&self, mut entry: AuditEntry) -> Result<AuditRecord> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(detail) = entry.detail.take() {
            entry.detail = Some(redact(&detail));
        }
        let records = self.read_records().map_err(|e| {
            eyre!(
                "the audit log could not be read ({e}); a person must review it with \
                 `rbx-studio-mcp audit-verify` before more uploads"
            )
        })?;
        let status = self.check(&records);
        if !status.ok {
            return Err(eyre!(
                "the audit log failed verification ({}); a person must review it with \
                 `rbx-studio-mcp audit-verify` before more uploads",
                status.problem.unwrap_or_default()
            ));
        }
        let (seq, prev_hash) = match records.last() {
            Some(last) => (last.seq + 1, last.hash.clone()),
            None => (1, GENESIS_HASH.to_string()),
        };
        let mut record = AuditRecord {
            seq,
            time: now_rfc3339(),
            entry,
            prev_hash,
            hash: String::new(),
        };
        record.hash = record.compute_hash();

        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).wrap_err("creating the audit folder")?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .wrap_err("opening the audit log")?;
        let line = serde_json::to_string(&record)?;
        writeln!(file, "{line}").wrap_err("writing the audit log")?;
        file.flush().wrap_err("flushing the audit log")?;

        // Best effort: platforms without a secure store simply have no head.
        let _ = self.secrets.set(
            AUDIT_HEAD,
            &Secret::new(format!("{}:{}", record.seq, record.hash)),
        );
        Ok(record)
    }

    /// The newest `count` records (oldest first) and the chain status.
    pub fn tail(&self, count: usize) -> Result<(Vec<AuditRecord>, ChainStatus)> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let records = self.read_records()?;
        let status = self.check(&records);
        let skip = records.len().saturating_sub(count);
        Ok((records.into_iter().skip(skip).collect(), status))
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::MemoryStore;

    fn log() -> (AuditLog, PathBuf, Arc<dyn SecretStore>) {
        let dir = std::env::temp_dir().join(format!("rbx-audit-{}", uuid::Uuid::new_v4()));
        let path = dir.join("uploads.jsonl");
        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        (AuditLog::new(path.clone(), secrets.clone()), path, secrets)
    }

    fn entry(event: &str) -> AuditEntry {
        AuditEntry {
            event: event.into(),
            sha256: Some("ab".repeat(32)),
            bytes: Some(10),
            ..Default::default()
        }
    }

    #[test]
    fn lines_chain_and_verify() {
        let (log, path, _) = log();
        assert_eq!(
            log.verify(),
            ChainStatus {
                ok: true,
                records: 0,
                problem: None
            }
        );
        let a = log.append(entry("plan")).unwrap();
        let b = log.append(entry("upload_started")).unwrap();
        assert_eq!((a.seq, b.seq), (1, 2));
        assert_eq!(a.prev_hash, GENESIS_HASH);
        assert_eq!(b.prev_hash, a.hash);
        assert!(log.verify().ok);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn editing_a_line_breaks_the_chain() {
        let (log, path, _) = log();
        for e in ["plan", "upload_started", "upload_finished"] {
            log.append(entry(e)).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"bytes\":10", "\"bytes\":11")).unwrap();
        let status = log.verify();
        assert!(!status.ok);
        assert!(status.problem.unwrap().contains("changed"));
    }

    #[test]
    fn deleting_a_middle_line_breaks_the_chain() {
        let (log, path, _) = log();
        for e in ["plan", "upload_started", "upload_finished"] {
            log.append(entry(e)).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
        assert!(!log.verify().ok);
    }

    #[test]
    fn truncating_the_tail_or_deleting_the_file_is_caught_by_the_stored_head() {
        let (log, path, _) = log();
        for e in ["plan", "upload_started", "upload_finished"] {
            log.append(entry(e)).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let first_two: Vec<&str> = text.lines().take(2).collect();
        std::fs::write(&path, first_two.join("\n") + "\n").unwrap();
        let status = log.verify();
        assert!(!status.ok, "{status:?}");
        assert!(status.problem.unwrap().contains("shorter"));

        std::fs::remove_file(&path).unwrap();
        assert!(!log.verify().ok);
    }

    #[test]
    fn a_broken_log_refuses_new_entries() {
        let (log, path, _) = log();
        log.append(entry("plan")).unwrap();
        std::fs::write(&path, "not json\n").unwrap();
        let err = log.append(entry("upload_started")).unwrap_err().to_string();
        assert!(err.contains("audit-verify"), "{err}");
    }

    #[test]
    fn details_are_redacted_and_secrets_never_land_in_the_file() {
        let (log, path, _) = log();
        let mut e = entry("upload_failed");
        e.detail = Some(
            "rejected: x-api-key: abcdef123456 Zk3fQ9xLmN2pRt7vWb4YcD8eHjK5sUaP1gXoIq6TyChEzF0lBn"
                .into(),
        );
        log.append(e).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("abcdef123456"), "{text}");
        assert!(!text.contains("Zk3fQ9xLmN2p"), "{text}");
        assert!(log.verify().ok);
    }

    #[test]
    fn tail_returns_the_newest_records_with_status() {
        let (log, _, _) = log();
        for i in 0..5 {
            log.append(entry(&format!("e{i}"))).unwrap();
        }
        let (records, status) = log.tail(2).unwrap();
        assert!(status.ok);
        assert_eq!(
            records
                .iter()
                .map(|r| r.entry.event.as_str())
                .collect::<Vec<_>>(),
            ["e3", "e4"]
        );
        assert_eq!(log.tail(100).unwrap().0.len(), 5);
    }
}
