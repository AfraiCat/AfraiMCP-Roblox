//! Append-only, hash-chained audit log of uploads.
//!
//! Placeholder seam (plan step 4, extended in step 5). It will write JSONL
//! lines (time, sha256, bytes, asset type, creator, operation path, asset id,
//! status; never secrets or file contents) where each line carries the hash of
//! the previous one so tampering is detectable, and back the `audit_log_tail`
//! tool.
//!
//! Intentionally empty until then.
