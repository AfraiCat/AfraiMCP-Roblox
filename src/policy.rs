//! Upload policy: what an agent is allowed to upload, and where.
//!
//! Placeholder seam (plan step 4). It will load the HMAC-signed
//! `upload-policy.json` (disabled by default) at call time and enforce the
//! enabled flag, allowed roots and deny globs on the canonicalized path, the
//! asset-type allowlist, size cap, creator aliases and the rate limit. An
//! unsigned or altered policy refuses every upload.
//!
//! Intentionally empty until then. Uploads are not gated yet, so the cloud
//! tools must not be registered in Claude before that step lands.
