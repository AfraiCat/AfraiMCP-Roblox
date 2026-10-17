//! Authentication providers for the Open Cloud tools.
//!
//! Placeholder seam (plan step 3). It will define an `AuthProvider` trait with
//! an API-key provider (header `x-api-key`, the default) and an OAuth provider
//! (the existing flow in `oauth.rs`, with the client secret read from
//! `secret_store` rather than environment variables), plus a `cloud_auth_status`
//! that reports scopes and expiry and never prints a secret.
//!
//! Intentionally empty until then.
