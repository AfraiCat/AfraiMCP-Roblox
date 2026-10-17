//! Secret storage behind a trait.
//!
//! Placeholder seam (plan step 3). It will hold the Windows Credential
//! Manager / DPAPI backend and an in-memory backend for tests, a one-time CLI
//! prompt for entering a key (never a tool argument or MCP-config environment
//! variable), and the redaction helpers that keep keys and tokens out of logs
//! and error text.
//!
//! Intentionally empty until then; `token_store.rs` still stores OAuth tokens
//! as plaintext JSON and is migrated away from in that step.
