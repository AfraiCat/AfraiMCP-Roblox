//! Asset types, file extensions, content types and validation.
//!
//! Placeholder seam (plan step 2, `Claude-Migration/plans/roblox-mcp-direct-upload.md`).
//! It will hold the enum of the real Open Cloud asset types (Animation, Audio,
//! Decal, Image, Mesh, Model, Video), per-type extensions and size limits, the
//! explicit multipart content types, and magic-byte sniffing that rejects a file
//! whose bytes do not match its declared type. Implementation order follows the
//! user's priority: Model, then Image, then Audio, then the rest.
//!
//! Intentionally empty until then; `open_cloud.rs` still owns the current
//! (known-incomplete) validation.
