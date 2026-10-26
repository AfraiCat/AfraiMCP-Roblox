//! Upload policy: what an agent is allowed to upload, and where.
//!
//! The policy is a JSON file a person creates (`rbx-studio-mcp policy init`),
//! edits and signs (`rbx-studio-mcp policy sign`). The signature is an
//! HMAC-SHA256 over the exact file bytes with a key kept in the secret store.
//! It is loaded and verified on every upload call; a missing, unsigned or
//! altered policy refuses everything, and a policy with `enabled: false`
//! (the default) refuses everything too. An agent that edits the file cannot
//! re-sign it without the signing step, which needs an interactive terminal.
//!
//! Honest limit: malicious code running as the same Windows user can also run
//! the signing step or read the key. This stops accidents, prompt-injected
//! uploads of the wrong file and silent policy changes, not that.

use crate::asset_types::AssetKind;
use crate::secret_store::{Secret, SecretStore, POLICY_KEY};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use color_eyre::eyre::{eyre, Result, WrapErr};
use globset::{GlobBuilder, GlobMatcher};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

pub const POLICY_FILE: &str = "upload-policy.json";
pub const SIGNATURE_FILE: &str = "upload-policy.sig";

/// Rules that apply whatever the policy says: private reference material,
/// secrets and the server's own state can never be uploaded.
const BUILTIN_DENY_GLOBS: [&str; 7] = [
    "**/reference-images/**",
    "**/.env",
    "**/.env.*",
    "**/oauth-tokens.json",
    "**/*.dpapi",
    "**/rbx-studio-mcp/**",
    "**/upload-policy.*",
];

/// The folder that holds the policy, signature, secrets and audit log.
pub fn app_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .map(|d| d.join("rbx-studio-mcp"))
        .ok_or_else(|| eyre!("no config directory"))
}

/// Who owns an uploaded asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Creator {
    User(String),
    Group(String),
}

impl Creator {
    pub fn kind(&self) -> &'static str {
        match self {
            Creator::User(_) => "user",
            Creator::Group(_) => "group",
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Creator::User(id) | Creator::Group(id) => id,
        }
    }

    /// `user 123` / `group 456`.
    pub fn label(&self) -> String {
        format!("{} {}", self.kind(), self.id())
    }
}

/// A creator together with the alias it was chosen by, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCreator {
    pub creator: Creator,
    pub alias: Option<String>,
}

impl ResolvedCreator {
    /// `personal (user 123)` or `user 123`.
    pub fn describe(&self) -> String {
        match &self.alias {
            Some(alias) => format!("{alias} ({})", self.creator.label()),
            None => self.creator.label(),
        }
    }
}

/// One entry of `creators`: exactly one of `userId` or `groupId`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreatorSpec {
    #[serde(rename = "userId", default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(rename = "groupId", default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
}

fn numeric_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.chars().all(|c| c.is_ascii_digit())
}

impl CreatorSpec {
    fn to_creator(&self, alias: &str) -> Result<Creator, PolicyError> {
        match (&self.user_id, &self.group_id) {
            (Some(u), None) if numeric_id(u) => Ok(Creator::User(u.clone())),
            (None, Some(g)) if numeric_id(g) => Ok(Creator::Group(g.clone())),
            _ => Err(PolicyError::Invalid(format!(
                "creator '{alias}' needs exactly one numeric userId or groupId"
            ))),
        }
    }
}

fn default_types() -> Vec<String> {
    AssetKind::ALL
        .iter()
        .map(|k| k.api_name().to_string())
        .collect()
}

fn default_max_bytes() -> u64 {
    crate::asset_types::MAX_UPLOAD_BYTES
}

fn default_true() -> bool {
    true
}

fn default_rate() -> u32 {
    10
}

/// Default and hard limits for `max_batch_files`.
pub const DEFAULT_MAX_BATCH_FILES: u32 = 25;
pub const MAX_BATCH_FILES_CEILING: u32 = 200;

fn default_max_batch_files() -> u32 {
    DEFAULT_MAX_BATCH_FILES
}

/// The policy document. Unknown fields are rejected so a typo can never
/// silently fall back to a default. Every default is the safe one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub enabled: bool,
    /// Folders (glob patterns, `/` separators) an uploaded file must live in.
    #[serde(default)]
    pub allowed_roots: Vec<String>,
    /// Extra deny patterns on top of the built-in ones.
    #[serde(default)]
    pub deny_globs: Vec<String>,
    #[serde(default = "default_types")]
    pub allowed_asset_types: Vec<String>,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Named upload targets (personal account, groups).
    #[serde(default)]
    pub creators: BTreeMap<String, CreatorSpec>,
    /// Alias used when the caller names no target; leave unset to force the
    /// agent to ask the user where to upload.
    #[serde(default)]
    pub default_creator: Option<String>,
    /// Allow a raw `userId`/`groupId` that is not listed in `creators`.
    #[serde(default = "default_true")]
    pub allow_unlisted_creators: bool,
    #[serde(default = "default_rate")]
    pub rate_limit_per_minute: u32,
    /// Most files one batch upload may contain (1-200). Optional: a policy
    /// signed before batch mode existed keeps working with the default. Every
    /// other rule of the policy still applies to each file of a batch.
    #[serde(default = "default_max_batch_files")]
    pub max_batch_files: u32,
}

impl Policy {
    /// What `policy init` writes: everything switched off, nothing allowed yet.
    pub fn template() -> Self {
        Policy {
            enabled: false,
            allowed_roots: Vec::new(),
            deny_globs: vec![
                "**/*.spp".to_string(),
                "**/*token*".to_string(),
                "**/*secret*".to_string(),
            ],
            allowed_asset_types: default_types(),
            max_bytes: default_max_bytes(),
            creators: BTreeMap::new(),
            default_creator: None,
            allow_unlisted_creators: true,
            rate_limit_per_minute: default_rate(),
            max_batch_files: default_max_batch_files(),
        }
    }

    fn matcher(pattern: &str) -> Result<GlobMatcher, PolicyError> {
        let normalized = pattern.replace('\\', "/");
        GlobBuilder::new(normalized.trim_end_matches('/'))
            .literal_separator(true)
            .case_insensitive(true)
            .build()
            .map(|g| g.compile_matcher())
            .map_err(|e| PolicyError::Invalid(format!("bad pattern '{pattern}': {e}")))
    }

    /// Check the document is internally consistent (called when loading and
    /// before signing, so a broken policy can not be signed).
    pub fn validate(&self) -> Result<(), PolicyError> {
        for pattern in self.allowed_roots.iter().chain(self.deny_globs.iter()) {
            Self::matcher(pattern)?;
        }
        for name in &self.allowed_asset_types {
            AssetKind::parse(name)
                .map_err(|_| PolicyError::Invalid(format!("unknown asset type '{name}'")))?;
        }
        for (alias, spec) in &self.creators {
            if alias.trim().is_empty() {
                return Err(PolicyError::Invalid("empty creator alias".into()));
            }
            spec.to_creator(alias)?;
        }
        if let Some(default) = &self.default_creator {
            if !self.creators.contains_key(default) {
                return Err(PolicyError::Invalid(format!(
                    "default_creator '{default}' is not listed in creators"
                )));
            }
        }
        if self.max_bytes == 0 {
            return Err(PolicyError::Invalid("max_bytes must be above 0".into()));
        }
        if self.rate_limit_per_minute == 0 || self.rate_limit_per_minute > 600 {
            return Err(PolicyError::Invalid(
                "rate_limit_per_minute must be between 1 and 600".into(),
            ));
        }
        if self.max_batch_files == 0 || self.max_batch_files > MAX_BATCH_FILES_CEILING {
            return Err(PolicyError::Invalid(format!(
                "max_batch_files must be between 1 and {MAX_BATCH_FILES_CEILING}"
            )));
        }
        Ok(())
    }

    /// May this kind of asset be uploaded at this size?
    pub fn check_kind_and_size(&self, kind: AssetKind, len: u64) -> Result<(), PolicyError> {
        let allowed = self
            .allowed_asset_types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(kind.api_name()));
        if !allowed {
            return Err(PolicyError::Denied(format!(
                "the policy does not allow {kind} uploads"
            )));
        }
        let limit = self.max_bytes.min(kind.max_bytes());
        if len > limit {
            return Err(PolicyError::Denied(format!(
                "the file is {len} bytes; the policy allows at most {limit}"
            )));
        }
        Ok(())
    }

    /// Resolve the path (symlinks and `..` included) and check it against the
    /// deny rules and allowed roots. Returns the canonical path to read from.
    pub fn check_path(&self, path: &Path) -> Result<PathBuf, PolicyError> {
        let canonical = std::fs::canonicalize(path).map_err(|e| {
            PolicyError::Denied(format!("cannot resolve the file ({:?})", e.kind()))
        })?;
        if !canonical.is_file() {
            return Err(PolicyError::Denied("the path is not a regular file".into()));
        }
        let normalized = normalize(&canonical);

        for pattern in BUILTIN_DENY_GLOBS
            .iter()
            .copied()
            .chain(self.deny_globs.iter().map(String::as_str))
        {
            if Self::matcher(pattern)?.is_match(&normalized) {
                return Err(PolicyError::Denied(format!(
                    "the file matches the deny rule '{pattern}'"
                )));
            }
        }

        let mut roots = Vec::with_capacity(self.allowed_roots.len());
        for root in &self.allowed_roots {
            roots.push(Self::matcher(root)?);
        }
        let inside = canonical
            .ancestors()
            .skip(1)
            .map(normalize)
            .any(|ancestor| roots.iter().any(|r| r.is_match(&ancestor)));
        if !inside {
            return Err(PolicyError::Denied(
                "the file is outside every allowed_roots folder".into(),
            ));
        }
        Ok(canonical)
    }

    /// Resolve a folder and check it sits inside an allowed root (the folder
    /// may itself be a root). Used by batch uploads before listing it.
    pub fn check_folder(&self, folder: &Path) -> Result<PathBuf, PolicyError> {
        let canonical = std::fs::canonicalize(folder).map_err(|e| {
            PolicyError::Denied(format!("cannot resolve the folder ({:?})", e.kind()))
        })?;
        if !canonical.is_dir() {
            return Err(PolicyError::Denied("the path is not a folder".into()));
        }
        let mut roots = Vec::with_capacity(self.allowed_roots.len());
        for root in &self.allowed_roots {
            roots.push(Self::matcher(root)?);
        }
        let inside = canonical
            .ancestors()
            .map(normalize)
            .any(|ancestor| roots.iter().any(|r| r.is_match(&ancestor)));
        if !inside {
            return Err(PolicyError::Denied(
                "the folder is outside every allowed_roots folder".into(),
            ));
        }
        Ok(canonical)
    }

    /// List the files under `folder` (already checked with [`check_folder`])
    /// whose path relative to it matches `pattern` (`/` separators; `*.png`
    /// matches the top level only, `**/*.png` also sub-folders). The result is
    /// sorted. Symlinks are never followed into folders, and a file symlink
    /// whose target resolves outside the folder is reported in `skipped`, not
    /// listed. Every listed file still goes through [`check_path`] later.
    pub fn expand_folder(
        &self,
        folder: &Path,
        pattern: &str,
        limit: usize,
    ) -> Result<FolderListing, PolicyError> {
        const MAX_DEPTH: usize = 12;
        const MAX_ENTRIES: usize = 20_000;
        let matcher = Self::matcher(pattern)?;
        let root = std::fs::canonicalize(folder).map_err(|e| {
            PolicyError::Denied(format!("cannot resolve the folder ({:?})", e.kind()))
        })?;
        let io = |e: std::io::Error| {
            PolicyError::Denied(format!("cannot list the folder ({:?})", e.kind()))
        };
        let mut found = std::collections::BTreeSet::new();
        let mut skipped = Vec::new();
        let mut visited = 0usize;
        let mut stack = vec![(root.clone(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            for entry in std::fs::read_dir(&dir).map_err(io)? {
                let entry = entry.map_err(io)?;
                visited += 1;
                if visited > MAX_ENTRIES {
                    return Err(PolicyError::Denied(format!(
                        "the folder holds more than {MAX_ENTRIES} entries; use a narrower folder"
                    )));
                }
                let kind = entry.file_type().map_err(io)?;
                let path = entry.path();
                let candidate = if kind.is_symlink() {
                    match std::fs::canonicalize(&path) {
                        Ok(target) if !target.starts_with(&root) => {
                            skipped.push((
                                normalize(&path),
                                "a symlink that resolves outside the folder".to_string(),
                            ));
                            continue;
                        }
                        Ok(target) if target.is_file() => target,
                        Ok(_) => continue, // symlinked folders are not followed
                        Err(_) => {
                            skipped.push((normalize(&path), "a broken symlink".to_string()));
                            continue;
                        }
                    }
                } else if kind.is_dir() {
                    if depth < MAX_DEPTH {
                        stack.push((path, depth + 1));
                    }
                    continue;
                } else if kind.is_file() {
                    path
                } else {
                    continue;
                };
                let Ok(relative) = candidate.strip_prefix(&root) else {
                    continue;
                };
                if matcher.is_match(normalize(relative)) {
                    found.insert(normalize(&candidate));
                    if found.len() > limit {
                        return Err(PolicyError::Denied(format!(
                            "the glob matches more than {limit} files (max_batch_files);                              narrow the glob or split the batch"
                        )));
                    }
                }
            }
        }
        Ok(FolderListing {
            files: found.into_iter().map(PathBuf::from).collect(),
            skipped,
        })
    }

    /// Is this creator acceptable under the policy (listed, or unlisted ones allowed)?
    pub fn permits_creator(&self, creator: &Creator) -> bool {
        self.allow_unlisted_creators
            || self
                .creators
                .iter()
                .filter_map(|(alias, spec)| spec.to_creator(alias).ok())
                .any(|c| &c == creator)
    }

    fn listed_creators(&self) -> String {
        if self.creators.is_empty() {
            return "no creators are listed in the policy".to_string();
        }
        self.creators
            .iter()
            .filter_map(|(alias, spec)| {
                spec.to_creator(alias)
                    .ok()
                    .map(|c| format!("{alias} ({})", c.label()))
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Pick the upload target. Exactly one of alias, userId, groupId may be
    /// given; with none, `default_creator` applies, and without that the error
    /// tells the agent to ask the user where to upload.
    pub fn resolve_creator(
        &self,
        alias: Option<&str>,
        user_id: Option<&str>,
        group_id: Option<&str>,
    ) -> Result<ResolvedCreator, PolicyError> {
        let given = [alias.is_some(), user_id.is_some(), group_id.is_some()]
            .into_iter()
            .filter(|g| *g)
            .count();
        if given > 1 {
            return Err(PolicyError::Creator(
                "give only one of creator, userId or groupId".into(),
            ));
        }

        let by_alias = |name: &str| -> Result<ResolvedCreator, PolicyError> {
            let spec = self.creators.get(name).ok_or_else(|| {
                PolicyError::Creator(format!(
                    "unknown creator '{name}'. Available: {}. Ask the user which one to use.",
                    self.listed_creators()
                ))
            })?;
            Ok(ResolvedCreator {
                creator: spec.to_creator(name)?,
                alias: Some(name.to_string()),
            })
        };

        let raw = |creator: Creator| -> Result<ResolvedCreator, PolicyError> {
            if !self.permits_creator(&creator) {
                return Err(PolicyError::Creator(format!(
                    "{} is not listed in the policy and unlisted creators are not allowed. \
                     Available: {}",
                    creator.label(),
                    self.listed_creators()
                )));
            }
            let alias = self.creators.iter().find_map(|(name, spec)| {
                (spec.to_creator(name).ok().as_ref() == Some(&creator)).then(|| name.clone())
            });
            Ok(ResolvedCreator { creator, alias })
        };

        match (alias, user_id, group_id) {
            (Some(name), _, _) => by_alias(name.trim()),
            (_, Some(id), _) => {
                let id = id.trim();
                if !numeric_id(id) {
                    return Err(PolicyError::Creator("userId must be a number".into()));
                }
                raw(Creator::User(id.to_string()))
            }
            (_, _, Some(id)) => {
                let id = id.trim();
                if !numeric_id(id) {
                    return Err(PolicyError::Creator("groupId must be a number".into()));
                }
                raw(Creator::Group(id.to_string()))
            }
            _ => match &self.default_creator {
                Some(name) => by_alias(name),
                None => Err(PolicyError::Creator(format!(
                    "No upload target was given. Ask the user where to upload (a personal \
                     account or a group) and pass creator, userId or groupId. Available: {}.",
                    self.listed_creators()
                ))),
            },
        }
    }
}

/// What [`Policy::expand_folder`] found.
#[derive(Debug, Default)]
pub struct FolderListing {
    /// Matching files, sorted, as normalized (`/`) paths.
    pub files: Vec<PathBuf>,
    /// Entries left out on purpose, as (path, reason).
    pub skipped: Vec<(String, String)>,
}

/// `C:/dir/file` form: forward slashes, no `\\?\` prefix.
fn normalize(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    s.strip_prefix("//?/").map(str::to_string).unwrap_or(s)
}

/// Why the policy refused or could not be used. Messages are written for the
/// agent that will read them and never contain secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Missing,
    Unsigned,
    BadSignature,
    NoSigningKey,
    Disabled,
    Invalid(String),
    Denied(String),
    Creator(String),
    Io(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Missing => f.write_str(
                "No upload policy exists, so uploads are off. A person must create one: run \
                 `rbx-studio-mcp policy init`, edit the file, then `rbx-studio-mcp policy sign`.",
            ),
            PolicyError::Unsigned => f.write_str(
                "The upload policy has no signature, so uploads are off. A person must review it \
                 and run `rbx-studio-mcp policy sign`.",
            ),
            PolicyError::BadSignature => f.write_str(
                "The upload policy does not match its signature (it was edited after signing, or \
                 signed with another key), so uploads are off. A person must review it and run \
                 `rbx-studio-mcp policy sign`.",
            ),
            PolicyError::NoSigningKey => f.write_str(
                "There is no policy signing key, so uploads are off. A person must run \
                 `rbx-studio-mcp policy sign`.",
            ),
            PolicyError::Disabled => f.write_str(
                "Uploads are disabled in the policy (enabled is false). Only the user can change \
                 that; do not try to work around it.",
            ),
            PolicyError::Invalid(why) => write!(f, "The upload policy is invalid: {why}."),
            PolicyError::Denied(why) => write!(f, "Upload refused: {why}."),
            PolicyError::Creator(why) => write!(f, "{why}"),
            PolicyError::Io(why) => write!(f, "Policy file problem: {why}."),
        }
    }
}

impl std::error::Error for PolicyError {}

/// A policy whose signature was checked. Only [`PolicyStore`] creates one.
#[derive(Debug, Clone)]
pub struct VerifiedPolicy(Policy);

impl std::ops::Deref for VerifiedPolicy {
    type Target = Policy;
    fn deref(&self) -> &Policy {
        &self.0
    }
}

/// What `policy sign` / `policy show` report (no secrets).
#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub enabled: bool,
    pub allowed_roots: Vec<String>,
    pub allowed_asset_types: Vec<String>,
    pub creators: Vec<String>,
    pub default_creator: Option<String>,
    pub allow_unlisted_creators: bool,
    pub max_bytes: u64,
    pub rate_limit_per_minute: u32,
    pub max_batch_files: u32,
}

impl From<&Policy> for PolicySummary {
    fn from(p: &Policy) -> Self {
        PolicySummary {
            enabled: p.enabled,
            allowed_roots: p.allowed_roots.clone(),
            allowed_asset_types: p.allowed_asset_types.clone(),
            creators: p
                .creators
                .iter()
                .filter_map(|(a, s)| s.to_creator(a).ok().map(|c| format!("{a} = {}", c.label())))
                .collect(),
            default_creator: p.default_creator.clone(),
            allow_unlisted_creators: p.allow_unlisted_creators,
            max_bytes: p.max_bytes,
            rate_limit_per_minute: p.rate_limit_per_minute,
            max_batch_files: p.max_batch_files,
        }
    }
}

/// Loads, verifies and (for the human CLI) creates and signs the policy.
pub struct PolicyStore {
    dir: PathBuf,
    secrets: Arc<dyn SecretStore>,
}

impl PolicyStore {
    pub fn new(dir: PathBuf, secrets: Arc<dyn SecretStore>) -> Self {
        Self { dir, secrets }
    }

    pub fn policy_path(&self) -> PathBuf {
        self.dir.join(POLICY_FILE)
    }

    pub fn signature_path(&self) -> PathBuf {
        self.dir.join(SIGNATURE_FILE)
    }

    fn signing_key(&self) -> Result<Option<Secret>> {
        self.secrets.get(POLICY_KEY)
    }

    /// Create the signing key if it does not exist yet. Returns true if created.
    fn ensure_signing_key(&self) -> Result<bool> {
        if self.signing_key()?.is_some() {
            return Ok(false);
        }
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        self.secrets
            .set(POLICY_KEY, &Secret::new(STANDARD.encode(bytes)))?;
        Ok(true)
    }

    fn mac(key: &Secret, bytes: &[u8]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(key.expose().as_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(bytes);
        mac
    }

    /// Write a safe template (everything off). Refuses to overwrite.
    pub fn init_template(&self) -> Result<PathBuf> {
        let path = self.policy_path();
        if path.exists() {
            return Err(eyre!(
                "{} already exists; edit it instead of re-creating it",
                path.display()
            ));
        }
        std::fs::create_dir_all(&self.dir).wrap_err("creating the policy folder")?;
        let json = serde_json::to_string_pretty(&Policy::template())?;
        std::fs::write(&path, json).wrap_err("writing the policy template")?;
        Ok(path)
    }

    /// Parse and validate the policy file without signing it (so a person can
    /// review exactly what they are about to approve).
    pub fn preview(&self) -> Result<PolicySummary> {
        let bytes = std::fs::read(self.policy_path())
            .map_err(|_| eyre!("no policy file; run `rbx-studio-mcp policy init` first"))?;
        let policy: Policy =
            serde_json::from_slice(&bytes).map_err(|e| eyre!("the policy is invalid: {e}"))?;
        policy.validate().map_err(|e| eyre!("{e}"))?;
        Ok(PolicySummary::from(&policy))
    }

    /// Validate the policy file and write its signature. The caller (the
    /// CLI) is responsible for making a human confirm.
    pub fn sign(&self) -> Result<PolicySummary> {
        let bytes = std::fs::read(self.policy_path())
            .map_err(|_| eyre!("no policy file; run `rbx-studio-mcp policy init` first"))?;
        let policy: Policy =
            serde_json::from_slice(&bytes).map_err(|e| eyre!("the policy is invalid: {e}"))?;
        policy.validate().map_err(|e| eyre!("{e}"))?;
        self.ensure_signing_key()?;
        let key = self
            .signing_key()?
            .ok_or_else(|| eyre!("could not read back the signing key"))?;
        let signature = hex::encode(Self::mac(&key, &bytes).finalize().into_bytes());
        std::fs::write(self.signature_path(), signature).wrap_err("writing the signature")?;
        Ok(PolicySummary::from(&policy))
    }

    /// Read the policy and verify its signature. Does not check `enabled`.
    pub fn load_verified(&self) -> Result<VerifiedPolicy, PolicyError> {
        let bytes = match std::fs::read(self.policy_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(PolicyError::Missing),
            Err(e) => return Err(PolicyError::Io(format!("{:?}", e.kind()))),
        };
        let signature = match std::fs::read_to_string(self.signature_path()) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(PolicyError::Unsigned)
            }
            Err(e) => return Err(PolicyError::Io(format!("{:?}", e.kind()))),
        };
        let key = self
            .signing_key()
            .map_err(|_| PolicyError::NoSigningKey)?
            .ok_or(PolicyError::NoSigningKey)?;
        let expected = hex::decode(signature.trim()).map_err(|_| PolicyError::BadSignature)?;
        Self::mac(&key, &bytes)
            .verify_slice(&expected)
            .map_err(|_| PolicyError::BadSignature)?;
        let policy: Policy = serde_json::from_slice(&bytes)
            .map_err(|e| PolicyError::Invalid(e.to_string().replace('\n', " ")))?;
        policy.validate()?;
        Ok(VerifiedPolicy(policy))
    }

    /// Verified and enabled: the only state in which an upload may proceed.
    pub fn load_enabled(&self) -> Result<VerifiedPolicy, PolicyError> {
        let policy = self.load_verified()?;
        if !policy.enabled {
            return Err(PolicyError::Disabled);
        }
        Ok(policy)
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use crate::secret_store::MemoryStore;

    pub fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rbx-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A policy store in a temp folder with `json` written and signed.
    pub fn signed_store(json: &str) -> (PolicyStore, PathBuf, Arc<dyn SecretStore>) {
        let dir = temp_dir("policy");
        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        let store = PolicyStore::new(dir.clone(), secrets.clone());
        std::fs::write(store.policy_path(), json).unwrap();
        store.sign().unwrap();
        (store, dir, secrets)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use std::fs;

    fn policy_json(root: &str, extra: &str) -> String {
        format!(
            r#"{{ "enabled": true, "allowed_roots": ["{root}"], "creators": {{
                "personal": {{ "userId": "111" }}, "team": {{ "groupId": "222" }} }} {extra} }}"#
        )
    }

    fn write_file(dir: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }

    fn root_of(dir: &Path) -> String {
        normalize(&fs::canonicalize(dir).unwrap())
    }

    #[test]
    fn missing_unsigned_altered_and_disabled_policies_refuse() {
        let dir = temp_dir("policy-states");
        let secrets: Arc<dyn SecretStore> = Arc::new(crate::secret_store::MemoryStore::new());
        let store = PolicyStore::new(dir.clone(), secrets);
        assert_eq!(store.load_enabled().unwrap_err(), PolicyError::Missing);

        fs::write(store.policy_path(), r#"{ "enabled": true }"#).unwrap();
        assert_eq!(store.load_enabled().unwrap_err(), PolicyError::Unsigned);

        store.sign().unwrap();
        assert!(store.load_enabled().is_ok());

        // An agent flips a setting after signing.
        fs::write(
            store.policy_path(),
            r#"{ "enabled": true, "max_bytes": 5 }"#,
        )
        .unwrap();
        assert_eq!(store.load_enabled().unwrap_err(), PolicyError::BadSignature);

        fs::write(store.policy_path(), r#"{ "enabled": false }"#).unwrap();
        store.sign().unwrap();
        assert_eq!(store.load_enabled().unwrap_err(), PolicyError::Disabled);
        assert!(store.load_verified().is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_signature_from_another_key_is_rejected() {
        let (store, dir, secrets) = signed_store(r#"{ "enabled": true }"#);
        secrets
            .set(POLICY_KEY, &Secret::new("a-different-signing-key-value"))
            .unwrap();
        assert_eq!(
            store.load_verified().unwrap_err(),
            PolicyError::BadSignature
        );
        secrets.delete(POLICY_KEY).unwrap();
        assert_eq!(
            store.load_verified().unwrap_err(),
            PolicyError::NoSigningKey
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unknown_fields_and_inconsistent_policies_can_not_be_signed() {
        for json in [
            r#"{ "enable": true }"#,
            r#"{ "default_creator": "nobody" }"#,
            r#"{ "creators": { "x": { "userId": "abc" } } }"#,
            r#"{ "creators": { "x": { "userId": "1", "groupId": "2" } } }"#,
            r#"{ "allowed_asset_types": ["Spaceship"] }"#,
            r#"{ "rate_limit_per_minute": 0 }"#,
            r#"{ "max_bytes": 0 }"#,
        ] {
            let dir = temp_dir("policy-bad");
            let secrets: Arc<dyn SecretStore> = Arc::new(crate::secret_store::MemoryStore::new());
            let store = PolicyStore::new(dir.clone(), secrets);
            fs::write(store.policy_path(), json).unwrap();
            assert!(store.sign().is_err(), "{json} was signed");
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn init_template_is_safe_and_never_overwrites() {
        let dir = temp_dir("policy-init");
        let secrets: Arc<dyn SecretStore> = Arc::new(crate::secret_store::MemoryStore::new());
        let store = PolicyStore::new(dir.clone(), secrets);
        store.init_template().unwrap();
        let policy: Policy =
            serde_json::from_slice(&fs::read(store.policy_path()).unwrap()).unwrap();
        assert!(!policy.enabled);
        assert!(policy.allowed_roots.is_empty());
        assert!(policy.default_creator.is_none());
        policy.validate().unwrap();
        assert!(store.init_template().is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn paths_must_sit_inside_an_allowed_root() {
        let dir = temp_dir("policy-paths");
        let inside = write_file(&dir, "exports/pet.glb", b"x");
        let outside_dir = temp_dir("policy-outside");
        let outside = write_file(&outside_dir, "other.glb", b"x");
        let root = format!("{}/exports", root_of(&dir));
        let (store, pdir, _) = signed_store(&policy_json(&root, ""));
        let policy = store.load_enabled().unwrap();

        assert!(policy.check_path(&inside).is_ok());
        assert!(matches!(
            policy.check_path(&outside),
            Err(PolicyError::Denied(_))
        ));
        assert!(matches!(
            policy.check_path(&dir.join("exports/missing.glb")),
            Err(PolicyError::Denied(_))
        ));
        // `..` traversal that escapes the root is resolved before the check.
        let sneaky = dir
            .join("exports")
            .join("..")
            .join("..")
            .join(outside_dir.file_name().unwrap())
            .join("other.glb");
        assert!(matches!(
            policy.check_path(&sneaky),
            Err(PolicyError::Denied(_))
        ));
        for d in [dir, outside_dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn a_wildcard_root_matches_sibling_project_folders() {
        let dir = temp_dir("policy-wild");
        let a = write_file(&dir, "Proj-A/asset/a.glb", b"x");
        let b = write_file(&dir, "Proj-B/asset/b.glb", b"x");
        let c = write_file(&dir, "Notes/asset/c.glb", b"x");
        let root = format!("{}/Proj-*/asset", root_of(&dir));
        let (store, pdir, _) = signed_store(&policy_json(&root, ""));
        let policy = store.load_enabled().unwrap();
        assert!(policy.check_path(&a).is_ok());
        assert!(policy.check_path(&b).is_ok());
        assert!(policy.check_path(&c).is_err());
        for d in [dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn deny_rules_win_over_roots_including_reference_images() {
        let dir = temp_dir("policy-deny");
        let reference = write_file(&dir, "exports/reference-images/ref.png", b"x");
        let token = write_file(&dir, "exports/my-token.png", b"x");
        let env = write_file(&dir, "exports/.env", b"x");
        let spp = write_file(&dir, "exports/paint.spp", b"x");
        let fine = write_file(&dir, "exports/pet.png", b"x");
        let root = root_of(&dir);
        // A root that covers everything: only the deny rules can stop these.
        let (store, pdir, _) = signed_store(&policy_json(
            &root,
            r#", "deny_globs": ["**/*.spp", "**/*token*"]"#,
        ));
        let policy = store.load_enabled().unwrap();
        for path in [&reference, &token, &env, &spp] {
            assert!(
                matches!(policy.check_path(path), Err(PolicyError::Denied(_))),
                "{} was allowed",
                path.display()
            );
        }
        assert!(policy.check_path(&fine).is_ok());
        for d in [dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn built_in_rules_apply_even_if_the_policy_lists_none() {
        let dir = temp_dir("policy-builtin");
        let reference = write_file(&dir, "reference-images/ref.png", b"x");
        let (store, pdir, _) = signed_store(&policy_json(&root_of(&dir), ""));
        let policy = store.load_enabled().unwrap();
        assert!(policy.check_path(&reference).is_err());
        for d in [dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        let dir = temp_dir("policy-link");
        let outside_dir = temp_dir("policy-link-out");
        let target = write_file(&outside_dir, "secret.glb", b"x");
        fs::create_dir_all(dir.join("exports")).unwrap();
        std::os::unix::fs::symlink(&target, dir.join("exports/link.glb")).unwrap();
        let (store, pdir, _) =
            signed_store(&policy_json(&format!("{}/exports", root_of(&dir)), ""));
        let policy = store.load_enabled().unwrap();
        assert!(policy.check_path(&dir.join("exports/link.glb")).is_err());
        for d in [dir, outside_dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        let dir = temp_dir("policy-link");
        let outside_dir = temp_dir("policy-link-out");
        let target = write_file(&outside_dir, "secret.glb", b"x");
        fs::create_dir_all(dir.join("exports")).unwrap();
        if std::os::windows::fs::symlink_file(&target, dir.join("exports/link.glb")).is_err() {
            eprintln!("skipped: creating symlinks needs Developer Mode or elevation");
            return;
        }
        let (store, pdir, _) =
            signed_store(&policy_json(&format!("{}/exports", root_of(&dir)), ""));
        let policy = store.load_enabled().unwrap();
        assert!(policy.check_path(&dir.join("exports/link.glb")).is_err());
        for d in [dir, outside_dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn type_and_size_limits() {
        let (store, pdir, _) = signed_store(
            r#"{ "enabled": true, "allowed_asset_types": ["Model", "image"], "max_bytes": 100 }"#,
        );
        let policy = store.load_enabled().unwrap();
        assert!(policy.check_kind_and_size(AssetKind::Model, 100).is_ok());
        assert!(policy.check_kind_and_size(AssetKind::Image, 1).is_ok());
        assert!(policy.check_kind_and_size(AssetKind::Audio, 1).is_err());
        assert!(policy.check_kind_and_size(AssetKind::Model, 101).is_err());
        let _ = fs::remove_dir_all(pdir);
    }

    #[test]
    fn a_creator_is_required_and_the_error_tells_the_agent_to_ask() {
        let (store, pdir, _) = signed_store(&policy_json("C:/x", ""));
        let policy = store.load_enabled().unwrap();
        let err = policy
            .resolve_creator(None, None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Ask the user"), "{err}");
        assert!(
            err.contains("personal (user 111)") && err.contains("team (group 222)"),
            "{err}"
        );
        let _ = fs::remove_dir_all(pdir);
    }

    #[test]
    fn creators_resolve_by_alias_or_raw_id_and_exactly_one_may_be_given() {
        let (store, pdir, _) = signed_store(&policy_json("C:/x", ""));
        let policy = store.load_enabled().unwrap();

        let by_alias = policy.resolve_creator(Some("team"), None, None).unwrap();
        assert_eq!(by_alias.creator, Creator::Group("222".into()));
        assert_eq!(by_alias.describe(), "team (group 222)");

        let listed = policy.resolve_creator(None, Some("111"), None).unwrap();
        assert_eq!(listed.alias.as_deref(), Some("personal"));

        let unlisted = policy.resolve_creator(None, Some("999"), None).unwrap();
        assert_eq!(unlisted.alias, None);
        assert_eq!(unlisted.describe(), "user 999");

        assert!(policy
            .resolve_creator(Some("team"), Some("1"), None)
            .is_err());
        assert!(policy.resolve_creator(None, Some("1"), Some("2")).is_err());
        assert!(policy.resolve_creator(Some("nobody"), None, None).is_err());
        assert!(policy.resolve_creator(None, Some("12ab"), None).is_err());
        assert!(policy.resolve_creator(None, None, Some("")).is_err());
        let _ = fs::remove_dir_all(pdir);
    }

    #[test]
    fn default_creator_applies_only_when_nothing_is_given_and_unlisted_can_be_blocked() {
        let (store, pdir, _) = signed_store(&policy_json(
            "C:/x",
            r#", "default_creator": "personal", "allow_unlisted_creators": false"#,
        ));
        let policy = store.load_enabled().unwrap();
        assert_eq!(
            policy.resolve_creator(None, None, None).unwrap().creator,
            Creator::User("111".into())
        );
        assert!(policy.resolve_creator(None, Some("999"), None).is_err());
        assert!(policy.resolve_creator(None, Some("111"), None).is_ok());
        assert!(!policy.permits_creator(&Creator::Group("999".into())));
        let _ = fs::remove_dir_all(pdir);
    }

    #[test]
    fn a_policy_without_max_batch_files_still_loads_with_the_default() {
        // The exact shape a policy signed before batch mode existed has.
        let (store, pdir, _) = signed_store(
            r#"{ "enabled": true, "allowed_roots": ["C:/x"], "rate_limit_per_minute": 5 }"#,
        );
        let policy = store.load_enabled().unwrap();
        assert_eq!(policy.max_batch_files, DEFAULT_MAX_BATCH_FILES);
        assert_eq!(PolicySummary::from(&*policy).max_batch_files, 25);
        let _ = fs::remove_dir_all(pdir);
    }

    #[test]
    fn max_batch_files_is_limited_to_1_through_200() {
        for (value, ok) in [(0, false), (1, true), (200, true), (201, false)] {
            let dir = temp_dir("policy-batch-limit");
            let secrets: Arc<dyn SecretStore> = Arc::new(crate::secret_store::MemoryStore::new());
            let store = PolicyStore::new(dir.clone(), secrets);
            fs::write(
                store.policy_path(),
                format!(r#"{{ "max_batch_files": {value} }}"#),
            )
            .unwrap();
            assert_eq!(store.sign().is_ok(), ok, "{value}");
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn folders_must_sit_inside_an_allowed_root() {
        let dir = temp_dir("policy-folder");
        write_file(&dir, "exports/a.png", b"x");
        write_file(&dir, "elsewhere/b.png", b"x");
        let root = format!("{}/exports", root_of(&dir));
        let (store, pdir, _) = signed_store(&policy_json(&root, ""));
        let policy = store.load_enabled().unwrap();
        assert!(policy.check_folder(&dir.join("exports")).is_ok());
        assert!(policy.check_folder(&dir.join("elsewhere")).is_err());
        assert!(policy.check_folder(&dir.join("exports/a.png")).is_err());
        assert!(policy.check_folder(&dir.join("missing")).is_err());
        // A parent of the root is not inside it.
        assert!(policy.check_folder(&dir).is_err());
        for d in [dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn expanding_a_folder_is_sorted_and_respects_the_glob_and_the_limit() {
        let dir = temp_dir("policy-expand");
        for rel in ["b.png", "a.png", "c.jpg", "sub/d.png", "sub/deep/e.png"] {
            write_file(&dir, rel, b"x");
        }
        let (store, pdir, _) = signed_store(&policy_json(&root_of(&dir), ""));
        let policy = store.load_enabled().unwrap();
        let names = |pattern: &str, limit: usize| -> Result<Vec<String>, PolicyError> {
            policy.expand_folder(&dir, pattern, limit).map(|l| {
                l.files
                    .iter()
                    .map(|f| {
                        f.strip_prefix(root_of(&dir))
                            .unwrap()
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect()
            })
        };
        assert_eq!(names("*.png", 10).unwrap(), ["a.png", "b.png"]);
        assert_eq!(names("*.PNG", 10).unwrap(), ["a.png", "b.png"]);
        assert_eq!(
            names("**/*.png", 10).unwrap(),
            ["a.png", "b.png", "sub/d.png", "sub/deep/e.png"]
        );
        assert!(names("**/*.png", 3)
            .unwrap_err()
            .to_string()
            .contains("more than 3"));
        assert!(names("*.gif", 10).unwrap().is_empty());
        for d in [dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[cfg(windows)]
    #[test]
    fn expanding_a_folder_leaves_out_symlinks_that_escape_it() {
        let dir = temp_dir("policy-expand-link");
        let outside_dir = temp_dir("policy-expand-link-out");
        let target = write_file(&outside_dir, "secret.png", b"x");
        write_file(&dir, "in/ok.png", b"x");
        if std::os::windows::fs::symlink_file(&target, dir.join("in/link.png")).is_err() {
            eprintln!("skipped: creating symlinks needs Developer Mode or elevation");
            return;
        }
        let (store, pdir, _) = signed_store(&policy_json(&root_of(&dir), ""));
        let policy = store.load_enabled().unwrap();
        let listing = policy.expand_folder(&dir.join("in"), "*.png", 10).unwrap();
        assert_eq!(listing.files.len(), 1);
        assert_eq!(listing.skipped.len(), 1);
        for d in [dir, outside_dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[cfg(unix)]
    #[test]
    fn expanding_a_folder_leaves_out_symlinks_that_escape_it() {
        let dir = temp_dir("policy-expand-link");
        let outside_dir = temp_dir("policy-expand-link-out");
        let target = write_file(&outside_dir, "secret.png", b"x");
        write_file(&dir, "in/ok.png", b"x");
        std::os::unix::fs::symlink(&target, dir.join("in/link.png")).unwrap();
        let (store, pdir, _) = signed_store(&policy_json(&root_of(&dir), ""));
        let policy = store.load_enabled().unwrap();
        let listing = policy.expand_folder(&dir.join("in"), "*.png", 10).unwrap();
        assert_eq!(listing.files.len(), 1);
        assert_eq!(listing.skipped.len(), 1);
        for d in [dir, outside_dir, pdir] {
            let _ = fs::remove_dir_all(d);
        }
    }
}
