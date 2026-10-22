use crate::audit::AuditEntry;
use crate::auth::AuthManager;
use crate::error::{Report, Result};
use crate::oauth;
use crate::open_cloud::OpenCloudClient;
use crate::secret_store::redact;
use crate::upload_flow::{ApprovedUpload, PlanRequest, UploadFlow};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{extract::State, Json};
use color_eyre::eyre::{eyre, Error, OptionExt};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    schemars, tool, tool_handler, tool_router, ErrorData, ServerHandler,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::oneshot::Receiver;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::Duration;
use uuid::Uuid;

pub const STUDIO_PLUGIN_PORT: u16 = 44755;
const LONG_POLL_DURATION: Duration = Duration::from_secs(15);
// Default per-tool timeout on the MCP->plugin round trip. Covers the common
// hang case (plugin disconnected, Studio frozen, tool yielding forever inside
// Roblox). run_script_in_play_mode passes its own longer timeout below.
const DEFAULT_TOOL_TIMEOUT: Duration = Duration::from_secs(45);
// Extra slack on top of the user-provided timeout for run_script_in_play_mode
// so the plugin has room to tear down the play session and send its reply.
const PLAY_MODE_TIMEOUT_SLACK: Duration = Duration::from_secs(15);

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ToolArguments {
    args: ToolArgumentValues,
    id: Option<Uuid>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct RunCommandResponse {
    success: bool,
    response: String,
    id: Uuid,
}

pub struct AppState {
    process_queue: VecDeque<ToolArguments>,
    output_map: HashMap<Uuid, mpsc::UnboundedSender<Result<String>>>,
    waiter: watch::Receiver<()>,
    trigger: watch::Sender<()>,
}
pub type PackedState = Arc<Mutex<AppState>>;

impl AppState {
    pub fn new() -> Self {
        let (trigger, waiter) = watch::channel(());
        Self {
            process_queue: VecDeque::new(),
            output_map: HashMap::new(),
            waiter,
            trigger,
        }
    }
}

impl ToolArguments {
    fn new(args: ToolArgumentValues) -> (Self, Uuid) {
        Self { args, id: None }.with_id()
    }
    fn with_id(self) -> (Self, Uuid) {
        let id = Uuid::new_v4();
        (
            Self {
                args: self.args,
                id: Some(id),
            },
            id,
        )
    }
}

/// RAII guard that removes an entry from `AppState::output_map` when dropped.
/// Ensures cleanup on timeout, cancellation, or normal completion.
struct OutputMapGuard {
    state: PackedState,
    id: Uuid,
}

impl OutputMapGuard {
    fn new(state: PackedState, id: Uuid) -> Self {
        Self { state, id }
    }
}

impl Drop for OutputMapGuard {
    fn drop(&mut self) {
        // Spawn a task because Drop isn't async. `try_lock` first to avoid
        // spawning when we can clean up inline.
        if let Ok(mut state) = self.state.try_lock() {
            state.output_map.remove(&self.id);
            return;
        }
        let state = self.state.clone();
        let id = self.id;
        tokio::spawn(async move {
            let mut state = state.lock().await;
            state.output_map.remove(&id);
        });
    }
}
/// Which tool set this process serves (`--mode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ServerMode {
    /// Studio plugin tools plus the Open Cloud tools (the original behaviour).
    #[default]
    Studio,
    /// Only the Open Cloud tools: no Studio plugin port and no plugin server.
    Cloud,
}

/// Tools that need no Studio plugin and stay available in `ServerMode::Cloud`.
/// Everything else is removed from the tool router in that mode.
pub const CLOUD_TOOLS: [&str; 8] = [
    "cloud_auth_status",
    "roblox_login",
    "roblox_logout",
    "plan_upload",
    "upload_asset",
    "audit_log_tail",
    "get_asset_info",
    "list_my_assets",
];

#[derive(Clone)]
pub struct RBXStudioServer {
    mode: ServerMode,
    state: PackedState,
    /// Credentials for the Open Cloud tools (API key by default, OAuth
    /// optional), resolved on every call. Without any credentials the tools
    /// return a setup hint instead of crashing.
    auth: Arc<AuthManager>,
    /// Policy, plans, rate limit and audit log for uploads.
    flow: Arc<UploadFlow>,
    tool_router: ToolRouter<Self>,
}

#[tool_handler]
impl ServerHandler for RBXStudioServer {
    fn get_info(&self) -> ServerInfo {
        if self.mode == ServerMode::Cloud {
            return ServerInfo {
                protocol_version: ProtocolVersion::LATEST,
                capabilities: ServerCapabilities::builder().enable_tools().build(),
                server_info: Implementation {
                    name: "Roblox_Cloud".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    title: Some("Roblox Cloud MCP Server (Custom Fork)".to_string()),
                    icons: None,
                    website_url: None,
                },
                instructions: Some(
                    "Open Cloud asset tools only; there is no Roblox Studio connection in this mode. \
Only upload when the user asked for it in this conversation, and ask where to upload \
(personal account or a group) unless they already said.
- cloud_auth_status: Show which credentials are configured (never prints a secret). Check this first.
- roblox_login: Optional OAuth sign-in. Opens a browser tab. Not needed with an API key.
- roblox_logout: Clear locally stored OAuth tokens.
- plan_upload: Step 1. Check a local file against the user's signed upload policy; uploads nothing. Pass the creator (ask the user where to upload).
- upload_asset: Step 2. Send a planned file to Roblox with planId, confirm and the exact confirmPhrase, only after the user agreed.
- audit_log_tail: Recent upload audit entries and whether the log verifies.
- get_asset_info: Read asset metadata by ID.
- list_my_assets: Page through a user's inventory."
                        .to_string(),
                ),
            };
        }
        ServerInfo {
            protocol_version: ProtocolVersion::LATEST,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "Roblox_Studio".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("Roblox Studio MCP Server (Custom Fork)".to_string()),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "You must be aware of current studio mode before using any tools; infer from context or use get_studio_mode.
PREFER dedicated read tools over run_code when possible:
- get_instance_tree: Get hierarchy/structure as JSON (faster than run_code + print)
- get_properties: Read instance properties directly
- get_asset_ids: Get rbxassetid from images, sounds, etc.
- read_datastore: Inspect DataStore values (dev storage)
Use run_code for custom logic or when no dedicated tool exists.
After run_script_in_play_mode, datamodel resets to stop. Prefer start_stop_play; use run_script_in_play_mode only for one-off server tests.
Batch operations: use batch_apply to set properties on multiple instances (by tag, className, or path).
Selection: use select_instances and open_script for Explorer/editor navigation.
Rojo tools (rojo_sourcemap, rojo_build) run on host; require Rojo installed.

Open Cloud tools (an API key stored with `rbx-studio-mcp set-key`, or optional OAuth). Only upload when the user asked for it in this conversation, and ask where to upload (personal account or a group) unless they already said:
- cloud_auth_status: Show which credentials and upload policy are configured (never prints a secret).
- roblox_login: Optional OAuth sign-in. Opens a browser tab.
- roblox_logout: Revoke locally stored OAuth tokens.
- plan_upload: Step 1. Check a local file against the signed upload policy; uploads nothing.
- upload_asset: Step 2. Send a planned file with planId, confirm and the exact confirmPhrase, only after the user agreed.
- audit_log_tail: Recent upload audit entries.
- get_asset_info: Read asset metadata by ID.
- list_my_assets: Page through a user's inventory.
These tools live in the Rust process and do not require Roblox Studio to be running."
                    .to_string(),
            ),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct RunCode {
    #[schemars(description = "Code to run")]
    command: String,
}
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct InsertModel {
    #[schemars(description = "Query to search for the model")]
    query: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct GetConsoleOutput {}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct ClearConsole {}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct GetStudioMode {}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct StartStopPlay {
    #[schemars(
        description = "Mode to start or stop, must be start_play, stop, or run_server. Don't use run_server unless you are sure no client/player is needed."
    )]
    mode: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct RunScriptInPlayMode {
    #[schemars(description = "Code to run")]
    code: String,
    #[schemars(description = "Timeout in seconds, defaults to 100 seconds")]
    timeout: Option<u32>,
    #[schemars(description = "Mode to run in, must be start_play or run_server")]
    mode: String,
}

// Custom fork: Read operations
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct GetInstanceTree {
    #[serde(rename = "rootPath")]
    #[schemars(
        description = "Root path (e.g. 'game', 'Workspace', 'Workspace.Model'). Default: game"
    )]
    root_path: Option<String>,
    #[serde(rename = "maxDepth")]
    #[schemars(
        description = "Max depth for tree traversal. Default: 3, max: 5. Use narrower rootPath (e.g. Workspace.MyModel) for deeper trees."
    )]
    max_depth: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct GetProperties {
    #[serde(rename = "instancePath")]
    #[schemars(description = "Instance path (e.g. 'Workspace.Part', 'game.Lighting')")]
    instance_path: String,
    #[serde(rename = "propertyNames")]
    #[schemars(
        description = "Optional list of property names to fetch. If omitted, returns common properties"
    )]
    property_names: Option<Vec<String>>,
}

// Custom fork: Batch operations
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct BatchApply {
    #[schemars(description = "How to select instances: tag, className, or path")]
    selector: String,
    #[serde(rename = "selectorValue")]
    #[schemars(description = "Value for selector (tag name, class name, or instance path)")]
    selector_value: String,
    #[schemars(description = "Property to set (e.g. Color, Position, Size)")]
    property: String,
    #[schemars(
        description = "Value to set. For Color use [r,g,b] 0-1. For Position/Size use [x,y,z]"
    )]
    value: serde_json::Value,
}

// Custom fork: Selection & navigation
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct SelectInstances {
    #[serde(rename = "instancePaths")]
    #[schemars(description = "Array of instance paths to select in Explorer")]
    instance_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct OpenScript {
    #[serde(rename = "instancePath")]
    #[schemars(description = "Path to script instance (e.g. 'StarterPlayerScripts.MainScript')")]
    instance_path: String,
}

// Custom fork: DataStore inspection
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct ReadDataStore {
    #[serde(rename = "datastoreName")]
    #[schemars(description = "DataStore name")]
    datastore_name: String,
    #[schemars(description = "Key to read")]
    key: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct MockDataStore {
    #[serde(rename = "datastoreName")]
    #[schemars(description = "DataStore name")]
    datastore_name: String,
    #[schemars(description = "Key to set")]
    key: String,
    #[schemars(description = "Value to store (JSON-serializable)")]
    value: serde_json::Value,
}

// Custom fork: Asset management
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct GetAssetIds {
    #[serde(rename = "rootPath")]
    #[schemars(description = "Root path to search. Default: game")]
    root_path: Option<String>,
    #[serde(rename = "assetTypes")]
    #[schemars(description = "Filter by instance types (e.g. ['ImageLabel', 'Sound', 'Decal'])")]
    asset_types: Option<Vec<String>>,
}

// OAuth + Open Cloud arg structs. These tools run entirely in the Rust
// process and do not need the Studio plugin.

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct RobloxLogin {}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct RobloxLogout {}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct CloudAuthStatus {}

/// Error result for the Open Cloud tools. Everything an agent can read passes
/// through the redactor, so a key or token that leaks into an error body from
/// a server or library can not reach the model.
fn cloud_error(message: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(redact(&message))])
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct PlanUpload {
    #[serde(rename = "filePath")]
    #[schemars(description = "Absolute path to the local file to upload. Max 20MB.")]
    file_path: String,
    #[serde(rename = "assetType")]
    #[schemars(
        description = "One of: Animation, Audio, Decal, Image, Mesh, Model, Video (case-insensitive). The file extension must match the type and the file content is checked: Model .fbx/.gltf/.glb/.rbxm/.rbxmx; Image and Decal .png/.jpg/.jpeg/.bmp/.tga; Audio .mp3/.ogg/.wav/.flac; Animation .rbxm/.rbxmx; Video .mp4/.mov; Mesh takes Roblox-format data only (upload .fbx/.glb as Model)"
    )]
    asset_type: String,
    #[serde(rename = "displayName")]
    #[schemars(description = "Display name shown on the Roblox catalog page")]
    display_name: String,
    #[schemars(description = "Optional description (up to 1000 characters)")]
    description: Option<String>,
    #[schemars(
        description = "Where to upload, as a creator alias from the user's policy (for example 'personal' or a group name). Give exactly one of creator, userId or groupId. If the user has not said where to upload, ask them first."
    )]
    creator: Option<String>,
    #[serde(rename = "userId")]
    #[schemars(description = "Upload under this numeric user ID (personal account)")]
    user_id: Option<String>,
    #[serde(rename = "groupId")]
    #[schemars(description = "Upload under this numeric group ID")]
    group_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct UploadAsset {
    #[serde(rename = "planId")]
    #[schemars(description = "The planId returned by plan_upload")]
    plan_id: String,
    #[schemars(
        description = "Must be true, and only after the user agreed to the exact upload in the plan summary"
    )]
    confirm: bool,
    #[serde(rename = "confirmPhrase")]
    #[schemars(description = "The confirmPhrase from the plan, copied exactly")]
    confirm_phrase: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct AuditLogTail {
    #[schemars(description = "How many of the newest entries to return (1-200, default 20)")]
    count: Option<u32>,
}

fn approved_entry(event: &str, approved: &ApprovedUpload) -> AuditEntry {
    AuditEntry {
        event: event.to_string(),
        plan_id: Some(approved.plan_id.clone()),
        path: Some(approved.path.display().to_string()),
        sha256: Some(approved.sha256.clone()),
        bytes: Some(approved.bytes.len() as u64),
        asset_type: Some(approved.kind.api_name().to_string()),
        creator: Some(approved.creator.describe()),
        ..Default::default()
    }
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct GetAssetInfo {
    #[serde(rename = "assetId")]
    #[schemars(description = "Asset ID to fetch metadata for")]
    asset_id: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct ListMyAssets {
    #[serde(rename = "userId")]
    #[schemars(
        description = "Optional: fetch a different user's inventory. Defaults to the logged-in user."
    )]
    user_id: Option<String>,
    #[serde(rename = "pageSize")]
    #[schemars(description = "Items per page (1-100). Defaults to Roblox's default.")]
    page_size: Option<u32>,
    #[serde(rename = "pageToken")]
    #[schemars(description = "Pagination cursor returned by a previous call")]
    page_token: Option<String>,
    #[schemars(
        description = "Inventory filter, e.g. 'assetIds=1,2,3' or 'inventoryItemAssetTypes=DECAL'"
    )]
    filter: Option<String>,
}

// Custom fork: Rojo/File sync (runs locally in Rust, not in plugin)
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct RojoSourcemap {
    #[serde(rename = "projectPath")]
    #[schemars(
        description = "Path to Rojo project (default.project.json) or directory. Default: current workspace"
    )]
    project_path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct RojoBuild {
    #[serde(rename = "projectPath")]
    #[schemars(description = "Path to Rojo project. Default: current workspace")]
    project_path: Option<String>,
    #[schemars(description = "Output file path for built place")]
    output: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
enum ToolArgumentValues {
    RunCode(RunCode),
    InsertModel(InsertModel),
    GetConsoleOutput(GetConsoleOutput),
    ClearConsole(ClearConsole),
    StartStopPlay(StartStopPlay),
    RunScriptInPlayMode(RunScriptInPlayMode),
    GetStudioMode(GetStudioMode),
    // Custom fork
    GetInstanceTree(GetInstanceTree),
    GetProperties(GetProperties),
    BatchApply(BatchApply),
    SelectInstances(SelectInstances),
    OpenScript(OpenScript),
    ReadDataStore(ReadDataStore),
    MockDataStore(MockDataStore),
    GetAssetIds(GetAssetIds),
    RojoSourcemap(RojoSourcemap),
    RojoBuild(RojoBuild),
}
#[tool_router]
impl RBXStudioServer {
    pub fn new(
        state: PackedState,
        auth: Arc<AuthManager>,
        flow: Arc<UploadFlow>,
        mode: ServerMode,
    ) -> Self {
        let mut tool_router = Self::tool_router();
        if mode == ServerMode::Cloud {
            // Removing the routes (not just hiding them in the list) also makes
            // call_tool refuse the Studio tools in cloud mode.
            for tool in tool_router.list_all() {
                if !CLOUD_TOOLS.contains(&tool.name.as_ref()) {
                    tool_router.remove_route(&tool.name);
                }
            }
        }
        Self {
            mode,
            state,
            auth,
            flow,
            tool_router,
        }
    }

    /// Helper: build the Open Cloud client. Credentials are resolved per
    /// request, so a missing key surfaces as the tool's error text (with the
    /// setup hint) rather than here.
    fn open_cloud(&self) -> OpenCloudClient {
        OpenCloudClient::new(self.auth.clone())
    }

    #[tool(
        description = "Runs a command in Roblox Studio and returns the printed output. Can be used to both make changes and retrieve information"
    )]
    async fn run_code(
        &self,
        Parameters(args): Parameters<RunCode>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::RunCode(args))
            .await
    }

    #[tool(
        description = "Inserts a model from the Roblox marketplace into the workspace. Returns the inserted model name."
    )]
    async fn insert_model(
        &self,
        Parameters(args): Parameters<InsertModel>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::InsertModel(args))
            .await
    }

    #[tool(description = "Get the console output from Roblox Studio.")]
    async fn get_console_output(
        &self,
        Parameters(args): Parameters<GetConsoleOutput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::GetConsoleOutput(args))
            .await
    }

    #[tool(
        description = "Clear the captured console output buffer. Use before running code to get fresh output."
    )]
    async fn clear_console(
        &self,
        Parameters(args): Parameters<ClearConsole>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::ClearConsole(args))
            .await
    }

    #[tool(
        description = "Start or stop play mode or run the server, Don't enter run_server mode unless you are sure no client/player is needed."
    )]
    async fn start_stop_play(
        &self,
        Parameters(args): Parameters<StartStopPlay>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::StartStopPlay(args))
            .await
    }

    #[tool(
        description = "Run a script in play mode and automatically stop play after script finishes or timeout. Returns the output of the script.
        Result format: { success: boolean, value: string, error: string, logs: { level: string, message: string, ts: number }[], errors: { level: string, message: string, ts: number }[], duration: number, isTimeout: boolean }.
        - Prefer using start_stop_play tool instead run_script_in_play_mode, Only used run_script_in_play_mode to run one time unit test code on server datamodel.
        - After calling run_script_in_play_mode, the datamodel status will be reset to stop mode.
        - If It returns `StudioTestService: Previous call to start play session has not been completed`, call start_stop_play tool to stop play mode first then try it again."
    )]
    async fn run_script_in_play_mode(
        &self,
        Parameters(args): Parameters<RunScriptInPlayMode>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::RunScriptInPlayMode(args))
            .await
    }

    #[tool(
        description = "Get the current studio mode. Returns the studio mode. The result will be one of start_play, run_server, or stop."
    )]
    async fn get_studio_mode(
        &self,
        Parameters(args): Parameters<GetStudioMode>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::GetStudioMode(args))
            .await
    }

    // Custom fork: Read operations (faster than run_code + print parsing)
    #[tool(
        description = "Get the instance tree/hierarchy as structured JSON. Returns Name, ClassName, FullName, Children, and common properties. Use instead of run_code for reading structure."
    )]
    async fn get_instance_tree(
        &self,
        Parameters(args): Parameters<GetInstanceTree>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::GetInstanceTree(args))
            .await
    }

    #[tool(
        description = "Get properties of an instance directly. Returns Name, ClassName, Attributes, Tags, and requested/serializable properties. Faster than run_code for property inspection."
    )]
    async fn get_properties(
        &self,
        Parameters(args): Parameters<GetProperties>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::GetProperties(args))
            .await
    }

    // Custom fork: Batch operations
    #[tool(
        description = "Apply a property change to multiple instances. Select by tag (CollectionService), className, or path. E.g. set all Parts with tag 'Enemy' to Color [1,0,0]."
    )]
    async fn batch_apply(
        &self,
        Parameters(args): Parameters<BatchApply>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::BatchApply(args))
            .await
    }

    // Custom fork: Selection & navigation
    #[tool(
        description = "Select instances in the Explorer. Pass array of instance paths (e.g. ['Workspace.Model', 'Lighting'])"
    )]
    async fn select_instances(
        &self,
        Parameters(args): Parameters<SelectInstances>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::SelectInstances(args))
            .await
    }

    #[tool(
        description = "Open a script in the Script Editor. Pass path to Script, ModuleScript, or LocalScript instance."
    )]
    async fn open_script(
        &self,
        Parameters(args): Parameters<OpenScript>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::OpenScript(args))
            .await
    }

    // Custom fork: DataStore inspection
    #[tool(
        description = "Read a value from a DataStore. Works in Edit mode (reads last-saved dev data) or Play mode. Use for development inspection."
    )]
    async fn read_datastore(
        &self,
        Parameters(args): Parameters<ReadDataStore>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::ReadDataStore(args))
            .await
    }

    #[tool(
        description = "Set a value in a DataStore for testing. Uses Studio development storage. Use to mock test data scenarios."
    )]
    async fn mock_datastore(
        &self,
        Parameters(args): Parameters<MockDataStore>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::MockDataStore(args))
            .await
    }

    // Custom fork: Asset management
    #[tool(
        description = "Get asset IDs (rbxassetid) from instances in the game. Optionally filter by type (ImageLabel, Sound, Decal, etc.). Returns path, property, and asset ID."
    )]
    async fn get_asset_ids(
        &self,
        Parameters(args): Parameters<GetAssetIds>,
    ) -> Result<CallToolResult, ErrorData> {
        self.generic_tool_run(ToolArgumentValues::GetAssetIds(args))
            .await
    }

    // Custom fork: Rojo/File sync (runs locally, not in plugin)
    #[tool(
        description = "Run rojo sourcemap to get file-to-instance mapping. Requires Rojo installed. Pass project_path or use workspace root. Runs on host machine."
    )]
    async fn rojo_sourcemap(
        &self,
        Parameters(args): Parameters<RojoSourcemap>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_rojo_sourcemap(args).await
    }

    #[tool(
        description = "Run rojo build to validate/sync project. Requires Rojo installed. Optionally specify output path. Runs on host machine."
    )]
    async fn rojo_build(
        &self,
        Parameters(args): Parameters<RojoBuild>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_rojo_build(args).await
    }

    // -------- OAuth + Open Cloud tools (run in Rust, no plugin needed) --------

    #[tool(
        description = "Start the Roblox OAuth login flow. Opens your browser to authorize this MCP, then stores access/refresh tokens locally so subsequent upload/asset tools work without re-prompting. Re-run to switch accounts or after revoking."
    )]
    async fn roblox_login(
        &self,
        Parameters(_args): Parameters<RobloxLogin>,
    ) -> Result<CallToolResult, ErrorData> {
        let cfg = match self.auth.oauth_config() {
            Ok(c) => c,
            Err(e) => {
                return Ok(cloud_error(format!(
                    "OAuth is not configured ({e}). OAuth is optional; an API key set with \
                     `rbx-studio-mcp set-key` works without logging in."
                )));
            }
        };
        match oauth::login(self.auth.cache(), &cfg).await {
            Ok(tokens) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Logged in as user {}. Granted scope: {}",
                tokens.user_id.as_deref().unwrap_or("(unknown)"),
                tokens.scope.as_deref().unwrap_or("(none)")
            ))])),
            Err(e) => Ok(cloud_error(format!("Login failed: {e}"))),
        }
    }

    #[tool(
        description = "Clear locally stored OAuth tokens. After this, the next upload/asset tool call requires roblox_login. Does not revoke tokens on Roblox's side; do that from the Creator Dashboard if you need to."
    )]
    async fn roblox_logout(
        &self,
        Parameters(_args): Parameters<RobloxLogout>,
    ) -> Result<CallToolResult, ErrorData> {
        match self.auth.cache().clear().await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(
                "Cleared local OAuth tokens.".to_string(),
            )])),
            Err(e) => Ok(cloud_error(format!("Logout failed: {e}"))),
        }
    }

    #[tool(
        description = "Step 1 of uploading a local file to Roblox: check it against the user's signed upload policy and return a plan. Uploads nothing. Only use when the user asked for an upload in this conversation. Pass creator (a policy alias such as 'personal'), or userId, or groupId; if the user has not said where to upload (their personal account or a group), ask them first. assetType is one of Animation, Audio, Decal, Image, Mesh, Model, Video; the file extension and content must match it. Show the returned summary to the user, and only after they agree call upload_asset with planId, confirm: true and confirmPhrase exactly as returned."
    )]
    async fn plan_upload(
        &self,
        Parameters(args): Parameters<PlanUpload>,
    ) -> Result<CallToolResult, ErrorData> {
        let flow = self.flow.clone();
        let request = PlanRequest {
            file_path: args.file_path,
            asset_type: args.asset_type,
            display_name: args.display_name,
            description: args.description,
            creator: args.creator,
            user_id: args.user_id,
            group_id: args.group_id,
        };
        // Reading and hashing a file (up to 20 MB) is blocking work.
        match tokio::task::spawn_blocking(move || flow.plan(request)).await {
            Ok(Ok(summary)) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&summary).unwrap_or_default(),
            )])),
            Ok(Err(e)) => Ok(cloud_error(e.to_string())),
            Err(e) => Ok(cloud_error(format!("plan_upload failed: {e}"))),
        }
    }

    #[tool(
        description = "Step 2 of uploading: send the file named by a plan from plan_upload to Roblox. Needs planId, confirm: true and the exact confirmPhrase from the plan, and only after the user agreed to that exact upload. Plans are single use and expire after 10 minutes. Returns the asset ID and moderation state; use insert_asset in Studio to bring it into a place."
    )]
    async fn upload_asset(
        &self,
        Parameters(args): Parameters<UploadAsset>,
    ) -> Result<CallToolResult, ErrorData> {
        let flow = self.flow.clone();
        let (plan_id, confirm, phrase) = (args.plan_id, args.confirm, args.confirm_phrase);
        let approved =
            match tokio::task::spawn_blocking(move || flow.approve(&plan_id, confirm, &phrase))
                .await
            {
                Ok(Ok(approved)) => approved,
                Ok(Err(e)) => return Ok(cloud_error(format!("Upload refused: {e}"))),
                Err(e) => return Ok(cloud_error(format!("Upload failed: {e}"))),
            };

        let client = self.open_cloud();
        let operation = match client.start_upload(&approved).await {
            Ok(path) => path,
            Err(e) => {
                let mut entry = approved_entry("upload_failed", &approved);
                entry.detail = Some(e.to_string());
                let _ = self.flow.record(entry);
                return Ok(cloud_error(format!("Upload failed: {e}")));
            }
        };

        // The asset may exist from here on, so record the operation before polling.
        let mut started = approved_entry("upload_started", &approved);
        started.operation = Some(operation.clone());
        let audit_warning = self.flow.record(started).err();

        let outcome = client.finish_operation(&operation, 60).await;
        let mut finished = approved_entry("upload_finished", &approved);
        finished.operation = Some(operation.clone());
        let result = match outcome {
            Ok(response) => {
                let asset_id = response["assetId"].as_str().map(str::to_string);
                let moderation = response["moderationResult"]["moderationState"]
                    .as_str()
                    .map(str::to_string);
                finished.asset_id = asset_id.clone();
                finished.status = moderation.clone().or_else(|| Some("done".to_string()));
                let body = serde_json::json!({
                    "assetId": asset_id,
                    "moderationState": moderation,
                    "operation": operation,
                    "creator": approved.creator.describe(),
                    "assetType": approved.kind.api_name(),
                    "next": "Use insert_asset (official Studio MCP) with this assetId to bring it into a place.",
                    "auditWarning": audit_warning.as_ref().map(|e| e.to_string()),
                    "response": response,
                });
                CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&body).unwrap_or_default(),
                )])
            }
            Err(e) => {
                finished.event = "upload_failed".to_string();
                finished.detail = Some(e.to_string());
                cloud_error(format!(
                    "Upload started (operation {operation}) but did not complete: {e}"
                ))
            }
        };
        if let Err(e) = self.flow.record(finished) {
            tracing::error!("could not record the upload result in the audit log: {e}");
        }
        Ok(result)
    }

    #[tool(
        description = "Show the newest entries of the upload audit log (plans, approvals, denials, uploads) and whether the hash chain still verifies. Never contains secrets."
    )]
    async fn audit_log_tail(
        &self,
        Parameters(args): Parameters<AuditLogTail>,
    ) -> Result<CallToolResult, ErrorData> {
        let count = args.count.unwrap_or(20).clamp(1, 200) as usize;
        match self.flow.audit().tail(count) {
            Ok((records, chain)) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(
                    &serde_json::json!({ "chain": chain, "records": records }),
                )
                .unwrap_or_default(),
            )])),
            Err(e) => Ok(cloud_error(format!("audit_log_tail failed: {e}"))),
        }
    }

    #[tool(description = "Get metadata for a Roblox asset by ID via the Open Cloud Assets API.")]
    async fn get_asset_info(
        &self,
        Parameters(args): Parameters<GetAssetInfo>,
    ) -> Result<CallToolResult, ErrorData> {
        let client = self.open_cloud();
        match client.get_asset_info(&args.asset_id).await {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()),
            )])),
            Err(e) => Ok(cloud_error(format!("get_asset_info failed: {e}"))),
        }
    }

    #[tool(
        description = "List inventory items belonging to a user (defaults to the logged-in user). Supports pagination and Roblox's filter syntax."
    )]
    async fn list_my_assets(
        &self,
        Parameters(args): Parameters<ListMyAssets>,
    ) -> Result<CallToolResult, ErrorData> {
        let client = self.open_cloud();
        match client
            .list_inventory(
                args.user_id.as_deref(),
                args.page_size,
                args.page_token.as_deref(),
                args.filter.as_deref(),
            )
            .await
        {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()),
            )])),
            Err(e) => Ok(cloud_error(format!("list_my_assets failed: {e}"))),
        }
    }

    #[tool(
        description = "Show which Roblox credentials are configured (API key, OAuth), what Roblox reports about the API key (permissions, expiry, warnings) and where secrets are stored. Never prints a secret. Call this before uploading, and tell the user to run `rbx-studio-mcp set-key` in a terminal if nothing is configured."
    )]
    async fn cloud_auth_status(
        &self,
        Parameters(_args): Parameters<CloudAuthStatus>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut status = self.auth.status().await;
        status["uploadPolicy"] = self.flow.policy_status();
        Ok(CallToolResult::success(vec![Content::text(redact(
            &serde_json::to_string_pretty(&status).unwrap_or_else(|_| status.to_string()),
        ))]))
    }

    async fn generic_tool_run(
        &self,
        args: ToolArgumentValues,
    ) -> Result<CallToolResult, ErrorData> {
        // Choose a per-call timeout. run_script_in_play_mode gets the user's
        // requested timeout plus slack; everything else gets the default.
        let tool_timeout = match &args {
            ToolArgumentValues::RunScriptInPlayMode(inner) => {
                let base = inner.timeout.unwrap_or(100) as u64;
                Duration::from_secs(base).saturating_add(PLAY_MODE_TIMEOUT_SLACK)
            }
            _ => DEFAULT_TOOL_TIMEOUT,
        };

        let (command, id) = ToolArguments::new(args);
        tracing::debug!("Running command: {:?}", command);
        let (tx, mut rx) = mpsc::unbounded_channel::<Result<String>>();
        let trigger = {
            let mut state = self.state.lock().await;
            state.process_queue.push_back(command);
            state.output_map.insert(id, tx);
            state.trigger.clone()
        };
        trigger
            .send(())
            .map_err(|e| ErrorData::internal_error(format!("Unable to trigger send {e}"), None))?;

        // Guard cleans up output_map on every exit path (timeout, future drop,
        // or normal completion). Without this, a cancelled call or timed-out
        // response leaks a sender and a stale UUID that can later trigger
        // "Unknown ID" errors on the response endpoint.
        let guard = OutputMapGuard::new(self.state.clone(), id);
        let recv_result = tokio::time::timeout(tool_timeout, rx.recv()).await;
        drop(guard);

        match recv_result {
            Err(_) => {
                // Also evict the command from the queue if the plugin never
                // picked it up (disconnected before /request). This avoids
                // stale commands running on next reconnect.
                {
                    let mut state = self.state.lock().await;
                    state.process_queue.retain(|cmd| cmd.id != Some(id));
                }
                tracing::warn!(
                    "Tool call {id} timed out after {:?}; plugin may be disconnected or stuck",
                    tool_timeout
                );
                Ok(CallToolResult::error(vec![Content::text(format!(
                    "Tool call timed out after {}s. The Roblox Studio plugin did not respond. \
                     Check that the MCP plugin is enabled in Studio and that Studio is not frozen. \
                     If a tool is expected to run longer (e.g. run_script_in_play_mode), pass an explicit timeout.",
                    tool_timeout.as_secs()
                ))]))
            }
            Ok(None) => Ok(CallToolResult::error(vec![Content::text(
                "Plugin response channel closed unexpectedly".to_string(),
            )])),
            Ok(Some(result)) => {
                tracing::debug!("Sending to MCP: {result:?}");
                match result {
                    Ok(result) => Ok(CallToolResult::success(vec![Content::text(result)])),
                    Err(err) => Ok(CallToolResult::error(vec![Content::text(err.to_string())])),
                }
            }
        }
    }

    async fn run_rojo_sourcemap(&self, args: RojoSourcemap) -> Result<CallToolResult, ErrorData> {
        let project_path = args
            .project_path
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));

        let output = Command::new("rojo")
            .args(["sourcemap", project_path.to_str().unwrap_or(".")])
            .output()
            .await
            .map_err(|e| ErrorData::internal_error(format!("Failed to run rojo: {e}"), None))?;

        let result = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            format!("rojo sourcemap failed: {stderr}")
        };

        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    async fn run_rojo_build(&self, args: RojoBuild) -> Result<CallToolResult, ErrorData> {
        let project_path = args
            .project_path
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));

        let mut cmd = Command::new("rojo");
        cmd.arg("build").arg(project_path.to_str().unwrap_or("."));
        if let Some(ref output_path) = args.output {
            cmd.args(["--output", output_path]);
        }

        let output = cmd
            .output()
            .await
            .map_err(|e| ErrorData::internal_error(format!("Failed to run rojo: {e}"), None))?;

        let result = if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() {
                "rojo build completed successfully.".to_string()
            } else {
                stdout.to_string()
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            format!("rojo build failed: {stderr}")
        };

        Ok(CallToolResult::success(vec![Content::text(result)]))
    }
}

pub async fn request_handler(State(state): State<PackedState>) -> Result<impl IntoResponse> {
    let timeout = tokio::time::timeout(LONG_POLL_DURATION, async {
        let mut waiter = { state.lock().await.waiter.clone() };
        loop {
            {
                let mut state = state.lock().await;
                if let Some(task) = state.process_queue.pop_front() {
                    return Ok::<ToolArguments, Error>(task);
                }
            }
            waiter.changed().await?
        }
    })
    .await;
    match timeout {
        Ok(result) => Ok(Json(result?).into_response()),
        _ => Ok((StatusCode::LOCKED, String::new()).into_response()),
    }
}

pub async fn response_handler(
    State(state): State<PackedState>,
    Json(payload): Json<RunCommandResponse>,
) -> Result<impl IntoResponse> {
    tracing::debug!("Received reply from studio {payload:?}");
    let mut state = state.lock().await;
    let tx = state
        .output_map
        .remove(&payload.id)
        .ok_or_eyre("Unknown ID")?;
    let result: Result<String, Report> = if payload.success {
        Ok(payload.response)
    } else {
        Err(Report::from(eyre!(payload.response)))
    };
    Ok(tx.send(result)?)
}

pub async fn proxy_handler(
    State(state): State<PackedState>,
    Json(command): Json<ToolArguments>,
) -> Result<impl IntoResponse> {
    let id = command.id.ok_or_eyre("Got proxy command with no id")?;
    tracing::debug!("Received request to proxy {command:?}");
    let (tx, mut rx) = mpsc::unbounded_channel();
    {
        let mut state = state.lock().await;
        state.process_queue.push_back(command);
        state.output_map.insert(id, tx);
    }
    let guard = OutputMapGuard::new(state.clone(), id);
    let recv_result = tokio::time::timeout(DEFAULT_TOOL_TIMEOUT, rx.recv()).await;
    drop(guard);

    let (success, response) = match recv_result {
        Err(_) => {
            {
                let mut state = state.lock().await;
                state.process_queue.retain(|cmd| cmd.id != Some(id));
            }
            (
                false,
                format!(
                    "Proxy timed out after {}s waiting for plugin response",
                    DEFAULT_TOOL_TIMEOUT.as_secs()
                ),
            )
        }
        Ok(None) => (false, "Proxy response channel closed".to_string()),
        Ok(Some(Ok(s))) => (true, s),
        Ok(Some(Err(e))) => (false, e.to_string()),
    };
    tracing::debug!("Sending back to dud: success={success}, response={response:?}");
    Ok(Json(RunCommandResponse {
        success,
        response,
        id,
    }))
}

pub async fn dud_proxy_loop(state: PackedState, exit: Receiver<()>) {
    let client = reqwest::Client::new();

    let mut waiter = { state.lock().await.waiter.clone() };
    while exit.is_empty() {
        let entry = { state.lock().await.process_queue.pop_front() };
        if let Some(entry) = entry {
            // Guard against missing ids (shouldn't happen, but we don't want
            // to panic the whole loop if it does).
            let entry_id = match entry.id {
                Some(id) => id,
                None => {
                    tracing::error!("dud_proxy_loop: dropping queue entry with no id");
                    continue;
                }
            };

            let tx = {
                let mut s = state.lock().await;
                s.output_map.remove(&entry_id)
            };
            let Some(tx) = tx else {
                tracing::warn!(
                    "dud_proxy_loop: no output sender for id {entry_id}; skipping entry"
                );
                continue;
            };

            let res = client
                .post(format!("http://127.0.0.1:{STUDIO_PLUGIN_PORT}/proxy"))
                .json(&entry)
                .send()
                .await;

            let payload: Result<String> = match res {
                Ok(res) => res
                    .json::<RunCommandResponse>()
                    .await
                    .map(|r| r.response)
                    .map_err(Into::into),
                Err(e) => {
                    tracing::error!("Failed to proxy: {e}");
                    Err(e.into())
                }
            };

            // Receiver may already be dropped (timeout on the MCP side);
            // just log and move on.
            if let Err(send_err) = tx.send(payload) {
                tracing::debug!(
                    "dud_proxy_loop: receiver dropped before response delivered: {send_err:?}"
                );
            }
        } else if waiter.changed().await.is_err() {
            // Sender dropped; we're shutting down.
            tracing::debug!("dud_proxy_loop: waiter closed, exiting");
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Tools that need the Studio plugin. Studio mode must keep serving exactly
    /// these plus `CLOUD_TOOLS`; a new tool has to be added here on purpose.
    const STUDIO_ONLY_TOOLS: [&str; 17] = [
        "batch_apply",
        "clear_console",
        "get_asset_ids",
        "get_console_output",
        "get_instance_tree",
        "get_properties",
        "get_studio_mode",
        "insert_model",
        "mock_datastore",
        "open_script",
        "read_datastore",
        "rojo_build",
        "rojo_sourcemap",
        "run_code",
        "run_script_in_play_mode",
        "select_instances",
        "start_stop_play",
    ];

    fn server(mode: ServerMode) -> RBXStudioServer {
        use crate::audit::AuditLog;
        use crate::policy::PolicyStore;
        use crate::secret_store::{MemoryStore, SecretStore};
        use crate::token_store::TokenCache;
        let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        let cache = Arc::new(TokenCache::new(store.clone()));
        // An empty temp folder: no policy exists, so uploads are off.
        let dir = std::env::temp_dir().join(format!("rbx-srv-{}", uuid::Uuid::new_v4()));
        let flow = Arc::new(UploadFlow::new(
            PolicyStore::new(dir.clone(), store.clone()),
            Arc::new(AuditLog::new(dir.join("uploads.jsonl"), store.clone())),
        ));
        RBXStudioServer::new(
            Arc::new(Mutex::new(AppState::new())),
            Arc::new(AuthManager::new(store, cache)),
            flow,
            mode,
        )
    }

    fn result_text(result: &CallToolResult) -> String {
        serde_json::to_string(result).unwrap()
    }

    #[test]
    fn cloud_error_redacts_secret_shaped_values() {
        let leaked = "Zk3fQ9xLmN2pRt7vWb4YcD8eHjK5sUaP1gXoIq6TyChEzF0lBnMrVd9wSuOe3A";
        let result = cloud_error(format!(
            "Upload failed: bad key {leaked}; x-api-key: abcdef123456"
        ));
        let text = result_text(&result);
        assert!(!text.contains(leaked), "{text}");
        assert!(!text.contains("abcdef123456"), "{text}");
    }

    #[tokio::test]
    async fn tools_explain_how_to_set_up_credentials_when_none_exist() {
        let s = server(ServerMode::Cloud);
        let result = s
            .get_asset_info(Parameters(GetAssetInfo {
                asset_id: "1".to_string(),
            }))
            .await
            .unwrap();
        let text = result_text(&result);
        assert!(text.contains("set-key"), "{text}");
    }

    #[tokio::test]
    async fn auth_status_tool_reports_none_without_leaking() {
        let s = server(ServerMode::Cloud);
        let result = s
            .cloud_auth_status(Parameters(CloudAuthStatus {}))
            .await
            .unwrap();
        let text = result_text(&result);
        assert!(text.contains("activeMethod"), "{text}");
        assert!(text.contains("none"), "{text}");
    }

    #[test]
    fn cloud_tools_are_the_documented_eight_and_studio_adds_seventeen() {
        assert_eq!(CLOUD_TOOLS.len(), 8);
        assert_eq!(tool_names(&server(ServerMode::Studio)).len(), 25);
        assert_eq!(tool_names(&server(ServerMode::Cloud)).len(), 8);
    }

    #[test]
    fn no_tool_uploads_from_a_path_or_updates_an_asset_without_the_flow() {
        let s = server(ServerMode::Cloud);
        assert!(!tool_names(&s).contains("update_asset"));
        let upload = s
            .tool_router
            .list_all()
            .into_iter()
            .find(|t| t.name == "upload_asset")
            .unwrap();
        let schema = serde_json::to_string(&upload).unwrap();
        for field in ["planId", "confirm", "confirmPhrase"] {
            assert!(schema.contains(field), "{field} missing: {schema}");
        }
        for forbidden in ["filePath", "userId", "groupId", "assetType"] {
            assert!(!schema.contains(forbidden), "{forbidden} present: {schema}");
        }
    }

    #[tokio::test]
    async fn upload_asset_without_a_plan_is_refused_before_any_network_call() {
        let s = server(ServerMode::Cloud);
        let result = s
            .upload_asset(Parameters(UploadAsset {
                plan_id: "made-up".to_string(),
                confirm: true,
                confirm_phrase: "UPLOAD anything".to_string(),
            }))
            .await
            .unwrap();
        let text = result_text(&result);
        assert!(text.contains("unknown or already used"), "{text}");
    }

    #[tokio::test]
    async fn plan_upload_without_a_policy_explains_how_to_create_one() {
        let s = server(ServerMode::Cloud);
        let result = s
            .plan_upload(Parameters(PlanUpload {
                file_path: "C:/anything.glb".to_string(),
                asset_type: "Model".to_string(),
                display_name: "x".to_string(),
                description: None,
                creator: Some("personal".to_string()),
                user_id: None,
                group_id: None,
            }))
            .await
            .unwrap();
        let text = result_text(&result);
        assert!(text.contains("policy init"), "{text}");
    }

    #[tokio::test]
    async fn the_audit_tail_works_on_an_empty_log() {
        let s = server(ServerMode::Cloud);
        let result = s
            .audit_log_tail(Parameters(AuditLogTail { count: None }))
            .await
            .unwrap();
        let text = result_text(&result);
        assert!(text.contains("records"), "{text}");
    }

    fn tool_names(server: &RBXStudioServer) -> BTreeSet<String> {
        server
            .tool_router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_mode_is_studio() {
        assert_eq!(ServerMode::default(), ServerMode::Studio);
    }

    #[test]
    fn studio_mode_lists_every_tool() {
        let mut expected = names(&STUDIO_ONLY_TOOLS);
        expected.extend(names(&CLOUD_TOOLS));
        assert_eq!(tool_names(&server(ServerMode::Studio)), expected);
    }

    #[test]
    fn cloud_mode_lists_only_the_cloud_tools() {
        assert_eq!(tool_names(&server(ServerMode::Cloud)), names(&CLOUD_TOOLS));
    }

    #[test]
    fn cloud_mode_removes_the_studio_routes() {
        let cloud = server(ServerMode::Cloud);
        for tool in STUDIO_ONLY_TOOLS {
            assert!(!cloud.tool_router.has_route(tool), "{tool} still routable");
        }
        for tool in CLOUD_TOOLS {
            assert!(cloud.tool_router.has_route(tool), "{tool} missing");
        }
    }

    #[test]
    fn upload_tool_text_lists_the_real_asset_types_only() {
        use crate::asset_types::AssetKind;
        for mode in [ServerMode::Studio, ServerMode::Cloud] {
            let s = server(mode);
            for name in ["plan_upload"] {
                let tool = s
                    .tool_router
                    .list_all()
                    .into_iter()
                    .find(|t| t.name == name)
                    .unwrap_or_else(|| panic!("{name} missing"));
                let text = serde_json::to_string(&tool).unwrap();
                assert!(!text.contains("ModelFromFbx"), "{name}: {text}");
                assert!(!text.contains("MeshPart"), "{name}: {text}");
                if name == "plan_upload" {
                    for kind in AssetKind::ALL {
                        assert!(text.contains(kind.api_name()), "{name} lacks {kind}");
                    }
                }
            }
            let info = serde_json::to_string(&s.get_info()).unwrap();
            assert!(!info.contains("ModelFromFbx"), "{info}");
        }
    }

    #[test]
    fn cloud_mode_identifies_itself_as_cloud() {
        let info = server(ServerMode::Cloud).get_info();
        assert_eq!(info.server_info.name, "Roblox_Cloud");
        let studio = server(ServerMode::Studio).get_info();
        assert_eq!(studio.server_info.name, "Roblox_Studio");
    }
}
