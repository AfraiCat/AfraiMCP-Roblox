use crate::error::{Report, Result};
use crate::oauth::{self, OAuthConfig};
use crate::open_cloud::{OpenCloudClient, UploadArgs};
use crate::token_store::TokenCache;
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
#[derive(Clone)]
pub struct RBXStudioServer {
    state: PackedState,
    /// Shared token cache for OAuth-backed tools. Always present; if OAuth
    /// env vars aren't set the tools that need them return a helpful error
    /// instead of crashing.
    token_cache: Arc<TokenCache>,
    /// Present only when ROBLOX_OAUTH_CLIENT_ID and _SECRET were found at
    /// startup. `None` means "OAuth tools should refuse with a setup hint".
    oauth_config: Option<OAuthConfig>,
    tool_router: ToolRouter<Self>,
}

#[tool_handler]
impl ServerHandler for RBXStudioServer {
    fn get_info(&self) -> ServerInfo {
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

OAuth-backed Open Cloud tools (require ROBLOX_OAUTH_CLIENT_ID / ROBLOX_OAUTH_CLIENT_SECRET env vars and a one-time roblox_login):
- roblox_login: First-time / re-auth. Opens a browser tab.
- roblox_logout: Revoke locally stored tokens.
- upload_asset: Upload a local file (Decal/Audio/Model/etc.) to the user's account.
- update_asset: Replace contents of an existing asset by ID.
- get_asset_info: Read asset metadata by ID.
- list_my_assets: Page through the logged-in user's inventory.
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
struct UploadAsset {
    #[serde(rename = "filePath")]
    #[schemars(description = "Absolute path to the local file to upload. Max 20MB.")]
    file_path: String,
    #[serde(rename = "assetType")]
    #[schemars(
        description = "One of: Decal, Audio, Model, ModelFromFbx, MeshPart, Animation, Video"
    )]
    asset_type: String,
    #[serde(rename = "displayName")]
    #[schemars(description = "Display name shown on the Roblox catalog page")]
    display_name: String,
    #[schemars(description = "Optional description")]
    description: Option<String>,
    /// Override the creator. Defaults to the logged-in user.
    #[serde(rename = "userId")]
    #[schemars(
        description = "Optional override: upload under this user ID (defaults to current user)"
    )]
    user_id: Option<String>,
    #[serde(rename = "groupId")]
    #[schemars(
        description = "Optional override: upload under this group ID. Mutually exclusive with userId."
    )]
    group_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct UpdateAsset {
    #[serde(rename = "assetId")]
    #[schemars(description = "ID of the existing asset to update")]
    asset_id: String,
    #[serde(rename = "filePath")]
    #[schemars(description = "Absolute path to the new local file. Max 20MB.")]
    file_path: String,
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
        token_cache: Arc<TokenCache>,
        oauth_config: Option<OAuthConfig>,
    ) -> Self {
        Self {
            state,
            token_cache,
            oauth_config,
            tool_router: Self::tool_router(),
        }
    }

    /// Helper: build the Open Cloud client or surface a clear error if OAuth
    /// env vars are missing. Shared by every OAuth-backed tool below.
    fn open_cloud(&self) -> std::result::Result<OpenCloudClient, ErrorData> {
        let cfg = self.oauth_config.clone().ok_or_else(|| {
            ErrorData::invalid_params(
                "OAuth is not configured. Set ROBLOX_OAUTH_CLIENT_ID and \
                 ROBLOX_OAUTH_CLIENT_SECRET environment variables on the MCP server \
                 process, restart it, then run roblox_login.",
                None,
            )
        })?;
        Ok(OpenCloudClient::new(self.token_cache.clone(), cfg))
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
        let cfg = match self.oauth_config.clone() {
            Some(c) => c,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "OAuth is not configured. Set ROBLOX_OAUTH_CLIENT_ID and \
                     ROBLOX_OAUTH_CLIENT_SECRET environment variables on the MCP server \
                     process and restart it."
                        .to_string(),
                )]));
            }
        };
        match oauth::login(self.token_cache.clone(), &cfg).await {
            Ok(tokens) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Logged in as user {}. Granted scope: {}",
                tokens.user_id.as_deref().unwrap_or("(unknown)"),
                tokens.scope.as_deref().unwrap_or("(none)")
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Login failed: {e}"
            ))])),
        }
    }

    #[tool(
        description = "Clear locally stored OAuth tokens. After this, the next upload/asset tool call requires roblox_login. Does not revoke tokens on Roblox's side; do that from the Creator Dashboard if you need to."
    )]
    async fn roblox_logout(
        &self,
        Parameters(_args): Parameters<RobloxLogout>,
    ) -> Result<CallToolResult, ErrorData> {
        match self.token_cache.clear().await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(
                "Cleared local OAuth tokens.".to_string(),
            )])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Logout failed: {e}"
            ))])),
        }
    }

    #[tool(
        description = "Upload a local file to Roblox as a new asset under the logged-in user's account. Returns the resolved asset metadata including assetId on success."
    )]
    async fn upload_asset(
        &self,
        Parameters(args): Parameters<UploadAsset>,
    ) -> Result<CallToolResult, ErrorData> {
        let client = self.open_cloud()?;
        let upload = UploadArgs {
            file_path: args.file_path,
            asset_type: args.asset_type,
            display_name: args.display_name,
            description: args.description,
            user_id: args.user_id,
            group_id: args.group_id,
            poll_timeout_secs: None,
        };
        match client.upload_asset(upload).await {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()),
            )])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Upload failed: {e}"
            ))])),
        }
    }

    #[tool(
        description = "Replace the contents of an existing asset (by assetId) with the bytes of a local file. The asset type stays the same. Returns the updated asset metadata."
    )]
    async fn update_asset(
        &self,
        Parameters(args): Parameters<UpdateAsset>,
    ) -> Result<CallToolResult, ErrorData> {
        let client = self.open_cloud()?;
        let path = std::path::PathBuf::from(&args.file_path);
        match client.update_asset_content(&args.asset_id, &path, 60).await {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()),
            )])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Update failed: {e}"
            ))])),
        }
    }

    #[tool(description = "Get metadata for a Roblox asset by ID via the Open Cloud Assets API.")]
    async fn get_asset_info(
        &self,
        Parameters(args): Parameters<GetAssetInfo>,
    ) -> Result<CallToolResult, ErrorData> {
        let client = self.open_cloud()?;
        match client.get_asset_info(&args.asset_id).await {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()),
            )])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "get_asset_info failed: {e}"
            ))])),
        }
    }

    #[tool(
        description = "List inventory items belonging to a user (defaults to the logged-in user). Supports pagination and Roblox's filter syntax."
    )]
    async fn list_my_assets(
        &self,
        Parameters(args): Parameters<ListMyAssets>,
    ) -> Result<CallToolResult, ErrorData> {
        let client = self.open_cloud()?;
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
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "list_my_assets failed: {e}"
            ))])),
        }
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
