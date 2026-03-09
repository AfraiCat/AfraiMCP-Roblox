use crate::error::{Report, Result};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{extract::State, Json};
use color_eyre::eyre::{eyre, Error, OptionExt};
use std::path::PathBuf;
use tokio::process::Command;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    schemars, tool, tool_handler, tool_router, ErrorData, ServerHandler,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::oneshot::Receiver;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::Duration;
use uuid::Uuid;

pub const STUDIO_PLUGIN_PORT: u16 = 44755;
const LONG_POLL_DURATION: Duration = Duration::from_secs(15);

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
#[derive(Clone)]
pub struct RBXStudioServer {
    state: PackedState,
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
Rojo tools (rojo_sourcemap, rojo_build) run on host; require Rojo installed."
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
    #[schemars(description = "Root path (e.g. 'game', 'Workspace', 'Workspace.Model'). Default: game")]
    root_path: Option<String>,
    #[serde(rename = "maxDepth")]
    #[schemars(description = "Max depth for tree traversal. Default: 3, max: 5. Use narrower rootPath (e.g. Workspace.MyModel) for deeper trees.")]
    max_depth: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct GetProperties {
    #[serde(rename = "instancePath")]
    #[schemars(description = "Instance path (e.g. 'Workspace.Part', 'game.Lighting')")]
    instance_path: String,
    #[serde(rename = "propertyNames")]
    #[schemars(description = "Optional list of property names to fetch. If omitted, returns common properties")]
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
    #[schemars(description = "Value to set. For Color use [r,g,b] 0-1. For Position/Size use [x,y,z]")]
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

// Custom fork: Rojo/File sync (runs locally in Rust, not in plugin)
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, Clone)]
struct RojoSourcemap {
    #[serde(rename = "projectPath")]
    #[schemars(description = "Path to Rojo project (default.project.json) or directory. Default: current workspace")]
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
    pub fn new(state: PackedState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
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

    async fn generic_tool_run(
        &self,
        args: ToolArgumentValues,
    ) -> Result<CallToolResult, ErrorData> {
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
        let result = rx
            .recv()
            .await
            .ok_or(ErrorData::internal_error("Couldn't receive response", None))?;
        {
            let mut state = self.state.lock().await;
            state.output_map.remove_entry(&id);
        }
        tracing::debug!("Sending to MCP: {result:?}");
        match result {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(result)])),
            Err(err) => Ok(CallToolResult::error(vec![Content::text(err.to_string())])),
        }
    }

    async fn run_rojo_sourcemap(
        &self,
        args: RojoSourcemap,
    ) -> Result<CallToolResult, ErrorData> {
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
    let result = rx.recv().await.ok_or_eyre("Couldn't receive response")?;
    {
        let mut state = state.lock().await;
        state.output_map.remove_entry(&id);
    }
    let (success, response) = match result {
        Ok(s) => (true, s),
        Err(e) => (false, e.to_string()),
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
            let res = client
                .post(format!("http://127.0.0.1:{STUDIO_PLUGIN_PORT}/proxy"))
                .json(&entry)
                .send()
                .await;
            if let Ok(res) = res {
                let tx = {
                    state
                        .lock()
                        .await
                        .output_map
                        .remove(&entry.id.unwrap())
                        .unwrap()
                };
                let res = res
                    .json::<RunCommandResponse>()
                    .await
                    .map(|r| r.response)
                    .map_err(Into::into);
                tx.send(res).unwrap();
            } else {
                tracing::error!("Failed to proxy: {res:?}");
            };
        } else {
            waiter.changed().await.unwrap();
        }
    }
}
