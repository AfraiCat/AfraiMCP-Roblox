local Main = script:FindFirstAncestor("MCPStudioPlugin")
local ConsoleOutput = require(Main.Utils.ConsoleOutput)
local DataModelType = require(Main.Utils.DataModelType)
local GameStopUtil = require(Main.Utils.GameStopUtil)
local MockWebSocketService = require(Main.MockWebSocketService)
local PluginUtils = require(Main.Utils.PluginUtils)
local ToolDispatcher = require(Main.Utils.ToolDispatcher)
local Types = require(Main.Types)

local ChangeHistoryService = game:GetService("ChangeHistoryService")
local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")
local StudioService = game:GetService("StudioService")

local URI = "http://localhost:44755"
local RECEIVE_ENDPOINT = "/request"
local SEND_ENDPOINT = "/response"
local PLUGIN_DISABLED_SETTING_KEY = "Disabled-MCP-plugin-setting"

PluginUtils.plugin = plugin

local datamodelType = DataModelType.getDataModelType()

if datamodelType == "Server" then
	task.spawn(GameStopUtil.monitorForStopPlay)
end

if RunService:IsRunning() then
	return
end

local connMessageOut = ConsoleOutput.startListener()
plugin.Unloading:Connect(function()
	connMessageOut:Disconnect()
end)

local old_warn = warn
local function log(...)
	if false then
		old_warn(...)
	end
end

-- Read-only tools don't need to create undo-history entries. Wrapping them
-- in ChangeHistoryService would produce bogus undo steps and also risks
-- "Previous recording not finished" warnings when requests overlap.
local READ_ONLY_TOOLS: { [string]: true } = {
	GetConsoleOutput = true,
	GetStudioMode = true,
	GetInstanceTree = true,
	GetProperties = true,
	GetAssetIds = true,
	ReadDataStore = true,
}

local function toolCallHandler(args: Types.ToolArgs): string
	local toolName = next(args)
	if not toolName then
		error("No tool name found in request")
	end

	local toolArgs = args[toolName]
	if not toolArgs or type(toolArgs) ~= "table" then
		error("Invalid tool args found for tool name: " .. toolName)
	end

	local isReadOnly = READ_ONLY_TOOLS[toolName] == true
	-- Unique recording name so overlapping write tools don't collide.
	local recording = if isReadOnly
		then nil
		else ChangeHistoryService:TryBeginRecording("StudioMCP:" .. toolName .. ":" .. HttpService:GenerateGUID(false))

	local success, response = pcall(ToolDispatcher.dispatchTool, toolName, toolArgs)
	if recording then
		ChangeHistoryService:FinishRecording(
			recording,
			if success
				then Enum.FinishRecordingOperation.Commit
				else Enum.FinishRecordingOperation.Cancel
		)
	end

	if success then
		return response or ""
	end
	error("Error handling request: " .. tostring(response))
end

local function connectWebSocket()
	local client = MockWebSocketService:CreateClient(URI)
	client:SetReceiveEndpoint(RECEIVE_ENDPOINT)
	client:SetSendEndpoint(SEND_ENDPOINT)

	client.Opened:Once(function()
		log("[MCP] Connection opened")
	end)

	client.Closed:Once(function()
		log("[MCP] Connection closed")
	end)

	client.MessageReceived:Connect(function(message)
		log("[MCP] Message received")

		local ok, body = pcall(HttpService.JSONDecode, HttpService, message)
		if not ok or not body or not body.id or not body.args then
			log("[MCP] Invalid message received:", message)
			return
		end

		local id: string = body.id
		local args: Types.ToolArgs = body.args

		-- Run each request on its own coroutine so the HTTP poll loop can
		-- return and pick up the next request immediately. Previously, a
		-- single slow tool (play mode, deep tree walk, ExecutePlayModeAsync)
		-- would stall the poll loop and force every other tool to wait.
		task.spawn(function()
			local responseSent = false
			local function sendResponseOnce(success: boolean, response: string)
				if responseSent then
					return
				end
				responseSent = true
				log("[MCP] Sending response:", response)
				client:Send({
					id = id,
					success = success,
					response = response,
				})
			end

			local success, response = pcall(toolCallHandler, args)
			sendResponseOnce(success, tostring(response))

			log("[MCP] Successfully handled request")
		end)
	end)

	return client
end

local function getButtonImage()
	local ok, response = pcall(function()
		return StudioService:GetClassIcon("PackageLink").Image
	end)
	return ok and response or "rbxasset://textures/ui/GuiImagePlaceholder.png"
end

local toolbar = plugin:CreateToolbar("MCP")
local toggleButton = toolbar:CreateButton("Toggle MCP", "Toggle connection to the server", getButtonImage())
toggleButton.ClickableWhenViewportHidden = true

local currentClient: MockWebSocketService.MockWebSocketClient?

if not plugin:GetSetting(PLUGIN_DISABLED_SETTING_KEY) then
	currentClient = connectWebSocket()
	print("The MCP Studio plugin is ready for prompts.")
end

toggleButton:SetActive(currentClient ~= nil)

toggleButton.Click:Connect(function()
	if not currentClient then
		currentClient = connectWebSocket()
		print("The MCP Studio plugin is ready for prompts.")
	else
		currentClient:Close()
		currentClient = nil
		print("The MCP Studio plugin is stopped.")
	end
	toggleButton:SetActive(currentClient ~= nil)
	plugin:SetSetting(PLUGIN_DISABLED_SETTING_KEY, currentClient == nil)
end)
