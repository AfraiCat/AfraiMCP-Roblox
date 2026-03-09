local Main = script:FindFirstAncestor("MCPStudioPlugin")
local Types = require(Main.Types)

local tools: { [string]: Types.ToolFunction } = {
	["GetConsoleOutput"] = require(Main.Tools.GetConsoleOutput),
	["ClearConsole"] = require(Main.Tools.ClearConsole),
	["GetStudioMode"] = require(Main.Tools.GetStudioMode),
	["InsertModel"] = require(Main.Tools.InsertModel),
	["RunCode"] = require(Main.Tools.RunCode),
	["RunScriptInPlayMode"] = require(Main.Tools.RunScriptInPlayMode),
	["StartStopPlay"] = require(Main.Tools.StartStopPlay),
	-- Custom fork: Read operations
	["GetInstanceTree"] = require(Main.Tools.GetInstanceTree),
	["GetProperties"] = require(Main.Tools.GetProperties),
	-- Custom fork: Batch operations
	["BatchApply"] = require(Main.Tools.BatchApply),
	-- Custom fork: Selection & navigation
	["SelectInstances"] = require(Main.Tools.SelectInstances),
	["OpenScript"] = require(Main.Tools.OpenScript),
	-- Custom fork: DataStore inspection
	["ReadDataStore"] = require(Main.Tools.ReadDataStore),
	["MockDataStore"] = require(Main.Tools.MockDataStore),
	-- Custom fork: Asset management
	["GetAssetIds"] = require(Main.Tools.GetAssetIds),
}

local function dispatchTool(toolName: string, args: Types.ToolArgs): string?
	local toolFunction = tools[toolName]
	if not toolFunction then
		error("Tool " .. toolName .. " not found")
	end

	return toolFunction(args)
end

return {
	tools = tools,
	dispatchTool = dispatchTool,
}
