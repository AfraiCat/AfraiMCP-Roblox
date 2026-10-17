local Main = script:FindFirstAncestor("MCPStudioPlugin")
local PathResolver = require(Main.Utils.PathResolver)
local Types = require(Main.Types)

local ScriptEditorService = game:GetService("ScriptEditorService")

local function handleOpenScript(args: Types.OpenScriptArgs): string?
	local instancePath = args.instancePath
	if not instancePath or instancePath == "" then
		error("instancePath is required")
	end
	if instancePath == "game" or instancePath == "Game" then
		error("instancePath must point to a script instance")
	end

	local instance = PathResolver.resolve(instancePath)

	if not instance:IsA("LuaSourceContainer") then
		error("Instance must be a script (Script, ModuleScript, or LocalScript): " .. instance.ClassName)
	end

	local success, err = ScriptEditorService:OpenScriptDocumentAsync(instance :: LuaSourceContainer)
	if success then
		return "Opened script: " .. instance:GetFullName()
	else
		error("Failed to open script: " .. tostring(err))
	end
end

return handleOpenScript :: Types.ToolFunction
