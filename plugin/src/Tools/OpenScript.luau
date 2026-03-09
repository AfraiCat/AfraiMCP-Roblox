local Main = script:FindFirstAncestor("MCPStudioPlugin")
local Types = require(Main.Types)

local ScriptEditorService = game:GetService("ScriptEditorService")

local function resolvePath(path: string): Instance
	if path == "" or path == "game" or path == "Game" then
		error("instancePath must point to a script instance")
	end

	local parts = string.split(path, ".")
	local current: Instance = game

	for i, part in parts do
		if i == 1 and (part == "game" or part == "Game") then
			current = game
		else
			local child = current:FindFirstChild(part)
			if not child then
				error("Instance not found: " .. path)
			end
			current = child
		end
	end

	return current
end

local function handleOpenScript(args: Types.OpenScriptArgs): string?
	local instancePath = args.instancePath
	if not instancePath or instancePath == "" then
		error("instancePath is required")
	end

	local instance = resolvePath(instancePath)

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
