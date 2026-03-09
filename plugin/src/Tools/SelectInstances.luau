local Main = script:FindFirstAncestor("MCPStudioPlugin")
local Types = require(Main.Types)

local Selection = game:GetService("Selection")

local function resolvePath(path: string): Instance
	if path == "" or path == "game" or path == "Game" then
		return game
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

local function handleSelectInstances(args: Types.SelectInstancesArgs): string?
	local paths = args.instancePaths
	if not paths or #paths == 0 then
		error("instancePaths is required and must not be empty")
	end

	local instances = {}
	for _, path in paths do
		local instance = resolvePath(path)
		table.insert(instances, instance)
	end

	Selection:Set(instances)
	return "Selected " .. #instances .. " instance(s)"
end

return handleSelectInstances :: Types.ToolFunction
