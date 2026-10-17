local Main = script:FindFirstAncestor("MCPStudioPlugin")
local PathResolver = require(Main.Utils.PathResolver)
local Types = require(Main.Types)

local Selection = game:GetService("Selection")

local function handleSelectInstances(args: Types.SelectInstancesArgs): string?
	local paths = args.instancePaths
	if not paths or #paths == 0 then
		error("instancePaths is required and must not be empty")
	end

	local instances = {}
	for _, path in paths do
		local instance = PathResolver.resolve(path)
		table.insert(instances, instance)
	end

	Selection:Set(instances)
	return "Selected " .. #instances .. " instance(s)"
end

return handleSelectInstances :: Types.ToolFunction
