local Main = script:FindFirstAncestor("MCPStudioPlugin")
local PathResolver = require(Main.Utils.PathResolver)
local Types = require(Main.Types)

local HttpService = game:GetService("HttpService")

-- Limits to prevent huge responses that freeze/crash the chat
local DEFAULT_MAX_DEPTH = 3
local MAX_DEPTH_CAP = 5
local MAX_NODE_COUNT = 500
local MAX_RESPONSE_BYTES = 100 * 1024 -- 100KB

local function serializeInstance(
	instance: Instance,
	maxDepth: number,
	currentDepth: number,
	nodeCount: { number }
): { [string]: any }
	if currentDepth > maxDepth then
		return { _truncated = true, _reason = "max_depth_exceeded" }
	end

	nodeCount[1] += 1
	if nodeCount[1] > MAX_NODE_COUNT then
		return { _truncated = true, _reason = "max_node_count_exceeded", _hint = "Use a narrower rootPath or lower maxDepth" }
	end

	local result: { [string]: any } = {
		Name = instance.Name,
		ClassName = instance.ClassName,
		FullName = instance:GetFullName(),
	}

	if instance:IsA("BasePart") then
		result.Position = { instance.Position.X, instance.Position.Y, instance.Position.Z }
		result.Size = { instance.Size.X, instance.Size.Y, instance.Size.Z }
		result.Color = { instance.Color.R, instance.Color.G, instance.Color.B }
	elseif instance:IsA("Model") then
		result.PivotPosition = { instance:GetPivot().Position.X, instance:GetPivot().Position.Y, instance:GetPivot().Position.Z }
	end

	local attrs = instance:GetAttributes()
	if next(attrs) then
		result.Attributes = attrs
	end

	local tags = instance:GetTags()
	if #tags > 0 then
		result.Tags = tags
	end

	local children = {}
	for _, child in instance:GetChildren() do
		table.insert(children, serializeInstance(child, maxDepth, currentDepth + 1, nodeCount))
	end
	if #children > 0 then
		result.Children = children
	end

	return result
end

local function safeEncode(value: any): string
	local ok, encoded = pcall(function()
		return HttpService:JSONEncode(value)
	end)
	if ok then
		return encoded
	end
	-- Fallback so a weird value (NaN, inf, cycle) doesn't crash the whole
	-- tool call.
	return HttpService:JSONEncode({
		_error = "json_encode_failed",
		_reason = tostring(encoded),
	})
end

local function handleGetInstanceTree(args: Types.GetInstanceTreeArgs): string?
	local rootPath = if args.rootPath and args.rootPath ~= "" then args.rootPath else "game"
	local requestedDepth = if args.maxDepth and args.maxDepth > 0 then args.maxDepth else DEFAULT_MAX_DEPTH
	local maxDepth = math.min(requestedDepth, MAX_DEPTH_CAP)

	local rootInstance = PathResolver.resolve(rootPath)
	local nodeCount = { 0 }
	local tree = serializeInstance(rootInstance, maxDepth, 0, nodeCount)

	local json = safeEncode(tree)
	if #json > MAX_RESPONSE_BYTES then
		return safeEncode({
			_truncated = true,
			_reason = "response_too_large",
			_hint = "Use a narrower rootPath (e.g. Workspace.MyModel) or lower maxDepth",
			_preview = string.sub(json, 1, 2000) .. "...",
		})
	end
	return json
end

return handleGetInstanceTree :: Types.ToolFunction
