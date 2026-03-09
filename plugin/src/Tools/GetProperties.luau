local Main = script:FindFirstAncestor("MCPStudioPlugin")
local Types = require(Main.Types)

local HttpService = game:GetService("HttpService")

local SERIALIZABLE_TYPES = { "string", "number", "boolean", "table" }
local SKIP_PROPERTIES = { "Parent", "Archivable" }

local function serializeValue(value: any): any
	local valueType = typeof(value)
	if valueType == "Vector3" then
		return { value.X, value.Y, value.Z }
	elseif valueType == "Vector2" then
		return { value.X, value.Y }
	elseif valueType == "Color3" then
		return { value.R, value.G, value.B }
	elseif valueType == "CFrame" then
		return { "CFrame", value.Position.X, value.Position.Y, value.Position.Z }
	elseif valueType == "UDim2" then
		return { value.X.Scale, value.X.Offset, value.Y.Scale, value.Y.Offset }
	elseif valueType == "Rect" then
		return { value.Min.X, value.Min.Y, value.Width, value.Height }
	elseif valueType == "EnumItem" then
		return tostring(value)
	elseif valueType == "Instance" then
		return value and value:GetFullName() or nil
	elseif valueType == "BrickColor" then
		return value.Name
	elseif table.find(SERIALIZABLE_TYPES, valueType) then
		return value
	else
		return tostring(value)
	end
end

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

local function getInstanceProperties(instance: Instance, propertyNames: { string }?): { [string]: any }
	local result: { [string]: any } = {
		Name = instance.Name,
		ClassName = instance.ClassName,
		FullName = instance:GetFullName(),
	}

	-- Add Attributes and Tags if available
	local ok, attrs = pcall(function()
		return instance:GetAttributes()
	end)
	if ok and attrs and next(attrs) then
		result.Attributes = attrs
	end

	local okTags, tags = pcall(function()
		return instance:GetTags()
	end)
	if okTags and tags and #tags > 0 then
		result.Tags = tags
	end

	-- Get specific properties or all common ones
	if propertyNames and #propertyNames > 0 then
		for _, propName in propertyNames do
			local ok, value = pcall(function()
				return instance[propName]
			end)
			if ok and value ~= nil and not table.find(SKIP_PROPERTIES, propName) then
				result[propName] = serializeValue(value)
			end
		end
	else
		-- Common properties to try
		local commonProps = { "Name", "ClassName", "Position", "Size", "Color", "Transparency", "Material", "Anchored", "CanCollide", "Visible", "Text", "TextColor3", "BackgroundColor3", "Source" }
		for _, propName in commonProps do
			local ok, value = pcall(function()
				return instance[propName]
			end)
			if ok and value ~= nil then
				result[propName] = serializeValue(value)
			end
		end
	end

	return result
end

local function handleGetProperties(args: Types.GetPropertiesArgs): string?
	local instancePath = args.instancePath or "game"
	local propertyNames = args.propertyNames

	local instance = resolvePath(instancePath)
	local properties = getInstanceProperties(instance, propertyNames)
	return HttpService:JSONEncode(properties)
end

return handleGetProperties :: Types.ToolFunction
