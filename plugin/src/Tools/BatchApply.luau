local Main = script:FindFirstAncestor("MCPStudioPlugin")
local Types = require(Main.Types)

local HttpService = game:GetService("HttpService")

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

local function getTargetInstances(selector: string, selectorValue: string): { Instance }
	local instances = {}

	if selector == "tag" then
		instances = game:GetService("CollectionService"):GetTagged(selectorValue)
	elseif selector == "className" then
		for _, desc in game:GetDescendants() do
			if desc:IsA(selectorValue) then
				table.insert(instances, desc)
			end
		end
	elseif selector == "path" then
		local inst = resolvePath(selectorValue)
		table.insert(instances, inst)
	end

	return instances
end

local function setPropertyValue(instance: Instance, property: string, value: any): boolean
	local success = pcall(function()
		if property == "Color" and instance:IsA("BasePart") then
			if type(value) == "table" and #value == 3 then
				-- Support 0-1 scale or 0-255 scale
				local r, g, b = value[1], value[2], value[3]
				if r <= 1 and g <= 1 and b <= 1 then
					instance.Color = Color3.new(r, g, b)
				else
					instance.Color = Color3.fromRGB(r, g, b)
				end
			elseif type(value) == "number" then
				instance.BrickColor = BrickColor.new(value)
			end
		elseif property == "Position" and instance:IsA("BasePart") then
			if type(value) == "table" and #value >= 3 then
				instance.Position = Vector3.new(value[1], value[2], value[3])
			end
		elseif property == "Size" and instance:IsA("BasePart") then
			if type(value) == "table" and #value >= 3 then
				instance.Size = Vector3.new(value[1], value[2], value[3])
			end
		else
			instance[property] = value
		end
	end)
	return success
end

local function handleBatchApply(args: Types.BatchApplyArgs): string?
	local selector = args.selector
	local selectorValue = args.selectorValue
	local property = args.property
	local value = args.value

	if not selector or not selectorValue or not property then
		error("Missing required arguments: selector, selectorValue, property")
	end

	local instances = getTargetInstances(selector, selectorValue)
	local modified = 0
	local errors = {}

	for _, instance in instances do
		local success = setPropertyValue(instance, property, value)
		if success then
			modified += 1
		else
			table.insert(errors, instance:GetFullName())
		end
	end

	return HttpService:JSONEncode({
		modified = modified,
		total = #instances,
		errors = errors,
	})
end

return handleBatchApply :: Types.ToolFunction
