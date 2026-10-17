local Main = script:FindFirstAncestor("MCPStudioPlugin")
local PathResolver = require(Main.Utils.PathResolver)
local Types = require(Main.Types)

local HttpService = game:GetService("HttpService")

-- Hard cap for className selectors scanning the entire game. Prevents
-- pathological cases where the plugin spends seconds walking a huge
-- place and stalls other requests.
local MAX_CLASSNAME_MATCHES = 2000

local function getTargetInstances(selector: string, selectorValue: string): ({ Instance }, boolean)
	local instances = {}
	local truncated = false

	if selector == "tag" then
		instances = game:GetService("CollectionService"):GetTagged(selectorValue)
	elseif selector == "className" then
		for _, desc in game:GetDescendants() do
			if desc:IsA(selectorValue) then
				table.insert(instances, desc)
				if #instances >= MAX_CLASSNAME_MATCHES then
					truncated = true
					break
				end
			end
		end
	elseif selector == "path" then
		local inst = PathResolver.resolve(selectorValue)
		table.insert(instances, inst)
	else
		error("Unknown selector: " .. tostring(selector) .. " (expected tag, className, or path)")
	end

	return instances, truncated
end

local function setPropertyValue(instance: Instance, property: string, value: any): (boolean, string?)
	local ok, err = pcall(function()
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
			else
				error("Invalid Color value; expected {r,g,b} or numeric BrickColor")
			end
		elseif property == "Position" and instance:IsA("BasePart") then
			if type(value) == "table" and #value >= 3 then
				instance.Position = Vector3.new(value[1], value[2], value[3])
			else
				error("Invalid Position value; expected {x,y,z}")
			end
		elseif property == "Size" and instance:IsA("BasePart") then
			if type(value) == "table" and #value >= 3 then
				instance.Size = Vector3.new(value[1], value[2], value[3])
			else
				error("Invalid Size value; expected {x,y,z}")
			end
		else
			instance[property] = value
		end
	end)
	if ok then
		return true, nil
	end
	return false, tostring(err)
end

local function handleBatchApply(args: Types.BatchApplyArgs): string?
	local selector = args.selector
	local selectorValue = args.selectorValue
	local property = args.property
	local value = args.value

	if not selector or not selectorValue or not property then
		error("Missing required arguments: selector, selectorValue, property")
	end

	local instances, truncated = getTargetInstances(selector, selectorValue)
	local modified = 0
	local errors = {}

	for _, instance in instances do
		local ok, err = setPropertyValue(instance, property, value)
		if ok then
			modified += 1
		else
			table.insert(errors, {
				path = instance:GetFullName(),
				error = err,
			})
		end
	end

	return HttpService:JSONEncode({
		modified = modified,
		total = #instances,
		truncated = truncated,
		_hint = if truncated
			then "Hit " .. MAX_CLASSNAME_MATCHES .. " match cap for className selector; narrow the search"
			else nil,
		errors = errors,
	})
end

return handleBatchApply :: Types.ToolFunction
