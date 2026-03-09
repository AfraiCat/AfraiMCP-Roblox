local Main = script:FindFirstAncestor("MCPStudioPlugin")
local Types = require(Main.Types)

local DataStoreService = game:GetService("DataStoreService")
local HttpService = game:GetService("HttpService")

local function handleMockDataStore(args: Types.MockDataStoreArgs): string?
	local datastoreName = args.datastoreName
	local key = args.key
	local value = args.value

	if not datastoreName or not key then
		error("datastoreName and key are required")
	end

	local datastore = DataStoreService:GetDataStore(datastoreName)
	local success, err = pcall(function()
		datastore:SetAsync(key, value)
	end)

	if not success then
		error("DataStore write failed: " .. tostring(err))
	end

	return HttpService:JSONEncode({
		success = true,
		key = key,
		message = "Value set successfully. Note: In Studio, DataStore uses development storage.",
	})
end

return handleMockDataStore :: Types.ToolFunction
