local Main = script:FindFirstAncestor("MCPStudioPlugin")
local Types = require(Main.Types)

local DataStoreService = game:GetService("DataStoreService")
local HttpService = game:GetService("HttpService")

local function handleReadDataStore(args: Types.ReadDataStoreArgs): string?
	local datastoreName = args.datastoreName
	local key = args.key

	if not datastoreName or not key then
		error("datastoreName and key are required")
	end

	local datastore = DataStoreService:GetDataStore(datastoreName)
	local success, result = pcall(function()
		return datastore:GetAsync(key)
	end)

	if not success then
		error("DataStore read failed: " .. tostring(result))
	end

	return HttpService:JSONEncode({
		key = key,
		value = result,
		exists = result ~= nil,
	})
end

return handleReadDataStore :: Types.ToolFunction
