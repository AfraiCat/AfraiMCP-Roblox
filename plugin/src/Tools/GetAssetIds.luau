local Main = script:FindFirstAncestor("MCPStudioPlugin")
local Types = require(Main.Types)

local HttpService = game:GetService("HttpService")

-- Limit to prevent huge responses when scanning full game
local MAX_ASSETS_TO_RETURN = 200

local ASSET_PROPERTIES = {
	Image = { "Image", "ImageColor3" },
	Decal = { "Texture" },
	Sound = { "SoundId" },
	VideoFrame = { "Video" },
	MeshPart = { "MeshId" },
	SpecialMesh = { "MeshId", "TextureId" },
	FileMesh = { "MeshId" },
	Texture = { "Texture" },
	Sky = { "SkyboxUp", "SkyboxDn", "SkyboxLf", "SkyboxRt", "SkyboxFt", "SkyboxBk" },
	SurfaceAppearance = { "ColorMap", "NormalMap", "MetalnessMap", "RoughnessMap" },
	Accessory = { "AccessoryType" },
	Shirt = { "ShirtTemplate" },
	Pants = { "PantsTemplate" },
	ShirtGraphic = { "Graphic" },
	PackageLink = { "PackageId" },
	Animation = { "AnimationId" },
}

local function extractAssetIdFromRbxAsset(rbxAsset: string): number?
	local match = string.match(rbxAsset, "rbxassetid://(%d+)")
	if match then
		return tonumber(match)
	end
	match = string.match(rbxAsset, "rbxasset://(%d+)")
	if match then
		return tonumber(match)
	end
	return nil
end

local function getAssetIdsFromInstance(instance: Instance, assetTypes: { string }?): { { id: number, path: string, property: string, type: string } }
	local results = {}
	local instanceType = instance.ClassName

	if assetTypes and #assetTypes > 0 then
		local allowed = {}
		for _, t in assetTypes do
			allowed[t] = true
		end
		if not allowed[instanceType] then
			return results
		end
	end

	local props = ASSET_PROPERTIES[instanceType]
	if not props then
		return results
	end

	for _, propName in props do
		local ok, value = pcall(function()
			return instance[propName]
		end)
		if ok and type(value) == "string" and value ~= "" then
			local assetId = extractAssetIdFromRbxAsset(value)
			if assetId then
				table.insert(results, {
					id = assetId,
					path = instance:GetFullName(),
					property = propName,
					type = instanceType,
				})
			end
		end
	end

	return results
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

local function handleGetAssetIds(args: Types.GetAssetIdsArgs): string?
	local rootPath = if args.rootPath and args.rootPath ~= "" then args.rootPath else "game"
	local assetTypes = args.assetTypes

	local rootInstance = resolvePath(rootPath)
	local allAssets = {}

	local toSearch = { rootInstance }
	if rootInstance == game then
		toSearch = game:GetDescendants()
		table.insert(toSearch, 1, game)
	end

	local truncated = false
	for _, instance in toSearch do
		if #allAssets >= MAX_ASSETS_TO_RETURN then
			truncated = true
			break
		end
		local assets = getAssetIdsFromInstance(instance, assetTypes)
		for _, asset in assets do
			table.insert(allAssets, asset)
			if #allAssets >= MAX_ASSETS_TO_RETURN then
				truncated = true
				break
			end
		end
	end

	return HttpService:JSONEncode({
		rootPath = rootPath,
		count = #allAssets,
		truncated = truncated,
		_hint = if truncated then "Use a narrower rootPath (e.g. Workspace) to get more results" else nil,
		assets = allAssets,
	})
end

return handleGetAssetIds :: Types.ToolFunction
