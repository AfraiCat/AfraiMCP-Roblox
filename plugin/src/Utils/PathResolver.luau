-- Shared path resolver used by every read/write tool. Previously this logic
-- was copy-pasted into six different tool files with subtle drift between
-- them; centralize it here so fixes apply everywhere.

local PathResolver = {}

--[[
	Resolve a dotted instance path like "Workspace.Model.Part" to an Instance.
	Accepts:
	  - ""                       -> game
	  - "game" / "Game"          -> game
	  - "game.Workspace.Foo"     -> game.Workspace.Foo
	  - "Workspace.Foo"          -> game.Workspace.Foo  (implicit game prefix)

	Raises if any segment is missing. Uses FindFirstChild which means
	instance names containing a literal "." cannot currently be resolved.
	This matches the previous behavior; callers that need richer paths
	should extend here rather than copy this function.
]]
function PathResolver.resolve(path: string): Instance
	if not path or path == "" or path == "game" or path == "Game" then
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
				error("Instance not found: " .. path .. " (missing segment: " .. part .. ")")
			end
			current = child
		end
	end

	return current
end

return PathResolver
