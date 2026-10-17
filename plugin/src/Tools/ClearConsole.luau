local Main = script:FindFirstAncestor("MCPStudioPlugin")
local Types = require(Main.Types)

local LogService = game:GetService("LogService")
local ConsoleOutput = require(Main.Utils.ConsoleOutput)

local function handleClearConsole(): string?
	pcall(function()
		LogService:ClearOutput()
	end)
	ConsoleOutput.outputMessage = ""
	ConsoleOutput.truncated = false
	return "Console cleared"
end

return handleClearConsole :: Types.ToolFunction
