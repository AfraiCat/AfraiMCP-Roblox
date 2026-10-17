local LogService = game:GetService("LogService")

local DEBUG_TOOL_MAX_OUTPUT = 10000
local TRUNCATION_SUFFIX = "\n[MCP] ...output truncated (10KB cap)..."

local ConsoleOutput = {
	outputMessage = "",
	truncated = false,
}

function ConsoleOutput.startListener()
	local connMessageOut = LogService.MessageOut:Connect(function(message: string, _: Enum.MessageType)
		if #ConsoleOutput.outputMessage + #message <= DEBUG_TOOL_MAX_OUTPUT then
			if #ConsoleOutput.outputMessage == 0 then
				ConsoleOutput.outputMessage = message
			else
				ConsoleOutput.outputMessage = ConsoleOutput.outputMessage .. "\n" .. message
			end
		elseif not ConsoleOutput.truncated then
			-- Record that we dropped output so callers (GetConsoleOutput,
			-- RunCode) don't silently return an incomplete buffer.
			ConsoleOutput.truncated = true
			ConsoleOutput.outputMessage = ConsoleOutput.outputMessage .. TRUNCATION_SUFFIX
		end
	end)
	return connMessageOut
end

return ConsoleOutput
