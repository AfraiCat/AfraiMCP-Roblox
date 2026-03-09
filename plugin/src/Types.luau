export type InsertModelArgs = {
	query: string,
}

export type RunCodeArgs = {
	command: string,
}

export type TestMode = "start_play" | "run_server"

export type StartStopPlayMode = TestMode | "stop"

export type StartStopPlayArgs = {
	mode: StartStopPlayMode,
}

export type RunScriptInPlayModeArgs = {
	code: string,
	timeout: number?,
	mode: TestMode,
}

export type GetInstanceTreeArgs = {
	rootPath: string?,
	maxDepth: number?,
}

export type GetPropertiesArgs = {
	instancePath: string,
	propertyNames: { string }?,
}

export type BatchApplyArgs = {
	selector: "tag" | "className" | "path",
	selectorValue: string,
	property: string,
	value: any,
}

export type SelectInstancesArgs = {
	instancePaths: { string },
}

export type OpenScriptArgs = {
	instancePath: string,
}

export type ReadDataStoreArgs = {
	datastoreName: string,
	key: string,
}

export type MockDataStoreArgs = {
	datastoreName: string,
	key: string,
	value: any,
}

export type GetAssetIdsArgs = {
	rootPath: string?,
	assetTypes: { string }?,
}

export type ClearConsoleArgs = {}

export type ToolArgs =
	{}
	| { InsertModel: InsertModelArgs }
	| { RunCode: RunCodeArgs }
	| { StartStopPlay: StartStopPlayArgs }
	| { RunScriptInPlayMode: RunScriptInPlayModeArgs }
	| { GetInstanceTree: GetInstanceTreeArgs }
	| { GetProperties: GetPropertiesArgs }
	| { BatchApply: BatchApplyArgs }
	| { SelectInstances: SelectInstancesArgs }
	| { OpenScript: OpenScriptArgs }
	| { ReadDataStore: ReadDataStoreArgs }
	| { MockDataStore: MockDataStoreArgs }
	| { GetAssetIds: GetAssetIdsArgs }
	| { ClearConsole: ClearConsoleArgs }

export type ToolFunction = (ToolArgs) -> string?

return {}
