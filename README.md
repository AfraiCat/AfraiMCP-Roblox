# Roblox Studio MCP Server (Custom Fork)

A custom fork of the [Roblox Studio MCP Server](https://github.com/Roblox/studio-rust-mcp-server) with additional tools for faster reads, batch operations, selection/navigation, DataStore inspection, asset management, and Rojo integration.

# Quick Setup
1. Build from source: `cargo run` (installs plugin + configures MCP clients)
2. Or use upstream binaries: [Windows](https://github.com/Roblox/studio-rust-mcp-server/releases/latest/download/rbx-studio-mcp.exe) | [macOS](https://github.com/Roblox/studio-rust-mcp-server/releases/latest/download/macOS-rbx-studio-mcp.zip)
3. Restart AI Client (Claude, Cursor, etc) and Roblox Studio
4. Done!

# Roblox Studio MCP Server

This repository contains a reference implementation of the Model Context Protocol (MCP) that enables
communication between Roblox Studio via a plugin and [Claude Desktop](https://claude.ai/download) or [Cursor](https://www.cursor.com/).
It consists of the following Rust-based components, which communicate through internal shared
objects.

- A web server built on `axum` that a Studio plugin long polls.
- A `rmcp` server that talks to Claude via `stdio` transport.

When LLM requests to run a tool, the plugin will get a request through the long polling and post a
response. It will cause responses to be sent to the Claude app.

**Please note** that this MCP server will be accessed by third-party tools, allowing them to modify
and read the contents of your opened place. Third-party data handling and privacy practices are
subject to their respective terms and conditions.

![Scheme](MCP-Server.png)

The setup process also contains a small plugin installation and Claude Desktop configuration script.

### Included tools

**Core (upstream):**
- **run_code** - Runs a command in Roblox Studio and returns the printed output. Can be used to both make changes and retrieve information.
- **insert_model** - Inserts a model from the Roblox Creator Store into the workspace. Returns the inserted model name.
- **get_console_output** - Gets the console output from Roblox Studio.
- **start_stop_play** - Starts or stops play mode or runs the server.
- **run_script_in_play_mode** - Runs a script in play mode and automatically stops play after the script finishes or times out. Returns structured output including logs, errors, and duration.
- **get_studio_mode** - Gets the current Studio mode (`start_play`, `run_server`, or `stop`).

**Custom fork additions:**
- **get_instance_tree** - Get instance hierarchy as structured JSON (faster than run_code + print parsing). Optional rootPath, maxDepth (default 3, max 5). Limited to 500 nodes / 100KB to prevent chat freezes.
- **get_properties** - Read instance properties directly (Name, ClassName, Attributes, Tags, Position, etc.).
- **batch_apply** - Apply property changes to multiple instances. Select by tag, className, or path.
- **select_instances** - Select instances in the Explorer programmatically.
- **open_script** - Open a script in the Script Editor.
- **read_datastore** - Read DataStore entries (development storage).
- **mock_datastore** - Set DataStore values for test scenarios.
- **get_asset_ids** - Get rbxassetid from instances (images, sounds, decals, etc.). Limited to 200 assets when scanning full game.
- **rojo_sourcemap** - Run `rojo sourcemap` for file-to-instance mapping (requires Rojo).
- **rojo_build** - Run `rojo build` to validate/sync project (requires Rojo).

**OAuth / Open Cloud tools (require setup, see below):**
- **roblox_login** - One-time browser-based OAuth login. Stores tokens locally.
- **roblox_logout** - Clear locally stored tokens.
- **plan_upload** / **upload_asset** - Upload a local file (Animation, Audio, Decal, Image, Mesh, Model or Video) to your Roblox account or a group: `plan_upload` checks the file against your signed upload policy, `upload_asset` sends it after the exact confirm phrase is given.
- **plan_upload_batch** / **upload_batch** - The same for many files at once, see [Batch uploads](#batch-uploads).
- **update_asset** - Replace the contents of an existing asset by ID.
- **get_asset_info** - Read asset metadata via the Open Cloud Assets API.
- **list_my_assets** - Page through your inventory items via the v2 inventory endpoint.

## Batch uploads

Batch mode uploads many files with one plan and one confirmation. It uses the same signed policy, audit log and rate limit as single uploads, and every rule of the policy (`allowed_roots`, `deny_globs`, `allowed_asset_types`, per-type and `max_bytes` size limits, `creators`) applies to **each file**. Nothing is uploaded until the plan is confirmed.

**1. `plan_upload_batch`** (uploads nothing)

| Parameter | Meaning |
|---|---|
| `items` | `[{ filePath, assetType, displayName?, description? }]`. `displayName` defaults to the file name without its extension. |
| `folder`, `glob`, `assetType` | Alternative to `items`: expand `glob` under `folder` (sorted). `*.png` matches the top level, `**/*.png` also sub-folders. The folder itself must be inside `allowed_roots`; symlinks are never followed out of it. |
| `creator` / `userId` / `groupId` | Exactly one; the whole batch goes to that one target. |
| `skipRefused` | Default `false`. By default one refused file means **no plan** and every refusal is returned with its reason. With `true`, the plan covers the accepted files and the refused ones are listed in the result. |

Empty batches, duplicate files (also the same file under two spellings) and more files than the policy's `max_batch_files` are rejected, even with `skipRefused`. The result has `batchPlanId`, a per-file table (file, type, bytes, first 8 hex of the SHA-256, displayName), the refused list, totals, the expiry (10 minutes), an estimate of the time the rate limit alone will take, and the exact `confirmPhrase`:

```
UPLOAD BATCH 5 files (3 Model, 2 Image) to user 123 sha:1a2b3c4d
```

The type counts list the most common type first. The 8 hex digits are the start of a SHA-256 over the sorted lines `{canonical path}\0{file sha256}\0{type}\0{displayName}\0{sha256 of the description}`, so changing, adding or removing a file, or changing its type, name or description, changes the phrase. A plan is single use, and a wrong phrase discards it. Planning the same file again replaces any older pending plan that includes it, so only the newest phrase for a file can be confirmed. The batch id is `batch:<uuid>`.

**2. `upload_batch`**

| Parameter | Meaning |
|---|---|
| `planId` | The `batchPlanId`. |
| `confirm` | Must be `true`, and only after the user agreed to the exact plan. |
| `confirmPhrase` | Copied exactly from the plan. |
| `onError` | `"stop"` (default): halt after the first failed file, the rest are `not_started`. `"continue"`: keep going. |
| `maxWaitSeconds` | Default 600, at most 3600. Caps the **total time the batch spends sleeping for the rate limit**. Time spent uploading and waiting for Roblox to process a file does not count. |

Approval reloads the signed policy and re-checks **every** file (path, type, size, creator, a fresh read, SHA-256 equal to the planned one) before the first upload; one failure aborts the whole batch and nothing is sent. Then the files upload one at a time, in plan order. Each file re-reads and re-verifies its bytes just before it is sent.

*Rate limit.* The policy's `rate_limit_per_minute` (re-read from the signed policy before every file) is a sliding one-minute window shared with single uploads. When it is full, the batch sleeps until the window has room instead of failing. With the default of 10 per minute, 26 files take at least 2 minutes of waiting. A file is not started if its slot would open only after the sleeping budget `maxWaitSeconds` is used up; it and the remaining files are reported `not_started` (the result shows `waitedSeconds`). An upload already in flight is polled to completion (up to 60 seconds) and does not use the budget. The window and the batch lock live in the server process: they are not shared between two server processes, and restarting the server resets the window, so run only one server per Roblox account. The call blocks until the batch ends, so MCP clients need a long enough tool timeout.

*Cancelling.* If the client cancels the request (or disconnects), the batch stops between files and interrupts a rate-limit sleep; the upload in flight finishes first. The remaining files are reported `not_started` with the reason "cancelled", `batch_finished` is still written and the lock is released.

*Policy changes mid-batch.* The signed policy is reloaded before every file. If it is disabled, invalid, unsigned or no longer permits the creator, the batch ends whatever `onError` says: the remaining files are `not_started` and no further rate-limit slot is taken or waited for.

*Result.* One entry per file with `status` (`uploaded`, `failed`, `not_started`), `assetId` or `operation`, `moderationState` and `error`, plus `uploaded`/`failed`/`not_started` counts and `elapsedSeconds`. The tool result is flagged as an error when any file failed or was not started, so a partial batch is not reported as done.

*Only one at a time.* A batch holds a lock: a second `upload_batch` while one runs is refused (without using up its plan), and so are single uploads, and a batch is refused while a single upload is in flight.

*Audit log.* `batch_planned`, `batch_approved` or `batch_denied`, then per file `upload_sending`, `upload_started` and `upload_finished` or `upload_failed`, then `batch_finished` with the summary. `upload_sending` (path, SHA-256, type, display name, description hash) is written **before** the request leaves; if it cannot be written the file is not sent and the batch stops, so after a crash the log still shows which file was going out. `upload_started` is written after the request returns an operation (it is the only entry that carries the operation id); if that write fails the current file is still polled to completion and then the batch stops. This is stricter than single uploads, which continue and report an `auditWarning`. All entries carry the batch id in the `plan_id` field.

*Policy.* `max_batch_files` (1 to 200, default 25) is optional; a policy signed before it existed keeps working with the default. To change it, edit the policy and run `rbx-studio-mcp policy sign` again.

## OAuth setup (one-time)

The Open Cloud tools above require a Roblox OAuth 2.0 application. The MCP itself never sees the client secret embedded in source — it reads two environment variables at startup and stores OAuth tokens locally per-user.

1. Visit the [Creator Dashboard → Open Cloud → OAuth 2.0 Apps](https://create.roblox.com/dashboard/credentials) and create an app.
2. Add **`http://localhost:44756/callback`** as a Redirect URI (the port is fixed; Roblox does not honor wildcard ports for native apps).
3. Under Permissions, enable at minimum **`openid`**, **`profile`**, **`asset:read`**, **`asset:write`**, and **`user.inventory-item:read`** (for `list_my_assets`). You can enable more scopes if you plan to extend the MCP later.
4. Copy the **Client ID** and **Client Secret**.
5. Export them as environment variables in the same shell / launch profile that runs the MCP binary:
   ```sh
   export ROBLOX_OAUTH_CLIENT_ID=...
   export ROBLOX_OAUTH_CLIENT_SECRET=...
   ```
   On Windows (PowerShell):
   ```powershell
   setx ROBLOX_OAUTH_CLIENT_ID "..."
   setx ROBLOX_OAUTH_CLIENT_SECRET "..."
   ```
   For Claude Desktop and similar GUI clients, you'll need to launch them from a shell where these are set (macOS/Linux) or use `setx` (Windows) so they're inherited.
6. Restart the MCP server, then ask the MCP `roblox_login`. A browser tab opens; authorize; you're done.
7. Tokens are written to `~/.config/rbx-studio-mcp/oauth-tokens.json` (or the platform equivalent) with `0600` perms on Unix. Refresh happens automatically as long as the refresh token is valid.

To revoke: run `roblox_logout` (clears local tokens) and/or revoke the app from the Creator Dashboard.

## Setup

### Install with release binaries

This MCP Server supports pretty much any MCP Client but will automatically set up only [Claude Desktop](https://claude.ai/download) and [Cursor](https://www.cursor.com/) if found.

To set up automatically:

1. Ensure you have [Roblox Studio](https://create.roblox.com/docs/en-us/studio/setup),
   and [Claude Desktop](https://claude.ai/download)/[Cursor](https://www.cursor.com/) installed and started at least once.
1. Exit MCP Clients and Roblox Studio if they are running.
1. Download and run the installer:
   1. Go to the [releases](https://github.com/Roblox/studio-rust-mcp-server/releases) page and
      download the latest release for your platform.
   1. Unzip the downloaded file if necessary and run the installer.
   1. Restart Claude/Cursor and Roblox Studio if they are running.

### Setting up manually

To set up manually add following to your MCP Client config:

```json
{
  "mcpServers": {
    "Roblox_Studio": {
      "args": [
        "--stdio"
      ],
      "command": "Path-to-downloaded\\rbx-studio-mcp.exe"
    }
  }
}
```

On macOS the path would be something like `"/Applications/RobloxStudioMCP.app/Contents/MacOS/rbx-studio-mcp"` if you move the app to the Applications directory.

For Claude Desktop, go to Settings > Developer > Edit Config. This opens location of the  `claude_desktop_config.json`.

Some clients require user to setup the mcp server manually for each project.
For example, Claude Code command would look like this:
```sh
claude mcp add --transport stdio Roblox_Studio -- '/Applications/RobloxStudioMCP.app/Contents/MacOS/rbx-studio-mcp' --stdio
```

### Build from source

To build and install the MCP reference implementation from this repository's source code:

1. Ensure you have [Roblox Studio](https://create.roblox.com/docs/en-us/studio/setup) and
   [Claude Desktop](https://claude.ai/download) installed and started at least once.
1. Exit Claude and Roblox Studio if they are running.
1. [Install](https://www.rust-lang.org/tools/install) Rust.
1. Download or clone this repository.
1. Run the following command from the root of this repository.
   ```sh
   cargo run
   ```
   This command carries out the following actions:
      - Builds the Rust MCP server app.
      - Sets up Claude to communicate with the MCP server.
      - Builds and installs the Studio plugin to communicate with the MCP server.

After the command completes, the Studio MCP Server is installed and ready for your prompts from
Claude Desktop.

## Verify setup

To make sure everything is set up correctly, follow these steps:

1. In Roblox Studio, click on the **Plugins** tab and verify that the MCP plugin appears. Clicking on
   the icon toggles the MCP communication with Claude Desktop on and off, which you can verify in
   the Roblox Studio console output.
1. In the console, verify that `The MCP Studio plugin is ready for prompts.` appears in the output.
   Clicking on the plugin's icon toggles MCP communication with Claude Desktop on and off,
   which you can also verify in the console output.
1. Verify that Claude Desktop is correctly configured by clicking on the hammer icon for MCP tools
   beneath the text field where you enter prompts. This should open a window with the list of
   available Roblox Studio tools (`insert_model` and `run_code`).

**Note**: You can fix common issues with setup by restarting Studio and Claude Desktop. Claude
sometimes is hidden in the system tray, so ensure you've exited it completely.

## Send requests

1. Open a place in Studio.
1. Type a prompt in Claude Desktop and accept any permissions to communicate with Studio.
1. Verify that the intended action is performed in Studio by checking the console, inspecting the
   data model in Explorer, or visually confirming the desired changes occurred in your place.
