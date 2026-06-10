# MCP configuration for the harness

Sixth (which descends from Cline) reads MCP servers from a single global settings file —
**not** from this folder directly. The file here is a **template** you merge into that
global file.

## Why only `fetch`, and why read-only?

The harness is intentionally minimal. The bundled server is the Model Context Protocol
**fetch** server — it retrieves a URL and returns the content (and headers) as text. It is
read-only HTTP and respects `robots.txt` by default, which fits the non-destructive rules
of engagement. The agent can also use the terminal (`curl`, `dig`, `openssl`) for the same
checks; MCP `fetch` is a convenience.

`autoApprove` is deliberately **empty** so you approve each fetch. That manual gate is part
of keeping requests in-scope. Only add `"fetch"` to `autoApprove` if you accept
auto-approved outbound requests.

## Install

1. Ensure [`uv`](https://docs.astral.sh/uv/) is installed (provides `uvx`):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   # alternatively, run the server with pipx: pipx run mcp-server-fetch
   ```
2. Open the global MCP settings file (create it if missing). On this machine:
   - **VS Code:** `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
   - **VS Code Insiders:** `~/.config/Code - Insiders/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
   - macOS: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
   - Windows: `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

   Or open it from the Sixth panel: **MCP Servers → Configure / Edit Settings**.
3. Merge the `"fetch"` entry from [cline_mcp_settings.json](cline_mcp_settings.json) into the
   `"mcpServers"` object of that file. If the file is empty, paste the whole contents.
4. Save. Sixth watches the file and will connect the server automatically.

## Optional: identify your researcher User-Agent

If a program requires a specific `User-Agent`, configure the fetch server to use it:

```jsonc
"fetch": {
  "command": "uvx",
  "args": ["mcp-server-fetch", "--user-agent", "h1-<your-handle>-research"],
  "disabled": false,
  "autoApprove": [],
  "timeout": 60
}
```

Do **not** pass `--ignore-robots-txt`; respecting robots is part of staying courteous.

## A note on scope

MCP `fetch` can request any URL. It does **not** know your program scope. Always run
`scope-authorization-guard` first and only fetch in-scope hosts. The empty `autoApprove`
keeps a human in the loop for every request.
