# MCP Shieldwall `v0.3.0` — 9-Client IDE & CLI Integration Guide

**Copy-paste-ready setup for running `mcp-shieldwall` (`serve-mcp` native `stdio` MCP server + `audit-config` CLI config auditor) across all 9 major MCP clients.**

- **Version:** `v0.3.0` (100% Python 3.9+ stdlib · **zero external dependencies**)
- **Repository:** [`https://github.com/andrejpimenov122-lab/mcp-shieldwall`](https://github.com/andrejpimenov122-lab/mcp-shieldwall)
- **Live Playground:** [`https://huggingface.co/spaces/snsnshnwh/mcp-shieldwall`](https://huggingface.co/spaces/snsnshnwh/mcp-shieldwall)
- **MCP Protocol Support:** JSON-RPC 2.0 over `stdio` (`2025-03-26` & `2024-11-05`, auto-detecting newline and `Content-Length` framing)

---

## Table of Contents

- [Quick Compatibility Matrix (All 9 Clients)](#quick-compatibility-matrix-all-9-clients)
- [Prerequisites & Install Channels (Pre-PyPI vs Post-PyPI)](#prerequisites--install-channels-pre-pypi-vs-post-pypi)
- [What `serve-mcp` Exposes Inside Your IDE](#what-serve-mcp-exposes-inside-your-ide)
- [1. Claude Desktop (`claude_desktop_config.json`)](#1-claude-desktop-claude_desktop_configjson)
- [2. Claude Code CLI (`claude mcp add` & `.mcp.json`)](#2-claude-code-cli-claude-mcp-add--mcpjson)
- [3. Cursor (`~/.cursor/mcp.json` & `.cursor/mcp.json`)](#3-cursor-cursormcpjson--cursormcpjson)
- [4. Windsurf (`~/.codeium/windsurf/mcp_config.json`)](#4-windsurf-codeiumwindsurfmcp_configjson)
- [5. VS Code GitHub Copilot (`.vscode/mcp.json` — `"servers"` Root Key)](#5-vs-code-github-copilot-vscodemcpjson--servers-root-key)
- [6. Cline (`cline_mcp_settings.json`)](#6-cline-cline_mcp_settingsjson)
- [7. Roo Code (`mcp_settings.json` & `.roo/mcp.json`)](#7-roo-code-mcp_settingsjson--roomcpjson)
- [8. Zed (`settings.json` — `context_servers`)](#8-zed-settingsjson--context_servers)
- [9. Continue.dev (`config.yaml` — `mcpServers`)](#9-continuedev-configyaml--mcpservers)
- [IDE Agent Prompt Playbook](#ide-agent-prompt-playbook)
- [Audit All Installed Clients at Once (`quickcheck` & Batch CLI)](#audit-all-installed-clients-at-once-quickcheck--batch-cli)
- [Security Rule Reference (`MCP-001` – `MCP-304`) & Exit Codes](#security-rule-reference-mcp-001--mcp-304--exit-codes)
- [Troubleshooting](#troubleshooting)

---

## Quick Compatibility Matrix (All 9 Clients)

| # | MCP Client | Config File(s) | Root Key & Format | Direct `audit-config` | Auto-Checked by `quickcheck` |
| :- | :--- | :--- | :--- | :---: | :---: |
| **1** | **Claude Desktop** | `claude_desktop_config.json` | `"mcpServers"` (JSON) | Yes | Yes |
| **2** | **Claude Code CLI** | `.mcp.json`, `~/.claude.json`, `~/.claude/mcp.json` | `"mcpServers"` (JSON) | Yes | Yes |
| **3** | **Cursor** | `~/.cursor/mcp.json`, `.cursor/mcp.json` | `"mcpServers"` (JSON) | Yes | Yes |
| **4** | **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | `"mcpServers"` (JSON) | Yes | Via `audit-config` |
| **5** | **VS Code GitHub Copilot** | `.vscode/mcp.json`, `Code/User/mcp.json` | **`"servers"`** (JSON) | Yes | Yes |
| **6** | **Cline** | `cline_mcp_settings.json` | `"mcpServers"` (JSON) | Yes | Via `audit-config` |
| **7** | **Roo Code** | `mcp_settings.json`, `.roo/mcp.json` | `"mcpServers"` (JSON) | Yes | Via `audit-config` |
| **8** | **Zed** | `~/.config/zed/settings.json`, `.zed/settings.json` | `"context_servers"` (JSON/JSONC) | Via 1-line adapter / MCP tool | Via 1-line adapter |
| **9** | **Continue.dev** | `~/.continue/config.yaml`, `.continue/mcpServers/*.yaml` | `mcpServers:` list (YAML) | Via 1-line adapter / MCP tool | Via 1-line adapter |

---

## Prerequisites & Install Channels (Pre-PyPI vs Post-PyPI)

All snippets below use [`uv`](https://docs.astral.sh/uv/) (`uvx`), which runs `mcp-shieldwall` in an isolated cache with zero global pollution. Install `uv` if needed:

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Channel A — Pre-PyPI (Run Directly from GitHub Today)

```bash
# Run instant local MCP config security quickcheck:
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall

# Optional immutable tag pin (@v0.3.0):
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall@v0.3.0 mcp-shieldwall
```

### Channel B — Post-PyPI (Once Published on PyPI)

```bash
# Latest release:
uvx mcp-shieldwall

# Pin exact version (recommended for production / enterprise):
uvx mcp-shieldwall@0.3.0
```

> **Alternative without `uvx`:** Install into Python (`pip install git+https://github.com/andrejpimenov122-lab/mcp-shieldwall.git` pre-PyPI or `pip install mcp-shieldwall==0.3.0` post-PyPI), then set `"command": "mcp-shieldwall"` and `"args": ["serve-mcp"]` (or `"command": "mcp-shieldwall-server"`, `"args": []`).

---

## What `serve-mcp` Exposes Inside Your IDE

When connected via `serve-mcp`, your IDE agent gains **4 local, deterministic security tools** (zero network calls, 100% local execution):

| MCP Tool Name | Key Arguments | What It Does |
| :--- | :--- | :--- |
| `audit_client_config` | `config_path` or `config_json`, `format` (`"json"` \| `"markdown"`) | Audits `mcpServers` / `servers` configs for unsafe flags (`MCP-301`), hardcoded secrets (`MCP-302`), unpinned `npx -y` packages (`MCP-303`), and plaintext `http://` URLs (`MCP-304`). |
| `scan_tools_manifest` | `manifest_path` or `manifest_json`, `format` (`"json"` \| `"markdown"`) | Scans MCP `tools/list` definitions for prompt injection (`MCP-001`), `.env`/SSH exfiltration (`MCP-002`), rogue webhooks (`MCP-003`), and Base64-obfuscated payloads (`MCP-004`). |
| `verify_schema_lock` | `manifest_path`, `lock_path` | Verifies canonical SHA-256 per-tool fingerprints (`description` + `inputSchema`) against `.mcp-lock.json` to catch silent upstream "rug-pull" mutations. |
| `redact_sensitive_text` | `text` | Scrubs leaked Anthropic, OpenAI, GitHub, AWS, Slack, Google, and Stripe tokens (`MCP-201`) from logs or tool outputs. |

---

## 1. Claude Desktop (`claude_desktop_config.json`)

### Config File Locations
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

### MCP Server Setup — Pre-PyPI (GitHub)
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrejpimenov122-lab/mcp-shieldwall",
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

### MCP Server Setup — Post-PyPI
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

*(Restart Claude Desktop after saving `claude_desktop_config.json`, then click the hammer/tools icon to confirm `mcp-shieldwall` is active.)*

### CLI Config Auditor (`audit-config`)
```bash
# Pre-PyPI (macOS):
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall audit-config \
  "$HOME/Library/Application Support/Claude/claude_desktop_config.json" --format markdown

# Post-PyPI (macOS):
uvx mcp-shieldwall audit-config \
  "$HOME/Library/Application Support/Claude/claude_desktop_config.json" --format markdown

# Post-PyPI (Windows PowerShell):
uvx mcp-shieldwall audit-config "$env:APPDATA\Claude\claude_desktop_config.json" --format markdown
```

### Example Prompt to Ask Claude Desktop
> `"Use mcp-shieldwall to audit my MCP configuration at ~/Library/Application Support/Claude/claude_desktop_config.json in markdown format and list any hardcoded tokens or unpinned npx servers."`

---

## 2. Claude Code CLI (`claude mcp add` & `.mcp.json`)

Claude Code supports both one-line CLI registration (`claude mcp add`) and repository-shared `.mcp.json` configs.

### Config File Locations
- **Project-shared config (committed to git):** `./.mcp.json`
- **User-scoped config:** `~/.claude.json` (and `~/.claude/mcp.json`)

### Register via `claude mcp add` — Pre-PyPI (GitHub)
```bash
# Current project (local scope):
claude mcp add mcp-shieldwall -- uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall serve-mcp

# User-wide across all repositories:
claude mcp add --scope user mcp-shieldwall -- uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall serve-mcp

# Shared team config (writes to ./.mcp.json):
claude mcp add --scope project mcp-shieldwall -- uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall serve-mcp
```

### Register via `claude mcp add` — Post-PyPI
```bash
# Current project (local scope):
claude mcp add mcp-shieldwall -- uvx mcp-shieldwall serve-mcp

# User-wide across all repositories:
claude mcp add --scope user mcp-shieldwall -- uvx mcp-shieldwall serve-mcp

# Shared team config (writes to ./.mcp.json):
claude mcp add --scope project mcp-shieldwall -- uvx mcp-shieldwall serve-mcp
```

### Direct `.mcp.json` File — Pre-PyPI & Post-PyPI

**Pre-PyPI (`.mcp.json`):**
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrejpimenov122-lab/mcp-shieldwall",
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

**Post-PyPI (`.mcp.json`):**
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

Verify registration inside Claude Code with `claude mcp list` or `/mcp`.

### CLI Config Auditor (`audit-config`)
```bash
# Pre-PyPI — audit repo .mcp.json and user ~/.claude.json:
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall audit-config \
  .mcp.json ~/.claude.json --format markdown

# Post-PyPI:
uvx mcp-shieldwall audit-config .mcp.json ~/.claude.json --format markdown
```

### Example Prompt to Ask Claude Code
> `"Use mcp-shieldwall to audit my MCP configuration in .mcp.json and ~/.claude.json, then propose exact version pins and environment-variable substitutions for any findings."`

---

## 3. Cursor (`~/.cursor/mcp.json` & `.cursor/mcp.json`)

Cursor supports both a global user config (`~/.cursor/mcp.json`) and a per-workspace config (`.cursor/mcp.json`).

### Config File Locations
- **Global (macOS / Linux):** `~/.cursor/mcp.json`
- **Global (Windows):** `%USERPROFILE%\.cursor\mcp.json`
- **Project / Workspace:** `<repo-root>/.cursor/mcp.json`

### MCP Server Setup — Pre-PyPI (GitHub)
Save to `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (workspace):
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrejpimenov122-lab/mcp-shieldwall",
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

### MCP Server Setup — Post-PyPI
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

*(In Cursor, open **Settings → Cursor Settings → Tools & Integrations / MCP** and verify the green status dot next to `mcp-shieldwall`.)*

### CLI Config Auditor (`audit-config`)
```bash
# Pre-PyPI — audit global and workspace Cursor MCP configs:
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall audit-config \
  ~/.cursor/mcp.json .cursor/mcp.json --format markdown

# Post-PyPI:
uvx mcp-shieldwall audit-config ~/.cursor/mcp.json .cursor/mcp.json --format markdown
```

### Example Prompt to Ask Cursor Agent (`Cmd+I` / `Ctrl+I`)
> `"Use mcp-shieldwall to audit my MCP configuration in ~/.cursor/mcp.json and .cursor/mcp.json (format: markdown) and flag any MCP-301..MCP-304 security issues."`

---

## 4. Windsurf (`~/.codeium/windsurf/mcp_config.json`)

Windsurf Cascade reads MCP servers from `~/.codeium/windsurf/mcp_config.json` (accessible in UI via **Cascade → Hammer/Plugins Icon → Configure**).

### Config File Locations
- **macOS / Linux:** `~/.codeium/windsurf/mcp_config.json`
- **Windows:** `%USERPROFILE%\.codeium\windsurf\mcp_config.json`

### MCP Server Setup — Pre-PyPI (GitHub)
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrejpimenov122-lab/mcp-shieldwall",
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

### MCP Server Setup — Post-PyPI
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

*(Click **Refresh** in Windsurf Cascade's MCP panel after saving `mcp_config.json`.)*

### CLI Config Auditor (`audit-config`)
```bash
# Pre-PyPI:
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall audit-config \
  ~/.codeium/windsurf/mcp_config.json --format markdown

# Post-PyPI:
uvx mcp-shieldwall audit-config ~/.codeium/windsurf/mcp_config.json --format markdown
```

### Example Prompt to Ask Windsurf Cascade
> `"Use mcp-shieldwall to audit my MCP configuration at ~/.codeium/windsurf/mcp_config.json and summarize any security risks in a markdown table."`

---

## 5. VS Code GitHub Copilot (`.vscode/mcp.json` — `"servers"` Root Key)

> **Important Schema Difference:** VS Code GitHub Copilot Agent Mode uses **`"servers"`** (NOT `"mcpServers"`) as its top-level JSON key in `.vscode/mcp.json` and `Code/User/mcp.json`, along with `"type": "stdio"`. `mcp-shieldwall` natively parses and audits **both** `"servers"` and `"mcpServers"`!

### Config File Locations
- **Workspace (recommended for teams):** `<repo-root>/.vscode/mcp.json`
- **User Global (macOS):** `~/Library/Application Support/Code/User/mcp.json`
- **User Global (Linux):** `~/.config/Code/User/mcp.json`
- **User Global (Windows):** `%APPDATA%\Code\User\mcp.json`

### MCP Server Setup (`.vscode/mcp.json`) — Pre-PyPI (GitHub)
```json
{
  "servers": {
    "mcp-shieldwall": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrejpimenov122-lab/mcp-shieldwall",
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

### MCP Server Setup (`.vscode/mcp.json`) — Post-PyPI
```json
{
  "servers": {
    "mcp-shieldwall": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "mcp-shieldwall",
        "serve-mcp"
      ]
    }
  }
}
```

### Optional One-Line Registration via `code --add-mcp`
```bash
# Pre-PyPI:
code --add-mcp '{"name":"mcp-shieldwall","type":"stdio","command":"uvx","args":["--from","git+https://github.com/andrejpimenov122-lab/mcp-shieldwall","mcp-shieldwall","serve-mcp"]}'

# Post-PyPI:
code --add-mcp '{"name":"mcp-shieldwall","type":"stdio","command":"uvx","args":["mcp-shieldwall","serve-mcp"]}'
```

### CLI Config Auditor (`audit-config`)
```bash
# Pre-PyPI — audit workspace .vscode/mcp.json:
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall audit-config \
  .vscode/mcp.json --format markdown

# Post-PyPI — audit workspace + macOS User mcp.json:
uvx mcp-shieldwall audit-config \
  .vscode/mcp.json "$HOME/Library/Application Support/Code/User/mcp.json" --format markdown
```

### Example Prompt to Ask GitHub Copilot Chat (Agent Mode)
> `"Use mcp-shieldwall to audit my MCP configuration in .vscode/mcp.json and report any unsafe flags, plaintext http:// endpoints, unpinned npx packages, or hardcoded secrets."`

---

## 6. Cline (`cline_mcp_settings.json`)

In Cline (VS Code / Cursor extension `saoudrizwan.claude-dev`), open the **MCP Servers** icon in the Cline top bar → **Configure** → **Configure MCP Servers** to open `cline_mcp_settings.json`.

### Config File Locations
- **macOS:** `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **Linux:** `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **Windows:** `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

*(If running Cline inside Cursor, replace `Code` with `Cursor` in the path above.)*

### MCP Server Setup — Pre-PyPI (GitHub)
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrejpimenov122-lab/mcp-shieldwall",
        "mcp-shieldwall",
        "serve-mcp"
      ],
      "disabled": false,
      "autoApprove": [
        "scan_tools_manifest",
        "audit_client_config",
        "verify_schema_lock",
        "redact_sensitive_text"
      ]
    }
  }
}
```

### MCP Server Setup — Post-PyPI
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "mcp-shieldwall",
        "serve-mcp"
      ],
      "disabled": false,
      "autoApprove": [
        "scan_tools_manifest",
        "audit_client_config",
        "verify_schema_lock",
        "redact_sensitive_text"
      ]
    }
  }
}
```

### CLI Config Auditor (`audit-config`)
```bash
# Pre-PyPI (macOS):
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall audit-config \
  "$HOME/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" \
  --format markdown

# Post-PyPI (macOS):
uvx mcp-shieldwall audit-config \
  "$HOME/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" \
  --format markdown

# Post-PyPI (Linux):
uvx mcp-shieldwall audit-config \
  "$HOME/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" \
  --format markdown
```

### Example Prompt to Ask Cline
> `"Use mcp-shieldwall to audit my Cline MCP configuration (cline_mcp_settings.json) and tell me if any installed MCP servers expose hardcoded secrets or unsafe flags."`

---

## 7. Roo Code (`mcp_settings.json` & `.roo/mcp.json`)

Roo Code (`rooveterinaryinc.roo-cline`) supports both global MCP settings (`mcp_settings.json`, opened via **MCP Servers → Edit Global MCP**) and project-level `.roo/mcp.json` (**Edit Project MCP**).

### Config File Locations
- **Project / Workspace:** `<repo-root>/.roo/mcp.json`
- **Global (macOS):** `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json`
- **Global (Linux):** `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json`
- **Global (Windows):** `%APPDATA%\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json`

### MCP Server Setup — Pre-PyPI (GitHub)
Save to `mcp_settings.json` or `.roo/mcp.json`:
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrejpimenov122-lab/mcp-shieldwall",
        "mcp-shieldwall",
        "serve-mcp"
      ],
      "disabled": false,
      "alwaysAllow": [
        "scan_tools_manifest",
        "audit_client_config",
        "verify_schema_lock",
        "redact_sensitive_text"
      ]
    }
  }
}
```

### MCP Server Setup — Post-PyPI
```json
{
  "mcpServers": {
    "mcp-shieldwall": {
      "command": "uvx",
      "args": [
        "mcp-shieldwall",
        "serve-mcp"
      ],
      "disabled": false,
      "alwaysAllow": [
        "scan_tools_manifest",
        "audit_client_config",
        "verify_schema_lock",
        "redact_sensitive_text"
      ]
    }
  }
}
```

### CLI Config Auditor (`audit-config`)
```bash
# Pre-PyPI — audit project .roo/mcp.json and macOS global mcp_settings.json:
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall audit-config \
  .roo/mcp.json \
  "$HOME/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json" \
  --format markdown

# Post-PyPI:
uvx mcp-shieldwall audit-config \
  .roo/mcp.json \
  "$HOME/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json" \
  --format markdown
```

### Example Prompt to Ask Roo Code
> `"Use mcp-shieldwall to audit my MCP configuration in .roo/mcp.json and my global Roo Code mcp_settings.json, and output a markdown security report."`

---

## 8. Zed (`settings.json` — `context_servers`)

Zed configures MCP servers inside `settings.json` under the **`"context_servers"`** key (open via `Cmd+,` / `Ctrl+,` → `zed: open settings`).

### Config File Locations
- **Global (macOS / Linux):** `~/.config/zed/settings.json`
- **Global (Windows):** `%APPDATA%\Zed\settings.json`
- **Project / Workspace:** `<repo-root>/.zed/settings.json`

### MCP Server Setup (`settings.json`) — Pre-PyPI (GitHub)
```json
{
  "context_servers": {
    "mcp-shieldwall": {
      "source": "custom",
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrejpimenov122-lab/mcp-shieldwall",
        "mcp-shieldwall",
        "serve-mcp"
      ],
      "env": {}
    }
  }
}
```

### MCP Server Setup (`settings.json`) — Post-PyPI
```json
{
  "context_servers": {
    "mcp-shieldwall": {
      "source": "custom",
      "command": "uvx",
      "args": [
        "mcp-shieldwall",
        "serve-mcp"
      ],
      "env": {}
    }
  }
}
```

> **Legacy Zed Schema Note:** Older Zed builds (< `0.175`) nested `"command"` as `{"path": "uvx", "args": [...], "env": {}}`. Modern Zed uses top-level `"source": "custom"`, `"command": "uvx"`, `"args": [...]` as shown above.

### CLI Config Auditor for Zed `context_servers`
Because Zed stores MCP entries under `"context_servers"` inside `settings.json` (which may also include `//` JSONC comments or legacy `command.path` objects), normalize `context_servers` into `"mcpServers"` and pass to `mcp-shieldwall audit-config`:

```bash
# Pre-PyPI — normalize ~/.config/zed/settings.json and audit:
python3 -c '
import json, pathlib, re, tempfile
raw = pathlib.Path("~/.config/zed/settings.json").expanduser().read_text()
clean = re.sub(r"(?m)^\s*//.*$", "", raw)
cs = json.loads(clean).get("context_servers", {})
norm = {}
for k, v in cs.items():
    if isinstance(v, dict) and isinstance(v.get("command"), dict):
        cmd = v["command"]
        norm[k] = {"command": cmd.get("path", ""), "args": cmd.get("args", []), "env": cmd.get("env", v.get("env", {}))}
    else:
        norm[k] = v
tmp = pathlib.Path(tempfile.gettempdir()) / "zed_mcp_normalized.json"
tmp.write_text(json.dumps({"mcpServers": norm}, indent=2))
print(tmp)
' | xargs -I{} uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall audit-config "{}" --format markdown

# Post-PyPI (replace the final xargs command with):
# | xargs -I{} uvx mcp-shieldwall audit-config "{}" --format markdown
```

### Example Prompt to Ask Zed Agent Panel
> `"Read ~/.config/zed/settings.json, map its context_servers entries under an mcpServers JSON object, and pass that JSON into mcp-shieldwall's audit_client_config tool (format: markdown) to audit my Zed MCP configuration."`

---

## 9. Continue.dev (`config.yaml` — `mcpServers`)

Continue.dev (`v1.0+`) configures MCP servers in YAML inside `~/.continue/config.yaml` (or as standalone workspace YAML blocks in `.continue/mcpServers/mcp-shieldwall.yaml`).

### Config File Locations
- **Global (macOS / Linux):** `~/.continue/config.yaml`
- **Global (Windows):** `%USERPROFILE%\.continue\config.yaml`
- **Workspace Modular Block:** `<repo-root>/.continue/mcpServers/mcp-shieldwall.yaml`

### MCP Server Setup (`config.yaml` / `.continue/mcpServers/mcp-shieldwall.yaml`) — Pre-PyPI (GitHub)
```yaml
name: Local Assistant
version: 1.0.0
schema: v1
mcpServers:
  - name: mcp-shieldwall
    command: uvx
    args:
      - --from
      - git+https://github.com/andrejpimenov122-lab/mcp-shieldwall
      - mcp-shieldwall
      - serve-mcp
```

### MCP Server Setup (`config.yaml` / `.continue/mcpServers/mcp-shieldwall.yaml`) — Post-PyPI
```yaml
name: Local Assistant
version: 1.0.0
schema: v1
mcpServers:
  - name: mcp-shieldwall
    command: uvx
    args:
      - mcp-shieldwall
      - serve-mcp
```

*(Ensure Continue is set to **Agent** mode so MCP tools are enabled in the chat dropdown.)*

### CLI Config Auditor for Continue `config.yaml`
Continue's `config.yaml` stores `mcpServers` as a YAML list (`- name: ...`). Convert `mcpServers` from `~/.continue/config.yaml` to JSON and audit with `mcp-shieldwall audit-config`:

```bash
# Pre-PyPI (uses PyYAML if installed, or run inside a uvx --with pyyaml ephemeral env):
uvx --with pyyaml --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall python -c '
import json, pathlib, sys, yaml
from mcp_shieldwall.cli import build_config_report, format_markdown_report
cfg_path = pathlib.Path("~/.continue/config.yaml").expanduser()
doc = yaml.safe_load(cfg_path.read_text()) or {}
servers = {item["name"]: {k: v for k, v in item.items() if k != "name"} for item in doc.get("mcpServers", []) if isinstance(item, dict) and "name" in item}
report = build_config_report({"mcpServers": servers}, str(cfg_path))
print(format_markdown_report(report))
sys.exit(0 if report["passed"] else 2)
'

# Post-PyPI:
uvx --with pyyaml --from mcp-shieldwall python -c '
import pathlib, sys, yaml
from mcp_shieldwall.cli import build_config_report, format_markdown_report
cfg_path = pathlib.Path("~/.continue/config.yaml").expanduser()
doc = yaml.safe_load(cfg_path.read_text()) or {}
servers = {item["name"]: {k: v for k, v in item.items() if k != "name"} for item in doc.get("mcpServers", []) if isinstance(item, dict) and "name" in item}
report = build_config_report({"mcpServers": servers}, str(cfg_path))
print(format_markdown_report(report))
sys.exit(0 if report["passed"] else 2)
'
```

### Example Prompt to Ask Continue Agent
> `"Use mcp-shieldwall to audit my MCP configuration: read ~/.continue/config.yaml, convert the mcpServers list into an {\"mcpServers\": {\"<name>\": ...}} JSON object, and call audit_client_config with format='markdown'."`

---

## IDE Agent Prompt Playbook

Once `mcp-shieldwall` is active in **any** of the 9 clients above, copy-paste these prompts directly into your IDE chat/agent window:

### 1. Audit Your Active MCP Client Configuration (`audit_client_config`)
```text
Use mcp-shieldwall to audit my MCP configuration and return the report in markdown format. Highlight any hardcoded API keys (MCP-302), unpinned npx -y packages (MCP-303), unsafe flags like --allow-all (MCP-301), or unencrypted http:// URLs (MCP-304), and show me the exact remediated config.
```

### 2. Scan a Third-Party MCP `tools/list` Manifest for Tool Poisoning (`scan_tools_manifest`)
```text
Use mcp-shieldwall's scan_tools_manifest tool (format: "markdown") on ./tools.json to check for hidden prompt-injection instructions (MCP-001), SSH/.env exfiltration directives (MCP-002), suspicious webhooks (MCP-003), and Base64-obfuscated payloads (MCP-004).
```

### 3. Verify Schema Lockfile Against Upstream "Rug-Pulls" (`verify_schema_lock`)
```text
Use mcp-shieldwall's verify_schema_lock tool to compare ./tools.json against ./.mcp-lock.json and tell me if any tool descriptions or inputSchemas silently changed upstream.
```

### 4. Scrub Secrets Before Sharing Logs or Opening an Issue (`redact_sensitive_text`)
```text
Use mcp-shieldwall's redact_sensitive_text tool to scrub any leaked Anthropic, OpenAI, GitHub, AWS, Slack, Google, or Stripe credentials from the following log snippet before summarizing it:
<paste log text>
```

---

## Audit All Installed Clients at Once (`quickcheck` & Batch CLI)

### Instant Zero-Arg Auto-Discovery (`quickcheck`)
Running `mcp-shieldwall` with no arguments automatically discovers and audits existing configs across `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `~/.claude.json`, `~/.claude/mcp.json`, `~/.cursor/mcp.json`, Claude Desktop `claude_desktop_config.json`, and VS Code User `mcp.json`:

```bash
# Pre-PyPI:
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall

# Pre-PyPI (machine-readable JSON summary):
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall quickcheck --format json

# Post-PyPI:
uvx mcp-shieldwall
uvx mcp-shieldwall quickcheck --format json
```

### Multi-Client Sweep (Includes Windsurf, Cline & Roo Code)
```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIGS=()
for candidate in \
  ".mcp.json" \
  ".cursor/mcp.json" \
  ".vscode/mcp.json" \
  ".roo/mcp.json" \
  "$HOME/.claude.json" \
  "$HOME/.claude/mcp.json" \
  "$HOME/.cursor/mcp.json" \
  "$HOME/.codeium/windsurf/mcp_config.json" \
  "$HOME/Library/Application Support/Claude/claude_desktop_config.json" \
  "$HOME/.config/Claude/claude_desktop_config.json" \
  "$HOME/Library/Application Support/Code/User/mcp.json" \
  "$HOME/.config/Code/User/mcp.json" \
  "$HOME/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" \
  "$HOME/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" \
  "$HOME/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json" \
  "$HOME/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"
do
  [[ -f "$candidate" ]] && CONFIGS+=("$candidate")
done

if [[ ${#CONFIGS[@]} -eq 0 ]]; then
  echo "No JSON MCP client configs found."
  exit 0
fi

# Pre-PyPI (swap to `uvx mcp-shieldwall audit-config ...` post-PyPI):
uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall \
  mcp-shieldwall audit-config "${CONFIGS[@]}" --format markdown
```

### Block Unsafe Config Commits in Git (`pre-commit`)
Add to `.pre-commit-config.yaml` to automatically block unsafe `.mcp.json`, `.cursor/mcp.json`, or `.vscode/mcp.json` commits:

```yaml
repos:
  - repo: https://github.com/andrejpimenov122-lab/mcp-shieldwall
    rev: v0.3.0
    hooks:
      - id: mcp-shieldwall-config
      - id: mcp-shieldwall-manifest
```

---

## Security Rule Reference (`MCP-001` – `MCP-304`) & Exit Codes

| Rule ID | Severity | Scope | Description |
| :--- | :---: | :--- | :--- |
| `MCP-001` | `CRITICAL` | `scan` / `scan_tools_manifest` | Hidden prompt-injection directive (`<IMPORTANT>`, `ignore previous instructions`, `silently exfiltrate`) in tool metadata |
| `MCP-002` | `CRITICAL` | `scan` / `scan_tools_manifest` | Sensitive credential / `~/.ssh/id_rsa` / `.env` / keychain access directive in tool metadata |
| `MCP-003` | `HIGH` | `scan` / `scan_tools_manifest` | Suspicious exfiltration webhook (`webhook.site`, `ngrok-free.app`, `requestbin`, raw `curl -X POST`) |
| `MCP-004` | `CRITICAL` | `scan` / `scan_tools_manifest` | Base64 / Base64URL-obfuscated prompt-injection or destructive payload inside tool schema |
| `MCP-101` | `CRITICAL` | Runtime JSON-RPC Guard | Destructive shell command (`rm -rf /`, `mkfs.`, `dd if=`, `chmod -R 777 /`) in `tools/call` arguments |
| `MCP-102` | `CRITICAL` | Runtime JSON-RPC Guard | Pipe-to-shell RCE pattern (`curl ... \| bash`, `wget ... \| sh`) in `tools/call` arguments |
| `MCP-103` | `CRITICAL` | Runtime JSON-RPC Guard | Base64-obfuscated destructive or injection payload in `tools/call` arguments |
| `MCP-201` | `HIGH` | `redact` / `redact_sensitive_text` | Leaked API key/token detected and scrubbed (Anthropic, OpenAI, GitHub, AWS, Slack, Google, Stripe) |
| `MCP-301` | `HIGH` / `CRITICAL` | `audit-config` / `audit_client_config` | Unsafe permissive flag (`--allow-all`, `--dangerously-skip-permissions`, `--no-sandbox`, `--yolo`, `--privileged`) or destructive shell command |
| `MCP-302` | `CRITICAL` / `HIGH` | `audit-config` / `audit_client_config` | Hardcoded API token, Bearer header, or literal secret in `command`, `args`, `url`, `headers`, or `env` |
| `MCP-303` | `HIGH` | `audit-config` / `audit_client_config` | Unpinned `npx -y <pkg>` without an immutable version specifier (e.g., missing `@1.2.3` or using `@latest`) |
| `MCP-304` | `MEDIUM` | `audit-config` / `audit_client_config` | Remote (non-localhost) MCP server URL uses unencrypted `http://` instead of `https://` |

**CLI Exit Codes:**
- `0` — Clean pass (no findings / lockfile verified)
- `1` — Input error (missing file, malformed JSON, or passing a client config to `scan` instead of `audit-config`)
- `2` — Security findings detected or lockfile mismatch (fails CI / pre-commit gates deterministically)

---

## Troubleshooting

1. **`spawn uvx ENOENT` in GUI apps (Claude Desktop, Cursor, Windsurf, Zed on macOS/Windows):**
   GUI apps on macOS often do not inherit `~/.local/bin` or Homebrew paths from `~/.zshrc`. Run `which uvx` in your terminal (commonly `/Users/you/.local/bin/uvx` or `/opt/homebrew/bin/uvx`) and set `"command"` to that full absolute path.
2. **Smoke-testing `serve-mcp` from your terminal:**
   Verify the JSON-RPC handshake directly before restarting your IDE:
   ```bash
   printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"1.0"}}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' \
     | uvx --from git+https://github.com/andrejpimenov122-lab/mcp-shieldwall mcp-shieldwall serve-mcp
   ```
   You should see `serverInfo: {"name": "mcp-shieldwall", "version": "0.3.0"}` followed by all 4 tools (`scan_tools_manifest`, `audit_client_config`, `verify_schema_lock`, `redact_sensitive_text`).
3. **Accidentally passing an MCP config to `mcp-shieldwall scan`:**
   `mcp-shieldwall` refuses false-clean passes (`ValueError: ... is an MCP client config (mcpServers/servers), not a tools/list manifest`). Always use `mcp-shieldwall audit-config <config.json>` for client configurations and `mcp-shieldwall scan <tools.json>` for tool manifests.
