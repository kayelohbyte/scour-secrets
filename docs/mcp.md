# MCP Reference

The `sanitize-mcp` binary wraps the `sanitize` CLI as a Model Context Protocol server. All sensitive data processing happens inside the audited Rust CLI — the MCP layer handles only protocol framing. This means files are sanitized **before** their contents enter the LLM context window.

---

## Installation

Download the `sanitize-mcp` binary for your platform from the [Releases](https://github.com/kayelohbyte/rust-sanitize/releases) page (no Deno or Node required — the runtime is embedded).

Alternatively, run from source with [Deno](https://deno.land) 2.x (no compile step):

```bash
SANITIZE_BIN=/usr/local/bin/sanitize \
  deno run --allow-run --allow-env --allow-read --allow-write \
  mcp/src/index.ts
```

---

## Keeping Secrets Out of the Context Window

This is the core purpose of the MCP integration. The `files` parameter takes a **file path**, not file contents. `sanitize-mcp` opens and processes the file as a subprocess — raw bytes never enter the MCP transport or the LLM context window. The agent passes a path string and receives sanitized text back. It never sees the original.

```
Agent                    MCP server          Sanitize binary
  │                          │                     │
  │── files: ["/path"]  ────▶│                     │
  │   secrets_file: "/s.yaml"│── spawns process ──▶│ opens /path
  │                          │                     │ opens /s.yaml
  │                          │                     │ processes bytes
  │◀── sanitized text ───────│◀── sanitized text ──│ (raw bytes stay here)
```

This applies to **all path-type parameters**: `files`, `secrets_file`, and `profile`. The agent never sees your pattern definitions or detection rules, only the sanitized output. A compromised context cannot exfiltrate either.

### Blocking Direct File Reads by AI Tool

The MCP path prevents the agent from reading raw content *through the sanitize tool*. A separate concern is whether the agent can read the same file directly through its own file-browsing tools. The answer depends on which tool you're using.

| Tool | Direct file reads | Built-in path deny | MCP subprocess affected by deny |
|------|------------------|-------------------|--------------------------------|
| Claude Code | Yes | ✓ `PreToolUse` hook (verified) | No — hook only intercepts built-in Read tool |
| OpenCode | Yes | ✓ `permission.read` deny rules | No — rules apply to agent reads, not subprocesses |
| Cursor | Yes | ✓ Enforcement hooks (enterprise) | No — hooks intercept agent reads only |
| OpenAI Codex | Yes | ✓ TOML deny rules (OS-enforced) | **Yes** — Seatbelt/bubblewrap applies to all child processes |
| VS Code (Copilot) | Yes | ✗ | N/A |
| ChatGPT / Gemini | No direct filesystem access | ✗ | N/A — files must be explicitly uploaded |

For **Claude Code, OpenCode, and Cursor**: deny rules block the agent's direct file reads but leave MCP subprocess calls unaffected — sanitize-mcp can be spawned on-demand and will still access the files.

For **OpenAI Codex**: deny rules are enforced by the OS sandbox (Seatbelt on macOS, bubblewrap on Linux). All child processes inherit the sandbox, including an on-demand `sanitize-mcp`. To allow sanitize-mcp to access denied files, run it as a **persistent daemon outside the Codex sandbox** — connect Codex to the already-running MCP server rather than having Codex spawn it.

For **VS Code**: OS-level file permissions (service-user model) are the only mechanism.

For **ChatGPT and Gemini**: no ambient filesystem access — control what you explicitly upload.

### File System Permissions (All Tools)

Own sensitive files by a dedicated service user so the agent's login process cannot open them directly:

```bash
sudo useradd -r -s /sbin/nologin sanitize-svc
sudo chown sanitize-svc:sanitize-svc /var/data/sensitive.log
sudo chmod 0600 /var/data/sensitive.log
```

The agent process (running as your login user) cannot open the file. For `sanitize-mcp` to open it, the server must also run as `sanitize-svc` — which requires the **persistent daemon** setup below. When AI tools spawn `sanitize-mcp` on demand it inherits the login user's permissions, so on-demand mode cannot access files owned exclusively by the service user.

For multi-user deployments a shared group is more practical:

```bash
sudo groupadd sanitize-readers
sudo usermod -aG sanitize-readers sanitize-svc
sudo chown root:sanitize-readers /var/data/sensitive.log
sudo chmod 0640 /var/data/sensitive.log
```

### Running as a Persistent Daemon

Run `sanitize-mcp` as a system service with `--http`. The server binds to `127.0.0.1` only on port **6277** by default and requires a bearer token on every request — set via `SANITIZE_MCP_HTTP_TOKEN`. AI tools connect to the already-running server rather than spawning it, so the daemon's user and file permissions are independent of the AI tool. Pass `--http <n>` to bind to a different port; update the port in your client config to match.

**Generate a token:**

```bash
openssl rand -hex 32
# e.g. a3f8c2...  — store this; you'll need it in both the service file and your MCP client config
```

**macOS — launchd plist** (`/Library/LaunchDaemons/com.sanitize.mcp.plist`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>com.sanitize.mcp</string>
  <key>UserName</key>          <string>sanitize-svc</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/sanitize-mcp</string>
    <string>--http</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SANITIZE_BIN</key>             <string>/usr/local/bin/sanitize</string>
    <key>SANITIZE_SECRETS_DIR</key>     <string>/var/sanitize/secrets</string>
    <key>SANITIZE_MCP_HTTP_TOKEN</key>  <string>YOUR_TOKEN_HERE</string>
  </dict>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>StandardErrorPath</key> <string>/var/log/sanitize-mcp.log</string>
</dict>
</plist>
```

```bash
# Restrict the plist — it contains the token
sudo chmod 0600 /Library/LaunchDaemons/com.sanitize.mcp.plist
sudo launchctl load /Library/LaunchDaemons/com.sanitize.mcp.plist
```

**Linux — systemd unit** (`/etc/systemd/system/sanitize-mcp.service`):

Store secrets in a separate environment file rather than inline in the unit — the unit file is world-readable via `systemctl show`, the env file is not:

```bash
sudo mkdir -p /etc/sanitize-mcp
sudo tee /etc/sanitize-mcp/env > /dev/null <<'EOF'
SANITIZE_BIN=/usr/local/bin/sanitize
SANITIZE_SECRETS_DIR=/var/sanitize/secrets
SANITIZE_MCP_HTTP_TOKEN=YOUR_TOKEN_HERE
EOF
sudo chmod 0600 /etc/sanitize-mcp/env
```

```ini
[Unit]
Description=sanitize-mcp daemon
After=network.target

[Service]
User=sanitize-svc
ExecStart=/usr/local/bin/sanitize-mcp --http
EnvironmentFile=/etc/sanitize-mcp/env
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now sanitize-mcp
```

**Windows — NSSM** ([nssm.cc](https://nssm.cc) or `scoop install nssm`):

NSSM wraps any executable as a Windows service and handles env vars, stdout/stderr, and auto-restart.

```powershell
nssm install sanitize-mcp "C:\Program Files\sanitize\sanitize-mcp.exe"
nssm set sanitize-mcp AppParameters "--http"
nssm set sanitize-mcp AppEnvironmentExtra `
  "SANITIZE_BIN=C:\Program Files\sanitize\sanitize.exe" `
  "SANITIZE_SECRETS_DIR=C:\ProgramData\sanitize\secrets" `
  "SANITIZE_MCP_HTTP_TOKEN=YOUR_TOKEN_HERE"
nssm set sanitize-mcp AppStderr "C:\ProgramData\sanitize\logs\sanitize-mcp.log"
nssm set sanitize-mcp Start SERVICE_AUTO_START
nssm start sanitize-mcp
```

NSSM stores env vars in `HKLM\SYSTEM\CurrentControlSet\Services\sanitize-mcp\Parameters\AppEnvironment`, which requires admin privileges to read.

**Connecting AI tools to the daemon** — use a `url` with an `Authorization` header instead of a `command`. Put this in **user-scope config only** — never in project-scope config that gets committed to version control.

Claude Code (`~/.claude/claude.json`, user scope):

```json
{
  "mcpServers": {
    "rust-sanitize": {
      "url": "http://127.0.0.1:6277/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

OpenCode (`~/.config/opencode/opencode.json`, global scope):

```json
{
  "mcp": {
    "rust-sanitize": {
      "type": "remote",
      "url": "http://127.0.0.1:6277/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

For Codex, add a remote MCP entry pointing to the same URL with the same header. The daemon runs outside Codex's OS sandbox, so it can access any files `sanitize-svc` has permission to read.

> **Single-session limit:** The HTTP daemon maintains one active MCP session at a time. When the AI tool disconnects cleanly (sends the MCP DELETE request), the daemon exits and the service manager restarts it automatically — the next connection gets a fresh session. This covers the common case: Claude Code, OpenCode, and most clients send DELETE on shutdown or session end. Unclean disconnects (process crash, kill signal) leave the daemon in a stuck state; the service manager cannot detect these without a health-check probe, so a manual `launchctl kickstart`/`systemctl restart`/`nssm restart` is required after an unclean exit.

> **Security notes:**
> - The token is the only access control. Treat it like a password — rotate by updating the service config, reloading the daemon, and updating your client configs.
> - The server binds to `127.0.0.1` only and is not reachable from the network.
> - The token travels in plaintext over loopback. This is acceptable for local use (sniffing loopback requires root). For remote deployment, put a TLS-terminating reverse proxy (e.g. Caddy) in front.
> - Do not put the token in project-scope `.mcp.json` — it will end up in version control.
> - Service configuration files containing the token must be mode `0600` (shown above for macOS and Linux).
> - **What the daemon logs:** only a startup message (`sanitize-mcp daemon ready on 127.0.0.1:<port>`) and unhandled error class names. It never logs request bodies, file paths, file content, or the `Authorization` header. The sanitize subprocess is audited separately — its output is always the redacted result, never raw secrets.

### OpenCode: Block Direct Reads with `permission.read`

OpenCode has a built-in `permission.read` system that supports path-pattern deny rules. Add entries to `opencode.json` in your project root (or `~/.config/opencode/opencode.json` for global scope):

```json
{
  "permission": {
    "read": {
      "*": "allow",
      "/var/sanitize/secrets/**": "deny",
      "/var/data/sensitive/**": "deny"
    }
  }
}
```

Rules are evaluated by pattern match with **last match winning** — place the catch-all `"*": "allow"` first, then specific deny patterns after. Supports `*` (any characters) and `?` (single character) wildcards.

MCP tool calls pass file paths to the sanitize subprocess and are not subject to `permission.read` rules — the agent cannot read the raw file, but the sanitize tool processes it normally.

### Cursor: Block Direct Reads with Enforcement Hooks (Enterprise)

Cursor's enterprise tier supports enforcement hooks that intercept the agent loop at four points, including **before file reading**. Hooks are bash scripts that receive JSON context on stdin and return a structured response. A hook that outputs `"permission": "deny"` and exits with code `3` blocks the read.

The hook pattern mirrors Claude Code's approach: inspect the incoming file path and deny if it matches a restricted prefix. Refer to [Cursor's enterprise documentation](https://cursor.com/docs/enterprise/llm-safety-and-controls) for the exact JSON field names and registration syntax, as these are enterprise-tier specifics.

> **Note:** `.cursorignore` is explicitly not a security boundary — Cursor's own documentation states it is a convenience feature for excluding files from indexing, not for preventing access. Do not rely on it to protect sensitive files.

### OpenAI Codex: Block Reads with OS-Enforced TOML Deny Rules

Codex uses a TOML permission profile with `deny` rules enforced at the OS level — Seatbelt on macOS, bubblewrap on Linux, sandbox users on Windows. Add deny rules to your permission profile:

```toml
[permissions.project-edit.filesystem]
"/var/sanitize/secrets" = "deny"
"/var/data/sensitive" = "deny"

[permissions.project-edit.filesystem.":workspace_roots"]
"." = "write"
"**/*.env" = "deny"
```

`deny` blocks both reads and writes. Narrower rules take precedence over broader ones at the same path level.

**Important:** because enforcement is OS-level, all child processes inherit the sandbox — including `sanitize-mcp` if Codex spawns it on demand. To allow sanitize-mcp to access denied paths, run it as a **persistent daemon** and connect Codex to the already-running server via HTTP. See [Running as a Persistent Daemon](#running-as-a-persistent-daemon).

Refer to the [Codex permissions documentation](https://developers.openai.com/codex/permissions#filesystem-permissions) for the full profile schema and platform-specific notes.

### Claude Code: Block Direct Reads with a PreToolUse Hook

For Claude Code, a `PreToolUse` hook intercepts `Read` tool calls before they execute. MCP tool calls run in a separate subprocess channel and are not affected — the hook only blocks the agent's built-in file reader. Add this to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -c \"\nimport json, sys, os\nd = json.load(sys.stdin)\npath = os.path.realpath(d.get('tool_input', {}).get('file_path', ''))\nblocked = [\n  '/var/sanitize/secrets',\n  '/var/data/sensitive',\n]\nif any(path.startswith(b) for b in blocked):\n    print(json.dumps({'decision': 'block', 'reason': 'Path is restricted — pass it to the sanitize MCP tool instead.'}))\n    sys.exit(2)\n\""
          }
        ]
      }
    ]
  }
}
```

The hook receives the tool call as JSON on stdin, resolves the path (following symlinks via `os.path.realpath`), and exits with code `2` to block if it falls under a restricted prefix. The `reason` string is shown to the agent. Update the `blocked` list to match your deployment paths. Changes take effect on the next session start.

This has been verified on macOS and Linux: `Read` calls to blocked paths are rejected with the reason message, while the sanitize CLI processes the same paths successfully through Bash or the MCP tool.

On **Linux** you can additionally use `sandbox.filesystem.denyRead` (requires `sandbox.enabled: true`), which uses bubblewrap to enforce read restrictions at the OS level.

### Recommended Storage Locations

| Location | Notes |
|----------|-------|
| `/var/data/<service>/` | Outside project tree; own by a service user |
| `~/sensitive/` | Outside version-controlled directories |
| `/run/secrets/` | Docker secrets mount; tmpfs, readable only by container user |
| `/mnt/secrets/` | Kubernetes `hostPath` volume or CSI secrets store |

Avoid storing sensitive source files inside the project directory — editors and agents routinely scan and index everything reachable under the workspace root.

### Namespace Secrets Directory Permissions

The `SANITIZE_SECRETS_DIR` namespace layout enforces permission checks at load time: the `.password` file for each namespace must be `0600` or `0400` or the server will refuse to start. Apply the same ownership model to the parent directory so agents cannot enumerate namespaces:

```bash
sudo chown -R sanitize-svc:sanitize-svc /var/sanitize/secrets/
sudo chmod 0750 /var/sanitize/secrets/           # sanitize-svc can enter; agent user cannot
sudo chmod 0700 /var/sanitize/secrets/acme-corp/ # namespace dirs: service user only
sudo chmod 0600 /var/sanitize/secrets/acme-corp/secrets.yaml
sudo chmod 0600 /var/sanitize/secrets/acme-corp/.password
```

---

## IDE & Editor Setup

All configurations assume `sanitize-mcp` is at `/usr/local/bin/sanitize-mcp` and `sanitize` is at `/usr/local/bin/sanitize`. Adjust paths to match your installation.

### Claude Code

Add at **project scope** (writes `.mcp.json` in the repo root, checked into version control):

```bash
claude mcp add --scope project rust-sanitize /usr/local/bin/sanitize-mcp \
  -e SANITIZE_BIN=/usr/local/bin/sanitize
```

Add at **user scope** (available across all your projects):

```bash
claude mcp add --scope user rust-sanitize /usr/local/bin/sanitize-mcp \
  -e SANITIZE_BIN=/usr/local/bin/sanitize
```

Or write `.mcp.json` at the repo root manually:

```json
{
  "mcpServers": {
    "rust-sanitize": {
      "command": "/usr/local/bin/sanitize-mcp",
      "env": {
        "SANITIZE_BIN": "/usr/local/bin/sanitize"
      }
    }
  }
}
```

### Cursor

**Project scope** — create `.cursor/mcp.json` in the repo root:

```json
{
  "mcpServers": {
    "rust-sanitize": {
      "command": "/usr/local/bin/sanitize-mcp",
      "args": [],
      "env": {
        "SANITIZE_BIN": "/usr/local/bin/sanitize"
      }
    }
  }
}
```

**Global scope** — same format at `~/.cursor/mcp.json`.

Requires Cursor 0.43 or later. Restart Cursor after editing the file.

### Neovim

**mcphub.nvim** — add to `~/.config/mcphub/servers.json`:

```json
{
  "servers": {
    "rust-sanitize": {
      "command": "/usr/local/bin/sanitize-mcp",
      "args": [],
      "env": {
        "SANITIZE_BIN": "/usr/local/bin/sanitize"
      }
    }
  }
}
```

**codecompanion.nvim** (v19+, built-in MCP support) — add to your Lua config:

```lua
require("codecompanion").setup({
  strategies = {
    chat = { adapter = "anthropic" },
  },
  extensions = {
    mcphub = {
      callback = "mcphub.extensions.codecompanion",
      opts = { show_result_in_chat = true },
    },
  },
})
```

**avante.nvim** — wire via mcphub bridge:

```lua
require("avante").setup({
  provider = "claude",
  custom_tools = require("mcphub.extensions.avante").mcp_tool(),
  system_prompt = function()
    local hub = require("mcphub").get_hub_instance()
    return hub and hub:get_active_servers_prompt() or ""
  end,
})
```

### OpenCode

**Project scope** — create `opencode.json` in the repo root:

```json
{
  "mcp": {
    "rust-sanitize": {
      "type": "local",
      "command": ["/usr/local/bin/sanitize-mcp"],
      "environment": {
        "SANITIZE_BIN": "/usr/local/bin/sanitize",
        "PATH": "{env:PATH}"
      }
    }
  }
}
```

**Global scope** — same format at `~/.config/opencode/opencode.json`. Both files are merged, so project config layers on top of global config. Use `{env:VAR}` syntax to forward existing shell variables into the server process.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SANITIZE_BIN` | `sanitize` | Path to the `sanitize` binary. |
| `SANITIZE_MCP_HTTP_TOKEN` | _(unset)_ | Bearer token required when running in HTTP daemon mode (`--http`). Must be set; the server refuses to start without it when `--http` is used. |
| `SANITIZE_MCP_MAX_CONTENT_BYTES` | `524288` (512 KB) | Per-call inline content size limit. |
| `SANITIZE_MCP_TIMEOUT_MS` | `60000` (60 s) | Subprocess timeout — kills the CLI and returns an error if exceeded. |
| `SANITIZE_MCP_THREADS` | _(unset = CLI default = logical CPUs)_ | Worker thread cap for every invocation — useful on shared hosts. |
| `SANITIZE_MCP_MAX_ARCHIVE_DEPTH` | `5` | Default max archive nesting depth (matches CLI default). |
| `SANITIZE_SECRETS_DIR` | _(unset)_ | Root directory for per-namespace secrets. Each subdirectory is a namespace and may contain `secrets.yaml[.enc]`, `profile.yaml`, and an optional `.password` file (`0600`/`0400` permissions enforced). |

---

## Available Tools

| Tool | Description |
|------|-------------|
| `sanitize` | Sanitize inline text or files. Set `llm_template` to `'troubleshoot'`, `'review-config'`, or `'review-security'` for a fully-formatted LLM prompt. |
| `scan` | Scan for secrets and return a report without modifying content. |
| `strip_config_values` | Strip values from key=value config files, preserving keys and structure. |
| `test_allowlist` | Test which values match a set of allowlist patterns. |
| `list_apps` | List all available app bundles (built-in + user-defined). |
| `init` | Create a starter secrets file on disk from a preset template and return its contents. |
| `build_secrets` | Build a tailored secrets file from specific patterns. Typical workflow: scan → identify gaps → build_secrets → sanitize. |
| `test_pattern` | Test which values are matched by a secrets file, app bundle, or inline patterns. Returns per-value match results. |

---

## Tool Examples

All examples show the JSON parameters passed to the relevant tool.

### Choosing between `content` and `files`

**Prefer `files` whenever you have a file path.** The engine processes the file directly — raw bytes never enter the LLM context, binary and archive formats are handled correctly, and there is no inline size limit.

Use `content` only when you already have the text in your context and no file path is available (e.g. text extracted by another tool call, or a short string generated in memory).

| | `files` | `content` |
|---|---|---|
| Raw bytes in LLM context | No | Yes |
| Binary / archive support | Yes | No |
| Size limit | None | 512 KB default |
| **Use when** | **You have a path** | **You only have the text** |

### Sanitize inline content

Inline text is piped through the CLI via stdin — use this only when you have the text in context and no file path is available.

```json
{
  "tool": "sanitize",
  "content": "Error connecting to postgres://admin:hunter2@db.internal:5432/prod"
}
```

When no `secrets_file` or `app` is specified, the built-in pattern set is used automatically — covering API keys, emails, IPs, JWTs, UUIDs, and credential URLs. Returns the sanitized string.

### Sanitize files before the LLM reads them

Pass file paths via `files` — the CLI processes them directly and the raw content never enters the LLM context window.

```json
{
  "tool": "sanitize",
  "files": ["/etc/gitlab/gitlab.rb", "/var/log/gitlab/production_json.log"],
  "app": ["gitlab"]
}
```

Returns a `results` array — one entry per input file — each containing `input` (original path), `file` (output filename), and `content` (sanitized text).

### Get a fully-formatted LLM prompt

Set `llm_template` to skip raw sanitized text and get a structured prompt ready to paste directly into a conversation. This is the fastest path from raw logs or configs to actionable LLM analysis.

```json
{
  "tool": "sanitize",
  "files": ["/var/log/server.log"],
  "llm_template": "troubleshoot"
}
```

Returns a pre-structured incident-triage prompt with the sanitized content embedded. All built-in templates instruct the LLM to ask clarifying questions rather than guessing at redacted values.

Use `"review-config"` for configuration review:

```json
{
  "tool": "sanitize",
  "files": ["/etc/gitlab/gitlab.rb"],
  "app": ["gitlab"],
  "llm_template": "review-config"
}
```

Use `"review-security"` for a security posture assessment covering auth, network exposure, TLS/crypto, CVEs, and hardcoded secret placement:

```json
{
  "tool": "sanitize",
  "files": ["/etc/nginx/nginx.conf"],
  "app": ["nginx"],
  "llm_template": "review-security"
}
```

Combine with `extract_context` to surface notable error and warning events inside the prompt:

```json
{
  "tool": "sanitize",
  "files": ["server.log"],
  "llm_template": "troubleshoot",
  "extract_context": true,
  "context_lines": 15,
  "context_keywords": ["timeout", "oomkilled", "segfault"]
}
```

### Multiple files with a secrets file

```json
{
  "tool": "sanitize",
  "files": ["server.log", "config.yaml", "backup.zip"],
  "secrets_file": "patterns.yaml",
  "profile": "fields.yaml"
}
```

Archives are extracted, sanitized entry-by-entry, and re-packaged. Archive results carry `binary: true` and `size` instead of inline `content`.

### App bundles

App bundles pair a secrets pattern set with a structured field profile for a specific application.

```json
{
  "tool": "sanitize",
  "files": ["/etc/nginx/nginx.conf"],
  "app": ["nginx"]
}
```

```json
{
  "tool": "sanitize",
  "files": ["docker-compose.yml", "values.yaml"],
  "app": ["docker-compose", "kubernetes"]
}
```

Use `list_apps` to discover all available bundle names including user-defined bundles:

```json
{ "tool": "list_apps" }
```

### Archive entry filtering

Use `archive_filters` to restrict which entries inside an archive are processed — equivalent to the CLI's `--only` / `--exclude` flags.

```json
{
  "tool": "sanitize",
  "files": ["backup.zip", "logs.tar.gz"],
  "archive_filters": [
    {
      "path": "backup.zip",
      "only": ["config/", "**/*.json"],
      "exclude": ["config/secrets.json"]
    },
    {
      "path": "logs.tar.gz",
      "only": ["**/*.log"]
    }
  ]
}
```

Patterns follow the same rules as the CLI: `*` does not cross `/`, `**` does, trailing `/` is a directory-prefix match.

### Scan for secrets (audit without modifying)

Returns a structured JSON report of what would be replaced — nothing is written.

```json
{
  "tool": "scan",
  "files": ["config.yaml"],
  "app": ["gitlab"]
}
```

### Security gate — fail if secrets are detected

`fail_on_match` adds a `secrets_detected` boolean to the response. Agents can branch on it without parsing the full report.

```json
{
  "tool": "scan",
  "files": ["terraform.tfvars"],
  "fail_on_match": true
}
```

Returns `{ "secrets_detected": true, "report": { ... } }` if secrets are found, `{ "secrets_detected": false, "report": { ... } }` otherwise.

### Extract context (error/warning snippets)

`extract_context` scans the sanitized output for error/warning keywords and returns a structured context report alongside the sanitized content.

```json
{
  "tool": "sanitize",
  "content": "...",
  "extract_context": true,
  "context_lines": 10,
  "context_keywords": ["timeout", "connection refused"],
  "max_context_matches": 100
}
```

Response becomes `{ content, report }`. `report` contains per-file match lists with surrounding lines.

To replace the built-in default keywords entirely rather than extending them, add `context_keywords_replace: true`:

```json
{
  "tool": "sanitize",
  "files": ["server.log"],
  "extract_context": true,
  "context_keywords": ["FATAL", "OOM"],
  "context_keywords_replace": true
}
```

### Deterministic replacements

Supply a `seed` for HMAC-deterministic mode. Identical seed + identical input produces identical replacements across calls and sessions.

```json
{
  "tool": "sanitize",
  "content": "alice@corp.com logged in from 10.0.1.5",
  "seed": "session-2024-incident-42"
}
```

Use the same `seed` in follow-up calls to get consistent replacements when correlating sanitized data across multiple files.

### Inline patterns (no secrets file)

Define patterns directly in the tool call using the `patterns` array. Supports `regex`, `literal`, and `allow` kinds.

```json
{
  "tool": "sanitize",
  "content": "user alice@corp.com, token sk-proj-abc123, host db.internal",
  "patterns": [
    { "name": "corp_email",  "pattern": "alice@corp\\.com",   "category": "email",      "kind": "regex" },
    { "name": "openai_key",  "pattern": "sk-proj-abc123",     "category": "auth_token", "kind": "literal" },
    { "name": "safe_host",   "pattern": "*.internal",          "category": "auth_token", "kind": "allow" }
  ]
}
```

`allow` entries pass through unchanged and are not recorded in the mapping store. `kind` defaults to `"literal"` when omitted.

### Shannon entropy detection

Add `entropy_threshold` to catch high-entropy tokens beyond pattern matching. Tokens of 20–200 alphanumeric characters whose Shannon entropy exceeds the threshold (bits per character) are treated as secrets. Typical secrets sit above 4.5; random UUIDs sit around 3.8.

```json
{
  "tool": "sanitize",
  "files": ["server.log"],
  "entropy_threshold": 4.5
}
```

### Force streaming scan (bypass structured processors)

`force_text` skips all structured processors (JSON, YAML, etc.) and runs only the byte-level streaming scanner. Use when the format is ambiguous or when guaranteed full-byte coverage is needed regardless of field rules.

```json
{
  "tool": "sanitize",
  "files": ["unknown-format.dat"],
  "force_text": true
}
```

### Binary entries in archives

By default, binary entries inside archives are skipped. Set `include_binary: true` to process them.

```json
{
  "tool": "sanitize",
  "files": ["mixed-content.zip"],
  "include_binary": true
}
```

### Archive depth limit

Override the server-wide archive depth default on a per-call basis. The default is `5`. Override the server default for all calls via `SANITIZE_MCP_MAX_ARCHIVE_DEPTH`.

```json
{
  "tool": "sanitize",
  "files": ["nested.tar.gz"],
  "max_archive_depth": 8
}
```

### Path exclusions and hidden files

Use `include_path` to restrict a directory walk to only specific file patterns, and `exclude_path` to drop paths from an otherwise-broad walk. When both match a file, exclusion wins. Neither flag affects explicitly named file arguments or archive entries — use `archive_filters` for archive entry filtering.

```json
{
  "tool": "sanitize",
  "files": ["/repo/logs/"],
  "include_path": ["**/*.log", "**/*.conf"],
  "exclude_path": ["tests/fixtures/", "vendor/"],
  "hidden": true
}
```

```json
{
  "tool": "scan",
  "files": ["/etc/"],
  "include_path": ["**/*.conf", "**/*.yaml"],
  "exclude_path": ["**/default/"]
}
```

`hidden` walks dot-files and dot-directories that would otherwise be skipped.

### Strip config values (reveal structure only)

`strip_config_values` removes all values from a key=value config file, leaving keys, comments, and structure. Useful for sharing config layout without exposing secrets. Accepts inline `content` or `files`.

```json
{
  "tool": "strip_config_values",
  "files": ["/etc/gitlab/gitlab.rb"]
}
```

```json
{
  "tool": "strip_config_values",
  "content": "REDIS_URL=redis://user:pass@cache.internal:6379/0\nDEBUG=false",
  "delimiter": "="
}
```

For colon-delimited formats (nginx, some `.conf` files):

```json
{
  "tool": "strip_config_values",
  "files": ["nginx.conf"],
  "delimiter": " ",
  "comment_prefix": "#"
}
```

### Test allowlist patterns

Verify that allowlist patterns match the intended values before committing to a full run. Patterns support three forms:

- **Exact string** — `"localhost"` matches only that literal value (case-insensitive).
- **Glob** — `"*.internal"` matches any hostname ending with `.internal`. `*` does not cross `/`.
- **Regex** — `"regex:^10\\.[0-9]+"` matches using a full regular expression. Prefix the pattern with `regex:`.

```json
{
  "tool": "test_allowlist",
  "patterns": ["*.internal", "192.168.1.*", "localhost", "regex:^10\\.[0-9]+\\.[0-9]+\\.[0-9]+$"],
  "values": ["db.internal", "192.168.1.50", "10.0.4.1", "api.example.com", "localhost"]
}
```

Returns a per-value result showing which pattern matched (or none), plus a summary count.

### Test patterns before sanitizing

`test_pattern` checks which values would be matched by a secrets file, app bundle, or inline patterns — without processing any files.

```json
{
  "tool": "test_pattern",
  "values": ["glpat-abc123xyz", "AKIA1234567890ABCDEF", "safe-value"],
  "app": ["gitlab"]
}
```

Returns a per-value result showing which pattern matched and what replacement category applies.

### Build a tailored secrets file

After scanning and spotting what the default patterns missed, use `build_secrets` to create a targeted secrets file for those gaps. Typical workflow:

1. `scan` with no secrets file to see what the built-in patterns catch
2. Identify patterns that weren't matched
3. `build_secrets` to write a file covering those gaps
4. `sanitize` with the new `secrets_file`

```json
{
  "tool": "build_secrets",
  "output_path": "patterns.yaml",
  "preset": "generic",
  "entries": [
    { "label": "gitlab_token", "pattern": "glpat-[A-Za-z0-9_-]{20}", "kind": "regex", "category": "auth_token" },
    { "label": "internal_db_host", "pattern": "db.internal.corp", "kind": "literal", "category": "hostname" }
  ]
}
```

Omit `preset` to create a file with only the entries you specify. Returns the written file content.

### Create a starter secrets file

`init` writes a ready-to-use secrets YAML to disk and returns its contents for immediate review and customization.

```json
{ "tool": "init", "output_path": "patterns.yaml", "preset": "web" }
```

Available presets: `generic` (default), `web`, `k8s`, `database`, `aws`. Pass `overwrite: true` to replace an existing file. Once created, pass the path via `secrets_file` on subsequent `sanitize` or `scan` calls.

---

## Namespace-Based Secrets (Multi-Tenant / MSP)

Set `SANITIZE_SECRETS_DIR` to a directory and create one subdirectory per customer or software type:

```
/var/sanitize/secrets/
  acme-corp/
    secrets.yaml        # or secrets.yaml.enc
    profile.yaml        # optional structured-field profile
    .password           # required if encrypted; must be chmod 0600
  widgets-inc/
    secrets.yaml.enc
    .password
```

Pass `namespace` in `sanitize` or `scan` tool calls. The server loads only that namespace's secrets, profile, and password — keeping pattern sets isolated across tenants.

```json
{
  "tool": "sanitize",
  "files": ["/var/log/acme/server.log"],
  "namespace": "acme-corp"
}
```

```json
{
  "tool": "scan",
  "files": ["report.json"],
  "namespace": "widgets-inc",
  "fail_on_match": true
}
```

An explicit `profile` parameter overrides the namespace's `profile.yaml` when both are present.

