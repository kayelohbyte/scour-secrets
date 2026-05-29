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
  "max_archive_depth": 4
}
```

### Path exclusions and hidden files

```json
{
  "tool": "sanitize",
  "files": ["/repo/logs/"],
  "exclude_path": ["tests/fixtures/", "vendor/", "**/*.generated.*"],
  "hidden": true
}
```

`exclude_path` excludes paths matching glob patterns (trailing `/` prunes entire subtrees). `include_path` restricts the walk to only files matching those patterns — when both match, exclusion wins. `hidden` walks dot-files and dot-directories that would otherwise be skipped.

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

Verify that glob patterns match the intended values before committing to a full run.

```json
{
  "tool": "test_allowlist",
  "patterns": ["*.internal", "192.168.1.*", "localhost"],
  "values": ["db.internal", "192.168.1.50", "api.example.com", "localhost"]
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
