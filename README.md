# sanitize-engine

[![CI](https://github.com/kayelohbyte/rust-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/kayelohbyte/rust-sanitize/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sanitize-engine.svg)](https://crates.io/crates/sanitize-engine)
[![docs.rs](https://docs.rs/sanitize-engine/badge.svg)](https://docs.rs/sanitize-engine)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rust-1.74%2B-blue.svg)]()

Deterministic, one-way data sanitization engine and CLI tool.

`sanitize-engine` scans files and archives for sensitive data — emails, IP addresses, API keys, credentials, and other secrets — and replaces every match with a category-aware, structurally plausible substitute. Replacements are one-way within the system design: no reverse mapping is stored or recoverable from sanitized output alone. There is no restore mode.

## Intended Audience

- Security and compliance teams sanitizing production data for safe sharing.
- CI/CD pipelines that must fail when secrets leak into configuration or logs.
- Developers preparing realistic but non-sensitive test datasets.

## Core Differentiators

- **One-way only.** No mapping file, no restore mode. Forward map lives in process memory and is zeroized on drop.
- **Deterministic or random.** HMAC-SHA256 seeded mode produces identical replacements across runs; CSPRNG mode produces fresh replacements each run (still consistent within a single run via dedup cache).
- **Streaming architecture.** Processes 20–100 GB+ files in bounded memory via configurable chunk + overlap scanning.
- **Format-aware processing.** Structured processors for JSON, NDJSON/JSON Lines, YAML, TOML, XML, CSV, `.env`, INI, and key-value files replace only matched field values while preserving document structure exactly — comments, indentation, key ordering, and quoting style are all retained.
- **Archive support.** Tar, tar.gz, and zip archives are processed entry-by-entry with automatic format detection and metadata preservation.
- **Zero `unsafe` code.** The entire crate contains no `unsafe` blocks.

---

## Design Principles

1. **One-way only.** No reverse mappings, no restore mode. Security by elimination.
2. **Deterministic reproducibility.** Same seed + same input = same output, across machines and runs.
3. **Format-aware.** Replace values, not structure. JSON stays valid JSON; YAML stays valid YAML.
4. **Streaming-first.** Constant memory regardless of file size. Process 100 GB files on a 512 MB machine.
5. **Zero `unsafe`.** Thread safety through `DashMap` and `Arc`, not pointer arithmetic.
6. **Defence in depth.** Input size caps, regex automaton limits, depth limits, node-count caps — every parser has a budget.

---

## Quick Start

```bash
# 1. Create a profile to target specific fields in structured files:
cat > profile.yaml <<'EOF'
- processor: yaml
  extensions: [".yaml", ".yml"]
  fields:
    - pattern: "*.password"
      category: "custom:password"
    - pattern: "*.username"
      category: email

- processor: jsonl
  extensions: [".jsonl", ".ndjson", ".log"]
  options:
    skip_invalid: "true"   # pass non-JSON lines through unchanged
  fields:
    - pattern: "*.email"
      category: email
    - pattern: "*.user"
      category: name
    - pattern: "*.ip"
      category: ipv4
EOF

# 2. Create a secrets file (can be empty — sanitize populates it on the first run):
touch secrets.yaml

# 3. Sanitize a config file — only matched fields are replaced:
sanitize config.yaml --profile profile.yaml -s secrets.yaml
# Comments, indentation, and unmatched values are preserved exactly.
# NDJSON/log files are processed line-by-line in bounded memory (streaming).
# --secrets-file is required with --profile: values discovered in Phase 1 are
# written into it so the Phase 2 scanner can match them in logs and other files.

# 4. Second run (and beyond) — Phase 2 now catches those values everywhere:
sanitize config.yaml app.log --profile profile.yaml -s secrets.yaml
# Values found in config.yaml are replaced in app.log with the same substitutes.
```

### Quick Start — Secrets File (streaming scanner)

```bash
# 1. Create a plaintext secrets file (YAML is the canonical authoring format):
cat > secrets.yaml <<'EOF'
- pattern: "alice@corp\\.com"
  kind: regex
  category: email
  label: alice_email

- pattern: "sk-proj-abc123secret"
  kind: literal
  category: "custom:api_key"
  label: openai_key
EOF

# 2. Encrypt it (recommended for production):
sanitize encrypt secrets.yaml secrets.yaml.enc --password

# 3. Remove the plaintext:
rm secrets.yaml

# 4. Sanitize a file (output goes to data-sanitized.log next to the input):
sanitize data.log -s secrets.yaml.enc --encrypted-secrets --password

# 5. Sanitize multiple files at once:
sanitize data.log config.yaml backup.zip -s secrets.yaml.enc --encrypted-secrets --password
# Produces: data-sanitized.log  config-sanitized.yaml  backup.sanitized.zip

# 6. Send all sanitized files to a directory:
sanitize data.log config.yaml backup.zip -s secrets.yaml.enc --encrypted-secrets --password -o /tmp/clean/

# 7. Or write a single file to an explicit path:
sanitize data.log -s secrets.yaml.enc --encrypted-secrets --password -o output.log

# 8. Or write to stdout (use env var to avoid interactive prompt in scripts):
export SANITIZE_PASSWORD="my-password"
sanitize data.log -s secrets.yaml.enc --encrypted-secrets > output.log

# 9. CI gate — fail the build if secrets are detected:
SANITIZE_PASSWORD="my-password" sanitize config.yaml -s secrets.yaml.enc --encrypted-secrets --fail-on-match

# 10. Filter archive entries — keep only specific paths (--only / --exclude):
#     Patterns match the full stored path inside the archive.
#     * does not cross /, ** does. Trailing / is a directory-prefix match.
sanitize backup.zip --only 'config/' -s secrets.yaml
sanitize backup.zip --only '**/*.json' --exclude config/secrets.json -s secrets.yaml
sanitize test.zip --only test/test.config -s secrets.yaml

# 11. Per-archive filters in a single command:
sanitize a.zip --only 'config/' b.tar.gz --only '**/*.log' -s secrets.yaml

# 12. Mix stdin with file and archive inputs (stdin → stdout):
cat extra.log | sanitize - backup.zip --only 'logs/' config.yaml -s secrets.yaml
```

### Quick Start — Guided Setup

For a logs-focused starter template, run the interactive wizard:

```bash
sanitize guided
```

The wizard produces two files:

- **`secrets.guided.yaml`** — a streaming scanner config covering emails, IPs, UUIDs, API keys, tokens, PEM keys, and cloud provider identifiers. Encrypted to `secrets.guided.yaml.enc` if you choose to encrypt (plaintext is then removed automatically).
- **`secrets.guided.profile.yaml`** — structured field rules for the formats you select (YAML/JSON, NDJSON, `.env`, TOML, INI). Use this with `--profile` to replace specific fields by name rather than scanning raw bytes. Omitted if you choose `None` for formats.

```bash
# After the wizard finishes, run sanitize with both files:
sanitize app.log config.yaml -s secrets.guided.yaml.enc --encrypted-secrets --password --profile secrets.guided.profile.yaml
```

The **workspace type** controls which patterns are included:

| Workspace type | Extra coverage |
|----------------|----------------|
| Generic | Tokens, emails, IPs, UUIDs (default) |
| Web app | Session IDs, OAuth access/refresh tokens |
| Kubernetes | Service-account tokens, namespaces, container IDs, k8s `data.*`/`stringData.*` field rules |
| Database | Connection strings, DSNs, DB usernames |
| AWS | Like Generic but defaults to Aggressive strictness |

A second prompt sets the **replacement strictness** (`Balanced` or `Aggressive`). Aggressive additionally matches broad hostnames, short container IDs, and high-entropy token patterns — recommended when sharing logs with an LLM.

For a full step-by-step breakdown of prompts and the exact categories/patterns generated, see the `sanitize guided` section in [docs/cli-reference.md](docs/cli-reference.md).

### Quick Start — Built-in Patterns (`--use-default`, `--app`, `--allow`)

**`--use-default`** — scan without writing a secrets file. Covers the most common high-value secrets: API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, GitLab, SendGrid, npm), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM headers, password/secret key=value pairs, and credential URLs.

```bash
# No secrets file required:
sanitize data.log --use-default

# Dry-run to see what would be replaced:
sanitize data.log --use-default -n

# Fail CI if anything is detected:
sanitize config.yaml --use-default --fail-on-match
```

`--use-default` is additive with `--secrets-file`, `--app`, and `--profile` — combine them to extend the built-in patterns with your own.

**`--app`** — load a built-in bundle for a specific application. Each bundle provides both a secrets pattern set and a structured field profile so field-level sanitization works out of the box.

Run `sanitize apps` (or the `list_apps` MCP tool) to see all available bundles. Built-in bundles include: `ansible`, `aws-cli`, `circleci`, `django`, `docker-compose`, `elasticsearch`, `fstab`, `github-actions`, `gitlab`, `grafana`, `heroku`, `kubernetes`, `laravel`, `mongodb`, `mysql`, `nginx`, `postgresql`, `rails`, `redis`, `splunk`, `spring-boot`, `terraform`.

```bash
# List available bundles (built-in and user-defined):
sanitize apps

# Sanitize a GitLab config file using the gitlab bundle:
sanitize /etc/gitlab/gitlab.rb --app gitlab

# Sanitize nginx virtual host configs:
sanitize /etc/nginx/sites-enabled/ --app nginx

# Combine multiple bundles in one run:
sanitize gitlab.rb nginx.conf --app gitlab,nginx

# Add a custom secrets file on top of an app bundle:
sanitize gitlab.rb --app gitlab -s extra-secrets.yaml
```

**Installing custom app bundles** — add your own bundles with `sanitize apps add`:

```bash
# Install from a profile and a secrets file:
sanitize apps add elastic \
  --profile elastic.profile.yaml \
  --secrets elastic.secrets.yaml

# Use it immediately:
sanitize app.log --app elastic

# Show where bundles are stored:
sanitize apps dir

# Remove a custom bundle:
sanitize apps remove elastic --yes
```

The first `# comment` line of either YAML file becomes the description shown in `sanitize apps`. User-defined bundles take precedence over built-ins with the same name, so you can also override a built-in by installing a custom bundle under the same name.

**`--allow`** — suppress specific values from replacement. Allowed values pass through unchanged and are not recorded in the mapping store, so they will not propagate to other files in the same run.

```bash
# Exact match — never replace "localhost":
sanitize data.log -s secrets.yaml --allow localhost

# Glob — pass through all .internal hostnames:
sanitize data.log -s secrets.yaml --allow "*.internal"

# Multiple patterns:
sanitize data.log -s secrets.yaml \
  --allow localhost \
  --allow "*.internal" \
  --allow "192.168.1.*"
```

For project-stable allowlist entries, add them directly to your secrets file using `kind: allow`:

```yaml
# secrets.yaml
- pattern: "*.internal"
  kind: allow

- pattern: "192.168.1.*"
  kind: allow

- pattern: "alice@corp\\.com"
  kind: regex
  category: email
  label: alice_email
```

### Quick Start — Stdin Pipes

When reading from stdin (no file arguments, or explicit `-` marker), sanitized
output goes to **stdout** automatically. File inputs produce a
`<stem>-sanitized.<ext>` sibling file. Directory inputs produce a
`<dirname>-sanitized/` peer directory with the tree structure preserved. Use
`-o` to override any of these defaults.

```bash
# Pipe from grep → sanitized output on stdout:
grep "error" app.log | sanitize -s secrets.yaml

# Pipe from grep with an encrypted secrets file (use env var since stdin is a pipe):
export SANITIZE_PASSWORD="my-password"
grep "error" app.log | sanitize -s secrets.enc --encrypted-secrets

# Read from stdin, write sanitized output to a file (plaintext secrets):
# -f is required when the format cannot be inferred from a filename.
cat data.csv | sanitize -s secrets.yaml -f csv -o clean.csv

# Explicit stdout for a file input (-o with no PATH, or -o -):
sanitize data.log -s secrets.yaml -o -
sanitize data.log -s secrets.yaml --output -

# Chain with other tools (stdin → stdout → gzip):
mysqldump mydb | sanitize -s secrets.yaml | gzip > dump.sql.gz

# Mix stdin with file and archive inputs:
# stdin → stdout; file inputs → per-file <stem>-sanitized.<ext> siblings.
cat extra.log | sanitize - backup.zip config.yaml -s secrets.yaml
```

> **Format detection with stdin**: when the format cannot be inferred from a
> filename (because there is none), use `-f`/`--format` to specify it:
> `-f yaml`, `-f json`, `-f csv`, `-f log`, etc. Without `-f`, the scanner
> falls back to byte-level pattern matching only (no structured field rules).

### Quick Start — Archive Entry Filtering (`--only` / `--exclude`)

Filter which entries are written into the output archive. Patterns match the **full stored path** inside the archive (e.g. `test/test.config`, not just `test.config`).

- `*` matches within a single directory segment (does **not** cross `/`).
- `**` matches across directory boundaries.
- A pattern ending with `/` is a directory-prefix match.

```bash
# Keep only a specific file (use the full stored path):
sanitize test.zip --only test/test.config -s secrets.yaml

# Keep all JSON files at any depth:
sanitize backup.zip --only '**/*.json' -s secrets.yaml

# Keep an entire directory subtree:
sanitize backup.zip --only 'config/' -s secrets.yaml

# Drop all log files:
sanitize backup.zip --exclude '**/*.log' -s secrets.yaml

# Combine: keep JSON, then drop the secrets file:
sanitize backup.zip --only '**/*.json' --exclude config/secrets.json -s secrets.yaml

# Independent filters per archive in one command:
sanitize a.zip --only 'config/' b.tar.gz --only '**/*.log' -s secrets.yaml
```

Directory entries always pass through regardless of any filter. Nested archives inherit their parent's filter.

For full pattern syntax and rules see [docs/cli-reference.md — Archive Entry Filtering](docs/cli-reference.md#archive-entry-filtering----only----exclude).

### Quick Start — Plaintext Secrets (default)

Plaintext secrets files are the default. No password or `SANITIZE_PASSWORD` env var is needed:

```bash
# Use a plaintext YAML secrets file (canonical):
sanitize data.log -s secrets.yaml

# Deterministic mode works the same way:
sanitize data.csv -s secrets.yaml -d
```

JSON and TOML secrets files remain fully supported. YAML is the recommended default for human authoring.

### Quick Start — Encrypted Secrets (opt-in)

Encryption is optional. Use `--encrypted-secrets` to decrypt an AES-256-GCM file:

```bash
# Prompt for password interactively:
sanitize data.log -s secrets.enc --encrypted-secrets -p

# Or provide via file (CI-friendly):
sanitize data.log -s secrets.enc --encrypted-secrets -P /run/secrets/pw
```

### Redaction Summary

After every successful run, `sanitize` prints a one-line summary to `stderr` showing what was redacted:

```
Redacted: 4 email, 2 ipv4, 1 auth_token
```

If nothing matched: `Redacted: nothing`. Counts are sorted by frequency. In `sanitize scan` (dry-run) mode the label reads `Matched:` instead. The summary appears in all contexts — TTY, CI, and non-TTY pipelines alike. Suppress it with `--quiet` when only the exit code matters.

### Entropy Calibration Histogram

When `--entropy-threshold` is active in dry-run / `sanitize scan` mode, `sanitize` also prints a calibration histogram to stderr showing how many candidate tokens fall at each entropy level. This helps tune the threshold before a full run:

```
Entropy calibration — alphanumeric (20–200 chars):
  ≥3.0 bits      45
  ≥3.5 bits      23
  ≥4.0 bits      12
  ≥4.5 bits       3  ← threshold
  ≥5.0 bits       1
  ≥5.5 bits       0
  3 candidates examined
```

Only counts are printed — no token values are ever shown.

### Startup Config Summary

When running interactively (TTY or `--progress on`), `sanitize` prints a one-line-per-setting summary of the resolved configuration to stderr before processing begins:

```
  secrets:  /home/user/.config/sanitize/secrets.yaml
  profile:  /repo/.sanitize/k8s-profile.yaml  [config]
  apps:     k8s, database  [config]
  flags:    --strict  [config]
```

Settings that came from `settings.yaml` or `.sanitize.toml` rather than the command line are annotated with `[config]`. Silent in pipe/script contexts (auto+non-TTY). Use `sanitize show-config` for the full effective configuration at any time.

---

## Installation

### From crates.io

```bash
cargo install sanitize-engine
```

### From source

```bash
git clone https://github.com/kayelohbyte/rust-sanitize.git
cd rust-sanitize
cargo build --release
```

Binaries are placed at `target/release/sanitize`.

> **Windows:** Building from source requires the MSVC linker. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and select the **Desktop development with C++** workload before running `cargo build`.

### As a library

```bash
cargo add sanitize-engine
```

```rust
use sanitize_engine::category::Category;
use sanitize_engine::generator::HmacGenerator;
use sanitize_engine::store::MappingStore;
use std::sync::Arc;

// Create a deterministic generator with a fixed seed.
let generator = Arc::new(HmacGenerator::new([42u8; 32]));

// Create the replacement store (optional capacity limit).
let store = MappingStore::new(generator, None);

// Sanitize a value (one-way).
let sanitized = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
assert!(sanitized.contains("@corp.com"));
assert_eq!(sanitized.len(), "alice@corp.com".len());

// Same input → same output (per-run consistency).
let again = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
assert_eq!(sanitized, again);
```

### As an MCP server

The `sanitize-mcp` binary wraps the `sanitize` CLI as an MCP server. All sensitive data processing happens inside the audited Rust CLI — the MCP layer handles only protocol framing. This means files are sanitized **before** their contents enter the LLM context window.

Download the `sanitize-mcp` binary for your platform from the [Releases](https://github.com/kayelohbyte/rust-sanitize/releases) page (no Deno or Node required — the runtime is embedded).

**Claude Code:**

```bash
claude mcp add sanitize-engine /usr/local/bin/sanitize-mcp \
  -e SANITIZE_BIN=/usr/local/bin/sanitize
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sanitize-engine": {
      "command": "/usr/local/bin/sanitize-mcp",
      "env": {
        "SANITIZE_BIN": "/usr/local/bin/sanitize"
      }
    }
  }
}
```

**Run from source** with [Deno](https://deno.land) 2.x (no compile step):

```bash
SANITIZE_BIN=/usr/local/bin/sanitize \
  deno run --allow-run --allow-env --allow-read --allow-write \
  mcp/src/index.ts
```

#### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SANITIZE_BIN` | `sanitize` | Path to the `sanitize` binary |
| `SANITIZE_MCP_MAX_CONTENT_BYTES` | `524288` (512 KB) | Per-call inline content size limit |
| `SANITIZE_MCP_TIMEOUT_MS` | `60000` (60 s) | Subprocess timeout — kills the CLI and returns an error if exceeded |
| `SANITIZE_MCP_THREADS` | _(unset = CLI default = logical CPUs)_ | Worker thread cap for every invocation — useful on shared hosts |
| `SANITIZE_MCP_MAX_ARCHIVE_DEPTH` | `2` | Default max archive nesting depth (CLI default is 3; MCP default is lower to limit zip-bomb exposure) |
| `SANITIZE_SECRETS_DIR` | _(unset)_ | Root directory for per-namespace secrets. Each subdirectory is a namespace and may contain `secrets.yaml[.enc]`, `profile.yaml`, and an optional `.password` file (`0600`/`0400` permissions enforced). |

#### Available tools

| Tool | Description |
|------|-------------|
| `sanitize` | Sanitize inline text or files. Set `llm_template: 'troubleshoot'`, `'review-config'`, or `'review-security'` for a fully-formatted LLM prompt. |
| `scan` | Scan for secrets and return a report without modifying content. |
| `strip_config_values` | Strip values from key=value config files, preserving keys and structure. |
| `test_allowlist` | Test which values match a set of allowlist patterns. |
| `list_apps` | List all available app bundles (built-in + user-defined). |
| `init` | Create a starter secrets file on disk from a preset template and return its contents. |
| `build_secrets` | Build a tailored secrets file from specific patterns. The setup workflow: scan → identify gaps → build_secrets → sanitize. |
| `test_pattern` | Test which values are matched by a secrets file, app bundle, or inline patterns. Returns per-value match results. |

---

#### MCP examples

All examples show the JSON parameters passed to the relevant tool.

##### Sanitize inline content

Inline text is piped through the CLI via stdin — content never touches disk.

```json
{
  "tool": "sanitize",
  "content": "Error connecting to postgres://admin:hunter2@db.internal:5432/prod",
  "use_default": true
}
```

Returns the sanitized string. `use_default` enables the built-in pattern set covering API keys, emails, IPs, JWTs, UUIDs, and credential URLs with no secrets file required.

##### Sanitize files before the LLM reads them

Pass file paths via `files` — the CLI processes them directly and the raw content never enters the LLM context window.

```json
{
  "tool": "sanitize",
  "files": ["/etc/gitlab/gitlab.rb", "/var/log/gitlab/production_json.log"],
  "app": ["gitlab"]
}
```

Returns a `results` array — one entry per input file — each containing `input` (original path), `file` (output filename), and `content` (sanitized text).

##### Get a fully-formatted LLM prompt (the main workflow)

Set `llm_template` to skip raw sanitized text and get a structured prompt ready to paste directly into a conversation. This is the fastest path from raw logs/configs to actionable LLM analysis.

```json
{
  "tool": "sanitize",
  "files": ["/var/log/app.log"],
  "use_default": true,
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

Combine with `extract_context` to have notable error/warning events surfaced and highlighted inside the prompt:

```json
{
  "tool": "sanitize",
  "files": ["app.log"],
  "use_default": true,
  "llm_template": "troubleshoot",
  "extract_context": true,
  "context_lines": 15,
  "context_keywords": ["timeout", "oomkilled", "segfault"]
}
```

##### Multiple files with a secrets file

```json
{
  "tool": "sanitize",
  "files": ["app.log", "config.yaml", "backup.zip"],
  "secrets_file": "secrets.yaml",
  "profile": "profile.yaml"
}
```

Archives are extracted, sanitized entry-by-entry, and re-packaged. Archive results carry `binary: true` and `size` instead of inline `content`.

##### Archive entry filtering

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
  ],
  "use_default": true
}
```

Patterns follow the same rules as the CLI: `*` does not cross `/`, `**` does, trailing `/` is a directory-prefix match.

##### Scan for secrets (audit without modifying)

Returns a structured JSON report of what would be replaced — nothing is written.

```json
{
  "tool": "scan",
  "files": ["config.yaml"],
  "app": ["gitlab"],
  "use_default": true
}
```

##### Security gate — fail if secrets are detected

`fail_on_match` adds a `secrets_detected` boolean to the response. Agents can branch on it without parsing the full report.

```json
{
  "tool": "scan",
  "files": ["terraform.tfvars"],
  "use_default": true,
  "fail_on_match": true
}
```

Returns `{ "secrets_detected": true, "report": { ... } }` if secrets are found, `{ "secrets_detected": false, "report": { ... } }` otherwise.

##### App bundles

App bundles pair a secrets pattern set with a structured field profile for a specific application. Pass one or more bundle names to `app`.

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

Use `list_apps` to discover all available bundle names including any user-defined bundles:

```json
{ "tool": "list_apps" }
```

##### Extract context (error/warning snippets)

`extract_context` scans the sanitized output for error/warning keywords and returns a structured context report alongside the sanitized content. Requires `extract_context: true` on the `sanitize` tool.

```json
{
  "tool": "sanitize",
  "content": "...",
  "use_default": true,
  "extract_context": true,
  "context_lines": 10,
  "context_keywords": ["timeout", "connection refused"],
  "max_context_matches": 100
}
```

Response becomes `{ content, report }`. `report` contains per-file match lists with surrounding lines.

To use an entirely custom keyword set (replacing the built-in defaults), add `context_keywords_replace: true`:

```json
{
  "tool": "sanitize",
  "files": ["app.log"],
  "use_default": true,
  "extract_context": true,
  "context_keywords": ["FATAL", "OOM"],
  "context_keywords_replace": true
}
```

##### Deterministic replacements

Supply a `seed` for HMAC-deterministic mode. Identical seed + identical input → identical replacements across calls and sessions.

```json
{
  "tool": "sanitize",
  "content": "alice@corp.com logged in from 10.0.1.5",
  "use_default": true,
  "seed": "session-2024-incident-42"
}
```

Use the same `seed` in follow-up calls to get consistent replacements when correlating sanitized data across multiple files.

##### Inline patterns (no secrets file)

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

##### Force streaming scan (bypass structured processors)

`force_text` skips all structured processors (JSON, YAML, etc.) and runs only the byte-level streaming scanner. Use when the format is ambiguous or when guaranteed full-byte coverage is required regardless of field rules.

```json
{
  "tool": "sanitize",
  "files": ["unknown-format.dat"],
  "use_default": true,
  "force_text": true
}
```

##### Binary entries in archives

By default, binary entries inside archives are skipped. Set `include_binary: true` to process them.

```json
{
  "tool": "sanitize",
  "files": ["mixed-content.zip"],
  "use_default": true,
  "include_binary": true
}
```

##### Archive depth limit

Override the server-wide archive depth default on a per-call basis. Useful for known-safe deeply nested archives.

```json
{
  "tool": "sanitize",
  "files": ["nested.tar.gz"],
  "use_default": true,
  "max_archive_depth": 4
}
```

The MCP server default is `2` (lower than the CLI's `3`). Override the server default for all calls via the `SANITIZE_MCP_MAX_ARCHIVE_DEPTH` environment variable.

##### Namespace-based secrets (multi-tenant / MSP)

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
  "files": ["/var/log/acme/app.log"],
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

##### Strip config values (reveal structure only)

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

##### Test allowlist patterns

Verify that glob patterns match the intended values before committing to a full run.

```json
{
  "tool": "test_allowlist",
  "patterns": ["*.internal", "192.168.1.*", "localhost"],
  "values": ["db.internal", "192.168.1.50", "api.example.com", "localhost"]
}
```

Returns a per-value result showing which pattern matched (or none), plus a summary count.

##### Test patterns before sanitizing

`test_pattern` checks which values would be matched by a secrets file, app bundle, or inline patterns — without processing any files.

```json
{
  "tool": "test_pattern",
  "values": ["glpat-abc123xyz", "AKIA1234567890ABCDEF", "safe-value"],
  "app": ["gitlab"]
}
```

Returns a per-value result showing which pattern matched and what replacement category applies. Exit code 1 (some values unmatched) is treated as informational — the JSON result is always returned.

##### Build a tailored secrets file

After scanning content and spotting what the default patterns missed, use `build_secrets` to create a targeted secrets file for those specific values. The workflow:

1. `scan` with `use_default: true` to see what's already caught
2. Identify patterns that weren't matched (specific tokens, internal hostnames, etc.)
3. `build_secrets` to write a file covering those gaps
4. `sanitize` with the new `secrets_file`

```json
{
  "tool": "build_secrets",
  "output_path": "secrets.yaml",
  "preset": "generic",
  "entries": [
    { "label": "gitlab_token", "pattern": "glpat-[A-Za-z0-9_-]{20}", "kind": "regex", "category": "auth_token" },
    { "label": "internal_db_host", "pattern": "db.internal.corp", "kind": "literal", "category": "hostname" }
  ]
}
```

Omit `preset` to create a file with only the entries you specify. Returns the written file content.

##### Shannon entropy detection

Add `entropy_threshold` to the sanitize tool to catch high-entropy tokens beyond pattern matching:

```json
{
  "tool": "sanitize",
  "files": ["app.log"],
  "use_default": true,
  "entropy_threshold": 4.5
}
```

Tokens of 20–200 alphanumeric characters whose Shannon entropy exceeds the threshold (bits per character) are treated as secrets. Typical secrets sit above 4.5; random UUIDs sit around 3.8. Supplements pattern matching — catches high-entropy tokens not covered by your secrets file.

##### Path exclusions and hidden files

```json
{
  "tool": "sanitize",
  "files": ["/repo/logs/"],
  "use_default": true,
  "exclude_path": ["tests/fixtures/", "vendor/", "**/*.generated.*"],
  "hidden": true
}
```

`exclude_path` excludes paths matching glob patterns (trailing `/` prunes entire subtrees). `include_path` restricts the walk to only files matching those patterns — when both match, exclusion wins. `hidden` walks dot-files and dot-directories that would otherwise be skipped.

##### Create a starter secrets file

`init` writes a ready-to-use secrets YAML to disk and returns its contents so you can review and customise it immediately.

```json
{ "tool": "init", "output_path": "secrets.yaml", "preset": "web" }
```

Available presets: `generic` (default), `web`, `k8s`, `database`, `aws`. Pass `overwrite: true` to replace an existing file. Once created, pass the path via `secrets_file` on subsequent `sanitize` or `scan` calls.

#### IDE & editor setup

All configurations assume `sanitize-mcp` is at `/usr/local/bin/sanitize-mcp` and `sanitize` is at `/usr/local/bin/sanitize`. Adjust paths to match your installation.

##### Claude Code (CLI / VS Code extension)

Add at **project scope** (writes `.mcp.json` in the repo root, checked into version control):

```bash
claude mcp add --scope project sanitize-engine /usr/local/bin/sanitize-mcp \
  -e SANITIZE_BIN=/usr/local/bin/sanitize
```

Add at **user scope** (available in all your projects):

```bash
claude mcp add --scope user sanitize-engine /usr/local/bin/sanitize-mcp \
  -e SANITIZE_BIN=/usr/local/bin/sanitize
```

Or write `.mcp.json` at the repo root manually:

```json
{
  "mcpServers": {
    "sanitize-engine": {
      "command": "/usr/local/bin/sanitize-mcp",
      "env": {
        "SANITIZE_BIN": "/usr/local/bin/sanitize"
      }
    }
  }
}
```

##### Cursor

**Project scope** — create `.cursor/mcp.json` in the repo root:

```json
{
  "mcpServers": {
    "sanitize-engine": {
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

##### Neovim

**mcphub.nvim** — add to `~/.config/mcphub/servers.json`:

```json
{
  "servers": {
    "sanitize-engine": {
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

##### OpenCode

**Project scope** — create `opencode.json` in the repo root:

```json
{
  "mcp": {
    "sanitize-engine": {
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

**Global scope** — same format at `~/.config/opencode/opencode.json`. Both files are merged, so project config layers on top of global config.

Use `{env:VAR}` syntax to forward existing shell variables into the server process.

---

### Requirements

- Rust 1.74 or later (stable toolchain)
- **Windows only:** [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **Desktop development with C++** workload (provides the MSVC linker required by the default `x86_64-pc-windows-msvc` target). VS Code alone is not sufficient. Alternatively, use the GNU toolchain target (`x86_64-pc-windows-gnu`) via MSYS2/MinGW-w64.

---

## Documentation

| Document | Description |
|----------|-------------|
| [CLI Reference](docs/cli-reference.md) | Full `sanitize` command reference (including `encrypt` and `decrypt` subcommands), secrets file format, and usage examples. |
| [Structured Processing](docs/structured-processing.md) | `--profile` usage, file-type profiles, field rules, include/exclude globs, two-phase pipeline, format preservation, deterministic discovery, and processor-specific options. |
| [Supported Categories](docs/categories.md) | All 18 built-in replacement categories with strategies and examples, plus custom categories. |
| [Pluggable Strategies](docs/strategies.md) | The `Strategy` trait, 5 built-in strategies, and guide to writing custom strategies. |
| [Library API Reference](docs/api-reference.md) | Module-by-module public API tables (scanner, store, generator, strategy, processor, archive, report, atomic, secrets, error, category). |
| [Defensive Limits & Streaming](docs/defensive-limits.md) | Streaming chunking model, archive processing flow, and all defensive size/depth/count limits. |
| [Architecture](ARCHITECTURE.md) | Internal architecture, data flow diagrams, module map, concurrency model, and streaming design. |
| [Security](SECURITY.md) | Security properties, threat mitigations, encryption details, zeroization strategy, and threat model. |
| [Contributing](CONTRIBUTING.md) | Build instructions, test suite, fuzz targets, linting, and PR guidelines. |
| [Changelog](CHANGELOG.md) | Release history and version notes. |

---

## Supported Formats

| Format | Processor | Detection |
|--------|-----------|-----------|
| Plain text | `StreamScanner` (chunk + overlap) | Default fallback for all files |
| JSON | `JsonProcessor` | Profile match or `{`/`[` heuristic |
| NDJSON / JSON Lines | `JsonLinesProcessor` | Profile match (`jsonl`) or multi-line `{` heuristic; **streaming** — processes GB-scale log files in bounded memory |
| YAML | `YamlProcessor` | Profile match or `---`/`- `/`: ` heuristic |
| TOML | `TomlProcessor` | Profile match or `[section]` heuristic |
| XML | `XmlProcessor` | Profile match or `<?xml`/`<` heuristic |
| CSV / TSV | `CsvProcessor` | Profile match only |
| `.env` | `EnvProcessor` | Profile match only |
| INI / `.conf` | `IniProcessor` | Profile match only |
| Key-value | `KeyValueProcessor` | Profile match only |
| Log lines (mixed) | `LogLineProcessor` | Profile match only |
| Tar | `ArchiveProcessor` | `.tar` extension |
| Tar.gz / .tgz | `ArchiveProcessor` | `.tar.gz` / `.tgz` extension |
| Zip | `ArchiveProcessor` | `.zip` extension |

---

## Security Model

Replacements are one-way within the system design. No reverse mapping is stored or recoverable from sanitized output alone. The `MappingStore` forward map lives only in process memory, is never persisted to disk, and is zeroized on drop. There is no restore or decrypt-output mode.

Key security properties:

- **Encryption at rest** — Secrets files are encrypted with AES-256-GCM (PBKDF2-HMAC-SHA256, 600 000 iterations). Plaintext secrets are also supported.
- **Zeroization** — HMAC keys, secret entries, mapping store keys, and decrypted blobs are zeroized on drop.
- **Regex hardening** — Per-pattern automaton and DFA size limits (1 MiB each) prevent ReDoS and unbounded memory.
- **Defensive limits** — Input size caps, recursion depth limits, node-count caps, and pattern count limits bound every parser.
- **Zero `unsafe`** — Thread safety through `DashMap` and `Arc`. `Send + Sync` bounds verified at compile time.

For the full security model, threat mitigations, and out-of-scope threats, see [SECURITY.md](SECURITY.md).

---

## Examples

**Sanitize a single file (output goes next to the source as `data-sanitized.log`):**

```bash
sanitize data.log -s secrets.enc --password
```

**Sanitize multiple files in one command:**

```bash
sanitize test.txt a.json backup.zip -s secrets.enc --password
# Produces: test-sanitized.txt  a-sanitized.json  backup.sanitized.zip
```

**Send all outputs to a directory:**

```bash
sanitize test.txt a.json backup.zip -s secrets.enc --password -o /tmp/clean/
```

**Write a single file to an explicit path:**

```bash
sanitize data.log -s secrets.enc --password -o output.log
```

**Pipe from another command (non-interactive; use env var or password-file):**

```bash
export SANITIZE_PASSWORD="my-password"
grep "error" app.log | sanitize -s secrets.enc
```

**Deterministic mode (same seed → same replacements every run):**

```bash
sanitize data.csv -s s.enc --password -d
```

**Fail CI if secrets are detected:**

```bash
sanitize config.yaml -s s.enc -P /run/secrets/pw --fail-on-match
```

**Stream per-match findings as NDJSON for CI integration:**

`--findings` emits one JSON object per file plus a summary line, suitable
for `jq` filtering, SIEM ingest, or counting leaks by pattern label.
Use an explicit path when sanitizing to stdout so the two streams don't mix:

```bash
# Write findings to a file, sanitized content to stdout:
sanitize app.log -s secrets.yaml --findings findings.ndjson

# Write findings to stdout only (dry-run or scan mode):
sanitize app.log -s secrets.yaml --dry-run --findings

# Count matches per pattern label in CI:
sanitize app.log -s secrets.yaml --dry-run --findings | \
  jq -r 'select(.type=="file") | .pattern_counts | to_entries[] | "\(.value)\t\(.key)"' | sort -rn
```

**Shannon entropy detection (catches high-entropy tokens beyond pattern matching):**

```bash
sanitize app.log -s secrets.yaml --entropy-threshold 4.5
sanitize ./configs/ -s secrets.yaml --entropy-threshold 4.0 --report report.json
```

**Exclude paths from a directory walk:**

```bash
sanitize ./logs/ -s secrets.yaml --exclude-path "tests/fixtures/"
sanitize . --app gitlab --exclude-path "vendor/" --exclude-path "**/*.generated.*"
```

**Only process specific file types in a directory:**

```bash
sanitize ./support-bundle/ -s secrets.yaml --include-path '*.log'
sanitize /etc/ -s secrets.yaml --include-path '**/*.conf' --include-path '**/*.yaml'

# Combine include and exclude — exclusion wins when both match:
sanitize ./logs/ -s secrets.yaml --include-path '*.log' --exclude-path "tests/"
```

**Directory expansion feedback** — before processing starts, a brief line is printed to stderr:

```
  14 files in /etc/nginx/ (3 excluded)
```

Suppressed in `--log-format json` mode (structured log event is emitted instead).

**Walk hidden files when scanning a directory:**

```bash
sanitize . -s secrets.yaml --hidden
sanitize . --app gitlab --hidden --exclude-path ".git/"
```

**Extract context from sanitized output (error/warning snippets for LLM sharing):**

```bash
sanitize app.log -s secrets.yaml --report report.json --extract-context
sanitize app.log -s secrets.yaml --report report.json --extract-context --context-lines 20
sanitize app.log -s secrets.yaml --report report.json --extract-context --max-context-matches 200
sanitize app.log -s secrets.yaml --report report.json --extract-context --context-keywords timeout,oomkilled --context-case-sensitive
```

**Generate an LLM-ready prompt (sanitized content + structured summary):**

```bash
# Built-in troubleshoot template (default — incident triage):
sanitize app.log -s secrets.yaml --llm

# Configuration review:
sanitize app.log -s secrets.yaml --llm review-config

# Security posture review:
sanitize nginx.conf --app nginx --llm review-security

# Custom template file:
sanitize app.log -s secrets.yaml --llm /path/to/prompt-template.txt

# Combine with --extract-context to include notable events:
sanitize app.log -s secrets.yaml --report /tmp/r.json --extract-context --llm troubleshoot
```

Built-in template text uses [caveman compression](https://github.com/wilpel/caveman-compression) to minimise instruction tokens (~45% reduction vs. natural prose) while preserving all semantic content.

**Strip values from a config file (reveal structure without exposing secrets):**

```bash
# Default key=value format (delimiter is =):
sanitize config.ini --strip-values -o config-stripped.ini

# Colon-delimited (YAML-style, nginx-style):
sanitize nginx.conf --strip-values --strip-delimiter : -o nginx-stripped.conf

# C-style comments (// prefix):
sanitize app.conf --strip-values --strip-comment-prefix // -o app-stripped.conf
```

See [docs/cli-reference.md](docs/cli-reference.md) for the complete set of examples including archive processing, stdin pipes, dry-run, plaintext secrets, and custom chunk sizes.

> **Security note:** `-p` / `--password` now triggers a secure interactive prompt (masked input, no shell history). For non-interactive automation use `-P` / `--password-file` or the `SANITIZE_PASSWORD` environment variable.

---

## Limitations

- **Structured-to-scanner handoff.** When `--profile` is active (which requires `--secrets-file`), values discovered in typed fields are automatically appended to that secrets file as `kind: literal` entries so the scanner pass can catch those same values in logs, comments, and unstructured text. This is intentional — disabling it weakens coverage. Pass `--no-structured-handoff` to suppress the write if needed. In CI pipelines, consider setting `no_structured_handoff: true` in `settings.yaml` or `.sanitize.toml`. For `--app` bundles that include a profile, the handoff only runs when `--secrets-file` is also provided explicitly.

- **No restore.** Replacements are one-way by design. There is no undo, decrypt-output, or reverse-mapping capability.
- **Deterministic mode caveats.** Deterministic replacements require the same secrets key and the same secret values to produce identical output. Changing the secrets file or key produces entirely different replacements.
- **Structured processor size limit.** Files exceeding 256 MiB (archive entries) or `--max-structured-size` (standalone files) fall back to the streaming scanner. The scanner performs byte-level regex replacement without document awareness — it may match inside JSON keys or XML tags rather than just field values. In practice this limit is never reached by real configuration files; it is only relevant for large data dumps or log files serialized as JSON, which are better handled by the scanner anyway.
- **Zeroization scope.** Zeroization covers secrets, HMAC keys, and mapping store keys. It does not cover incidental copies the Rust compiler may create (e.g. during optimization passes). This is an inherent limitation of safe Rust zeroization.
- **Large archive sequential fallback.** Zip and tar archives whose total uncompressed content exceeds 256 MiB are processed sequentially rather than in parallel to avoid holding the entire archive in memory. Output entry order is always deterministic regardless of thread count.
- **Binary detection.** Entries detected as binary are skipped by default. Use `--include-binary` to override.

---

## Security Disclosure

If you discover a security vulnerability in this project, please report it responsibly. Do not open a public issue for security-sensitive findings.

Contact the maintainers via the security contact configured in the repository. If no security contact is listed, open a private security advisory through the repository hosting platform or contact the maintainers directly via the email address in `Cargo.toml` or commit history.

Include:

- Description of the vulnerability.
- Steps to reproduce.
- Potential impact assessment.

Maintainers will acknowledge receipt within 5 business days and aim to provide a fix or mitigation timeline within 30 days.

---

## Stability

This project follows [Semantic Versioning](https://semver.org/). As of 0.8.0,
the public library API and CLI interface are considered stable. Breaking changes
will be avoided but may occur in minor releases until 1.0.0.

### What is stable

- **One-way replacement** — replacements are never reversed or exposed.
- **Deterministic mode** — same seed + same input → same output, across all
  1.x releases.
- **Length preservation** — all 18 built-in categories always produce output
  whose byte length matches the input.
- **Encrypted secrets format** — AES-256-GCM + PBKDF2 envelope; files
  encrypted with any 1.x release can be decrypted by any other 1.x release.
- **Public library API** — all types and functions re-exported from `lib.rs`
  (e.g. `Category`, `MappingStore`, `StreamScanner`, `HmacGenerator`).
- **CLI flags** — all flags documented in `sanitize --help` are stable.

### What may evolve in minor releases

- Internal processor heuristics (which files auto-detect as JSON/YAML/etc.).
- Default safety limit values (`DEFAULT_ARCHIVE_DEPTH`, chunk sizes, etc.).
- Report JSON schema (additive changes only — no existing fields removed).
- Tracing/log output format and verbosity.

### MSRV policy

The minimum supported Rust version is **1.74** (stable toolchain). It will
only be raised in a **minor** version bump (never in a patch), with at least
one release cycle of notice. The current MSRV is declared in `Cargo.toml`
under `rust-version` and is enforced in CI.

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
the full text.
