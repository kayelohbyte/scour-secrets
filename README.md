# rust-sanitize

[![CI](https://github.com/kayelohbyte/rust-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/kayelohbyte/rust-sanitize/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/rust-sanitize.svg)](https://crates.io/crates/rust-sanitize)
[![docs.rs](https://docs.rs/rust-sanitize/badge.svg)](https://docs.rs/rust-sanitize)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rust-1.74%2B-blue.svg)]()

Scrub sensitive data from logs and configs before sharing them — with support teams, vendors, or AI tools.

`rust-sanitize` replaces API keys, emails, IPs, passwords, tokens, and other secrets with structurally plausible substitutes. Replacements are **one-way**: no mapping file is stored, there's no restore mode, and nothing sensitive persists after the run.

Works as a **CLI**, a **Rust library**, and an **MCP server** — so AI assistants like Claude and Cursor can sanitize files on your behalf before raw content ever reaches the model.

---

## MCP: Clean Before the LLM Sees It

Install the MCP server and your AI assistant can sanitize files directly — secrets stay inside the audited Rust process and never enter the context window.

**Claude Code:**

```bash
claude mcp add rust-sanitize /usr/local/bin/sanitize-mcp \
  -e SANITIZE_BIN=/usr/local/bin/sanitize
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "rust-sanitize": {
      "command": "/usr/local/bin/sanitize-mcp",
      "env": { "SANITIZE_BIN": "/usr/local/bin/sanitize" }
    }
  }
}
```

Once connected, the assistant can sanitize inline text or files, scan for leaks without modifying anything, or produce a pre-structured prompt ready for incident triage or config review. See [docs/mcp.md](docs/mcp.md) for the full tool reference, all parameter examples, and setup instructions for Cursor, Neovim, and OpenCode.

---

## Install

**CLI from crates.io:**

```bash
cargo install rust-sanitize
```

**From source:**

```bash
git clone https://github.com/kayelohbyte/rust-sanitize.git
cd rust-sanitize
cargo build --release
# Binary: target/release/sanitize
```

> **Windows:** Requires the MSVC linker. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and select the **Desktop development with C++** workload.

**As a Rust library:**

```bash
cargo add rust-sanitize
```

**MCP binary:** Download `sanitize-mcp` for your platform from the [Releases](https://github.com/kayelohbyte/rust-sanitize/releases) page — no Deno or Node required, the runtime is embedded.

---

## Quick Start

### No setup — scan immediately

When you run `sanitize` with no secrets file or app bundle, the built-in patterns activate automatically. They cover the most common secrets: API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, and more), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM headers, credential URLs, and password/secret key=value pairs.

```bash
sanitize server.log
```

Output goes to `server-sanitized.log` next to the source. Use `-o /path/to/output` to override, or `-o -` for stdout.

```bash
# Dry-run — see what would be replaced without writing anything:
sanitize server.log -n

# CI gate — fail if secrets are detected:
sanitize config.yaml --fail-on-match
```

### Guided setup — answer a few questions, get a tailored config

```bash
sanitize guided
```

The wizard asks for your workspace type (Generic, Web app, Kubernetes, Database, AWS), replacement strictness, company domains, and which file formats to cover. It produces two files:

- `secrets.guided.yaml` — your pattern set, optionally encrypted
- `secrets.guided.profile.yaml` — structured field rules for the formats you chose

```bash
sanitize server.log config.yaml \
  -s secrets.guided.yaml \
  --profile secrets.guided.profile.yaml
```

Aggressive strictness also matches broad hostnames, short container IDs, and high-entropy token patterns — recommended when sharing logs with an LLM.

### App bundles — zero config for common applications

Built-in bundles for 22 applications pair a secrets pattern set with a structured field profile so field-level sanitization works out of the box, no authoring required.

```bash
sanitize /etc/gitlab/gitlab.rb --app gitlab
sanitize nginx.conf docker-compose.yml --app nginx,docker-compose
sanitize values.yaml --app kubernetes

# See all available bundles:
sanitize apps
```

Built-in bundles: `ansible`, `aws-cli`, `circleci`, `django`, `docker-compose`, `elasticsearch`, `fstab`, `github-actions`, `gitlab`, `grafana`, `heroku`, `kubernetes`, `laravel`, `mongodb`, `mysql`, `nginx`, `postgresql`, `rails`, `redis`, `splunk`, `spring-boot`, `terraform`.

---

## Common Workflows

### Multiple files and archives in one pass

```bash
sanitize server.log config.yaml backup.zip -s patterns.yaml
# Produces: server-sanitized.log  config-sanitized.yaml  backup.sanitized.zip

# Send all outputs to a directory:
sanitize server.log config.yaml backup.zip -s patterns.yaml -o /tmp/clean/
```

### Pipe from another command

Stdin is sanitized and sent to stdout automatically.

```bash
grep "error" server.log | sanitize -s patterns.yaml
mysqldump mydb | sanitize | gzip > dump.sql.gz

# Mix stdin with file inputs (stdin → stdout; files → per-file siblings):
cat extra.log | sanitize - config.yaml -s patterns.yaml
```

When reading from stdin and the format can't be inferred from a filename, use `-f` to specify it: `-f yaml`, `-f json`, `-f csv`, `-f log`, etc.

### CI secrets gate

```bash
# Fail the build if secrets are detected:
sanitize config.yaml -s patterns.yaml --fail-on-match

# Same with encrypted patterns file:
SANITIZE_PASSWORD="..." sanitize config.yaml -s patterns.enc --encrypted-secrets --fail-on-match

# Stream per-match findings as NDJSON for jq or SIEM ingest:
sanitize server.log -s patterns.yaml --dry-run --findings | \
  jq 'select(.type=="file") | .pattern_counts'
```

### Archive entry filtering

Filter which entries inside an archive are processed. `*` matches within a single directory segment, `**` crosses directory boundaries, trailing `/` matches a subtree.

```bash
# Keep only the config directory:
sanitize backup.zip --only 'config/' -s patterns.yaml

# Keep all JSON, drop the secrets file:
sanitize backup.zip --only '**/*.json' --exclude config/secrets.json -s patterns.yaml

# Independent filters per archive in one command:
sanitize a.zip --only 'config/' b.tar.gz --only '**/*.log' -s patterns.yaml
```

### Structured field rules (`--profile`)

Replace specific named fields in YAML, JSON, TOML, CSV, `.env`, and INI files. Comments, indentation, key ordering, and unmatched values are preserved exactly.

```yaml
# fields.yaml
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
    - pattern: "*.ip"
      category: ipv4
```

```bash
sanitize config.yaml server.log --profile fields.yaml -s patterns.yaml
```

When `--profile` is active, values discovered in structured fields are automatically written back to the patterns file as literals so the streaming scanner can match them in other files too. See [Structured Processing](docs/structured-processing.md) for the full field pattern syntax and two-phase pipeline.

### Encrypted patterns file

```bash
# Encrypt once:
sanitize encrypt patterns.yaml patterns.yaml.enc --password

# Use interactively:
sanitize data.log -s patterns.enc --encrypted-secrets -p

# Non-interactive (CI / pipes):
SANITIZE_PASSWORD="my-password" sanitize data.log -s patterns.enc --encrypted-secrets
# Or read from a file:
sanitize data.log -s patterns.enc --encrypted-secrets -P /run/secrets/pw
```

### Allowlist — pass specific values through unchanged

```bash
sanitize data.log -s patterns.yaml --allow localhost --allow "*.internal" --allow "192.168.1.*"
```

For project-stable allowlists, add `kind: allow` entries directly to your patterns file:

```yaml
- pattern: "*.internal"
  kind: allow
- pattern: "192.168.1.*"
  kind: allow
```

### Deterministic mode

Same seed + same input produces identical replacements across runs and machines — useful when correlating sanitized data across multiple files or sharing a reproducible dataset with a team.

```bash
sanitize data.csv -s patterns.yaml -d
```

### Shannon entropy detection

Catch high-entropy tokens not covered by any pattern — useful for novel API keys, obfuscated secrets, or anything that wasn't anticipated when the patterns file was written.

```bash
sanitize server.log -s patterns.yaml --entropy-threshold 4.5

# Dry-run prints a calibration histogram to help tune the threshold:
sanitize server.log -s patterns.yaml -n --entropy-threshold 4.5
```

### LLM-ready output

Sanitize and produce a structured prompt in one step:

```bash
sanitize server.log -s patterns.yaml --llm                  # incident triage
sanitize nginx.conf --app nginx --llm review-config         # configuration review
sanitize nginx.conf --app nginx --llm review-security       # security posture review
```

The prompt includes a `## Files Analyzed` manifest and embeds sanitized content inline (`<content>` blocks). For large file sets or agentic LLMs that can read files with their own tools, add `--output` to switch to **reference mode** — files are written to disk and the prompt lists their absolute paths instead:

```bash
sanitize logs/ -s patterns.yaml --llm review-security --output /tmp/sanitized/
```

---

## Supported Formats

| Format | Detection |
|--------|-----------|
| Plain text / log | Default fallback for all files |
| JSON | Profile match or `{`/`[` heuristic |
| NDJSON / JSON Lines | Profile match or multi-line `{` heuristic; streaming — bounded memory for GB-scale log files |
| YAML | Profile match or `---`/`- `/`: ` heuristic |
| TOML | Profile match or `[section]` heuristic |
| XML | Profile match or `<?xml`/`<` heuristic |
| CSV / TSV | Profile match only |
| `.env` | Profile match only |
| INI / `.conf` | Profile match only |
| Key-value | Profile match only |
| Log lines (mixed) | Profile match only |
| Tar | `.tar` extension |
| Tar.gz / .tgz | `.tar.gz` / `.tgz` extension |
| Zip | `.zip` extension |

---

## Library

```bash
cargo add rust-sanitize
```

```rust
use rust_sanitize::category::Category;
use rust_sanitize::generator::HmacGenerator;
use rust_sanitize::store::MappingStore;
use std::sync::Arc;

// Deterministic generator seeded with a fixed 32-byte key.
let generator = Arc::new(HmacGenerator::new([42u8; 32]));
let store = MappingStore::new(generator, None);

// One-way replacement.
let sanitized = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
assert!(sanitized.contains("@corp.com"));
assert_eq!(sanitized.len(), "alice@corp.com".len());

// Same input → same output within a run.
let again = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
assert_eq!(sanitized, again);
```

See [Library API Reference](docs/api-reference.md) for the full module-by-module API.

---

## Security Model

Replacements are one-way by design. No reverse mapping is stored or recoverable from sanitized output alone. The `MappingStore` forward map lives only in process memory and is zeroized on drop.

Key properties:

- **Encryption at rest** — secrets files use AES-256-GCM (PBKDF2-HMAC-SHA256, 600 000 iterations). Plaintext files are also supported.
- **Zeroization** — HMAC keys, secret entries, mapping-store keys, and decrypted blobs are zeroized on drop.
- **Regex hardening** — per-pattern automaton and DFA size limits (1 MiB each) prevent ReDoS and unbounded memory growth.
- **Defensive limits** — input size caps, recursion depth limits, node-count caps, and pattern-count limits bound every parser.
- **Zero `unsafe`** — thread safety through `DashMap` and `Arc`; `Send + Sync` bounds verified at compile time.

See [SECURITY.md](SECURITY.md) for the full threat model and mitigations.

---

## Documentation

| Document | Description |
|----------|-------------|
| [MCP Reference](docs/mcp.md) | MCP server setup, all tool parameters, JSON examples, IDE configs (Cursor, Neovim, OpenCode), and namespace-based multi-tenant setup. |
| [CLI Reference](docs/cli-reference.md) | Full `sanitize` command reference including all flags, subcommands, secrets file format, and examples. |
| [Structured Processing](docs/structured-processing.md) | `--profile` usage, field patterns, two-phase pipeline, format preservation, and processor options. |
| [Supported Categories](docs/categories.md) | All 18 built-in replacement categories with strategies and examples, plus custom categories. |
| [Pluggable Strategies](docs/strategies.md) | The `Strategy` trait, 5 built-in strategies, and guide to writing custom strategies. |
| [Library API Reference](docs/api-reference.md) | Module-by-module public API tables. |
| [Defensive Limits & Streaming](docs/defensive-limits.md) | Streaming chunking model, archive processing flow, and all defensive size/depth/count limits. |
| [Architecture](ARCHITECTURE.md) | Internal architecture, data flow, module map, concurrency model, and streaming design. |
| [Security](SECURITY.md) | Security properties, threat mitigations, encryption details, and zeroization strategy. |
| [Contributing](CONTRIBUTING.md) | Build instructions, test suite, fuzz targets, linting, and PR guidelines. |
| [Changelog](CHANGELOG.md) | Release history and version notes. |

---

## Limitations

- **No restore.** Replacements are one-way by design. No undo, decrypt-output, or reverse-mapping capability.
- **Structured-to-scanner handoff.** When `--profile` is active, discovered values are appended to your secrets file as `kind: literal` entries so the scanner can find them in other files. Use `--no-structured-handoff` to suppress the write if needed.
- **Structured processor size limit.** Files over 256 MiB (or `--max-structured-size`) fall back to the streaming scanner, which replaces raw bytes without document awareness. In practice this only affects large serialized data dumps, not real config files.
- **Deterministic mode caveats.** Identical output requires the same secrets file and the same seed. Changing either produces completely different replacements.
- **Zeroization scope.** Covers secrets, HMAC keys, and mapping-store keys. Incidental copies the Rust compiler creates during optimization passes are not covered — an inherent limitation of safe Rust zeroization.
- **Large archive sequential fallback.** Zip and tar archives whose total uncompressed content exceeds 256 MiB are processed sequentially rather than in parallel to avoid unbounded memory use.
- **Binary detection.** Entries detected as binary are skipped by default. Use `--include-binary` to override.

---

## Security Disclosure

Do not open a public issue for security-sensitive findings. Report privately via a security advisory on the repository or via the maintainer contact in `Cargo.toml`. Include a description, reproduction steps, and potential impact. Maintainers will acknowledge within 5 business days and provide a fix or mitigation timeline within 30 days.

---

## Stability

This project follows [Semantic Versioning](https://semver.org/). As of 0.8.0, the public library API and CLI interface are considered stable. Breaking changes will be avoided but may occur in minor releases until 1.0.0. The MSRV is **1.74** (stable toolchain), declared under `rust-version` in `Cargo.toml` and enforced in CI.

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
