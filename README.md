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

# 2. Sanitize a config file — only matched fields are replaced:
sanitize config.yaml --profile profile.yaml
# Comments, indentation, and unmatched values are preserved exactly.
# NDJSON/log files are processed line-by-line in bounded memory (streaming).

# 3. Combine with a secrets file to also catch those values in logs:
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

### Quick Start — Built-in Patterns (`--default`, `--app`, `--allow`)

**`--default`** — scan without writing a secrets file. Covers the most common high-value secrets: API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, GitLab, SendGrid, npm), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM headers, password/secret key=value pairs, and credential URLs.

```bash
# No secrets file required:
sanitize data.log --default

# Dry-run to see what would be replaced:
sanitize data.log --default -n

# Fail CI if anything is detected:
sanitize config.yaml --default --fail-on-match
```

`--default` cannot be combined with `--secrets-file`. Use `--secrets-file` when you need custom patterns on top.

**`--app`** — load a built-in bundle for a specific application. Each bundle provides both a secrets pattern set and a structured field profile so field-level sanitization works out of the box.

Built-in bundles: `docker-compose`, `django`, `gitlab`, `kubernetes`, `nginx`, `postgresql`, `rails`, `spring-boot`.

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

You can pipe data directly into `sanitize`:

```bash
# Pipe from grep with a plaintext secrets file:
grep "error" app.log | sanitize -s secrets.yaml

# Pipe from grep with an encrypted secrets file (use env var since stdin is a pipe):
export SANITIZE_PASSWORD="my-password"
grep "error" app.log | sanitize -s secrets.enc --encrypted-secrets

# Read from stdin, write sanitized output to a file (plaintext secrets):
cat data.csv | sanitize -s secrets.yaml -f csv -o clean.csv

# Chain with other tools:
mysqldump mydb | sanitize -s secrets.yaml | gzip > dump.sql.gz

# Mix stdin with file and archive inputs (stdin → stdout; files get per-file outputs):
cat extra.log | sanitize - backup.zip config.yaml -s secrets.yaml
```

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

Download the `sanitize-mcp` binary for your platform from the [Releases](https://github.com/kayelohbyte/rust-sanitize/releases) page (no Deno or Node required — the runtime is embedded).

Add it to your MCP client config. Example for Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sanitize": {
      "command": "/usr/local/bin/sanitize-mcp",
      "env": {
        "SANITIZE_BIN": "/usr/local/bin/sanitize"
      }
    }
  }
}
```

**Environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `SANITIZE_BIN` | `sanitize` | Path to the `sanitize` binary |
| `SANITIZE_MCP_MAX_CONTENT_BYTES` | `524288` (512 KB) | Per-call content size limit |
| `SANITIZE_SECRETS_DIR` | _(unset)_ | Root directory for per-namespace secrets. Each subdirectory is a namespace and may contain `secrets.yaml` (or `.enc`), `profile.yaml`, and an optional `.password` file (`0600`/`0400` permissions enforced). |

**Available tools:**

| Tool | Key parameters | Description |
|------|----------------|-------------|
| `sanitize` | `content`, `secrets_file`, `patterns`, `seed`, `format`, `namespace`, `use_default`, `app`, `allow`, `extract_context`, `context_keywords`, `max_context_matches`, `context_lines`, `context_case_sensitive` | Sanitize sensitive values in text. Namespace takes priority over inline patterns/secrets file. Returns plain text or a `{ content, report }` object when `extract_context` is true. |
| `scan` | `content`, `secrets_file`, `patterns`, `format`, `namespace`, `use_default`, `app`, `allow` | Scan text for sensitive values and return a structured match report without modifying content. |
| `strip_config_values` | `content`, `delimiter`, `comment_prefix` | Strip values from a key/value config file, preserving keys, comments, and structure. |
| `test_allowlist` | `patterns`, `values` | Test which values match a set of allowlist patterns. Returns per-value match results with the matched pattern and a summary count. Use this to verify `--allow` globs before running a full sanitization. |
| `list_processors` | _(none)_ | Return the list of valid processor names for use in `format` parameters and profile YAML `processor` fields. |
| `list_templates` | _(none)_ | List built-in LLM prompt templates. |

**Namespace-based secrets (multi-tenant / MSP)**

Set `SANITIZE_SECRETS_DIR` to a directory and create one subdirectory per customer or software type:

```
/var/sanitize/secrets/
  acme-corp/
    secrets.yaml        # or secrets.yaml.enc
    profile.yaml        # optional structured-field profile
    .password           # optional; must be chmod 0600
  widgets-inc/
    secrets.yaml.enc
    .password
```

Pass `namespace: "acme-corp"` in `sanitize` or `scan` tool calls. The server loads only that namespace's secrets and profile, keeping pattern sets isolated and avoiding false positives across tenants.

Alternatively, run from source with [Deno](https://deno.land) 2.x:

```bash
SANITIZE_BIN=/usr/local/bin/sanitize \
  deno run --allow-run --allow-env --allow-read --allow-write \
  mcp/src/index.ts
```

### Requirements

- Rust 1.74 or later (stable toolchain)

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

**Extract context from sanitized output (error/warning snippets for LLM sharing):**

```bash
sanitize app.log -s secrets.yaml --report report.json --extract-context
sanitize app.log -s secrets.yaml --report report.json --extract-context --context-lines 20
sanitize app.log -s secrets.yaml --report report.json --extract-context --max-context-matches 200
sanitize app.log -s secrets.yaml --report report.json --extract-context --context-keywords timeout,oomkilled --context-case-sensitive
```

**Generate an LLM-ready prompt (sanitized content + structured summary):**

```bash
# Built-in troubleshoot template (default):
sanitize app.log -s secrets.yaml --llm

# Built-in review-config template:
sanitize app.log -s secrets.yaml --llm review-config

# Custom template file:
sanitize app.log -s secrets.yaml --llm /path/to/prompt-template.txt

# Combine with --extract-context to include notable events:
sanitize app.log -s secrets.yaml --report /tmp/r.json --extract-context --llm troubleshoot
```

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

- **No restore.** Replacements are one-way by design. There is no undo, decrypt-output, or reverse-mapping capability.
- **Deterministic mode caveats.** Deterministic replacements require the same secrets key and the same secret values to produce identical output. Changing the secrets file or key produces entirely different replacements.
- **Structured fallback.** Files exceeding structured processor size limits silently fall back to the streaming scanner. The streaming scanner performs byte-level regex replacement and does not understand document structure — it may match inside JSON keys, XML tags, or other structural elements.
- **Structured file size limit.** Files exceeding `--max-structured-size` (default 256 MiB) fall back to the streaming scanner, which does not understand document structure.
- **Zeroization scope.** Zeroization covers secrets, HMAC keys, and mapping store keys. It does not cover incidental copies the Rust compiler may create (e.g. during optimization passes). This is an inherent limitation of safe Rust zeroization.
- **Sequential archive processing.** Archive entries are processed sequentially (not in parallel) to preserve deterministic ordering.
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

This project follows [Semantic Versioning](https://semver.org/). As of 1.0.0,
the public library API and CLI interface are stable. Breaking changes require a
major version bump.

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
