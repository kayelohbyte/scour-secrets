# scour-secrets

[![CI](https://github.com/kayelohbyte/scour-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/kayelohbyte/scour-secrets/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/scour-secrets)](https://crates.io/crates/scour-secrets)
[![docs.rs](https://img.shields.io/docsrs/scour-secrets)](https://docs.rs/scour-secrets)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rust-1.86%2B-blue.svg)]()

Scrub sensitive data from logs and configs before sharing them — with support teams, vendors, or AI tools.

`scour-secrets` replaces API keys, emails, IPs, passwords, tokens, and other secrets with structurally plausible substitutes. Replacements are **one-way**: no mapping file is stored, there's no restore mode, and nothing sensitive persists after the run.

Works as a **CLI**, a **Rust library**, and an **MCP server** — so AI assistants like Claude and Cursor can sanitize files on your behalf before raw content ever reaches the model.

> **Scope:** `scour-secrets` targets **structured secret patterns** — API keys, tokens, credentials, emails, IPs, and other typed values in logs and configs. It is **not** a general-purpose anonymization tool and does **not** perform free-text NLP redaction of prose PII (names, addresses buried in sentences). For that, reach for a dedicated anonymization/NER library.

---

## MCP: Clean Before the LLM Sees It

Install the MCP server and your AI assistant can sanitize files directly — secrets stay inside the audited Rust process and never enter the context window.

**Step 1 — Install the binaries**

Download `scour-secrets` and `scour-secrets-mcp` for your platform from the [Releases](https://github.com/kayelohbyte/scour-secrets/releases) page and place them on your `$PATH` (e.g. `/usr/local/bin/`). No Deno or Node required — the runtime is embedded.

**Step 2 — Register with your AI tool**

**Claude Code:**

```bash
claude mcp add scour-secrets /usr/local/bin/scour-secrets-mcp \
  -e SCOUR_SECRETS_BIN=/usr/local/bin/scour-secrets
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "scour-secrets": {
      "command": "/usr/local/bin/scour-secrets-mcp",
      "env": { "SCOUR_SECRETS_BIN": "/usr/local/bin/scour-secrets" }
    }
  }
}
```

Once connected, the assistant can sanitize inline text or files, scan for leaks without modifying anything, or produce a pre-structured prompt ready for incident triage or config review. See [docs/mcp.md](docs/mcp.md) for the full tool reference, all parameter examples, and setup instructions for Cursor, Neovim, and OpenCode.

---

## Install

**CLI from crates.io:**

```bash
cargo install scour-secrets
```

**From source:**

```bash
git clone https://github.com/kayelohbyte/scour-secrets.git
cd scour-secrets
cargo build --release
# Binary: target/release/scour-secrets
```

> **Windows:** Requires the MSVC linker. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and select the **Desktop development with C++** workload.

**As a Rust library:**

```bash
cargo add scour-secrets
```

**MCP binary:** Download `scour-secrets-mcp` for your platform from the [Releases](https://github.com/kayelohbyte/scour-secrets/releases) page — no Deno or Node required, the runtime is embedded.

---

## Quick Start

![Zero-config scan: secrets in a log replaced with structurally plausible substitutes](docs/demos/out/01-quickstart.gif)

> More demos — dry-run & CI gate, app bundles, stdin piping, structured field rules — in [docs/demos](docs/demos/). All recordings are scripted and regenerable.

### No setup — scan immediately

When you run `scour-secrets` with no secrets file or app bundle, the built-in patterns activate automatically. They cover the most common secrets: API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, and more), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM headers, credential URLs, and password/secret key=value pairs.

```bash
scour-secrets server.log
```

Output goes to `server-sanitized.log` next to the source. Use `-o /path/to/output` to override, or `-o -` for stdout.

On first run, the same balanced pattern set is written to `~/.config/scour-secrets/secrets.yaml` so you can extend it for repeat use. See [Configuration](docs/cli-reference.md#configuration) for the full layered config model, env vars, and project-level `.scour-secrets.yaml`.

```bash
# Dry-run — see what would be replaced without writing anything:
scour-secrets server.log -n

# CI gate — fail if secrets are detected:
scour-secrets config.yaml --fail-on-match
```

### Template-based setup — start from a preset

```bash
scour-secrets template balanced       # mirrors the built-in runtime defaults
scour-secrets template aggressive     # balanced + entropy detection + broad token patterns
scour-secrets template k8s -o k8s.secrets.yaml
```

Each preset writes a ready-to-edit `secrets.template.<preset>.yaml` covering one use case. Available presets: `balanced` (default), `aggressive`, `generic`, `web`, `k8s`, `database`, `aws`.

```bash
scour-secrets server.log -s secrets.template.balanced.yaml
```

`aggressive` also matches broad hostnames, short container IDs, and high-entropy token patterns — recommended when sharing logs with an LLM.

### App bundles — zero config for common applications

Built-in bundles for 28 applications pair a secrets pattern set with a structured field profile so field-level sanitization works out of the box, no authoring required.

```bash
scour-secrets /etc/gitlab/gitlab.rb --app gitlab
scour-secrets nginx.conf docker-compose.yml --app nginx,docker-compose
scour-secrets values.yaml --app kubernetes

# See all available bundles:
scour-secrets apps
```

Built-in bundles: `ansible`, `aws-cli`, `bruno`, `circleci`, `datadog`, `dataiku`, `django`, `docker-compose`, `elasticsearch`, `fstab`, `github-actions`, `gitlab`, `grafana`, `har`, `heroku`, `insomnia`, `kubernetes`, `laravel`, `mongodb`, `mysql`, `nginx`, `postgresql`, `postman`, `rails`, `redis`, `splunk`, `spring-boot`, `terraform`.

---

## Common Workflows

### Multiple files and archives in one pass

```bash
scour-secrets server.log config.yaml backup.zip -s patterns.yaml
# Produces: server-sanitized.log  config-sanitized.yaml  backup.sanitized.zip

# Send all outputs to a directory:
scour-secrets server.log config.yaml backup.zip -s patterns.yaml -o /tmp/clean/
```

### Pipe from another command

Stdin is sanitized and sent to stdout automatically.

```bash
grep "error" server.log | scour-secrets -s patterns.yaml
mysqldump mydb | scour-secrets | gzip > dump.sql.gz

# Mix stdin with file inputs (stdin → stdout; files → per-file siblings):
cat extra.log | scour-secrets - config.yaml -s patterns.yaml
```

When reading from stdin and the format can't be inferred from a filename, use `-f` to specify it: `-f yaml`, `-f json`, `-f csv`, `-f log`, etc.

### CI secrets gate

```bash
# Fail the build if secrets are detected:
scour-secrets config.yaml -s patterns.yaml --fail-on-match

# Same with encrypted patterns file:
SCOUR_SECRETS_PASSWORD="..." scour-secrets config.yaml -s patterns.enc --encrypted-secrets --fail-on-match

# Stream per-match findings as NDJSON for jq or SIEM ingest:
scour-secrets server.log -s patterns.yaml --dry-run --findings | \
  jq 'select(.type=="file") | .pattern_counts'
```

### Archive entry filtering

Filter which entries inside an archive are processed. `*` matches within a single directory segment, `**` crosses directory boundaries, trailing `/` matches a subtree.

```bash
# Keep only the config directory:
scour-secrets backup.zip --only 'config/' -s patterns.yaml

# Keep all JSON, drop the secrets file:
scour-secrets backup.zip --only '**/*.json' --exclude config/secrets.json -s patterns.yaml

# Independent filters per archive in one command:
scour-secrets a.zip --only 'config/' b.tar.gz --only '**/*.log' -s patterns.yaml
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
scour-secrets config.yaml server.log --profile fields.yaml -s patterns.yaml
```

When `--profile` is active, values discovered in structured fields are automatically written back to the patterns file as literals so the streaming scanner can match them in other files too — and in future runs. The write-back preserves the file's on-disk form: an encrypted secrets file is re-encrypted with the same password, and JSON/YAML/TOML plaintext files keep their format. See [Structured Processing](docs/structured-processing.md) for the full field pattern syntax and two-phase pipeline.

### Encrypted patterns file

```bash
# Encrypt once:
scour-secrets encrypt patterns.yaml patterns.yaml.enc --password

# Use interactively:
scour-secrets data.log -s patterns.enc --encrypted-secrets -p

# Non-interactive (CI / pipes):
SCOUR_SECRETS_PASSWORD="my-password" scour-secrets data.log -s patterns.enc --encrypted-secrets
# Or read from a file:
scour-secrets data.log -s patterns.enc --encrypted-secrets -P /run/secrets/pw
```

### Allowlist — pass specific values through unchanged

```bash
scour-secrets data.log -s patterns.yaml --allow localhost --allow "*.internal" --allow "192.168.1.*"
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
scour-secrets data.csv -s patterns.yaml -d
```

For a whole team, commit the flags to the project's `.scour-secrets.yaml` so nobody has to remember them — every member gets byte-identical output from the same input, and the shared rules file stays immutable:

```yaml
# .scour-secrets.yaml (committed to the repo)
profile: sanitize.profile.yaml            # committed field rules
secrets_file: patterns.yaml               # committed detection rules — never modified
handoff_file: .scour-secrets.local.yaml   # gitignored per-user overlay for discoveries
deterministic: true
seed_salt_file: .seed-salt                # committed; password is shared out-of-band
```

See [Team setup](docs/cli-reference.md#team-setup) for the full layout and caveats.

### Shannon entropy detection

Catch high-entropy tokens not covered by any pattern — useful for novel API keys, obfuscated secrets, or anything that wasn't anticipated when the patterns file was written.

```bash
scour-secrets server.log -s patterns.yaml --entropy-threshold 4.5

# Dry-run prints a calibration histogram to help tune the threshold:
scour-secrets server.log -s patterns.yaml -n --entropy-threshold 4.5
```

### LLM-ready output

Sanitize and produce a structured prompt in one step:

```bash
scour-secrets server.log -s patterns.yaml --llm                  # incident triage
scour-secrets nginx.conf --app nginx --llm review-config         # configuration review
scour-secrets nginx.conf --app nginx --llm review-security       # security posture review
```

The prompt includes a `## Files Analyzed` manifest and embeds sanitized content inline (`<content>` blocks). For large file sets or agentic LLMs that can read files with their own tools, add `--output` to switch to **reference mode** — files are written to disk and the prompt lists their absolute paths instead:

```bash
scour-secrets logs/ -s patterns.yaml --llm review-security --output /tmp/sanitized/
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
cargo add scour-secrets
```

```rust
use scour_secrets::category::Category;
use scour_secrets::generator::HmacGenerator;
use scour_secrets::store::MappingStore;
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

### Feature flags

The default build includes the CLI binary and every processor. Library-only consumers can trim dependencies by disabling default features and opting back into just what they need:

```toml
# Core only — HMAC/random generators, mapping store, streaming scanner,
# and the always-on JSON/YAML/TOML/INI/env/key-value/log-line/command-output processors.
# Drops clap, ureq, walkdir, ctrlc, rpassword, tracing-subscriber, zip, tar, flate2, csv, csv-core, quick-xml.
scour-secrets = { version = "0.17", default-features = false }

# Add archive (zip/tar/tar.gz) and/or the CSV + XML processors as needed.
scour-secrets = { version = "0.17", default-features = false, features = ["archive", "structured"] }
```

| Feature | Pulls in | Enables |
|---------|----------|---------|
| `cli` *(default)* | `clap`, `ureq`, `walkdir`, `ctrlc`, `rpassword`, `tracing-subscriber` | The `scour-secrets` binary; implies `archive` + `structured` |
| `archive` *(default)* | `zip`, `tar`, `flate2` | `ArchiveProcessor` (zip / tar / tar.gz) |
| `structured` *(default)* | `csv`, `csv-core`, `quick-xml` | `CsvProcessor` and `XmlProcessor` |

JSON, YAML, TOML, INI, `.env`, key-value, log-line, and command-output processing — plus the regex/literal streaming scanner — are always built. The format-preserving structured editors parse with small byte-span crates (`jiter` for JSON/JSONL, `saphyr-parser` for YAML, `toml_edit` for TOML); these are always on and not behind a feature flag.

---

## Security Model

Replacements are one-way by design. No reverse mapping is stored or recoverable from sanitized output alone. The `MappingStore` forward map lives only in process memory and is zeroized on drop.

Key properties:

- **Encryption at rest** — secrets files use AES-256-GCM with an Argon2id-derived key (memory-hard: 19 MiB, 2 passes). Plaintext files are also supported.
- **Zeroization** — HMAC keys, secret entries, mapping-store keys, and decrypted blobs are zeroized on drop.
- **Regex hardening** — per-pattern automaton and DFA size limits (1 MiB each) prevent ReDoS and unbounded memory growth.
- **Defensive limits** — input size caps, recursion depth limits, node-count caps, and pattern-count limits bound every parser.
- **Zero `unsafe`** — thread safety through `DashMap` and `Arc`; `Send + Sync` bounds verified at compile time.

See [SECURITY.md](SECURITY.md) for the full threat model and mitigations.

---

## Documentation

| Document | Description |
|----------|-------------|
| [MCP Reference](docs/mcp.md) | MCP server setup, all tool parameters, JSON examples, IDE configs (Cursor, Neovim, OpenCode), containerized-agent isolation, and namespace-based multi-tenant setup. |
| [CLI Reference](docs/cli-reference.md) | Full `scour-secrets` command reference including all flags, subcommands, secrets file format, and examples. |
| [Structured Processing](docs/structured-processing.md) | `--profile` usage, field patterns, two-phase pipeline, format preservation, and processor options. |
| [Supported Categories](docs/categories.md) | All 18 built-in replacement categories with strategies and examples, plus custom categories. |
| [Pluggable Strategies](docs/strategies.md) | The `Strategy` trait, 6 built-in strategies, and guide to writing custom strategies. |
| [Library API Reference](docs/api-reference.md) | Module-by-module public API tables. |
| [Detection Quality](docs/detection-quality.md) | CI-gated corpus scorecard: per-pattern positives, hard negatives, chunk-boundary checks. |
| [Defensive Limits & Streaming](docs/defensive-limits.md) | Streaming chunking model, archive processing flow, and all defensive size/depth/count limits. |
| [Architecture](ARCHITECTURE.md) | Internal architecture, data flow, module map, concurrency model, and streaming design. |
| [Security](SECURITY.md) | Security properties, threat mitigations, encryption details, and zeroization strategy. |
| [Contributing](CONTRIBUTING.md) | Build instructions, test suite, fuzz targets, linting, and PR guidelines. |
| [Roadmap](ROADMAP.md) | Stability posture, path to 1.0, and deliberately deferred features. |
| [Changelog](CHANGELOG.md) | Release history and version notes. |

---

## Limitations

- **No restore.** Replacements are one-way by design. No undo, decrypt-output, or reverse-mapping capability.
- **Structured-to-scanner handoff.** When `--profile` is active, discovered values are appended to your secrets file as `kind: literal` entries so the scanner can find them in other files and future runs. The file is written 0600 and re-encrypted when it was encrypted; it holds originals only (no mapping to replacements). Use `--handoff-file` to redirect the write to a local overlay instead — keeping a shared, committed secrets file immutable — or `--no-structured-handoff` to suppress it entirely.
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

This project follows [Semantic Versioning](https://semver.org/). As of 0.8.0, the public library API and CLI interface are considered stable. Breaking changes will be avoided but may occur in minor releases until 1.0.0.

The MSRV is **1.86** (stable toolchain), declared under `rust-version` in `Cargo.toml` and enforced in CI. **MSRV policy:** raising the MSRV is treated as a **minor** version bump (noted in the changelog), not a breaking change, and it is only raised when a dependency or a required language feature makes it necessary.

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
