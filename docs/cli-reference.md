# CLI Reference

## `sanitize`

```
sanitize [OPTIONS] [INPUT]...
command | sanitize [OPTIONS]
sanitize guided
sanitize apps
sanitize apps add <NAME> [OPTIONS]
sanitize apps remove <NAME> [OPTIONS]
sanitize apps dir
sanitize allow-test --allow <PATTERN>... [VALUE]...
sanitize template [OPTIONS]
sanitize encrypt [OPTIONS] <INPUT> <OUTPUT>
sanitize decrypt [OPTIONS] <INPUT> <OUTPUT>
```

The default mode (no subcommand) sanitizes one or more files and archives. Multiple `INPUT` paths may be given in a single invocation and may mix plain files, structured files, and archives freely. When `INPUT` is omitted, data is read from stdin; use `-` to include stdin alongside file paths. Use `encrypt` / `decrypt` subcommands to manage encrypted secrets files.

### `sanitize guided`

Interactive wizard for generating a logs-focused starter secrets template and optional structured profile.

```
sanitize guided
```

What it does:

- Prompts for a **workspace type** (Generic, Web app, Kubernetes, Database, AWS) to seed type-specific patterns.
- Prompts for **replacement strictness** (`Balanced` vs `Aggressive`) to control breadth of token matching.
- Asks for up to 3 company domains to seed domain-specific host/email patterns.
- Asks for cloud providers (AWS, Azure, GCP) and adds provider-specific entries.
- Asks which **structured file formats** to include (YAML/JSON, JSON Lines, `.env`, TOML, INI/conf) and generates a matching profile file.
- Prompts for noisy-ID handling (`trace_id`/`span_id`-like high-entropy noise toggle).
- Generates and validates a plaintext YAML secrets file (default: `secrets.guided.yaml`).
- Generates a profile file alongside it (default: `<stem>.profile.yaml`) when formats are selected.
- Optionally encrypts the secrets file and removes the plaintext copy.
- Optionally runs sanitization immediately using the generated files.

#### Guided Flow (Step by Step)

1. Checks for a TTY (non-interactive shells are rejected with an error).
2. Asks for **workspace type** (select 1–5):
   - `1) Generic` — tokens, emails, IPs, hostnames, UUIDs (default).
   - `2) Web app` — JWTs, session cookies, emails, URLs.
   - `3) Kubernetes` — service accounts, tokens, namespaces.
   - `4) Database` — passwords, connection strings, usernames.
   - `5) AWS` — like Generic but uses the Aggressive strictness preset.
3. Asks for **replacement strictness** (select 1–2; default: Aggressive):
   - `1) Balanced` — replace clearly sensitive values only.
   - `2) Aggressive` — also replace high-entropy tokens (recommended for LLM sharing).
4. Prompts for company domains (comma-separated, up to 3).
5. Prompts for cloud provider scope (AWS, Azure, GCP, none).
6. Prompts for **structured file formats** to include in the generated profile:
   - `1) YAML / JSON` — k8s manifests, docker-compose, app configs.
   - `2) JSON Lines` — NDJSON structured logs (`.jsonl`, `.ndjson`).
   - `3) .env files` — twelve-factor app secrets, CI variables.
   - `4) TOML` — Rust, Hugo, and other TOML configs.
   - `5) INI / conf` — system services, databases, legacy apps.
   - `6) All of the above` (default).
   - `7) None` — secrets file only, no profile.
7. Prompts for noisy-ID handling (`trace_id`/`span_id`-like high-entropy noise toggle).
8. Prompts for output secrets file path (default: `secrets.guided.yaml`); forces `.yaml` extension.
9. Generates secrets entries and validates all regexes by compiling them before writing.
10. Writes plaintext YAML secrets file.
11. If formats were selected, prompts for profile file path (default: `<secrets-stem>.profile.yaml`) and writes it.
12. Optionally encrypts the secrets file; removes plaintext after successful encryption.
13. Optionally runs sanitization immediately:
    - Prompts for input path (or `-` for stdin).
    - Prompts for optional output path.
    - Prompts for dry-run choice.
    - Prompts for deterministic mode choice.

#### What Guided Picks Out to Sanitize

The guided template writes regex rules with these categories and targets.

Always included (all workspace types and strictness levels):

- `email`: email addresses.
- `ipv4`: IPv4 addresses.
- `ipv6`: IPv6 addresses.
- `mac_address`: MAC addresses with `:` or `-` separators.
- `uuid`: RFC-like UUIDs.
- `jwt`: JWT-like `header.payload.signature` tokens.
- `url`: `http://` and `https://` URLs.
- `auth_token`: PEM/private-key headers, generic `secret_key`/`api_key` key-value patterns, GitHub PAT patterns, GCP API key prefix.
- `custom:password`: password key-value pattern.
- `file_path`: `/home/<user>` and `/Users/<user>` paths.
- `container_id`: Docker image digests (`sha256:<64-hex>`).

Aggressive-strictness additions (also included for Web app, Kubernetes, and Database workspace types):

- `auth_token`: bearer/authorization token context regex.
- `custom:high_entropy_token`: broad long-token pattern (`[A-Za-z0-9_-]{20,}`), unless noisy-ID exclusion is enabled.

Aggressive-strictness-only additions (not included at Balanced strictness):

- `hostname`: broad DNS-style FQDN regex. Intentionally excluded from Balanced because it matches many non-secret dotted identifiers in application logs.
- `container_id`: short 12-hex container ID pattern.

Web app workspace additions:

- `auth_token`: session ID/token key-value regex.
- `auth_token`: OAuth access/refresh token key-value regex.

Kubernetes workspace additions:

- `auth_token`: generic token key-value regex.
- `custom:k8s_namespace`: Kubernetes namespace regex.
- `container_id`: full 64-char SHA256 image digest and short 12-char container ID.

Database workspace additions:

- `url`: database connection string regex (postgres, mysql, mongodb, redis, amqp, jdbc).
- `name`: username key-value regex.

Domain-derived additions (for each provided domain):

- `email`: domain-specific email regex (`...@<domain>`).
- `hostname`: domain-specific host regex (`*.<domain>` style).

Cloud-provider additions:

- AWS selected:
  - `aws_arn`: ARN-like values.
  - `auth_token`: AWS access key ID shape (`AKIA`/`ASIA` + 16 chars).
  - `container_id`: EC2 instance ID shape (`i-<8-17 hex chars>`).
- Azure selected:
  - `azure_resource_id`: subscription/resourceGroups/provider path shapes.
- GCP selected:
  - `custom:gcp_service_account`: service-account email shape.
  - `custom:gcp_resource`: `projects/<id>/...` resource-path shape.

Intentionally excluded by default (logs-first design):

- `ssn`, `phone`, `credit_card`.

#### Strictness Levels

**`Balanced`** — replace clearly sensitive values only.

- Focuses on high-confidence, low-false-positive patterns.
- Excludes broad hostname regex and short container-ID patterns.
- Excludes `bearer`/`authorization` token context regex and broad high-entropy token pattern.
- Suitable for logs containing many non-secret high-entropy identifiers (trace IDs, synthetic IDs).

**`Aggressive`** — replace high-entropy tokens too (recommended for LLM sharing).

- Adds the broad hostname regex, short container-ID patterns, and high-entropy token pattern.
- Higher false-positive risk for long identifiers that are not secrets.
- If noisy-ID exclusion is enabled, the high-entropy token entry is removed.
- Recommended when over-redaction on a first pass is acceptable.

#### Replacement Behavior for Guided Rules

- All replacements are one-way and length-preserving.
- Category controls output shape (for example `email` preserves domain; `uuid` preserves dash layout; `url` preserves URL structure).
- `custom:*` categories use the custom formatter (`__SANITIZED_<hex>__` style adjusted to input length).

#### Example Generated YAML (Guided)

Example (Generic workspace, Aggressive strictness, `example.com` domain, GCP selected):

```yaml
- pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
  kind: regex
  category: email
  label: email

- pattern: \b(?:\d{1,3}\.){3}\d{1,3}\b
  kind: regex
  category: ipv4
  label: ipv4

- pattern: \beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b
  kind: regex
  category: jwt
  label: jwt

- pattern: (?i)(?:bearer|authorization)[\s:]+[A-Za-z0-9._~+/=-]{16,}\b
  kind: regex
  category: auth_token
  label: bearer_token

- pattern: '[A-Za-z0-9._%+-]+@example\.com'
  kind: regex
  category: email
  label: email_example_com

- pattern: \b(?:[A-Za-z0-9-]+\.)*example\.com\b
  kind: regex
  category: hostname
  label: host_example_com

- pattern: \b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b
  kind: regex
  category: custom:gcp_service_account
  label: gcp_service_account

- pattern: \bprojects/[a-z][a-z0-9-]{4,30}/[A-Za-z0-9/_-]+\b
  kind: regex
  category: custom:gcp_resource
  label: gcp_resource
```

Notes:

- Guided mode is intended for application/system logs and excludes common consumer-PII categories by default.
- In non-interactive environments, guided mode exits with an error because it requires a TTY.
- GCP patterns currently use `custom:gcp_*` categories (no built-in GCP formatter yet).
- The generated profile file contains no secrets and is safe to commit to version control.

### `sanitize apps`

Manage app bundles: list available bundles, install custom ones, remove them, or show the storage directory.

```
sanitize apps
sanitize apps add <NAME> [OPTIONS]
sanitize apps remove <NAME> [OPTIONS]
sanitize apps dir
```

#### `sanitize apps` (list)

Prints built-in and user-defined bundles. Use the name with `--app` to load the bundle.

```bash
sanitize apps
# Built-in app bundles (use with --app <name>):
#
#   docker-compose     Docker Compose — compose.yml environment variables...
#   django             Django — .env files, SECRET_KEY, database credentials...
#   gitlab             GitLab — CI/CD logs, runner output, .gitlab-ci.yml variables
#   kubernetes         Kubernetes — kubeconfig credentials, Secret manifests...
#   nginx              Nginx — nginx.conf virtual hosts, proxy upstreams...
#   postgresql         PostgreSQL — postgresql.conf, connection strings, pg logs
#   rails              Ruby on Rails — database.yml, .env, config/secrets.yml
#   spring-boot        Spring Boot — application.yml, application.properties...

# Use a single bundle:
sanitize config.rb --app gitlab -s secrets.yaml

# Combine multiple bundles in one run:
sanitize nginx.conf gitlab.rb --app nginx,gitlab

# Combine a bundle with a custom secrets file and profile:
sanitize config.rb app.log --app gitlab -s extra-secrets.yaml --profile custom.profile.yaml
```

Each app bundle includes:
- A set of secrets patterns compiled into the scanner alongside any `--secrets-file` patterns.
- A structured field profile merged with any `--profile` you supply.

#### `sanitize apps add`

Install a custom app bundle from local YAML files. At least one of `--profile` or `--secrets` must be supplied. Both files are validated before anything is written to disk.

```
sanitize apps add <NAME> [--profile FILE] [--secrets FILE] [--overwrite]
```

| Flag | Description |
|------|-------------|
| `<NAME>` | Bundle name (letters, digits, hyphens, underscores; must start with a letter or digit). |
| `--profile <FILE>` | Path to a profile YAML file (`Vec<FileTypeProfile>`). |
| `--secrets <FILE>` | Path to a secrets YAML file (`Vec<SecretEntry>`). |
| `--overwrite` | Replace an existing custom bundle with the same name. |

```bash
# Install from a profile and a secrets file:
sanitize apps add elastic \
  --profile elastic.profile.yaml \
  --secrets elastic.secrets.yaml

# Profile only (no scanner patterns):
sanitize apps add myapp --profile myapp.profile.yaml

# Secrets only (no structured field rules):
sanitize apps add myapp --secrets myapp.secrets.yaml

# Replace an existing custom bundle:
sanitize apps add elastic --profile elastic.profile.yaml --overwrite

# Use it immediately after installing:
sanitize app.log --app elastic
```

The bundle is stored under the user apps directory (see `sanitize apps dir`). The first `# comment` line of either YAML file becomes the description shown in `sanitize apps`.

#### `sanitize apps remove`

Remove a custom app bundle. Built-in bundles cannot be removed.

```
sanitize apps remove <NAME> [--yes]
```

| Flag | Description |
|------|-------------|
| `<NAME>` | Name of the custom bundle to remove. |
| `--yes` / `-y` | Confirm removal. Required — the command refuses to delete without it. |

```bash
# Remove a custom bundle (--yes required):
sanitize apps remove elastic --yes

# Short form:
sanitize apps remove elastic -y
```

#### `sanitize apps dir`

Print the path to the user apps directory. Bundles are stored one subdirectory per app name.

```bash
sanitize apps dir
# /Users/alice/.config/sanitize/apps

# Override the location with an environment variable:
SANITIZE_APPS_DIR=/opt/sanitize/apps sanitize apps dir
```

You can also drop bundle directories manually without using `sanitize apps add`:

```
~/.config/sanitize/apps/
  elastic/
    secrets.yaml      # Vec<SecretEntry>
    profile.yaml      # Vec<FileTypeProfile> (optional)
  myapp/
    profile.yaml
```

The directory name is the app name. `SANITIZE_APPS_DIR` overrides the default location. User-defined bundles take precedence over built-in bundles with the same name.

### `sanitize allow-test`

Test which values match your allowlist patterns before committing to a full sanitization run.

```
sanitize allow-test --allow <PATTERN>... [VALUE]...
```

| Flag / Argument | Description |
|-----------------|-------------|
| `--allow <PATTERN>` | Allowlist pattern to test (repeatable). Supports exact strings and `*` glob wildcards. |
| `[VALUE]...` | Values to test. If omitted, values are read from stdin one per line. |
| `--json` | Output results as JSON instead of human-readable text. |
| `-h, --help` | Print help. |

Each value is printed with `✓` (matched — would pass through unchanged) or `✗` (no match — would be replaced), and the matching pattern is shown alongside hits.

```bash
# Test a glob pattern against specific values:
sanitize allow-test --allow '*.internal' db.internal github.com staging.db.internal

# ✓  db.internal                               → *.internal
# ✗  github.com                                (no match)
# ✓  staging.db.internal                       → *.internal
#
# 2/3 values allowed

# Test multiple patterns at once:
sanitize allow-test \
  --allow localhost \
  --allow '*.internal' \
  --allow '192.168.1.*' \
  db.internal 192.168.1.5 8.8.8.8

# Feed values from a file (one per line):
cut -f3 app.log | sort -u | sanitize allow-test --allow '*.internal' --allow localhost

# Machine-readable output for scripting:
sanitize allow-test --allow '*.internal' db.internal github.com --json
```

JSON output shape:

```json
{
  "results": [
    { "value": "db.internal",  "allowed": true,  "pattern": "*.internal" },
    { "value": "github.com",   "allowed": false }
  ],
  "summary": { "total": 2, "allowed": 1, "blocked": 1 }
}
```

### `sanitize template`

Generate a starter secrets-template YAML file for a given use case.

```
sanitize template [OPTIONS]
```

| Flag / Argument | Description |
|-----------------|-------------|
| `--preset <PRESET>` | Which template to generate. Choices: `generic` (default), `web`, `k8s`, `database`, `aws`. |
| `-o, --output <FILE>` | Output path (default: `secrets.template.yaml`). |
| `--overwrite` | Overwrite the output file if it already exists. |
| `-h, --help` | Print help. |

**Presets:**

| Preset | Contents |
|--------|----------|
| `generic` | Common secrets: tokens, emails, IPs, hostnames — a good starting point for most log types. |
| `web` | Web-app logs: JWTs, session IDs, OAuth tokens, emails, URLs. |
| `k8s` | Kubernetes configs: service-account tokens, namespaces, container IDs. |
| `database` | Database configs: passwords, connection strings (postgres/mysql/mongo/redis), usernames. |
| `aws` | AWS: access key IDs (`AKIA`/`ASIA`), secret access keys, ARNs, account IDs, EC2 instance IDs. |

Templates contain commented-out examples and inline guidance so you can uncomment and adapt the entries you need.

```bash
# Generic template → secrets.template.yaml (default):
sanitize template

# Web-app template → secrets.template.yaml:
sanitize template --preset web

# Kubernetes template to a custom path:
sanitize template --preset k8s -o k8s-secrets.yaml

# AWS template, overwrite if already exists:
sanitize template --preset aws --overwrite
```

### Default Mode — Sanitize

| Flag / Argument | Short | Description |
|-----------------|-------|-------------|
| `[INPUT]...` | | One or more paths to sanitize. Any mix of plain files, structured files, and archives is accepted. Omit to read from stdin; use `-` to include stdin alongside file paths. `-` may appear at most once. |
| `-o, --output <FILE>` | `-o` | Output path. For a **single input stream** this is the output file path. For **multiple inputs** this is treated as an output directory (created automatically if absent); output files are written there instead. |}
| `-s, --secrets-file <FILE>` | `-s` | Path to a secrets file. Plaintext (`.json`, `.yaml`, `.toml`) is loaded directly by default. Use `--encrypted-secrets` to decrypt an AES-256-GCM encrypted file. |
| `-p, --password` | `-p` | Trigger an interactive password prompt (masked input, never echoed). Requires `--encrypted-secrets`. Providing this flag without `--encrypted-secrets` is an error. For non-interactive automation use `--password-file` or `SANITIZE_PASSWORD` instead. |
| `-P, --password-file <FILE>` | `-P` | Read the decryption password from a file. Requires `--encrypted-secrets`. The file must have permissions `0600` or `0400` (owner-only). Trailing newline is stripped. |
| `--encrypted-secrets` | | Treat the secrets file as AES-256-GCM encrypted and decrypt it before loading. Requires a password via `-p`, `--password-file`, or `SANITIZE_PASSWORD`. Without this flag the file is loaded as plaintext. Providing any password input without this flag is an error. |
| `-f, --format <FMT>` | `-f` | Force input format, overriding file-extension detection. Values: `text`, `json`, `yaml`, `xml`, `csv`, `key-value`. Required for structured processing when reading from stdin. |
| `-n, --dry-run` | `-n` | Scan and report matches without writing output. |
| `--fail-on-match` | | Exit with code 2 if any matches are found. |
| `-r, --report [PATH]` | `-r` | Write a JSON report to `PATH` (or stderr if no path given). Use `--report -` to write the report to stdout. The report includes: `metadata` (tool version, flags), `summary` (totals, `duration_ms`, `pattern_counts`), and a `files` array with per-file `matches`, `replacements`, byte counts, `pattern_counts`, and `method`. `pattern_counts` maps each pattern `label` to its scanner hit count; it is empty (`{}`) when all matches came from the structured-processor pass or when patterns have no label. |
| `--strict` | | Abort on the first error instead of skipping and continuing. |
| `-d, --deterministic` | `-d` | Use HMAC-deterministic replacements (reproducible across runs with the same password). Requires a password via `SANITIZE_PASSWORD`, `--password-file`, or `-p`. |
| `--no-update-secrets` | | Suppress the automatic save of values discovered during a profile-driven run. By default, when a profile is active (`--profile` or `--app` with a profile), any field values found are appended to `--secrets-file` (or `sanitize-discovered.yaml` if no secrets file is given) as `kind: literal` entries so future runs can match them without re-running the profile. Pass this flag to disable that write. |
| `--include-binary` | | Process entries that appear to be binary data (default: skip). |
| `--threads <N>` | | Number of worker threads. When multiple input files are given, files are processed in parallel up to this limit. For a single archive input, entries are sanitized in parallel using the same budget. Defaults to the number of logical CPUs. Capped to available parallelism. |
| `--chunk-size <BYTES>` | | Chunk size for the streaming scanner in bytes (default: `1048576` = 1 MiB). |
| `--max-mappings <N>` | | Maximum unique replacement mappings in memory (default: `10000000`). Use `0` for unlimited. |
| `--max-structured-size <BYTES>` | | Maximum structured file size in bytes before falling back to streaming (default: `268435456` = 256 MiB). |
| `--max-archive-depth <N>` | | Maximum nesting depth for recursive archive processing (default: `3`, max: `10`). Each nesting level may buffer up to 256 MiB. |
| `--profile <FILE>` | | Path to a file-type profile (JSON or YAML). Enables structured field-level sanitization for matched files. Discovered field values are automatically saved to the secrets file after the run (see `--no-update-secrets`). Loads common allow patterns (loopback IPs, `localhost`, `example.com`, nil UUID, etc.) so those values are never replaced. See [Structured Processing](structured-processing.md). |
| `--default` | | Use built-in balanced detection patterns without a secrets file. Covers API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, GitLab, SendGrid, npm), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM headers, password/secret key=value pairs, and credential URLs. Loads common allow patterns so loopback IPs, `localhost`, `example.com`, etc. are never replaced. Cannot be combined with `--secrets-file`. |
| `--app <APPS>` | | Load built-in secrets patterns and structured field profiles for one or more applications. Comma-separated app names (e.g. `--app gitlab` or `--app gitlab,nginx`). Additive with `--default`, `--secrets-file`, and `--profile`. Loads common allow patterns. Run `sanitize apps` to list available app names. |
| `--allow <PATTERN>` | | Allow a specific value through unchanged (repeatable). Matched values are not replaced and not recorded in the mapping store — they will pass through in every file processed in the same run. Supports exact strings and `*` glob patterns. Examples: `--allow localhost`, `--allow "*.internal"`, `--allow "192.168.1.*"`. Allowlist entries can also be placed in the secrets file as `kind: allow` entries. |
| `--only <PATTERN>` | | Keep only archive entries whose full path matches `PATTERN`. Must follow the archive path it applies to. Multiple `--only` flags accumulate. Combined with `--exclude`: `--only` narrows first, then `--exclude` removes. Only affects archive inputs; ignored for plain files. |
| `--exclude <PATTERN>` | | Remove archive entries whose full path matches `PATTERN`. Must follow the archive path it applies to. Multiple `--exclude` flags accumulate. |
| `--log-format <FMT>` | | Log output format: `human` (default) or `json`. |
| `--progress <MODE>` | | Progress display mode: `auto`, `on`, or `off`. Default: `auto`. |
| `--no-progress` | | Alias for `--progress off`. |
| `--progress-interval-ms <MS>` | | Minimum interval between progress refreshes (default: `200`). |
| `--extract-context` | | After sanitizing, scan the output for error/warning/failure keywords and embed matching lines with surrounding context in the JSON report. Each file entry in `files[]` gets its own `log_context` object. Requires `--report`. Has no effect without `--report`. For stdout paths larger than 256 MiB the flag is silently skipped (use file output and the two-pass reader path instead). |
| `--context-lines <N>` | | Lines of context to capture before and after each keyword match when `--extract-context` is set. Default: `10`. |
| `--context-keywords <KEYWORDS>` | | Comma-separated list of keywords to scan for when `--extract-context` is set. Merged with the built-in defaults (`error`, `failure`, `warning`, `warn`, `fatal`, `exception`, `critical`) unless `--context-keywords-only` is also passed. Example: `--context-keywords timeout,oomkilled,backoff`. |
| `--context-keywords-only` | | When set, `--context-keywords` replaces the built-in default keyword list entirely instead of being merged with it. Has no effect without `--context-keywords`. |
| `--max-context-matches <N>` | | Maximum number of keyword matches to capture per file when `--extract-context` is set. Default: `50`. Once this cap is hit, `truncated: true` is set in `log_context` and the rest of the file is skipped. Increase this (not `--context-lines`) when you are missing events. |
| `--context-case-sensitive` | | Make keyword matching case-sensitive when `--extract-context` is set. By default keywords are matched case-insensitively (`error` matches `ERROR`, `Error`, etc.). |
| `--force-text` | | Bypass all structured processors (JSON, YAML, XML, TOML, etc.) and run only the streaming scanner on every file. Use when you want a guarantee that every byte is pattern-scanned regardless of file type. |
| `--strip-values` | | Strip all values from structured output, emitting only keys and structure. Useful for generating a profile template from a real config file without exposing any values. Bypasses the sanitization pipeline — no secrets file is required. |
| `--strip-delimiter <DELIM>` | | Delimiter string used to split key/value lines when `--strip-values` is set. Default: `=`. Use `--strip-delimiter :` for YAML-style or nginx-style config files. Requires `--strip-values`. |
| `--strip-comment-prefix <PREFIX>` | | Line prefix that marks a comment when `--strip-values` is set. Comment lines are preserved verbatim. Default: `#`. Use `--strip-comment-prefix //` for C-style or nginx-style comment lines. Requires `--strip-values`. |
| `-h, --help` | `-h` | Print help. |
| `-V, --version` | `-V` | Print version. |

Log level is controlled via the `SANITIZE_LOG` environment variable (e.g. `SANITIZE_LOG=debug`).

#### Archive Entry Filtering (`--only` / `--exclude`)

`--only` and `--exclude` filter which entries are written into the output archive. They must appear **after** the archive path they apply to. Patterns match the full stored entry path (e.g. `test/test.config`, not just `test.config`).

**Pattern syntax**

| Pattern | Meaning |
|---------|---------|
| `*.log` | Matches any `.log` file in the root of the archive. `*` does **not** cross `/`. |
| `**/*.log` | Matches `.log` files at any depth. `**` crosses `/`. |
| `logs/` | Directory-prefix match: keeps `logs/` itself and every entry under it. Trailing `/` is required. |
| `config/app.yaml` | Exact full-path match. |
| `??.txt` | `?` matches any single character except `/`. |
| `[abc].txt` | Character-class match for `a.txt`, `b.txt`, or `c.txt`. |

**Rules**

- `--only` and `--exclude` are **per-archive**. Use interleaved syntax to filter multiple archives independently.
- Both flags can be combined: `--only` narrows the set first, then `--exclude` removes from it.
- **Directory entries** (entries whose stored type is a directory) always pass through regardless of any filter. Only file entries are filtered.
- **Nested archives** inherit the same filter applied to their parent archive.
- `--only` / `--exclude` before any archive path on the command line is a hard error.
- A non-archive plain file appearing between `--only`/`--exclude` and their pattern values is a hard error.

**Single archive**

```bash
# Keep only entries matching test/test.config (exact full path):
sanitize archive.zip --only test/test.config -s secrets.yaml

# Keep only JSON files at any depth:
sanitize archive.zip --only '**/*.json' -s secrets.yaml

# Keep only entries under the config/ prefix:
sanitize archive.zip --only 'config/' -s secrets.yaml

# Drop all .log files:
sanitize archive.zip --exclude '*.log' -s secrets.yaml

# Keep only JSON files, then drop secrets.json:
sanitize archive.zip --only '**/*.json' --exclude config/secrets.json -s secrets.yaml

# Keep only JSON files in the root (not subdirectories):
sanitize archive.zip --only '*.json' -s secrets.yaml
```

**Multiple archives — each gets its own filter**

```bash
# a.zip keeps only config/, b.tar.gz keeps only *.log files:
sanitize a.zip --only 'config/' b.tar.gz --only '**/*.log' -s secrets.yaml

# Mix an archive with a plain file — the plain file is not filtered:
sanitize report.txt backup.zip --only 'logs/' -s secrets.yaml

# Mix stdin with an archive filter:
cat extra.log | sanitize - backup.zip --only 'logs/' -s secrets.yaml
```

#### Progress Behavior

Progress output is designed to stay safe for pipelines and machine-readable logging:

- Live progress renders on `stderr` only.
- `stdout` remains reserved for sanitized payloads and explicit report output.
- In `auto` mode, live progress is disabled when `stderr` is not a TTY, when `TERM=dumb`, when `CI` is set, or when `--log-format json` is active.
- In `json` log mode, spinner frames are suppressed so logs remain parseable.
- `--progress on` forces progress reporting, but non-interactive environments fall back to milestone-style status instead of a live spinner.

Examples:

```bash
# Default behavior: spinner in interactive terminals, silent in CI/non-TTY.
sanitize large.log -s secrets.enc --encrypted-secrets --password

# Force progress messages even in non-interactive environments.
sanitize large.log -s secrets.enc --encrypted-secrets --password --progress on

# Disable progress completely.
sanitize large.log -s secrets.enc --encrypted-secrets --password --no-progress

# Redirect sanitized payload and progress separately.
sanitize large.log -s secrets.enc --encrypted-secrets --password --progress on > clean.log 2> progress.log

# Keep machine-readable JSON logs clean (no spinner frames).
sanitize large.log -s secrets.enc --encrypted-secrets --password --log-format json --progress on > clean.log 2> events.jsonl
```

#### Output Naming

When no `--output` is given, each input gets its own output file written next to the source:

| Input type | Default output name |
|------------|--------------------|
| Plain / structured file (`foo.txt`, `a.json`) | `<stem>-sanitized.<ext>` — e.g. `foo-sanitized.txt`, `a-sanitized.json` |
| Archive (`data.tar`, `data.tar.gz`, `archive.zip`) | `<stem>.sanitized.<ext>` — e.g. `data.sanitized.tar`, `data.sanitized.tar.gz`, `archive.sanitized.zip` |
| Stdin (no file path) | stdout |

When multiple inputs map to the same computed output name within one run, a numeric suffix is appended automatically (e.g. `same-sanitized-1.txt`, `same-sanitized-2.txt`).

When `--output <PATH>` is given:
- **Single input:** writes to that exact path.
- **Multiple inputs:** `PATH` is treated as a directory. The directory is created if absent. Output files are placed inside it using the per-input naming rules above.


#### Stdin Support

When no input path is given (or one of the paths is `-`), `sanitize` reads from stdin. `-` may be mixed freely with file paths and may appear at most once. Stdin output defaults to stdout unless `--output` is given.

```bash
# Pipe from grep with a plaintext secrets file:
grep "error" app.log | sanitize -s secrets.yaml

# Pipe from grep with an encrypted secrets file (use env var since stdin is a pipe):
export SANITIZE_PASSWORD="my-password"
grep "error" app.log | sanitize -s secrets.enc --encrypted-secrets

# Read from stdin, write to a file (plaintext secrets):
cat data.csv | sanitize -s secrets.yaml -f csv -o clean.csv

# Use with heredoc:
sanitize -s secrets.json <<< "my secret api-key-12345"
```

Stdin mode supports plain text streaming by default. Use `--format` / `-f` to enable structured processing (e.g., `-f json` for JSON-aware field replacement). Archive formats (tar, zip) are not supported via stdin.

#### Processing Order

The order in which stdin and file inputs are processed depends on whether `--profile` is active.

**Without `--profile`:**

1. Stdin — processed immediately with the base scanner.
2. All file targets — run in parallel (Phase 2 only).

**With `--profile`:**

1. **Phase 1 — serial, in command-line order** — plain files that match a `--profile` entry, using the structured processor to discover and record field values.
2. **Archive discovery pre-pass** — each archive in the input is read a second time to find profile-matched entries and add their values to the store.
3. **Augmented scanner is built** — base secrets patterns + all literals discovered in steps 1–2.
4. **Stdin** — now processed with the augmented scanner, so values found in structured config files are also replaced in piped input.
5. **Phase 2 — parallel** — archives and non-profile plain files, using the augmented scanner.

Deferring stdin until after file discovery is what makes piping work correctly alongside `--profile`:

```bash
# config.yaml runs first (Phase 1), discovers e.g. password: hunter2
# error.json (stdin) is processed after — "hunter2" is replaced in it too
cat error.json | sanitize config.yaml --profile profile.yaml -s secrets.yaml

# Without --profile, stdin runs immediately (no deferral — no discovery happens)
cat error.json | sanitize -s secrets.yaml
```

**Does file order matter?**

In the common case (no `--profile`), all file targets go straight to Phase 2 and run in parallel — command-line order has no effect on results. The mapping store is thread-safe with first-writer-wins semantics, so the same value always receives the same replacement regardless of which file encounters it first.

With `--profile`, Phase 1 files run in command-line order. In practice, order rarely matters because each value has one canonical replacement — the order only affects which file *first* adds a given value to the store, not what the replacement is.

**Cross-file consistency**

The mapping store is shared across all phases and all threads. If `hunter2` is discovered as a password in `config.yaml` (Phase 1), the same replacement is applied everywhere that literal appears — in Phase 2 archives, plain-text logs, and deferred stdin.

```bash
# file order within Phase 2 does not affect replacements:
sanitize a.log b.log c.log -s secrets.yaml   # same result as c b a order
```

#### Examples

```bash
# Sanitize a single log file (output goes to data-sanitized.log):
sanitize data.log -s secrets.yaml

# Sanitize multiple files in one command:
sanitize test.txt a.json b.zip -s secrets.yaml
# Produces: test-sanitized.txt  a-sanitized.json  b.sanitized.zip

# Send all sanitized files to a specific output directory:
sanitize test.txt a.json b.zip -s secrets.yaml -o /tmp/clean/

# Override output path for a single file:
sanitize data.log -s secrets.yaml -o clean.log

# Pipe from grep (plaintext secrets):
grep "error" app.log | sanitize -s secrets.yaml

# Mix stdin with file inputs (stdin goes to stdout, files get per-file outputs):
cat extra.txt | sanitize - data.log -s secrets.yaml

# Mix stdin with an archive (stdin sanitized to stdout; archive gets its own output file):
cat extra.log | sanitize - backup.zip -s secrets.yaml

# Archive and plain file together (each gets its own output file):
sanitize backup.zip config.yaml -s secrets.yaml
# Produces: backup.sanitized.zip  config-sanitized.yaml

# Filter archive entries — keep only files under config/:
sanitize backup.zip --only 'config/' -s secrets.yaml

# Filter by glob — keep only JSON files at any depth:
sanitize backup.zip --only '**/*.json' -s secrets.yaml

# Filter by exact full path (paths are stored as-is inside the archive):
sanitize test.zip --only test/test.config -s secrets.yaml

# Combine --only and --exclude: keep JSON, drop secrets file:
sanitize backup.zip --only '**/*.json' --exclude config/secrets.json -s secrets.yaml

# Drop all log files from the output archive:
sanitize backup.zip --exclude '**/*.log' -s secrets.yaml

# Per-archive filters — each archive has independent --only / --exclude:
sanitize a.zip --only 'config/' b.tar.gz --only '**/*.log' -s secrets.yaml

# Plain file alongside a filtered archive:
sanitize report.txt backup.zip --only 'logs/' -s secrets.yaml
# Produces: report-sanitized.txt  backup.sanitized.zip (with only logs/ entries)

# Force progress to stderr while keeping stdout pipe-safe:
grep "error" app.log | sanitize -s secrets.yaml --progress on > clean.log 2> progress.log

# Structured stdin processing:
cat config.yaml | sanitize -s secrets.yaml -f yaml -o clean.yaml

# Encrypted secrets file — requires --encrypted-secrets:
sanitize data.log -s secrets.enc --encrypted-secrets --password
sanitize data.log -s secrets.enc --encrypted-secrets --password -o clean.log

# Non-interactive pipeline with encrypted secrets (env var):
export SANITIZE_PASSWORD="my-password"
grep "error" app.log | sanitize -s secrets.enc --encrypted-secrets

# Deterministic mode (reproducible replacements) with encrypted secrets:
sanitize data.csv -s s.enc --encrypted-secrets --password -d

# Dry-run (scan only):
sanitize config.yaml -s s.enc --encrypted-secrets --password -n

# Fail CI if matches found:
sanitize config.yaml -s s.enc --encrypted-secrets -P /run/secrets/pw --fail-on-match

# Read password from a file:
sanitize data.log -s s.enc --encrypted-secrets -P /run/secrets/pw

# Extract context from sanitized output (capture surrounding lines for each error/warning):
sanitize app.log -s secrets.yaml --report report.json --extract-context

# Increase captured context window from default 10 to 20 lines:
sanitize app.log -s secrets.yaml --report report.json --extract-context --context-lines 20

# Increase match cap (default 50) to capture more events before truncation:
sanitize app.log -s secrets.yaml --report report.json --extract-context --max-context-matches 200

# Case-sensitive keyword matching (default is case-insensitive):
sanitize app.log -s secrets.yaml --report report.json --extract-context --context-case-sensitive

# Custom keywords merged with defaults:
sanitize app.log -s secrets.yaml --report report.json --extract-context --context-keywords timeout,oomkilled,backoff

# Use only custom keywords, suppress built-in defaults:
sanitize app.log -s secrets.yaml --report report.json --extract-context --context-keywords "timeout,oomkilled" --context-keywords-only

# Strip values from a key=value config file (default delimiter is =):
sanitize config.ini -s secrets.yaml --strip-values -o config-stripped.ini

# Strip values using a colon delimiter (e.g. YAML-style or nginx-style configs):
sanitize nginx.conf -s secrets.yaml --strip-values --strip-delimiter : -o nginx-stripped.conf

# Strip values with C-style comment lines (// prefix):
sanitize app.conf -s secrets.yaml --strip-values --strip-comment-prefix // -o app-stripped.conf

# Generate a sanitized LLM-ready prompt with built-in troubleshoot template:
sanitize app.log -s secrets.yaml --llm

# Use a specific LLM template:
sanitize app.log -s secrets.yaml --llm review-config

# Use a custom template file:
sanitize app.log -s secrets.yaml --llm /path/to/my-template.txt

# Combine LLM output with context extraction for notable events:
sanitize app.log -s secrets.yaml --report /tmp/report.json --extract-context --llm troubleshoot
```

### `sanitize encrypt`

Encrypt a plaintext secrets file for use with the sanitizer.

```
sanitize encrypt [OPTIONS] <INPUT> <OUTPUT>
```

| Flag / Argument | Description |
|-----------------|-------------|
| `<INPUT>` | Path to plaintext secrets file (`.json`, `.yaml`, `.yml`, `.toml`). |
| `<OUTPUT>` | Path for encrypted output file (`.enc`). |
| `--password` | Prompt interactively for the encryption password. The password is never echoed. For non-interactive automation use `--password-file` or `SANITIZE_PASSWORD` instead. |
| `--password-file <FILE>` | Read the password from a file (must have `0600` or `0400` permissions). |
| `--format <FMT>` | Force input format: `json`, `yaml`, or `toml` (default: auto-detect from extension). |
| `--validate` | Parse plaintext before encrypting and report errors (default). |
| `--no-validate` | Skip pre-encryption validation. |
| `-h, --help` | Print help. |

### `sanitize decrypt`

Decrypt an encrypted secrets file back to plaintext for editing.

```
sanitize decrypt [OPTIONS] <INPUT> <OUTPUT>
```

| Flag / Argument | Description |
|-----------------|-------------|
| `<INPUT>` | Path to encrypted secrets file (`.enc`). |
| `<OUTPUT>` | Path for decrypted plaintext output. |
| `--password` | Prompt interactively for the decryption password. The password is never echoed. For non-interactive automation use `--password-file` or `SANITIZE_PASSWORD` instead. |
| `--password-file <FILE>` | Read the password from a file (must have `0600` or `0400` permissions). |
| `--format <FMT>` | Validate decrypted content as this format (`json`, `yaml`, `toml`). If omitted, raw bytes are written. |
| `-h, --help` | Print help. |

---

## Creating and Formatting a Secrets File

The secrets file defines which patterns to detect and how to categorize matches.

Recommended canonical authoring format: YAML.

Compatibility formats: JSON and TOML remain fully supported for existing workflows and automation.

### Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `pattern` | Yes | — | The string to match. Interpreted as a regex or literal depending on `kind`. For `kind: allow` entries, `*` is treated as a glob wildcard. |
| `kind` | No | `"literal"` | `"regex"` for regular expression matching, `"literal"` for exact string matching, or `"allow"` to pass the value through unchanged (see below). |
| `category` | No | `"custom:secret"` | Controls replacement format. Built-in values: `email`, `name`, `phone`, `ipv4`, `ipv6`, `credit_card`, `ssn`, `hostname`, `mac_address`, `container_id`, `uuid`, `jwt`, `auth_token`, `file_path`, `windows_sid`, `url`, `aws_arn`, `azure_resource_id`. Use `custom:<tag>` for arbitrary categories. Ignored for `kind: allow` entries. |
| `label` | No | Truncated `pattern` | Human-readable label for reporting and statistics. Ignored for `kind: allow` entries. |

### YAML format (canonical)

```yaml
- pattern: "alice@corp\\.com"
  kind: regex
  category: email
  label: alice_email

- pattern: "sk-proj-abc123secret"
  kind: literal
  category: "custom:api_key"
  label: openai_key
```

### Allowlist entries (`kind: allow`)

Use `kind: allow` to suppress specific values from sanitization. A value matching an allow entry passes through the output unchanged and is **not** recorded in the mapping store — so it will not be propagated as a discovered literal in Phase 2.

`pattern` supports exact strings and `*` glob wildcards (same as `--allow`). `category` and `label` are ignored.

```yaml
# Exact match — the literal string "localhost" is never replaced:
- pattern: "localhost"
  kind: allow

# Glob — any hostname ending with ".internal" passes through:
- pattern: "*.internal"
  kind: allow

# Glob — any IP in the 192.168.1.0/24 range passes through:
- pattern: "192.168.1.*"
  kind: allow

# Prefix+suffix glob — internal test accounts are not redacted:
- pattern: "user-*@corp.com"
  kind: allow
```

`kind: allow` entries can be freely mixed with `kind: regex` and `kind: literal` entries in the same file. They are filtered out before the scanner is built, so they have no effect on pattern matching — only on the replacement gate inside the mapping store.

Equivalent via CLI (for ad-hoc runs without editing the secrets file):

```bash
sanitize data.log -s secrets.yaml \
  --allow localhost \
  --allow "*.internal" \
  --allow "192.168.1.*"
```

Both sources are merged: patterns from `kind: allow` entries in the secrets file are combined with `--allow` values from the command line.

### JSON format (compatibility)

```json
[
  {
    "pattern": "alice@corp\\.com",
    "kind": "regex",
    "category": "email",
    "label": "alice_email"
  },
  {
    "pattern": "sk-proj-abc123secret",
    "kind": "literal",
    "category": "custom:api_key",
    "label": "openai_key"
  }
]
```

### TOML format (compatibility)

```toml
[[secrets]]
pattern = "alice@corp\\.com"
kind = "regex"
category = "email"
label = "alice_email"

[[secrets]]
pattern = "sk-proj-abc123secret"
kind = "literal"
category = "custom:api_key"
label = "openai_key"
```

> **Note on regex patterns:** When `kind` is `"regex"`, the `pattern` field is compiled as a Rust regular expression. Metacharacters (`.`, `*`, `+`, `?`, `(`, `)`, `[`, `]`, `{`, `}`, `\`, `^`, `$`, `|`) must be escaped with a backslash to match literally. When `kind` is `"literal"`, the pattern is treated as exact text — no manual escaping is needed.

At runtime, literal patterns are matched by an Aho-Corasick automaton (single multi-literal scan), while regex patterns are matched via `RegexSet` pre-filtering plus per-pattern regex scans. Each match triggers a one-way replacement through the `MappingStore`, formatted according to the pattern's category.

---

## Examples

**Sanitize a single file (interactive password prompt):**

```bash
sanitize data.log -s secrets.enc --encrypted-secrets --password
```

**Structured field-level sanitization with a profile:**

```bash
# Sanitize only the password and username fields in config YAML files:
sanitize config.yaml -s secrets.yaml --profile profile.yaml

# Process a config file and log file together:
# values found in config.yaml are also replaced in app.log
sanitize config.yaml app.log --profile profile.yaml -s secrets.yaml
```

**Deterministic mode with profile (saves discovered values to secrets file):**

```bash
# First run: discovers "hunter2" as a password, appends it to secrets.yaml
SANITIZE_PASSWORD=secret sanitize config.yaml \
  --profile profile.yaml --deterministic --secrets-file secrets.yaml

# Second run against a log: "hunter2" is now in secrets.yaml and gets
# the same replacement as in the first run
SANITIZE_PASSWORD=secret sanitize app.log \
  --deterministic --secrets-file secrets.yaml
```

**Deterministic mode (same seed → same replacements every run):**

```bash
sanitize data.csv -s s.enc --encrypted-secrets --password -d
```

**Process a tar.gz archive with strict error handling:**

```bash
sanitize backup.tar.gz -s s.enc --encrypted-secrets --password -o backup.sanitized.tar.gz --strict
```

**Filter archive entries — keep only files under a specific path:**

```bash
# Exact full path (paths are stored as-is inside the archive, e.g. test/test.config):
sanitize test.zip --only test/test.config -s secrets.yaml

# Keep all JSON files at any depth (**/ crosses directory boundaries):
sanitize backup.zip --only '**/*.json' -s secrets.yaml

# Keep an entire directory subtree (trailing / = directory-prefix match):
sanitize backup.zip --only 'config/' -s secrets.yaml

# Drop all log files:
sanitize backup.zip --exclude '**/*.log' -s secrets.yaml

# Combine: keep JSON files, then drop the secrets file:
sanitize backup.zip --only '**/*.json' --exclude config/secrets.json -s secrets.yaml
```

**Per-archive filters — each archive in a multi-input command is filtered independently:**

```bash
# a.zip keeps only config/; b.tar.gz keeps only *.log files:
sanitize a.zip --only 'config/' b.tar.gz --only '**/*.log' -s secrets.yaml

# Plain file alongside a filtered archive:
sanitize report.txt backup.zip --only 'logs/' -s secrets.yaml
# Produces: report-sanitized.txt  backup.sanitized.zip (logs/ entries only)
```

**Mix stdin with file and archive inputs:**

```bash
# stdin goes to stdout; each file/archive gets its own output file:
cat extra.log | sanitize - backup.zip --only 'logs/' config.yaml -s secrets.yaml
```

**Dry-run — see what would be replaced without writing output:**

```bash
sanitize config.yaml -s s.enc --encrypted-secrets --password -n
```

**Fail CI if secrets are detected:**

```bash
sanitize config.yaml -s s.enc --encrypted-secrets -P /run/secrets/pw --fail-on-match
```

**Extract error context into the JSON report (for LLM triage):**

```bash
# Basic: report gets a log_context block per file with default keywords and 10 lines of context.
sanitize app.log -s secrets.yaml --report report.json --extract-context

# Multiple files: each file gets its own log_context in the report.
sanitize app.log worker.log -s secrets.yaml --report report.json --extract-context

# Custom context window and extra keywords:
sanitize app.log -s secrets.yaml --report report.json \
  --extract-context --context-lines 20 --context-keywords timeout,oomkilled,backoff

# Pipe stdin and capture context (output to file required when input > 256 MiB):
cat app.log | sanitize -s secrets.yaml --report - --extract-context

# Only keywords you care about (replaces defaults entirely):
sanitize app.log -s secrets.yaml --report report.json \
  --extract-context --context-keywords fatal,critical --context-keywords-only
```

**Report JSON — `log_context` shape** (present per file when `--extract-context` is used):

```json
{
  "path": "app.log",
  "matches": 3,
  "replacements": 3,
  "bytes_processed": 10240,
  "bytes_output": 10240,
  "pattern_counts": { "kael_email": 2 },
  "method": "scanner",
  "log_context": {
    "total_lines": 1500,
    "match_count": 2,
    "truncated": false,
    "matches": [
      {
        "line_number": 42,
        "keyword": "error",
        "line": "2026-05-01T10:00:05Z ERROR db: connection timeout",
        "before": ["2026-05-01T10:00:04Z INFO  executing query"],
        "after":  ["2026-05-01T10:00:06Z INFO  retrying connection"]
      }
    ]
  }
}
```

`log_context` is omitted entirely from a file entry when `--extract-context` was not used. `truncated: true` means `--max-context-matches` (default 50) was hit before the end of the file — increase `--max-context-matches`, not `--context-lines`. Truncation is about total match count, not window size.

**Read password from a file (avoids shell history and /proc exposure):**

```bash
sanitize data.log -s s.enc --encrypted-secrets -P /run/secrets/pw
```

**Custom chunk size for memory-constrained environments:**

```bash
sanitize huge.log -s s.enc --encrypted-secrets --password --chunk-size 262144
```

**JSON-structured logs for SIEM ingestion:**

```bash
sanitize data.log -s s.enc --encrypted-secrets --password --log-format json
```

**Use a plaintext secrets file (default — no password needed):**

```bash
# Plaintext YAML/JSON/TOML is the default — just point at the file:
sanitize data.log -s secrets.yaml
sanitize data.log -s secrets.json

# Deterministic mode with plaintext secrets:
sanitize data.csv -s secrets.yaml -d

# Fail CI with plaintext secrets:
sanitize config.yaml -s secrets.yaml --fail-on-match
```

**Use an encrypted secrets file (opt-in with `--encrypted-secrets`):**

```bash
# Interactive password prompt:
sanitize data.log -s secrets.enc --encrypted-secrets --password

# Password from file (CI-friendly):
sanitize data.log -s secrets.enc --encrypted-secrets -P /run/secrets/pw

# Password from environment variable:
SANITIZE_PASSWORD=hunter2 sanitize data.log -s secrets.enc --encrypted-secrets
```

**Encrypted secrets file workflow:**

```bash
# 1. Create a plaintext secrets file (JSON):
cat > secrets.json <<'EOF'
[
  {"pattern": "alice@corp\\.com", "kind": "regex", "category": "email", "label": "alice_email"},
  {"pattern": "sk-proj-abc123secret", "kind": "literal", "category": "custom:api_key", "label": "openai_key"}
]
EOF

# 2. Encrypt it:
sanitize encrypt secrets.json secrets.json.enc --password

# 3. Remove the plaintext:
rm secrets.json

# 4. Use the encrypted file (interactive prompt):
sanitize data.log -s secrets.json.enc --encrypted-secrets --password

# 5. Decrypt to edit later:
sanitize decrypt secrets.json.enc secrets.json --password
```

> **Security note:** `-p` / `--password` triggers a secure interactive prompt (masked input, no shell history). All password inputs (`-p`, `-P`, `SANITIZE_PASSWORD`) require `--encrypted-secrets`. For non-interactive automation use `-P` / `--password-file` or the `SANITIZE_PASSWORD` environment variable.
