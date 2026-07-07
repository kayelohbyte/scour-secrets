# CLI Reference

> For MCP server setup, tool parameters, and JSON call examples, see [mcp.md](mcp.md).

## Configuration

`scour-secrets` reads three layered config sources on every run before CLI flags are applied.

### Directory layout

```
~/.config/scour-secrets/             # global per-user
  secrets.yaml                  # default pattern set — auto-created on first plain run
  settings.yaml                 # global flag defaults — created by `scour-secrets init-hook`
  apps/<name>/                  # custom or copied-and-edited app bundles
    secrets.yaml
    profile.yaml

<project>/.scour-secrets.yaml        # per-project flag defaults — found by walking up from cwd
```

Path resolution:

- **Unix/macOS** — `$XDG_CONFIG_HOME/sanitize/`, falling back to `~/.config/scour-secrets/`.
- **Windows** — `%APPDATA%\sanitize\`, falling back to `%USERPROFILE%\.config\sanitize\`.

### Apply order (lowest → highest precedence)

1. Built-in defaults
2. Global `~/.config/scour-secrets/settings.yaml`
3. Project `.scour-secrets.yaml`
4. CLI flags

List fields (`app`, `allow`, `exclude_path`, `include_path`, `context_keywords`) merge **additively** across all layers. Scalar fields use last-wins replacement.

For the full `settings.yaml` key reference and an annotated example, see the [Settings file](#settings-file) section under `scour-secrets install-hook`. For `.scour-secrets.yaml`, see [Project config (`.scour-secrets.yaml`)](#project-config-sanitizeyaml). For the custom apps directory, see [`scour-secrets apps`](#sanitize-apps).

### Environment variables

| Variable | Effect |
|----------|--------|
| `XDG_CONFIG_HOME` | Overrides `~/.config` for the config dir base (Unix/macOS). |
| `SCOUR_SECRETS_APPS_DIR` | Overrides the apps directory (default: `<config-dir>/apps/`). |
| `SCOUR_SECRETS_CONFIG` | Explicit path to a project config file; overrides the cwd-walk. |
| `SCOUR_SECRETS_NO_CONFIG=1` | Skip project `.scour-secrets.yaml` loading entirely. |
| `SCOUR_SECRETS_NO_SETTINGS=1` | Skip global `settings.yaml` loading entirely. |
| `SCOUR_SECRETS_LOG` | Default log level when `--log-level` is not passed (`off`, `error`, `warn`, `info`, `debug`, `trace`). |
| `SCOUR_SECRETS_PASSWORD` | Decryption password for encrypted secrets files (non-interactive alternative to `-p` / `--password-file`). |
| `SCOUR_SECRETS_LLM_ENDPOINT` / `SCOUR_SECRETS_LLM_MODEL` / `SCOUR_SECRETS_LLM_KEY` | Defaults for `--llm-endpoint` / `--llm-model` / `--llm-key`. |
| `SCOUR_SECRETS_SKIP=1` | Inside an installed git hook, bypass scanning for one commit or push. |

`SCOUR_SECRETS_SECRETS_DIR` is **MCP-only** — it configures the MCP server's per-namespace secret store, not the CLI. See [docs/mcp.md](mcp.md).

---

## `scour-secrets`

```
scour-secrets [OPTIONS] [INPUT]...
command | scour-secrets [OPTIONS]
scour-secrets scan [OPTIONS] [INPUT]...
scour-secrets test-pattern [OPTIONS] [VALUE]...
scour-secrets init-hook [OPTIONS]
scour-secrets show-config
scour-secrets install-hook [OPTIONS]
scour-secrets apps
scour-secrets apps add <NAME> [OPTIONS]
scour-secrets apps remove <NAME> [OPTIONS]
scour-secrets apps dir
scour-secrets allow-test --allow <PATTERN>... [VALUE]...
scour-secrets template [PRESET]
scour-secrets encrypt [OPTIONS] <INPUT> <OUTPUT>
scour-secrets decrypt [OPTIONS] <INPUT> <OUTPUT>
```

The default mode (no subcommand) sanitizes one or more files and archives. Multiple `INPUT` paths may be given in a single invocation and may mix plain files, structured files, and archives freely. When `INPUT` is omitted, data is read from stdin; use `-` to include stdin alongside file paths. Use `encrypt` / `decrypt` subcommands to manage encrypted secrets files.

### `scour-secrets apps`

Manage app bundles: list available bundles, install custom ones, remove them, or show the storage directory.

```
scour-secrets apps
scour-secrets apps add <NAME> [OPTIONS]
scour-secrets apps remove <NAME> [OPTIONS]
scour-secrets apps edit <NAME>
scour-secrets apps dir
```

#### `scour-secrets apps` (list)

Prints built-in and user-defined bundles. Use the name with `--app` to load the bundle.

```bash
scour-secrets apps
# Built-in app bundles (use with --app <name>):
#
#   ansible            Ansible — group_vars, host_vars, vault credentials
#   aws-cli            AWS CLI — ~/.aws/credentials, ~/.aws/config access keys
#   bruno              Bruno — .bru collections and OpenCollection YAML (Bruno 3.0+) credentials
#   circleci           CircleCI — .circleci/config.yml job/step environment variables, docker auth
#   datadog            Datadog Agent — datadog.yaml API keys, proxy credentials, SNMP auth, cluster agent tokens
#   django             Django — .env files, SECRET_KEY, database credentials, third-party API keys
#   docker-compose     Docker Compose — compose.yml environment variables, image credentials
#   elasticsearch      Elasticsearch — elasticsearch.yml, Kibana/Logstash credentials
#   fstab              fstab — /etc/fstab CIFS/SMB credentials, NFS and iSCSI server addresses
#   github-actions     GitHub Actions — workflow env vars, step inputs, container registry credentials
#   gitlab             GitLab — CI/CD logs, runner output, .gitlab-ci.yml variables
#   grafana            Grafana — grafana.ini admin credentials, provisioning datasource secrets
#   har                HAR (HTTP Archive) — browser-captured request/response traffic, auth headers, cookies
#   heroku             Heroku — app.json env values, add-on credentials (Postgres, Redis, SendGrid…)
#   insomnia           Insomnia — workspace exports, request auth, environment variables
#   kubernetes         Kubernetes — kubeconfig credentials, Secret manifests, Helm values
#   laravel            Laravel — .env files, APP_KEY, Pusher, Passport, Stripe secrets
#   mongodb            MongoDB — mongod.conf TLS passwords, .env connection strings
#   mysql              MySQL / MariaDB — my.cnf credentials, .env DATABASE_URL
#   nginx              Nginx — nginx.conf virtual hosts, proxy upstreams, access/error logs
#   postgresql         PostgreSQL — postgresql.conf, connection strings, pg logs
#   postman            Postman — collection credentials, environment variables, auth configs
#   rails              Ruby on Rails — database.yml, .env, config/secrets.yml
#   redis              Redis — redis.conf requirepass/masterauth, .env credentials
#   splunk             Splunk — outputs.conf, inputs.conf, authentication.conf credentials
#   spring-boot        Spring Boot — application.yml, application.properties, datasource credentials
#   terraform          Terraform — *.tfvars variable files, terraform.tfstate sensitive outputs

# Use a single bundle:
scour-secrets config.rb --app gitlab -s patterns.yaml

# Combine multiple bundles in one run:
scour-secrets nginx.conf gitlab.rb --app nginx,gitlab

# Combine a bundle with a custom patterns file and profile:
scour-secrets config.rb server.log --app gitlab -s extra-patterns.yaml --profile custom.profile.yaml
```

Each app bundle includes:
- A set of secrets patterns compiled into the scanner alongside any `--secrets-file` patterns.
- A structured field profile merged with any `--profile` you supply.

#### `scour-secrets apps add`

Install a custom app bundle from local YAML files. At least one of `--profile` or `--secrets` must be supplied. Both files are validated before anything is written to disk.

```
scour-secrets apps add <NAME> [--profile FILE] [--secrets FILE] [--overwrite]
```

| Flag | Description |
|------|-------------|
| `<NAME>` | Bundle name (letters, digits, hyphens, underscores; must start with a letter or digit). |
| `--profile <FILE>` | Path to a profile YAML file (`Vec<FileTypeProfile>`). |
| `--secrets <FILE>` | Path to a secrets YAML file (`Vec<SecretEntry>`). |
| `--overwrite` | Replace an existing custom bundle with the same name. |

```bash
# Install from a profile and a secrets file:
scour-secrets apps add elastic \
  --profile elastic.profile.yaml \
  --secrets elastic.secrets.yaml

# Profile only (no scanner patterns):
scour-secrets apps add myapp --profile myapp.profile.yaml

# Secrets only (no structured field rules):
scour-secrets apps add myapp --secrets myapp.secrets.yaml

# Replace an existing custom bundle:
scour-secrets apps add elastic --profile elastic.profile.yaml --overwrite

# Use it immediately after installing:
scour-secrets server.log --app elastic
```

The bundle is stored under the user apps directory (see `scour-secrets apps dir`). The first `# comment` line of either YAML file becomes the description shown in `scour-secrets apps`.

#### `scour-secrets apps remove`

Remove a custom app bundle. Built-in bundles cannot be removed.

```
scour-secrets apps remove <NAME> [--yes]
```

| Flag | Description |
|------|-------------|
| `<NAME>` | Name of the custom bundle to remove. |
| `--yes` / `-y` | Confirm removal. Required — the command refuses to delete without it. |

```bash
# Remove a custom bundle (--yes required):
scour-secrets apps remove elastic --yes

# Short form:
scour-secrets apps remove elastic -y
```

#### `scour-secrets apps dir`

Print the path to the user apps directory. Bundles are stored one subdirectory per app name.

```bash
scour-secrets apps dir
# /Users/alice/.config/sanitize/apps

# Override the location with an environment variable:
SCOUR_SECRETS_APPS_DIR=/opt/sanitize/apps scour-secrets apps dir
```

#### `scour-secrets apps edit`

Copy a built-in app bundle's YAML files into the user apps directory so you can customise them. Opens the copied files in `$EDITOR` (or `$VISUAL`) if one is set.

```
scour-secrets apps edit <NAME>
```

| Argument | Description |
|----------|-------------|
| `<NAME>` | Name of the built-in bundle to copy (e.g. `rails`, `kubernetes`, `gitlab`). |

```bash
# Copy the built-in rails bundle into the user apps directory for editing:
scour-secrets apps edit rails

# After editing, use the customised bundle like any other:
scour-secrets server.log --app rails
```

The copied files are placed in the user apps directory (see `scour-secrets apps dir`). To revert to the built-in version, remove the user copy with `scour-secrets apps remove <name> --yes`.

You can also drop bundle directories manually without using `scour-secrets apps add`:

```
~/.config/scour-secrets/apps/
  elastic/
    secrets.yaml      # Vec<SecretEntry>
    profile.yaml      # Vec<FileTypeProfile> (optional)
  myapp/
    profile.yaml
```

The directory name is the app name. `SCOUR_SECRETS_APPS_DIR` overrides the default location. User-defined bundles take precedence over built-in bundles with the same name.

### `scour-secrets init-hook`

One-time repo setup. Creates the persistent settings file and installs a git hook in the current repository. The global secrets file (`~/.config/scour-secrets/secrets.yaml`) is created automatically on the first plain `scour-secrets` run — no explicit setup needed for that.

Config directory locations:
- **Unix/macOS**: `$XDG_CONFIG_HOME/sanitize/` → `~/.config/scour-secrets/`
- **Windows**: `%APPDATA%\sanitize\` → `%USERPROFILE%\.config\sanitize\`

```
scour-secrets init-hook [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--hook <pre-commit\|pre-push>` | Git hook to install (default: `pre-commit`). |
| `--mode <scan\|sanitize>` | `scan` (default) blocks the commit if secrets are found. `scour-secrets` rewrites staged files in place. |
| `--global` | Install the hook globally for all repositories on this machine. |
| `-f, --force` | Overwrite existing settings file and hook without prompting. |
| `--dry-run` | Print what would be created without writing any files. |

```bash
# Create settings file + install pre-commit hook:
scour-secrets init-hook

# Hook that sanitizes staged files in place instead of blocking:
scour-secrets init-hook --mode sanitize

# Install a pre-push hook instead:
scour-secrets init-hook --hook pre-push

# Install globally for every repository on this machine:
scour-secrets init-hook --global

# Preview without writing:
scour-secrets init-hook --dry-run

# Recreate files (e.g. after a tool upgrade):
scour-secrets init-hook --force
```

---

### `scour-secrets scan`

Scan files for secrets without modifying them. Exits with code 2 if any matches are found, 0 if the input is clean. Equivalent to running the default mode with `--dry-run --fail-on-match`, but discoverable as a dedicated subcommand designed for CI.

```
scour-secrets scan [OPTIONS] [INPUT]...
```

| Flag | Description |
|------|-------------|
| `[INPUT]...` | Files, directories, or archives to scan. Omit to read from stdin. |
| `-s, --secrets-file <FILE>` | Secrets file to match against. |
| `--encrypted-secrets` | Secrets file is AES-256-GCM encrypted. |
| `-p, --password` | Prompt for decryption password interactively. |
| `-P, --password-file <FILE>` | Read decryption password from a file (0600/0400 only). |
| `--app <APPS>` | App bundle(s) to load. Comma-separated. Repeatable. |
| `--allow <PATTERN>` | Allow values through unchanged. Repeatable. Supports exact strings, `*` glob wildcards, and `regex:<pattern>` for full regex matching. |
| `--profile <FILE>` | Field-level profile for structured files. Requires `--secrets-file`. |
| `--hidden` | Walk hidden files and directories. |
| `--exclude-path <GLOB>` | Exclude paths by glob pattern during directory walks. Repeatable. |
| `--include-path <GLOB>` | Only scan files matching this glob pattern during directory walks. Repeatable. When both `--include-path` and `--exclude-path` match a file, exclusion wins. No effect on explicitly named file arguments. |
| `-r, --report [PATH]` | Write a match report to PATH (or stderr if omitted). |
| `--report-format <FMT>` | Format for `--report` output: `json` (default), `sarif`, or `html`. |
| `--entropy-threshold <THRESHOLD>` | Enable Shannon entropy detection for high-entropy tokens (bits/char, e.g. `4.5`). Off by default. Prints an entropy calibration histogram to stderr (counts only — no token values). |
| `--findings` | Write per-file findings as NDJSON to stdout instead of human-readable log. One JSON object per file plus a summary line. Implies `--progress off`. |
| `--threads <N>` | Worker thread count (default: auto). |
| `--log-format <FMT>` | `human` (default) or `json`. |

**Exit codes:** `0` = clean, `2` = matches found, `1` = error.

**`--findings` flag:** writes per-file findings as NDJSON to stdout instead of human-readable log output. Each line is a self-contained JSON object — one per file, plus a summary line. Implies `--no-progress`. Compatible with `jq`, SIEM ingest, and line-oriented JSON tools.

```
{"type":"file","file":"server.log","matches":3,"clean":false,"patterns":{"aws_access_key":2,"github_pat":1},"bytes_processed":4096}
{"type":"file","file":"clean.log","matches":0,"clean":true,"bytes_processed":512}
{"type":"summary","files":2,"matches":3,"clean":false}
```

```bash
scour-secrets scan server.log -s patterns.yaml                       # scan a file
scour-secrets scan ./logs/ --app gitlab                              # scan a directory
scour-secrets scan . --exclude-path tests/fixtures/                   # skip test fixtures
scour-secrets scan ./logs/ --include-path '*.log'                    # only .log files
scour-secrets scan ./support-bundle/ --include-path '**/*.conf' --include-path '**/*.log'
git diff HEAD | scour-secrets scan -s patterns.yaml                  # scan a patch

# Machine-readable output:
scour-secrets scan ./logs/ --app gitlab --findings
scour-secrets scan ./logs/ --app gitlab --findings | jq 'select(.type=="file" and .clean==false)'
scour-secrets scan ./logs/ --app gitlab --findings | jq -r 'select(.type=="summary") | .matches'
```

---

### `scour-secrets test-pattern`

Test whether secrets patterns match example values. Useful when authoring custom entries in a secrets file — shows exactly which pattern matched, the matched span, and which part would be replaced versus preserved.

```
scour-secrets test-pattern [OPTIONS] [VALUE]...
```

| Flag | Description |
|------|-------------|
| `-P, --pattern <REGEX>` | Inline regex to test. Repeatable. |
| `-s, --secrets-file <FILE>` | Test all patterns from this file. |
| `--app <APPS>` | Test patterns from app bundle(s). |
| `[VALUE]...` | Example strings to test. Omit to read from stdin (one per line). |
| `--json` | Output results as JSON. |

All three pattern sources are additive — you can combine `--pattern`, `--secrets-file`, and `--app` in one invocation.

**Output:** Each value is printed with ✓ (matched) or ✗ (no match). For matches, the label, category, matched text, and byte span are shown. When a pattern uses capture group 1, the output notes "partial — prefix/suffix preserved" to show that the surrounding context would be kept verbatim.

**Exit codes:** `0` = all values matched at least one pattern, `1` = one or more values unmatched (useful for scripting).

```bash
# Test an inline pattern:
scour-secrets test-pattern --pattern 'ghp_([A-Za-z0-9_]{36})' 'ghp_abc123...'

# Test all patterns in a patterns file:
scour-secrets test-pattern -s patterns.yaml 'my-secret' 'safe-value'

# Test an app bundle's patterns:
scour-secrets test-pattern --app gitlab 'glpat-abc123xyz'

# Read values from stdin:
echo 'AKIA1234567890ABCDEF' | scour-secrets test-pattern --app aws

# JSON output for scripting:
scour-secrets test-pattern -s patterns.yaml --json 'value1' 'value2'
```

---

### `scour-secrets show-config`

Print the effective configuration that will apply on the next `scour-secrets` run: the global secrets and settings files, the project-level `.scour-secrets.yaml` (if any), and which values are active versus using their defaults.

```
scour-secrets show-config
```

No flags.

```bash
scour-secrets show-config
SCOUR_SECRETS_NO_SETTINGS=1 scour-secrets show-config   # see a no-settings invocation
SCOUR_SECRETS_NO_CONFIG=1   scour-secrets show-config   # see without project config
```

#### Startup config summary

When running in interactive mode (`--progress auto` on a TTY or `--progress on`), `scour-secrets` automatically prints a brief configuration summary to stderr showing which secrets file, profile, and apps are active. Settings that came from `settings.yaml` or `.scour-secrets.yaml` rather than the CLI are annotated with `[config]`. This output is silent in pipe and script contexts.

Example:

```
  secrets:  /home/user/.config/scour-secrets/secrets.yaml
  profile:  /repo/.sanitize/k8s-profile.yaml  [config]
  apps:     k8s, database  [config]
  flags:    --strict  [config]
```

---

### `scour-secrets install-hook`

Install a git hook that scans staged files for secrets before each commit (or push). The default secrets file is created automatically on the first plain `scour-secrets` run — no prior setup required. The installed script is plain POSIX sh — no external dependencies beyond `scour-secrets` itself. If `scour-secrets` is not in PATH the hook silently passes so teammates who haven't installed the tool are unaffected.

**Windows note:** The hook script uses POSIX sh syntax and requires [Git for Windows](https://git-scm.com/download/win) (which bundles Git Bash). It will not execute under cmd.exe or PowerShell directly. Git for Windows is the standard git installation on Windows and executes hooks via its bundled shell automatically.

```
scour-secrets install-hook [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--hook <pre-commit\|pre-push>` | Git hook to install (default: `pre-commit`). |
| `--mode <scan\|sanitize>` | `scan` (default) blocks the commit if secrets are found without modifying anything. `scour-secrets` rewrites staged files in place and re-stages them — committed content will differ from what you typed. |
| `--app <NAMES>` | Comma-separated app bundles to load in addition to the default secrets file (e.g. `gitlab,kubernetes`). |
| `-s, --secrets <FILE>` | Path to a custom secrets file to bake into the hook (overrides the auto-loaded default). |
| `--global` | Install globally for all repositories via `~/.config/git/hooks/` (or the value of `git config --global core.hooksPath`). |
| `-f, --force` | Overwrite an existing hook without prompting. |
| `--remove` | Remove a hook previously installed by `scour-secrets install-hook`. |
| `--dry-run` | Print the script that would be written without touching any files. |

```bash
# Most common setup — default secrets file is auto-created on first run:
scour-secrets install-hook

# Add app bundles on top of the default patterns:
scour-secrets install-hook --app gitlab,kubernetes

# Use a custom patterns file instead of the default:
scour-secrets install-hook -s .sanitize/patterns.yaml

# Sanitize staged files in place (they'll be modified before committing):
scour-secrets install-hook --mode sanitize

# Install a pre-push hook instead:
scour-secrets install-hook --hook pre-push

# Install globally for every repository on this machine:
scour-secrets install-hook --global

# Preview what would be written without installing:
scour-secrets install-hook --dry-run

# Uninstall:
scour-secrets install-hook --remove
scour-secrets install-hook --hook pre-push --remove   # remove a pre-push hook
scour-secrets install-hook --global --remove          # remove a global hook
```

#### Settings file

Created by `scour-secrets init-hook`. Provides persistent defaults for CLI flags — values here apply when the corresponding flag is not passed on the command line. An explicit CLI flag always wins.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `app` | list of strings | `[]` | App bundles to load on every run. Equivalent to passing `--app` each time. |
| `allow` | list of strings | `[]` | Values to pass through unchanged. Supports exact strings, `*` glob wildcards, and `regex:<pattern>`. Merged with `--allow` on the CLI. |
| `fail_on_match` | bool | `false` | Exit with code 2 when any match is found. Equivalent to `--fail-on-match`. |
| `strict` | bool | `false` | Abort on the first error instead of skipping and continuing. Equivalent to `--strict`. |
| `no_structured_handoff` | bool | `false` | Suppress the Phase 1 → Phase 2 value handoff (discovered field values are not seeded into the scanner). Equivalent to `--no-structured-handoff`. |
| `no_field_signal` | bool | `false` | Disable the field-name entropy heuristic. When active, key names matching sensitive keywords (`password`, `secret`, `token`, …) are flagged by their value's Shannon entropy even without an explicit `FieldRule`. Default thresholds: 3.0 bits/char for strong keywords, 3.5 for ambiguous ones. Equivalent to `--no-field-signal`. |
| `threads` | integer | auto | Worker thread count. Omit or set to `null` for auto-detect. Equivalent to `--threads`. |
| `log_format` | string | `"human"` | Log output format: `"human"` or `"json"` for SIEM ingestion. Equivalent to `--log-format`. |
| `log_level` | string | `"warn"` | Log verbosity: `"off"`, `"error"`, `"warn"`, `"info"`, `"debug"`, or `"trace"`. Overridden by the `SCOUR_SECRETS_LOG` env var. Equivalent to `--log-level`. |
| `no_progress` | bool | `false` | Disable progress output. Equivalent to `--no-progress`. |

```yaml
# ~/.config/scour-secrets/settings.yaml
# All fields are optional — uncomment and edit to activate.

# Load these app bundles on every run (--app).
# app:
#   - gitlab
#   - kubernetes

# Values that pass through unchanged (--allow).
# Supports exact strings, * glob wildcards, and regex:<pattern> for regex matching.
# allow:
#   - localhost
#   - "*.internal"
#   - "regex:^10\\.[0-9]+\\.[0-9]+\\.[0-9]+$"

# Exit with code 2 when any secrets are found (--fail-on-match).
# fail_on_match: false

# Abort on the first error instead of skipping (--strict).
# strict: false

# Suppress the structured-to-scanner value handoff (--no-structured-handoff).
# no_structured_handoff: false

# Disable the field-name entropy heuristic (--no-field-signal).
# no_field_signal: false

# Worker thread count — omit for auto-detect (--threads).
# threads: 4

# Log format: "human" (default) or "json" for SIEM ingestion (--log-format).
# log_format: human

# Log level: off, error, warn (default), info, debug, trace (--log-level).
# Override with SCOUR_SECRETS_LOG env var.
# log_level: warn

# Disable progress output (--no-progress).
# no_progress: false
```

Set `SCOUR_SECRETS_NO_SETTINGS=1` to skip loading the settings file entirely — useful in CI where you want fully explicit, reproducible behaviour.

#### Project config (`.scour-secrets.yaml`)

Place a `.scour-secrets.yaml` file in any directory (typically the root of a repository). `scour-secrets` searches for it by walking up from the current working directory. Project config is applied **after** `settings.yaml` but **before** CLI flags, so it overrides global defaults while explicit flags still win.

The project config uses the same YAML schema as `settings.yaml` — all behavior fields are valid in both files. Fields that make most sense at project level include `secrets_file`, `profile`, `app`, `allow`, and `exclude_path`.

```yaml
# .scour-secrets.yaml  — project-level config, committed to the repository

# Extra app bundles to load (merged with --app / settings.yaml app).
app:
  - gitlab
  - kubernetes

# Additional allow-list values (merged with --allow / settings.yaml allow).
allow:
  - localhost
  - "*.internal"

# Secrets file path, relative to this file.
# Overrides the global default (~/.config/scour-secrets/secrets.yaml) but is
# itself overridden by --secrets-file on the CLI.
secrets_file: patterns.yaml

# Set to true when the secrets_file above is AES-GCM encrypted.
# encrypted_secrets: false

# Profile YAML for field-level rules, relative to this file.
# profile: sanitize.profile.yaml

# Exit 2 when any match is found (--fail-on-match).
# fail_on_match: false

# Abort on first error instead of skipping (--strict).
# strict: false

# Path-level exclusions — matched relative to this file's location.
# Patterns without a `/` also match the bare filename anywhere in the tree.
# A trailing `/` prunes the entire subtree (no files inside are scanned).
# exclude_path:
#   - "tests/fixtures/"   # fake credentials used in unit tests
#   - "vendor/"           # checked-in dependencies
#   - "**/*.generated.*"  # generated source files
```

**Apply order (lowest to highest precedence):**
1. Built-in defaults
2. `settings.yaml` in the scour-secrets config directory (global, per-machine)
3. `.scour-secrets.yaml` (per-project, committed to the repo)
4. CLI flags (always win)

**Multi-customer use:** create a `.scour-secrets.yaml` in each customer directory pointing to that customer's `secrets_file`. Running `scour-secrets ./customer-a/` picks up `customer-a/.scour-secrets.yaml` automatically.

Override the file path directly with `SCOUR_SECRETS_CONFIG=/path/to/file.yaml`.  
Set `SCOUR_SECRETS_NO_CONFIG=1` to disable project config entirely (useful in CI or when composing flags from multiple repos).

The installed script responds to `SCOUR_SECRETS_SKIP=1 git commit ...` for a one-time override without using `--no-verify` (which would bypass all hooks). The hook detects husky (`.husky/` directory) and writes to the appropriate location. For lefthook and the pre-commit framework it prints instructions for manual integration.

### `scour-secrets allow-test`

Test which values match your allowlist patterns before committing to a full sanitization run.

```
scour-secrets allow-test --allow <PATTERN>... [VALUE]...
```

| Flag / Argument | Description |
|-----------------|-------------|
| `--allow <PATTERN>` | Allowlist pattern to test (repeatable). Supports exact strings, `*` glob wildcards, and `regex:<pattern>` for regex matching. |
| `[VALUE]...` | Values to test. If omitted, values are read from stdin one per line. |
| `--json` | Output results as JSON instead of human-readable text. |
| `-h, --help` | Print help. |

Each value is printed with `✓` (matched — would pass through unchanged) or `✗` (no match — would be replaced), and the matching pattern is shown alongside hits.

```bash
# Test a glob pattern against specific values:
scour-secrets allow-test --allow '*.internal' db.internal github.com staging.db.internal

# ✓  db.internal                               → *.internal
# ✗  github.com                                (no match)
# ✓  staging.db.internal                       → *.internal
#
# 2/3 values allowed

# Test multiple patterns at once:
scour-secrets allow-test \
  --allow localhost \
  --allow '*.internal' \
  --allow '192.168.1.*' \
  db.internal 192.168.1.5 8.8.8.8

# Feed values from a file (one per line):
cut -f3 server.log | sort -u | scour-secrets allow-test --allow '*.internal' --allow localhost

# Machine-readable output for scripting:
scour-secrets allow-test --allow '*.internal' db.internal github.com --json
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

### `scour-secrets template`

Generate a starter secrets-template YAML file for a given use case. The preset
argument is positional (not a flag).

```
scour-secrets template [PRESET] [-o FILE] [--overwrite]
```

| Flag / Argument | Description |
|-----------------|-------------|
| `[PRESET]` | Which template to generate. Default: `balanced`. |
| `-o, --output <FILE>` | Output path. Default: `secrets.template.<preset>.yaml`. |
| `--overwrite` | Overwrite the output file if it already exists. |
| `-h, --help` | Print help. |

**Presets:**

| Preset | Contents |
|--------|----------|
| `balanced` | **(Default)** Mirrors the built-in runtime detection set exactly — the same patterns loaded when no `--secrets-file` is given. The template is fully commented and editable. Use as a baseline for any log type. |
| `aggressive` | Extends `balanced` with high-entropy token detection, bearer/authorization context patterns, and short container IDs. Higher false-positive risk; recommended when over-redaction is acceptable (e.g. before sharing with an LLM). |
| `generic` | Minimal starter: tokens, emails, IPs, hostnames. |
| `web` | Web-app logs: JWTs, session IDs, OAuth tokens, emails, URLs. |
| `k8s` | Kubernetes configs: service-account tokens, namespaces, container IDs. |
| `database` | Database configs: passwords, connection strings (postgres/mysql/mongo/redis), usernames. |
| `aws` | AWS: access key IDs (`AKIA`/`ASIA`), secret access keys, ARNs, account IDs, EC2 instance IDs. |

Templates contain commented-out examples and inline guidance so you can uncomment and adapt the entries you need.

```bash
# Balanced template (default) → secrets.template.balanced.yaml:
scour-secrets template

# Aggressive template for LLM sharing:
scour-secrets template aggressive

# Balanced to a custom path, overwrite if present:
scour-secrets template balanced -o my-secrets.yaml --overwrite

# Kubernetes preset:
scour-secrets template k8s -o k8s-secrets.yaml
```

### Default Mode — Sanitize

When neither `-s`/`--secrets-file` nor `--app` is provided, the built-in pattern set is loaded automatically. It covers API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, GitLab, SendGrid, npm), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM headers, password/secret key=value pairs, and credential URLs — with common allow-patterns so loopback IPs, `localhost`, `example.com`, and similar are never replaced.

| Flag / Argument | Short | Description |
|-----------------|-------|-------------|
| `[INPUT]...` | | One or more paths to sanitize. Any mix of plain files, structured files, and archives is accepted. Omit to read from stdin; use `-` to include stdin alongside file paths. `-` may appear at most once. |
| `-o, --output <FILE>` | `-o` | Output path. For a **single input stream** this is the output file path. For **multiple inputs** this is treated as an output directory (created automatically if absent); output files are written there instead. |}
| `-s, --secrets-file <FILE>` | `-s` | Path to a secrets file. Plaintext (`.json`, `.yaml`, `.toml`) is loaded directly by default. Use `--encrypted-secrets` to decrypt an AES-256-GCM encrypted file. |
| `-p, --password` | `-p` | Trigger an interactive password prompt (masked input, never echoed). Requires `--encrypted-secrets`. Providing this flag without `--encrypted-secrets` is an error. For non-interactive automation use `--password-file` or `SCOUR_SECRETS_PASSWORD` instead. |
| `-P, --password-file <FILE>` | `-P` | Read the decryption password from a file. Requires `--encrypted-secrets`. The file must have permissions `0600` or `0400` (owner-only). Trailing newline is stripped. |
| `--encrypted-secrets` | | Treat the secrets file as AES-256-GCM encrypted and decrypt it before loading. Requires a password via `-p`, `--password-file`, or `SCOUR_SECRETS_PASSWORD`. Without this flag the file is loaded as plaintext. Providing any password input without this flag is an error. |
| `-f, --format <FMT>` | `-f` | Force input format for stdin and for inputs that aren't otherwise typeable (e.g. an extensionless file). A file whose own extension already maps to a structured format keeps that format, so this never forces an accompanying `.yaml`/`.csv`/… file to be misparsed as the stdin format. Values: `text`, `json`, `jsonl`, `yaml`, `yml`, `xml`, `csv`, `tsv`, `key-value`, `toml`, `env`, `ini`, `log`. Required for structured processing when reading from stdin. |
| `-n, --dry-run` | `-n` | Scan and report matches without writing output. |
| `--fail-on-match` | | Exit with code 2 if any matches are found. |
| `-r, --report [PATH]` | `-r` | Write a JSON report to `PATH` (or stderr if no path given). Use `--report -` to write the report to stdout. The report includes: `metadata` (tool version, flags), `summary` (totals, `duration_ms`, `pattern_counts`), and a `files` array with per-file `matches`, `replacements`, byte counts, `pattern_counts`, and `method`. `pattern_counts` maps each pattern `label` to its scanner hit count; it is empty (`{}`) when all matches came from the structured-processor pass or when patterns have no label. |
| `--strict` | | Abort on the first error instead of skipping and continuing. |
| `-d, --deterministic` | `-d` | Use HMAC-deterministic replacements (reproducible across runs with the same password **and** seed salt). Requires a password via `SCOUR_SECRETS_PASSWORD`, `--password-file`, or `-p`. The seed salt is unique per install by default (generated at `<config_dir>/seed-salt`, mode `0600`); see `--seed-salt-file`. |
| `--seed-salt-file <PATH>` | | File whose contents (any length; SHA-256-normalized) are used as the deterministic seed salt. Overrides the per-install salt and the `SCOUR_SECRETS_SEED_SALT` env var. Share this file (or the env var) across machines to reproduce identical deterministic output for a team. Note: 0.16.0 switched the seed KDF to Argon2id, so output is not comparable to pre-0.16.0 runs even with the same salt. |
| `--randomize-length` | | Draw each replacement's length from a per-category band instead of preserving the original's length, so the output no longer leaks how long the secret was. Output stays type-valid (a number stays digits, an email stays an email, a path keeps its extension) and preserved substrings (email domain, file extension, ARN/Azure segments) are unchanged. Canonical-shape categories (UUID, MAC, IPv4/6, container ID, Windows SID, JWT) keep their natural length. Composes with `--deterministic`. See SECURITY.md §4. |
| `--no-structured-handoff` | | Suppress the structured-to-scanner value handoff. By default, when a profile is active (`--profile` or `--app` with a profile) and `--secrets-file` is provided, values discovered in typed fields are appended to that file as `kind: literal` entries so the scanner pass can catch those same values in logs, comments, and unstructured text. The write-back preserves the file's on-disk form: an **encrypted** secrets file is decrypted, merged, and re-encrypted with the same password (never downgraded to plaintext), and JSON/YAML/TOML plaintext files keep their own format; the file is written with `0600` permissions. Disabling this weakens coverage — the scanner will no longer see values that were only found by the structured pass. |
| `--include-binary` | | Process entries that appear to be binary data (default: skip). |
| `--threads <N>` | | Number of worker threads. When multiple input files are given, files are processed in parallel up to this limit. For a single archive input, entries are sanitized in parallel using the same budget. Defaults to the number of logical CPUs. Capped to available parallelism. |
| `--max-archive-depth <N>` | | Maximum nesting depth for recursive archive processing (default: `5`, max: `10`). Each nesting level may buffer up to 256 MiB. Advanced flag — hidden from `--help` but works at runtime. |
| `--profile <FILE>` | | Path to a file-type profile (JSON or YAML). Enables structured field-level sanitization for matched files. **Requires `--secrets-file`** — without one, discovered field values have nowhere to go and Phase 2 runs blind, producing incomplete sanitization. The secrets file may be empty on the first run; discovered literals are appended to it automatically (see `--no-structured-handoff`) so subsequent runs catch those values everywhere. See [Structured Processing](structured-processing.md). |
| `--app <APPS>` | | Load built-in secrets patterns and structured field profiles for one or more applications. Comma-separated app names (e.g. `--app gitlab` or `--app gitlab,nginx`). Additive with `--secrets-file` and `--profile`. Run `scour-secrets apps` to list available app names. |
| `--allow <PATTERN>` | | Allow a specific value through unchanged (repeatable). Matched values are not replaced and not recorded in the mapping store — they will pass through in every file processed in the same run. Supports exact strings and `*` glob patterns. Matching is **case-insensitive** by default (patterns and values are lowercased before comparison). Examples: `--allow localhost`, `--allow "*.internal"`, `--allow "192.168.1.*"`. Allowlist entries can also be placed in the secrets file as `kind: allow` entries. |
| `--quick <PATTERN>` | | Add one-off literal or regex patterns for the current run without touching any secrets file. Comma-separated; prefix individual values with `regex:` to enable regex matching (bare values are treated as literals). Repeatable — `--quick a --quick b` accumulates. Example: `--quick "tok-abc123,regex:sk-[A-Za-z0-9]{40}"`. Replacements use the `auth_token` shape regardless of value type. |
| `--only <PATTERN>` | | Keep only archive entries whose full path matches `PATTERN`. Must follow the archive path it applies to. Multiple `--only` flags accumulate. Combined with `--exclude`: `--only` narrows first, then `--exclude` removes. Only affects archive inputs; ignored for plain files. |
| `--exclude <PATTERN>` | | Remove archive entries whose full path matches `PATTERN`. Must follow the archive path it applies to. Multiple `--exclude` flags accumulate. |
| `--log-format <FMT>` | | Log output format: `human` (default) or `json`. |
| `--progress <MODE>` | | Progress display mode: `auto`, `on`, or `off`. Default: `auto`. |
| `--quiet` | | Suppress the post-run redaction summary and all decorative stderr output. Implies `--progress off`. Use in scripts or pipelines where only the exit code matters. |
| `--no-progress` | | Deprecated. Use `--progress off` instead. Hidden from `--help`. |
| `--extract-context` | | After sanitizing, scan the output for error/warning/failure keywords and embed matching lines with surrounding context in the JSON report. Each file entry in `files[]` gets its own `log_context` object. Requires `--report`. Has no effect without `--report`. For stdout paths larger than 256 MiB the flag is silently skipped (use file output and the two-pass reader path instead). |
| `--context-lines <N>` | | Lines of context to capture before and after each keyword match when `--extract-context` is set. Default: `10`. |
| `--context-keywords <KEYWORDS>` | | Comma-separated list of keywords to scan for when `--extract-context` is set. Merged with the built-in defaults (`error`, `failure`, `warning`, `warn`, `fatal`, `exception`, `critical`) unless `--context-keywords-replace` is also passed. Example: `--context-keywords timeout,oomkilled,backoff`. |
| `--context-keywords-replace` | | Replace the built-in keyword list entirely with the keywords given by `--context-keywords`. Without this flag, custom keywords are merged with the built-ins. Has no effect if `--context-keywords` is not set. |
| `--max-context-matches <N>` | | Maximum number of keyword matches to capture per file when `--extract-context` is set. Default: `50`. Once this cap is hit, `truncated: true` is set in `log_context` and the rest of the file is skipped. Increase this (not `--context-lines`) when you are missing events. |
| `--context-case-sensitive` | | Make keyword matching case-sensitive when `--extract-context` is set. By default keywords are matched case-insensitively (`error` matches `ERROR`, `Error`, etc.). |
| `--findings [PATH]` | | Write per-file findings as NDJSON to PATH (or stdout when PATH is omitted or `-`). Each line is a JSON object: one `{"type":"file",...}` per processed file with match count and per-pattern breakdown, followed by `{"type":"summary",...}`. In default scour-secrets mode, use `--output` to redirect sanitized content so stdout is free for findings. |
| `--entropy-threshold <THRESHOLD>` | | Enable Shannon entropy detection for high-entropy tokens not caught by pattern matching. `THRESHOLD` is bits per character (e.g. `4.5`). Tokens of 20–200 alphanumeric characters whose entropy meets or exceeds this value are treated as secrets. Off by default. Supplement with `kind: entropy` entries in the secrets file for finer control. In `--dry-run` / `scour-secrets scan` mode, prints an entropy calibration histogram to stderr (counts only — no token values) so you can tune the threshold before committing to a full run. See "Entropy Calibration Histogram" below. |
| `--hidden` | | When an input is a directory, also walk hidden files and directories (names starting with `.`). VCS metadata directories (`.git`, `.hg`, `.svn`, `.bzr`) are always skipped regardless of this flag. |
| `--exclude-path <GLOB>` | | Exclude paths matching these glob patterns from directory walks (repeatable). Patterns are matched against the path relative to the input root (or against the filename alone when no `/` is present in the pattern). A trailing `/` excludes the entire subtree. Merged with `exclude` entries in `.scour-secrets.yaml`; CLI patterns are applied in addition to, not instead of, project config patterns. Example: `--exclude-path "tests/fixtures/"`. |
| `--include-path <GLOB>` | | Only process files matching these glob patterns during directory walks (repeatable). Patterns use the same rules as `--exclude-path`: matched against the relative path first, then the bare filename when no `/` is present. A trailing `/` includes the entire subtree. When both `--include-path` and `--exclude-path` match a file, exclusion wins. Has no effect on explicitly named file arguments or archive entries. Example: `--include-path "**/*.log" --include-path "**/*.conf"`. |
| `--force-text` | | Bypass all structured processors (JSON, YAML, XML, TOML, etc.) and run only the streaming scanner on every file. Use when you want a guarantee that every byte is pattern-scanned regardless of file type. |
| `--strip-values` | | Strip all values from structured output, emitting only keys and structure. Useful for generating a profile template from a real config file without exposing any values. Bypasses the sanitization pipeline — no secrets file is required. |
| `--strip-delimiter <DELIM>` | | Delimiter string used to split key/value lines when `--strip-values` is set. Default: `=`. Use `--strip-delimiter :` for YAML-style or nginx-style config files. Requires `--strip-values`. |
| `--strip-comment-prefix <PREFIX>` | | Line prefix that marks a comment when `--strip-values` is set. Comment lines are preserved verbatim. Default: `#`. Use `--strip-comment-prefix //` for C-style or nginx-style comment lines. Requires `--strip-values`. |
| `--llm [TEMPLATE]` | | Format the sanitized output as an LLM-ready prompt. Without `--llm-endpoint` the prompt is written to stdout; with `--llm-endpoint` it is sent to the API and the response is streamed to stdout. `TEMPLATE` selects the instruction set: `troubleshoot` (default — incident triage: root cause, event sequence, remediation), `review-config` (configuration review: misconfigurations and best practices), `review-security` (security posture: auth, network exposure, TLS, CVEs, hardcoded secrets), or a path to a custom template file. All built-in templates include a preamble explaining the sanitization model and instructing the LLM to ask clarifying questions rather than guessing at redacted values. Template text uses [caveman compression](https://github.com/wilpel/caveman-compression) to minimise instruction tokens (~45% reduction vs. natural prose) while preserving all semantic content. Combine with `--extract-context` to include notable log events. **Two modes:** without `--output` (inline mode) sanitized content is embedded directly in `<content>` blocks; with `--output` (reference mode) sanitized files are written to disk and the prompt lists their absolute paths — useful for large file sets or agentic LLMs that can read files with their own tools. The prompt is always written to stdout; `--report` still writes its JSON file normally. |
| `--llm-endpoint <URL>` | | Send the `--llm` prompt to an OpenAI-compatible HTTP endpoint instead of printing to stdout. Requires `--llm`. The response is streamed to stdout. Local model example: `http://localhost:11434/v1` (Ollama). Cloud example: `https://api.openai.com/v1`. Set via `SCOUR_SECRETS_LLM_ENDPOINT`. |
| `--llm-model <MODEL>` | | Model name to pass to `--llm-endpoint` (e.g. `phi4-mini`, `gpt-4o`, `llama3`). Required when the endpoint does not infer a model from the path. Set via `SCOUR_SECRETS_LLM_MODEL`. Requires `--llm-endpoint`. |
| `--llm-key <KEY>` | | API key for `--llm-endpoint`. Prefer the `SCOUR_SECRETS_LLM_KEY` environment variable — passing the value on the command line exposes it in process listings. Local models (Ollama, LM Studio) accept any non-empty value. |
| `-h, --help` | `-h` | Print help. |
| `-V, --version` | `-V` | Print version. |

> **Advanced / hidden flags:** `--chunk-size <BYTES>`, `--max-mappings <N>`, `--max-structured-size <BYTES>`, and `--progress-interval-ms <MS>` are performance-tuning flags that still work at runtime but are hidden from `--help`. `--max-archive-depth <N>` is also hidden from `--help` but widely useful (see table row above). Use these only when the defaults are insufficient for your workload.

Log level is controlled via the `SCOUR_SECRETS_LOG` environment variable (e.g. `SCOUR_SECRETS_LOG=debug`).

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
scour-secrets archive.zip --only test/test.config -s patterns.yaml

# Keep only JSON files at any depth:
scour-secrets archive.zip --only '**/*.json' -s patterns.yaml

# Keep only entries under the config/ prefix:
scour-secrets archive.zip --only 'config/' -s patterns.yaml

# Drop all .log files:
scour-secrets archive.zip --exclude '*.log' -s patterns.yaml

# Keep only JSON files, then drop secrets.json:
scour-secrets archive.zip --only '**/*.json' --exclude config/secrets.json -s patterns.yaml

# Keep only JSON files in the root (not subdirectories):
scour-secrets archive.zip --only '*.json' -s patterns.yaml
```

**Multiple archives — each gets its own filter**

```bash
# a.zip keeps only config/, b.tar.gz keeps only *.log files:
scour-secrets a.zip --only 'config/' b.tar.gz --only '**/*.log' -s patterns.yaml

# Mix an archive with a plain file — the plain file is not filtered:
scour-secrets report.txt backup.zip --only 'logs/' -s patterns.yaml

# Mix stdin with an archive filter:
cat extra.log | scour-secrets - backup.zip --only 'logs/' -s patterns.yaml
```

#### Directory Walk Filtering (`--include-path` / `--exclude-path`)

`--include-path` and `--exclude-path` filter which files are processed when a directory is given as input. They apply to files discovered during the recursive walk — not to files named explicitly on the command line.

**Pattern syntax**

| Pattern | Meaning |
|---------|---------|
| `*.log` | Matches any `.log` file anywhere in the tree (bare filename match). |
| `**/*.log` | Matches `.log` files at any depth via relative path. |
| `logs/` | Subtree match: includes (or excludes) `logs/` and everything under it. Trailing `/` required. |
| `vendor/` | Prunes the entire `vendor/` subtree when used with `--exclude-path`. |

**Rules**

- Both flags are **global** — they apply to all directory inputs in the same invocation.
- When `--include-path` and `--exclude-path` both match a file, **exclusion wins**.
- Patterns without a `/` are matched against the bare filename, so `*.log` skips minified files anywhere in the tree without needing a `**/*.log` prefix.
- Neither flag affects explicitly named files or archive entries (`--only` / `--exclude` handle archives).

```bash
# Only process .log files in a directory:
scour-secrets ./logs/ -s patterns.yaml --include-path '*.log'

# Only .conf and .log files anywhere in the tree:
scour-secrets /etc/ -s patterns.yaml --include-path '**/*.conf' --include-path '**/*.log'

# Include a subtree:
scour-secrets ./support-bundle/ -s patterns.yaml --include-path 'app/'

# Include only logs but skip test fixtures (exclusion wins):
scour-secrets ./logs/ -s patterns.yaml --include-path '*.log' --exclude-path 'tests/'

# Exclude a vendor subtree (no include filter — all other files are processed):
scour-secrets . -s patterns.yaml --exclude-path 'vendor/'
```

**Directory expansion feedback**

When a directory input is expanded, `scour-secrets` prints a brief line to stderr before processing begins:

```
  14 files in /etc/nginx/ (3 excluded)
```

This line is suppressed in `--log-format json` mode (the structured `expanding directory input` log event is emitted instead). It is not suppressed by `--dry-run`.

#### Redaction Summary

After every successful run, `scour-secrets` prints a one-line redaction summary to `stderr`:

```
Redacted: 4 email, 2 ipv4, 1 auth_token
```

If nothing was found:

```
Redacted: nothing
```

Counts are sorted by frequency (highest first). In `scour-secrets scan` (dry-run) mode the label reads `Matched:` instead of `Redacted:` since no output is written.

The summary is always printed regardless of `--progress` mode — it appears even in non-TTY and CI contexts where the live spinner is silent. Suppress it with `--quiet` when only the exit code matters (e.g. in scripts).

#### Entropy Calibration Histogram

When `--entropy-threshold` (or `kind: entropy` entries in the secrets file) is active **and** the run is in dry-run mode (`-n` / `scour-secrets scan`), `scour-secrets` prints an entropy calibration histogram to `stderr` after processing:

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

Each row is the count of candidate tokens whose Shannon entropy **met or exceeded** that level. "Candidates examined" is the number of tokens that passed the charset and length filter — a useful denominator for false-positive estimation.

- `← threshold` marks the row matching the configured threshold.
- If the configured threshold does not align with a standard 0.5-bit step, a note is printed below the table.
- If no candidates were found (no token passed the charset/length filter), prints `no candidates found` instead of the table.
- For `kind: entropy` entries with a non-default label, the header shows `Entropy calibration [label_name] — ...`.
- The histogram is always printed to `stderr`, even when `--quiet` is set, because the calibration data is the primary output of a dry-run entropy scan.

This output contains only counts — no token values are ever printed or stored.

Use this to tune your threshold before a full run:

```bash
# See how many tokens exceed each level across all files — no output written:
scour-secrets scan ./logs/ --app gitlab --entropy-threshold 4.5

# Adjust threshold down if too few matches, up if too many:
scour-secrets scan ./logs/ --app gitlab --entropy-threshold 4.0
```

#### Progress Behavior

Progress output is designed to stay safe for pipelines and machine-readable logging:

- Live progress renders on `stderr` only.
- `stdout` remains reserved for sanitized payloads and explicit report output.
- In `auto` mode, live progress is disabled when `stderr` is not a TTY, when `TERM=dumb`, when `CI` is set, or when `--log-format json` is active.
- In `json` log mode, spinner frames are suppressed so logs remain parseable.
- `--progress on` forces progress reporting, but non-interactive environments fall back to milestone-style status instead of a live spinner.
- `--quiet` suppresses both the redaction summary and all progress output. Implies `--progress off`.

Examples:

```bash
# Default behavior: spinner in interactive terminals, silent in CI/non-TTY.
# Redaction summary always prints to stderr.
scour-secrets large.log -s patterns.enc --encrypted-secrets --password

# Force progress messages even in non-interactive environments.
scour-secrets large.log -s patterns.enc --encrypted-secrets --password --progress on

# Suppress all decorative output (summary + progress). Exit code only.
scour-secrets large.log -s patterns.enc --encrypted-secrets --password --quiet

# Redirect sanitized payload and progress separately.
scour-secrets large.log -s patterns.enc --encrypted-secrets --password --progress on > clean.log 2> progress.log

# Keep machine-readable JSON logs clean (no spinner frames).
scour-secrets large.log -s patterns.enc --encrypted-secrets --password --log-format json --progress on > clean.log 2> events.jsonl
```

#### Output Naming

When no `--output` is given, the output location depends on the input type:

| Input type | Default output |
|------------|----------------|
| Plain / structured file (`foo.txt`, `a.json`) | `<stem>-sanitized.<ext>` next to the source — e.g. `foo-sanitized.txt` |
| Archive (`data.tar`, `data.tar.gz`, `archive.zip`) | `<stem>.sanitized.<ext>` next to the source — e.g. `data.sanitized.tar.gz` |
| **Directory** (`logs/`, `/etc/nginx/`) | **`<dirname>-sanitized/` peer directory** — tree structure is mirrored inside it. E.g. `scour-secrets logs/` → `logs-sanitized/` with all relative paths preserved. |
| Stdin (no file path) | stdout |

When multiple inputs map to the same computed output name within one run, a numeric suffix is appended automatically (e.g. `same-sanitized-1.txt`, `same-sanitized-2.txt`).

When `--output <PATH>` is given:
- **Single input:** writes to that exact path.
- **Multiple inputs:** `PATH` is treated as a directory. The directory is created if absent. Output files are placed inside it using the per-input naming rules above.
- **Directory input with `--output`:** the tree is mirrored into the specified output directory (same as without `--output`, but under your chosen path).


#### Stdin Support

When no input path is given (or one of the paths is `-`), `scour-secrets` reads from stdin. `-` may be mixed freely with file paths and may appear at most once. Stdin output defaults to stdout unless `--output` is given.

```bash
# Pipe from grep with a plaintext secrets file:
grep "error" server.log | scour-secrets -s patterns.yaml

# Pipe from grep with an encrypted secrets file (use env var since stdin is a pipe):
export SCOUR_SECRETS_PASSWORD="my-password"
grep "error" server.log | scour-secrets -s patterns.enc --encrypted-secrets

# Read from stdin, write to a file (plaintext secrets):
cat data.csv | scour-secrets -s patterns.yaml -f csv -o clean.csv

# Use with heredoc:
scour-secrets -s secrets.json <<< "my secret api-key-12345"
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
cat error.json | scour-secrets config.yaml --profile fields.yaml -s patterns.yaml

# Without --profile, stdin runs immediately (no deferral — no discovery happens)
cat error.json | scour-secrets -s patterns.yaml
```

**Does file order matter?**

In the common case (no `--profile`), all file targets go straight to Phase 2 and run in parallel — command-line order has no effect on results. The mapping store is thread-safe with first-writer-wins semantics, so the same value always receives the same replacement regardless of which file encounters it first.

With `--profile`, Phase 1 files run in command-line order. In practice, order rarely matters because each value has one canonical replacement — the order only affects which file *first* adds a given value to the store, not what the replacement is.

**Cross-file consistency**

The mapping store is shared across all phases and all threads. If `hunter2` is discovered as a password in `config.yaml` (Phase 1), the same replacement is applied everywhere that literal appears — in Phase 2 archives, plain-text logs, and deferred stdin.

```bash
# file order within Phase 2 does not affect replacements:
scour-secrets a.log b.log c.log -s patterns.yaml   # same result as c b a order
```

#### Examples

```bash
# Sanitize a single log file (output goes to data-sanitized.log):
scour-secrets data.log -s patterns.yaml

# Sanitize a directory (output goes to logs-sanitized/, tree structure preserved):
scour-secrets logs/ -s patterns.yaml
# Produces: logs-sanitized/server.log  logs-sanitized/sub/db.log  …

# Sanitize a directory to an explicit output location:
scour-secrets logs/ -s patterns.yaml -o /tmp/clean-logs/

# Sanitize multiple files in one command:
scour-secrets test.txt a.json b.zip -s patterns.yaml
# Produces: test-sanitized.txt  a-sanitized.json  b.sanitized.zip

# Send all sanitized files to a specific output directory:
scour-secrets test.txt a.json b.zip -s patterns.yaml -o /tmp/clean/

# Override output path for a single file:
scour-secrets data.log -s patterns.yaml -o clean.log

# Pipe from grep (plaintext secrets):
grep "error" server.log | scour-secrets -s patterns.yaml

# Mix stdin with file inputs (stdin goes to stdout, files get per-file outputs):
cat extra.txt | scour-secrets - data.log -s patterns.yaml

# Mix stdin with an archive (stdin sanitized to stdout; archive gets its own output file):
cat extra.log | scour-secrets - backup.zip -s patterns.yaml

# Archive and plain file together (each gets its own output file):
scour-secrets backup.zip config.yaml -s patterns.yaml
# Produces: backup.sanitized.zip  config-sanitized.yaml

# Filter archive entries — keep only files under config/:
scour-secrets backup.zip --only 'config/' -s patterns.yaml

# Filter by glob — keep only JSON files at any depth:
scour-secrets backup.zip --only '**/*.json' -s patterns.yaml

# Filter by exact full path (paths are stored as-is inside the archive):
scour-secrets test.zip --only test/test.config -s patterns.yaml

# Combine --only and --exclude: keep JSON, drop secrets file:
scour-secrets backup.zip --only '**/*.json' --exclude config/secrets.json -s patterns.yaml

# Drop all log files from the output archive:
scour-secrets backup.zip --exclude '**/*.log' -s patterns.yaml

# Per-archive filters — each archive has independent --only / --exclude:
scour-secrets a.zip --only 'config/' b.tar.gz --only '**/*.log' -s patterns.yaml

# Plain file alongside a filtered archive:
scour-secrets report.txt backup.zip --only 'logs/' -s patterns.yaml
# Produces: report-sanitized.txt  backup.sanitized.zip (with only logs/ entries)

# Force progress to stderr while keeping stdout pipe-safe:
grep "error" server.log | scour-secrets -s patterns.yaml --progress on > clean.log 2> progress.log

# Structured stdin processing:
cat config.yaml | scour-secrets -s patterns.yaml -f yaml -o clean.yaml

# Encrypted secrets file — requires --encrypted-secrets:
scour-secrets data.log -s patterns.enc --encrypted-secrets --password
scour-secrets data.log -s patterns.enc --encrypted-secrets --password -o clean.log

# Non-interactive pipeline with encrypted secrets (env var):
export SCOUR_SECRETS_PASSWORD="my-password"
grep "error" server.log | scour-secrets -s patterns.enc --encrypted-secrets

# Deterministic mode (reproducible replacements) with encrypted secrets:
scour-secrets data.csv -s s.enc --encrypted-secrets --password -d

# Dry-run (scan only):
scour-secrets config.yaml -s s.enc --encrypted-secrets --password -n

# Fail CI if matches found:
scour-secrets config.yaml -s s.enc --encrypted-secrets -P /run/secrets/pw --fail-on-match

# Read password from a file:
scour-secrets data.log -s s.enc --encrypted-secrets -P /run/secrets/pw

# Extract context from sanitized output (capture surrounding lines for each error/warning):
scour-secrets server.log -s patterns.yaml --report report.json --extract-context

# Increase captured context window from default 10 to 20 lines:
scour-secrets server.log -s patterns.yaml --report report.json --extract-context --context-lines 20

# Increase match cap (default 50) to capture more events before truncation:
scour-secrets server.log -s patterns.yaml --report report.json --extract-context --max-context-matches 200

# Case-sensitive keyword matching (default is case-insensitive):
scour-secrets server.log -s patterns.yaml --report report.json --extract-context --context-case-sensitive

# Custom keywords merged with defaults:
scour-secrets server.log -s patterns.yaml --report report.json --extract-context --context-keywords timeout,oomkilled,backoff

# Use only custom keywords, suppress built-in defaults:
scour-secrets server.log -s patterns.yaml --report report.json --extract-context --context-keywords "timeout,oomkilled" --context-keywords-replace

# Strip values from a key=value config file — no secrets file required:
scour-secrets config.ini --strip-values -o config-stripped.ini

# Strip values using a colon delimiter (e.g. YAML-style or nginx-style configs):
scour-secrets nginx.conf --strip-values --strip-delimiter : -o nginx-stripped.conf

# Strip values with C-style comment lines (// prefix):
scour-secrets app.conf --strip-values --strip-comment-prefix // -o app-stripped.conf

# Generate a sanitized LLM-ready prompt with built-in troubleshoot template:
scour-secrets server.log -s patterns.yaml --llm

# Configuration review:
scour-secrets server.log -s patterns.yaml --llm review-config

# Security posture review:
scour-secrets nginx.conf --app nginx --llm review-security
scour-secrets kubeconfig --app kubernetes --llm review-security

# Use a custom template file:
scour-secrets server.log -s patterns.yaml --llm /path/to/my-template.txt

# Reference mode: write sanitized files to disk, prompt lists absolute paths
# (useful for large file sets or agentic LLMs that read files with their tools):
scour-secrets server.log -s patterns.yaml --llm --output /tmp/sanitized/server.log
scour-secrets logs/ -s patterns.yaml --llm review-security --output /tmp/sanitized/

# Combine LLM output with context extraction for notable events:
scour-secrets server.log -s patterns.yaml --report /tmp/report.json --extract-context --llm troubleshoot

# Send prompt directly to a local Ollama model and stream the response:
scour-secrets server.log -s patterns.yaml --llm troubleshoot \
  --llm-endpoint http://localhost:11434/v1 \
  --llm-model phi4-mini \
  --llm-key any-value

# Send to OpenAI (key from environment variable — preferred):
export SCOUR_SECRETS_LLM_KEY=sk-...
scour-secrets server.log -s patterns.yaml --llm review-security \
  --llm-endpoint https://api.openai.com/v1 \
  --llm-model gpt-4o

# Use --quick for one-off patterns without a secrets file:
scour-secrets deploy.log --quick "tok-abc123,regex:sk-[A-Za-z0-9]{40}"
scour-secrets app.log --quick "regex:AKIA[A-Z0-9]{16}" --quick "my-literal-secret"

# Shannon entropy detection for unrecognized high-entropy tokens:
scour-secrets server.log -s patterns.yaml --entropy-threshold 4.5
scour-secrets server.log -s patterns.yaml --entropy-threshold 4.0 --report report.json

# Exclude paths from a directory walk:
scour-secrets ./logs/ -s patterns.yaml --exclude-path "tests/fixtures/"
scour-secrets ./logs/ -s patterns.yaml --exclude-path "vendor/" --exclude-path "**/*.generated.*"

# Only process specific file types in a directory:
scour-secrets ./support-bundle/ -s patterns.yaml --include-path '*.log'
scour-secrets /etc/ -s patterns.yaml --include-path '**/*.conf' --include-path '**/*.yaml'

# Combine include and exclude (exclusion wins when both match):
scour-secrets ./logs/ -s patterns.yaml --include-path '*.log' --exclude-path "tests/"

# Walk hidden files (dot-files) in a directory:
scour-secrets ./config/ -s patterns.yaml --hidden
scour-secrets . --app gitlab --hidden --exclude-path ".git/"
```

### `scour-secrets encrypt`

Encrypt a plaintext secrets file for use with the sanitizer.

```
scour-secrets encrypt [OPTIONS] <INPUT> <OUTPUT>
```

| Flag / Argument | Description |
|-----------------|-------------|
| `<INPUT>` | Path to plaintext secrets file (`.json`, `.yaml`, `.yml`, `.toml`). |
| `<OUTPUT>` | Path for encrypted output file (`.enc`). |
| `--password` | Prompt interactively for the encryption password. The password is never echoed. For non-interactive automation use `--password-file` or `SCOUR_SECRETS_PASSWORD` instead. |
| `--password-file <FILE>` | Read the password from a file (must have `0600` or `0400` permissions). |
| `--secrets-format <FMT>` | Force input format: `json`, `yaml`, or `toml` (default: auto-detect from extension). |
| `--validate` | Parse plaintext before encrypting and report errors (default). |
| `--no-validate` | Skip pre-encryption validation. |
| `-h, --help` | Print help. |

### `scour-secrets decrypt`

Decrypt an encrypted secrets file back to plaintext for editing.

```
scour-secrets decrypt [OPTIONS] <INPUT> <OUTPUT>
```

| Flag / Argument | Description |
|-----------------|-------------|
| `<INPUT>` | Path to encrypted secrets file (`.enc`). |
| `<OUTPUT>` | Path for decrypted plaintext output. |
| `--password` | Prompt interactively for the decryption password. The password is never echoed. For non-interactive automation use `--password-file` or `SCOUR_SECRETS_PASSWORD` instead. |
| `--password-file <FILE>` | Read the password from a file (must have `0600` or `0400` permissions). |
| `--secrets-format <FMT>` | Validate decrypted content as this format (`json`, `yaml`, `toml`). If omitted, raw bytes are written. |
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

`pattern` supports three forms (same as `--allow`): exact strings, `*` glob wildcards, and `regex:<pattern>` for full regex matching. `category` and `label` are ignored.

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

# Regex — allow any RFC-1918 10.x.x.x address (anchored, digit-strict):
- pattern: "regex:^10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"
  kind: allow

# Regex — allow token-format strings like TOKEN-ABC-1234 (case-insensitive via (?i)):
- pattern: "regex:(?i)^token-[a-z]{3}-[0-9]{4}$"
  kind: allow
```

`kind: allow` entries can be freely mixed with `kind: regex` and `kind: literal` entries in the same file. They are filtered out before the scanner is built, so they have no effect on pattern matching — only on the replacement gate inside the mapping store.

Equivalent via CLI (for ad-hoc runs without editing the secrets file):

```bash
scour-secrets data.log -s patterns.yaml \
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
scour-secrets data.log -s patterns.enc --encrypted-secrets --password
```

**Structured field-level sanitization with a profile:**

```bash
# Sanitize only the password and username fields in config YAML files:
scour-secrets config.yaml -s patterns.yaml --profile fields.yaml

# Process a config file and log file together:
# values found in config.yaml are also replaced in server.log
scour-secrets config.yaml server.log --profile fields.yaml -s patterns.yaml
```

**Deterministic mode with profile (saves discovered values to secrets file):**

```bash
# First run: discovers "hunter2" as a password, appends it to patterns.yaml
SCOUR_SECRETS_PASSWORD=secret scour-secrets config.yaml \
  --profile fields.yaml --deterministic --secrets-file patterns.yaml

# Second run against a log: "hunter2" is now in patterns.yaml and gets
# the same replacement as in the first run
SCOUR_SECRETS_PASSWORD=secret scour-secrets server.log \
  --deterministic --secrets-file patterns.yaml
```

**Deterministic mode (same seed → same replacements every run):**

```bash
scour-secrets data.csv -s s.enc --encrypted-secrets --password -d
```

The seed salt is unique per install by default. To reproduce identical output
on another machine, share the salt:

```bash
# Machine A: copy ~/.config/scour-secrets/seed-salt to machine B, or:
SCOUR_SECRETS_SEED_SALT="team-shared-value" scour-secrets data.csv --password -d
# Machine B: same env var (or --seed-salt-file) → identical mappings
```

**Length-randomizing mode (hide how long each secret was):**

```bash
# id=123456 → a digit run of a different length; the @corp.com domain is kept
echo 'id=123456 e=alice@corp.com' | scour-secrets -s secrets.yaml --randomize-length

# Composes with -d: reproducible across runs, but length ≠ input length
echo 'id=123456' | SCOUR_SECRETS_PASSWORD=secret scour-secrets -s secrets.yaml -d --randomize-length
```

**Process a tar.gz archive with strict error handling:**

```bash
scour-secrets backup.tar.gz -s s.enc --encrypted-secrets --password -o backup.sanitized.tar.gz --strict
```

**Filter archive entries — keep only files under a specific path:**

```bash
# Exact full path (paths are stored as-is inside the archive, e.g. test/test.config):
scour-secrets test.zip --only test/test.config -s patterns.yaml

# Keep all JSON files at any depth (**/ crosses directory boundaries):
scour-secrets backup.zip --only '**/*.json' -s patterns.yaml

# Keep an entire directory subtree (trailing / = directory-prefix match):
scour-secrets backup.zip --only 'config/' -s patterns.yaml

# Drop all log files:
scour-secrets backup.zip --exclude '**/*.log' -s patterns.yaml

# Combine: keep JSON files, then drop the secrets file:
scour-secrets backup.zip --only '**/*.json' --exclude config/secrets.json -s patterns.yaml
```

**Per-archive filters — each archive in a multi-input command is filtered independently:**

```bash
# a.zip keeps only config/; b.tar.gz keeps only *.log files:
scour-secrets a.zip --only 'config/' b.tar.gz --only '**/*.log' -s patterns.yaml

# Plain file alongside a filtered archive:
scour-secrets report.txt backup.zip --only 'logs/' -s patterns.yaml
# Produces: report-sanitized.txt  backup.sanitized.zip (logs/ entries only)
```

**Mix stdin with file and archive inputs:**

```bash
# stdin goes to stdout; each file/archive gets its own output file:
cat extra.log | scour-secrets - backup.zip --only 'logs/' config.yaml -s patterns.yaml
```

**Dry-run — see what would be replaced without writing output:**

```bash
scour-secrets config.yaml -s s.enc --encrypted-secrets --password -n
```

**Fail CI if secrets are detected:**

```bash
scour-secrets config.yaml -s s.enc --encrypted-secrets -P /run/secrets/pw --fail-on-match
```

**Extract error context into the JSON report (for LLM triage):**

```bash
# Basic: report gets a log_context block per file with default keywords and 10 lines of context.
scour-secrets server.log -s patterns.yaml --report report.json --extract-context

# Multiple files: each file gets its own log_context in the report.
scour-secrets server.log worker.log -s patterns.yaml --report report.json --extract-context

# Custom context window and extra keywords:
scour-secrets server.log -s patterns.yaml --report report.json \
  --extract-context --context-lines 20 --context-keywords timeout,oomkilled,backoff

# Pipe stdin and capture context (output to file required when input > 256 MiB):
cat server.log | scour-secrets -s patterns.yaml --report - --extract-context

# Only keywords you care about (replaces defaults entirely):
scour-secrets server.log -s patterns.yaml --report report.json \
  --extract-context --context-keywords fatal,critical --context-keywords-replace
```

**Report JSON — `log_context` shape** (present per file when `--extract-context` is used):

```json
{
  "path": "server.log",
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
scour-secrets data.log -s s.enc --encrypted-secrets -P /run/secrets/pw
```

**Custom chunk size for memory-constrained environments:**

```bash
scour-secrets huge.log -s s.enc --encrypted-secrets --password --chunk-size 262144
```

**JSON-structured logs for SIEM ingestion:**

```bash
scour-secrets data.log -s s.enc --encrypted-secrets --password --log-format json
```

**Use a plaintext secrets file (default — no password needed):**

```bash
# Plaintext YAML/JSON/TOML is the default — just point at the file:
scour-secrets data.log -s patterns.yaml
scour-secrets data.log -s secrets.json

# Deterministic mode with plaintext secrets:
scour-secrets data.csv -s patterns.yaml -d

# Fail CI with plaintext secrets:
scour-secrets config.yaml -s patterns.yaml --fail-on-match
```

**Use an encrypted secrets file (opt-in with `--encrypted-secrets`):**

```bash
# Interactive password prompt:
scour-secrets data.log -s patterns.enc --encrypted-secrets --password

# Password from file (CI-friendly):
scour-secrets data.log -s patterns.enc --encrypted-secrets -P /run/secrets/pw

# Password from environment variable:
SCOUR_SECRETS_PASSWORD=hunter2 scour-secrets data.log -s patterns.enc --encrypted-secrets
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
scour-secrets encrypt secrets.json secrets.json.enc --password

# 3. Remove the plaintext:
rm secrets.json

# 4. Use the encrypted file (interactive prompt):
scour-secrets data.log -s secrets.json.enc --encrypted-secrets --password

# 5. Decrypt to edit later:
scour-secrets decrypt secrets.json.enc secrets.json --password
```

> **Security note:** `-p` / `--password` triggers a secure interactive prompt (masked input, no shell history). All password inputs (`-p`, `-P`, `SCOUR_SECRETS_PASSWORD`) require `--encrypted-secrets`. For non-interactive automation use `-P` / `--password-file` or the `SCOUR_SECRETS_PASSWORD` environment variable.
