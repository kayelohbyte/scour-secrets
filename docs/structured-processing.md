# Structured Processing

Structured processors parse a file's format (JSON, YAML, XML, CSV, key-value), walk its data structure, and replace only the values at field paths you specify — leaving keys, comments, formatting, and unmatched values untouched.

The streaming scanner treats files as raw bytes and replaces pattern matches wherever they appear. Structured processing is complementary: it targets *specific fields by name*, which reduces false positives and avoids touching unrelated values.

---

## Quick Start with `--profile`

Write a profile file describing which fields to sanitize, then pass it with `--profile`:

```yaml
# profile.yaml
- processor: yaml
  extensions: [".yaml", ".yml"]
  fields:
    - pattern: "*.password"
      category: "custom:password"
    - pattern: "*.username"
      category: email

- processor: json
  extensions: [".json"]
  fields:
    - pattern: "*.password"
      category: "custom:password"
    - pattern: "*.email"
      category: email
```

```bash
# --secrets-file is required when using --profile.
# The file can be empty on the first run — scour populates it with discovered
# literals automatically so Phase 2 can match them in logs and other files.
scour config.yaml -s secrets.yaml --profile profile.yaml
```

Input:
```yaml
# Production database config
database:
  host: db.corp.com        # primary host
  username: alice@corp.com
  password: hunter2        # rotated monthly
  port: 5432
```

Output:
```yaml
# Production database config
database:
  host: db.corp.com        # primary host
  username: ab12@corp.com
  password: f3c9a1b8       # rotated monthly
  port: 5432
```

Comments, indentation, blank lines, and unmatched fields are preserved exactly. Only the values at matched field paths change.

---

## How the Two-Pass Pipeline Works

When `--profile` is supplied, every input goes through two passes:

```
Phase 1 — structured files (serial)
  ┌─────────────────────────────────────────────────────────────┐
  │  For each file matched by a profile:                         │
  │    1. Run structured processor → populate MappingStore       │
  │    2. Build a per-file scanner: base patterns + discovered   │
  │       literals from this file                                │
  │    3. Scan the ORIGINAL bytes with the per-file scanner      │
  │       (format is preserved exactly)                          │
  └─────────────────────────────────────────────────────────────┘
                          ↓
  Build augmented scanner: base patterns + ALL discovered literals

Phase 2 — everything else (parallel)
  ┌─────────────────────────────────────────────────────────────┐
  │  Plain text files, archives, and any file not matched by a  │
  │  profile are scanned with the augmented scanner.            │
  │  Values discovered in Phase 1 are found verbatim here too.  │
  └─────────────────────────────────────────────────────────────┘
```

**Cross-file propagation:** if Phase 1 finds `hunter2` as a password in `config.yaml`, the augmented scanner used in Phase 2 automatically replaces that same string in `app.log`, `backup.tar.gz`, or any other file — with the same replacement value.

```bash
# config.yaml has password: hunter2
# app.log contains "auth failed for hunter2"
scour config.yaml app.log --profile profile.yaml -s secrets.yaml

# Both files get the same replacement for "hunter2"
```

### Processing Order with `--profile`

When mixing stdin, profile-matched files, archives, and plain files in a single command, the execution order depends on whether `--profile` is active:

**Without `--profile`:**

1. Stdin (immediately, using base scanner)
2. All file targets in parallel (Phase 2 only)

**With `--profile`:**

1. **Phase 1a — discovery pre-pass, serial, in command-line order** — plain files whose name matches at least one profile entry are parsed structurally to populate the mapping store with their field values. No output is written yet.
2. **Archive discovery pre-pass** — for each archive in the input set, a second read scans for profile-matched entries so their values are also recorded in the store.
3. **Augmented scanner is built** — base secrets patterns + all literals discovered from the Phase 1a files and the archive pre-pass.
4. **Phase 1b — structured output pass, serial** — the profile-matched files are re-processed and written, each building its format-preserving scanner from the **entire** store. Because discovery already saw every structured file, a value found in one config is redacted in all of them — including where it appears in comments or other unstructured regions of a structured file.
5. **Stdin** — processed with the fully-populated augmented scanner, so values from structured config files are replaced in piped input.
6. **Phase 2 — parallel** — archives and plain files not matched by any profile, also using the augmented scanner.

Deferring stdin until after discovery and the archive pre-pass is what makes this work correctly:

```bash
# config.yaml is discovered first (Phase 1a), seeding e.g. password: hunter2
# stdin is processed after, so "hunter2" is replaced in error.json too
cat error.json | scour config.yaml -s secrets.yaml --profile profile.yaml

# Without --profile, stdin runs first (no deferral needed — no discovery happens)
cat error.json | scour -s secrets.yaml
```

**Does command-line order matter?**

- **Without `--profile`:** No. All file targets run in parallel, and the mapping store's first-writer-wins semantics guarantee consistent replacements regardless of which file finishes first.
- **With `--profile`:** No. The discovery pre-pass populates the store from *all* structured files before any output is written, so the same value is redacted identically in every file. Command-line order only affects which file *first* adds a given value to the store, not whether — or to what — it is replaced.

```bash
# Phase 2 ordering never changes results — same replacements regardless of file order
scour a.log b.log c.log -s secrets.yaml   # identical result to c.log b.log a.log
```

---

## Format Preservation

The structured pass edits each matched value **at its exact byte span in the original file**, never re-serializing a parsed copy. This means:

- Comments are preserved
- Indentation style is preserved
- Key ordering is preserved
- Quoting style is preserved
- Blank lines are preserved

Because the edit targets the source bytes directly, a value that is **escaped in the source** — JSON `\/` or `\uXXXX`, XML entities (`a&lt;b`), CSV `""` doubling, or quoted/escaped YAML/TOML scalars — is redacted exactly where it appears and never leaks. (JSON/JSONL use `jiter`, YAML `saphyr-parser`, TOML `toml_edit`, XML `quick-xml`, CSV `csv-core` for byte spans.)

```yaml
# Before
server:
  host: "prod.example.com"  # primary
  port: 8080
  api_key: "sk-abc123"      # rotated weekly

# After (profile targets *.api_key)
server:
  host: "prod.example.com"  # primary
  port: 8080
  api_key: "sk-xyz789"      # rotated weekly
```

The streaming scanner then runs on that output to catch any remaining patterns from the secrets file — also byte-level, so formatting is maintained end-to-end.

---

## Profile File Format

A profile file is a YAML or JSON array of profile entries. Each entry selects a processor, one or more file extensions, optional include/exclude globs, and a list of field rules.

```yaml
- processor: yaml
  extensions: [".yaml", ".yml"]
  include: []       # optional: restrict to filenames matching these globs
  exclude: []       # optional: skip filenames matching these globs
  fields:
    - pattern: "*.password"
      category: "custom:password"
    - pattern: "database.host"
      category: hostname
  options: {}       # processor-specific options
```

### Profile Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `processor` | Yes | — | Processor name: `"json"`, `"yaml"`, `"xml"`, `"csv"`, `"key_value"`, `"toml"`, `"env"`, `"ini"`, `"log"`, `"jsonl"`. |
| `extensions` | Yes | `[]` | File extensions this profile applies to (e.g. `[".json"]`). An empty list matches nothing. |
| `include` | No | `[]` | If non-empty, only files whose name matches at least one glob are processed. |
| `exclude` | No | `[]` | Files whose name matches any glob are excluded from structured processing. |
| `fields` | Yes | — | Array of field rules specifying which keys/paths to sanitize. |
| `options` | No | `{}` | Processor-specific options (e.g. delimiter, comment characters). |

### Include / Exclude Globs

Use `include` and `exclude` when you have multiple files with the same extension that need different treatment — for example, JSON config files and JSON log files:

```yaml
- processor: json
  extensions: [".json"]
  include: ["config*.json", "settings*.json"]   # only these
  fields:
    - pattern: "*.password"
      category: "custom:password"

- processor: json
  extensions: [".json"]
  exclude: ["config*.json", "settings*.json"]   # everything else
  fields:
    - pattern: "*"
      category: "custom:field"
```

**Pattern matching rules:**

- Patterns without a path separator are matched against both the filename and the full path.
- `*` matches any characters within a single path component.
- `**` matches across path separators.
- A file must match at least one `include` pattern (if any are set), and must not match any `exclude` pattern.

```yaml
# Only process files named config.json or config-prod.json:
include: ["config*.json"]

# Skip log-formatted JSON regardless of name:
exclude: ["*.log.json", "logs/**"]
```

---

## Field Rules

Each field rule specifies a key pattern to match and how to replace its value.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `pattern` | Yes | — | Key pattern to match (see pattern syntax below). |
| `category` | No | `"custom:field"` | Category for replacement generation. Accepts any built-in category or `custom:<tag>`. |
| `label` | No | — | Human-readable label for reporting and per-pattern hit counts. |
| `min_length` | No | — | Minimum byte length a value must reach before it is replaced. Values shorter than this threshold pass through unchanged. Use this with broad glob patterns like `*token*` or `*secret*` to avoid redacting obviously non-secret values such as `"false"`, `"0"`, or `"nil"`. A value of `8` is a reasonable default for token/password fields. |
| `sub_processor` | No | — | Processor name (`"yaml"`, `"json"`, `"toml"`, etc.) to use when the field's value is itself a structured document embedded as a string (e.g. YAML inside a Ruby heredoc). The parent processor extracts the value and delegates it to this processor. |
| `sub_fields` | No | `[]` | Field rules applied by `sub_processor` to the nested content. Ignored when `sub_processor` is absent. |

### Pattern Syntax

| Pattern | Matches |
|---------|---------|
| `"password"` | Exact key `password` at any depth |
| `"database.password"` | Exact dotted path `database.password` |
| `"*.password"` | Any key ending in `.password`, or `password` itself |
| `"db.*"` | Any key starting with `db.` |
| `"*password*"` | Any key containing `password` as a substring |
| `"*"` | Every field |

Patterns are matched against the full dot-separated key path (JSON/YAML), slash-separated path (XML), or literal key string (key-value files).

### `min_length` — Avoiding false positives with broad patterns

Broad patterns like `*token*` or `*secret*` can match short non-secret values (`"false"`, `"0"`, `"nil"`). Use `min_length` to skip values below a threshold:

```yaml
fields:
  - pattern: "*token*"
    category: auth_token
    min_length: 8      # skip values shorter than 8 bytes
  - pattern: "*password*"
    category: "custom:password"
    min_length: 8
```

### `sub_processor` — Nested structured content

When a field value is itself a structured document (e.g. YAML embedded as a string inside a Ruby config file), use `sub_processor` to delegate it:

```yaml
- processor: key_value
  extensions: [".rb"]
  include: ["gitlab.rb"]
  fields:
    - pattern: "*['ldap_servers']"
      sub_processor: yaml
      sub_fields:
        - pattern: "*.password"
          category: "custom:password"
          min_length: 8
        - pattern: "*.bind_dn"
          category: "custom:dn"
```

---

## Processor Reference

### YAML (`"yaml"`)

Parses YAML, walks the value tree with dot-separated paths. Arrays are traversed transparently — a rule for `users.email` matches `email` inside every object in the `users` array.

```yaml
# profile entry
- processor: yaml
  extensions: [".yaml", ".yml"]
  fields:
    - pattern: "*.password"
      category: "custom:password"
    - pattern: "*.email"
      category: email
    - pattern: "server.host"
      category: hostname
```

```yaml
# input
server:
  host: db.corp.com
  port: 5432
  credentials:
    password: hunter2

users:
  - email: alice@corp.com
  - email: bob@corp.com
```

```yaml
# output (original formatting preserved)
server:
  host: ab12345678  # hostname replacement
  port: 5432
  credentials:
    password: f3c9a1b8

users:
  - email: cd34@corp.com
  - email: ef56@corp.com
```

### JSON (`"json"`)

Same dot-separated path convention and array traversal as YAML.

| Option | Default | Description |
|--------|---------|-------------|
| `compact` | `"false"` | Set to `"true"` for compact (single-line) output. |

```yaml
- processor: json
  extensions: [".json"]
  fields:
    - pattern: "*.password"
      category: "custom:password"
    - pattern: "*.email"
      category: email
  options:
    compact: "true"
```

### Key-Value (`"key_value"`)

Handles line-oriented `key = value` configuration files. Preserves blank lines, comments, indentation, and quoting style. Supports Ruby `gitlab.rb` bracket-notation keys (`gitlab_rails['smtp_password']`) and heredoc values delegated to a sub-processor.

| Option | Default | Description |
|--------|---------|-------------|
| `delimiter` | `"="` | Primary key-value separator string. |
| `secondary_delimiter` | *(none)* | Optional second delimiter tried when the primary delimiter's key does not match any field rule. Useful for files that mix two delimiter styles (e.g. `:` alongside `=`). |
| `comment_prefix` | `"#"` | Lines starting with this prefix (after leading whitespace) are preserved verbatim. |
| `value_strip_suffix` | *(none)* | Strip this suffix from a value before comparing and replacing. Useful for nginx-style lines that end with `;` (e.g. `proxy_pass http://secret/;`). |

```yaml
- processor: key_value
  extensions: [".conf", ".env"]
  fields:
    - pattern: "DB_PASSWORD"
      category: "custom:password"
    - pattern: "SMTP_USER"
      category: email
  options:
    delimiter: "="
    comment_prefix: "#"
```

```
# database settings
DB_HOST=db.corp.com
DB_PASSWORD=hunter2   →   DB_PASSWORD=f3c9a1b8
SMTP_USER=ops@corp.com →  SMTP_USER=ab12@corp.com
```

**Key path convention:** the full text to the left of the delimiter (trimmed). For files like `gitlab_rails['smtp_password'] = "value"`, the pattern is the full key string: `gitlab_rails['smtp_password']`.

### XML (`"xml"`)

Streaming XML parser. Preserves document structure, attributes, and non-matched content.

**Path convention:** slash-separated element paths (`database/password`). Attributes use `element/@attr` syntax.

```yaml
- processor: xml
  extensions: [".xml"]
  fields:
    - pattern: "config/database/password"
      category: "custom:password"
    - pattern: "config/smtp/@host"
      category: hostname
```

### CSV (`"csv"`)

Replaces values in specified columns by header name. Preserves the delimiter and row structure.

| Option | Default | Description |
|--------|---------|-------------|
| `delimiter` | `","` | Field delimiter (single ASCII character). Use `"\t"` for TSV. |
| `has_header` | `"true"` | When `"true"`, match by header name. When `"false"`, match by column index string (`"0"`, `"1"`, …). |

```yaml
- processor: csv
  extensions: [".csv"]
  fields:
    - pattern: "email"
      category: email
    - pattern: "ip_address"
      category: ipv4
```

### INI (`"ini"`)

Handles INI / CFG files: `[section]` headers, `key = value` and `key: value`
syntax, `#` and `;` comments, and inline comments. Comments and blank lines are
preserved verbatim. Inline comments are stripped from values before replacement
so sensitive content hidden after a `;` is caught.

Field patterns use dot-path notation: `section.key`, bare `key` (matches any
section), or `*` (all values in all sections).

```yaml
- processor: ini
  extensions: [".ini", ".cfg", ".conf"]
  fields:
    # Specific section + key:
    - pattern: "database.password"
      category: "custom:password"
    # Key in any section:
    - pattern: "api_key"
      category: auth_token
    # Every value in the [credentials] section:
    - pattern: "credentials.*"
      category: auth_token
    # Every value in every section:
    - pattern: "*"
      category: generic
```

Example input / output with the profile above:

```ini
[database]
host     = db.corp.internal    ; primary replica
password = s3cretpw            ; NEVER commit this

[credentials]
api_key = AKIA1234567890ABCDEF
token   = ghp_AbCdEfGhIjKlMnOp
```

After sanitization (keys and comments preserved, values replaced):

```ini
[database]
host     = db.corp.internal    ; primary replica
password = __SANITIZED_a1b2__  ; NEVER commit this

[credentials]
api_key = __SANITIZED_c3d4__
token   = __SANITIZED_e5f6__
```

---

## Deterministic Mode + Profile: Saving Discovered Values

When `--deterministic` is set alongside `--profile`, values found by the structured pass are saved to the secrets file after the run. On the next run those values are loaded as patterns so the streaming scanner finds them in unstructured files too.

```bash
# First run: config.yaml is processed structurally.
# Discovered values (e.g. "hunter2") are appended to secrets.yaml.
SCOUR_SECRETS_PASSWORD=secret sanitize config.yaml \
  --profile profile.yaml \
  --deterministic \
  --secrets-file secrets.yaml

# Second run against a log file: "hunter2" is now in secrets.yaml
# so the streaming scanner replaces it in app.log with the same value.
SCOUR_SECRETS_PASSWORD=secret sanitize app.log \
  --deterministic \
  --secrets-file secrets.yaml
```

A secrets file is always required when using `--profile`. The file can be empty on the first run — `--deterministic` will create it if it does not yet exist.

The replacement value for any given input is determined solely by the password and the original string — not by the secrets file contents. This means:

- Same password + same original value = same replacement, always
- Adding new entries to the secrets file never changes existing replacements
- Running two separate files with the same password produces consistent replacements even if they're processed in separate invocations

```bash
# Separate runs, same password → consistent replacements across both outputs
SCOUR_SECRETS_PASSWORD=secret sanitize log-one.txt --deterministic -s secrets.yaml
SCOUR_SECRETS_PASSWORD=secret sanitize log-two.txt --deterministic -s secrets.yaml
# "hunter2" maps to the same replacement in both outputs
```

**Treat your secrets file like a schema:** version-control it and only ever append. Removing a pattern breaks coverage for that value in future runs.

---

## Structured vs Streaming: When to Use Which

| | Structured (`--profile`) | Streaming (`--secrets-file` only) |
|---|---|---|
| **Targeting** | Replaces only matched field values by key path | Replaces pattern matches anywhere in the file |
| **Format** | Original formatting preserved exactly | Byte-level replacement, format preserved |
| **Setup** | Write a profile YAML with field rules | Add entries to secrets file |
| **False positives** | Lower — only targeted fields | Higher — any match anywhere |
| **Discovery** | Finds values in known fields even if not in secrets file | Only finds what's in the secrets file |
| **Best for** | Config files with known field names | Logs, arbitrary text, known secret values |

**Use both for defence in depth:**

```bash
# Structured pass targets known config fields.
# Streaming scanner catches those same values in logs.
scour config.yaml app.log --profile profile.yaml -s secrets.yaml
```

---

## Library API

```rust
use scour_secrets::category::Category;
use scour_secrets::generator::HmacGenerator;
use scour_secrets::processor::key_value::KeyValueProcessor;
use scour_secrets::processor::profile::{FieldRule, FileTypeProfile};
use scour_secrets::processor::Processor;
use scour_secrets::store::MappingStore;
use std::sync::Arc;

let generator = Arc::new(HmacGenerator::new([42u8; 32]));
let store = MappingStore::new(generator, None);

let profile = FileTypeProfile::new(
    "key_value",
    vec![
        FieldRule::new("server_config")
            .with_category(Category::Hostname),
        FieldRule::new("*.password")
            .with_category(Category::Custom("password".into())),
    ],
)
.with_extension(".conf")
.with_option("delimiter", "=")
.with_option("comment_prefix", "#");

let input = b"# Server settings\nserver_config = db.corp.com\nserver_port = 8080\ndb_password = hunter2\n";
let processor = KeyValueProcessor;
let output = processor.process(input, &profile, &store).unwrap();
// server_config and db_password replaced; server_port and comment preserved
```

### `FileTypeProfile` builder

```rust
let profile = FileTypeProfile::new("json", vec![
    FieldRule::new("*.password").with_category(Category::Custom("password".into())),
    FieldRule::new("*.email").with_category(Category::Email),
])
.with_extension(".json")
.with_include("config*.json")     // only files named config*.json
.with_exclude("*.log.json")       // skip log-formatted JSON
.with_option("compact", "false");
```

---

## Nested Archives

When processing archives with `--profile`, structured matching applies to individual entries inside the archive. A YAML config file inside a `.tar.gz` is processed structurally, and values it discovers are propagated to other entries in the same archive and to other files in the same run.

Recursion is bounded by `--max-archive-depth` (default: 3, max: 10).
