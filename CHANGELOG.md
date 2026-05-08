# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] — 2026-05-08

This release marks the **stability boundary**. The public library API and CLI
interface are now covered by Semantic Versioning: breaking changes require a
major version bump. See the [Stability section in README.md](README.md#stability)
for the full stability contract and MSRV policy.

### Added

- **`SecretEntry.values`** — new optional field in secrets files for compact
  multi-value `kind: allow` entries. A single entry with `values: [...]`
  replaces N separate single-pattern entries. Fully backward-compatible via
  `#[serde(default)]`; existing files require no changes.

- **Common allow patterns in built-in presets** — the `balanced`, `aggressive`,
  and guided-entry code paths now automatically allow common non-sensitive
  values: loopback IPs (`127.0.0.1`, `::1`), subnet masks, `localhost`,
  `example.{com,org,net}`, nil UUID, and localhost URLs. Reduces false
  positives out of the box.

- **`processor/limits.rs`** — single source of truth for all processor safety
  limits. Constants (`DEFAULT_ARCHIVE_DEPTH`, `YAML_INPUT_SIZE`, etc.) are now
  imported from one module instead of redefined per-processor.

- **`TreeNode` trait + `walk_tree` generic function** — shared tree-walker used
  by the JSON, YAML, and TOML processors. Eliminates ~150 lines of duplicated
  recursive walk code.

### Changed

- **`AllowlistMatcher` internals** — exact patterns are now stored in a
  `HashSet` for O(1) lookup; only glob patterns walk a `Vec`. No API change.

- **`DEFAULT_MAX_ARCHIVE_DEPTH` renamed to `DEFAULT_ARCHIVE_DEPTH`** —
  re-exported from `processor::limits`. The old name is removed; update any
  direct imports.

- **`format_char_class_lp` extraction in `generator.rs`** — `format_digits_lp`
  and `format_hex_digits_lp` are now thin wrappers around a shared helper.
  Outputs are identical to previous versions.

- **`scan_reader_with_progress` split into helpers** — the main scan loop now
  delegates per-window work to `process_committed_window` and pattern count
  folding to `fold_chunk_counts`. Behavior is unchanged.

### Fixed

- **`zeroize` on drop for `SecretEntry.values`** — the new `values` field is
  included in the `Drop` impl that zeros sensitive memory.

## [0.5.0] — 2026-05-05

### Added

- **`--default` flag** — scan without a secrets file using built-in balanced patterns. Covers API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, GitLab, SendGrid, npm), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM headers, password/secret key=value pairs, and credential URLs. Cannot be combined with `--secrets-file`.

- **`--app <APPS>` flag** — load built-in app bundles (comma-separated). Each bundle provides app-specific secrets patterns and a structured field profile. Additive with `--default`, `--secrets-file`, and `--profile`. Eight built-in bundles: `docker-compose`, `django`, `gitlab`, `kubernetes`, `nginx`, `postgresql`, `rails`, `spring-boot`.

- **`--allow <PATTERN>` flag** — suppress specific values from replacement (repeatable). Matched values pass through unchanged and are not recorded in the mapping store, so they will not propagate to other files in the same run. Supports exact strings and `*` glob wildcards (`*.internal`, `192.168.1.*`).

- **`kind: allow` in secrets files** — allowlist entries can be placed in the secrets file alongside `kind: regex` and `kind: literal` entries. Patterns support the same `*` glob syntax as `--allow`. Entries from the secrets file and `--allow` flags are merged at runtime.

- **`sanitize apps` subcommands** — `sanitize apps` now dispatches to four sub-subcommands:
  - `sanitize apps` (no subcommand) — list built-in and user-defined bundles.
  - `sanitize apps add <NAME> [--profile FILE] [--secrets FILE] [--overwrite]` — install a custom app bundle from local YAML files. Both files are validated before anything is written to disk.
  - `sanitize apps remove <NAME> [--yes]` — remove a custom app bundle. Built-in bundles are protected. Requires `--yes` to confirm.
  - `sanitize apps dir` — print the user apps directory (`$SANITIZE_APPS_DIR` or `~/.config/sanitize/apps`).

- **`sanitize allow-test` subcommand** — test allowlist patterns against values before a full run. Accepts `--allow` patterns, positional values or stdin (one per line), and `--json` for machine-readable output. Shows which pattern matched each value and a summary count.

- **`sanitize template` subcommand** — generate a starter secrets template YAML for a preset use case (`generic`, `web`, `k8s`, `database`, `aws`). Output defaults to `secrets.template.<preset>.yaml`.

- **`AllowlistMatcher`** — new public type in `sanitize_engine::allowlist`. Compiles `*`-glob and exact patterns; `is_allowed()` and `match_pattern()` methods; atomic seen-counter; regex-character warning on construction.

- **`AllowlistMatcher::match_pattern`** — returns the first matching pattern string (not just a bool), used by `allow-test` to show which pattern matched.

- **`MappingStore::new_with_allowlist`** — constructs a store with an injected `AllowlistMatcher`. Allowlist check happens inside `get_or_insert` before any replacement is recorded, so allowed values never enter the forward map or Phase 2 augmentation.

- **MCP: `use_default`, `app`, `allow` parameters** — `sanitize` and `scan` tools now expose all three new flags. `use_default` is validated in TypeScript before spawning the subprocess (conflicts with `secrets_file`, `namespace`, and `patterns` are caught early with a clear error message).

- **MCP: `test_allowlist` tool** — accepts `patterns: string[]` and `values: string[]`, delegates to `sanitize allow-test --json`, and returns structured match results.

- **`--strip-delimiter <DELIM>` flag** — sets the delimiter used to split key/value lines when `--strip-values` is active. Default: `=`. Use `--strip-delimiter :` for YAML-style or nginx-style configs. Requires `--strip-values`.

- **`--strip-comment-prefix <PREFIX>` flag** — sets the line prefix that marks a comment when `--strip-values` is active. Default: `#`. Requires `--strip-values`.

- **`--max-context-matches <N>` flag** — caps keyword matches captured per file when `--extract-context` is active. Default: `50`.

- **`--context-case-sensitive` flag** — makes keyword matching case-sensitive when `--extract-context` is active.

- **MCP server (`mcp/`)** — Deno-based MCP server wrapping the `sanitize` binary as a subprocess. Ships as a standalone binary for Linux x64, macOS x64, macOS arm64, and Windows. Tools: `sanitize`, `scan`, `strip_config_values`, `test_allowlist`, `list_processors`, `list_templates`.

- **MCP: `namespace` parameter** — per-namespace secrets resolution from `$SANITIZE_SECRETS_DIR/<namespace>/`.

- **Test suites** — `tests/allow_test_cli_tests.rs` (11 tests), `tests/apps_cli_tests.rs` (19 tests), `tests/strip_values_cli_tests.rs` (6 tests); new unit tests for `AllowlistMatcher::match_pattern`, glob edge cases, `sanitize_zip_entry_name`, `parse_secrets` size cap, and `truncate_label` boundary.

### Fixed

- **Zip entry name traversal** — zip entry names are now sanitised on read: leading `/`, `./`, and `../` segments are stripped. A crafted archive with entry names like `../../etc/passwd` would previously propagate those names into the output zip; they are now normalised to safe relative paths.

- **Secrets file size cap** — `parse_secrets` now rejects inputs larger than 10 MiB before attempting deserialization, preventing OOM from accidentally passing a large binary or log file as a secrets file.

### Changed

- **`sanitize apps` is now a subcommand group** — previously `sanitize apps` was a bare list command. It now accepts `add`, `remove`, and `dir` sub-subcommands. The bare `sanitize apps` (no subcommand) still lists bundles.

- **`validate_app_name` error messages** — now name the specific invalid character rather than giving a generic character-class description.

- **`truncate_label` magic number replaced** — `31`/`32` replaced with `MAX_LABEL_CHARS = 32` constant.

## [0.4.0] — 2026-05-01

### Added

- **`--llm [TEMPLATE]` flag** — formats sanitized output as an LLM-ready prompt and writes it to stdout instead of a file. Built-in templates: `troubleshoot` (default) and `review-config`. A custom template file path can be provided instead. Sanitized content appears in `<content name="...">` blocks followed by a Sanitization Summary and (optionally) a `<notable_events>` section when used with `--extract-context`.

- **Validation: `--llm` conflicts** — `--llm` cannot be combined with `--output` (the prompt is the output) or `--dry-run` (no sanitized content to include). A nonexistent or non-file custom template path is also rejected with a clear error.

- **Unit tests for `--llm` helpers** — `resolve_llm_template`, `format_llm_prompt` (content blocks, sanitization summary, notable events, multiple entries), and `validate_args` for all `--llm` rejection cases.

- **Integration test suite: `tests/llm_tests.rs`** — end-to-end CLI coverage for `--llm`: validation rejections, template selection, prompt structure, secret sanitization in prompt, `--extract-context` integration, and no-write guarantee.

- **Integration test suite: `tests/extract_context_tests.rs`** — CLI coverage for `--extract-context` (report JSON output, `--context-lines` 0 and non-zero), `--context-keywords`, `--context-keywords-only`, and `--strip-values` (file and stdin paths).

- **Unit tests for `--strip-values` helpers** — `strip_values_from_text` preserves keys, comments, blank lines, section headers, and pass-through lines without a delimiter.

- **Unit tests for `validate_args`** — covers `--format`, `--log-format`, `--threads 0`, `--password` without `--encrypted-secrets`, known LLM templates, and all `--llm` rejection paths.

## [0.3.0] — 2026-04-29

### Added

- **`--profile <FILE>` flag** — enables structured field-level sanitization. A profile YAML or JSON file maps file extensions to processors and field rules (e.g. replace `*.password` with `custom:password` category). Profiles are evaluated before the streaming scanner.

- **Two-phase pipeline** — when `--profile` is supplied, profile-matched files are processed first (serially) to populate the replacement store with discovered field values. The streaming scanner used for all other files is then augmented with those values as literal patterns, so the same secret found in `config.yaml` is automatically replaced in `app.log` with the same replacement.

- **Format-preserving structured pass** — the structured processor populates the store with field-value mappings, then the original file bytes are scanned with a per-file scanner containing those literals. Comments, indentation, key ordering, blank lines, and quoting style are all preserved exactly.

- **`include` / `exclude` globs on `FileTypeProfile`** — profiles can now restrict which files they apply to beyond extension matching. `include` narrows to filenames matching at least one glob; `exclude` skips matching filenames. Patterns without a path separator are matched against both the filename and the full path.

- **Discovered-value persistence** (`--deterministic` + `--profile`) — when `--deterministic` is set alongside `--profile`, values discovered by the structured pass are appended to `--secrets-file` after the run (creating the file if absent, deduplicating if it exists). Subsequent runs against unstructured files load those patterns and produce consistent replacements.

- **`--deterministic` without `--encrypted-secrets`** — `--deterministic` can now be used with a plaintext secrets file. The password (via `SANITIZE_PASSWORD`, `--password-file`, or `-p`) is used as the HMAC seed only; `--encrypted-secrets` is no longer required when using deterministic mode without an encrypted secrets file.

- **Archive structured discovery pre-pass** — archives in Phase 2 are opened once before the augmented scanner is built. Profile-matched entries inside the archive populate the store, so their values are included in the augmented scanner used for all Phase 2 processing.

- **`ScanPattern::Clone`** — `ScanPattern` now implements `Clone` (via the internally ref-counted `regex::bytes::Regex`).

- **`StreamScanner::with_extra_literals`** — builds an extended copy of a scanner with additional literal patterns appended. Used internally for per-file scanners in the structured pass.

- **`MappingStore::snapshot_keys`** — returns a `HashSet` of all current `(Category, original)` keys. Used to diff the store before and after structured processing to find newly discovered literals.

### Changed

- **Default secrets mode is now plaintext** — `sanitize` loads secrets files as
  plaintext JSON / YAML / TOML by default. Encrypted (AES-256-GCM) files now
  require the explicit `--encrypted-secrets` flag.
- **`--unencrypted-secrets` removed** — replaced by the inverse `--encrypted-secrets`
  flag. Scripts using `--unencrypted-secrets` must remove the flag (the default
  behaviour is now plaintext).
- **Password inputs require `--encrypted-secrets`** — supplying `--password`,
  `--password-file`, or the `SANITIZE_PASSWORD` environment variable without
  `--encrypted-secrets` is now a hard error with a clear message.
- **`--password` / `-p` is now interactive** — The flag no longer accepts an
  inline value. When provided, it triggers a secure interactive password prompt
  (masked input via `rpassword`, no shell history or process listing exposure).
  Passing `--password VALUE` is rejected by the parser. In non-interactive
  contexts (no TTY) the flag returns a clear error and directs users to
  `--password-file` or `SANITIZE_PASSWORD`.

## [0.2.0] — 2026-03-20

### Fixed

- **CLI panic on startup** — `required_unless_present = "command"` referenced
  a clap subcommand field that is not exposed as a named argument in clap 4.5,
  causing a debug assertion panic on every invocation. Replaced with manual
  validation after parsing.
- **`--unencrypted-secrets` still prompted for password** — password resolution
  via `rpassword` was called unconditionally, even when `--unencrypted-secrets`
  was set. Now skips password resolution entirely when the flag is present.
- **`--dry-run --report` showed zero matches for archives** — `ScanStats` from
  per-entry scanning were discarded (`_scan_stats`). Added
  `file_scan_stats: HashMap<String, ScanStats>` to `ArchiveStats` and
  aggregated per-entry scan results so reports reflect actual match counts.

### Changed

- **Consolidated `encrypt-secrets` into `sanitize` subcommands.** The separate
  `encrypt-secrets` binary has been removed. Use `sanitize encrypt <IN> <OUT>`
  and `sanitize decrypt <IN> <OUT>` instead. The default sanitize mode
  (`sanitize [INPUT]`) is unchanged and requires no subcommand.
- **Unified password handling** across all modes with a single resolution
  chain: `--password` flag → `--password-file` → `SANITIZE_PASSWORD` env var
  → interactive prompt (masked via `rpassword`).
- **Removed `--secrets-key`** — use `--password` instead.
- **`OUTPUT` is now `--output` / `-o`** — Output path changed from a positional
  argument to a named flag. Usage: `sanitize data.log -s s.enc -o output.log`.
  Plain files still default to stdout; archives default to
  `<input>.sanitized.<ext>`.
- **Cross-platform support** — `nix` dependency is now Unix-only; password-file
  permission checks degrade gracefully on non-Unix platforms.

### Added

- **CLI smoke tests** — 15 unit tests in `src/bin/sanitize.rs` covering argument
  parsing, subcommand dispatch, short flags, stdin detection, and flag
  combinations. Prevents future clap derive regressions.
- **Stdin support** — When `INPUT` is omitted or set to `-`, `sanitize` reads
  from stdin. Enables Unix pipeline usage:
  `export SANITIZE_PASSWORD="secret"; grep "error" log.txt | sanitize -s secrets.enc`.
  TTY detection prevents hanging when run interactively without input.
- **Short flags** — Common options now have short aliases: `-s` (secrets-file),
  `-p` (password), `-P` (password-file), `-o` (output), `-n` (dry-run),
  `-d` (deterministic), `-r` (report), `-f` (format).
- **`--format` / `-f` flag** — Force input format (`text`, `json`, `yaml`,
  `xml`, `csv`, `key-value`), overriding file-extension detection. Required
  for structured processing when reading from stdin.
- **`sanitize encrypt`** subcommand — encrypts a plaintext secrets file with
  AES-256-GCM (replaces the standalone `encrypt-secrets` binary).
- **`sanitize decrypt`** subcommand — decrypts an encrypted secrets file back
  to plaintext for editing, with optional format validation.
- **`--password <PW>`** flag — provides the password for the default
  sanitize mode. Also available in `encrypt` and `decrypt` subcommands.
- **`--password-file <PATH>`** flag — read the password from a file with
  strict Unix permissions enforcement (`0600` or `0400`). Avoids shell
  history and `/proc/<pid>/environ` exposure.
- **Interactive password prompt** — when no password is provided via flag,
  file, or env var, the user is prompted on the terminal with masked input
  (via the `rpassword` crate).

### Removed

- **`encrypt-secrets` binary** — functionality absorbed into
  `sanitize encrypt` and `sanitize decrypt`.

## [0.1.0] — 2026-03-19

### Added

- **Streaming scanner** with configurable chunk + overlap for bounded-memory
  processing of arbitrarily large files.
- **18 built-in categories**: email, name, phone, credit card, SSN, IPv4, IPv6,
  MAC address, hostname, container ID, UUID, JWT, auth token, file path,
  Windows SID, URL, AWS ARN, Azure resource ID, plus `custom:<tag>`.
- **Structured processors** for JSON, YAML, XML, CSV, and key-value formats
  that replace matched values while preserving document structure.
- **Archive support** for tar, tar.gz, and zip with entry-by-entry processing
  and metadata preservation (timestamps, permissions, uid/gid).
- **Deterministic mode** using HMAC-SHA256 seeded replacements — same seed and
  same input produce identical output across runs.
- **Random mode** (default) using CSPRNG with per-run dedup cache for
  consistency within a single run.
- **Length-preserving replacements** for all 18 built-in categories.
- **Encrypted secrets file** (AES-256-GCM with PBKDF2, 600 000 iterations) for
  storing detection patterns at rest.
- **Plaintext secrets** support with auto-detection (JSON, YAML, TOML).
- **`encrypt-secrets` CLI** (since removed — see 0.2.0) for converting
  plaintext secrets to encrypted form.
- **`sanitize` CLI** with `--dry-run`, `--fail-on-match`, `--report`,
  `--deterministic`, `--strict`, and streaming/structured processing options.
- **Regex hardening**: per-pattern automaton size limits (1 MiB), DFA size
  limits, and pattern count cap (10 000).
- **YAML alias bomb mitigation**: input size cap (64 MiB), node count cap
  (10 000 000), and recursion depth limit (128).
- **Memory bounds** for all structured processors (JSON/XML/CSV: 256 MiB;
  YAML: 64 MiB) with automatic fallback to streaming.
- **Atomic file writes** using temp-file + rename for crash safety.
- **Zeroization** of sensitive data (HMAC keys, secret entries, mapping store)
  on drop via the `zeroize` crate.
- **Graceful shutdown** on SIGINT with atomic flag.
- **JSON report output** (`--report`) with per-file and aggregate statistics.
- **Zero `unsafe` code** — entire crate uses safe Rust only.
- **290+ tests** including unit, integration, property-based (proptest), and
  4 fuzz targets.

[Unreleased]: https://github.com/kayelohbyte/rust-sanitize/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/kayelohbyte/rust-sanitize/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/kayelohbyte/rust-sanitize/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kayelohbyte/rust-sanitize/releases/tag/v0.4.0
[0.3.0]: https://github.com/kayelohbyte/rust-sanitize/releases/tag/v0.3.0
[0.2.0]: https://github.com/kayelohbyte/rust-sanitize/releases/tag/v0.2.0
[0.1.0]: https://github.com/kayelohbyte/rust-sanitize/releases/tag/v0.1.0
