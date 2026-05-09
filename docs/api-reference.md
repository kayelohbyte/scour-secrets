# Library API Reference

All public types are re-exported from the crate root (`sanitize_engine::*`) for convenience. The table below summarises every module and its key exports.

## Scanner Module (`scanner`)

| Type / Function | Description |
|-----------------|-------------|
| `StreamScanner` | Streaming regex scanner. Processes input in chunks with overlap to catch boundary-straddling matches. |
| `StreamScanner::new(patterns, store, config)` | Create a scanner from a `Vec<ScanPattern>`, a `MappingStore`, and a `ScanConfig`. |
| `StreamScanner::new_with_max_patterns(patterns, store, config, max_patterns)` | Same as `new()` but with a custom pattern count limit (default: 10 000). |
| `StreamScanner::from_encrypted_secrets(bytes, password, format, store, config, extra)` | Convenience constructor that decrypts a secrets file and builds patterns. Returns `(scanner, warnings)`. |
| `StreamScanner::from_plaintext_secrets(plaintext, format, store, config, extra)` | Convenience constructor that parses a plaintext secrets file and builds patterns. Returns `(scanner, warnings)`. |
| `StreamScanner::scan_reader(reader, writer)` | Scan a `Read` stream, writing sanitized output to a `Write` stream. Returns `ScanStats`. |
| `StreamScanner::scan_bytes(input)` | Scan an in-memory byte slice. Returns `(Vec<u8>, ScanStats)`. |
| `StreamScanner::pattern_count()` | Number of compiled patterns. |
| `StreamScanner::config()` / `store()` | Accessors for the scanner's config and mapping store. |
| `StreamScanner::with_extra_literals(extra)` | Returns a new scanner with the same base patterns plus additional literal patterns. |
| `StreamScanner::for_structured_pass(extra)` | Returns a new scanner for format-preserving structured-file passes. Filters out `_kv`-labeled patterns (those that match key+value pairs as a unit, which would corrupt YAML/JSON/TOML keys) and adds the provided extra literals. |
| `ScanPattern` | A single detection pattern with category and label. |
| `ScanPattern::from_regex(pattern, category, label)` | Create from a regex string. |
| `ScanPattern::from_literal(literal, category, label)` | Create from a literal string (auto-escaped). |
| `ScanConfig` | Configuration for chunk size and overlap size. |
| `ScanConfig::new(chunk_size, overlap_size)` | Explicit construction. |
| `ScanConfig::default()` | Defaults: 1 MiB chunk, 4 KiB overlap. |
| `ScanConfig::validate()` | Validate that `chunk_size > 0` and `overlap_size < chunk_size`. |
| `ScanStats` | Results of a scan: `bytes_processed`, `bytes_output`, `matches_found`, `replacements_applied`, `pattern_counts: HashMap<String, u64>`. `pattern_counts` is keyed by the `label` field of each `ScanPattern` and counts how many times that pattern matched. Only the scanner path populates this map; structured-processor hits are counted in `matches_found` but are not broken down by label here. |

## Store Module (`store`)

| Type / Function | Description |
|-----------------|-------------|
| `MappingStore` | Thread-safe, one-way replacement cache backed by `DashMap` (64 shards). |
| `MappingStore::new(generator, capacity_limit)` | Create with a generator and optional max entries. |
| `MappingStore::with_expected_capacity(generator, capacity_limit, expected)` | Pre-allocate for an expected number of unique values. |
| `MappingStore::get_or_insert(category, original)` | Primary API: returns cached replacement or generates and caches a new one. Atomic first-writer-wins. |
| `MappingStore::forward_lookup(category, original)` | Read-only lookup without insert. |
| `MappingStore::len()` / `is_empty()` | Current entry count. |
| `MappingStore::clear()` | Zeroize and remove all entries. |
| `MappingStore::iter()` | Iterator over `(Category, original, replacement)` triples. |

## Generator Module (`generator`)

| Type / Function | Description |
|-----------------|-------------|
| `ReplacementGenerator` | Trait: `fn generate(&self, category: &Category, original: &str) -> String`. Must be `Send + Sync`. |
| `HmacGenerator` | Deterministic generator using `HMAC-SHA256(key, category_tag \|\| "\x00" \|\| original)`. Key is zeroized on drop. |
| `HmacGenerator::new(key: [u8; 32])` | Create from a 32-byte key. |
| `HmacGenerator::from_slice(bytes)` | Create from a byte slice (must be exactly 32 bytes). |
| `RandomGenerator` | Non-deterministic generator using OS CSPRNG (`thread_rng`). |
| `RandomGenerator::new()` | Create a new random generator. |

## Strategy Module (`strategy`)

| Type / Function | Description |
|-----------------|-------------|
| `Strategy` | Trait: `fn name(&self) -> &str` + `fn replace(&self, original: &str, entropy: &[u8; 32]) -> String`. Object-safe. |
| `StrategyGenerator` | Adapter: bridges `Strategy` → `ReplacementGenerator` with configurable entropy. |
| `EntropyMode` | Enum: `Deterministic { key: [u8; 32] }` or `Random`. |
| `RandomString`, `RandomUuid`, `FakeIp`, `PreserveLength`, `HmacHash` | Five built-in strategy implementations (see [Pluggable Strategies](strategies.md)). |

## Processor Module (`processor`)

| Type / Function | Description |
|-----------------|-------------|
| `Processor` | Trait: `fn name()`, `fn can_handle(content, profile)`, `fn process(content, profile, store)`. Must be `Send + Sync`. |
| `ProcessorRegistry` | Maps processor names to `Arc<dyn Processor>`. `ProcessorRegistry::with_builtins()` pre-loads all ten built-in processors: `key_value`, `json`, `jsonl`, `yaml`, `xml`, `csv`, `toml`, `env`, `ini`, `log`. |
| `FileTypeProfile` | Associates a processor name, file extensions, field rules, and options. |
| `FieldRule` | A field pattern + optional category and label. |

## Archive Module (`processor::archive`)

| Type / Function | Description |
|-----------------|-------------|
| `ArchiveProcessor` | Processes `.tar`, `.tar.gz`, and `.zip` archives entry-by-entry. Routes entries to structured processors or the streaming scanner. Recursively processes nested archives up to a configurable depth. |
| `ArchiveProcessor::new(registry, scanner, store, profiles)` | Create from a `ProcessorRegistry`, `StreamScanner`, `MappingStore`, and file-type profiles. |
| `ArchiveProcessor::with_max_depth(depth)` | Builder method: set the maximum nesting depth for recursive archive processing (clamped to `MAX_ALLOWED_ARCHIVE_DEPTH`). |
| `ArchiveProcessor::with_parallel_threshold(threshold)` | Builder method: set the minimum file-entry count required to enable parallel entry sanitization. Default: `4`. Set to `usize::MAX` to disable entry-level parallelism (e.g. when outer file-level parallelism already saturates the thread budget). |
| `ArchiveFormat` | Enum: `Tar`, `TarGz`, `Zip`. |
| `ArchiveStats` | Processing results: `files_processed`, `entries_skipped`, `structured_hits`, `scanner_fallback`, `nested_archives`, `total_input_bytes`, `total_output_bytes`, `file_methods`, `file_scan_stats`. |
| `DEFAULT_ARCHIVE_DEPTH` | Default maximum nesting depth for recursive archive processing (`3`). |

## Report Module (`report`)

| Type / Function | Description |
|-----------------|-------------|
| `SanitizeReport` | Top-level report: `metadata`, `summary`, `files: Vec<FileReport>`. Never contains original secret values. |
| `SanitizeReport::to_json()` / `to_json_pretty()` | Serialize to compact or pretty-printed JSON. |
| `ReportMetadata` | Run parameters: `version`, `timestamp`, `deterministic`, `dry_run`, `strict`, `chunk_size`, `threads`, `secrets_file`. |
| `ReportSummary` | Aggregated summary: `total_files`, `total_matches`, `total_replacements`, `total_bytes_processed`, `total_bytes_output`, `duration_ms`, `pattern_counts`. `pattern_counts` is aggregated from all file entries. |
| `ReportBuilder` | Thread-safe report builder. Wrap in `Arc` for multi-threaded use. `record_file()` / `record_files()` add entries; `set_file_log_context(path, result)` attaches log context to a specific file entry; `finish()` computes wall-clock duration and returns `SanitizeReport`. |
| `FileReport` | Per-file results: `path`, `matches`, `replacements`, `bytes_processed`, `bytes_output`, `pattern_counts`, `method`, and optional `log_context`. `pattern_counts` maps each pattern label to its hit count for that file; it is empty (`{}`) when no labeled patterns matched or when matches came exclusively from the structured processor pass. `method` is `"scanner"` for plain-text streaming, `"structured:<format>"` for structured files (e.g. `"structured:json"`), or a composite for archives. `log_context` is `null`/absent unless `--extract-context` was used. |
| `FileReport::from_scan_stats(path, stats, method)` | Convenience constructor: converts `ScanStats` into a `FileReport`. |

## Log Context Module (`log_context`)

Scans sanitized output for error/warning keywords and captures the surrounding lines as context windows — useful for feeding triage information to LLMs or dashboards without exposing raw logs.

| Type / Constant / Function | Description |
|----------------------------|-------------|
| `DEFAULT_KEYWORDS` | Built-in keyword list: `["error", "failure", "warning", "warn", "fatal", "exception", "critical"]`. Matched as case-insensitive substrings. |
| `DEFAULT_CONTEXT_LINES` | Default lines of context around each match: `10`. |
| `DEFAULT_MAX_MATCHES` | Default cap on matches per result: `50`. |
| `LogContextConfig` | Configuration: `keywords`, `context_lines`, `max_matches`, `case_sensitive`. |
| `LogContextConfig::new()` | Default config (uses built-in keywords, 10 context lines, 50 match cap, case-insensitive). |
| `LogContextConfig::with_extra_keywords(iter)` | Merge additional keywords into the list without replacing the defaults. |
| `LogContextConfig::with_keywords(iter)` | Replace the keyword list entirely. |
| `LogContextConfig::with_context_lines(n)` | Set lines of context before/after each match. |
| `LogContextConfig::with_max_matches(n)` | Set the match cap. |
| `LogContextConfig::case_sensitive(bool)` | Enable case-sensitive matching (default: `false`). |
| `LogContextResult` | Output: `total_lines`, `match_count`, `truncated`, `matches: Vec<LogContextMatch>`. `truncated` is `true` when `max_matches` was reached before end-of-input. |
| `LogContextMatch` | A single match: `line_number` (1-based), `keyword` (which keyword triggered the match), `line` (the matching line), `before: Vec<String>` (up to `context_lines` preceding lines), `after: Vec<String>` (up to `context_lines` following lines). |
| `extract_context(content, config)` | In-memory variant. Collects all lines into a `Vec<&str>` first; suitable for content already in a buffer. |
| `extract_context_reader(reader, config)` | Streaming variant for large files. Uses an `O(context_lines)` ring buffer regardless of input size. Safe for multi-gigabyte files. Returns `io::Result<LogContextResult>`. |

### Example — in-memory

```rust
use sanitize_engine::log_context::{extract_context, LogContextConfig};

let log = "INFO  startup\nERROR disk full\nINFO  retrying\nINFO  done";
let config = LogContextConfig::new().with_context_lines(1);
let result = extract_context(log, &config);

assert_eq!(result.match_count, 1);
assert_eq!(result.matches[0].line_number, 2);
assert_eq!(result.matches[0].keyword, "error");
assert_eq!(result.matches[0].before, vec!["INFO  startup"]);
assert_eq!(result.matches[0].after,  vec!["INFO  retrying"]);
```

### Example — streaming (large files)

```rust
use sanitize_engine::log_context::{extract_context_reader, LogContextConfig};
use std::io::BufReader;
use std::fs::File;

let f = File::open("huge.log")?;
let config = LogContextConfig::new()
    .with_extra_keywords(["oomkilled", "timeout"])
    .with_context_lines(5)
    .with_max_matches(200);
let result = extract_context_reader(BufReader::new(f), &config)?;
println!("{} matches found in {} lines", result.match_count, result.total_lines);
```

### Report JSON shape for a file entry with `log_context`

When `--extract-context` is used, each file entry in the report's `files` array gains a `log_context` object:

```json
{
  "path": "app.log",
  "matches": 3,
  "replacements": 3,
  "bytes_processed": 10240,
  "bytes_output": 10240,
  "pattern_counts": { "kael_email": 2, "api_key": 1 },
  "method": "scanner",
  "log_context": {
    "total_lines": 1500,
    "match_count": 2,
    "truncated": false,
    "matches": [
      {
        "line_number": 42,
        "keyword": "error",
        "line": "2026-05-01T10:00:05Z ERROR db: connection timeout (DB_CONN_ERR)",
        "before": [
          "2026-05-01T10:00:04Z INFO  db: executing query"
        ],
        "after": [
          "2026-05-01T10:00:06Z INFO  retry: retrying connection"
        ]
      }
    ]
  }
}
```

`log_context` is omitted entirely from a file entry when `--extract-context` was not used.

## Atomic I/O Module (`atomic`)

| Type / Function | Description |
|-----------------|-------------|
| `AtomicFileWriter` | Crash-safe file writer: writes to a temp file, calls `fsync`, then atomically renames to the destination. On drop without `finish()`, cleans up the temp file. Implements `std::io::Write`. |
| `AtomicFileWriter::new(dest)` | Create and open a temp file in the same directory as `dest`. |
| `AtomicFileWriter::finish()` | Flush, sync, and atomically rename to destination. |
| `atomic_write(dest, data)` | Convenience: write `&[u8]` atomically to a path in one call. |

## Secrets Module (`secrets`)

| Type / Function | Description |
|-----------------|-------------|
| `SecretEntry` | A single secret: `pattern`, `kind` (`"regex"`, `"literal"`, or `"allow"`), `category`, `label`, `values` (optional `Vec<String>` for compact multi-value `kind: allow` entries). Zeroized on drop. |
| `SecretsFormat` | Enum: `Json`, `Yaml`, `Toml`. |
| `load_secrets_auto(data, password, format, force_plaintext)` | Detect encrypted vs plaintext and load secret patterns accordingly. Returns `(PatternCompileResult, was_encrypted)`. |
| `looks_encrypted(data)` | Heuristic: returns `true` if the data does not look like plaintext JSON/YAML/TOML (i.e. it's likely encrypted). |
| `encrypt_secrets(plaintext, password)` | Encrypt a byte slice with AES-256-GCM (PBKDF2 key derivation). |
| `decrypt_secrets(encrypted, password)` | Decrypt and return `Zeroizing<Vec<u8>>`. |
| `parse_secrets(content, format)` | Parse plaintext secrets into `Vec<SecretEntry>`. |
| `serialize_secrets(entries, format)` | Serialize `Vec<SecretEntry>` back to JSON, YAML, or TOML bytes. |
| `entries_to_patterns(entries)` | Convert `Vec<SecretEntry>` to `(Vec<ScanPattern>, warnings)`. Patterns that fail to compile are skipped and returned in warnings. |
| `parse_category(s)` | Parse a category string (`"email"`, `"custom:tag"`, etc.) into a `Category`. |

## Error Module (`error`)

| Type | Description |
|------|-------------|
| `SanitizeError` | Non-exhaustive error enum: `CapacityExceeded`, `InvalidSeedLength`, `IoError`, `ParseError`, `RecursionDepthExceeded`, `InputTooLarge`, `PatternCompileError`, `InvalidConfig`, `SecretsEmptyPassword`, `SecretsTooShort`, `SecretsDecryptFailed`, `SecretsCipherError(String)`, `SecretsFormatError { format, message }`, `SecretsInvalidUtf8(String)`, `SecretsPasswordRequired`, `ArchiveError`. |
| `Result<T>` | Type alias for `std::result::Result<T, SanitizeError>`. |

## Category Module (`category`)

| Type | Description |
|------|-------------|
| `Category` | Enum with 18 built-in variants (`Email`, `Name`, `Phone`, `IpV4`, `IpV6`, `CreditCard`, `Ssn`, `Hostname`, `MacAddress`, `ContainerId`, `Uuid`, `Jwt`, `AuthToken`, `FilePath`, `WindowsSid`, `Url`, `AwsArn`, `AzureResourceId`) plus `Custom(CompactString)`. |
| `Category::as_str()` | String representation (e.g. `"email"`, `"custom:tag"`). |
