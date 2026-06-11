# Log Context Extraction

The `log_context` module scans sanitized output for keyword-matching lines and
captures surrounding context windows. The result is structured for LLM triage
(see [llm.md](llm.md)) and human review.

## Quick Start

```rust
use rust_sanitize::log_context::{extract_context, LogContextConfig};

let log = "INFO  start\nERROR disk full\nINFO  retrying\nWARN  degraded\nINFO  done";

let config = LogContextConfig::new().with_context_lines(1);
let result = extract_context(log, &config);

assert_eq!(result.match_count, 2);                      // "error" and "warn"
assert_eq!(result.matches[0].keyword, "error");
assert_eq!(result.matches[0].before, vec!["INFO  start"]);
assert_eq!(result.matches[0].after,  vec!["INFO  retrying"]);
assert_eq!(result.matches[0].line_number, 2);           // 1-based
```

## Configuration

`LogContextConfig` is built with a fluent API:

```rust
use rust_sanitize::log_context::LogContextConfig;

let config = LogContextConfig::new()
    .with_extra_keywords(["timeout", "oomkilled"])  // append to defaults
    .with_context_lines(15)                         // lines before + after each hit
    .with_max_matches(100)                          // cap before truncation
    .case_sensitive(false);                         // default: case-insensitive
```

| Method | Default | Description |
|---|---|---|
| `with_keywords(list)` | — | Replace all keywords with the given list |
| `with_extra_keywords(list)` | — | Append to the default keyword list |
| `with_context_lines(n)` | 10 | Lines of context captured before and after each match |
| `with_max_matches(n)` | 50 | Stop collecting after this many matches; sets `truncated = true` |
| `case_sensitive(bool)` | `false` | Toggle case-sensitive keyword matching |

### Default keywords

`error`, `failure`, `warning`, `warn`, `fatal`, `exception`, `critical`

These are exported as `DEFAULT_KEYWORDS` if you need to reference or extend them.

## Output Types

### `LogContextResult`

| Field | Type | Description |
|---|---|---|
| `total_lines` | `usize` | Total lines in the input |
| `match_count` | `usize` | Number of matches in `matches` |
| `matches` | `Vec<LogContextMatch>` | The captured matches |
| `truncated` | `bool` | `true` when `max_matches` was reached; more matches exist |

### `LogContextMatch`

| Field | Type | Description |
|---|---|---|
| `line_number` | `usize` | 1-based line number of the matching line |
| `keyword` | `String` | The keyword that triggered the match |
| `line` | `String` | The matching line verbatim |
| `before` | `Vec<String>` | Up to `context_lines` lines before the match, in order |
| `after` | `Vec<String>` | Up to `context_lines` lines after the match, in order |

## Streaming Reader Variant

For large files where reading the entire content into a `String` is undesirable,
use `extract_context_reader`:

```rust
use rust_sanitize::log_context::{extract_context_reader, LogContextConfig};
use std::io::Cursor;

let log = b"INFO start\nERROR disk full\nINFO done";
let mut reader = Cursor::new(log);
let config = LogContextConfig::new();
let result = extract_context_reader(&mut reader, &config).unwrap();
```

The reader variant buffers only the context window, not the full file.

## Integration with LLM Prompts

`LogContextResult` is stored on `FileReport` and automatically included in
LLM prompts when `Some(&report)` is passed to `format_llm_prompt`. The
notable events section is only emitted when `match_count > 0`.

```rust
use rust_sanitize::log_context::{extract_context, LogContextConfig};

// After sanitizing, extract context from the sanitized output.
let ctx = extract_context(&sanitized_text, &LogContextConfig::new());

// Record it on the report for inclusion in the LLM prompt.
report_builder.set_file_log_context("app.log", ctx);
```
