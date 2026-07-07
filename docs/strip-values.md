# Strip Values

`strip_values_from_text` removes the value side of every `key = value` line,
leaving keys, delimiters, comments, and structure intact. It is a lightweight
alternative to full sanitization when you only need to share a config file's
shape — not its content.

## When to Use This vs Full Sanitization

| | `strip_values_from_text` | Full sanitization |
|---|---|---|
| **Output** | Keys preserved, values blanked | Structurally plausible replacements |
| **Reversibility** | Not applicable — values are gone | One-way, no restore |
| **Secrets file needed** | No | Yes (or `--profile`) |
| **Best for** | Sharing config structure for review | Sharing sanitized data for analysis or LLM triage |

Use `strip_values_from_text` when the question is "what keys does this config
have?" and full sanitization when the question is "what does this data look like
with secrets removed?"

## API

```rust
pub fn strip_values_from_text(
    content: &str,
    delimiter: &str,
    comment_prefix: &str,
) -> String
```

| Parameter | Description |
|---|---|
| `content` | The full text of the config file |
| `delimiter` | The key/value separator, e.g. `"="` or `":"` |
| `comment_prefix` | Lines starting with this string are passed through unchanged, e.g. `"#"` or `";"` |

## Example

```rust
use scour_secrets::strip_values_from_text;

let input = "\
# Database settings
[database]
host = db-prod-01.internal
port = 5432
password = s3cr3t!

[cache]
url = redis://10.0.0.5:6379
";

let output = strip_values_from_text(input, "=", "#");
// # Database settings
// [database]
// host =
// port =
// password =
//
// [cache]
// url =
```

## Behaviour Details

- **Lines with the delimiter** — everything after the first occurrence is removed;
  the key and delimiter are kept. Leading whitespace in the key is preserved.
- **Comment lines** — lines whose trimmed form starts with `comment_prefix` are
  passed through unchanged.
- **Blank lines** — passed through unchanged.
- **Lines without a delimiter** — passed through unchanged. This covers section
  headers (`[section]`), bare directives, and any non-key-value content.
- **Inline comments** — not handled separately; if the delimiter appears before
  a comment marker, the comment is stripped along with the value.

## CLI

The `--strip-values` flag exposes this function directly on key-value
format files. See the [CLI reference](cli-reference.md) for usage.
