//! INI / CFG file processor with `[section]` awareness.
//!
//! Handles Windows/Unix INI-style configuration files:
//!
//! ```ini
//! [section]
//! key = value
//! key: value
//! ; semicolon comment
//! # hash comment
//! ```
//!
//! # Key Paths
//!
//! Field rules use dot notation combining section and key:
//! - `"database.host"` — matches key `host` in section `[database]`
//! - `"*"` — matches all key=value pairs in all sections
//! - `"global_key"` — matches a key before any section header (global scope)
//!
//! # Formatting Preservation
//!
//! - Section headers `[section]` are preserved verbatim.
//! - `#` and `;` comment lines are preserved verbatim.
//! - Blank lines are preserved.
//! - Leading whitespace in value is stripped; quoting is not applied.
//! - Inline comments (`key = value ; comment`) are stripped and NOT written
//!   back to avoid leaking sensitive context in comments.
//! - Both `key = value` and `key: value` assignment operators are handled.

use crate::error::{Result, SanitizeError};
use crate::processor::limits::DEFAULT_INPUT_SIZE;
use crate::processor::{find_matching_rule, replace_value, FileTypeProfile, Processor};
use crate::store::MappingStore;

/// Structured processor for INI / CFG files.
pub struct IniProcessor;

impl Processor for IniProcessor {
    fn name(&self) -> &'static str {
        "ini"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        profile.processor == "ini"
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        if content.len() > DEFAULT_INPUT_SIZE {
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: DEFAULT_INPUT_SIZE,
            });
        }

        let text = String::from_utf8_lossy(content);
        let mut output = String::with_capacity(text.len());
        let mut current_section: Option<String> = None;

        for line in text.split('\n') {
            let trimmed = line.trim();

            // Blank line.
            if trimmed.is_empty() {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Comment line.
            if trimmed.starts_with('#') || trimmed.starts_with(';') {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Section header: `[section_name]`
            if trimmed.starts_with('[') {
                if let Some(close) = trimmed.find(']') {
                    current_section = Some(trimmed[1..close].trim().to_string());
                }
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Key=value or key:value line.
            let Some((raw_key, raw_value)) = split_kv(trimmed) else {
                // Unrecognised line — preserve as-is.
                output.push_str(line);
                output.push('\n');
                continue;
            };

            let key = raw_key.trim();

            // Capture leading whitespace for output reconstruction.
            let indent_len = line.len() - line.trim_start().len();
            let indent = &line[..indent_len];

            // Capture the original delimiter (` = ` or ` : ` etc.).
            let delimiter = extract_delimiter(line, key, raw_value);

            // Strip inline comments from the value.
            let value = strip_inline_comment(raw_value.trim_start());

            // Build section-qualified key path.
            let path = match &current_section {
                Some(section) => format!("{}.{}", section, key),
                None => key.to_string(),
            };

            if let Some(rule) = find_matching_rule(&path, profile) {
                let replaced = replace_value(value, rule, store, "ini")?;
                output.push_str(indent);
                output.push_str(key);
                output.push_str(&delimiter);
                output.push_str(&replaced);
                output.push('\n');
            } else {
                output.push_str(line);
                output.push('\n');
            }
        }

        // Remove the trailing newline we added if the original didn't end with one.
        if !text.ends_with('\n') && output.ends_with('\n') {
            output.pop();
        }

        Ok(output.into_bytes())
    }
}

/// Split `key = value` or `key: value` on the first `=` or `:` delimiter.
/// Returns `None` if no delimiter is found.
fn split_kv(s: &str) -> Option<(&str, &str)> {
    // Prefer `=` first (most common in INI files).
    if let Some(pos) = s.find('=') {
        return Some((&s[..pos], &s[pos + 1..]));
    }
    if let Some(pos) = s.find(':') {
        return Some((&s[..pos], &s[pos + 1..]));
    }
    None
}

/// Reproduce the original delimiter string from the source line.
/// Falls back to `" = "` if extraction fails.
fn extract_delimiter(line: &str, key: &str, after_delim: &str) -> String {
    // Locate the key in the line to find where the delimiter starts.
    if let Some(key_start) = line.find(key.trim()) {
        let after_key = &line[key_start + key.trim().len()..];
        // The delimiter ends where after_delim (unstripped) begins.
        // after_delim already includes everything after the `=`/`:` character.
        // We need: after_key[..pos_of_value_start].
        let delimiter_end = after_key
            .len()
            .saturating_sub(after_delim.len())
            .saturating_add(1);
        // `delimiter_end` is a byte offset derived from length arithmetic, so it
        // can land inside a multi-byte char (e.g. a U+FFFD produced by
        // from_utf8_lossy on invalid UTF-8). Guard the slice to avoid panicking;
        // fall through to the default delimiter when it isn't a char boundary.
        if delimiter_end <= after_key.len() && after_key.is_char_boundary(delimiter_end) {
            return after_key[..delimiter_end].to_string();
        }
    }
    " = ".to_string()
}

/// Strip trailing inline comments from a value string.
/// Recognises ` # ` and ` ; ` as inline comment markers.
fn strip_inline_comment(value: &str) -> &str {
    for marker in [" # ", " ; "] {
        if let Some(pos) = value.find(marker) {
            return value[..pos].trim_end();
        }
    }
    value.trim_end()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::HmacGenerator;
    use crate::processor::profile::FieldRule;
    use std::sync::Arc;

    fn make_store() -> MappingStore {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        MappingStore::new(gen, None)
    }

    fn wildcard_profile() -> FileTypeProfile {
        FileTypeProfile::new("ini", vec![FieldRule::new("*")])
    }

    #[test]
    fn basic_ini_replacement() {
        let store = make_store();
        let proc = IniProcessor;
        let content =
            b"[database]\nhost = db.corp.com\npassword = s3cret\n\n[smtp]\nuser = admin\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        // Values replaced.
        assert!(!text.contains("db.corp.com"));
        assert!(!text.contains("s3cret"));
        assert!(!text.contains("admin"));
        // Section headers preserved.
        assert!(text.contains("[database]"));
        assert!(text.contains("[smtp]"));
        // Keys preserved.
        assert!(text.contains("host =") || text.contains("host="));
    }

    #[test]
    fn section_qualified_rule() {
        let store = make_store();
        let proc = IniProcessor;
        let content = b"[database]\npassword = secret\n[app]\nname = myapp\n";
        let profile = FileTypeProfile::new("ini", vec![FieldRule::new("database.password")]);
        let output = proc.process(content, &profile, &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        // password replaced, app.name untouched.
        assert!(!text.contains("secret"));
        assert!(text.contains("myapp"));
    }

    #[test]
    fn comments_and_blanks_preserved() {
        let store = make_store();
        let proc = IniProcessor;
        let content = b"# Global config\n\n[section]\n; this is a semicolon comment\nkey = val\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("# Global config"));
        assert!(text.contains("; this is a semicolon comment"));
        // Blank line preserved.
        assert!(text.contains("\n\n"));
    }

    #[test]
    fn colon_delimiter_handled() {
        let store = make_store();
        let proc = IniProcessor;
        let content = b"[section]\napi_key: abc123\n";
        let profile = FileTypeProfile::new("ini", vec![FieldRule::new("section.api_key")]);
        let output = proc.process(content, &profile, &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("abc123"));
        // Non-secret structure preserved: section header, key, and `:` delimiter.
        assert!(text.contains("[section]"));
        assert!(text.contains("api_key:"));
    }

    #[test]
    fn invalid_utf8_value_does_not_panic() {
        // Fuzz regression (fuzz_ini crash-c11471bb): `=` followed by a lone
        // 0xCA byte becomes `=\u{FFFD}` via from_utf8_lossy, and the delimiter
        // reconstruction sliced `after_key` at a byte index inside the 3-byte
        // replacement char. Must process cleanly instead of panicking.
        let store = make_store();
        let content = [b'=', 0xCA, b'\n'];
        let output = IniProcessor
            .process(&content, &wildcard_profile(), &store)
            .expect("invalid-UTF-8 INI value must not panic or error");
        // Output is valid UTF-8 and round-trips without crashing.
        String::from_utf8(output).expect("output must be valid UTF-8");
    }

    #[test]
    fn input_too_large_returns_error() {
        let store = make_store();
        // One byte over the limit — only the length is checked before any parsing.
        let content = vec![b'\n'; DEFAULT_INPUT_SIZE + 1];
        let err = IniProcessor
            .process(&content, &wildcard_profile(), &store)
            .unwrap_err();
        assert!(
            matches!(err, SanitizeError::InputTooLarge { .. }),
            "oversized input must return InputTooLarge; got: {err:?}",
        );
    }
}
