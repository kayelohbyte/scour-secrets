//! `.env` file processor.
//!
//! Handles shell-style environment variable files with lines of the form:
//!
//! ```text
//! KEY=value
//! KEY="quoted value"
//! KEY='single quoted'
//! export KEY=value
//! # comment lines are preserved
//! ```
//!
//! The `export` keyword is stripped before key matching so that a
//! FieldRule for `"SECRET_KEY"` correctly matches both `SECRET_KEY=val`
//! and `export SECRET_KEY=val`.
//!
//! # Inline Comments
//!
//! Unquoted values may have inline comments (`KEY=value # comment`).
//! The comment and trailing whitespace are stripped before replacement
//! and the comment is NOT written back (it may contain sensitive context).
//! Quoted values are treated as opaque — everything between the quotes
//! is the value.
//!
//! # Formatting Preservation
//!
//! - Leading whitespace, blank lines, and `#` comment lines are preserved.
//! - The original quoting style (single, double, or unquoted) is retained.
//! - The `export` prefix, if present, is retained in the output.

use crate::error::{Result, SanitizeError};
use crate::processor::limits::DEFAULT_INPUT_SIZE;
use crate::processor::{
    find_field_signal, find_matching_rule, replace_by_signal, replace_value, FileTypeProfile,
    Processor,
};
use crate::store::MappingStore;

/// Structured processor for `.env` / shell environment files.
pub struct EnvProcessor;

impl Processor for EnvProcessor {
    fn name(&self) -> &'static str {
        "env"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        profile.processor == "env"
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

        for line in text.split('\n') {
            let trimmed = line.trim();

            // Preserve blank lines.
            if trimmed.is_empty() {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Preserve comment-only lines.
            if trimmed.starts_with('#') {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Capture leading whitespace (indentation) for output reconstruction.
            let indent_len = line.len() - line.trim_start().len();
            let indent = &line[..indent_len];

            // Detect and preserve `export ` prefix.
            let (has_export, after_export) = if let Some(rest) = trimmed.strip_prefix("export ") {
                (true, rest.trim_start())
            } else {
                (false, trimmed)
            };

            // Split on the first `=`.
            let Some((raw_key, after_eq)) = after_export.split_once('=') else {
                // No `=` — not a key=value line; preserve as-is.
                output.push_str(line);
                output.push('\n');
                continue;
            };

            let key = raw_key.trim();

            // Detect quoting and extract the inner value.
            let (quote_char, inner_value) = detect_env_quotes(after_eq);

            // Strip inline comments from unquoted values.
            let inner_value = if quote_char.is_none() {
                // Everything before a ` #` (space-hash) is the value.
                inner_value
                    .find(" #")
                    .map_or(inner_value, |pos| &inner_value[..pos])
                    .trim_end()
            } else {
                inner_value
            };

            if let Some(rule) = find_matching_rule(key, profile) {
                let replaced = replace_value(inner_value, rule, store, "env")?;

                // Reconstruct: indent + [export ] + KEY=["']value["']
                output.push_str(indent);
                if has_export {
                    output.push_str("export ");
                }
                output.push_str(key);
                output.push('=');
                if let Some(q) = quote_char {
                    output.push(q);
                    output.push_str(&replaced);
                    output.push(q);
                } else {
                    output.push_str(&replaced);
                }
                output.push('\n');
            } else if let Some(sig) = find_field_signal(key, &profile.field_name_signals) {
                if let Some(replaced) = replace_by_signal(inner_value, sig, store, "env")? {
                    output.push_str(indent);
                    if has_export {
                        output.push_str("export ");
                    }
                    output.push_str(key);
                    output.push('=');
                    if let Some(q) = quote_char {
                        output.push(q);
                        output.push_str(&replaced);
                        output.push(q);
                    } else {
                        output.push_str(&replaced);
                    }
                    output.push('\n');
                } else {
                    output.push_str(line);
                    output.push('\n');
                }
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

/// Detect surrounding quotes and return `(quote_char, inner_value)`.
/// Returns `(None, value)` for unquoted values.
fn detect_env_quotes(value: &str) -> (Option<char>, &str) {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return (Some(first as char), &value[1..value.len() - 1]);
        }
    }
    (None, value)
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
        FileTypeProfile::new("env", vec![FieldRule::new("*")])
    }

    #[test]
    fn basic_key_value() {
        let store = make_store();
        let proc = EnvProcessor;
        let content = b"SECRET_KEY=abc123\nDB_HOST=localhost\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("abc123"));
        assert!(!text.contains("localhost"));
        // Keys are preserved.
        assert!(text.contains("SECRET_KEY="));
        assert!(text.contains("DB_HOST="));
    }

    #[test]
    fn export_prefix_preserved() {
        let store = make_store();
        let proc = EnvProcessor;
        let content = b"export SECRET=hunter2\nDBPASS=s3cret\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("s3cret"));
        // `export` keyword is kept.
        assert!(text.contains("export SECRET="));
        // Non-export line works too.
        assert!(text.contains("DBPASS="));
    }

    #[test]
    fn quoted_values() {
        let store = make_store();
        let proc = EnvProcessor;
        let content = b"PW=\"my secret\"\nKEY='another secret'\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("my secret"));
        assert!(!text.contains("another secret"));
        // Quote chars are preserved.
        assert!(text.contains("PW=\""));
        assert!(text.contains("KEY='"));
    }

    #[test]
    fn comments_and_blanks_preserved() {
        let store = make_store();
        let proc = EnvProcessor;
        let content = b"# This is a comment\n\nKEY=value\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("# This is a comment"));
        assert!(text.contains("\n\n"));
    }

    #[test]
    fn field_rule_targets_specific_key() {
        let store = make_store();
        let proc = EnvProcessor;
        let content = b"SECRET=abc123\nPUBLIC_URL=https://example.com\n";
        let profile = FileTypeProfile::new("env", vec![FieldRule::new("SECRET")]);
        let output = proc.process(content, &profile, &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        // SECRET replaced, PUBLIC_URL unchanged.
        assert!(!text.contains("abc123"));
        assert!(text.contains("https://example.com"));
    }
}
