//! NDJSON / JSON Lines structured processor.
//!
//! Processes files where each non-empty line is an independent JSON object
//! (Newline-Delimited JSON, also called JSON Lines). Unlike the [`JsonProcessor`](crate::processor::json_proc::JsonProcessor),
//! this processor never builds a full in-memory parse tree for the whole file —
//! each line is parsed, walked, serialised, and written out independently,
//! keeping per-line memory overhead constant regardless of input size.
//!
//! When used via the CLI with a matching profile, the processor is invoked
//! through the streaming path: the file is opened as a reader and processed
//! line-by-line without `fs::read` loading it into a `Vec<u8>` first. This
//! makes GB-scale NDJSON log files practical to sanitize.
//!
//! # Options
//!
//! | Key | Values | Default | Description |
//! |-----|--------|---------|-------------|
//! | `skip_invalid` | `"true"` / `"false"` | `"false"` | Pass malformed lines through unchanged instead of returning an error. Useful for mixed log files that interleave plain-text lines with JSON. |
//! | `compact` | `"true"` / `"false"` | `"true"` | Serialise each output line as compact JSON. Set to `"false"` only for debugging — pretty-printed NDJSON is non-standard. |
//!
//! # Example profile entry
//!
//! ```yaml
//! - processor: jsonl
//!   extensions: [".jsonl", ".ndjson", ".log"]
//!   options:
//!     skip_invalid: "true"
//!   fields:
//!     - pattern: "*.email"
//!       category: email
//!     - pattern: "*.password"
//!       category: "custom:password"
//! ```

use crate::error::{Result, SanitizeError};
use crate::processor::json_proc::walk_json;
use crate::processor::{FileTypeProfile, Processor};
use crate::store::MappingStore;
use serde_json::Value;
use std::io::{self, BufRead, BufReader, Write};

/// Structured processor for NDJSON / JSON Lines files.
pub struct JsonLinesProcessor;

impl JsonLinesProcessor {
    /// Core line-by-line processing logic, shared by both `process` and
    /// `process_stream`. Reads from any `BufRead` source and writes to any
    /// `Write` sink.
    fn process_lines(
        reader: impl BufRead,
        writer: &mut dyn Write,
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<()> {
        let skip_invalid = profile
            .options
            .get("skip_invalid")
            .is_some_and(|v| v == "true");

        let compact = profile
            .options
            .get("compact")
            .map_or(true, |v| v != "false");

        for (line_no, line_result) in reader.lines().enumerate() {
            let raw_line = line_result?;

            if raw_line.trim().is_empty() {
                continue;
            }

            let mut value: Value = match serde_json::from_str(&raw_line) {
                Ok(v) => v,
                Err(e) => {
                    if skip_invalid {
                        writer.write_all(raw_line.as_bytes())?;
                        writer.write_all(b"\n")?;
                        continue;
                    }
                    return Err(SanitizeError::ParseError {
                        format: "JSONL".into(),
                        message: format!("line {}: {}", line_no + 1, e),
                    });
                }
            };

            walk_json(&mut value, "", profile, store, 0)?;

            let serialised = if compact {
                serde_json::to_vec(&value)
            } else {
                serde_json::to_vec_pretty(&value)
            }
            .map_err(|e| SanitizeError::IoError(format!("JSONL serialize error: {}", e)))?;

            writer.write_all(&serialised)?;
            writer.write_all(b"\n")?;
        }

        Ok(())
    }
}

impl Processor for JsonLinesProcessor {
    fn name(&self) -> &'static str {
        "jsonl"
    }

    fn can_handle(&self, content: &[u8], profile: &FileTypeProfile) -> bool {
        if profile.processor == "jsonl" {
            return true;
        }
        // Heuristic: first non-empty line starts with `{` and there are
        // multiple lines — distinguishes NDJSON from a single-object JSON file.
        let Ok(text) = std::str::from_utf8(content) else {
            return false;
        };
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        let first = match lines.next() {
            Some(l) => l.trim_start(),
            None => return false,
        };
        first.starts_with('{') && lines.next().is_some()
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        // Validate UTF-8 upfront so the error points at the file, not a line.
        std::str::from_utf8(content).map_err(|e| SanitizeError::ParseError {
            format: "JSONL".into(),
            message: format!("invalid UTF-8: {}", e),
        })?;
        let mut output = Vec::with_capacity(content.len());
        Self::process_lines(BufReader::new(content), &mut output, profile, store)?;
        Ok(output)
    }

    fn process_stream(
        &self,
        reader: &mut dyn io::Read,
        writer: &mut dyn io::Write,
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<()> {
        Self::process_lines(BufReader::new(reader), writer, profile, store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::generator::HmacGenerator;
    use crate::processor::profile::FieldRule;
    use std::sync::Arc;

    fn make_store() -> MappingStore {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        MappingStore::new(gen, None)
    }

    fn make_profile(fields: Vec<FieldRule>) -> FileTypeProfile {
        FileTypeProfile::new("jsonl", fields).with_option("compact", "true")
    }

    #[test]
    fn replaces_matched_fields_across_lines() {
        let store = make_store();
        let proc = JsonLinesProcessor;
        let input = b"{\"email\":\"a@b.com\",\"level\":\"info\"}\n{\"email\":\"c@d.com\",\"level\":\"warn\"}\n";
        let profile = make_profile(vec![FieldRule::new("email").with_category(Category::Email)]);

        let result = proc.process(input, &profile, &store).unwrap();
        let lines: Vec<&str> = std::str::from_utf8(&result).unwrap().lines().collect();

        assert_eq!(lines.len(), 2);
        let v0: Value = serde_json::from_str(lines[0]).unwrap();
        let v1: Value = serde_json::from_str(lines[1]).unwrap();
        assert_ne!(v0["email"].as_str().unwrap(), "a@b.com");
        assert_ne!(v1["email"].as_str().unwrap(), "c@d.com");
        assert_eq!(v0["level"].as_str().unwrap(), "info");
        assert_eq!(v1["level"].as_str().unwrap(), "warn");
    }

    #[test]
    fn process_stream_matches_process() {
        let input = b"{\"email\":\"a@b.com\"}\n{\"email\":\"c@d.com\"}\n";
        let profile = make_profile(vec![FieldRule::new("email").with_category(Category::Email)]);

        // process
        let store1 = make_store();
        let proc = JsonLinesProcessor;
        let from_process = proc.process(input, &profile, &store1).unwrap();

        // process_stream with identical store seed
        let store2 = make_store();
        let mut reader = io::Cursor::new(input);
        let mut from_stream = Vec::new();
        proc.process_stream(&mut reader, &mut from_stream, &profile, &store2)
            .unwrap();

        assert_eq!(from_process, from_stream);
    }

    #[test]
    fn glob_suffix_pattern() {
        let store = make_store();
        let proc = JsonLinesProcessor;
        let input = b"{\"db\":{\"password\":\"pw1\"},\"name\":\"app\"}\n";
        let profile = make_profile(vec![
            FieldRule::new("*.password").with_category(Category::Custom("pw".into()))
        ]);

        let result = proc.process(input, &profile, &store).unwrap();
        let trimmed = result
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map_or(&[][..], |i| &result[..=i]);
        let v: Value = serde_json::from_slice(trimmed).unwrap();
        assert_ne!(v["db"]["password"].as_str().unwrap(), "pw1");
        assert_eq!(v["name"].as_str().unwrap(), "app");
    }

    #[test]
    fn skip_invalid_passes_through_bad_lines() {
        let store = make_store();
        let proc = JsonLinesProcessor;
        let input = b"{\"email\":\"a@b.com\"}\nnot json at all\n{\"email\":\"c@d.com\"}\n";
        let profile = FileTypeProfile::new(
            "jsonl",
            vec![FieldRule::new("email").with_category(Category::Email)],
        )
        .with_option("skip_invalid", "true")
        .with_option("compact", "true");

        let result = proc.process(input, &profile, &store).unwrap();
        let text = std::str::from_utf8(&result).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], "not json at all");
        let v0: Value = serde_json::from_str(lines[0]).unwrap();
        assert_ne!(v0["email"].as_str().unwrap(), "a@b.com");
    }

    #[test]
    fn error_on_invalid_line_by_default() {
        let store = make_store();
        let proc = JsonLinesProcessor;
        let input = b"{\"email\":\"a@b.com\"}\nnot json\n";
        let profile = make_profile(vec![FieldRule::new("email").with_category(Category::Email)]);

        assert!(proc.process(input, &profile, &store).is_err());
    }

    #[test]
    fn deterministic_same_value_same_replacement() {
        let store = make_store();
        let proc = JsonLinesProcessor;
        let input = b"{\"email\":\"a@b.com\"}\n{\"email\":\"a@b.com\"}\n";
        let profile = make_profile(vec![FieldRule::new("email").with_category(Category::Email)]);

        let result = proc.process(input, &profile, &store).unwrap();
        let lines: Vec<&str> = std::str::from_utf8(&result).unwrap().lines().collect();
        let v0: Value = serde_json::from_str(lines[0]).unwrap();
        let v1: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(v0["email"].as_str().unwrap(), v1["email"].as_str().unwrap());
    }

    #[test]
    fn can_handle_heuristic_multi_line_json_objects() {
        let proc = JsonLinesProcessor;
        let profile = FileTypeProfile::new("yaml", vec![]);
        let input = b"{\"a\":1}\n{\"b\":2}\n";
        assert!(proc.can_handle(input, &profile));
    }

    #[test]
    fn can_handle_rejects_single_object() {
        let proc = JsonLinesProcessor;
        let profile = FileTypeProfile::new("yaml", vec![]);
        let input = b"{\"a\":1}";
        assert!(!proc.can_handle(input, &profile));
    }

    #[test]
    fn supports_streaming_is_true() {
        assert!(JsonLinesProcessor.supports_streaming());
    }
}
