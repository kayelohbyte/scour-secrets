//! JSON-in-log-line processor (NDJSON / structured log output).
//!
//! Processes files where each line may contain an embedded JSON object
//! (e.g. structured logging output from `slog`, `tracing-json`, `bunyan`,
//! `logrus`, Datadog, etc.).
//!
//! # Behaviour
//!
//! Each line is processed individually:
//!
//! 1. Scan for the first `{` on the line.
//! 2. If found, attempt to locate the matching `}` using brace-counting.
//! 3. Parse the extracted `{...}` span as JSON.
//! 4. If parsing succeeds, pass the JSON object through the full JSON
//!    processor with all field rules from the profile.
//! 5. Reconstruct: `line_prefix` + sanitised JSON + `line_suffix`.
//! 6. If parsing fails or no JSON span is found, the line is emitted
//!    unchanged. The outer double-pass streaming scan will still catch
//!    plain-text secrets on those lines.
//!
//! # Format Detection
//!
//! This processor is **not** auto-detected from `.log` extension.
//! It must be requested explicitly with `--format log`.
//! This avoids misprocessing plain-text log files that happen to contain
//! individual `{` characters.
//!
//! # Field Rules
//!
//! Use `"*"` to sanitize every string field inside the JSON payloads,
//! or specific dot-separated paths (e.g. `"user.token"`) to be selective.

use crate::error::Result;
use crate::processor::json_proc::JsonProcessor;
use crate::processor::limits::DEFAULT_INPUT_SIZE;
use crate::processor::{FileTypeProfile, Processor};
use crate::store::MappingStore;

/// Structured processor for NDJSON / structured-log files.
pub struct LogLineProcessor {
    json_proc: JsonProcessor,
}

impl LogLineProcessor {
    pub fn new() -> Self {
        Self {
            json_proc: JsonProcessor,
        }
    }
}

impl Default for LogLineProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl Processor for LogLineProcessor {
    fn name(&self) -> &'static str {
        "log"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        profile.processor == "log"
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        if content.len() > DEFAULT_INPUT_SIZE {
            use crate::error::SanitizeError;
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: DEFAULT_INPUT_SIZE,
            });
        }

        let text = String::from_utf8_lossy(content);
        let mut output = String::with_capacity(text.len());

        // Split on '\n'. `split('\n')` on a '\n'-terminated string produces a
        // trailing empty element — skip it so we don't emit an extra blank line.
        let raw_lines: Vec<&str> = text.split('\n').collect();
        let lines = if raw_lines.last().is_some_and(|l| l.is_empty()) {
            &raw_lines[..raw_lines.len() - 1]
        } else {
            &raw_lines[..]
        };

        for line in lines {
            let processed_line = process_log_line(line, profile, store, &self.json_proc);
            output.push_str(&processed_line);
            output.push('\n');
        }

        // Restore the absence of a trailing newline if the original had none.
        if !text.ends_with('\n') && output.ends_with('\n') {
            output.pop();
        }

        Ok(output.into_bytes())
    }
}

/// Process a single log line: find embedded JSON, sanitise it, recombine.
/// Falls back to returning the line unchanged on any error.
fn process_log_line(
    line: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
    json_proc: &JsonProcessor,
) -> String {
    // Locate the first `{` in the line.
    let Some(json_start) = line.find('{') else {
        return line.to_string();
    };

    // Find the matching closing `}` by counting brace depth.
    let json_end = match find_matching_brace(&line[json_start..]) {
        Some(relative_end) => json_start + relative_end,
        None => return line.to_string(),
    };

    let json_span = &line[json_start..=json_end];
    let prefix = &line[..json_start];
    let suffix = &line[json_end + 1..];

    // Build a compact-JSON profile so the output stays on one line.
    let compact_profile =
        FileTypeProfile::new("json", profile.fields.clone()).with_option("compact", "true");

    // Try to sanitise the JSON span.
    match json_proc.process(json_span.as_bytes(), &compact_profile, store) {
        Ok(sanitised_bytes) => {
            let sanitised = String::from_utf8_lossy(&sanitised_bytes);
            format!("{}{}{}", prefix, sanitised, suffix)
        }
        // If JSON parsing fails (e.g. the `{` is part of a template string),
        // emit the line unchanged. The streaming scanner pass handles the rest.
        Err(_) => line.to_string(),
    }
}

/// Find the index of the matching `}` for the `{` at position 0 of `s`.
/// Returns `None` if the string does not start with `{` or has no matching `}`.
fn find_matching_brace(s: &str) -> Option<usize> {
    if !s.starts_with('{') {
        return None;
    }
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let bytes = s.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
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
        FileTypeProfile::new("log", vec![FieldRule::new("*")])
    }

    #[test]
    fn pure_ndjson_line() {
        let store = make_store();
        let proc = LogLineProcessor::new();
        let content = b"{\"level\":\"info\",\"token\":\"abc123\",\"msg\":\"ok\"}\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("abc123"));
        // JSON structure preserved.
        assert!(text.contains("\"level\""));
    }

    #[test]
    fn log_prefix_before_json() {
        let store = make_store();
        let proc = LogLineProcessor::new();
        let content = b"2024-01-01T00:00:00Z INFO {\"token\":\"secret\",\"user\":\"bob\"}\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        // Prefix preserved.
        assert!(text.contains("2024-01-01T00:00:00Z INFO "));
        // Secrets sanitised.
        assert!(!text.contains("secret"));
        assert!(!text.contains("bob"));
    }

    #[test]
    fn non_json_line_preserved() {
        let store = make_store();
        let proc = LogLineProcessor::new();
        let content = b"plain text log line with no json\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        assert_eq!(output, content);
    }

    #[test]
    fn malformed_json_line_preserved() {
        let store = make_store();
        let proc = LogLineProcessor::new();
        // Contains `{` but is not valid JSON — should pass through unchanged.
        let content = b"ERROR: template {name} not found\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        assert_eq!(output, content);
    }

    #[test]
    fn multi_line_ndjson() {
        let store = make_store();
        let proc = LogLineProcessor::new();
        let content = b"{\"token\":\"abc\"}\n{\"key\":\"xyz\"}\n";
        let output = proc.process(content, &wildcard_profile(), &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("abc"));
        assert!(!text.contains("xyz"));
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn find_matching_brace_simple() {
        assert_eq!(find_matching_brace("{\"a\":\"b\"}"), Some(8));
    }

    #[test]
    fn find_matching_brace_nested() {
        assert_eq!(find_matching_brace("{\"a\":{\"b\":\"c\"}}"), Some(14));
    }

    #[test]
    fn find_matching_brace_brace_in_string() {
        assert_eq!(find_matching_brace("{\"a\":\"{not_nested}\"}"), Some(19));
    }
}
