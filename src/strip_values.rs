//! Key-only structure extraction for configuration files.
//!
//! Strips the value side of every `key = value` line, leaving only the key
//! and delimiter. Comments, blank lines, and section headers (lines without a
//! delimiter, such as `[section]`) are passed through unchanged.
//!
//! This is useful for sharing a configuration file's structure (e.g. for a
//! code review or LLM prompt) without exposing the actual values.
//!
//! # Example
//!
//! ```rust
//! use rust_sanitize::strip_values_from_text;
//!
//! let input = "# db settings\nhost = localhost\nport = 5432\n";
//! let output = strip_values_from_text(input, "=", "#");
//!
//! assert!(output.contains("host =\n"));
//! assert!(output.contains("port =\n"));
//! assert!(!output.contains("localhost"));
//! assert!(output.contains("# db settings\n"));
//! ```

/// Strip values from `content`, preserving keys, comments, and structure.
///
/// For each line:
/// - Lines that are empty or start with `comment_prefix` are emitted unchanged.
/// - Lines containing `delimiter` have everything after the first occurrence
///   of the delimiter removed (the delimiter itself is kept).
/// - Lines without a delimiter (e.g. section headers like `[section]`) are
///   emitted unchanged.
#[must_use]
pub fn strip_values_from_text(content: &str, delimiter: &str, comment_prefix: &str) -> String {
    let mut out = String::with_capacity(content.len() / 2);
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(comment_prefix) {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if let Some(delim_pos) = line.find(delimiter) {
            let raw_key = &line[..delim_pos];
            out.push_str(raw_key);
            out.push_str(delimiter);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_values_preserves_keys() {
        let out = strip_values_from_text("host = localhost\nport = 5432\n", "=", "#");
        assert!(out.contains("host =\n"), "key should remain, got:\n{out}");
        assert!(out.contains("port =\n"), "key should remain, got:\n{out}");
        assert!(!out.contains("localhost"), "value should be stripped");
        assert!(!out.contains("5432"), "value should be stripped");
    }

    #[test]
    fn preserves_comments_and_blank_lines() {
        let input = "# a comment\n\nkey = value\n";
        let out = strip_values_from_text(input, "=", "#");
        assert!(out.contains("# a comment\n"), "comment should be preserved");
        assert!(!out.contains("value"), "value should be stripped");
        assert!(
            out.contains("\n\n") || out.starts_with('\n'),
            "blank line should be preserved"
        );
    }

    #[test]
    fn preserves_section_headers() {
        let out = strip_values_from_text("[database]\nhost = localhost\n", "=", "#");
        assert!(
            out.contains("[database]\n"),
            "section header should be preserved"
        );
        assert!(!out.contains("localhost"), "value should be stripped");
    }

    #[test]
    fn no_delimiter_line_passes_through() {
        let out = strip_values_from_text("just a bare line\n", "=", "#");
        assert_eq!(out, "just a bare line\n");
    }
}
