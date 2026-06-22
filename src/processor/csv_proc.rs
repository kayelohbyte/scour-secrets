//! CSV structured processor.
//!
//! Parses CSV (or TSV) input, replaces values in specified columns,
//! and writes back preserving the delimiter and quoting style.
//!
//! # Column Matching
//!
//! Field rules match by **header name**. If the first row is a header
//! (default assumption), column names are extracted from it and matched
//! against the profile's field rules.
//!
//! # Profile Options
//!
//! | Key          | Default | Description                            |
//! |--------------|---------|----------------------------------------|
//! | `delimiter`  | `","`   | Field delimiter (single ASCII char).   |
//! | `has_header` | `"true"`| Whether the first row is a header row. |

use crate::error::{Result, SanitizeError};
use crate::processor::limits::DEFAULT_INPUT_SIZE;
use crate::processor::{
    edit_token, find_matching_rule, pattern_matches, replace_value, FileTypeProfile, Processor,
    Replacement,
};
use crate::store::MappingStore;

/// Structured processor for CSV/TSV files.
pub struct CsvProcessor;

impl Processor for CsvProcessor {
    fn name(&self) -> &'static str {
        "csv"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        profile.processor == "csv"
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        // F-04 fix: enforce input size limit.
        if content.len() > DEFAULT_INPUT_SIZE {
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: DEFAULT_INPUT_SIZE,
            });
        }

        let delimiter = profile
            .options
            .get("delimiter")
            .and_then(|s| s.as_bytes().first().copied())
            .unwrap_or(b',');

        let has_header = profile
            .options
            .get("has_header")
            .is_none_or(|v| v != "false");

        let mut reader = csv::ReaderBuilder::new()
            .delimiter(delimiter)
            .has_headers(has_header)
            .flexible(true)
            .from_reader(content);

        let mut output = Vec::new();
        let mut wtr = csv::WriterBuilder::new()
            .delimiter(delimiter)
            .from_writer(&mut output);

        // Determine which column indices need replacement.
        let column_rules: Vec<Option<usize>> = if has_header {
            let headers = reader
                .headers()
                .map_err(|e| SanitizeError::ParseError {
                    format: "CSV".into(),
                    message: format!("CSV header error: {}", e),
                })?
                .clone();

            // Write header row.
            wtr.write_record(headers.iter()).map_err(|e| {
                SanitizeError::IoError(std::io::Error::other(format!("CSV write error: {e}")))
            })?;

            // Map each column index to the index of its first matching rule (if any).
            // Uses pattern_matches directly to avoid allocating a temporary
            // FileTypeProfile for every (header, rule) pair.
            headers
                .iter()
                .map(|h| {
                    profile
                        .fields
                        .iter()
                        .position(|r| pattern_matches(&r.pattern, h))
                })
                .collect()
        } else {
            Vec::new()
        };

        for result in reader.records() {
            let record = result.map_err(|e| SanitizeError::ParseError {
                format: "CSV".into(),
                message: format!("CSV read error: {}", e),
            })?;

            let mut row: Vec<String> = Vec::with_capacity(record.len());
            for (idx, field) in record.iter().enumerate() {
                if has_header {
                    if let Some(Some(rule_idx)) = column_rules.get(idx) {
                        let rule = &profile.fields[*rule_idx];
                        let replaced = replace_value(field, rule, store, "csv")?;
                        row.push(replaced);
                    } else {
                        row.push(field.to_string());
                    }
                } else {
                    // Without headers, match by column index as string.
                    let col_key = idx.to_string();
                    if let Some(rule) = find_matching_rule(&col_key, profile) {
                        let replaced = replace_value(field, rule, store, "csv")?;
                        row.push(replaced);
                    } else {
                        row.push(field.to_string());
                    }
                }
            }

            wtr.write_record(&row).map_err(|e| {
                SanitizeError::IoError(std::io::Error::other(format!("CSV write error: {e}")))
            })?;
        }

        wtr.flush().map_err(|e| {
            SanitizeError::IoError(std::io::Error::other(format!("CSV flush error: {e}")))
        })?;
        drop(wtr);

        Ok(output)
    }

    /// Span-based redaction: drive `csv-core` (the byte-accurate field state
    /// machine) over the source, recording an edit at each matched field's exact
    /// source span. The delimiter, quoting style, line endings, and non-matched
    /// fields are preserved, and a quoted/`""`-escaped field is hit as written so
    /// no value leaks.
    fn process_to_edits(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Option<Vec<Replacement>>> {
        if content.len() > DEFAULT_INPUT_SIZE {
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: DEFAULT_INPUT_SIZE,
            });
        }
        let delimiter = profile
            .options
            .get("delimiter")
            .and_then(|s| s.as_bytes().first().copied())
            .unwrap_or(b',');
        let has_header = profile
            .options
            .get("has_header")
            .is_none_or(|v| v != "false");

        let mut rdr = csv_core::ReaderBuilder::new().delimiter(delimiter).build();
        let mut edits = Vec::new();
        let mut out_chunk = vec![0u8; 4096];
        let mut value_buf: Vec<u8> = Vec::new();
        let mut pos = 0usize;
        let mut field_start = 0usize;
        let mut record_idx = 0usize;
        let mut col_idx = 0usize;
        let mut headers: Vec<String> = Vec::new();

        loop {
            let (result, n_in, n_out) = rdr.read_field(&content[pos..], &mut out_chunk);
            value_buf.extend_from_slice(&out_chunk[..n_out]);
            pos += n_in;

            match result {
                csv_core::ReadFieldResult::InputEmpty => {
                    if pos >= content.len() {
                        break;
                    }
                }
                csv_core::ReadFieldResult::OutputFull => {} // field continues; keep accumulating
                csv_core::ReadFieldResult::End => break,
                csv_core::ReadFieldResult::Field { record_end } => {
                    let term_len = field_terminator_len(&content[field_start..pos], record_end);
                    let value_end = pos - term_len;
                    let value = String::from_utf8_lossy(&value_buf).into_owned();

                    if has_header && record_idx == 0 {
                        headers.push(value);
                    } else {
                        let col_key;
                        let key: &str = if has_header {
                            headers.get(col_idx).map_or("", String::as_str)
                        } else {
                            col_key = col_idx.to_string();
                            &col_key
                        };
                        if !key.is_empty() {
                            if let Some(token) = edit_token(key, key, &value, profile, store)? {
                                edits.push(Replacement {
                                    start: field_start,
                                    end: value_end,
                                    value: csv_escape_token(&token),
                                });
                            }
                        }
                    }

                    value_buf.clear();
                    col_idx += 1;
                    field_start = pos;
                    if record_end {
                        record_idx += 1;
                        col_idx = 0;
                    }
                }
            }
        }
        Ok(Some(edits))
    }
}

/// Length of the field terminator at the end of `raw` (the bytes consumed for a
/// field, including its trailing separator): the delimiter (1) for a mid-record
/// field, or the record terminator (`\r\n` → 2, `\n`/`\r` → 1, EOF → 0).
fn field_terminator_len(raw: &[u8], record_end: bool) -> usize {
    if !record_end {
        return 1; // delimiter
    }
    if raw.ends_with(b"\r\n") {
        2
    } else {
        usize::from(raw.ends_with(b"\n") || raw.ends_with(b"\r"))
    }
}

/// CSV-quote a token if it contains a character that would need quoting. Tokens
/// are safe ASCII in practice, so this is a defensive no-op in the common case.
fn csv_escape_token(token: &str) -> String {
    if token.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", token.replace('"', "\"\""))
    } else {
        token.to_string()
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

    #[test]
    fn basic_csv_replacement() {
        let store = make_store();
        let proc = CsvProcessor;

        let content =
            b"name,email,department\nAlice,alice@corp.com,Engineering\nBob,bob@corp.com,Sales\n";
        let profile = FileTypeProfile::new(
            "csv",
            vec![
                FieldRule::new("name").with_category(Category::Name),
                FieldRule::new("email").with_category(Category::Email),
            ],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        assert!(!out.contains("Alice"));
        assert!(!out.contains("alice@corp.com"));
        assert!(!out.contains("Bob"));
        assert!(!out.contains("bob@corp.com"));
        // Department column preserved.
        assert!(out.contains("Engineering"));
        assert!(out.contains("Sales"));
        // Header preserved.
        assert!(out.starts_with("name,email,department"));
    }

    #[test]
    fn can_handle_requires_csv_profile() {
        let proc = CsvProcessor;
        let yes = FileTypeProfile::new("csv", vec![]).with_extension(".csv");
        let no = FileTypeProfile::new("json", vec![]).with_extension(".json");
        assert!(proc.can_handle(b"a,b,c\n1,2,3\n", &yes));
        assert!(!proc.can_handle(b"a,b,c\n1,2,3\n", &no));
    }

    #[test]
    fn tsv_delimiter() {
        let store = make_store();
        let proc = CsvProcessor;
        let content = b"name\temail\nAlice\talice@corp.com\n";
        let mut profile = FileTypeProfile::new(
            "csv",
            vec![FieldRule::new("email").with_category(Category::Email)],
        );
        profile.options.insert("delimiter".into(), "\t".into());

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(!out.contains("alice@corp.com"));
        assert!(out.contains("Alice"));
    }

    #[test]
    fn no_header_mode_matches_by_column_index() {
        let store = make_store();
        let proc = CsvProcessor;
        // Column 1 (0-indexed) should be replaced.
        let content = b"Alice,alice@corp.com,Engineering\n";
        let mut profile = FileTypeProfile::new(
            "csv",
            vec![FieldRule::new("1").with_category(Category::Email)],
        );
        profile.options.insert("has_header".into(), "false".into());

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(!out.contains("alice@corp.com"));
        assert!(out.contains("Alice"));
        assert!(out.contains("Engineering"));
    }

    #[test]
    fn header_only_no_data_rows() {
        let store = make_store();
        let proc = CsvProcessor;
        let content = b"name,email,department\n";
        let profile = FileTypeProfile::new(
            "csv",
            vec![FieldRule::new("email").with_category(Category::Email)],
        );
        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(out.contains("name,email,department"));
    }

    #[test]
    fn empty_field_passes_through() {
        let store = make_store();
        let proc = CsvProcessor;
        let content = b"email\n\nalice@corp.com\n";
        let profile = FileTypeProfile::new(
            "csv",
            vec![FieldRule::new("email").with_category(Category::Email)],
        );
        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(!out.contains("alice@corp.com"));
    }

    #[test]
    fn unmatched_columns_pass_through_unchanged() {
        let store = make_store();
        let proc = CsvProcessor;
        let content = b"id,email\n42,alice@corp.com\n";
        let profile = FileTypeProfile::new(
            "csv",
            vec![FieldRule::new("email").with_category(Category::Email)],
        );
        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(out.contains("42"), "id column must be preserved");
        assert!(!out.contains("alice@corp.com"));
    }

    #[test]
    fn csv_deterministic_replacement() {
        let store = make_store();
        let proc = CsvProcessor;

        let content = b"email\ntest@x.com\ntest@x.com\n";
        let profile = FileTypeProfile::new(
            "csv",
            vec![FieldRule::new("email").with_category(Category::Email)],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        let lines: Vec<&str> = out.lines().collect();

        // Same input → same replacement.
        assert_eq!(lines[1], lines[2]);
        assert_ne!(lines[1], "test@x.com");
    }

    /// Edit-mode redacts matched columns at their exact source span, including
    /// quoted fields with embedded commas and `""`-escaped quotes, leaving the
    /// header and non-matched columns intact.
    #[test]
    fn edits_redact_quoted_and_escaped_fields() {
        let store = make_store();
        let proc = CsvProcessor;
        let content =
            b"name,email,note\nAlice,a-SEC1@e.test,\"has,comma-SEC2\"\nBob,\"b\"\"q-SEC3@e.test\",x\n";
        let profile = FileTypeProfile::new(
            "csv",
            vec![
                FieldRule::new("email").with_category(Category::Email),
                FieldRule::new("note").with_category(Category::Custom("n".into())),
            ],
        );
        let edits = proc
            .process_to_edits(content, &profile, &store)
            .unwrap()
            .unwrap();
        let out = crate::processor::apply_edits(content, edits);
        let text = String::from_utf8(out).unwrap();
        for leak in ["SEC1", "SEC2", "SEC3"] {
            assert!(!text.contains(leak), "leaked {leak}: {text}");
        }
        // Header and the non-matched `name` column are untouched.
        assert!(
            text.starts_with("name,email,note\n"),
            "header changed: {text}"
        );
        assert!(text.contains("Alice,"), "name column changed: {text}");
        assert!(text.contains("Bob,"), "name column changed: {text}");
    }
}
