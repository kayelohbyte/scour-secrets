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
    find_matching_rule, pattern_matches, replace_value, FileTypeProfile, Processor,
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
}
