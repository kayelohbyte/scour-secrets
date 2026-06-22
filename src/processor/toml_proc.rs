//! TOML structured processor.
//!
//! Parses TOML input, walks the value tree, replaces matched field
//! values, and serializes back to TOML preserving structure.
//!
//! # Key Paths
//!
//! Nested keys use the same dot-separated convention as the JSON processor:
//! `database.password`, `server.credentials.token`.
//!
//! Array elements are traversed transparently — a rule for `servers.host`
//! matches the `host` field inside every table in the `servers` array.
//!
//! # Non-String Scalars
//!
//! When a FieldRule matches an integer, float, boolean, or datetime value,
//! that value is converted to a string replacement. This changes the TOML
//! type for that key but keeps the file syntactically valid. Use specific
//! field rules (e.g. `"database.password"`) rather than `"*"` if you want
//! to avoid replacing non-sensitive numeric values.

use crate::error::{Result, SanitizeError};
use crate::processor::limits::DEFAULT_INPUT_SIZE;
use crate::processor::{
    build_path, edit_token, walk_tree, FileTypeProfile, Processor, Replacement, TreeNode,
};
use crate::store::MappingStore;
use toml::Value;
use toml_edit::{ImDocument, Item, Table, Value as EditValue};

/// Structured processor for TOML configuration files.
pub struct TomlProcessor;

impl Processor for TomlProcessor {
    fn name(&self) -> &'static str {
        "toml"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        profile.processor == "toml"
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        let text = crate::processor::check_size_and_decode(content, "TOML", DEFAULT_INPUT_SIZE)?;

        let mut value: Value = toml::from_str(text).map_err(|e| SanitizeError::ParseError {
            format: "TOML".into(),
            message: format!("TOML parse error: {}", e),
        })?;

        walk_toml(&mut value, "", profile, store, 0)?;

        let output = toml::to_string_pretty(&value).map_err(|e| {
            SanitizeError::IoError(std::io::Error::other(format!("TOML serialize error: {e}")))
        })?;

        Ok(output.into_bytes())
    }

    /// Span-based redaction: parse with `toml_edit` (which retains byte spans),
    /// then emit an edit replacing each matched value's source span with a
    /// quoted token. Comments, key order, whitespace, and unrelated escaping are
    /// preserved exactly, and the real source bytes are hit regardless of how
    /// the value was quoted/escaped.
    fn process_to_edits(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Option<Vec<Replacement>>> {
        let text = crate::processor::check_size_and_decode(content, "TOML", DEFAULT_INPUT_SIZE)?;
        // `ImDocument` (immutable) retains byte spans for parsed values;
        // `DocumentMut` drops them. We only read spans, never mutate the tree.
        let doc = ImDocument::parse(text.to_string()).map_err(|e| SanitizeError::ParseError {
            format: "TOML".into(),
            message: format!("TOML parse error: {e}"),
        })?;
        let mut edits = Vec::new();
        collect_table_edits(doc.as_table(), "", profile, store, &mut edits)?;
        Ok(Some(edits))
    }
}

/// String form of a scalar `toml_edit` value, used as the mapping-store key.
fn edit_scalar_string(value: &EditValue) -> Option<String> {
    match value {
        EditValue::String(f) => Some(f.value().clone()),
        EditValue::Integer(f) => Some(f.value().to_string()),
        EditValue::Float(f) => Some(f.value().to_string()),
        EditValue::Boolean(f) => Some(f.value().to_string()),
        EditValue::Datetime(f) => Some(f.value().to_string()),
        EditValue::Array(_) | EditValue::InlineTable(_) => None,
    }
}

fn collect_table_edits(
    table: &Table,
    prefix: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
    edits: &mut Vec<Replacement>,
) -> Result<()> {
    for (key, item) in table {
        let path = build_path(prefix, key);
        match item {
            Item::Value(v) => collect_value_edits(key, &path, v, profile, store, edits)?,
            Item::Table(t) => collect_table_edits(t, &path, profile, store, edits)?,
            Item::ArrayOfTables(aot) => {
                // Array elements are path-transparent (mirrors the tree walk).
                for t in aot {
                    collect_table_edits(t, &path, profile, store, edits)?;
                }
            }
            Item::None => {}
        }
    }
    Ok(())
}

fn collect_value_edits(
    key: &str,
    path: &str,
    value: &EditValue,
    profile: &FileTypeProfile,
    store: &MappingStore,
    edits: &mut Vec<Replacement>,
) -> Result<()> {
    match value {
        EditValue::Array(arr) => {
            // Path-transparent: scalar/inline-table items keep the parent key/path.
            for item in arr {
                collect_value_edits(key, path, item, profile, store, edits)?;
            }
        }
        EditValue::InlineTable(it) => {
            for (k, v) in it {
                let p = build_path(path, k);
                collect_value_edits(k, &p, v, profile, store, edits)?;
            }
        }
        scalar => {
            let Some(s) = edit_scalar_string(scalar) else {
                return Ok(());
            };
            if let Some(token) = edit_token(key, path, &s, profile, store)? {
                if let Some(span) = value.span() {
                    edits.push(Replacement {
                        start: span.start,
                        end: span.end,
                        // Token is safe ASCII (no quote/backslash), so a basic
                        // double-quoted string is always valid here.
                        value: format!("\"{token}\""),
                    });
                }
            }
        }
    }
    Ok(())
}

impl TreeNode for Value {
    fn for_each_map_entry<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&str, &mut Self) -> Result<()>,
    {
        if let Self::Table(map) = self {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                if let Some(v) = map.get_mut(&key) {
                    f(&key, v)?;
                }
            }
        }
        Ok(())
    }

    fn for_each_seq_item<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&mut Self) -> Result<()>,
    {
        if let Self::Array(arr) = self {
            for item in arr.iter_mut() {
                f(item)?;
            }
        }
        Ok(())
    }

    fn as_str_mut(&mut self) -> Option<&mut String> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    fn is_scalar(&self) -> bool {
        // Non-string scalars are converted to string replacements. This changes
        // the TOML type for matched keys but keeps the file syntactically valid.
        matches!(
            self,
            Self::Integer(_) | Self::Float(_) | Self::Boolean(_) | Self::Datetime(_)
        )
    }

    fn scalar_to_string(&self) -> String {
        self.to_string()
    }

    fn set_string(&mut self, s: String) {
        *self = Self::String(s);
    }
}

/// Recursively walk a TOML value tree, replacing matched field values.
fn walk_toml(
    value: &mut Value,
    prefix: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
    depth: usize,
) -> Result<()> {
    walk_tree(value, prefix, profile, store, depth, "TOML")
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
    fn basic_toml_replacement() {
        let store = make_store();
        let proc = TomlProcessor;
        let content = br#"[database]
host = "db.corp.com"
password = "s3cret"
port = 5432

[smtp]
user = "admin@corp.com"
"#;
        let profile = FileTypeProfile::new(
            "toml",
            vec![
                FieldRule::new("database.password"),
                FieldRule::new("smtp.user").with_category(Category::Email),
            ],
        );
        let output = proc.process(content, &profile, &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        // Password replaced, host and port preserved.
        assert!(!text.contains("s3cret"));
        assert!(text.contains("db.corp.com"));
        assert!(text.contains("5432"));
        // Email replaced.
        assert!(!text.contains("admin@corp.com"));
    }

    #[test]
    fn wildcard_replaces_all_strings() {
        let store = make_store();
        let proc = TomlProcessor;
        let content = b"api_key = \"secret\"\ndb_url = \"postgres://user:pass@host/db\"\n";
        let profile = FileTypeProfile::new("toml", vec![FieldRule::new("*")]);
        let output = proc.process(content, &profile, &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("secret"));
        assert!(!text.contains("postgres://user:pass@host/db"));
        // Non-secret structure preserved: the keys remain (only values changed).
        assert!(text.contains("api_key"));
        assert!(text.contains("db_url"));
    }

    #[test]
    fn invalid_toml_returns_parse_error() {
        let store = make_store();
        let proc = TomlProcessor;
        let content = b"this is not valid toml [[[";
        let profile = FileTypeProfile::new("toml", vec![FieldRule::new("*")]);
        let result = proc.process(content, &profile, &store);
        assert!(result.is_err());
    }

    #[test]
    fn deeply_nested_toml() {
        let store = make_store();
        let proc = TomlProcessor;
        let content = b"[a.b.c]\nkey = \"value\"\n";
        let profile = FileTypeProfile::new("toml", vec![FieldRule::new("a.b.c.key")]);
        let output = proc.process(content, &profile, &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("value"));
        // Non-secret structure preserved: only the value changed, the nested
        // table and key remain.
        let parsed: toml::Value = toml::from_str(&text).unwrap();
        assert!(parsed["a"]["b"]["c"]["key"].as_str().is_some());
    }

    // ── process_to_edits (span-based, format-preserving) ─────────────────────

    /// Edit-mode alone (no scanner) must redact a value that is **escaped** in
    /// the source — the exact case the literal-scan approach leaks.
    #[test]
    fn edits_redact_escaped_basic_string() {
        let store = make_store();
        let proc = TomlProcessor;
        // Source bytes contain a\"b\"c-SECRET; the parsed value is a"b"c-SECRET.
        let content = br#"key = "a\"b\"c-SECRET""#;
        let profile = FileTypeProfile::new(
            "toml",
            vec![FieldRule::new("key").with_category(Category::Custom("k".into()))],
        );
        let edits = proc
            .process_to_edits(content, &profile, &store)
            .unwrap()
            .unwrap();
        let out = crate::processor::apply_edits(content, edits);
        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains("SECRET"),
            "escaped value leaked via edits: {text}"
        );
    }

    /// Edits preserve comments, key order, whitespace, and non-matched values.
    #[test]
    fn edits_preserve_comments_and_layout() {
        let store = make_store();
        let proc = TomlProcessor;
        let content =
            b"# top\n[db]\npassword = \"SECRETpw\"  # inline\nhost = \"keep.local\"\nport = 5432\n";
        let profile = FileTypeProfile::new(
            "toml",
            vec![FieldRule::new("db.password").with_category(Category::Custom("pw".into()))],
        );
        let edits = proc
            .process_to_edits(content, &profile, &store)
            .unwrap()
            .unwrap();
        let out = crate::processor::apply_edits(content, edits);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("SECRETpw"), "secret leaked: {text}");
        assert!(text.contains("# top"), "top comment dropped: {text}");
        assert!(text.contains("# inline"), "inline comment dropped: {text}");
        assert!(
            text.contains("host = \"keep.local\""),
            "non-secret changed: {text}"
        );
        assert!(text.contains("port = 5432"), "non-secret changed: {text}");
        assert!(
            toml::from_str::<toml::Value>(&text).is_ok(),
            "invalid TOML: {text}"
        );
    }
}
