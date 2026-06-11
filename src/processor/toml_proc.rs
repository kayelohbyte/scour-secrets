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
use crate::processor::{walk_tree, FileTypeProfile, Processor, TreeNode};
use crate::store::MappingStore;
use toml::Value;

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
    }
}
