//! JSON structured processor.
//!
//! Parses JSON input, walks the value tree, replaces values at matched
//! key paths, and serializes back to JSON preserving structure.
//!
//! # Key Paths
//!
//! Nested keys are expressed as dot-separated paths:
//! `database.password`, `smtp.credentials.user`.
//!
//! Array elements are traversed transparently — a rule for `users.email`
//! matches the `email` field inside every object in the `users` array.

use crate::error::{Result, SanitizeError};
use crate::processor::limits::DEFAULT_INPUT_SIZE;
use crate::processor::{walk_tree, FileTypeProfile, Processor, TreeNode};
use crate::store::MappingStore;
use serde_json::Value;

/// Structured processor for JSON files.
pub struct JsonProcessor;

impl Processor for JsonProcessor {
    fn name(&self) -> &'static str {
        "json"
    }

    fn can_handle(&self, content: &[u8], profile: &FileTypeProfile) -> bool {
        if profile.processor == "json" {
            return true;
        }
        // Heuristic: starts with `{` or `[` after optional whitespace.
        let trimmed = content.iter().copied().find(|b| !b.is_ascii_whitespace());
        matches!(trimmed, Some(b'{' | b'['))
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        // F-04 fix: enforce input size limit.
        let text = crate::processor::check_size_and_decode(content, "JSON", DEFAULT_INPUT_SIZE)?;

        let mut value: Value =
            serde_json::from_str(text).map_err(|e| SanitizeError::ParseError {
                format: "JSON".into(),
                message: format!("JSON parse error: {}", e),
            })?;

        walk_json(&mut value, "", profile, store, 0)?;

        let compact = profile.options.get("compact").is_some_and(|v| v == "true");

        let output = if compact {
            serde_json::to_vec(&value)
        } else {
            serde_json::to_vec_pretty(&value)
        }
        .map_err(|e| {
            SanitizeError::IoError(std::io::Error::other(format!("JSON serialize error: {e}")))
        })?;

        Ok(output)
    }
}

impl TreeNode for Value {
    fn for_each_map_entry<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&str, &mut Self) -> Result<()>,
    {
        if let Self::Object(map) = self {
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
        matches!(self, Self::Number(_) | Self::Bool(_))
    }

    fn scalar_to_string(&self) -> String {
        self.to_string()
    }

    fn set_string(&mut self, s: String) {
        *self = Self::String(s);
    }
}

/// Recursively walk a JSON value tree, replacing matched field values.
pub(crate) fn walk_json(
    value: &mut Value,
    prefix: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
    depth: usize,
) -> Result<()> {
    walk_tree(value, prefix, profile, store, depth, "JSON")
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
    fn basic_json_replacement() {
        let store = make_store();
        let proc = JsonProcessor;

        let content =
            br#"{"database": {"host": "db.corp.com", "password": "s3cret"}, "port": 5432}"#;
        let profile = FileTypeProfile::new(
            "json",
            vec![
                FieldRule::new("database.password").with_category(Category::Custom("pw".into())),
                FieldRule::new("database.host").with_category(Category::Hostname),
            ],
        )
        .with_option("compact", "true");

        let result = proc.process(content, &profile, &store).unwrap();
        let out: Value = serde_json::from_slice(&result).unwrap();

        assert_ne!(out["database"]["password"].as_str().unwrap(), "s3cret");
        assert_ne!(out["database"]["host"].as_str().unwrap(), "db.corp.com");
        assert_eq!(out["port"], 5432);
    }

    #[test]
    fn json_array_traversal() {
        let store = make_store();
        let proc = JsonProcessor;

        let content = br#"{"users": [{"email": "a@b.com"}, {"email": "c@d.com"}]}"#;
        let profile = FileTypeProfile::new(
            "json",
            vec![FieldRule::new("users.email").with_category(Category::Email)],
        )
        .with_option("compact", "true");

        let result = proc.process(content, &profile, &store).unwrap();
        let out: Value = serde_json::from_slice(&result).unwrap();

        let users = out["users"].as_array().unwrap();
        assert_ne!(users[0]["email"].as_str().unwrap(), "a@b.com");
        assert_ne!(users[1]["email"].as_str().unwrap(), "c@d.com");
    }

    #[test]
    fn json_glob_suffix_pattern() {
        let store = make_store();
        let proc = JsonProcessor;

        let content =
            br#"{"db": {"password": "pw1"}, "cache": {"password": "pw2"}, "name": "app"}"#;
        let profile = FileTypeProfile::new(
            "json",
            vec![FieldRule::new("*.password").with_category(Category::Custom("pw".into()))],
        )
        .with_option("compact", "true");

        let result = proc.process(content, &profile, &store).unwrap();
        let out: Value = serde_json::from_slice(&result).unwrap();

        assert_ne!(out["db"]["password"].as_str().unwrap(), "pw1");
        assert_ne!(out["cache"]["password"].as_str().unwrap(), "pw2");
        assert_eq!(out["name"], "app");
    }
}
