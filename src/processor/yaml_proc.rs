//! YAML structured processor.
//!
//! Parses YAML input, walks the value tree, replaces matched field
//! values, and serializes back. Structure is preserved but minor
//! formatting differences are possible (serde_yaml normalizes some
//! whitespace).
//!
//! Key paths use the same dot-separated convention as the JSON processor.

use crate::error::{Result, SanitizeError};
use crate::processor::limits::{DEFAULT_DEPTH, YAML_INPUT_SIZE, YAML_NODE_COUNT};
use crate::processor::{walk_tree, FileTypeProfile, Processor, TreeNode};
use crate::store::MappingStore;
use serde_yaml_ng::Value;

/// Structured processor for YAML files.
pub struct YamlProcessor;

impl Processor for YamlProcessor {
    fn name(&self) -> &'static str {
        "yaml"
    }

    fn can_handle(&self, content: &[u8], profile: &FileTypeProfile) -> bool {
        if profile.processor == "yaml" {
            return true;
        }
        // Heuristic: starts with `---` or a YAML-ish key: value.
        let text = String::from_utf8_lossy(content);
        let trimmed = text.trim_start();
        trimmed.starts_with("---")
            || trimmed.starts_with("- ")
            || trimmed.starts_with('{')
            || trimmed.contains(": ")
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        // Guard against alias bombs: reject inputs above YAML_INPUT_SIZE.
        let text = crate::processor::check_size_and_decode(content, "YAML", YAML_INPUT_SIZE)?;

        let mut value: Value =
            serde_yaml_ng::from_str(text).map_err(|e| SanitizeError::ParseError {
                format: "YAML".into(),
                message: format!("YAML parse error: {}", e),
            })?;

        // F-06 fix: count total nodes in the deserialized tree to detect
        // alias bombs. After expansion, aliased subtrees become
        // independent copies in memory, so the node count reflects the
        // true memory footprint.
        let node_count = count_yaml_nodes(&value);
        if node_count > YAML_NODE_COUNT {
            return Err(SanitizeError::InputTooLarge {
                size: node_count,
                limit: YAML_NODE_COUNT,
            });
        }

        walk_yaml(&mut value, "", profile, store, 0)?;

        let output = serde_yaml_ng::to_string(&value).map_err(|e| {
            SanitizeError::IoError(std::io::Error::other(format!("YAML serialize error: {e}")))
        })?;

        Ok(output.into_bytes())
    }
}

/// Count the total number of nodes in a YAML value tree (F-06 fix).
/// Used to detect alias bombs that produce a small source document
/// but expand to millions of nodes after alias resolution.
fn count_yaml_nodes(value: &Value) -> usize {
    count_yaml_nodes_inner(value, 0)
}

/// Inner recursive counter with depth guard to prevent stack overflow
/// on deeply nested YAML before `walk_yaml`'s depth check is reached.
fn count_yaml_nodes_inner(value: &Value, depth: usize) -> usize {
    if depth > DEFAULT_DEPTH {
        return 1; // Stop counting deeper; walk_yaml will catch depth violations
    }
    match value {
        Value::Mapping(map) => {
            1 + map
                .iter()
                .map(|(k, v)| {
                    count_yaml_nodes_inner(k, depth + 1) + count_yaml_nodes_inner(v, depth + 1)
                })
                .sum::<usize>()
        }
        Value::Sequence(seq) => {
            1 + seq
                .iter()
                .map(|v| count_yaml_nodes_inner(v, depth + 1))
                .sum::<usize>()
        }
        Value::Tagged(tagged) => 1 + count_yaml_nodes_inner(&tagged.value, depth + 1),
        _ => 1, // Null, Bool, Number, String
    }
}

impl TreeNode for Value {
    fn for_each_map_entry<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&str, &mut Self) -> Result<()>,
    {
        if let Self::Mapping(map) = self {
            let keys: Vec<Self> = map.keys().cloned().collect();
            for key in keys {
                let key_str = yaml_key_to_string(&key);
                if let Some(v) = map.get_mut(&key) {
                    f(&key_str, v)?;
                }
            }
        }
        Ok(())
    }

    fn for_each_seq_item<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&mut Self) -> Result<()>,
    {
        if let Self::Sequence(seq) = self {
            for item in seq.iter_mut() {
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
        yaml_scalar_to_string(self)
    }

    fn set_string(&mut self, s: String) {
        *self = Self::String(s);
    }
}

/// Recursively walk a YAML value tree, replacing matched field values.
fn walk_yaml(
    value: &mut Value,
    prefix: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
    depth: usize,
) -> Result<()> {
    walk_tree(value, prefix, profile, store, depth, "YAML")
}

fn yaml_key_to_string(key: &Value) -> String {
    match key {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => format!("{:?}", key),
    }
}

fn yaml_scalar_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
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
    fn basic_yaml_replacement() {
        let store = make_store();
        let proc = YamlProcessor;

        let content = b"database:\n  host: db.corp.com\n  password: s3cret\nport: 5432\n";
        let profile = FileTypeProfile::new(
            "yaml",
            vec![
                FieldRule::new("database.password").with_category(Category::Custom("pw".into())),
                FieldRule::new("database.host").with_category(Category::Hostname),
            ],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        assert!(!out.contains("s3cret"));
        assert!(!out.contains("db.corp.com"));
        // port should be preserved
        assert!(out.contains("5432"));
    }

    #[test]
    fn can_handle_by_profile_name() {
        let proc = YamlProcessor;
        let profile = FileTypeProfile::new("yaml", vec![]).with_extension(".yaml");
        assert!(proc.can_handle(b"anything", &profile));
    }

    #[test]
    fn can_handle_detects_document_marker() {
        let proc = YamlProcessor;
        let profile = FileTypeProfile::new("json", vec![]).with_extension(".json");
        assert!(proc.can_handle(b"---\nkey: value\n", &profile));
    }

    #[test]
    fn can_handle_detects_key_value_heuristic() {
        let proc = YamlProcessor;
        let profile = FileTypeProfile::new("other", vec![]).with_extension(".conf");
        assert!(proc.can_handle(b"host: localhost\nport: 5432\n", &profile));
    }

    #[test]
    fn can_handle_detects_sequence_heuristic() {
        let proc = YamlProcessor;
        let profile = FileTypeProfile::new("other", vec![]).with_extension(".txt");
        assert!(proc.can_handle(b"- item1\n- item2\n", &profile));
    }

    #[test]
    fn can_handle_rejects_plaintext() {
        let proc = YamlProcessor;
        let profile = FileTypeProfile::new("json", vec![]).with_extension(".json");
        assert!(!proc.can_handle(b"just plain text with no yaml markers", &profile));
    }

    #[test]
    fn non_string_scalars_not_targeted_pass_through() {
        let store = make_store();
        let proc = YamlProcessor;
        // Only target the 'secret' field; booleans and numbers are untouched.
        let content = b"enabled: true\ncount: 42\nsecret: hunter2\n";
        let profile = FileTypeProfile::new(
            "yaml",
            vec![FieldRule::new("secret").with_category(Category::Custom("pw".into()))],
        );
        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(!out.contains("hunter2"), "secret must be replaced");
        assert!(out.contains("42"), "integer must be preserved");
    }

    #[test]
    fn deeply_nested_yaml_replaced() {
        let store = make_store();
        let proc = YamlProcessor;
        let content = b"a:\n  b:\n    c:\n      secret: hunter2\n";
        let profile = FileTypeProfile::new(
            "yaml",
            vec![FieldRule::new("a.b.c.secret").with_category(Category::Custom("pw".into()))],
        );
        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn invalid_utf8_returns_parse_error() {
        let store = make_store();
        let proc = YamlProcessor;
        let bad = b"\xff\xfe invalid";
        let profile = FileTypeProfile::new("yaml", vec![]);
        let err = proc.process(bad, &profile, &store).unwrap_err();
        assert!(matches!(
            err,
            crate::error::SanitizeError::ParseError { .. }
        ));
    }

    #[test]
    fn invalid_yaml_returns_parse_error() {
        let store = make_store();
        let proc = YamlProcessor;
        let bad = b"key: [unclosed";
        let profile = FileTypeProfile::new("yaml", vec![]);
        let err = proc.process(bad, &profile, &store).unwrap_err();
        assert!(matches!(
            err,
            crate::error::SanitizeError::ParseError { .. }
        ));
    }

    #[test]
    fn yaml_sequence_traversal() {
        let store = make_store();
        let proc = YamlProcessor;

        let content = b"users:\n  - email: a@b.com\n  - email: c@d.com\n";
        let profile = FileTypeProfile::new(
            "yaml",
            vec![FieldRule::new("users.email").with_category(Category::Email)],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        assert!(!out.contains("a@b.com"));
        assert!(!out.contains("c@d.com"));
    }
}
