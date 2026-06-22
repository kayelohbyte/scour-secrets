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
use crate::processor::{
    build_path, edit_token, walk_tree, FileTypeProfile, Processor, Replacement, TreeNode,
};
use crate::store::MappingStore;
use jiter::{Jiter, Peek};
use serde_json::Value;

/// Map a `jiter` parse error to a `SanitizeError::ParseError`.
fn json_err(e: impl std::fmt::Display) -> SanitizeError {
    SanitizeError::ParseError {
        format: "JSON".into(),
        message: format!("JSON parse error: {e}"),
    }
}

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

    /// Span-based redaction: walk the document with `jiter` (a byte-position
    /// JSON parser), recording an edit that replaces each matched value's exact
    /// source span with a quoted token. Whitespace, key order, and the precise
    /// escaping of unrelated content are preserved, and the value is hit in the
    /// source *as written* — so values escaped as `\/`, `\uXXXX`, etc. are
    /// redacted with no leak.
    fn process_to_edits(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Option<Vec<Replacement>>> {
        // Enforce the size limit and reject non-UTF-8 (JSON must be UTF-8).
        crate::processor::check_size_and_decode(content, "JSON", DEFAULT_INPUT_SIZE)?;
        Ok(Some(json_value_edits(content, profile, store)?))
    }
}

/// Compute span edits for a single JSON document in `content` (spans are
/// relative to `content`). Shared by the JSON processor and, per line, by the
/// JSONL processor.
///
/// # Errors
///
/// Returns [`SanitizeError::ParseError`] if `content` is not valid JSON.
pub(crate) fn json_value_edits(
    content: &[u8],
    profile: &FileTypeProfile,
    store: &MappingStore,
) -> Result<Vec<Replacement>> {
    let mut jiter = Jiter::new(content);
    let mut edits = Vec::new();
    let peek = jiter.peek().map_err(json_err)?;
    collect_json_edits(
        &mut jiter, peek, "", "", content, profile, store, &mut edits,
    )?;
    Ok(edits)
}

/// Recursively walk a JSON value via `jiter`, emitting span edits for matched
/// leaf values. `peek` is the already-peeked type of the value about to be read,
/// and the parser is positioned at its first byte.
#[allow(clippy::too_many_arguments)]
fn collect_json_edits(
    jiter: &mut Jiter,
    peek: Peek,
    key: &str,
    path: &str,
    content: &[u8],
    profile: &FileTypeProfile,
    store: &MappingStore,
    edits: &mut Vec<Replacement>,
) -> Result<()> {
    if peek == Peek::Object {
        // `next_object`/`next_key` return each key and leave the parser at the
        // value (the `:` is consumed). Copy the key to release the borrow.
        let mut next = jiter.next_object().map_err(json_err)?.map(str::to_owned);
        while let Some(k) = next {
            let child_path = build_path(path, &k);
            let child_peek = jiter.peek().map_err(json_err)?;
            collect_json_edits(
                jiter,
                child_peek,
                &k,
                &child_path,
                content,
                profile,
                store,
                edits,
            )?;
            next = jiter.next_key().map_err(json_err)?.map(str::to_owned);
        }
    } else if peek == Peek::Array {
        // Array elements are path-transparent (keep the parent key/path).
        let mut elem = jiter.next_array().map_err(json_err)?;
        while let Some(elem_peek) = elem {
            collect_json_edits(jiter, elem_peek, key, path, content, profile, store, edits)?;
            elem = jiter.array_step().map_err(json_err)?;
        }
    } else if peek == Peek::String {
        let start = jiter.current_index();
        let s = jiter.next_str().map_err(json_err)?.to_owned();
        let end = jiter.current_index();
        if let Some(token) = edit_token(key, path, &s, profile, store)? {
            edits.push(Replacement {
                start,
                end,
                value: format!("\"{token}\""),
            });
        }
    } else {
        // null / true / false / number — capture the exact source text.
        let start = jiter.current_index();
        jiter.next_skip().map_err(json_err)?;
        let end = jiter.current_index();
        let s = String::from_utf8_lossy(&content[start..end]).into_owned();
        if let Some(token) = edit_token(key, path, &s, profile, store)? {
            edits.push(Replacement {
                start,
                end,
                value: format!("\"{token}\""),
            });
        }
    }
    Ok(())
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
        // Non-secret structure preserved: both elements and their keys remain.
        assert_eq!(users.len(), 2);
        let text = String::from_utf8_lossy(&result);
        assert!(text.contains("\"users\"") && text.contains("\"email\""));
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

    // ── process_to_edits (span-based, format-preserving) ─────────────────────

    /// Edit-mode alone (no scanner) must redact values that are **escaped** in
    /// the source — including non-canonical escapes (`\/`, `\uXXXX`) that the
    /// literal/alias approach leaks.
    #[test]
    fn edits_redact_escaped_and_noncanonical_values() {
        let store = make_store();
        let proc = JsonProcessor;
        // \" escaped quote, \/ PHP-style slash, \uXXXX unicode escape.
        let content =
            br#"{"a":"x\"y-SEC1","u":"http:\/\/SEC2.test","n":"caf\u00e9-SEC3","keep":"ok"}"#;
        let profile = FileTypeProfile::new(
            "json",
            vec![
                FieldRule::new("a").with_category(Category::Custom("k".into())),
                FieldRule::new("u").with_category(Category::Custom("k".into())),
                FieldRule::new("n").with_category(Category::Custom("k".into())),
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
        // Untouched field preserved and output is still valid JSON.
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["keep"], "ok");
    }

    /// Edits preserve compact formatting and leave non-matched values byte-exact.
    #[test]
    fn edits_preserve_compact_layout() {
        let store = make_store();
        let proc = JsonProcessor;
        let content = br#"{"db":{"password":"SECRETpw","host":"keep.local"},"port":5432}"#;
        let profile = FileTypeProfile::new(
            "json",
            vec![FieldRule::new("db.password").with_category(Category::Custom("pw".into()))],
        );
        let edits = proc
            .process_to_edits(content, &profile, &store)
            .unwrap()
            .unwrap();
        let out = crate::processor::apply_edits(content, edits);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("SECRETpw"), "secret leaked: {text}");
        // Still single-line/compact, untouched bytes intact.
        assert!(!text.contains('\n'), "formatting changed: {text}");
        assert!(
            text.contains(r#""host":"keep.local""#),
            "non-secret changed: {text}"
        );
        assert!(
            text.contains(r#""port":5432"#),
            "non-secret changed: {text}"
        );
    }
}
