//! Key-value processor for `gitlab.rb`-style configuration files.
//!
//! Handles files with lines of the form:
//!
//! ```text
//! key = "value"
//! key = 'value'
//! key = value
//! # comment lines are preserved
//! ```
//!
//! The delimiter, comment prefix, and quoting style are configurable
//! via the profile's `options` map.
//!
//! # Profile Options
//!
//! | Key              | Default | Description                                  |
//! |------------------|---------|----------------------------------------------|
//! | `delimiter`           | `"="`   | The key-value separator.                     |
//! | `secondary_delimiter` | *(none)*| Optional second delimiter tried when the     |
//! |                       |         | primary delimiter's key does not match any   |
//! |                       |         | field rule.  Surrounding quotes are stripped |
//! |                       |         | from the key before matching, and any suffix |
//! |                       |         | after the value (e.g. a trailing `,`) is     |
//! |                       |         | preserved in the output.  Useful for Ruby    |
//! |                       |         | hash literals that use `=>` as their         |
//! |                       |         | delimiter alongside a `=`-delimited file.    |
//! | `comment_prefix`      | `"#"`   | Lines starting with this (after whitespace)  |
//! |                  |         | are treated as comments and preserved as-is. |
//! | `value_strip_suffix`  | *(none)*| Strip this suffix from value before          |
//! |                       |         | sanitizing and re-append it afterwards.      |
//! |                       |         | Use `";"` for nginx-style `key value;` files.|
//!
//! # Heredoc / Sub-processor Support
//!
//! When a matched field rule has `sub_processor` set and the value is a
//! Ruby-style heredoc (`<<-'EOS'`, `<<~EOS`, etc.), the processor switches
//! into collection mode: it accumulates heredoc lines until the end marker,
//! then delegates the collected content to the named sub-processor using the
//! rule's `sub_fields`. This allows structured content embedded inside
//! key-value files (e.g. YAML inside `gitlab.rb`) to be sanitized at the
//! field level rather than relying solely on the streaming scanner.
//!
//! For non-heredoc values with `sub_processor`, the value (after quote
//! stripping) is passed directly to the sub-processor.
//!
//! # Formatting Preservation
//!
//! - Blank lines, comment lines, and indentation are preserved verbatim.
//! - The original quoting style (single, double, or unquoted) is kept.
//! - Whitespace around the delimiter is preserved where possible.
//! - Heredoc opening and closing marker lines are preserved verbatim.

use crate::error::{Result, SanitizeError};
use crate::processor::limits::DEFAULT_INPUT_SIZE;
use crate::processor::profile::FieldRule;
use crate::processor::{find_matching_rule, replace_value, FileTypeProfile, Processor};
use crate::store::MappingStore;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Internal state machine
// ---------------------------------------------------------------------------

/// Processing state for the line-by-line loop.
enum LineState {
    Normal,
    /// Collecting lines of a heredoc until `end_marker` is seen.
    Heredoc {
        end_marker: String,
        rule: FieldRule,
        lines: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Processor implementation
// ---------------------------------------------------------------------------

/// Structured processor for key = value configuration files.
pub struct KeyValueProcessor;

impl Processor for KeyValueProcessor {
    fn name(&self) -> &'static str {
        "key_value"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        matches!(profile.processor.as_str(), "key_value" | "key-value")
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        if content.len() > DEFAULT_INPUT_SIZE {
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: DEFAULT_INPUT_SIZE,
            });
        }

        let text = String::from_utf8_lossy(content);
        let delimiter = profile.options.get("delimiter").map_or("=", |s| s.as_str());
        let comment_prefix = profile
            .options
            .get("comment_prefix")
            .map_or("#", |s| s.as_str());
        let secondary_delimiter = profile
            .options
            .get("secondary_delimiter")
            .map(|s| s.as_str());
        let value_strip_suffix = profile
            .options
            .get("value_strip_suffix")
            .map(|s| s.as_str());

        let mut output = String::with_capacity(text.len());
        let mut state = LineState::Normal;

        for line in text.split('\n') {
            process_line(
                line,
                &mut state,
                &mut output,
                delimiter,
                comment_prefix,
                secondary_delimiter,
                value_strip_suffix,
                profile,
                store,
            )?;
        }

        // Normalise trailing newline: strip all, then re-add exactly one
        // iff the original ended with one. This corrects the extra '\n'
        // that split('\n') produces for a trailing-newline input.
        while output.ends_with('\n') {
            output.pop();
        }
        if text.ends_with('\n') {
            output.push('\n');
        }

        Ok(output.into_bytes())
    }
}

// ---------------------------------------------------------------------------
// Per-line processing (extracted to stay within clippy line limit)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn process_line(
    line: &str,
    state: &mut LineState,
    output: &mut String,
    delimiter: &str,
    comment_prefix: &str,
    secondary_delimiter: Option<&str>,
    value_strip_suffix: Option<&str>,
    profile: &FileTypeProfile,
    store: &MappingStore,
) -> Result<()> {
    match state {
        LineState::Heredoc {
            ref end_marker,
            ref rule,
            ref mut lines,
        } => {
            if line.trim() == end_marker.as_str() {
                let heredoc_content = lines.join("\n");
                let processed = process_sub_content(&heredoc_content, rule, store)?;
                for processed_line in processed.split('\n') {
                    output.push_str(processed_line);
                    output.push('\n');
                }
                output.push_str(line);
                output.push('\n');
                *state = LineState::Normal;
            } else {
                lines.push(line.to_owned());
            }
        }
        LineState::Normal => {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with(comment_prefix) {
                output.push_str(line);
                output.push('\n');
                return Ok(());
            }
            // Search for the delimiter in the indent-stripped line so that
            // indented directives (e.g. nginx `    proxy_pass URL;`) are found
            // even when the delimiter is a space character.
            let line_body = line.trim_start();
            let indent_len = line.len() - line_body.len();
            if let Some(delim_pos) = line_body.find(delimiter) {
                // raw_key preserves leading indent for faithful output reconstruction.
                let raw_key = &line[..indent_len + delim_pos];
                let after_delim = &line_body[delim_pos + delimiter.len()..];
                let key = line_body[..delim_pos].trim();
                if let Some(rule) = find_matching_rule(key, profile) {
                    if rule.sub_processor.is_some() {
                        if let Some((marker, _)) = detect_heredoc(after_delim) {
                            output.push_str(line);
                            output.push('\n');
                            *state = LineState::Heredoc {
                                end_marker: marker,
                                rule: rule.clone(),
                                lines: Vec::new(),
                            };
                            return Ok(());
                        }
                        let raw_value = after_delim.trim();
                        let (quote_char, inner) = detect_quotes(raw_value);
                        let processed = process_sub_content(inner, rule, store)?;
                        emit_replaced(
                            raw_key,
                            delimiter,
                            after_delim,
                            quote_char,
                            &processed,
                            output,
                        );
                        return Ok(());
                    }
                    let raw_value = after_delim.trim();
                    let (quote_char, inner) = detect_quotes(raw_value);
                    let (sanitize_inner, suffix) = match value_strip_suffix {
                        Some(sfx) if inner.ends_with(sfx) => {
                            (&inner[..inner.len() - sfx.len()], sfx)
                        }
                        _ => (inner, ""),
                    };
                    let replaced = replace_value(sanitize_inner, rule, store)?;
                    if suffix.is_empty() {
                        emit_replaced(
                            raw_key,
                            delimiter,
                            after_delim,
                            quote_char,
                            &replaced,
                            output,
                        );
                    } else {
                        emit_replaced_with_suffix(
                            raw_key,
                            delimiter,
                            after_delim,
                            quote_char,
                            &replaced,
                            suffix,
                            output,
                        );
                    }
                    return Ok(());
                }
            }
            // Try secondary delimiter (e.g. `=>` for Ruby hash lines like
            // `  'aws_access_key_id' => 'KEY',`).
            if let Some(sec_delim) = secondary_delimiter {
                if let Some(delim_pos) = line.find(sec_delim) {
                    let raw_key = &line[..delim_pos];
                    let after_delim = &line[delim_pos + sec_delim.len()..];
                    // Strip surrounding quotes from the key before matching
                    // (e.g. `'aws_access_key_id'` → `aws_access_key_id`).
                    let trimmed_key = raw_key.trim();
                    let (_, unquoted_key) = detect_quotes(trimmed_key);
                    if let Some(rule) = find_matching_rule(unquoted_key, profile) {
                        let (quote_char, inner, suffix) =
                            detect_quoted_value_with_suffix(after_delim);
                        let replaced = replace_value(inner, rule, store)?;
                        emit_replaced_with_suffix(
                            raw_key,
                            sec_delim,
                            after_delim,
                            quote_char,
                            &replaced,
                            suffix,
                            output,
                        );
                        return Ok(());
                    }
                }
            }
            output.push_str(line);
            output.push('\n');
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sub-processor dispatch
// ---------------------------------------------------------------------------

/// Delegate `content` to the processor named in `rule.sub_processor`.
///
/// Builds a synthetic [`FileTypeProfile`] from the rule's `sub_fields` and
/// calls the appropriate built-in processor directly. Returns the processed
/// content as a `String`.
fn process_sub_content(content: &str, rule: &FieldRule, store: &MappingStore) -> Result<String> {
    use super::env_proc::EnvProcessor;
    use super::ini_proc::IniProcessor;
    use super::json_proc::JsonProcessor;
    use super::log_line::LogLineProcessor;
    use super::toml_proc::TomlProcessor;
    use super::yaml_proc::YamlProcessor;

    let name = rule
        .sub_processor
        .as_deref()
        .ok_or_else(|| SanitizeError::InvalidConfig("sub_processor not set".into()))?;

    let sub_profile = FileTypeProfile {
        processor: name.to_owned(),
        extensions: Vec::new(),
        include: Vec::new(),
        exclude: Vec::new(),
        fields: rule.sub_fields.clone(),
        options: HashMap::new(),
    };

    let bytes = content.as_bytes();
    let out = match name {
        "yaml" => YamlProcessor.process(bytes, &sub_profile, store)?,
        "json" => JsonProcessor.process(bytes, &sub_profile, store)?,
        "toml" => TomlProcessor.process(bytes, &sub_profile, store)?,
        "ini" => IniProcessor.process(bytes, &sub_profile, store)?,
        "env" => EnvProcessor.process(bytes, &sub_profile, store)?,
        "log_line" => LogLineProcessor::new().process(bytes, &sub_profile, store)?,
        other => {
            return Err(SanitizeError::InvalidConfig(format!(
                "unknown sub_processor '{other}' — supported: yaml, json, toml, ini, env, log_line"
            )))
        }
    };

    String::from_utf8(out)
        .map_err(|e| SanitizeError::IoError(format!("sub-processor output is not UTF-8: {e}")))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reconstruct and append a replaced key-value line to `output`.
fn emit_replaced(
    raw_key: &str,
    delimiter: &str,
    after_delim: &str,
    quote_char: Option<char>,
    value: &str,
    output: &mut String,
) {
    let ws = leading_whitespace(after_delim);
    output.push_str(raw_key);
    output.push_str(delimiter);
    output.push_str(ws);
    if let Some(q) = quote_char {
        output.push(q);
        output.push_str(value);
        output.push(q);
    } else {
        output.push_str(value);
    }
    output.push('\n');
}

/// Like [`emit_replaced`] but appends a `suffix` after the closing quote.
///
/// Used for secondary-delimiter lines (e.g. Ruby hash `'key' => 'value',`)
/// where a trailing comma or closing brace must be preserved.
fn emit_replaced_with_suffix(
    raw_key: &str,
    delimiter: &str,
    after_delim: &str,
    quote_char: Option<char>,
    value: &str,
    suffix: &str,
    output: &mut String,
) {
    let ws = leading_whitespace(after_delim);
    output.push_str(raw_key);
    output.push_str(delimiter);
    output.push_str(ws);
    if let Some(q) = quote_char {
        output.push(q);
        output.push_str(value);
        output.push(q);
    } else {
        output.push_str(value);
    }
    output.push_str(suffix);
    output.push('\n');
}

/// Detect a quoted value in `after_delim` and return `(quote_char, inner, suffix)`.
///
/// Unlike [`detect_quotes`], this finds the *first* quoted span after any
/// leading whitespace and captures any trailing suffix (e.g. a comma in a
/// Ruby hash line `=> 'VALUE',`).  For unquoted values the whole trimmed
/// string is returned as `inner` with an empty suffix.
fn detect_quoted_value_with_suffix(after_delim: &str) -> (Option<char>, &str, &str) {
    let trimmed = after_delim.trim_start();
    if let Some(&first) = trimmed.as_bytes().first() {
        if first == b'\'' || first == b'"' {
            let q = first as char;
            if let Some(close_pos) = trimmed[1..].find(q) {
                // inner: the text between the quotes
                let inner = &trimmed[1..=close_pos];
                // suffix: everything after the closing quote (e.g. `,`)
                let suffix = &trimmed[close_pos + 2..];
                return (Some(q), inner, suffix);
            }
        }
    }
    (None, trimmed, "")
}

/// Detect a Ruby-style heredoc opener in `value` and return
/// `(end_marker, strip_indent)`.
///
/// Recognises `<<-'MARKER'`, `<<~MARKER`, `<<MARKER`, and variants with
/// single or double-quoted markers.
fn detect_heredoc(value: &str) -> Option<(String, bool)> {
    let pos = value.find("<<")?;
    let rest = &value[pos + 2..];

    let (strip, rest) = if rest.starts_with('-') || rest.starts_with('~') {
        (true, &rest[1..])
    } else {
        (false, rest)
    };

    let marker = if let Some(inner) = rest.strip_prefix('\'').and_then(|s| s.split('\'').next()) {
        inner.to_owned()
    } else if let Some(inner) = rest.strip_prefix('"').and_then(|s| s.split('"').next()) {
        inner.to_owned()
    } else {
        // Unquoted: read until whitespace or end of string.
        let m: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if m.is_empty() {
            return None;
        }
        m
    };

    Some((marker, strip))
}

/// Extract the leading whitespace of `s` (the portion before the first
/// non-whitespace character).
fn leading_whitespace(s: &str) -> &str {
    let trimmed = s.trim_start();
    &s[..s.len() - trimmed.len()]
}

/// Detect surrounding quotes and return `(quote_char, inner_value)`.
fn detect_quotes(value: &str) -> (Option<char>, &str) {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return (Some(first as char), &value[1..value.len() - 1]);
        }
    }
    (None, value)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::generator::HmacGenerator;
    use crate::processor::profile::FieldRule;
    use crate::store::MappingStore;
    use std::sync::Arc;

    fn make_store() -> Arc<MappingStore> {
        let gen = Arc::new(HmacGenerator::new([1u8; 32]));
        Arc::new(MappingStore::new(gen, None))
    }

    fn make_profile(fields: Vec<FieldRule>) -> FileTypeProfile {
        FileTypeProfile::new("key_value", fields)
    }

    fn process(content: &str, profile: &FileTypeProfile, store: &MappingStore) -> String {
        let out = KeyValueProcessor
            .process(content.as_bytes(), profile, store)
            .unwrap();
        String::from_utf8(out).unwrap()
    }

    // ---- basic key = value ----

    #[test]
    fn replaces_matched_key() {
        let store = make_store();
        let profile = make_profile(vec![
            FieldRule::new("password").with_category(Category::Custom("password".into()))
        ]);
        let input = "password = secret123\n";
        let out = process(input, &profile, &store);
        assert!(out.starts_with("password = "));
        assert!(!out.contains("secret123"));
    }

    #[test]
    fn preserves_unmatched_key() {
        let store = make_store();
        let profile = make_profile(vec![FieldRule::new("password")]);
        let input = "host = db.internal\n";
        let out = process(input, &profile, &store);
        assert_eq!(out, input);
    }

    #[test]
    fn preserves_quotes() {
        let store = make_store();
        let profile = make_profile(vec![FieldRule::new("password")]);
        let input = "password = \"secret\"\n";
        let out = process(input, &profile, &store);
        assert!(out.contains('"'));
        assert!(!out.contains("secret"));
    }

    #[test]
    fn preserves_single_quotes() {
        let store = make_store();
        let profile = make_profile(vec![FieldRule::new("key")]);
        let input = "key = 'value'\n";
        let out = process(input, &profile, &store);
        assert!(out.contains('\''));
        assert!(!out.contains("value"));
    }

    #[test]
    fn preserves_comments() {
        let store = make_store();
        let profile = make_profile(vec![]);
        let input = "# this is a comment\nkey = val\n";
        let out = process(input, &profile, &store);
        assert!(out.contains("# this is a comment"));
    }

    #[test]
    fn preserves_blank_lines() {
        let store = make_store();
        let profile = make_profile(vec![]);
        let input = "a = 1\n\nb = 2\n";
        let out = process(input, &profile, &store);
        assert_eq!(out, input);
    }

    #[test]
    fn glob_pattern_matches_ruby_bracket_key() {
        let store = make_store();
        let profile =
            make_profile(vec![FieldRule::new("*['smtp_password']")
                .with_category(Category::Custom("password".into()))]);
        let input = "gitlab_rails['smtp_password'] = \"secret\"\n";
        let out = process(input, &profile, &store);
        assert!(!out.contains("secret"));
        assert!(out.contains('"'));
    }

    // ---- heredoc detection ----

    #[test]
    fn detects_heredoc_single_quoted() {
        let (marker, strip) = detect_heredoc("YAML.load <<-'EOS'").unwrap();
        assert_eq!(marker, "EOS");
        assert!(strip);
    }

    #[test]
    fn detects_heredoc_double_quoted() {
        let (marker, _) = detect_heredoc("JSON.parse <<-\"END\"").unwrap();
        assert_eq!(marker, "END");
    }

    #[test]
    fn detects_heredoc_unquoted() {
        let (marker, strip) = detect_heredoc("<<~YAML").unwrap();
        assert_eq!(marker, "YAML");
        assert!(strip);
    }

    #[test]
    fn detects_heredoc_no_modifier() {
        let (marker, strip) = detect_heredoc("<<EOS").unwrap();
        assert_eq!(marker, "EOS");
        assert!(!strip);
    }

    #[test]
    fn no_heredoc_for_plain_value() {
        assert!(detect_heredoc("\"smtp.server\"").is_none());
        assert!(detect_heredoc("nil").is_none());
    }

    // ---- sub-processor: yaml heredoc ----

    #[test]
    fn sub_processor_yaml_heredoc() {
        let store = make_store();
        let sub_fields = vec![
            FieldRule::new("*.password").with_category(Category::Custom("password".into())),
            FieldRule::new("*.bind_dn").with_category(Category::Custom("dn".into())),
        ];
        let profile = make_profile(vec![FieldRule::new("*['ldap_servers']")
            .with_sub_processor("yaml")
            .with_sub_fields(sub_fields)]);

        let input = "\
gitlab_rails['ldap_servers'] = YAML.load <<-'EOS'
  main:
    bind_dn: 'cn=admin,dc=example,dc=com'
    password: 'real-ldap-password'
EOS
other_key = 'untouched'
";
        let out = process(input, &profile, &store);

        // Opening and closing lines preserved verbatim.
        assert!(out.contains("gitlab_rails['ldap_servers'] = YAML.load <<-'EOS'"));
        assert!(out.contains("EOS"));

        // Sensitive values replaced.
        assert!(!out.contains("real-ldap-password"));
        assert!(!out.contains("cn=admin,dc=example,dc=com"));

        // Unrelated key untouched.
        assert!(out.contains("other_key = 'untouched'"));
    }

    #[test]
    fn sub_processor_yaml_heredoc_end_marker_indented() {
        let store = make_store();
        let sub_fields =
            vec![FieldRule::new("*.secret").with_category(Category::Custom("s".into()))];
        let profile = make_profile(vec![FieldRule::new("config")
            .with_sub_processor("yaml")
            .with_sub_fields(sub_fields)]);

        let input = "\
config = <<-'EOS'
  app:
    secret: 'mysecret'
  EOS
";
        let out = process(input, &profile, &store);
        assert!(!out.contains("mysecret"));
        assert!(out.contains("EOS"));
    }

    // ---- sub-processor: non-heredoc inline value ----

    #[test]
    fn sub_processor_inline_json_value() {
        let store = make_store();
        let sub_fields =
            vec![FieldRule::new("password").with_category(Category::Custom("p".into()))];
        let profile = make_profile(vec![FieldRule::new("config")
            .with_sub_processor("json")
            .with_sub_fields(sub_fields)]);

        let input = "config = {\"password\": \"topsecret\"}\n";
        let out = process(input, &profile, &store);
        assert!(!out.contains("topsecret"));
        assert!(out.starts_with("config = "));
    }

    // ---- sub-processor: unknown name ----

    #[test]
    fn sub_processor_unknown_returns_error() {
        let store = make_store();
        let profile = make_profile(vec![FieldRule::new("key")
            .with_sub_processor("hcl")
            .with_sub_fields(vec![])]);
        let input = "key = \"value\"\n";
        let result = KeyValueProcessor.process(input.as_bytes(), &profile, &store);
        assert!(result.is_err());
    }

    // ---- field rule builder ----

    #[test]
    fn field_rule_with_sub_processor() {
        let rule = FieldRule::new("*.data")
            .with_sub_processor("yaml")
            .with_sub_fields(vec![FieldRule::new("*.password")]);
        assert_eq!(rule.sub_processor.as_deref(), Some("yaml"));
        assert_eq!(rule.sub_fields.len(), 1);
    }
}
