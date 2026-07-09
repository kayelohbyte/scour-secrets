//! Command-output processor for support-dump files.
//!
//! Handles the `> command` + output-block shape that vendor diagnostic
//! bundles use (Dataiku `diag.txt`, Elastic diagnostics, MongoDB `mdiag`,
//! sosreport-style dumps):
//!
//! ```text
//! Mon Jun 22 04:01:46 AM UTC 2026
//! > hostname --fqdn
//! dss-prod-01.corp.example.com
//!
//! ----------------------------------------------------------
//!
//! > printenv
//! HOSTNAME=dss-prod-01
//! HTTPS_PROXY=http://user:secret@proxy:3128
//! ```
//!
//! A line starting with the prompt prefix opens a block: the rest of that
//! line is the *command string*, and the block's content is every following
//! line until the next prompt line, a separator line (four or more dashes),
//! or end of input. Field rules are matched against the command string with
//! the usual glob syntax (`hostname*` matches `hostname --fqdn`).
//!
//! - A matching rule **with** `sub_processor` delegates the block content to
//!   that processor with the rule's `sub_fields` — e.g. a `printenv` block to
//!   the `env` processor.
//! - A matching rule **without** `sub_processor` treats the trimmed block as
//!   a single value and replaces it with the rule's category (fits
//!   single-line outputs like `hostname --fqdn`); surrounding whitespace and
//!   blank lines are preserved.
//! - Blocks with no matching rule, prompt lines, separators, timestamps, and
//!   any text outside a block are preserved byte-for-byte.
//!
//! # Profile Options
//!
//! | Key             | Default | Description                                 |
//! |-----------------|---------|---------------------------------------------|
//! | `prompt_prefix` | `"> "`  | Line prefix that opens a command block.     |

use crate::error::Result;
use crate::processor::profile::FieldRule;
use crate::processor::{
    find_matching_rule, process_sub_content, replace_value, FileTypeProfile, Processor,
};
use crate::store::MappingStore;

/// Default line prefix that opens a command block.
const DEFAULT_PROMPT_PREFIX: &str = "> ";

/// Minimum run of `-` for a line to count as a block separator.
const SEPARATOR_MIN_DASHES: usize = 4;

/// Processor for `> command` + output-block support dumps.
pub struct CommandOutputProcessor;

/// Whether `line` (terminator stripped) is a separator: nothing but dashes,
/// at least [`SEPARATOR_MIN_DASHES`] of them.
fn is_separator(line: &str) -> bool {
    let t = line.trim();
    t.len() >= SEPARATOR_MIN_DASHES && t.bytes().all(|b| b == b'-')
}

/// Replace the trimmed core of `block` via `rule`, keeping leading/trailing
/// whitespace (blank output lines, final newline) byte-for-byte. Blocks that
/// are all whitespace pass through unchanged.
fn replace_block_value(block: &str, rule: &FieldRule, store: &MappingStore) -> Result<String> {
    let trimmed = block.trim();
    if trimmed.is_empty() {
        return Ok(block.to_string());
    }
    let start = block
        .find(trimmed)
        .expect("trim of a str is always a substring of it");
    let end = start + trimmed.len();
    let replaced = replace_value(trimmed, rule, store)?;
    Ok(format!("{}{}{}", &block[..start], replaced, &block[end..]))
}

impl CommandOutputProcessor {
    /// Flush a completed block: apply the matching rule (if any) and append
    /// the result to `out`.
    fn flush_block(
        block: &str,
        rule: Option<&FieldRule>,
        store: &MappingStore,
        out: &mut String,
    ) -> Result<()> {
        match rule {
            Some(rule) if rule.sub_processor.is_some() => {
                out.push_str(&process_sub_content(block, rule, store)?);
            }
            Some(rule) => out.push_str(&replace_block_value(block, rule, store)?),
            None => out.push_str(block),
        }
        Ok(())
    }
}

impl Processor for CommandOutputProcessor {
    fn name(&self) -> &'static str {
        "command_output"
    }

    fn can_handle(&self, content: &[u8], profile: &FileTypeProfile) -> bool {
        let prompt = profile
            .options
            .get("prompt_prefix")
            .map_or(DEFAULT_PROMPT_PREFIX, |s| s.as_str());
        // A prompt line somewhere in the content (start of input or of a line).
        content.starts_with(prompt.as_bytes())
            || content
                .windows(prompt.len() + 1)
                .any(|w| w[0] == b'\n' && &w[1..] == prompt.as_bytes())
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        let text =
            std::str::from_utf8(content).map_err(|e| crate::error::SanitizeError::ParseError {
                format: "command_output".into(),
                message: format!("requires UTF-8 input: {e}"),
            })?;
        let prompt = profile
            .options
            .get("prompt_prefix")
            .map_or(DEFAULT_PROMPT_PREFIX, |s| s.as_str());

        let mut out = String::with_capacity(text.len());
        // Rule for the block currently being collected, and its raw content.
        let mut active_rule: Option<Option<&FieldRule>> = None;
        let mut block = String::new();

        for line in text.split_inclusive('\n') {
            let body = line.strip_suffix('\n').unwrap_or(line);
            let body = body.strip_suffix('\r').unwrap_or(body);

            if let Some(command) = body.strip_prefix(prompt) {
                // New prompt terminates any open block.
                if let Some(rule) = active_rule.take() {
                    Self::flush_block(&block, rule, store, &mut out)?;
                    block.clear();
                }
                out.push_str(line);
                active_rule = Some(find_matching_rule(command.trim(), profile));
            } else if is_separator(body) {
                if let Some(rule) = active_rule.take() {
                    Self::flush_block(&block, rule, store, &mut out)?;
                    block.clear();
                }
                out.push_str(line);
            } else if active_rule.is_some() {
                block.push_str(line);
            } else {
                out.push_str(line);
            }
        }
        if let Some(rule) = active_rule {
            Self::flush_block(&block, rule, store, &mut out)?;
        }

        Ok(out.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::generator::HmacGenerator;
    use crate::processor::profile::{FieldRule, FileTypeProfile};
    use std::sync::Arc;

    fn store() -> MappingStore {
        MappingStore::new(Arc::new(HmacGenerator::new([42u8; 32])), None)
    }

    fn profile(fields: Vec<FieldRule>) -> FileTypeProfile {
        FileTypeProfile::new("command_output", fields)
    }

    fn hostname_rule() -> FieldRule {
        FieldRule::new("hostname*")
            .with_category(Category::Hostname)
            .with_min_length(2)
    }

    const DUMP: &str = "DSS Diagnosis\n\
        Diagnosis started at Mon Jun 22 04:01:42 AM UTC 2026\n\
        \n\
        ----------------------------------------------------------\n\
        \n\
        Mon Jun 22 04:01:42 AM UTC 2026\n\
        > uname -a\n\
        Linux dss-prod-01 6.12.76-linuxkit #1 SMP x86_64 GNU/Linux\n\
        \n\
        ----------------------------------------------------------\n\
        \n\
        Mon Jun 22 04:01:46 AM UTC 2026\n\
        > hostname --fqdn\n\
        dss-prod-01.corp.example.com\n\
        \n\
        ----------------------------------------------------------\n";

    #[test]
    fn replaces_matched_command_output_and_preserves_the_rest() {
        let store = store();
        let profile = profile(vec![hostname_rule()]);
        let out = CommandOutputProcessor
            .process(DUMP.as_bytes(), &profile, &store)
            .unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(
            !out.contains("dss-prod-01.corp.example.com"),
            "fqdn must be replaced: {out}"
        );
        // Everything not covered by the matched rule is byte-identical,
        // including the prompt line, separators, timestamps, and the
        // unmatched uname block.
        assert!(out.contains("> hostname --fqdn\n"));
        assert!(out.contains("Linux dss-prod-01 6.12.76-linuxkit #1 SMP x86_64 GNU/Linux\n"));
        assert!(out.contains("Diagnosis started at Mon Jun 22 04:01:42 AM UTC 2026\n"));
        assert_eq!(
            out.matches("----------------------------------------------------------\n")
                .count(),
            3
        );
        // Trailing blank line of the block survives the value replacement.
        assert_eq!(out.lines().count(), DUMP.lines().count());
    }

    #[test]
    fn unmatched_input_is_byte_identical() {
        let store = store();
        let profile = profile(vec![
            FieldRule::new("nomatch*").with_category(Category::Hostname)
        ]);
        let out = CommandOutputProcessor
            .process(DUMP.as_bytes(), &profile, &store)
            .unwrap();
        assert_eq!(out, DUMP.as_bytes());
    }

    #[test]
    fn delegates_block_to_sub_processor() {
        let store = store();
        let profile = profile(vec![FieldRule::new("printenv")
            .with_sub_processor("env")
            .with_sub_fields(vec![FieldRule::new("*PASSWORD*")
                .with_category(Category::Custom("password".into()))
                .with_min_length(1)])]);
        let dump = "> printenv\nHOME=/home/dataiku\nDB_PASSWORD=hunter2secret\n\n> id\nuid=1000\n";
        let out = CommandOutputProcessor
            .process(dump.as_bytes(), &profile, &store)
            .unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(
            !out.contains("hunter2secret"),
            "env credential replaced: {out}"
        );
        assert!(
            out.contains("HOME=/home/dataiku\n"),
            "other vars preserved: {out}"
        );
        assert!(
            out.contains("> id\nuid=1000\n"),
            "next block preserved: {out}"
        );
    }

    #[test]
    fn custom_prompt_prefix_option() {
        let store = store();
        let mut profile = profile(vec![hostname_rule()]);
        profile.options.insert("prompt_prefix".into(), "$ ".into());
        let dump = "$ hostname\nweb-42.internal\n";
        assert!(CommandOutputProcessor.can_handle(dump.as_bytes(), &profile));
        let out = CommandOutputProcessor
            .process(dump.as_bytes(), &profile, &store)
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("web-42.internal"));
        assert!(out.starts_with("$ hostname\n"));
    }

    #[test]
    fn can_handle_requires_a_prompt_line() {
        let profile = profile(vec![]);
        assert!(CommandOutputProcessor.can_handle(b"> uname -a\nLinux\n", &profile));
        assert!(CommandOutputProcessor.can_handle(b"header\n> id\nuid=0\n", &profile));
        assert!(!CommandOutputProcessor.can_handle(b"plain text, no prompts\n", &profile));
    }

    #[test]
    fn empty_command_output_passes_through() {
        let store = store();
        let profile = profile(vec![hostname_rule()]);
        let dump = "> hostname --fqdn\n\n\n----\n";
        let out = CommandOutputProcessor
            .process(dump.as_bytes(), &profile, &store)
            .unwrap();
        assert_eq!(out, dump.as_bytes());
    }
}
