//! LLM prompt formatting — template resolution and prompt assembly.
//!
//! Provides the built-in prompt templates and the helpers needed to build a
//! structured LLM prompt from sanitized content and an optional sanitization
//! report.
//!
//! # Built-in templates
//!
//! | Name | Use case |
//! |------|----------|
//! | `"troubleshoot"` | Incident triage — root cause, event sequence, remediation |
//! | `"review-config"` | Config review — misconfigurations, security concerns, best practices |
//! | `"review-security"` | Security posture — auth, exposure, TLS, CVEs, hardcoded secrets |
//!
//! A filesystem path can be supplied instead of a name; the file's raw content
//! is used as-is (no substitution is applied to custom templates).
//!
//! # Prompt modes
//!
//! **Inline** ([`format_llm_prompt`]) — sanitized bytes are embedded directly in
//! `<content>` blocks. Use when piping output to an LLM without writing files.
//!
//! **Reference** ([`format_llm_prompt_reference`]) — sanitized files are written
//! to disk and the prompt lists their absolute paths. Use with `--output` so an
//! agentic LLM can read the files via its own tools.
//!
//! # Example
//!
//! ```rust
//! use sanitize_engine::llm::{format_llm_prompt, LlmEntry};
//!
//! let entries: Vec<LlmEntry> = vec![
//!     ("app.log".to_string(), b"INFO start\nERROR disk full\n".to_vec()),
//! ];
//! let prompt = format_llm_prompt("troubleshoot", &entries, None).unwrap();
//! assert!(prompt.contains("Root cause"));
//! assert!(prompt.contains("<content name=\"app.log\">"));
//! ```

use crate::report::SanitizeReport;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::PathBuf;

/// A single content entry for the LLM prompt: `(label, sanitized_bytes)`.
pub type LlmEntry = (String, Vec<u8>);

/// A reference entry for the LLM prompt: `(input_label, sanitized_output_path)`.
///
/// Used by [`format_llm_prompt_reference`] when sanitized files are written to
/// disk and the prompt should reference them by absolute path instead of
/// inlining their content.
pub type LlmPathEntry = (String, PathBuf);

/// Preamble injected into every built-in template, explaining the sanitization
/// model to the LLM so it does not attempt to recover original values.
pub const PROMPT_PREAMBLE: &str = "\
Content sanitized:
- Structured fields (passwords, tokens, API keys) → __SANITIZED-<hash>__
- Typed values (emails, IPs, hostnames, UUIDs) → same-format/length substitute

Same original = same replacement per run. Repeated values safe to correlate.

No inferring originals. Critical value missing? Ask specific clarifying question. Use sanitized forms only.
";

/// Built-in template for incident troubleshooting.
pub const TEMPLATE_TROUBLESHOOT: &str = "\
SRE troubleshooting incident. Logs/output sanitized.

{preamble}
Provide:
1. Root cause — specific triggering failure
2. Event sequence — timeline to failure
3. Remediation — concrete fix + prevent recurrence

Data insufficient? State what info needed and why. No speculating on sanitized values.

";

/// Built-in template for configuration review.
pub const TEMPLATE_REVIEW_CONFIG: &str = "\
Systems engineer reviewing sanitized config.

{preamble}
Identify:
1. Misconfigurations — invalid/inconsistent settings causing failures
2. Security concerns — exposed services, permissive rules, weak/default settings
3. Best practice violations — deprecated options, missing fields, non-standard patterns
4. Credential placement — flag secret locations; presence/placement = hardcoding risk

Cannot assess redacted credential strength. Risk depends on actual value? Flag + ask.

";

/// Built-in template for security posture review.
pub const TEMPLATE_REVIEW_SECURITY: &str = "\
Security engineer: posture review of sanitized config/logs.

{preamble}
Assess and report:
1. Authentication/authz — weak configs, missing enforcement, privilege issues
2. Network exposure — ports/services/interfaces needing restriction
3. Encryption/TLS — weak ciphers, outdated protocols, insecure defaults
4. Hardcoded secrets — flag credential locations; presence/placement = finding
5. Known CVEs — tie visible version strings to known weaknesses
6. Cannot assess — list findings needing original values (e.g. password strength, token format)

Cite field/file/line per finding. No guessing sanitized values. Need actual value? Ask specifically.

";

/// Resolve a template name or path to its instruction text.
///
/// Accepts `"troubleshoot"`, `"review-config"`, `"review-security"` (built-in
/// templates with the preamble embedded), or an arbitrary filesystem path whose
/// raw content is returned unchanged.
///
/// # Errors
///
/// Returns an error string if a custom path cannot be read from disk.
pub fn resolve_llm_template(template_name: &str) -> Result<String, String> {
    match template_name {
        "troubleshoot" => Ok(TEMPLATE_TROUBLESHOOT.replace("{preamble}", PROMPT_PREAMBLE)),
        "review-config" => Ok(TEMPLATE_REVIEW_CONFIG.replace("{preamble}", PROMPT_PREAMBLE)),
        "review-security" => Ok(TEMPLATE_REVIEW_SECURITY.replace("{preamble}", PROMPT_PREAMBLE)),
        path => fs::read_to_string(path)
            .map_err(|e| format!("failed to read LLM template '{}': {e}", path)),
    }
}

/// Build a complete LLM prompt from a template, content entries, and an
/// optional sanitization report.
///
/// The prompt structure is:
/// 1. Template instructions (with preamble embedded for built-ins)
/// 2. `## Sanitization Summary` — file count and total replacements (when `report` is `Some`)
/// 3. One `<content name="…">…</content>` block per entry
/// 4. `<notable_events>…</notable_events>` — keyword-matched log lines with
///    surrounding context (only when the report contains log context with hits)
///
/// # Errors
///
/// Returns an error string if the template cannot be resolved.
pub fn format_llm_prompt(
    template_name: &str,
    entries: &[LlmEntry],
    report: Option<&SanitizeReport>,
) -> Result<String, String> {
    let mut out = resolve_llm_template(template_name)?;

    if let Some(r) = report {
        let total_replacements: u64 = r.files.iter().map(|f| f.replacements).sum();
        write!(
            out,
            "## Sanitization Summary\n\
             - Files processed: {}\n\
             - Total replacements: {total_replacements}\n\n",
            r.files.len()
        )
        .unwrap();
    }

    if !entries.is_empty() {
        out.push_str("## Files Analyzed\n");
        for (label, _) in entries {
            writeln!(out, "- {label}").unwrap();
        }
        out.push('\n');
    }

    for (label, bytes) in entries {
        let content = String::from_utf8_lossy(bytes);
        write!(
            out,
            "<content name=\"{}\">\n{}\n</content>\n\n",
            label, content
        )
        .unwrap();
    }

    if let Some(r) = report {
        append_notable_events(&mut out, r);
    }

    Ok(out)
}

/// Build a reference-mode LLM prompt: sanitized files are written to disk and
/// the prompt lists their absolute paths for an agentic LLM to read directly.
///
/// Use this instead of [`format_llm_prompt`] when `--output` is specified so
/// that large file sets are not inlined into the prompt.
///
/// # Errors
///
/// Returns an error string if the template cannot be resolved.
pub fn format_llm_prompt_reference(
    template_name: &str,
    entries: &[LlmPathEntry],
    report: Option<&SanitizeReport>,
) -> Result<String, String> {
    let mut out = resolve_llm_template(template_name)?;

    if let Some(r) = report {
        let total_replacements: u64 = r.files.iter().map(|f| f.replacements).sum();
        write!(
            out,
            "## Sanitization Summary\n\
             - Files processed: {}\n\
             - Total replacements: {total_replacements}\n\n",
            r.files.len()
        )
        .unwrap();
    }

    if !entries.is_empty() {
        out.push_str("## Sanitized Files\n");
        out.push_str("Read each path below to review the sanitized content:\n\n");
        for (label, out_path) in entries {
            writeln!(out, "- {} → {}", label, out_path.display()).unwrap();
        }
        out.push('\n');
    }

    if let Some(r) = report {
        append_notable_events(&mut out, r);
    }

    Ok(out)
}

/// Append the `<notable_events>` block to `out` when the report contains
/// keyword-matched log lines.
fn append_notable_events(out: &mut String, report: &SanitizeReport) {
    let notable: Vec<_> = report
        .files
        .iter()
        .filter_map(|f| f.log_context.as_ref().map(|ctx| (&f.path, ctx)))
        .filter(|(_, ctx)| ctx.match_count > 0)
        .collect();

    if notable.is_empty() {
        return;
    }

    out.push_str("<notable_events>\n");
    let mut any_truncated = false;
    for (path, ctx) in &notable {
        writeln!(out, "# {path}").unwrap();
        for m in &ctx.matches {
            for line in &m.before {
                writeln!(out, "  {line}").unwrap();
            }
            writeln!(out, ">>> [{}] {}", m.keyword, m.line).unwrap();
            for line in &m.after {
                writeln!(out, "  {line}").unwrap();
            }
            out.push('\n');
        }
        if ctx.truncated {
            any_truncated = true;
        }
    }
    if any_truncated {
        out.push_str(
            "(notable events truncated — use --context-lines or --report for full context)\n",
        );
    }
    out.push_str("</notable_events>\n");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_context::{extract_context, LogContextConfig};
    use crate::report::{FileReport, ReportBuilder, ReportMetadata};
    use crate::scanner::ScanStats;
    use std::fs;
    use tempfile::tempdir;

    fn make_test_report(replacements: u64) -> SanitizeReport {
        let builder = ReportBuilder::new(ReportMetadata {
            version: "0.0.0".into(),
            timestamp: "test".into(),
            deterministic: false,
            dry_run: false,
            strict: false,
            chunk_size: 1024,
            threads: None,
            secrets_file: None,
        });
        builder.record_file(FileReport::from_scan_stats(
            "test.log",
            &ScanStats {
                matches_found: replacements,
                replacements_applied: replacements,
                ..Default::default()
            },
            "scanner",
        ));
        builder.finish()
    }

    #[test]
    fn troubleshoot_embeds_preamble_and_instructions() {
        let t = resolve_llm_template("troubleshoot").unwrap();
        assert!(t.contains("sanitized"), "preamble should be embedded");
        assert!(
            t.contains("Root cause"),
            "should request root cause analysis"
        );
        assert!(
            t.contains("Remediation"),
            "should request remediation steps"
        );
        assert!(
            t.contains("clarifying question"),
            "should instruct LLM to ask rather than guess"
        );
    }

    #[test]
    fn review_config_embeds_preamble_and_instructions() {
        let t = resolve_llm_template("review-config").unwrap();
        assert!(t.contains("sanitized"), "preamble should be embedded");
        assert!(
            t.contains("Misconfigurations"),
            "should request misconfiguration review"
        );
        assert!(
            t.contains("Security concerns"),
            "should request security review"
        );
        assert!(
            t.contains("clarifying question"),
            "should instruct LLM to ask rather than guess"
        );
    }

    #[test]
    fn review_security_embeds_preamble_and_instructions() {
        let t = resolve_llm_template("review-security").unwrap();
        assert!(t.contains("sanitized"), "preamble should be embedded");
        assert!(t.contains("Authentication"), "should cover auth review");
        assert!(t.contains("Encryption"), "should cover TLS/crypto review");
        assert!(
            t.contains("Hardcoded"),
            "should flag hardcoded credential placement"
        );
        assert!(
            t.contains("clarifying question"),
            "should instruct LLM to ask rather than guess"
        );
    }

    #[test]
    fn nonexistent_path_returns_error() {
        let err = resolve_llm_template("/nonexistent/template.txt").unwrap_err();
        assert!(err.contains("failed to read"), "got: {err}");
    }

    #[test]
    fn custom_file_returns_raw_content() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("custom.txt");
        fs::write(&p, "MY CUSTOM INSTRUCTIONS\n").unwrap();
        let t = resolve_llm_template(p.to_str().unwrap()).unwrap();
        assert_eq!(t, "MY CUSTOM INSTRUCTIONS\n");
    }

    #[test]
    fn prompt_includes_content_block() {
        let entries = vec![("app.log".to_string(), b"sanitized line\n".to_vec())];
        let prompt = format_llm_prompt("troubleshoot", &entries, None).unwrap();
        assert!(
            prompt.contains("<content name=\"app.log\">"),
            "got:\n{prompt}"
        );
        assert!(prompt.contains("sanitized line"), "got:\n{prompt}");
        assert!(prompt.contains("</content>"), "got:\n{prompt}");
    }

    #[test]
    fn prompt_includes_sanitization_summary() {
        let report = make_test_report(7);
        let entries: Vec<LlmEntry> = vec![];
        let prompt = format_llm_prompt("troubleshoot", &entries, Some(&report)).unwrap();
        assert!(prompt.contains("## Sanitization Summary"), "got:\n{prompt}");
        assert!(prompt.contains("Files processed: 1"), "got:\n{prompt}");
        assert!(prompt.contains("Total replacements: 7"), "got:\n{prompt}");
    }

    #[test]
    fn prompt_includes_notable_events_when_present() {
        let builder = ReportBuilder::new(ReportMetadata {
            version: "0.0.0".into(),
            timestamp: "test".into(),
            deterministic: false,
            dry_run: false,
            strict: false,
            chunk_size: 1024,
            threads: None,
            secrets_file: None,
        });
        builder.record_file(FileReport::from_scan_stats(
            "app.log",
            &ScanStats::default(),
            "scanner",
        ));
        let ctx = extract_context(
            "INFO start\nERROR disk full\nINFO done",
            &LogContextConfig::new().with_context_lines(1),
        );
        builder.set_file_log_context("app.log", ctx);
        let report = builder.finish();

        let entries: Vec<LlmEntry> = vec![];
        let prompt = format_llm_prompt("troubleshoot", &entries, Some(&report)).unwrap();
        assert!(prompt.contains("<notable_events>"), "got:\n{prompt}");
        assert!(prompt.contains("# app.log"), "got:\n{prompt}");
        assert!(prompt.contains(">>> [error]"), "got:\n{prompt}");
        assert!(prompt.contains("ERROR disk full"), "got:\n{prompt}");
        assert!(prompt.contains("</notable_events>"), "got:\n{prompt}");
    }

    #[test]
    fn prompt_omits_notable_events_when_no_matches() {
        let report = make_test_report(0);
        let entries: Vec<LlmEntry> = vec![];
        let prompt = format_llm_prompt("troubleshoot", &entries, Some(&report)).unwrap();
        assert!(
            !prompt.contains("<notable_events>"),
            "should omit section when no keyword matches"
        );
    }

    #[test]
    fn prompt_multiple_content_blocks_in_order() {
        let entries = vec![
            ("first.log".to_string(), b"first content".to_vec()),
            ("second.log".to_string(), b"second content".to_vec()),
        ];
        let prompt = format_llm_prompt("troubleshoot", &entries, None).unwrap();
        let first_pos = prompt.find("first.log").unwrap();
        let second_pos = prompt.find("second.log").unwrap();
        assert!(
            first_pos < second_pos,
            "entries should appear in insertion order"
        );
    }

    #[test]
    fn prompt_includes_files_analyzed_manifest() {
        let entries = vec![
            (
                "/abs/app.log".to_string(),
                b"sanitized line\n".to_vec(),
            ),
            (
                "/abs/config.yaml".to_string(),
                b"key: __SANITIZED__\n".to_vec(),
            ),
        ];
        let prompt = format_llm_prompt("troubleshoot", &entries, None).unwrap();
        assert!(prompt.contains("## Files Analyzed"), "got:\n{prompt}");
        assert!(prompt.contains("- /abs/app.log"), "got:\n{prompt}");
        assert!(prompt.contains("- /abs/config.yaml"), "got:\n{prompt}");
        let manifest_pos = prompt.find("## Files Analyzed").unwrap();
        let content_pos = prompt.find("<content name=").unwrap();
        assert!(
            manifest_pos < content_pos,
            "manifest should precede content blocks"
        );
    }

    #[test]
    fn prompt_omits_files_analyzed_when_no_entries() {
        let entries: Vec<LlmEntry> = vec![];
        let prompt = format_llm_prompt("troubleshoot", &entries, None).unwrap();
        assert!(
            !prompt.contains("## Files Analyzed"),
            "should omit manifest when no entries"
        );
    }

    #[test]
    fn reference_prompt_lists_output_paths() {
        let dir = tempdir().unwrap();
        let out1 = dir.path().join("app.log.sanitized");
        let out2 = dir.path().join("config.yaml.sanitized");
        let entries: Vec<LlmPathEntry> = vec![
            ("/abs/input/app.log".to_string(), out1.clone()),
            ("/abs/input/config.yaml".to_string(), out2.clone()),
        ];
        let prompt = format_llm_prompt_reference("troubleshoot", &entries, None).unwrap();
        assert!(prompt.contains("## Sanitized Files"), "got:\n{prompt}");
        assert!(
            prompt.contains("/abs/input/app.log"),
            "should include input label; got:\n{prompt}"
        );
        assert!(
            prompt.contains(&out1.display().to_string()),
            "should include output path; got:\n{prompt}"
        );
        assert!(
            !prompt.contains("<content"),
            "reference mode must not inline content"
        );
    }

    #[test]
    fn reference_prompt_includes_sanitization_summary() {
        let report = make_test_report(12);
        let entries: Vec<LlmPathEntry> = vec![];
        let prompt =
            format_llm_prompt_reference("troubleshoot", &entries, Some(&report)).unwrap();
        assert!(prompt.contains("## Sanitization Summary"), "got:\n{prompt}");
        assert!(prompt.contains("Total replacements: 12"), "got:\n{prompt}");
    }
}
