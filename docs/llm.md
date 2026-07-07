# LLM Prompt Formatting

The `llm` module assembles structured prompts from sanitized content, ready to
paste into an LLM or pipe to an AI tool. It handles template resolution,
content embedding, sanitization summaries, and notable-event extraction.

## Built-in Templates

| Name | Use case |
|---|---|
| `"troubleshoot"` | Incident triage — root cause, event sequence, remediation steps |
| `"review-config"` | Config review — misconfigurations, security concerns, best practices |
| `"review-security"` | Security posture — auth, network exposure, TLS, CVEs, hardcoded secrets |

Each built-in template embeds `PROMPT_PREAMBLE`, which tells the LLM that
content has been sanitized, explains the replacement model (same value → same
replacement), and instructs it not to attempt to recover original values.

A custom template can be supplied as a filesystem path — its raw content is used
as-is with no substitution.

## Prompt Modes

### Inline (`format_llm_prompt`)

Sanitized bytes are embedded directly in `<content name="…">` blocks. Use when
piping output to an LLM without writing files to disk.

```rust
use scour_secrets::llm::{format_llm_prompt, LlmEntry};

let entries: Vec<LlmEntry> = vec![
    ("app.log".to_string(), b"INFO start\nERROR disk full\n".to_vec()),
];
let prompt = format_llm_prompt("troubleshoot", &entries, None).unwrap();
// prompt contains the template instructions + <content name="app.log">...</content>
```

### Reference (`format_llm_prompt_reference`)

Sanitized files are written to disk and the prompt lists their absolute paths.
Use with `--output` when file sets are large and an agentic LLM should read
them via its own tools rather than consuming them inline.

```rust
use scour_secrets::llm::{format_llm_prompt_reference, LlmPathEntry};
use std::path::PathBuf;

let entries: Vec<LlmPathEntry> = vec![
    ("app.log".to_string(), PathBuf::from("/tmp/app.log.sanitized")),
];
let prompt = format_llm_prompt_reference("troubleshoot", &entries, None).unwrap();
// prompt lists paths for the LLM to read; no content is inlined
```

## Sanitization Summary

Pass `Some(&report)` to include a summary block showing how many files were
processed and how many replacements were applied:

```rust
let prompt = format_llm_prompt("troubleshoot", &entries, Some(&report)).unwrap();
// ## Sanitization Summary
// - Files processed: 3
// - Total replacements: 142
```

## Notable Events

When a `SanitizeReport` is provided and the report includes log context
(see [log-context.md](log-context.md)), the prompt automatically appends a
`<notable_events>` block containing the keyword-matched lines and their
surrounding context. This gives the LLM the most relevant log excerpts without
embedding the entire file.

```
<notable_events>
# app.log
  INFO  request received
>>> [error] ERROR disk full on /dev/sda1
  INFO  retrying mount

</notable_events>
```

## Custom Templates

Supply a filesystem path instead of a template name:

```rust
let prompt = format_llm_prompt("/path/to/my-template.txt", &entries, None).unwrap();
```

The file's raw content is used verbatim — no `{preamble}` substitution is
applied. Include your own context instructions for the LLM.

## Sending the Prompt to an LLM Endpoint

By default `--llm` writes the formatted prompt to stdout. Pass `--llm-endpoint`
to stream it to any OpenAI-compatible API instead.

| Flag | Env var | Description |
|------|---------|-------------|
| `--llm-endpoint <URL>` | `SCOUR_SECRETS_LLM_ENDPOINT` | Base URL of the OpenAI-compatible endpoint (e.g. `http://localhost:11434/v1` for Ollama). Requires `--llm`. |
| `--llm-model <MODEL>` | `SCOUR_SECRETS_LLM_MODEL` | Model name sent in the request body (e.g. `phi4-mini`, `gpt-4o`). Required by most endpoints. |
| `--llm-key <KEY>` | `SCOUR_SECRETS_LLM_KEY` | Bearer token / API key. Use the env var — passing on the CLI exposes it in `ps` output. Local models accept any non-empty value. |

The client enforces: HTTPS/HTTP scheme only (no `file://`, `data://`, etc.),
10 MiB SSE stream cap, ESC byte stripping from decoded content, and a separate
connect timeout distinct from the read timeout.

```bash
# Local Ollama model:
export SCOUR_SECRETS_LLM_ENDPOINT=http://localhost:11434/v1
export SCOUR_SECRETS_LLM_MODEL=phi4-mini
export SCOUR_SECRETS_LLM_KEY=ollama    # any non-empty value
sanitize server.log -s patterns.yaml --llm troubleshoot

# LM Studio (default port 1234):
sanitize config.yaml -s patterns.yaml --llm review-config \
  --llm-endpoint http://localhost:1234/v1 \
  --llm-model lmstudio-community/Meta-Llama-3-8B-Instruct-GGUF \
  --llm-key lm-studio

# OpenAI (key from environment):
export SCOUR_SECRETS_LLM_KEY=sk-proj-...
sanitize nginx.conf --app nginx --llm review-security \
  --llm-endpoint https://api.openai.com/v1 \
  --llm-model gpt-4o

# Combine with --extract-context to include notable log events:
sanitize server.log -s patterns.yaml \
  --report report.json --extract-context \
  --llm troubleshoot \
  --llm-endpoint http://localhost:11434/v1 \
  --llm-model phi4-mini --llm-key x
```

## API Reference

| Symbol | Description |
|---|---|
| `format_llm_prompt(template, entries, report)` | Inline prompt — content embedded in `<content>` blocks |
| `format_llm_prompt_reference(template, entries, report)` | Reference prompt — paths listed for agentic LLMs |
| `resolve_llm_template(name_or_path)` | Resolve a template name or path to its instruction text |
| `LlmEntry` | `(label: String, bytes: Vec<u8>)` — one file's sanitized content |
| `LlmPathEntry` | `(label: String, path: PathBuf)` — one file's output path |
| `PROMPT_PREAMBLE` | The sanitization explanation injected into built-in templates |
| `TEMPLATE_TROUBLESHOOT` | Raw troubleshooting template (without preamble substituted) |
| `TEMPLATE_REVIEW_CONFIG` | Raw config review template |
| `TEMPLATE_REVIEW_SECURITY` | Raw security posture template |
