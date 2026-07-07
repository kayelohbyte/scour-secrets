use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

/// Maximum bytes accepted from the SSE response stream.
const MAX_STREAM_BYTES: usize = 10 * 1024 * 1024; // 10 MB

/// Maximum bytes read from an HTTP error body.
const MAX_ERROR_BODY_BYTES: u64 = 4 * 1024; // 4 KB

/// Validate that `endpoint` uses an http or https scheme.
/// Called from `validate_args` before the HTTP request is made.
///
/// Also warns (without failing) when the endpoint is plain `http://` to a
/// non-loopback host — such a request sends the bearer key and the sanitized
/// prompt in cleartext. A local model (Ollama / LM Studio on `localhost`) over
/// `http://` is fine and does not warn.
pub(crate) fn validate_endpoint_scheme(endpoint: &str) -> Result<(), String> {
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Err(format!(
            "--llm-endpoint must start with http:// or https://; got: {endpoint}"
        ));
    }
    if is_cleartext_remote(endpoint) {
        tracing::warn!(
            "--llm-endpoint uses http:// to a non-loopback host: the API key and the \
             sanitized prompt are transmitted in cleartext. Use https://, a loopback \
             address, or a TLS-terminating reverse proxy."
        );
    }
    Ok(())
}

/// True when `endpoint` is plain `http://` (not `https`) to a host that is not a
/// loopback address — the case where credentials and prompt travel unencrypted.
fn is_cleartext_remote(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false; // https:// or other — not our concern here.
    };
    !is_loopback_host(endpoint_host(rest))
}

/// Extract the host from the part of a URL following the scheme
/// (`host[:port][/path]`, optionally with `user@` userinfo and `[..]` IPv6
/// brackets). Returns the bare host with brackets and port stripped.
fn endpoint_host(rest: &str) -> &str {
    // Authority ends at the first '/'.
    let authority = rest.split('/').next().unwrap_or("");
    // Drop any `userinfo@` prefix.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(after_bracket) = authority.strip_prefix('[') {
        // IPv6 literal: host is between the brackets.
        return after_bracket.split(']').next().unwrap_or(after_bracket);
    }
    // host:port → keep the host.
    authority.split(':').next().unwrap_or(authority)
}

/// Whether `host` is a loopback address (`localhost`, `127.0.0.0/8`, or `::1`).
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Remove ESC bytes from `s` to prevent terminal control-sequence injection.
fn strip_terminal_escapes(s: &str) -> String {
    s.replace('\x1b', "")
}

/// Read an SSE stream from `reader`, write extracted content to `writer`,
/// and enforce a `limit`-byte cap on raw stream bytes consumed.
///
/// Returns an error if the stream exceeds `limit`, if a read error occurs,
/// or if writing to `writer` fails. Stops cleanly on a `data: [DONE]` line.
/// Non-`data:` lines (comments, event names, blanks) are silently skipped.
fn process_sse_stream<R: BufRead, W: Write>(
    reader: R,
    writer: &mut W,
    limit: usize,
) -> Result<(), String> {
    let mut total_bytes: usize = 0;
    for line in reader.lines() {
        let line = line.map_err(|e| format!("error reading LLM response stream: {e}"))?;
        // Count raw line bytes before parsing to bound total stream consumption
        // for malformed/adversarial responses that carry no content field.
        total_bytes += line.len();
        if total_bytes > limit {
            return Err(format!(
                "LLM response exceeded {} MB limit; aborting",
                MAX_STREAM_BYTES / 1024 / 1024
            ));
        }
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        if data.trim() == "[DONE]" {
            break;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(data) {
            if let Some(content) = val["choices"][0]["delta"]["content"].as_str() {
                let safe = strip_terminal_escapes(content);
                writer
                    .write_all(safe.as_bytes())
                    .map_err(|e| format!("failed to write LLM response: {e}"))?;
                writer
                    .flush()
                    .map_err(|e| format!("failed to flush stdout: {e}"))?;
            }
        }
    }
    Ok(())
}

/// POST a prompt to an OpenAI-compatible `/v1/chat/completions` endpoint
/// and stream the response to stdout.
///
/// `key` may be any non-empty string for local models (Ollama, LM Studio).
/// The endpoint must support streaming (`stream: true`).
pub(crate) fn send_prompt(
    endpoint: &str,
    model: &str,
    key: &str,
    prompt: &str,
) -> Result<(), String> {
    let url = format!("{}/chat/completions", endpoint.trim_end_matches('/'));

    let body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": true
    });

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(300))
        .build();

    let response = agent
        .post(&url)
        .set("Authorization", &format!("Bearer {key}"))
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                let mut buf = Vec::new();
                let _ = resp
                    .into_reader()
                    .take(MAX_ERROR_BODY_BYTES)
                    .read_to_end(&mut buf);
                let body = String::from_utf8_lossy(&buf);
                format!("LLM endpoint returned HTTP {code}: {body}")
            }
            ureq::Error::Transport(t) => {
                format!("failed to reach LLM endpoint: {t}")
            }
        })?;

    let reader = BufReader::new(response.into_reader());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    process_sse_stream(reader, &mut out, MAX_STREAM_BYTES)?;
    drop(out);
    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sse_content_line(content: &str) -> String {
        let json = serde_json::json!({"choices":[{"delta":{"content": content}}]});
        format!("data: {json}\n")
    }

    // ---- is_cleartext_remote / endpoint host parsing ----

    #[test]
    fn cleartext_remote_flags_http_to_public_host() {
        assert!(is_cleartext_remote("http://api.example.com/v1"));
        assert!(is_cleartext_remote("http://10.0.0.5:8080/v1"));
        assert!(is_cleartext_remote("http://key@api.example.com/v1"));
    }

    #[test]
    fn cleartext_remote_ignores_https_and_loopback() {
        // https is encrypted regardless of host.
        assert!(!is_cleartext_remote("https://api.example.com/v1"));
        // Loopback over http is fine (local models).
        assert!(!is_cleartext_remote("http://localhost:11434/v1"));
        assert!(!is_cleartext_remote("http://127.0.0.1:1234/v1"));
        assert!(!is_cleartext_remote("http://127.5.6.7/v1"));
        assert!(!is_cleartext_remote("http://[::1]:8080/v1"));
    }

    #[test]
    fn endpoint_host_strips_port_userinfo_and_brackets() {
        assert_eq!(endpoint_host("api.example.com/v1"), "api.example.com");
        assert_eq!(endpoint_host("host:8080/v1"), "host");
        assert_eq!(endpoint_host("user@host:8080"), "host");
        assert_eq!(endpoint_host("[::1]:8080/v1"), "::1");
    }

    // ---- strip_terminal_escapes ----

    #[test]
    fn strip_esc_removes_all_esc_bytes() {
        assert_eq!(strip_terminal_escapes("\x1b[31mred\x1b[0m"), "[31mred[0m");
        assert_eq!(strip_terminal_escapes("safe text"), "safe text");
        assert_eq!(strip_terminal_escapes("\x1b"), "");
        assert_eq!(strip_terminal_escapes("a\x1bb\x1bc"), "abc");
    }

    #[test]
    fn strip_esc_empty_string() {
        assert_eq!(strip_terminal_escapes(""), "");
    }

    // ---- process_sse_stream ----

    #[test]
    fn sse_extracts_content_from_stream() {
        let input = format!(
            "{}{}data: [DONE]\n",
            sse_content_line("hello "),
            sse_content_line("world"),
        );
        let mut out = Vec::new();
        process_sse_stream(Cursor::new(input.as_bytes()), &mut out, MAX_STREAM_BYTES).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "hello world");
    }

    #[test]
    fn sse_strips_esc_in_content() {
        // ESC appears as  in JSON-encoded content.
        let input = format!("{}data: [DONE]\n", sse_content_line("\x1b[31mred\x1b[0m"));
        let mut out = Vec::new();
        process_sse_stream(Cursor::new(input.as_bytes()), &mut out, MAX_STREAM_BYTES).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            !s.contains('\x1b'),
            "ESC bytes must be stripped; got: {s:?}"
        );
        assert!(
            s.contains("[31mred[0m"),
            "non-ESC chars must be preserved; got: {s:?}"
        );
    }

    #[test]
    fn sse_stops_at_done() {
        let input = format!(
            "{}data: [DONE]\n{}",
            sse_content_line("first"),
            sse_content_line("should-not-appear"),
        );
        let mut out = Vec::new();
        process_sse_stream(Cursor::new(input.as_bytes()), &mut out, MAX_STREAM_BYTES).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "first");
    }

    #[test]
    fn sse_skips_non_data_lines() {
        let input = format!(
            "event: ping\n: comment\n\n{}data: [DONE]\n",
            sse_content_line("ok"),
        );
        let mut out = Vec::new();
        process_sse_stream(Cursor::new(input.as_bytes()), &mut out, MAX_STREAM_BYTES).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "ok");
    }

    #[test]
    fn sse_returns_error_when_stream_exceeds_limit() {
        // Use a small limit so the test doesn't need to allocate 10 MB.
        let limit = 500usize;
        // Each filler line is ~100 bytes; 6 lines puts us over 500.
        let filler = format!("non-data-line: {}\n", "x".repeat(90));
        let input = filler.repeat(7);
        let mut out = Vec::new();
        let err = process_sse_stream(Cursor::new(input.as_bytes()), &mut out, limit).unwrap_err();
        assert!(
            err.contains("exceeded"),
            "error must mention exceeded; got: {err}"
        );
    }
}
