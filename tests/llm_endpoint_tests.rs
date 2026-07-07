//! Integration tests for `--llm-endpoint` using a local mock HTTP server.
//!
//! The mock server binds to 127.0.0.1:0 (OS picks the port), handles exactly
//! one connection per instance, and shuts down when that connection is done.
//! Tests run the real `scour-secrets` binary against the mock and inspect exit
//! code / stdout / stderr.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Mock HTTP server
// ---------------------------------------------------------------------------

struct MockServer {
    port: u16,
    token: String,
}

impl MockServer {
    /// Bind, spawn a background thread that serves one connection, and return.
    /// If the client's Bearer token matches `token`, it receives `ok_response`;
    /// otherwise it receives a 401.
    fn start(token: &str, ok_response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let tok = token.to_string();

        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                serve(stream, &tok, &ok_response);
            }
        });

        MockServer {
            port,
            token: token.to_string(),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }

    fn token(&self) -> &str {
        &self.token
    }
}

/// Handle one HTTP request: read headers + body, check Bearer token, respond.
fn serve(stream: TcpStream, expected_token: &str, ok_response: &[u8]) {
    // Use try_clone() so the BufReader owns one fd and the writer owns another.
    // Both share the same underlying socket — reads on the reader consume from
    // the socket's receive buffer; writes on the writer go to the send buffer.
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    let mut bearer_ok = false;
    let mut content_length: usize = 0;

    // Read headers until the blank line.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if line == "\r\n" {
            break;
        }
        let lower = line.to_lowercase();
        if lower.starts_with("authorization: bearer ") {
            let prefix = "authorization: bearer ".len();
            bearer_ok = line[prefix..].trim() == expected_token;
        }
        if let Some(rest) = lower.strip_prefix("content-length: ") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }

    // Consume the request body so the socket buffer is drained before we
    // write the response — avoids connection-reset errors on the client side.
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        let _ = reader.read_exact(&mut body);
    }

    let mut writer = stream;
    if bearer_ok {
        let _ = writer.write_all(ok_response);
    } else {
        let err = b"{\"error\":\"unauthorized\"}";
        let _ = write!(
            writer,
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            err.len()
        );
        let _ = writer.write_all(err);
    }
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

/// Complete 200 SSE HTTP response streaming the given content chunks.
fn ok_sse(chunks: &[&str]) -> Vec<u8> {
    let mut body = String::new();
    for chunk in chunks {
        let json = serde_json::json!({"choices": [{"delta": {"content": chunk}}]});
        body.push_str(&format!("data: {json}\n\n"));
    }
    body.push_str("data: [DONE]\n\n");
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{body}")
        .into_bytes()
}

/// Complete HTTP error response.
fn http_error(status: u16, status_text: &str, json_body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {json_body}",
        json_body.len()
    )
    .into_bytes()
}

/// 200 SSE response whose content field contains ESC bytes.
fn ok_sse_with_esc() -> Vec<u8> {
    // serde_json serialises \x1b as ; the client must strip it.
    let json =
        serde_json::json!({"choices": [{"delta": {"content": "\x1b[31mred\x1b[0m normal"}}]});
    let body = format!("data: {json}\n\ndata: [DONE]\n\n");
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{body}")
        .into_bytes()
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TOKEN: &str = "test-bearer-token-abc";

fn empty_secrets(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(&p, "[]").unwrap();
    p
}

fn run(args: &[&str], stdin_data: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(args)
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(stdin_data).unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn endpoint_streams_content_to_stdout() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());
    let server = MockServer::start(TOKEN, ok_sse(&["Hello", " from", " mock"]));

    let out = run(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--llm",
            "troubleshoot",
            "--llm-endpoint",
            &server.endpoint(),
            "--llm-model",
            "test-model",
            "--llm-key",
            server.token(),
        ],
        b"log data\n",
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(
        s.contains("Hello from mock"),
        "streamed content must appear on stdout; got:\n{s}"
    );
}

#[test]
fn endpoint_wrong_token_exits_nonzero() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());
    // Server expects TOKEN; CLI sends a different key → 401.
    let server = MockServer::start(TOKEN, ok_sse(&["should-not-appear"]));

    let out = run(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--llm",
            "troubleshoot",
            "--llm-endpoint",
            &server.endpoint(),
            "--llm-model",
            "test-model",
            "--llm-key",
            "wrong-token",
        ],
        b"log data\n",
    );

    assert!(
        !out.status.success(),
        "wrong token must cause non-zero exit"
    );
    assert!(
        stderr(&out).contains("401"),
        "error must mention HTTP 401; got:\n{}",
        stderr(&out)
    );
}

#[test]
fn endpoint_http_error_exits_nonzero() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());
    let server = MockServer::start(
        TOKEN,
        http_error(
            500,
            "Internal Server Error",
            r#"{"error":"backend unavailable"}"#,
        ),
    );

    let out = run(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--llm",
            "troubleshoot",
            "--llm-endpoint",
            &server.endpoint(),
            "--llm-model",
            "test-model",
            "--llm-key",
            server.token(),
        ],
        b"log data\n",
    );

    assert!(!out.status.success(), "HTTP 500 must cause non-zero exit");
    let err = stderr(&out);
    assert!(err.contains("500"), "error must mention 500; got:\n{err}");
    assert!(
        err.contains("backend unavailable") || err.contains("Internal Server Error"),
        "error must include response body or status text; got:\n{err}"
    );
}

#[test]
fn endpoint_esc_bytes_stripped_from_output() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());
    let server = MockServer::start(TOKEN, ok_sse_with_esc());

    let out = run(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--llm",
            "troubleshoot",
            "--llm-endpoint",
            &server.endpoint(),
            "--llm-model",
            "test-model",
            "--llm-key",
            server.token(),
        ],
        b"log data\n",
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(
        !s.contains('\x1b'),
        "ESC bytes must be stripped from output; got:\n{s:?}"
    );
    assert!(
        s.contains("[31mred[0m normal"),
        "non-ESC content must be preserved; got:\n{s}"
    );
}
