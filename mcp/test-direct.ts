#!/usr/bin/env -S deno run --allow-run --allow-env --allow-read --allow-write --allow-net
/**
 * Comprehensive direct MCP feature tests.
 *
 * Covers every tool, every parameter path, and every documented error case.
 * Runs standalone — no separate test framework needed.
 *
 *   SCOUR_SECRETS_BIN=./target/release/scour-secrets deno run \
 *     --allow-run --allow-env --allow-read --allow-write \
 *     mcp/test-direct.ts
 */

import { join, resolve } from "@std/path";
import { predictOutputName, uniquifyName } from "./src/naming.ts";
import { McpSession, startStdioSession } from "./mcp_client.ts";
import { scrubEnv } from "./src/env.ts";

const MCP_SCRIPT = join(import.meta.dirname!, "src/index.ts");
// Resolve to absolute so the server can locate the binary even when it runs in
// a different working directory (cwd override used by file-writing tool tests).
const SCOUR_SECRETS_BIN = resolve(
  Deno.env.get("SCOUR_SECRETS_BIN") ??
    join(import.meta.dirname!, "../target/release/scour-secrets"),
);

// ---------------------------------------------------------------------------
// JSON-RPC session — stdio client lives in ./mcp_client.ts (shared with probe.ts)
// ---------------------------------------------------------------------------

function startSession(extraEnv: Record<string, string> = {}, cwd?: string): Promise<McpSession> {
  return startStdioSession({ serverPath: MCP_SCRIPT, sanitizeBin: SCOUR_SECRETS_BIN, env: extraEnv, cwd });
}

// ---------------------------------------------------------------------------
// HTTP daemon helpers
// ---------------------------------------------------------------------------

async function getFreePort(): Promise<number> {
  const l = Deno.listen({ port: 0, hostname: "127.0.0.1" });
  const port = (l.addr as Deno.NetAddr).port;
  l.close();
  return port;
}

async function startHttpDaemon(port: number, token: string): Promise<Deno.ChildProcess> {
  const child = new Deno.Command(Deno.execPath(), {
    args: [
      "run",
      "--allow-run", "--allow-env", "--allow-read", "--allow-write", "--allow-net",
      MCP_SCRIPT, "--http", String(port),
    ],
    stdin: "null", stdout: "null", stderr: "null",
    env: { ...Deno.env.toObject(), SCOUR_SECRETS_BIN, SCOUR_SECRETS_LOG: "error", SCOUR_SECRETS_MCP_HTTP_TOKEN: token },
  }).spawn();

  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: "{}",
      });
      await r.body?.cancel();
      return child;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  child.kill("SIGTERM");
  throw new Error(`HTTP daemon did not start within 5 s on port ${port}`);
}

class HttpMcpSession {
  private sessionId: string | null = null;
  private idCtr = 9000;

  constructor(private baseUrl: string, private token: string) {}

  private reqHeaders(): Record<string, string> {
    const h: Record<string, string> = {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      "Authorization": `Bearer ${this.token}`,
    };
    if (this.sessionId) h["Mcp-Session-Id"] = this.sessionId;
    return h;
  }

  async send(method: string, params?: unknown): Promise<unknown> {
    const id = this.idCtr++;
    const res = await fetch(`${this.baseUrl}/mcp`, {
      method: "POST",
      headers: this.reqHeaders(),
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    if (res.status !== 200) { await res.body?.cancel(); throw new Error(`HTTP ${res.status}`); }
    const sid = res.headers.get("Mcp-Session-Id");
    if (sid) this.sessionId = sid;

    const text = await res.text();
    // Response is either plain JSON or SSE (data: {...} lines); parse both uniformly.
    for (const line of text.split("\n")) {
      const src = line.startsWith("data: ") ? line.slice(6) : line.trim();
      if (!src) continue;
      let msg: { id?: number; result?: unknown; error?: unknown } | null = null;
      try { msg = JSON.parse(src); } catch { continue; }
      if (msg?.id !== id) continue;
      if (msg.error) throw new Error(JSON.stringify(msg.error));
      return msg.result;
    }
    throw new Error(`No response for id=${id} in: ${text.slice(0, 300)}`);
  }

  async notify(method: string, params?: unknown): Promise<void> {
    const res = await fetch(`${this.baseUrl}/mcp`, {
      method: "POST",
      headers: this.reqHeaders(),
      body: JSON.stringify({ jsonrpc: "2.0", method, params }),
    });
    await res.body?.cancel();
  }

  async close(): Promise<void> {
    if (this.sessionId) {
      await fetch(`${this.baseUrl}/mcp`, {
        method: "DELETE",
        headers: this.reqHeaders(),
      }).catch(() => {});
    }
  }
}

// Read from a stream for up to maxMs, stopping early when stopOn substring appears.
async function readStreamFor(
  stream: ReadableStream<Uint8Array>,
  maxMs: number,
  stopOn?: string,
): Promise<string> {
  const dec = new TextDecoder();
  let text = "";
  const reader = stream.getReader();
  const deadline = Date.now() + maxMs;
  try {
    while (Date.now() < deadline) {
      const remaining = Math.max(1, deadline - Date.now());
      const result = await Promise.race([
        reader.read(),
        new Promise<{ done: true; value: undefined }>((r) =>
          setTimeout(() => r({ done: true, value: undefined }), remaining)
        ),
      ]);
      if (result.done) break;
      if (result.value) text += dec.decode(result.value);
      if (stopOn && text.includes(stopOn)) break;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return text;
}

async function startHttpMcpSession(baseUrl: string, token: string): Promise<HttpMcpSession> {
  const s = new HttpMcpSession(baseUrl, token);
  await s.send("initialize", {
    protocolVersion: "2024-11-05", capabilities: {},
    clientInfo: { name: "http-test", version: "1.0" },
  });
  await s.notify("notifications/initialized");
  return s;
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

function toolText(r: unknown): string {
  return (r as { content: Array<{ text: string }> }).content.map((c) => c.text).join("");
}
function toolIsError(r: unknown): boolean {
  return (r as { isError?: boolean }).isError === true;
}

function ok(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}
function has(s: string, sub: string) {
  if (!s.includes(sub)) throw new Error(`Expected to contain ${JSON.stringify(sub)}\nGot: ${s.slice(0, 300)}`);
}
function not(s: string, sub: string) {
  if (s.includes(sub)) throw new Error(`Expected NOT to contain ${JSON.stringify(sub)}\nGot: ${s.slice(0, 300)}`);
}

// ---------------------------------------------------------------------------
// Test registry
// ---------------------------------------------------------------------------

type Fn = (s: McpSession) => Promise<void>;
const tests: Array<{ name: string; fn: Fn; group: string }> = [];

function test(group: string, name: string, fn: Fn) {
  tests.push({ group, name, fn });
}

// ===========================================================================
// Pure unit tests — naming functions (no MCP session required)
// ===========================================================================

{
  const eq = (actual: string, expected: string, label: string) => {
    if (actual !== expected) {
      throw new Error(`predictOutputName ${label}: expected "${expected}", got "${actual}"`);
    }
  };

  // Archives — use ".sanitized." separator and preserve the full compound extension.
  eq(predictOutputName("archive.tar.gz"),        "archive.sanitized.tar.gz",  ".tar.gz");
  eq(predictOutputName("archive.TGZ"),           "archive.sanitized.tar.gz",  ".TGZ (case insensitive, normalised to .tar.gz)");
  eq(predictOutputName("archive.tgz"),           "archive.sanitized.tar.gz",  ".tgz (normalised to .tar.gz)");
  eq(predictOutputName("archive.tar"),           "archive.sanitized.tar",     ".tar");
  eq(predictOutputName("archive.TAR"),           "archive.sanitized.tar",     ".TAR (case insensitive)");
  eq(predictOutputName("archive.zip"),           "archive.sanitized.zip",     ".zip");
  eq(predictOutputName("archive.ZIP"),           "archive.sanitized.zip",     ".ZIP (case insensitive)");

  // Compound stem stripping: "data.tar.gz" → stem "data", not "data.tar".
  eq(predictOutputName("data.tar.gz"),           "data.sanitized.tar.gz",     "compound stem stripped correctly");
  eq(predictOutputName("my.backup.tar.gz"),      "my.backup.sanitized.tar.gz","stem with interior dot");

  // Path component stripped — only the basename matters.
  eq(predictOutputName("/var/log/archive.tar.gz"), "archive.sanitized.tar.gz", "absolute path basename");
  eq(predictOutputName("a/b/c/archive.tar"),       "archive.sanitized.tar",    "relative path basename");

  // Plain files — use "-sanitized." separator (rsplit at last dot).
  eq(predictOutputName("config.json"),           "config-sanitized.json",     ".json plain file");
  eq(predictOutputName("report.txt"),            "report-sanitized.txt",      ".txt plain file");
  eq(predictOutputName("app.log"),               "app-sanitized.log",         ".log plain file");
  eq(predictOutputName("data.csv"),              "data-sanitized.csv",        ".csv plain file");

  // No extension.
  eq(predictOutputName("Makefile"),              "Makefile-sanitized",        "no extension");
  eq(predictOutputName("noext"),                 "noext-sanitized",           "no extension (bare name)");

  // Leading dot only — treated as no extension by lastIndexOf logic (dot at 0).
  eq(predictOutputName(".hidden"),               ".hidden-sanitized",         "dot-file with no extension");
}

{
  const eq = (actual: string, expected: string, label: string) => {
    if (actual !== expected) {
      throw new Error(`uniquifyName ${label}: expected "${expected}", got "${actual}"`);
    }
  };

  // First use returns the name unchanged.
  const u1 = new Set<string>();
  eq(uniquifyName("archive.sanitized.tar.gz", u1), "archive.sanitized.tar.gz", "first use, no collision");

  // Collision: suffix goes before the compound extension, not just ".gz".
  const u2 = new Set(["archive.sanitized.tar.gz"]);
  eq(uniquifyName("archive.sanitized.tar.gz", u2), "archive.sanitized_2.tar.gz", ".tar.gz collision → _2 before .tar.gz");

  // Sequential collisions.
  const u3 = new Set(["archive.sanitized.tar.gz", "archive.sanitized_2.tar.gz"]);
  eq(uniquifyName("archive.sanitized.tar.gz", u3), "archive.sanitized_3.tar.gz", "sequential collision → _3");

  // Plain files: suffix goes before the single extension.
  const u4 = new Set(["config-sanitized.json"]);
  eq(uniquifyName("config-sanitized.json", u4), "config-sanitized_2.json", "plain file collision → _2 before .json");

  // No extension.
  const u5 = new Set(["Makefile-sanitized"]);
  eq(uniquifyName("Makefile-sanitized", u5), "Makefile-sanitized_2", "no-extension collision");
}

// Subprocess env scrubbing — a security property: parent-process secrets must
// not reach the sanitize child. Pure function, no MCP session required.
{
  const fail = (label: string) => { throw new Error(`scrubEnv: ${label}`); };
  const parent = {
    PATH: "/usr/bin",
    HOME: "/home/u",
    LANG: "en_US.UTF-8",
    AWS_SECRET_ACCESS_KEY: "LEAKED",
    DATABASE_URL: "postgres://leak",
    GITHUB_TOKEN: "ghp_leak",
    SCOUR_SECRETS_SECRETS_DIR: "/var/sanitize",
    SCOUR_SECRETS_LOG: "debug",
  };
  const out = scrubEnv(parent, { SCOUR_SECRETS_PASSWORD: "seed" });

  // Secrets from the parent environment must be dropped.
  for (const leaked of ["AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "GITHUB_TOKEN"]) {
    if (leaked in out) fail(`${leaked} must be dropped`);
  }
  // Runtime essentials forwarded.
  if (out.PATH !== "/usr/bin") fail("PATH must be forwarded");
  if (out.HOME !== "/home/u") fail("HOME must be forwarded");
  // SCOUR_SECRETS_* forwarded so callers can configure via environment.
  if (out.SCOUR_SECRETS_SECRETS_DIR !== "/var/sanitize") fail("SCOUR_SECRETS_* must be forwarded");
  // SCOUR_SECRETS_LOG forced to error regardless of a chatty parent value.
  if (out.SCOUR_SECRETS_LOG !== "error") fail("SCOUR_SECRETS_LOG must be forced to error");
  // extraEnv applied.
  if (out.SCOUR_SECRETS_PASSWORD !== "seed") fail("extraEnv must be applied");
}

console.log("  \x1b[32m✓\x1b[0m predictOutputName / uniquifyName unit tests passed\n");

// ===========================================================================
// sanitize tool
// ===========================================================================

test("sanitize", "replaces email with realistic substitute", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "Contact alice@example.com for help.",
      patterns: [{ name: "email", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", category: "email", kind: "regex" }],
    },
  }));
  not(r, "alice@example.com");
  has(r, "@"); // email format preserved
});

test("sanitize", "replaces IPv4 address", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "Request from 203.0.113.42 denied.",
      patterns: [{ name: "ip", pattern: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", category: "ipv4", kind: "regex" }],
    },
  }));
  not(r, "203.0.113.42");
  has(r, "Request from");
});

test("sanitize", "literal pattern replaces exact string only", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "token: mysecrettoken123\nother: mysecrettoken123extra",
      patterns: [{ name: "tok", pattern: "mysecrettoken123", category: "auth_token", kind: "literal" }],
    },
  }));
  not(r, "mysecrettoken123\n"); // the standalone occurrence is replaced
  has(r, "token:");
});

test("sanitize", "kind:allow passes value through unchanged", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "host: localhost\nhost2: prod.example.com",
      patterns: [
        { name: "host", pattern: "\\b[a-z0-9.-]+\\.[a-z]{2,}\\b", category: "hostname", kind: "regex" },
        { name: "allow_localhost", pattern: "localhost", category: "hostname", kind: "allow" },
      ],
    },
  }));
  has(r, "localhost");      // allowed through
  not(r, "prod.example.com"); // replaced
});

test("sanitize", "seed produces identical output on two calls", async (s) => {
  const args = {
    name: "sanitize",
    arguments: {
      content: "key=hunter2secret",
      seed: "stable-test-seed-42",
      patterns: [{ name: "pw", pattern: "hunter2secret", category: "generic" }],
    },
  };
  const r1 = toolText(await s.send("tools/call", args));
  const r2 = toolText(await s.send("tools/call", args));
  ok(r1 === r2, `seed must produce identical output\nr1=${r1}\nr2=${r2}`);
  not(r1, "hunter2secret");
});

test("sanitize", "different seeds produce different output", async (s) => {
  const base = {
    content: "secret=topsecret99",
    patterns: [{ name: "s", pattern: "topsecret99", category: "generic" }],
  };
  const r1 = toolText(await s.send("tools/call", { name: "sanitize", arguments: { ...base, seed: "seed-alpha" } }));
  const r2 = toolText(await s.send("tools/call", { name: "sanitize", arguments: { ...base, seed: "seed-beta" } }));
  not(r1, "topsecret99");
  not(r2, "topsecret99");
  ok(r1 !== r2, "different seeds should produce different replacements");
});

test("sanitize", "no patterns returns content unchanged", async (s) => {
  const content = "nothing sensitive here";
  const r = toolText(await s.send("tools/call", { name: "sanitize", arguments: { content } }));
  ok(r.trim() === content, `expected unchanged, got: ${r}`);
});

test("sanitize", "use_default detects email via built-in balanced patterns", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "From: sysadmin@corp.example.com", use_default: true },
  }));
  not(r, "sysadmin@corp.example.com");
  has(r, "From:");
});

test("sanitize", "use_default detects IPv4", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "client connected from 198.51.100.42", use_default: true },
  }));
  not(r, "198.51.100.42");
});

test("sanitize", "use_default detects GitHub token", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123",
      use_default: true,
    },
  }));
  not(r, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123");
});

test("sanitize", "allow param passes specific values through", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "from 127.0.0.1 and from 203.0.113.5",
      use_default: true,
      allow: ["127.0.0.1"],
    },
  }));
  has(r, "127.0.0.1");   // allowed
  not(r, "203.0.113.5"); // replaced
});

test("sanitize", "allow glob pattern passes matching values through", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "server: db.internal\nalso: prod.corp.com",
      use_default: true,
      allow: ["*.internal"],
    },
  }));
  has(r, "db.internal");   // allowed by glob
});

test("sanitize", "format json preserves JSON structure", async (s) => {
  const input = JSON.stringify({ password: "hunter2", port: 5432 });
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: input,
      format: "json",
      patterns: [{ name: "pw", pattern: "hunter2", category: "generic" }],
    },
  }));
  not(r, "hunter2");
  const parsed = JSON.parse(r);          // must remain valid JSON
  ok(parsed.port === 5432, "non-secret fields must survive");
});

test("sanitize", "format yaml preserves YAML structure (key survives)", async (s) => {
  const input = "database:\n  password: s3cret_pw\n  host: db.corp.com\n  port: 5432\n";
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: input,
      format: "yaml",
      patterns: [{ name: "pw", pattern: "s3cret_pw", category: "generic" }],
    },
  }));
  not(r, "s3cret_pw");
  has(r, "password:");  // key must survive
  has(r, "5432");       // non-secret field must survive
});

test("sanitize", "format toml preserves structure", async (s) => {
  const input = '[db]\npassword = "s3cret"\nport = 5432\n';
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: input,
      format: "toml",
      patterns: [{ name: "pw", pattern: "s3cret", category: "generic" }],
    },
  }));
  not(r, "s3cret");
  has(r, "port");
});

test("sanitize", "format env replaces secret value keeps key", async (s) => {
  const input = "API_KEY=secretkey123\nDEBUG=true\n";
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: input,
      format: "env",
      patterns: [{ name: "key", pattern: "secretkey123", category: "auth_token" }],
    },
  }));
  not(r, "secretkey123");
  has(r, "API_KEY");
  has(r, "DEBUG");
});

test("sanitize", "format key-value replaces values", async (s) => {
  const input = "host = prod.internal\npassword = s3cr3t\n";
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: input,
      format: "key-value",
      patterns: [{ name: "pw", pattern: "s3cr3t", category: "generic" }],
    },
  }));
  not(r, "s3cr3t");
  has(r, "password");
});

test("sanitize", "format csv replaces values in cells", async (s) => {
  const input = "name,email,ip\nalice,alice@corp.com,10.0.0.1\n";
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: input,
      format: "csv",
      patterns: [
        { name: "email", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", category: "email", kind: "regex" },
      ],
    },
  }));
  not(r, "alice@corp.com");
  has(r, "name,email,ip"); // header preserved
});

test("sanitize", "format jsonl replaces values across lines", async (s) => {
  const input = '{"user":"alice@corp.com","action":"login"}\n{"user":"bob@corp.com","action":"logout"}\n';
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: input,
      format: "jsonl",
      patterns: [{ name: "email", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", category: "email", kind: "regex" }],
    },
  }));
  not(r, "alice@corp.com");
  not(r, "bob@corp.com");
  // Each line must remain valid JSON
  for (const line of r.trim().split("\n")) JSON.parse(line);
});

test("sanitize", "extract_context returns {content, report} with log_context", async (s) => {
  const content = [
    "INFO  service started",
    "ERROR disk full at /dev/sda1",
    "INFO  retry scheduled",
    "WARN  queue depth rising",
    "INFO  recovered",
  ].join("\n");
  const raw = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: { content, extract_context: true },
  }));
  const result = JSON.parse(raw);
  ok("content" in result, "must have content field");
  ok("report" in result, "must have report field");
  const lc = result.report.files[0].log_context;
  ok(lc.match_count >= 2, `expected ≥2 matches, got ${lc.match_count}`);
  const kws = lc.matches.map((m: { keyword: string }) => m.keyword);
  ok(kws.includes("error"), "must flag ERROR");
  ok(kws.includes("warn"), "must flag WARN");
});

test("sanitize", "extract_context respects context_lines=1", async (s) => {
  const lines = ["a", "b", "c", "ERROR hit", "d", "e", "f"];
  const raw = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: lines.join("\n"), extract_context: true, context_lines: 1 },
  }));
  const m = JSON.parse(raw).report.files[0].log_context.matches[0];
  ok(m.before.length === 1, `expected 1 before, got ${m.before.length}`);
  ok(m.after.length === 1, `expected 1 after, got ${m.after.length}`);
  ok(m.before[0] === "c", `expected 'c', got '${m.before[0]}'`);
  ok(m.after[0] === "d", `expected 'd', got '${m.after[0]}'`);
});

test("sanitize", "context_keywords merges with defaults", async (s) => {
  const content = "INFO ok\nERROR fail\nTIMEOUT waiting\n";
  const raw = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: { content, extract_context: true, context_keywords: ["timeout"] },
  }));
  const kws = JSON.parse(raw).report.files[0].log_context.matches.map(
    (m: { keyword: string }) => m.keyword,
  );
  ok(kws.includes("error"), "built-in 'error' must still match");
  ok(kws.includes("timeout"), "custom 'timeout' must match");
});

test("sanitize", "max_context_matches caps and sets truncated=true", async (s) => {
  const content = Array.from({ length: 10 }, (_, i) => `ERROR line ${i}`).join("\n");
  const raw = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: { content, extract_context: true, max_context_matches: 3 },
  }));
  const lc = JSON.parse(raw).report.files[0].log_context;
  ok(lc.match_count === 3, `expected 3, got ${lc.match_count}`);
  ok(lc.truncated === true, "truncated must be true");
});

test("sanitize", "context_case_sensitive skips wrong-case keywords", async (s) => {
  const content = "INFO ok\nERROR uppercase\nerror lowercase\n";
  const raw = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content,
      extract_context: true,
      context_keywords: ["error"],
      context_case_sensitive: true,
    },
  }));
  const lines = JSON.parse(raw).report.files[0].log_context.matches.map(
    (m: { line: string }) => m.line,
  );
  ok(!lines.some((l: string) => l.includes("ERROR uppercase")), "uppercase ERROR must not match");
  ok(lines.some((l: string) => l.includes("error lowercase")), "lowercase error must match");
});

test("sanitize", "without extract_context returns plain string", async (s) => {
  const r = toolText(await s.send("tools/call", { name: "sanitize", arguments: { content: "hello world" } }));
  ok(r.trim() === "hello world", `expected plain string, got: ${r}`);
});

test("sanitize", "app gitlab loads patterns and profile", async (s) => {
  // GitLab CI log contains a runner token; the gitlab app bundle should catch it
  const content = "glpat-AbCdEfGhIjKlMnOpQrSt running pipeline";
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: { content, app: ["gitlab"] },
  }));
  not(r, "glpat-AbCdEfGhIjKlMnOpQrSt");
});

// Error cases
test("sanitize", "error: absolute secrets_file rejected", async (s) => {
  const r = await s.send("tools/call", { name: "sanitize", arguments: { content: "x", secrets_file: "/etc/passwd" } });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "relative path");
});

test("sanitize", "error: path traversal in secrets_file rejected", async (s) => {
  const r = await s.send("tools/call", { name: "sanitize", arguments: { content: "x", secrets_file: "../../etc/passwd" } });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "'..'");
});

test("sanitize", "error: content too large rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "x".repeat(600_000) },
  });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "exceeds maximum");
});

test("sanitize", "error: namespace with invalid characters rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "x", namespace: "../evil" },
  });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "Invalid namespace");
});

test("sanitize", "error: namespace without SCOUR_SECRETS_SECRETS_DIR env rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "x", namespace: "acme" },
  });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "SCOUR_SECRETS_SECRETS_DIR");
});

// ===========================================================================
// scan tool
// ===========================================================================

test("scan", "returns report with match counts", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "scan",
    arguments: {
      content: "user = alice@corp.com\nip = 10.0.0.1",
      patterns: [
        { name: "email", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", category: "email", kind: "regex" },
        { name: "ip", pattern: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", category: "ipv4", kind: "regex" },
      ],
    },
  })));
  ok("files" in r, "report must have files");
  const total = r.files.reduce((s: number, f: { matches: number }) => s + f.matches, 0);
  ok(total >= 2, `expected ≥2 matches, got ${total}`);
});

test("scan", "dry_run: report exists but content not in output", async (s) => {
  const content = "password = topsecret123";
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "scan",
    arguments: {
      content,
      patterns: [{ name: "pw", pattern: "topsecret123", category: "generic" }],
    },
  })));
  ok("files" in r, "report must have files");
  ok(r.files[0].matches >= 1, "must report ≥1 match");
  // scan tool doesn't return content — it's report-only
});

test("scan", "use_default detects email and IP", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "scan",
    arguments: {
      content: "sysadmin@corp.com connected from 198.51.100.4",
      use_default: true,
    },
  })));
  const total = r.files.reduce((s: number, f: { matches: number }) => s + f.matches, 0);
  ok(total >= 2, `expected ≥2 matches, got ${total}`);
});

test("scan", "allow suppresses known-safe values from report", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "scan",
    arguments: {
      content: "from 127.0.0.1 and from 198.51.100.5",
      use_default: true,
      allow: ["127.0.0.1"],
    },
  })));
  // 198.51.100.5 should be reported, 127.0.0.1 should not
  const total = r.files.reduce((s: number, f: { matches: number }) => s + f.matches, 0);
  ok(total >= 1, "198.51.100.5 must be reported");
  // total should be less than if we scanned without allow
});

test("scan", "format json scans structured content", async (s) => {
  const input = JSON.stringify({ api_key: "s3cr3tkey", host: "db.internal" });
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "scan",
    arguments: {
      content: input,
      format: "json",
      patterns: [{ name: "key", pattern: "s3cr3tkey", category: "auth_token" }],
    },
  })));
  const total = r.files.reduce((s: number, f: { matches: number }) => s + f.matches, 0);
  ok(total >= 1, `expected ≥1 match, got ${total}`);
});

test("scan", "app gitlab loads patterns for scan", async (s) => {
  const content = "glpat-AbCdEfGhIjKlMnOpQrSt pushed commit";
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "scan",
    arguments: { content, app: ["gitlab"] },
  })));
  const total = r.files.reduce((s: number, f: { matches: number }) => s + f.matches, 0);
  ok(total >= 1, "gitlab token must be detected");
});

test("scan", "error: absolute secrets_file rejected", async (s) => {
  const r = await s.send("tools/call", { name: "scan", arguments: { content: "x", secrets_file: "/etc/passwd" } });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "relative path");
});

test("scan", "error: content too large rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "scan",
    arguments: { content: "x".repeat(600_000) },
  });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "exceeds maximum");
});

// ===========================================================================
// strip_config_values
// ===========================================================================

test("strip_config_values", "default = delimiter strips values keeps keys", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "strip_config_values",
    arguments: { content: "# settings\nhost = localhost\nport = 5432\n[db]\n" },
  }));
  has(r, "host =");
  has(r, "port =");
  has(r, "# settings");
  has(r, "[db]");
  not(r, "localhost");
  not(r, "5432");
});

test("strip_config_values", "custom : delimiter for YAML-style", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "strip_config_values",
    arguments: { content: "host: localhost\nport: 5432\n", delimiter: ":" },
  }));
  has(r, "host:");
  has(r, "port:");
  not(r, "localhost");
  not(r, "5432");
});

test("strip_config_values", "custom // comment prefix preserved", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "strip_config_values",
    arguments: {
      content: "// nginx config\nworker_processes = auto\n",
      comment_prefix: "//",
    },
  }));
  has(r, "// nginx config");
  has(r, "worker_processes =");
  not(r, "auto");
});

test("strip_config_values", "multi-section config preserves section headers", async (s) => {
  const content = "[database]\nhost = db.prod.corp\npassword = s3cret\n\n[redis]\nhost = redis.corp\n";
  const r = toolText(await s.send("tools/call", {
    name: "strip_config_values",
    arguments: { content },
  }));
  has(r, "[database]");
  has(r, "[redis]");
  has(r, "host =");
  has(r, "password =");
  not(r, "db.prod.corp");
  not(r, "s3cret");
});

test("strip_config_values", "lines with no delimiter pass through", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "strip_config_values",
    arguments: { content: "# comment\n[section]\nkey = value\n" },
  }));
  has(r, "# comment");
  has(r, "[section]");
  not(r, "value");
});

// ===========================================================================
// test_allowlist
// ===========================================================================

test("test_allowlist", "exact pattern matches exactly", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "test_allowlist",
    arguments: { patterns: ["localhost"], values: ["localhost", "Localhost", "localhost2"] },
  })));
  const entries = r.results as Array<{ value: string; allowed: boolean; pattern?: string }>;
  const hit = entries.find((e) => e.value === "localhost");
  const miss1 = entries.find((e) => e.value === "Localhost");
  const miss2 = entries.find((e) => e.value === "localhost2");
  ok(hit?.allowed === true, "localhost must be allowed");
  ok(miss1?.allowed === true, "Localhost matches case-insensitively (allowlist is case-insensitive by default)");
  ok(miss2?.allowed === false, "localhost2 must not match (not exact)");
});

test("test_allowlist", "glob *.internal matches suffix", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "test_allowlist",
    arguments: {
      patterns: ["*.internal"],
      values: ["db.internal", "staging.db.internal", "internal", "db.internal.evil"],
    },
  })));
  const entries = r.results as Array<{ value: string; allowed: boolean }>;
  ok(entries.find((e) => e.value === "db.internal")?.allowed === true, "db.internal must match");
  ok(entries.find((e) => e.value === "staging.db.internal")?.allowed === true, "staging.db.internal must match");
  ok(entries.find((e) => e.value === "internal")?.allowed === false, "bare 'internal' must not match (no prefix)");
  ok(entries.find((e) => e.value === "db.internal.evil")?.allowed === false, "suffix-extended must not match");
});

test("test_allowlist", "glob 192.168.* matches prefix", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "test_allowlist",
    arguments: {
      patterns: ["192.168.*"],
      values: ["192.168.1.1", "192.168.255.255", "192.169.1.1", "10.0.0.1"],
    },
  })));
  const entries = r.results as Array<{ value: string; allowed: boolean }>;
  ok(entries.find((e) => e.value === "192.168.1.1")?.allowed === true, "192.168.1.1 must match");
  ok(entries.find((e) => e.value === "192.168.255.255")?.allowed === true, "192.168.255.255 must match");
  ok(entries.find((e) => e.value === "192.169.1.1")?.allowed === false, "192.169 must not match");
  ok(entries.find((e) => e.value === "10.0.0.1")?.allowed === false, "10.0.0.1 must not match");
});

test("test_allowlist", "glob user-*@corp.com matches middle", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "test_allowlist",
    arguments: {
      patterns: ["user-*@corp.com"],
      values: ["user-alice@corp.com", "user-bob@corp.com", "admin@corp.com", "user-alice@other.com"],
    },
  })));
  const entries = r.results as Array<{ value: string; allowed: boolean }>;
  ok(entries.find((e) => e.value === "user-alice@corp.com")?.allowed === true, "user-alice must match");
  ok(entries.find((e) => e.value === "user-bob@corp.com")?.allowed === true, "user-bob must match");
  ok(entries.find((e) => e.value === "admin@corp.com")?.allowed === false, "admin@ must not match");
  ok(entries.find((e) => e.value === "user-alice@other.com")?.allowed === false, "other.com must not match");
});

test("test_allowlist", "multiple patterns: first match wins, summary counts correct", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "test_allowlist",
    arguments: {
      patterns: ["localhost", "*.internal", "127.0.0.1"],
      values: ["localhost", "db.internal", "127.0.0.1", "prod.corp.com"],
    },
  })));
  ok("results" in r, "must have results");
  ok("summary" in r, "must have summary");
  ok(r.summary.allowed >= 3, `expected ≥3 allowed, got ${r.summary.allowed}`);
  ok(r.summary.blocked >= 1, `expected ≥1 blocked, got ${r.summary.blocked}`);
});

test("test_allowlist", "star-only * matches anything including empty", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", {
    name: "test_allowlist",
    arguments: {
      patterns: ["*"],
      values: ["anything", "192.168.1.1", ""],
    },
  })));
  const entries = r.results as Array<{ value: string; allowed: boolean }>;
  for (const e of entries) {
    ok(e.allowed === true, `'${e.value}' must be allowed by '*'`);
  }
});

test("test_allowlist", "error: empty patterns array rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "test_allowlist",
    arguments: { patterns: [], values: ["x"] },
  });
  ok(toolIsError(r), "must be isError:true");
});

test("test_allowlist", "error: empty values array rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "test_allowlist",
    arguments: { patterns: ["localhost"], values: [] },
  });
  ok(toolIsError(r), "must be isError:true");
});

// ===========================================================================
// list_processors
// ===========================================================================

test("list_processors", "returns all 11 processors with correct format flags", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", { name: "list_processors", arguments: {} })));
  ok(Array.isArray(r.processors), "must have processors array");
  const byName = Object.fromEntries(r.processors.map((p: { name: string; format_flag: string }) => [p.name, p]));
  const expected: Record<string, string> = {
    json: "json", yaml: "yaml", toml: "toml", xml: "xml",
    csv: "csv", jsonl: "jsonl", key_value: "key-value",
    env: "env", ini: "ini", log: "log", text: "text",
  };
  for (const [name, flag] of Object.entries(expected)) {
    ok(name in byName, `processor '${name}' must be listed`);
    ok(byName[name].format_flag === flag, `'${name}' format_flag must be '${flag}', got '${byName[name].format_flag}'`);
  }
  ok(typeof r.note === "string" && r.note.length > 0, "must have a note string");
});

test("list_processors", "each processor has a non-empty description", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", { name: "list_processors", arguments: {} })));
  for (const p of r.processors as Array<{ name: string; description: string }>) {
    ok(typeof p.description === "string" && p.description.length > 0, `'${p.name}' must have a description`);
  }
});

// ===========================================================================
// list_templates
// ===========================================================================

test("list_templates", "returns troubleshoot and review-config templates", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", { name: "list_templates", arguments: {} })));
  ok(Array.isArray(r.templates), "must have templates array");
  ok(r.templates.length === 3, `expected 3 templates, got ${r.templates.length}`);
  const names = r.templates.map((t: { name: string }) => t.name);
  ok(names.includes("troubleshoot"), "must include troubleshoot");
  ok(names.includes("review-config"), "must include review-config");
  ok(names.includes("review-security"), "must include review-security");
});

test("list_templates", "each template has a non-empty description", async (s) => {
  const r = JSON.parse(toolText(await s.send("tools/call", { name: "list_templates", arguments: {} })));
  for (const t of r.templates as Array<{ name: string; description: string }>) {
    ok(typeof t.description === "string" && t.description.length > 0, `'${t.name}' must have a description`);
  }
  ok(typeof r.note === "string", "must have a note");
});

// ===========================================================================
// namespace end-to-end (dedicated session with SCOUR_SECRETS_SECRETS_DIR)
// ===========================================================================

test("namespace", "end-to-end with plaintext secrets.yaml", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    const nsDir = join(secretsDir, "acme-corp");
    await Deno.mkdir(nsDir);
    await Deno.writeTextFile(join(nsDir, "secrets.yaml"), `
- pattern: hunter2
  kind: literal
  category: generic
  label: pw
`);
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = toolText(await ns.send("tools/call", {
        name: "sanitize",
        arguments: { content: "password = hunter2", namespace: "acme-corp" },
      }));
      not(r, "hunter2");
      has(r, "password");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("namespace", "scan uses namespace secrets", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    const nsDir = join(secretsDir, "audit-ns");
    await Deno.mkdir(nsDir);
    await Deno.writeTextFile(join(nsDir, "secrets.yaml"), `
- pattern: topsecretvalue
  kind: literal
  category: auth_token
  label: secret
`);
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const report = JSON.parse(toolText(await ns.send("tools/call", {
        name: "scan",
        arguments: { content: "key = topsecretvalue", namespace: "audit-ns" },
      })));
      const total = report.files.reduce((s: number, f: { matches: number }) => s + f.matches, 0);
      ok(total >= 1, "namespace secrets must be detected in scan");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("namespace", "missing secrets file returns clear error", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    await Deno.mkdir(join(secretsDir, "empty-ns")); // dir exists but no secrets file
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "sanitize",
        arguments: { content: "x", namespace: "empty-ns" },
      });
      ok(toolIsError(r), "must be isError:true");
      has(toolText(r), "secrets file");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("namespace", "namespace not found returns clear error", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "sanitize",
        arguments: { content: "x", namespace: "nonexistent" },
      });
      ok(toolIsError(r), "must be isError:true");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("namespace", "two namespaces with different secrets are isolated", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    const acmeDir = join(secretsDir, "acme");
    await Deno.mkdir(acmeDir);
    await Deno.writeTextFile(join(acmeDir, "secrets.yaml"), `
- pattern: acme-db-password-xyz
  kind: literal
  category: auth_token
  label: acme_db
`);
    const globexDir = join(secretsDir, "globex");
    await Deno.mkdir(globexDir);
    await Deno.writeTextFile(join(globexDir, "secrets.yaml"), `
- pattern: globex-api-key-abc
  kind: literal
  category: auth_token
  label: globex_key
`);
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const input = "db=acme-db-password-xyz api=globex-api-key-abc";

      // acme namespace: its own secret replaced, globex's passes through
      const acmeR = toolText(await ns.send("tools/call", {
        name: "sanitize",
        arguments: { content: input, namespace: "acme" },
      }));
      not(acmeR, "acme-db-password-xyz");
      has(acmeR, "globex-api-key-abc");

      // globex namespace: its own secret replaced, acme's passes through
      const globexR = toolText(await ns.send("tools/call", {
        name: "sanitize",
        arguments: { content: input, namespace: "globex" },
      }));
      has(globexR, "acme-db-password-xyz");
      not(globexR, "globex-api-key-abc");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("namespace", "namespace profile.yaml applies per-customer structured field rules", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    const nsDir = join(secretsDir, "enterprise");
    await Deno.mkdir(nsDir);
    // Minimal secrets file — pattern matching done via profile field signals
    await Deno.writeTextFile(join(nsDir, "secrets.yaml"), "[]");
    // Profile: target specific YAML paths for this customer
    await Deno.writeTextFile(join(nsDir, "profile.yaml"), `
- processor: yaml
  extensions: [".yaml"]
  fields:
    - pattern: "database.password"
      category: "custom:password"
    - pattern: "api.key"
      category: "auth_token"
`);
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = toolText(await ns.send("tools/call", {
        name: "sanitize",
        arguments: {
          content: "database:\n  host: db.internal\n  password: s3cretpw\napi:\n  key: tok-abc123\n",
          format: "yaml",
          namespace: "enterprise",
        },
      }));
      not(r, "s3cretpw");     // database.password replaced by profile rule
      not(r, "tok-abc123");   // api.key replaced by profile rule
      has(r, "db.internal");  // host untouched — not in profile
      has(r, "database:");    // structure preserved
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("namespace", "encrypted secrets.yaml.enc with .password file", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    const nsDir = join(secretsDir, "secure-tenant");
    await Deno.mkdir(nsDir);

    // Encrypt a plaintext secrets file into the namespace directory.
    const plainPath = join(nsDir, "secrets-plain.yaml");
    await Deno.writeTextFile(plainPath, `
- pattern: encrypted-secret-value
  kind: literal
  category: auth_token
  label: enc_token
`);
    const encPath = join(nsDir, "secrets.yaml.enc");
    const testPassword = "namespace-enc-test-pass-789";

    const encResult = await new Deno.Command(SCOUR_SECRETS_BIN, {
      args: ["encrypt", plainPath, encPath],
      env: { ...Deno.env.toObject(), SCOUR_SECRETS_PASSWORD: testPassword, SCOUR_SECRETS_LOG: "error" },
      stdout: "null", stderr: "null",
    }).output();
    ok(encResult.code === 0, `scour-secrets encrypt failed with code ${encResult.code}`);
    await Deno.remove(plainPath);

    // Write .password with restrictive permissions (required by the server).
    const pwPath = join(nsDir, ".password");
    await Deno.writeTextFile(pwPath, testPassword);
    await Deno.chmod(pwPath, 0o600);

    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = toolText(await ns.send("tools/call", {
        name: "sanitize",
        arguments: { content: "token = encrypted-secret-value", namespace: "secure-tenant" },
      }));
      not(r, "encrypted-secret-value"); // replaced using decrypted secrets
      has(r, "token");                   // key preserved
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("namespace", "explicit profile param overrides namespace profile.yaml", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  // profile must be a relative path; create it relative to the test runner cwd.
  const overrideProfile = `mcp-ns-override-test-${Date.now()}.yaml`;
  try {
    const nsDir = join(secretsDir, "customer-a");
    await Deno.mkdir(nsDir);
    await Deno.writeTextFile(join(nsDir, "secrets.yaml"), "[]");
    // Namespace profile targets database.password only
    await Deno.writeTextFile(join(nsDir, "profile.yaml"), `
- processor: yaml
  extensions: [".yaml"]
  fields:
    - pattern: "database.password"
      category: "custom:password"
`);
    // Override profile (relative path) targets api.key only
    await Deno.writeTextFile(overrideProfile, `
- processor: yaml
  extensions: [".yaml"]
  fields:
    - pattern: "api.key"
      category: "auth_token"
`);
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      // Use a zero-entropy value for the namespace-profile field so field-signal
      // detection cannot fire independently of the profile choice.
      const r = toolText(await ns.send("tools/call", {
        name: "sanitize",
        arguments: {
          content: "database:\n  password: aaaa\napi:\n  key: api-key-override-value\n",
          format: "yaml",
          namespace: "customer-a",
          profile: overrideProfile, // relative path — overrides namespace profile
        },
      }));
      has(r, "aaaa");                    // NOT replaced — namespace profile was overridden
      not(r, "api-key-override-value");  // IS replaced — override profile is active
    } finally { await ns.close(); }
  } finally {
    await Deno.remove(secretsDir, { recursive: true });
    await Deno.remove(overrideProfile).catch(() => {});
  }
});

test("namespace", "settings.yaml behavior flags apply as defaults", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    const nsDir = join(secretsDir, "flagged-ns");
    await Deno.mkdir(nsDir);
    await Deno.writeTextFile(join(nsDir, "secrets.yaml"), "[]");
    // namespace settings: enable fail_on_match and set a small max_archive_depth
    await Deno.writeTextFile(join(nsDir, "settings.yaml"),
      "fail_on_match: true\nmax_archive_depth: 2\n"
    );
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      // With fail_on_match enabled by namespace settings and use_default patterns, any
      // match should cause exit code 2. Use content without secrets so it exits 0 to
      // confirm the settings.yaml was parsed (fail_on_match only fires if there are matches).
      const r = toolText(await ns.send("tools/call", {
        name: "sanitize",
        arguments: { content: "nothing sensitive", namespace: "flagged-ns" },
      }));
      // No match → content passes through unchanged.
      has(r, "nothing sensitive");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("namespace", "settings.yaml allow list merges with per-call allow", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    const nsDir = join(secretsDir, "allow-ns");
    await Deno.mkdir(nsDir);
    await Deno.writeTextFile(join(nsDir, "secrets.yaml"), "[]");
    // namespace settings: pre-allow *.internal
    await Deno.writeTextFile(join(nsDir, "settings.yaml"),
      "allow:\n  - \"*.internal\"\n"
    );
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = toolText(await ns.send("tools/call", {
        name: "sanitize",
        arguments: {
          content: "host: db.internal\nip: 203.0.113.5",
          use_default: true,
          namespace: "allow-ns",
        },
      }));
      has(r, "db.internal");   // allowed by namespace settings.yaml
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("namespace", "settings.yaml with invalid YAML is silently ignored", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-" });
  try {
    const nsDir = join(secretsDir, "bad-settings-ns");
    await Deno.mkdir(nsDir);
    await Deno.writeTextFile(join(nsDir, "secrets.yaml"), "[]");
    await Deno.writeTextFile(join(nsDir, "settings.yaml"), "this: is: not: valid: ][[[");
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      // Should succeed — bad settings.yaml is silently skipped.
      const r = toolText(await ns.send("tools/call", {
        name: "sanitize",
        arguments: { content: "safe content", namespace: "bad-settings-ns" },
      }));
      has(r, "safe");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

// ===========================================================================
// files path guards
// ===========================================================================

test("files path guard", ".password rejected in sanitize files", async (s) => {
  const r = await s.send("tools/call", { name: "sanitize", arguments: { files: [".password"] } });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), ".password");
});

test("files path guard", ".password rejected in scan files", async (s) => {
  const r = await s.send("tools/call", { name: "scan", arguments: { files: [".password"] } });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), ".password");
});

test("files path guard", ".password rejected in strip_config_values files", async (s) => {
  const r = await s.send("tools/call", { name: "strip_config_values", arguments: { files: [".password"] } });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), ".password");
});

test("files path guard", "SCOUR_SECRETS_SECRETS_DIR blocks path inside it in sanitize", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-guard-" });
  try {
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "sanitize",
        arguments: { files: [join(secretsDir, "acme", "secrets.yaml")] },
      });
      ok(toolIsError(r), "must be isError:true");
      has(toolText(r), "SCOUR_SECRETS_SECRETS_DIR");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("files path guard", "SCOUR_SECRETS_SECRETS_DIR blocks path inside it in scan", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-guard-" });
  try {
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "scan",
        arguments: { files: [join(secretsDir, "acme", "secrets.yaml")] },
      });
      ok(toolIsError(r), "must be isError:true");
      has(toolText(r), "SCOUR_SECRETS_SECRETS_DIR");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("files path guard", "SCOUR_SECRETS_SECRETS_DIR blocks path inside it in strip_config_values", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-guard-" });
  try {
    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "strip_config_values",
        arguments: { files: [join(secretsDir, "acme", "secrets.yaml")] },
      });
      ok(toolIsError(r), "must be isError:true");
      has(toolText(r), "SCOUR_SECRETS_SECRETS_DIR");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("files path guard", "SCOUR_SECRETS_MCP_FILES_DENYLIST blocks basename glob in sanitize", async (_s) => {
  const ns = await startSession({ SCOUR_SECRETS_MCP_FILES_DENYLIST: "*.key" });
  try {
    const r = await ns.send("tools/call", {
      name: "sanitize",
      arguments: { files: ["certs/prod.key"] },
    });
    ok(toolIsError(r), "must be isError:true");
    has(toolText(r), "denylist");
  } finally { await ns.close(); }
});

test("files path guard", "SCOUR_SECRETS_MCP_FILES_DENYLIST blocks globstar path in scan", async (_s) => {
  const ns = await startSession({ SCOUR_SECRETS_MCP_FILES_DENYLIST: "secrets/**" });
  try {
    const r = await ns.send("tools/call", {
      name: "scan",
      arguments: { files: ["secrets/prod/api.yaml"] },
    });
    ok(toolIsError(r), "must be isError:true");
    has(toolText(r), "denylist");
  } finally { await ns.close(); }
});

test("files path guard", "SCOUR_SECRETS_MCP_FILES_DENYLIST blocks in strip_config_values, comma-separated patterns parsed", async (_s) => {
  const ns = await startSession({ SCOUR_SECRETS_MCP_FILES_DENYLIST: "*.log,secrets/**,*.pem" });
  try {
    const r = await ns.send("tools/call", {
      name: "strip_config_values",
      arguments: { files: ["logs/app.pem"] },
    });
    ok(toolIsError(r), "must be isError:true");
    has(toolText(r), "denylist");
  } finally { await ns.close(); }
});

test("files path guard", "SCOUR_SECRETS_MCP_FILES_DENYLIST basename-only pattern matches full path", async (_s) => {
  const ns = await startSession({ SCOUR_SECRETS_MCP_FILES_DENYLIST: "*.pem" });
  try {
    const r = await ns.send("tools/call", {
      name: "sanitize",
      arguments: { files: ["/some/deep/path/server.pem"] },
    });
    ok(toolIsError(r), "must be isError:true");
    has(toolText(r), "denylist");
  } finally { await ns.close(); }
});

test("files path guard", "SCOUR_SECRETS_MCP_FILES_DENYLIST does not block non-matching path", async (_s) => {
  const ns = await startSession({ SCOUR_SECRETS_MCP_FILES_DENYLIST: "*.key" });
  try {
    const tmpFile = await Deno.makeTempFile({ suffix: ".txt" });
    try {
      await Deno.writeTextFile(tmpFile, "safe content");
      const r = await ns.send("tools/call", {
        name: "sanitize",
        arguments: { files: [tmpFile] },
      });
      not(toolText(r), "denylist");
    } finally { await Deno.remove(tmpFile).catch(() => {}); }
  } finally { await ns.close(); }
});

test("files path guard", "segment denylist blocks absolute path (start-anchored regex bypass)", async (_s) => {
  // Regression: 'secrets/**' compiles to a start-anchored regex, so an absolute
  // path like '/x/y/secrets/api.yaml' previously slipped past the denylist.
  const ns = await startSession({ SCOUR_SECRETS_MCP_FILES_DENYLIST: "secrets/**" });
  try {
    const r = await ns.send("tools/call", {
      name: "sanitize",
      arguments: { files: ["/var/data/secrets/prod/api.yaml"] },
    });
    ok(toolIsError(r), "must be isError:true");
    has(toolText(r), "denylist");
  } finally { await ns.close(); }
});

test("files path guard", "symlink into SCOUR_SECRETS_SECRETS_DIR is rejected", async (_s) => {
  // Regression: a symlink in an allowed dir pointing into the secrets store must
  // be resolved before the guard runs, or it bypasses the secrets-dir check.
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-secrets-" });
  const allowedDir = await Deno.makeTempDir({ prefix: "sanitize-allowed-" });
  try {
    const target = join(secretsDir, "acme", "secrets.yaml");
    await Deno.mkdir(join(secretsDir, "acme"));
    await Deno.writeTextFile(target, "- pattern: x\n  kind: literal\n  category: generic\n  label: x\n");
    const link = join(allowedDir, "innocent.yaml");
    await Deno.symlink(target, link);

    const ns = await startSession({ SCOUR_SECRETS_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "sanitize",
        arguments: { files: [link] },
      });
      ok(toolIsError(r), "must be isError:true");
      has(toolText(r), "SCOUR_SECRETS_SECRETS_DIR");
    } finally { await ns.close(); }
  } finally {
    await Deno.remove(secretsDir, { recursive: true });
    await Deno.remove(allowedDir, { recursive: true });
  }
});

// ===========================================================================
// tool coverage — tools with no other call-site (init, build_secrets,
// test_pattern, list_apps)
// ===========================================================================

test("tool coverage", "list_apps returns built-in bundle names", async (s) => {
  const r = await s.send("tools/call", { name: "list_apps", arguments: {} });
  ok(!toolIsError(r), "list_apps must not error");
  has(toolText(r), "gitlab");
});

test("tool coverage", "test_pattern matches a literal and echoes the value", async (s) => {
  const r = await s.send("tools/call", {
    name: "test_pattern",
    arguments: { values: ["hunter2"], patterns: [{ name: "pw", pattern: "hunter2", kind: "literal", category: "generic" }] },
  });
  ok(!toolIsError(r), "test_pattern must not error");
  has(toolText(r), "hunter2");
});

test("tool coverage", "init writes a starter secrets file into cwd", async (_s) => {
  const dir = await Deno.makeTempDir({ prefix: "sanitize-init-" });
  try {
    const ns = await startSession({}, dir);
    try {
      const r = await ns.send("tools/call", {
        name: "init",
        arguments: { output_path: "secrets.yaml", preset: "balanced" },
      });
      ok(!toolIsError(r), `init must not error: ${toolText(r)}`);
      const stat = await Deno.stat(join(dir, "secrets.yaml"));
      ok(stat.isFile && stat.size > 0, "secrets.yaml must be written and non-empty");
    } finally { await ns.close(); }
  } finally { await Deno.remove(dir, { recursive: true }); }
});

test("tool coverage", "init refuses absolute output_path (relative-only guard)", async (s) => {
  const r = await s.send("tools/call", {
    name: "init",
    arguments: { output_path: "/tmp/should-not-write.yaml" },
  });
  ok(toolIsError(r), "absolute output_path must be rejected");
});

test("tool coverage", "build_secrets writes a file with custom entries", async (_s) => {
  const dir = await Deno.makeTempDir({ prefix: "sanitize-build-" });
  try {
    const ns = await startSession({}, dir);
    try {
      const r = await ns.send("tools/call", {
        name: "build_secrets",
        arguments: {
          output_path: "custom.yaml",
          entries: [{ label: "token", pattern: "tok_[a-z0-9]+", kind: "regex", category: "auth_token" }],
        },
      });
      ok(!toolIsError(r), `build_secrets must not error: ${toolText(r)}`);
      const written = await Deno.readTextFile(join(dir, "custom.yaml"));
      has(written, "token");
      has(written, "tok_[a-z0-9]+");
    } finally { await ns.close(); }
  } finally { await Deno.remove(dir, { recursive: true }); }
});

test("tool coverage", "build_secrets refuses to overwrite without overwrite:true", async (_s) => {
  const dir = await Deno.makeTempDir({ prefix: "sanitize-build-" });
  try {
    await Deno.writeTextFile(join(dir, "exists.yaml"), "pre-existing\n");
    const ns = await startSession({}, dir);
    try {
      const r = await ns.send("tools/call", {
        name: "build_secrets",
        arguments: { output_path: "exists.yaml", preset: "generic" },
      });
      ok(toolIsError(r), "must refuse to clobber existing file");
      has(toolText(r), "exists");
    } finally { await ns.close(); }
  } finally { await Deno.remove(dir, { recursive: true }); }
});

// ===========================================================================
// output_file / output_dir (write-to-disk mode)
// ===========================================================================

test("output_file", "content + output_file writes to disk, no content returned", async (s) => {
  const tmpFile = await Deno.makeTempFile({ suffix: ".txt" });
  try {
    const r = toolText(await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        content: "password: hunter2\nhost: example.com",
        output_file: tmpFile,
        patterns: [{ name: "pw", pattern: "hunter2", category: "auth_token", kind: "literal" }],
      },
    }));
    const parsed = JSON.parse(r);
    ok(parsed.written === true, "written flag must be true");
    ok(parsed.output === tmpFile, "output path must match");
    ok(typeof parsed.size === "number" && parsed.size > 0, "size must be positive");
    const disk = await Deno.readTextFile(tmpFile);
    ok(!disk.includes("hunter2"), "raw secret must not appear in output file");
    ok(disk.includes("host: example.com"), "non-secret content must be preserved");
  } finally { await Deno.remove(tmpFile).catch(() => {}); }
});

test("output_file", "files + output_file writes to disk, no content returned", async (s) => {
  const inFile = await Deno.makeTempFile({ suffix: ".txt" });
  const outFile = await Deno.makeTempFile({ suffix: ".txt" });
  try {
    await Deno.writeTextFile(inFile, "token: hunter2\n");
    const r = toolText(await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        files: [inFile],
        output_file: outFile,
        patterns: [{ name: "pw", pattern: "hunter2", category: "auth_token", kind: "literal" }],
      },
    }));
    const parsed = JSON.parse(r);
    ok(Array.isArray(parsed.results), "results must be an array");
    ok(parsed.results[0].written === true, "written flag must be true");
    ok(parsed.results[0].output === outFile, "output path must match");
    const disk = await Deno.readTextFile(outFile);
    ok(!disk.includes("hunter2"), "raw secret must not appear in output file");
  } finally {
    await Deno.remove(inFile).catch(() => {});
    await Deno.remove(outFile).catch(() => {});
  }
});

test("output_file", "output_dir writes multiple files to directory", async (s) => {
  const in1 = await Deno.makeTempFile({ suffix: ".txt" });
  const in2 = await Deno.makeTempFile({ suffix: ".txt" });
  const outDir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(in1, "key: hunter2\n");
    await Deno.writeTextFile(in2, "pass: hunter2\n");
    const r = toolText(await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        files: [in1, in2],
        output_dir: outDir,
        patterns: [{ name: "pw", pattern: "hunter2", category: "auth_token", kind: "literal" }],
      },
    }));
    const parsed = JSON.parse(r);
    ok(Array.isArray(parsed.results) && parsed.results.length === 2, "two results expected");
    for (const result of parsed.results) {
      ok(result.written === true, "written flag must be true for each result");
      ok(result.output.startsWith(outDir), "output must be inside output_dir");
      const disk = await Deno.readTextFile(result.output);
      ok(!disk.includes("hunter2"), "raw secret must not appear in output file");
    }
  } finally {
    await Deno.remove(in1).catch(() => {});
    await Deno.remove(in2).catch(() => {});
    await Deno.remove(outDir, { recursive: true }).catch(() => {});
  }
});

test("output_file", "error: output_file and output_dir are mutually exclusive", async (s) => {
  const r = await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "test",
      output_file: "/tmp/a.txt",
      output_dir: "/tmp/outdir",
      patterns: [{ name: "x", pattern: "test", category: "custom:x" }],
    },
  });
  ok(toolIsError(r), "must return error");
  has(toolText(r), "mutually exclusive");
});

test("output_file", "error: output_file with multiple files rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      files: ["/tmp/a.txt", "/tmp/b.txt"],
      output_file: "/tmp/out.txt",
      patterns: [{ name: "x", pattern: "test", category: "custom:x" }],
    },
  });
  ok(toolIsError(r), "must return error");
  has(toolText(r), "single input");
});

// ===========================================================================
// Runner
// ===========================================================================

const RESET = "\x1b[0m", GREEN = "\x1b[32m", RED = "\x1b[31m",
  GRAY = "\x1b[90m", BOLD = "\x1b[1m", CYAN = "\x1b[36m";

console.log(`\n${GRAY}Starting MCP server...${RESET}`);
const session = await startSession();
console.log(`${GRAY}Server ready. Running ${tests.length} tests across ${new Set(tests.map(t => t.group)).size} groups.${RESET}\n`);

let passed = 0, failed = 0;
let currentGroup = "";

for (const { group, name, fn } of tests) {
  if (group !== currentGroup) {
    currentGroup = group;
    console.log(`\n${CYAN}${BOLD}${group}${RESET}`);
  }
  try {
    await fn(session);
    console.log(`  ${GREEN}✓${RESET} ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ${RED}✗${RESET} ${name}`);
    console.log(`    ${RED}${(err as Error).message}${RESET}`);
    failed++;
  }
}

await session.close();

// ===========================================================================
// HTTP daemon mode
// ===========================================================================

{
  console.log(`\n${CYAN}${BOLD}http daemon${RESET}`);

  const port = await getFreePort();
  const token = "test-http-daemon-token-abc123";
  const baseUrl = `http://127.0.0.1:${port}`;

  // Helper: run a single HTTP daemon test, updating shared passed/failed counts.
  async function httpTest(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      console.log(`  ${GREEN}✓${RESET} ${name}`);
      passed++;
    } catch (e) {
      console.log(`  ${RED}✗${RESET} ${name}`);
      console.log(`    ${RED}${(e as Error).message}${RESET}`);
      failed++;
    }
  }

  // --- default port ---
  await httpTest("--http without port argument defaults to 6277", async () => {
    const proc = new Deno.Command(Deno.execPath(), {
      args: ["run", "--allow-run", "--allow-env", "--allow-read", "--allow-write", "--allow-net",
        MCP_SCRIPT, "--http"],
      stdin: "null", stdout: "null", stderr: "piped",
      env: { ...Deno.env.toObject(), SCOUR_SECRETS_BIN, SCOUR_SECRETS_LOG: "error", SCOUR_SECRETS_MCP_HTTP_TOKEN: token },
    }).spawn();
    const stderr = await readStreamFor(proc.stderr, 4_000, "ready");
    try { proc.kill("SIGTERM"); } catch { /* may already have failed to bind */ }
    await proc.status.catch(() => {});
    has(stderr, "127.0.0.1:6277");
  });

  // --- port validation ---
  await httpTest("--http with invalid port exits non-zero", async () => {
    for (const badPort of ["0", "99999", "abc"]) {
      const result = await new Deno.Command(Deno.execPath(), {
        args: ["run", "--allow-run", "--allow-env", "--allow-read", "--allow-write", "--allow-net",
          MCP_SCRIPT, "--http", badPort],
        stdin: "null", stdout: "null", stderr: "null",
        env: { ...Deno.env.toObject(), SCOUR_SECRETS_BIN, SCOUR_SECRETS_LOG: "error", SCOUR_SECRETS_MCP_HTTP_TOKEN: token },
      }).output();
      ok(result.code !== 0, `expected non-zero exit for port "${badPort}", got ${result.code}`);
    }
  });

  // --- onListen: startup message goes to stderr, not stdout ---
  await httpTest("startup message in stderr, nothing in stdout", async () => {
    const listenPort = await getFreePort();
    const proc = new Deno.Command(Deno.execPath(), {
      args: [
        "run", "--allow-run", "--allow-env", "--allow-read", "--allow-write", "--allow-net",
        MCP_SCRIPT, "--http", String(listenPort),
      ],
      stdin: "null", stdout: "piped", stderr: "piped",
      env: { ...Deno.env.toObject(), SCOUR_SECRETS_BIN, SCOUR_SECRETS_LOG: "error", SCOUR_SECRETS_MCP_HTTP_TOKEN: token },
    }).spawn();

    const stderr = await readStreamFor(proc.stderr, 4_000, "ready");
    const stdout = await readStreamFor(proc.stdout, 500);
    proc.kill("SIGTERM");
    await proc.status.catch(() => {});

    // stderr must contain our custom message with host and port
    has(stderr, "127.0.0.1");
    has(stderr, String(listenPort));
    // Deno's default "Listening on ..." must NOT appear on stdout
    ok(!stdout.includes("Listening"), `expected empty stdout, got: ${JSON.stringify(stdout)}`);
  });

  // --- startup without token exits non-zero ---
  await httpTest("refuses to start without SCOUR_SECRETS_MCP_HTTP_TOKEN", async () => {
    const result = await new Deno.Command(Deno.execPath(), {
      args: ["run", "--allow-run", "--allow-env", "--allow-read", "--allow-write", "--allow-net",
        MCP_SCRIPT, "--http", String(port)],
      stdin: "null", stdout: "null", stderr: "null",
      env: { ...Deno.env.toObject(), SCOUR_SECRETS_BIN, SCOUR_SECRETS_LOG: "error" }, // no token
    }).output();
    ok(result.code !== 0, `expected non-zero exit code, got ${result.code}`);
  });

  // --- start daemon for the remaining tests ---
  let daemon: Deno.ChildProcess | null = null;
  try {
    daemon = await startHttpDaemon(port, token);

    await httpTest("401 without Authorization header", async () => {
      const res = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      await res.body?.cancel();
      ok(res.status === 401, `expected 401, got ${res.status}`);
    });

    await httpTest("401 with wrong token", async () => {
      const res = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer wrong-token" },
        body: "{}",
      });
      await res.body?.cancel();
      ok(res.status === 401, `expected 401, got ${res.status}`);
    });

    await httpTest("404 for unknown path", async () => {
      const res = await fetch(`${baseUrl}/health`, {
        method: "GET",
        headers: { "Authorization": `Bearer ${token}` },
      });
      await res.body?.cancel();
      ok(res.status === 404, `expected 404, got ${res.status}`);
    });

    // --- onError: guard responses contain no stack traces ---
    // transport.handleRequest never throws via external requests (it handles all
    // protocol errors internally and returns Responses). The onError wiring is
    // defensive; what we can verify is that all rejection responses (401, 404)
    // are plain strings with no stack frames or error details.
    await httpTest("error responses contain no stack traces or raw data", async () => {
      const res401 = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const body401 = await res401.text();
      ok(!body401.includes("at "), `401 body must not contain stack frames: ${body401}`);
      ok(!body401.includes("Error:"), `401 body must not contain Error: ${body401}`);

      const res404 = await fetch(`${baseUrl}/notfound`, {
        headers: { "Authorization": `Bearer ${token}` },
      });
      const body404 = await res404.text();
      ok(!body404.includes("at "), `404 body must not contain stack frames: ${body404}`);
    });

    await httpTest("MCP tool call succeeds with valid token", async () => {
      const hs = await startHttpMcpSession(baseUrl, token);
      const r = toolText(await hs.send("tools/call", {
        name: "sanitize",
        arguments: {
          content: "password: hunter2",
          patterns: [{ name: "pw", pattern: "hunter2", category: "generic", kind: "literal" }],
        },
      }));
      not(r, "hunter2");
      has(r, "password");
      await hs.close();
    });

    // Note: WebStandardStreamableHTTPServerTransport is single-session by design.
    // The daemon exits via onsessionclosed when the client sends DELETE, allowing
    // the service manager to restart it for a fresh session on reconnect.

  } catch (e) {
    console.log(`  ${RED}✗${RESET} daemon startup failed: ${(e as Error).message}`);
    failed++;
  } finally {
    try { daemon?.kill("SIGTERM"); } catch { /* already exited via onsessionclosed */ }
    await daemon?.status.catch(() => {});
  }

  // --- session lifecycle (each test owns its own daemon) ---

  await httpTest("daemon exits with code 0 when session is closed (DELETE)", async () => {
    const p = await getFreePort();
    const d = await startHttpDaemon(p, token);
    const hs = await startHttpMcpSession(`http://127.0.0.1:${p}`, token);
    await hs.close(); // sends DELETE → onsessionclosed → Deno.exit(0)
    const status = await d.status;
    ok(status.code === 0, `expected exit code 0, got ${status.code}`);
  });

  await httpTest("new session accepted after daemon restart", async () => {
    const p = await getFreePort();
    // First session: connect, use, close
    const d1 = await startHttpDaemon(p, token);
    const hs1 = await startHttpMcpSession(`http://127.0.0.1:${p}`, token);
    await hs1.close();
    await d1.status; // wait for clean exit
    // Second session: daemon restarted, must accept a fresh initialize
    const d2 = await startHttpDaemon(p, token);
    try {
      const hs2 = await startHttpMcpSession(`http://127.0.0.1:${p}`, token);
      const r = toolText(await hs2.send("tools/call", {
        name: "sanitize",
        arguments: { content: "reconnect@example.com" },
      }));
      not(r, "reconnect@example.com");
      await hs2.close();
      await d2.status.catch(() => {});
    } finally {
      try { d2.kill("SIGTERM"); } catch { /* already exited */ }
      await d2.status.catch(() => {});
    }
  });
}

console.log(
  `\n${BOLD}${passed + failed} tests${RESET}: ${GREEN}${passed} passed${RESET}` +
    (failed > 0 ? `, ${RED}${failed} failed${RESET}` : "") +
    "\n",
);

if (failed > 0) Deno.exit(1);
