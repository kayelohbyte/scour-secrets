#!/usr/bin/env -S deno run --allow-run --allow-env --allow-read --allow-write
/**
 * Comprehensive direct MCP feature tests.
 *
 * Covers every tool, every parameter path, and every documented error case.
 * Runs standalone — no separate test framework needed.
 *
 *   SANITIZE_BIN=./target/release/sanitize deno run \
 *     --allow-run --allow-env --allow-read --allow-write \
 *     mcp/test-direct.ts
 */

import { join } from "@std/path";

const MCP_SCRIPT = join(import.meta.dirname!, "src/index.ts");
const SANITIZE_BIN =
  Deno.env.get("SANITIZE_BIN") ??
  join(import.meta.dirname!, "../target/release/sanitize");

// ---------------------------------------------------------------------------
// JSON-RPC session
// ---------------------------------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();
let idCounter = 1;

function nextId() { return idCounter++; }
function ser(msg: unknown): Uint8Array { return enc.encode(JSON.stringify(msg) + "\n"); }

class McpSession {
  private child: Deno.ChildProcess;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private reader: ReadableStreamDefaultReader<string>;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: unknown) => void }>();
  private closed = false;

  constructor(child: Deno.ChildProcess) {
    this.child = child;
    this.writer = child.stdin.getWriter();
    const lineStream = child.stdout
      .pipeThrough(new TextDecoderStream())
      .pipeThrough(new TransformStream<string, string>({
        transform(chunk, ctrl) {
          for (const l of chunk.split("\n")) if (l.trim()) ctrl.enqueue(l.trim());
        },
      }));
    this.reader = lineStream.getReader();
    this.startReadLoop();
  }

  private async startReadLoop() {
    while (!this.closed) {
      let r: ReadableStreamReadResult<string>;
      try { r = await this.reader.read(); } catch { break; }
      if (r.done) break;
      try {
        const msg = JSON.parse(r.value) as { id?: number; result?: unknown; error?: unknown };
        if (msg.id !== undefined) {
          const p = this.pending.get(msg.id);
          if (p) {
            this.pending.delete(msg.id);
            if (msg.error) p.reject(msg.error); else p.resolve(msg.result);
          }
        }
      } catch { /* skip */ }
    }
  }

  async send(method: string, params?: unknown): Promise<unknown> {
    const id = nextId();
    const promise = new Promise((resolve, reject) => { this.pending.set(id, { resolve, reject }); });
    await this.writer.write(ser({ jsonrpc: "2.0", id, method, params }));
    return promise;
  }

  async notify(method: string, params?: unknown) {
    await this.writer.write(ser({ jsonrpc: "2.0", method, params }));
  }

  async close() {
    this.closed = true;
    try { await this.writer.close(); } catch { /* */ }
    try { this.child.kill("SIGTERM"); } catch { /* */ }
    await this.child.status;
  }
}

async function startSession(extraEnv: Record<string, string> = {}): Promise<McpSession> {
  const cmd = new Deno.Command(Deno.execPath(), {
    args: ["run", "--allow-run", "--allow-env", "--allow-read", "--allow-write", MCP_SCRIPT],
    stdin: "piped", stdout: "piped", stderr: "null",
    env: { ...Deno.env.toObject(), SANITIZE_BIN, SANITIZE_LOG: "error", ...extraEnv },
  });
  const child = cmd.spawn();
  const s = new McpSession(child);
  await s.send("initialize", {
    protocolVersion: "2024-11-05", capabilities: {},
    clientInfo: { name: "direct-test", version: "1.0" },
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
// sanitize tool
// ===========================================================================

test("sanitize", "replaces email with realistic substitute", async (s) => {
  const r = toolText(await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "Contact alice@example.com for help.",
      patterns: [{ name: "email", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", category: "email" }],
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
      patterns: [{ name: "ip", pattern: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", category: "ipv4" }],
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
        { name: "host", pattern: "\\b[a-z0-9.-]+\\.[a-z]{2,}\\b", category: "hostname" },
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
        { name: "email", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", category: "email" },
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
      patterns: [{ name: "email", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", category: "email" }],
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

test("sanitize", "error: use_default combined with secrets_file rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "x", use_default: true, secrets_file: "relative/path.yaml" },
  });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "use_default");
});

test("sanitize", "error: use_default combined with patterns rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "sanitize",
    arguments: {
      content: "x",
      use_default: true,
      patterns: [{ name: "p", pattern: "x", category: "generic" }],
    },
  });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "use_default");
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

test("sanitize", "error: namespace without SANITIZE_SECRETS_DIR env rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "x", namespace: "acme" },
  });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "SANITIZE_SECRETS_DIR");
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
        { name: "email", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", category: "email" },
        { name: "ip", pattern: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", category: "ipv4" },
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

test("scan", "error: use_default combined with secrets_file rejected", async (s) => {
  const r = await s.send("tools/call", {
    name: "scan",
    arguments: { content: "x", use_default: true, secrets_file: "relative/path.yaml" },
  });
  ok(toolIsError(r), "must be isError:true");
  has(toolText(r), "use_default");
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
// namespace end-to-end (dedicated session with SANITIZE_SECRETS_DIR)
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
    const ns = await startSession({ SANITIZE_SECRETS_DIR: secretsDir });
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
    const ns = await startSession({ SANITIZE_SECRETS_DIR: secretsDir });
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
    const ns = await startSession({ SANITIZE_SECRETS_DIR: secretsDir });
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
    const ns = await startSession({ SANITIZE_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "sanitize",
        arguments: { content: "x", namespace: "nonexistent" },
      });
      ok(toolIsError(r), "must be isError:true");
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

test("files path guard", "SANITIZE_SECRETS_DIR blocks path inside it in sanitize", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-guard-" });
  try {
    const ns = await startSession({ SANITIZE_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "sanitize",
        arguments: { files: [join(secretsDir, "acme", "secrets.yaml")] },
      });
      ok(toolIsError(r), "must be isError:true");
      has(toolText(r), "SANITIZE_SECRETS_DIR");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("files path guard", "SANITIZE_SECRETS_DIR blocks path inside it in scan", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-guard-" });
  try {
    const ns = await startSession({ SANITIZE_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "scan",
        arguments: { files: [join(secretsDir, "acme", "secrets.yaml")] },
      });
      ok(toolIsError(r), "must be isError:true");
      has(toolText(r), "SANITIZE_SECRETS_DIR");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("files path guard", "SANITIZE_SECRETS_DIR blocks path inside it in strip_config_values", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-guard-" });
  try {
    const ns = await startSession({ SANITIZE_SECRETS_DIR: secretsDir });
    try {
      const r = await ns.send("tools/call", {
        name: "strip_config_values",
        arguments: { files: [join(secretsDir, "acme", "secrets.yaml")] },
      });
      ok(toolIsError(r), "must be isError:true");
      has(toolText(r), "SANITIZE_SECRETS_DIR");
    } finally { await ns.close(); }
  } finally { await Deno.remove(secretsDir, { recursive: true }); }
});

test("files path guard", "SANITIZE_MCP_FILES_DENYLIST blocks basename glob in sanitize", async (_s) => {
  const ns = await startSession({ SANITIZE_MCP_FILES_DENYLIST: "*.key" });
  try {
    const r = await ns.send("tools/call", {
      name: "sanitize",
      arguments: { files: ["certs/prod.key"] },
    });
    ok(toolIsError(r), "must be isError:true");
    has(toolText(r), "denylist");
  } finally { await ns.close(); }
});

test("files path guard", "SANITIZE_MCP_FILES_DENYLIST blocks globstar path in scan", async (_s) => {
  const ns = await startSession({ SANITIZE_MCP_FILES_DENYLIST: "secrets/**" });
  try {
    const r = await ns.send("tools/call", {
      name: "scan",
      arguments: { files: ["secrets/prod/api.yaml"] },
    });
    ok(toolIsError(r), "must be isError:true");
    has(toolText(r), "denylist");
  } finally { await ns.close(); }
});

test("files path guard", "SANITIZE_MCP_FILES_DENYLIST blocks in strip_config_values, comma-separated patterns parsed", async (_s) => {
  const ns = await startSession({ SANITIZE_MCP_FILES_DENYLIST: "*.log,secrets/**,*.pem" });
  try {
    const r = await ns.send("tools/call", {
      name: "strip_config_values",
      arguments: { files: ["logs/app.pem"] },
    });
    ok(toolIsError(r), "must be isError:true");
    has(toolText(r), "denylist");
  } finally { await ns.close(); }
});

test("files path guard", "SANITIZE_MCP_FILES_DENYLIST basename-only pattern matches full path", async (_s) => {
  const ns = await startSession({ SANITIZE_MCP_FILES_DENYLIST: "*.pem" });
  try {
    const r = await ns.send("tools/call", {
      name: "sanitize",
      arguments: { files: ["/some/deep/path/server.pem"] },
    });
    ok(toolIsError(r), "must be isError:true");
    has(toolText(r), "denylist");
  } finally { await ns.close(); }
});

test("files path guard", "SANITIZE_MCP_FILES_DENYLIST does not block non-matching path", async (_s) => {
  const ns = await startSession({ SANITIZE_MCP_FILES_DENYLIST: "*.key" });
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

console.log(
  `\n${BOLD}${passed + failed} tests${RESET}: ${GREEN}${passed} passed${RESET}` +
    (failed > 0 ? `, ${RED}${failed} failed${RESET}` : "") +
    "\n",
);

if (failed > 0) Deno.exit(1);
