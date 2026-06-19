/**
 * Minimal MCP stdio client.
 *
 * Spawns the sanitize-engine MCP server as a subprocess, performs the JSON-RPC
 * handshake (initialize → notifications/initialized), and exposes send/notify.
 * Shared by the automated suite (test-direct.ts) and the manual probe CLI
 * (probe.ts) so there is a single source of truth for the protocol framing.
 */

const enc = new TextEncoder();
let idCounter = 1;

function nextId(): number {
  return idCounter++;
}

function ser(msg: unknown): Uint8Array {
  return enc.encode(JSON.stringify(msg) + "\n");
}

export class McpSession {
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

export interface StdioOptions {
  /** Path to the MCP server entrypoint (src/index.ts) or a compiled binary. */
  serverPath: string;
  /** Path to the `sanitize` binary the server shells out to. */
  sanitizeBin: string;
  /** Extra environment variables for the server process. */
  env?: Record<string, string>;
  /** Working directory for the server process (relative output paths resolve here). */
  cwd?: string;
  /**
   * When true, serverPath is executed directly (a compiled binary). When false
   * (default) it is run via `deno run` with the standard permission set.
   */
  compiled?: boolean;
}

/** Spawn the server over stdio and complete the MCP handshake. */
export async function startStdioSession(opts: StdioOptions): Promise<McpSession> {
  const command = opts.compiled ? opts.serverPath : Deno.execPath();
  const args = opts.compiled
    ? []
    : ["run", "--allow-run", "--allow-env", "--allow-read", "--allow-write", opts.serverPath];
  const child = new Deno.Command(command, {
    args,
    cwd: opts.cwd,
    stdin: "piped",
    stdout: "piped",
    stderr: "null",
    env: {
      ...Deno.env.toObject(),
      SANITIZE_BIN: opts.sanitizeBin,
      SANITIZE_LOG: "error",
      ...(opts.env ?? {}),
    },
  }).spawn();

  const session = new McpSession(child);
  await session.send("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "mcp-client", version: "1.0" },
  });
  await session.notify("notifications/initialized");
  return session;
}
