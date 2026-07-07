#!/usr/bin/env -S deno run --allow-run --allow-env --allow-read --allow-write
/**
 * Manual MCP probe — fire a single tool call at the scour-secrets-engine server and
 * print the result. A reusable stand-in for an AI agent, for poking the server
 * by hand (e.g. checking that path guards block a bypass, or that a legitimate
 * file still sanitizes) without writing a one-off driver each time.
 *
 * Usage:
 *   deno run -A mcp/probe.ts <tool> '<json-args>' [options]
 *
 * Options:
 *   --env KEY=VALUE     set a server env var (repeatable), e.g.
 *                       --env SCOUR_SECRETS_MCP_FILES_DENYLIST=secrets/**
 *   --bin <path>        path to the `scour-secrets` binary
 *                       (default: $SCOUR_SECRETS_BIN or ../target/release/scour-secrets)
 *   --server <path>     server entrypoint or compiled binary
 *                       (default: ./src/index.ts)
 *   --compiled          execute --server directly as a compiled binary
 *   --raw               print the raw JSON-RPC result instead of a summary
 *
 * Examples:
 *   deno run -A mcp/probe.ts sanitize '{"content":"key=AKIA1234567890ABCD12"}'
 *   deno run -A mcp/probe.ts sanitize '{"files":["/etc/app/secrets.yaml"]}' \
 *     --env SCOUR_SECRETS_MCP_FILES_DENYLIST=secrets/**
 *   deno run -A mcp/probe.ts scan '{"files":["app.log"]}' --raw
 */

import { join } from "@std/path";
import { startStdioSession } from "./mcp_client.ts";

function parseArgs(argv: string[]) {
  const positional: string[] = [];
  const env: Record<string, string> = {};
  let bin: string | undefined;
  let server: string | undefined;
  let compiled = false;
  let raw = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--env") {
      const kv = argv[++i] ?? "";
      const eq = kv.indexOf("=");
      if (eq === -1) throw new Error(`--env expects KEY=VALUE, got "${kv}"`);
      env[kv.slice(0, eq)] = kv.slice(eq + 1);
    } else if (a === "--bin") {
      bin = argv[++i];
    } else if (a === "--server") {
      server = argv[++i];
    } else if (a === "--compiled") {
      compiled = true;
    } else if (a === "--raw") {
      raw = true;
    } else if (a === "-h" || a === "--help") {
      printUsageAndExit(0);
    } else if (a.startsWith("--")) {
      throw new Error(`unknown option: ${a}`);
    } else {
      positional.push(a);
    }
  }
  return { positional, env, bin, server, compiled, raw };
}

function printUsageAndExit(code: number): never {
  const usage = [
    "Usage: deno run -A mcp/probe.ts <tool> '<json-args>' [options]",
    "",
    "Options:",
    "  --env KEY=VALUE   set a server env var (repeatable)",
    "  --bin <path>      path to the scour-secrets binary",
    "  --server <path>   server entrypoint or compiled binary (default: src/index.ts)",
    "  --compiled        execute --server directly as a compiled binary",
    "  --raw             print raw JSON-RPC result instead of a summary",
    "",
    "Example:",
    "  deno run -A mcp/probe.ts sanitize '{\"content\":\"key=AKIA1234567890ABCD12\"}'",
  ].join("\n");
  console.error(usage);
  Deno.exit(code);
}

async function main() {
  const { positional, env, bin, server, compiled, raw } = parseArgs(Deno.args);
  if (positional.length < 1) printUsageAndExit(1);

  const tool = positional[0];
  let args: unknown = {};
  if (positional[1] !== undefined) {
    try {
      args = JSON.parse(positional[1]);
    } catch (e) {
      console.error(`Invalid JSON for arguments: ${(e as Error).message}`);
      Deno.exit(1);
    }
  }

  const sanitizeBin = bin ??
    Deno.env.get("SCOUR_SECRETS_BIN") ??
    join(import.meta.dirname!, "../target/release/scour-secrets");
  const serverPath = server ?? join(import.meta.dirname!, "src/index.ts");

  const session = await startStdioSession({ serverPath, sanitizeBin, env, compiled });
  try {
    const result = await session.send("tools/call", { name: tool, arguments: args }) as {
      isError?: boolean;
      content?: Array<{ type: string; text: string }>;
    };

    if (raw) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    const text = (result.content ?? []).map((c) => c.text).join("");
    const status = result.isError ? "ERROR" : "OK";
    console.log(`[${status}] ${tool}`);
    console.log(text);
    if (result.isError) Deno.exitCode = 1;
  } finally {
    await session.close();
  }
}

if (import.meta.main) {
  await main();
}
