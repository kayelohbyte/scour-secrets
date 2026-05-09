#!/usr/bin/env -S deno run --allow-run --allow-env --allow-read --allow-write
/**
 * MCP server for sanitize-engine.
 *
 * Wraps the `sanitize` CLI binary as a subprocess so all sensitive data
 * processing stays inside the audited Rust implementation. TypeScript is
 * responsible only for MCP protocol framing.
 *
 * Environment variables:
 *   SANITIZE_BIN                    path to the `sanitize` binary (default: "sanitize")
 *   SANITIZE_MCP_MAX_CONTENT_BYTES  per-call content size limit in bytes (default: 524288)
 *   SANITIZE_SECRETS_DIR            base directory for namespace resolution (required for `namespace` param)
 *
 * Namespace directory layout:
 *   $SANITIZE_SECRETS_DIR/
 *     {namespace}/
 *       secrets.yaml        (or .json / .toml / .yaml.enc / .json.enc / .toml.enc)
 *       profile.yaml        (optional; loaded automatically)
 *       .password           (required when secrets file is encrypted; must be mode 0600 or 0400)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio";
import { join } from "@std/path";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const SANITIZE_BIN = Deno.env.get("SANITIZE_BIN") ?? "sanitize";
const MAX_CONTENT_BYTES = parseInt(
  Deno.env.get("SANITIZE_MCP_MAX_CONTENT_BYTES") ?? "524288",
  10,
);
const SANITIZE_SECRETS_DIR = Deno.env.get("SANITIZE_SECRETS_DIR");
const SERVER_VERSION = "1.0.0";

// ---------------------------------------------------------------------------
// Subprocess helpers
// ---------------------------------------------------------------------------

interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Spawn the sanitize binary, write `stdinData` to its stdin, and collect
 * stdout/stderr. The subprocess never receives sensitive content via argv —
 * only via the stdin pipe or a mode-0600 temp file.
 */
async function runSanitize(
  args: string[],
  stdinData: string,
  extraEnv: Record<string, string> = {},
): Promise<RunResult> {
  const cmd = new Deno.Command(SANITIZE_BIN, {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
    env: { ...Deno.env.toObject(), SANITIZE_LOG: "error", ...extraEnv },
  });

  const child = cmd.spawn();

  const writer = child.stdin.getWriter();
  await writer.write(encoder.encode(stdinData));
  await writer.close();

  const { stdout, stderr, code } = await child.output();

  return {
    stdout: decoder.decode(stdout),
    stderr: decoder.decode(stderr),
    exitCode: code,
  };
}

/** Write `data` to a temp file with mode 0o600 inside `dir`. */
async function writeTempFile(
  dir: string,
  name: string,
  data: string,
): Promise<string> {
  const p = join(dir, name);
  const file = await Deno.open(p, {
    write: true,
    create: true,
    truncate: true,
    mode: 0o600,
  });
  await file.write(encoder.encode(data));
  file.close();
  return p;
}

/**
 * Reject paths that could traverse outside the intended directory.
 * Blocks absolute paths and any ".." segment.
 *
 * Relative paths (including those starting with "./") are permitted because
 * the MCP server runs with the invoking user's own filesystem permissions —
 * there is no privilege boundary to cross. The Rust CLI enforces its own
 * file-existence and format checks on whatever path is passed.
 */
function validateUserPath(p: string, paramName: string): void {
  if (p.startsWith("/") || p.startsWith("\\")) {
    throw new Error(`${paramName} must be a relative path, not an absolute path`);
  }
  const segments = p.replace(/\\/g, "/").split("/");
  if (segments.some((s) => s === "..")) {
    throw new Error(`${paramName} must not contain '..' path traversal segments`);
  }
}

/** Enforce per-call content size limit. */
function checkContentSize(content: string, label = "content"): void {
  const bytes = encoder.encode(content).length;
  if (bytes > MAX_CONTENT_BYTES) {
    throw new Error(
      `${label} exceeds maximum allowed size (${bytes} > ${MAX_CONTENT_BYTES} bytes). ` +
        `Increase SANITIZE_MCP_MAX_CONTENT_BYTES to allow larger inputs.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Namespace resolution
// ---------------------------------------------------------------------------

const NAMESPACE_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;

interface ResolvedNamespace {
  secretsFile: string;
  profileFile?: string;
  encrypted: boolean;
  password?: string;
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await Deno.stat(p);
    return true;
  } catch {
    return false;
  }
}

async function resolveNamespace(namespace: string): Promise<ResolvedNamespace> {
  if (!NAMESPACE_RE.test(namespace)) {
    throw new Error(
      `Invalid namespace '${namespace}': only alphanumeric characters, hyphens, and underscores are allowed`,
    );
  }

  if (!SANITIZE_SECRETS_DIR) {
    throw new Error(
      "SANITIZE_SECRETS_DIR is not set; cannot resolve namespace. " +
        "Set this environment variable to the directory containing per-namespace secret files.",
    );
  }

  const nsDir = join(SANITIZE_SECRETS_DIR, namespace);

  // Resolve secrets file — encrypted variants take priority.
  const secretsCandidates = [
    ["secrets.yaml.enc", true],
    ["secrets.json.enc", true],
    ["secrets.toml.enc", true],
    ["secrets.yaml", false],
    ["secrets.json", false],
    ["secrets.toml", false],
  ] as const;

  let secretsFile: string | undefined;
  let encrypted = false;

  for (const [name, isEnc] of secretsCandidates) {
    const p = join(nsDir, name);
    if (await fileExists(p)) {
      secretsFile = p;
      encrypted = isEnc;
      break;
    }
  }

  if (!secretsFile) {
    throw new Error(
      `No secrets file found for namespace '${namespace}' in ${nsDir}. ` +
        `Expected one of: secrets.yaml[.enc], secrets.json[.enc], secrets.toml[.enc]`,
    );
  }

  // Resolve optional profile.
  let profileFile: string | undefined;
  for (const name of ["profile.yaml", "profile.json"]) {
    const p = join(nsDir, name);
    if (await fileExists(p)) {
      profileFile = p;
      break;
    }
  }

  // Read password for encrypted secrets.
  let password: string | undefined;
  if (encrypted) {
    const passwordPath = join(nsDir, ".password");

    let stat: Deno.FileInfo;
    try {
      stat = await Deno.stat(passwordPath);
    } catch {
      throw new Error(
        `Secrets file for namespace '${namespace}' is encrypted but no .password file found at ${passwordPath}`,
      );
    }

    // Enforce owner-only permissions on non-Windows.
    if (stat.mode !== null) {
      const perms = stat.mode & 0o777;
      if (perms !== 0o600 && perms !== 0o400) {
        throw new Error(
          `.password file for namespace '${namespace}' has insecure permissions ` +
            `(${perms.toString(8)}); must be 0600 or 0400`,
        );
      }
    }

    password = (await Deno.readTextFile(passwordPath)).trim();
    if (!password) {
      throw new Error(`.password file for namespace '${namespace}' is empty`);
    }
  }

  return { secretsFile, profileFile, encrypted, password };
}

// ---------------------------------------------------------------------------
// Inline-pattern secrets file helpers
// ---------------------------------------------------------------------------

interface InlinePattern {
  name: string;
  pattern: string;
  category: string;
  kind?: string;
}

function buildSecretsJson(patterns: InlinePattern[]): string {
  return JSON.stringify(
    patterns.map((p) => ({
      pattern: p.pattern,
      kind: p.kind ?? "regex",
      category: p.category,
      label: p.name,
    })),
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

interface SanitizeResult {
  content: string;
  report?: unknown;
}

async function toolSanitize(params: {
  content: string;
  namespace?: string;
  seed?: string;
  patterns?: InlinePattern[];
  secrets_file?: string;
  profile?: string;
  format?: string;
  use_default?: boolean;
  app?: string[];
  allow?: string[];
  extract_context?: boolean;
  context_lines?: number;
  context_keywords?: string[];
  max_context_matches?: number;
  context_case_sensitive?: boolean;
}): Promise<SanitizeResult> {
  checkContentSize(params.content);
  if (params.secrets_file) validateUserPath(params.secrets_file, "secrets_file");
  if (params.profile) validateUserPath(params.profile, "profile");
  if (params.use_default && (params.secrets_file || params.namespace || (params.patterns && params.patterns.length > 0))) {
    throw new Error("use_default cannot be combined with secrets_file, namespace, or patterns — each supplies its own pattern set");
  }

  const tmpDir = await Deno.makeTempDir({ prefix: "sanitize-mcp-" });
  try {
    const outputPath = join(tmpDir, "output.txt");
    const args: string[] = ["-", "--output", outputPath];
    const env: Record<string, string> = {};

    if (params.format) {
      args.push("--format", params.format);
    }

    // Namespace resolution takes priority over secrets_file and patterns.
    if (params.namespace) {
      const ns = await resolveNamespace(params.namespace);
      args.push("-s", ns.secretsFile);
      if (ns.encrypted) {
        args.push("--encrypted-secrets");
        env.SANITIZE_PASSWORD = ns.password!;
      }
      // Explicit profile param overrides namespace profile.
      const profileToUse = params.profile ?? ns.profileFile;
      if (profileToUse) {
        args.push("--profile", profileToUse);
      }
    } else {
      // Seed/deterministic only applies outside namespace mode (namespace
      // derives its own key from the per-namespace password).
      if (params.seed) {
        env.SANITIZE_PASSWORD = params.seed;
        args.push("--deterministic");
      }

      if (params.profile) {
        args.push("--profile", params.profile);
      }

      // secrets_file takes priority over inline patterns.
      if (params.secrets_file) {
        args.push("-s", params.secrets_file);
      } else if (params.patterns && params.patterns.length > 0) {
        const secretsPath = await writeTempFile(
          tmpDir,
          "secrets.json",
          buildSecretsJson(params.patterns),
        );
        args.push("-s", secretsPath);
      }
    }

    if (params.use_default) {
      args.push("--default");
    }
    if (params.app && params.app.length > 0) {
      args.push("--app", params.app.join(","));
    }
    if (params.allow && params.allow.length > 0) {
      for (const pattern of params.allow) {
        args.push("--allow", pattern);
      }
    }

    let reportPath: string | undefined;
    if (params.extract_context) {
      reportPath = join(tmpDir, "report.json");
      args.push("--extract-context", "--report", reportPath);
      if (params.context_lines !== undefined) {
        args.push("--context-lines", String(params.context_lines));
      }
      if (params.context_keywords && params.context_keywords.length > 0) {
        args.push("--context-keywords", params.context_keywords.join(","));
      }
      if (params.max_context_matches !== undefined) {
        args.push("--max-context-matches", String(params.max_context_matches));
      }
      if (params.context_case_sensitive) {
        args.push("--context-case-sensitive");
      }
    }

    const result = await runSanitize(args, params.content, env);

    if (result.exitCode !== 0) {
      throw new Error(
        `sanitize exited with code ${result.exitCode}: ${result.stderr.trim()}`,
      );
    }

    const content = await Deno.readTextFile(outputPath);

    if (reportPath) {
      const reportJson = await Deno.readTextFile(reportPath);
      return { content, report: JSON.parse(reportJson) };
    }

    return { content };
  } finally {
    await Deno.remove(tmpDir, { recursive: true });
  }
}

async function toolScan(params: {
  content: string;
  namespace?: string;
  patterns?: InlinePattern[];
  secrets_file?: string;
  format?: string;
  use_default?: boolean;
  app?: string[];
  allow?: string[];
}): Promise<unknown> {
  checkContentSize(params.content);
  if (params.secrets_file) validateUserPath(params.secrets_file, "secrets_file");
  if (params.use_default && (params.secrets_file || params.namespace || (params.patterns && params.patterns.length > 0))) {
    throw new Error("use_default cannot be combined with secrets_file, namespace, or patterns — each supplies its own pattern set");
  }

  const tmpDir = await Deno.makeTempDir({ prefix: "sanitize-mcp-" });
  try {
    const reportPath = join(tmpDir, "report.json");
    const outputPath = join(tmpDir, "output.txt");
    const args: string[] = ["-", "--dry-run", "--report", reportPath, "--output", outputPath];
    const env: Record<string, string> = {};

    if (params.format) {
      args.push("--format", params.format);
    }

    if (params.namespace) {
      const ns = await resolveNamespace(params.namespace);
      args.push("-s", ns.secretsFile);
      if (ns.encrypted) {
        args.push("--encrypted-secrets");
        env.SANITIZE_PASSWORD = ns.password!;
      }
    } else if (params.secrets_file) {
      args.push("-s", params.secrets_file);
    } else if (params.patterns && params.patterns.length > 0) {
      const secretsPath = await writeTempFile(
        tmpDir,
        "secrets.json",
        buildSecretsJson(params.patterns),
      );
      args.push("-s", secretsPath);
    }

    if (params.use_default) {
      args.push("--default");
    }
    if (params.app && params.app.length > 0) {
      args.push("--app", params.app.join(","));
    }
    if (params.allow && params.allow.length > 0) {
      for (const pattern of params.allow) {
        args.push("--allow", pattern);
      }
    }

    const result = await runSanitize(args, params.content, env);

    if (result.exitCode !== 0) {
      throw new Error(
        `sanitize exited with code ${result.exitCode}: ${result.stderr.trim()}`,
      );
    }

    const reportJson = await Deno.readTextFile(reportPath);
    return JSON.parse(reportJson);
  } finally {
    await Deno.remove(tmpDir, { recursive: true });
  }
}

async function toolStripConfigValues(params: {
  content: string;
  delimiter?: string;
  comment_prefix?: string;
}): Promise<string> {
  checkContentSize(params.content);

  const tmpDir = await Deno.makeTempDir({ prefix: "sanitize-mcp-" });
  try {
    const outputPath = join(tmpDir, "output.txt");
    const args = [
      "-",
      "--strip-values",
      "--strip-delimiter",
      params.delimiter ?? "=",
      "--strip-comment-prefix",
      params.comment_prefix ?? "#",
      "--output",
      outputPath,
    ];

    const result = await runSanitize(args, params.content);

    if (result.exitCode !== 0) {
      throw new Error(
        `sanitize exited with code ${result.exitCode}: ${result.stderr.trim()}`,
      );
    }

    return await Deno.readTextFile(outputPath);
  } finally {
    await Deno.remove(tmpDir, { recursive: true });
  }
}

async function toolTestAllowlist(params: {
  patterns: string[];
  values: string[];
}): Promise<unknown> {
  if (params.patterns.length === 0) {
    throw new Error("at least one pattern is required");
  }
  if (params.values.length === 0) {
    throw new Error("at least one value is required");
  }

  const args: string[] = ["allow-test", "--json"];
  for (const pat of params.patterns) {
    args.push("--allow", pat);
  }
  args.push(...params.values);

  const result = await runSanitize(args, "");

  if (result.exitCode !== 0) {
    throw new Error(
      `sanitize exited with code ${result.exitCode}: ${result.stderr.trim()}`,
    );
  }

  return JSON.parse(result.stdout);
}

function toolListProcessors(): unknown {
  return {
    processors: [
      { name: "json",      format_flag: "json",      description: "JSON — field-level replacement using key paths" },
      { name: "yaml",      format_flag: "yaml",      description: "YAML — field-level replacement using key paths" },
      { name: "toml",      format_flag: "toml",      description: "TOML — field-level replacement using key paths" },
      { name: "xml",       format_flag: "xml",       description: "XML — element and attribute replacement" },
      { name: "csv",       format_flag: "csv",       description: "CSV — column-level replacement by header name" },
      { name: "jsonl",     format_flag: "jsonl",     description: "NDJSON / JSON Lines — one JSON object per line" },
      { name: "key_value", format_flag: "key-value", description: "Key-value pairs (nginx, Apache, .conf files)" },
      { name: "env",       format_flag: "env",       description: ".env files — KEY=VALUE format" },
      { name: "ini",       format_flag: "ini",       description: "INI files with [sections]" },
      { name: "log",       format_flag: "log",       description: "Log files — streaming scanner only, no structure" },
      { name: "text",      format_flag: "text",      description: "Plain text — streaming scanner only, no structure" },
    ],
    note: "Pass format_flag as the `format` parameter to force a specific processor when content type cannot be inferred. Processor names are also used in the `processor` field of profile YAML/JSON files.",
  };
}

function toolListTemplates(): unknown {
  return {
    templates: [
      {
        name: "troubleshoot",
        description:
          "Incident triage — analyzes sanitized logs to identify root cause, event sequence, and remediation steps.",
      },
      {
        name: "review-config",
        description:
          "Configuration review — identifies misconfigurations, security concerns, and best practice violations.",
      },
    ],
    note: "Pass a filesystem path instead of a name to use a custom template file.",
  };
}

// ---------------------------------------------------------------------------
// Shared Zod schemas
// ---------------------------------------------------------------------------

const InlinePatternSchema = z.object({
  name: z.string().describe("Human-readable label for this pattern"),
  pattern: z.string().describe('Regular expression (or literal string when kind is "literal"). For kind "allow", supports exact strings and * glob wildcards.'),
  category: z
    .string()
    .describe(
      'Replacement category: "email", "ipv4", "ipv6", "hostname", "name", "uuid", "hash", "path", "url", "generic". Ignored for kind "allow".',
    ),
  kind: z
    .enum(["regex", "literal", "allow"])
    .optional()
    .describe('Match kind: "regex" (default), "literal" for exact string matching, or "allow" to pass the value through unchanged (not replaced, not recorded in the mapping store).'),
});

const FormatSchema = z
  .enum(["text", "json", "yaml", "xml", "csv", "key-value", "toml", "env", "ini", "jsonl", "log"])
  .optional()
  .describe(
    "Force input format, overriding file-extension detection. Required when the content type cannot be inferred from a filename. Use list_processors for descriptions of each format.",
  );

const NamespaceSchema = z
  .string()
  .optional()
  .describe(
    "Customer or tenant namespace. Resolves secrets, profile, and password from $SANITIZE_SECRETS_DIR/{namespace}/. Takes priority over secrets_file and patterns. Must be alphanumeric with hyphens/underscores only.",
  );

const SanitizeSchema = {
  content: z.string().describe("The text content to sanitize"),
  namespace: NamespaceSchema,
  seed: z
    .string()
    .optional()
    .describe(
      "Optional seed string for deterministic replacements. Same seed → same replacements across calls.",
    ),
  patterns: z
    .array(InlinePatternSchema)
    .optional()
    .describe("Inline regex/literal/allow patterns. Ignored when secrets_file is supplied. Use kind: 'allow' entries to pass specific values through unchanged."),
  secrets_file: z
    .string()
    .optional()
    .describe("Path to a JSON/TOML/YAML secrets file. Takes priority over patterns."),
  profile: z
    .string()
    .optional()
    .describe(
      "Path to a field-level profile YAML/JSON file defining which structured fields to sanitize.",
    ),
  use_default: z
    .boolean()
    .optional()
    .describe(
      "Use built-in balanced detection patterns without a secrets file. Covers API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, GitLab, SendGrid, npm), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM headers, and credential URLs. Cannot be combined with secrets_file.",
    ),
  app: z
    .array(z.string())
    .optional()
    .describe(
      "Built-in app bundle names to load (e.g. ['gitlab', 'nginx']). Each bundle adds app-specific secrets patterns and a structured field profile. Additive with secrets_file, use_default, and profile.",
    ),
  allow: z
    .array(z.string())
    .optional()
    .describe(
      "Values to pass through unchanged (not replaced, not recorded in the mapping store). Supports exact strings and * glob patterns — e.g. 'localhost', '*.internal', '192.168.1.*'.",
    ),
  format: FormatSchema,
  extract_context: z
    .boolean()
    .optional()
    .describe(
      "When true, scan the sanitized output for error/warning keywords and return a structured log context report alongside the sanitized content. Response becomes { content, report } instead of plain text.",
    ),
  context_lines: z
    .number()
    .int()
    .nonnegative()
    .optional()
    .describe("Lines of context to capture before and after each keyword match. Default: 10."),
  context_keywords: z
    .array(z.string())
    .optional()
    .describe(
      "Additional keywords to flag (merged with built-in defaults: error, failure, warning, warn, fatal, exception, critical). Only used when extract_context is true.",
    ),
  max_context_matches: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      "Maximum keyword matches to capture per file. Matches beyond this are dropped and truncated is set true in the report. Default: 50.",
    ),
  context_case_sensitive: z
    .boolean()
    .optional()
    .describe(
      "When true, keyword matching is case-sensitive. Default: false (ERROR, error, and Error all match).",
    ),
};

const ScanSchema = {
  content: z.string().describe("The text content to scan"),
  namespace: NamespaceSchema,
  patterns: z
    .array(InlinePatternSchema)
    .optional()
    .describe("Inline regex/literal/allow patterns to scan for. Use kind: 'allow' entries to suppress known-safe values from the report."),
  secrets_file: z
    .string()
    .optional()
    .describe("Path to a secrets file. Takes priority over patterns."),
  use_default: z
    .boolean()
    .optional()
    .describe(
      "Use built-in balanced detection patterns without a secrets file. Cannot be combined with secrets_file.",
    ),
  app: z
    .array(z.string())
    .optional()
    .describe(
      "Built-in app bundle names to load (e.g. ['gitlab', 'nginx']). Additive with secrets_file and use_default.",
    ),
  allow: z
    .array(z.string())
    .optional()
    .describe(
      "Values to exclude from the scan report. Supports exact strings and * glob patterns. Useful for suppressing known-safe values that would otherwise appear as false positives.",
    ),
  format: FormatSchema,
};

const StripSchema = {
  content: z.string().describe("The configuration file content to strip values from"),
  delimiter: z.string().optional().describe('Key-value delimiter (default: "=")'),
  comment_prefix: z.string().optional().describe('Comment prefix character (default: "#")'),
};

type SanitizeParams = z.infer<z.ZodObject<typeof SanitizeSchema>>;
type ScanParams = z.infer<z.ZodObject<typeof ScanSchema>>;
type StripParams = z.infer<z.ZodObject<typeof StripSchema>>;

// ---------------------------------------------------------------------------
// Server setup
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "sanitize-engine",
  version: SERVER_VERSION,
});

server.tool(
  "sanitize",
  "Sanitize sensitive values in text content. Structured fields (passwords, tokens, API keys) are replaced with __SANITIZED-<hash>__ markers. Typed values (emails, IPs, hostnames) are replaced with realistic-looking substitutes of the same format. Supply a seed for consistent replacements across multiple calls in a session.",
  SanitizeSchema,
  async (params: SanitizeParams) => {
    try {
      const result = await toolSanitize(params);
      const text = result.report !== undefined
        ? JSON.stringify(result, null, 2)
        : result.content;
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "scan",
  "Scan text content for sensitive values and return a structured report of what was found — without modifying the content. Useful for auditing before committing to full sanitization.",
  ScanSchema,
  async (params: ScanParams) => {
    try {
      const report = await toolScan(params);
      return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "strip_config_values",
  "Strip values from a key=value configuration file, preserving only keys, comments, section headers, and delimiters. Useful for sharing config structure without exposing secrets.",
  StripSchema,
  async (params: StripParams) => {
    try {
      const stripped = await toolStripConfigValues(params);
      return { content: [{ type: "text" as const, text: stripped }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "test_allowlist",
  "Test which values match a set of allowlist patterns before committing to a full sanitization run. Returns a per-value match result with the pattern that matched, plus a summary count.",
  {
    patterns: z
      .array(z.string())
      .min(1)
      .describe("Allowlist patterns to test. Supports exact strings and * glob wildcards — e.g. 'localhost', '*.internal', '192.168.1.*'."),
    values: z
      .array(z.string())
      .min(1)
      .describe("Values to test against the patterns."),
  },
  async (params: { patterns: string[]; values: string[] }) => {
    try {
      const report = await toolTestAllowlist(params);
      return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "list_processors",
  "List the available content processors and their format flag values. Use this to know what to pass as the `format` parameter on sanitize/scan, or as the `processor` field in a profile YAML file.",
  {},
  () => {
    try {
      return {
        content: [{ type: "text" as const, text: JSON.stringify(toolListProcessors(), null, 2) }],
      };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "list_templates",
  "List the available built-in LLM prompt templates for use with the sanitize CLI's --llm flag.",
  {},
  () => {
    try {
      return {
        content: [{ type: "text" as const, text: JSON.stringify(toolListTemplates(), null, 2) }],
      };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  },
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const transport = new StdioServerTransport();
await server.connect(transport);
