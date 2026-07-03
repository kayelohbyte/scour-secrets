#!/usr/bin/env -S deno run --allow-run --allow-env --allow-read --allow-write
/**
 * MCP server for scour-secrets-engine.
 *
 * Wraps the `scour-secrets` CLI binary as a subprocess so all sensitive data
 * processing stays inside the audited Rust implementation. TypeScript is
 * responsible only for MCP protocol framing.
 *
 * Flags:
 *   --http [port]                   listen on HTTP at http://127.0.0.1:<port>/mcp instead of stdio.
 *                                   Port defaults to 6277 when omitted. Requires SCOUR_SECRETS_MCP_HTTP_TOKEN to be set.
 *
 * Environment variables:
 *   SCOUR_SECRETS_BIN                    path to the `scour-secrets` binary (default: "scour-secrets")
 *   SCOUR_SECRETS_MCP_MAX_CONTENT_BYTES  per-call content size limit in bytes (default: 524288)
 *   SCOUR_SECRETS_MCP_TIMEOUT_MS         subprocess timeout in milliseconds (default: 60000)
 *   SCOUR_SECRETS_MCP_THREADS            worker thread cap for every sanitize invocation (default: unset = CLI default = logical CPUs)
 *   SCOUR_SECRETS_MCP_MAX_ARCHIVE_DEPTH  default maximum archive nesting depth (default: 5; matches CLI default)
 *   SCOUR_SECRETS_SECRETS_DIR            base directory for namespace resolution (required for `namespace` param)
 *   SCOUR_SECRETS_MCP_HTTP_TOKEN         bearer token required for HTTP daemon mode (must be set when using --http)
 *   SCOUR_SECRETS_MCP_FILES_DENYLIST     comma-separated glob patterns for file paths that the `files` param must never match
 *                                   (e.g. "secrets/**,*.key,*.pem"). Patterns without '/' also match the basename.
 *
 * Namespace directory layout:
 *   $SCOUR_SECRETS_SECRETS_DIR/
 *     {namespace}/
 *       secrets.yaml        (or .json / .toml / .yaml.enc / .json.enc / .toml.enc)
 *       profile.yaml        (optional; loaded automatically)
 *       .password           (required when secrets file is encrypted; must be mode 0600 or 0400)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp";
import { basename, dirname, join, resolve } from "@std/path";
import { globToRegExp } from "@std/path/glob-to-regexp";
import { parse as parseYaml } from "@std/yaml";
import { z } from "zod";
import { predictOutputName, uniquifyName } from "./naming.ts";
import { scrubEnv } from "./env.ts";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const SCOUR_SECRETS_BIN = Deno.env.get("SCOUR_SECRETS_BIN") ?? "scour-secrets";

/** Parse a positive integer from an env var string; returns fallback on NaN, 0, or negative. */
function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const MAX_CONTENT_BYTES = parsePositiveInt(
  Deno.env.get("SCOUR_SECRETS_MCP_MAX_CONTENT_BYTES"), 524288,
);
const MAX_ARCHIVE_DEPTH = parsePositiveInt(
  Deno.env.get("SCOUR_SECRETS_MCP_MAX_ARCHIVE_DEPTH"), 5,
);
// When set, appended to every processing invocation to cap CPU usage.
// The value is validated and re-serialised as a decimal integer to prevent flag injection.
const THREADS_ARGS: string[] = (() => {
  const t = Deno.env.get("SCOUR_SECRETS_MCP_THREADS");
  if (!t) return [];
  const n = parseInt(t, 10);
  return Number.isFinite(n) && n > 0 ? ["--threads", String(n)] : [];
})();
const SCOUR_SECRETS_SECRETS_DIR = Deno.env.get("SCOUR_SECRETS_SECRETS_DIR");
const SCOUR_SECRETS_SECRETS_DIR_RESOLVED = SCOUR_SECRETS_SECRETS_DIR
  ? canonicalPath(SCOUR_SECRETS_SECRETS_DIR)
  : undefined;

// Operator-configured denylist: comma-separated glob patterns.
const FILES_DENYLIST: RegExp[] = (() => {
  const raw = Deno.env.get("SCOUR_SECRETS_MCP_FILES_DENYLIST");
  if (!raw) return [];
  return raw
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => globToRegExp(p, { extended: true, globstar: true }));
})();

// Keep in sync with version field in Cargo.toml.
const SERVER_VERSION = "0.13.1";
const DEFAULT_HTTP_PORT = 6277;

const NO_STRUCTURED_HANDOFF_ARG = "--no-structured-handoff";
const TEMP_PREFIX = "scour-secrets-mcp-";

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
 * Spawn the scour-secrets binary and collect stdout/stderr.
 * Pass `stdinData` to pipe content through stdin (the "-" input mode).
 * Pass `null` when the CLI is reading a file directly — stdin is left closed.
 * The subprocess never receives sensitive content via argv —
 * only via the stdin pipe or a mode-0600 temp file.
 */
const SUBPROCESS_TIMEOUT_MS = parsePositiveInt(
  Deno.env.get("SCOUR_SECRETS_MCP_TIMEOUT_MS"), 60000,
);

/**
 * Build a minimal environment for the scour-secrets subprocess. Scrubbing logic
 * lives in ./env.ts (pure + unit-tested); here we just feed it the live
 * parent environment.
 */
function buildSubprocessEnv(extraEnv: Record<string, string>): Record<string, string> {
  return scrubEnv(Deno.env.toObject(), extraEnv);
}

/**
 * Read a report file produced by --report. JSON and SARIF are parsed into
 * objects; HTML is returned as a raw string so the caller receives it intact.
 */
async function readReport(path: string, format?: string): Promise<unknown> {
  const text = await Deno.readTextFile(path);
  return format === "html" ? text : JSON.parse(text);
}

async function runSanitize(
  args: string[],
  stdinData: string | null,
  extraEnv: Record<string, string> = {},
): Promise<RunResult> {
  const cmd = new Deno.Command(SCOUR_SECRETS_BIN, {
    args,
    stdin: stdinData !== null ? "piped" : "null",
    stdout: "piped",
    stderr: "piped",
    env: buildSubprocessEnv(extraEnv),
  });

  const child = cmd.spawn();

  if (stdinData !== null) {
    const writer = child.stdin.getWriter();
    try {
      await writer.write(encoder.encode(stdinData));
    } finally {
      await writer.close();
    }
  }

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try { child.kill("SIGKILL"); } catch { /* already exited */ }
  }, SUBPROCESS_TIMEOUT_MS);

  try {
    const { stdout, stderr, code } = await child.output();
    if (timedOut) {
      throw new Error(`scour-secrets subprocess timed out after ${SUBPROCESS_TIMEOUT_MS / 1000}s`);
    }
    return {
      stdout: decoder.decode(stdout),
      stderr: decoder.decode(stderr),
      exitCode: code,
    };
  } finally {
    clearTimeout(timer);
  }
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
 * Reject path traversal segments in any path parameter.
 * When `allowAbsolute` is false (default) also rejects absolute paths —
 * used for ancillary params like `secrets_file` and `profile` which must stay
 * relative so they cannot reference system files outside the project.
 * When `allowAbsolute` is true, absolute paths are permitted — used for the
 * `files` param where the caller may legitimately target system config files.
 * The Rust CLI enforces its own existence and format checks on the final path.
 */
function validatePath(p: string, paramName: string, allowAbsolute = false): void {
  if (!allowAbsolute && (p.startsWith("/") || p.startsWith("\\"))) {
    throw new Error(`${paramName} must be a relative path, not an absolute path`);
  }
  const segments = p.replace(/\\/g, "/").split("/");
  if (segments.some((s) => s === "..")) {
    throw new Error(`${paramName} must not contain '..' path traversal segments`);
  }
}

/**
 * Resolve `p` to a canonical absolute path with symlinks followed, so the
 * secrets-dir and denylist guards cannot be evaded by a symlink that points
 * into a protected location. For paths that do not yet exist (e.g. output
 * targets), the longest existing ancestor is realpath'd and the non-existent
 * tail re-appended. Best-effort by nature: a TOCTOU swap between this check and
 * the subprocess open is still possible, which is why OS-level permissions
 * (see docs/mcp.md) remain the authoritative boundary, not these guards.
 */
function canonicalPath(p: string): string {
  let head = resolve(p);
  const tail: string[] = [];
  for (;;) {
    try {
      const real = Deno.realPathSync(head);
      return tail.length ? join(real, ...tail) : real;
    } catch {
      const parent = dirname(head);
      if (parent === head) return resolve(p); // reached root without resolving
      tail.unshift(basename(head));
      head = parent;
    }
  }
}

/**
 * Test a path against the operator denylist. Glob patterns compile to
 * start-anchored regexes, so an absolute path like '/proj/secrets/db.yaml'
 * would never match a 'secrets/**' pattern. To close that gap, each pattern is
 * tested against the basename and against every trailing path suffix of both
 * the path as-given and its canonical (symlink-resolved) form, so segment
 * patterns match regardless of the absolute prefix or an intervening symlink.
 */
function pathMatchesDenylist(original: string, canonical: string): boolean {
  const candidates = new Set<string>();
  for (const raw of [original, canonical]) {
    const norm = raw.replace(/\\/g, "/");
    candidates.add(norm);
    candidates.add(basename(norm));
    const segments = norm.split("/").filter(Boolean);
    for (let i = 0; i < segments.length; i++) {
      candidates.add(segments.slice(i).join("/"));
    }
  }
  for (const pattern of FILES_DENYLIST) {
    for (const c of candidates) {
      if (pattern.test(c)) return true;
    }
  }
  return false;
}

/**
 * Guard `files` entries against three threat classes:
 *   1. Paths inside $SCOUR_SECRETS_SECRETS_DIR (operator secrets store)
 *   2. .password files (namespace encryption keys)
 *   3. Operator-configured denylist patterns (SCOUR_SECRETS_MCP_FILES_DENYLIST)
 *
 * All three checks run against the canonical, symlink-resolved path so a
 * symlink in an allowed directory cannot reach a protected target.
 */
function validateFilesPath(p: string): void {
  const canonical = canonicalPath(p);

  if (basename(p) === ".password" || basename(canonical) === ".password") {
    throw new Error(`files path '${p}' is not permitted: .password files cannot be processed`);
  }

  if (SCOUR_SECRETS_SECRETS_DIR_RESOLVED) {
    if (canonical === SCOUR_SECRETS_SECRETS_DIR_RESOLVED || canonical.startsWith(SCOUR_SECRETS_SECRETS_DIR_RESOLVED + "/")) {
      throw new Error(`files path '${p}' is not permitted: path resolves inside SCOUR_SECRETS_SECRETS_DIR`);
    }
  }

  if (FILES_DENYLIST.length > 0 && pathMatchesDenylist(p, canonical)) {
    throw new Error(`files path '${p}' is not permitted: matches operator denylist`);
  }
}

/** Enforce per-call content size limit. */
function checkContentSize(content: string, label = "content"): void {
  const bytes = encoder.encode(content).length;
  if (bytes > MAX_CONTENT_BYTES) {
    throw new Error(
      `${label} exceeds maximum allowed size (${bytes} > ${MAX_CONTENT_BYTES} bytes). ` +
        `Increase SCOUR_SECRETS_MCP_MAX_CONTENT_BYTES to allow larger inputs.`,
    );
  }
}

/**
 * Return a sanitized excerpt from subprocess stderr for use in error messages.
 * Capped at 200 chars to avoid leaking unexpectedly verbose output.
 */
function safeStderr(result: RunResult): string {
  const raw = result.stderr.trim();
  return raw.length > 200 ? raw.slice(0, 200) + "…" : raw;
}

// Concurrency guard: limit simultaneous subprocess invocations to avoid
// resource exhaustion when many tool calls arrive at once.
const MAX_CONCURRENT = 4;
let activeCalls = 0;

// ---------------------------------------------------------------------------
// Output name prediction + archive detection
// ---------------------------------------------------------------------------

// predictOutputName and uniquifyName are imported from ./naming.ts

/** Returns true for file extensions the CLI treats as archives. */
function isArchivePath(p: string): boolean {
  const lower = p.toLowerCase();
  return (
    lower.endsWith(".zip") ||
    lower.endsWith(".tar") ||
    lower.endsWith(".tar.gz") ||
    lower.endsWith(".tgz") ||
    lower.endsWith(".tar.bz2") ||
    lower.endsWith(".tar.xz") ||
    lower.endsWith(".tar.zst") ||
    lower.endsWith(".gz") ||
    lower.endsWith(".bz2") ||
    lower.endsWith(".xz") ||
    lower.endsWith(".zst")
  );
}

// ---------------------------------------------------------------------------
// Namespace resolution
// ---------------------------------------------------------------------------

const NAMESPACE_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;

/** Subset of SanitizeConfig fields that make sense as per-namespace defaults. */
interface NsSettings {
  app?: string[];
  allow?: string[];
  exclude_path?: string[];
  include_path?: string[];
  context_keywords?: string[];
  fail_on_match?: boolean;
  strict?: boolean;
  no_field_signal?: boolean;
  force_text?: boolean;
  include_binary?: boolean;
  hidden?: boolean;
  context_keywords_replace?: boolean;
  context_case_sensitive?: boolean;
  extract_context?: boolean;
  threads?: number;
  entropy_threshold?: number;
  max_archive_depth?: number;
  context_lines?: number;
  max_context_matches?: number;
}

interface ResolvedNamespace {
  secretsFile: string;
  profileFile?: string;
  encrypted: boolean;
  password?: string;
  settings?: NsSettings;
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

  if (!SCOUR_SECRETS_SECRETS_DIR) {
    throw new Error(
      "SCOUR_SECRETS_SECRETS_DIR is not set; cannot resolve namespace. " +
        "Set this environment variable to the directory containing per-namespace secret files.",
    );
  }

  const nsDir = join(SCOUR_SECRETS_SECRETS_DIR_RESOLVED!, namespace);

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

  // Optionally read per-namespace behavior defaults from settings.yaml.
  let settings: NsSettings | undefined;
  const nsSettingsPath = join(nsDir, "settings.yaml");
  if (await fileExists(nsSettingsPath)) {
    try {
      const raw = await Deno.readTextFile(nsSettingsPath);
      settings = parseYaml(raw) as NsSettings;
    } catch {
      // Silently ignore invalid YAML — same policy as the Rust config loader.
    }
  }

  return { secretsFile, profileFile, encrypted, password, settings };
}

// ---------------------------------------------------------------------------
// Inline-pattern secrets file helpers
// ---------------------------------------------------------------------------

interface InlinePattern {
  name: string;
  pattern: string;
  category?: string; // required for regex/literal; ignored (and optional) for allow
  kind?: string;
}

function yamlQuoteString(s: string): string {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\0/g, '\\0').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t') + '"';
}

function buildSecretsJson(patterns: InlinePattern[]): string {
  return JSON.stringify(
    patterns.map((p) => {
      const kind = p.kind ?? "literal";
      if (kind !== "allow" && !p.category) {
        throw new Error(`pattern "${p.name}" requires a category when kind is "${kind}"`);
      }
      const entry: Record<string, string> = { pattern: p.pattern, kind, label: p.name };
      if (p.category) entry.category = p.category;
      return entry;
    }),
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// Namespace settings → CLI flag conversion
// ---------------------------------------------------------------------------

/** Push CLI flags derived from a namespace settings.yaml into `args`.
 *
 * These are added before per-call params so that per-call flags take precedence
 * via clap's last-wins rule. List fields (app, allow, …) are additive in both
 * the CLI and the Rust merge layer so duplicates are fine.
 */
function appendNsSettingsArgs(args: string[], s: NsSettings): void {
  for (const v of s.app ?? []) {
    if (!v.startsWith("-")) args.push("--app", v);
  }
  for (const v of s.allow ?? []) {
    if (!v.startsWith("-")) args.push("--allow", v);
  }
  for (const v of s.exclude_path ?? []) {
    if (!v.startsWith("-")) args.push("--exclude-path", v);
  }
  for (const v of s.include_path ?? []) {
    if (!v.startsWith("-")) args.push("--include-path", v);
  }
  for (const v of s.context_keywords ?? []) {
    if (!v.startsWith("-")) args.push("--context-keywords", v);
  }
  if (s.fail_on_match) args.push("--fail-on-match");
  if (s.strict) args.push("--strict");
  if (s.no_field_signal) args.push("--no-field-signal");
  if (s.force_text) args.push("--force-text");
  if (s.include_binary) args.push("--include-binary");
  if (s.hidden) args.push("--hidden");
  if (s.context_keywords_replace) args.push("--context-keywords-replace");
  if (s.context_case_sensitive) args.push("--context-case-sensitive");
  if (s.extract_context) args.push("--extract-context");
  if (s.threads !== undefined) args.push("--threads", String(s.threads));
  if (s.entropy_threshold !== undefined) args.push("--entropy-threshold", String(s.entropy_threshold));
  if (s.context_lines !== undefined) args.push("--context-lines", String(s.context_lines));
  if (s.max_context_matches !== undefined) args.push("--max-context-matches", String(s.max_context_matches));
  // max_archive_depth is intentionally omitted here: it is threaded through the
  // effectiveMaxArchiveDepth variable in each tool handler so the MCP-level default
  // (SCOUR_SECRETS_MCP_MAX_ARCHIVE_DEPTH) does not silently override a namespace setting.
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

interface FileResult {
  input: string;      // original path as passed in `files`
  file: string;       // sanitized output filename (CLI naming: {stem}-sanitized.{ext})
  output?: string;    // full output path when written directly to disk (output_file/output_dir mode)
  content?: string;   // present for text/structured outputs (absent in write-to-disk mode)
  binary?: boolean;   // true when output is a binary archive — content not returned inline
  size?: number;      // byte size when binary is true, or when written to disk
  written?: boolean;  // true when output was written directly to disk without returning content
}

interface SanitizeResult {
  content?: string;        // populated for content-mode (inline text input)
  results?: FileResult[];  // populated for files-mode (one or more file paths)
  output?: string;         // output path in content-mode write-to-disk (output_file set)
  size?: number;           // byte size when content-mode output was written to disk
  written?: boolean;       // true when output was written directly to disk
  report?: unknown;
}

interface ArchiveFilter {
  path: string;
  only?: string[];
  exclude?: string[];
}

async function toolSanitize(params: {
  content?: string;
  files?: string[];
  output_file?: string;
  output_dir?: string;
  archive_filters?: ArchiveFilter[];
  namespace?: string;
  seed?: string;
  patterns?: InlinePattern[];
  secrets_file?: string;
  profile?: string;
  format?: string;
  app?: string[];
  allow?: string[];
  llm_template?: string;
  force_text?: boolean;
  include_binary?: boolean;
  hidden?: boolean;
  exclude_path?: string[];
  include_path?: string[];
  max_archive_depth?: number;
  entropy_threshold?: number;
  extract_context?: boolean;
  context_lines?: number;
  context_keywords?: string[];
  context_keywords_replace?: boolean;
  max_context_matches?: number;
  context_case_sensitive?: boolean;
  report?: boolean;
  report_format?: "json" | "sarif" | "html";
  strict?: boolean;
}): Promise<SanitizeResult> {
  const hasContent = params.content !== undefined;
  const hasFiles = params.files !== undefined && params.files.length > 0;

  if (!hasContent && !hasFiles) {
    throw new Error("Either 'content' or 'files' must be provided");
  }
  if (hasContent && hasFiles) {
    throw new Error("'content' and 'files' are mutually exclusive — provide one or the other");
  }
  if (hasFiles) {
    for (const f of params.files!) {
      if (f.startsWith("-")) throw new Error(`files entry '${f}' must not start with '-' (flag injection)`);
      validatePath(f, "files", true);
      validateFilesPath(f);
    }
  } else {
    checkContentSize(params.content!);
  }
  if (params.output_file && params.output_dir) {
    throw new Error("'output_file' and 'output_dir' are mutually exclusive — provide one or the other");
  }
  if (params.output_file) {
    if (params.output_file.startsWith("-")) throw new Error("output_file must not start with '-'");
    validatePath(params.output_file, "output_file", true);
    validateFilesPath(params.output_file);
    if (hasFiles && params.files!.length > 1) {
      throw new Error("'output_file' can only be used with a single input; use 'output_dir' for multiple files");
    }
  }
  if (params.output_dir) {
    if (params.output_dir.startsWith("-")) throw new Error("output_dir must not start with '-'");
    validatePath(params.output_dir, "output_dir", true);
    validateFilesPath(params.output_dir);
  }
  for (const af of params.archive_filters ?? []) {
    for (const p of af.only ?? []) {
      if (p.startsWith("-")) throw new Error(`archive_filters only pattern '${p}' must not start with '-'`);
    }
    for (const p of af.exclude ?? []) {
      if (p.startsWith("-")) throw new Error(`archive_filters exclude pattern '${p}' must not start with '-'`);
    }
  }
  if (params.secrets_file) validatePath(params.secrets_file, "secrets_file");
  if (params.profile) validatePath(params.profile, "profile");
  if (params.llm_template) {
    const builtins = ["troubleshoot", "review-config", "review-security"];
    if (!builtins.includes(params.llm_template)) {
      validatePath(params.llm_template, "llm_template");
    }
  }
  if (activeCalls >= MAX_CONCURRENT) {
    throw new Error(`Too many concurrent requests (max ${MAX_CONCURRENT}). Retry after current calls complete.`);
  }
  activeCalls++;
  const tmpDir = await Deno.makeTempDir({ prefix: TEMP_PREFIX });
  try {
    const env: Record<string, string> = {};
    // --no-structured-handoff: suppress writing scour-secrets-discovered.yaml to cwd.
    const commonArgs: string[] = [NO_STRUCTURED_HANDOFF_ARG];

    if (params.format) commonArgs.push("--format", params.format);

    // Namespace resolution takes priority over secrets_file and patterns.
    let nsSettings: NsSettings | undefined;
    if (params.namespace) {
      const ns = await resolveNamespace(params.namespace);
      commonArgs.push("-s", ns.secretsFile);
      if (ns.encrypted) {
        commonArgs.push("--encrypted-secrets");
        env.SCOUR_SECRETS_PASSWORD = ns.password!;
      }
      // Explicit profile param overrides namespace profile.
      const profileToUse = params.profile ?? ns.profileFile;
      if (profileToUse) commonArgs.push("--profile", profileToUse);
      // Apply per-namespace behavior defaults before per-call params.
      nsSettings = ns.settings;
      if (nsSettings) appendNsSettingsArgs(commonArgs, nsSettings);
    } else {
      // Seed/deterministic only applies outside namespace mode.
      if (params.seed) {
        env.SCOUR_SECRETS_PASSWORD = params.seed;
        commonArgs.push("--deterministic");
      }
      if (params.profile) commonArgs.push("--profile", params.profile);
      if (params.secrets_file) {
        commonArgs.push("-s", params.secrets_file);
      } else if (params.patterns && params.patterns.length > 0) {
        const secretsPath = await writeTempFile(
          tmpDir,
          "secrets.json",
          buildSecretsJson(params.patterns),
        );
        commonArgs.push("-s", secretsPath);
      }
    }

    if (params.app?.length) {
      for (const a of params.app) {
        if (a.startsWith("-")) throw new Error(`app '${a}' must not start with '-' (flag injection)`);
      }
      commonArgs.push("--app", params.app.join(","));
    }
    if (params.allow?.length) {
      for (const pattern of params.allow) {
        if (pattern.startsWith("-")) throw new Error(`allow pattern '${pattern}' must not start with '-' (flag injection)`);
        commonArgs.push("--allow", pattern);
      }
    }
    if (params.force_text) commonArgs.push("--force-text");
    if (params.include_binary) commonArgs.push("--include-binary");
    if (params.hidden) commonArgs.push("--hidden");
    if (params.exclude_path?.length) {
      for (const pattern of params.exclude_path) {
        if (pattern.startsWith("-")) throw new Error(`exclude_path '${pattern}' must not start with '-' (flag injection)`);
        commonArgs.push("--exclude-path", pattern);
      }
    }
    if (params.include_path?.length) {
      for (const pattern of params.include_path) {
        if (pattern.startsWith("-")) throw new Error(`include_path '${pattern}' must not start with '-' (flag injection)`);
        commonArgs.push("--include-path", pattern);
      }
    }
    if (params.entropy_threshold !== undefined) {
      commonArgs.push("--entropy-threshold", String(params.entropy_threshold));
    }
    if (params.llm_template) commonArgs.push("--llm", params.llm_template);
    if (params.strict) commonArgs.push("--strict");
    const effectiveMaxArchiveDepth = params.max_archive_depth ?? nsSettings?.max_archive_depth ?? MAX_ARCHIVE_DEPTH;
    commonArgs.push("--max-archive-depth", String(effectiveMaxArchiveDepth));
    commonArgs.push(...THREADS_ARGS);

    // A report is generated whenever report:true or extract_context:true.
    let reportPath: string | undefined;
    if (params.report || params.extract_context) {
      const ext = params.report_format === "sarif" ? "sarif"
                : params.report_format === "html"  ? "html"
                : "json";
      const rp = join(tmpDir, `report.${ext}`);
      reportPath = rp;
      commonArgs.push("--report", rp);
      if (params.report_format) commonArgs.push("--report-format", params.report_format);
    }
    if (params.extract_context) {
      commonArgs.push("--extract-context");
      if (params.context_lines !== undefined) {
        commonArgs.push("--context-lines", String(params.context_lines));
      }
      if (params.context_keywords?.length) {
        commonArgs.push("--context-keywords", params.context_keywords.join(","));
        if (params.context_keywords_replace) commonArgs.push("--context-keywords-replace");
      }
      if (params.max_context_matches !== undefined) {
        commonArgs.push("--max-context-matches", String(params.max_context_matches));
      }
      if (params.context_case_sensitive) commonArgs.push("--context-case-sensitive");
    }

    // -----------------------------------------------------------------------
    // Content mode — inline text via stdin
    // -----------------------------------------------------------------------
    if (hasContent) {
      if (params.llm_template) {
        // --llm writes the formatted prompt to stdout instead of the output file.
        const result = await runSanitize(["-", ...commonArgs], params.content!, env);
        if (result.exitCode !== 0) {
          throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
        }
        if (reportPath) {
          return { content: result.stdout, report: await readReport(reportPath, params.report_format) };
        }
        return { content: result.stdout };
      }
      if (params.output_file) {
        // Write directly to caller's path — content never returned to LLM.
        const result = await runSanitize(["-", "--output", params.output_file, ...commonArgs], params.content!, env);
        if (result.exitCode !== 0) {
          throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
        }
        const stat = await Deno.stat(params.output_file);
        const base: SanitizeResult = { output: params.output_file, size: stat.size, written: true };
        if (reportPath) base.report = await readReport(reportPath, params.report_format);
        return base;
      }
      const outputPath = join(tmpDir, "output.txt");
      const result = await runSanitize(["-", "--output", outputPath, ...commonArgs], params.content!, env);
      if (result.exitCode !== 0) {
        throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
      }
      const content = await Deno.readTextFile(outputPath);
      if (reportPath) {
        return { content, report: await readReport(reportPath, params.report_format) };
      }
      return { content };
    }

    // -----------------------------------------------------------------------
    // Files mode — one or more paths (files, archives)
    // -----------------------------------------------------------------------

    // Build a filter lookup keyed on the path string as given.
    const filterMap = new Map<string, ArchiveFilter>();
    for (const f of params.archive_filters ?? []) {
      filterMap.set(f.path, f);
    }

    // Interleave --only / --exclude immediately after each archive path, matching
    // the CLI's pre-parser expectation: `archive.zip --only *.log --exclude *.tmp`.
    const inputArgs: string[] = [];
    for (const filePath of params.files!) {
      inputArgs.push(filePath);
      const filter = filterMap.get(filePath);
      if (filter?.only?.length) inputArgs.push("--only", ...filter.only);
      if (filter?.exclude?.length) inputArgs.push("--exclude", ...filter.exclude);
    }

    // ── write-to-disk mode (output_file / output_dir) ───────────────────────
    // Output goes directly to the caller's path; content is never returned.
    const diskOutputTarget = params.output_file ?? params.output_dir;
    if (diskOutputTarget) {
      if (params.output_dir) {
        await Deno.mkdir(params.output_dir, { recursive: true });
      }
      const result = await runSanitize([...inputArgs, "--output", diskOutputTarget, ...commonArgs], null, env);
      if (result.exitCode !== 0) {
        throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
      }
      if (params.llm_template) {
        if (reportPath) return { content: result.stdout, report: await readReport(reportPath, params.report_format) };
        return { content: result.stdout };
      }
      const usedNames = new Set<string>();
      const fileResults: FileResult[] = params.files!.map((f) => {
        const outputName = uniquifyName(predictOutputName(f), usedNames);
        const outputPath = params.output_file ?? join(params.output_dir!, outputName);
        return { input: f, file: outputName, output: outputPath, written: true };
      });
      if (reportPath) return { results: fileResults, report: await readReport(reportPath, params.report_format) };
      return { results: fileResults };
    }

    // ── inline mode (default) — read output back and return to caller ────────
    const outputDir = join(tmpDir, "out");
    await Deno.mkdir(outputDir);

    const result = await runSanitize([...inputArgs, "--output", outputDir, ...commonArgs], null, env);

    if (result.exitCode !== 0) {
      throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
    }

    // When --llm is active, the formatted prompt is on stdout — return it directly.
    if (params.llm_template) {
      if (reportPath) {
        return { content: result.stdout, report: await readReport(reportPath, params.report_format) };
      }
      return { content: result.stdout };
    }

    // Build input→output name mapping using the same logic as the CLI so each
    // result carries the original input path. Process in input order.
    const usedNames = new Set<string>();
    const inputToOutput: [string, string][] = params.files!.map((f) => [
      f,
      uniquifyName(predictOutputName(f), usedNames),
    ]);

    const fileResults: FileResult[] = [];
    for (const [inputPath, outputName] of inputToOutput) {
      const outPath = join(outputDir, outputName);
      if (isArchivePath(inputPath)) {
        // Archives are returned as binary indicators — an LLM can't use a raw
        // archive blob. Caller can re-process individual entries via files[].
        const stat = await Deno.stat(outPath);
        fileResults.push({ input: inputPath, file: outputName, binary: true, size: stat.size });
      } else {
        fileResults.push({ input: inputPath, file: outputName, content: await Deno.readTextFile(outPath) });
      }
    }

    if (reportPath) {
      return { results: fileResults, report: await readReport(reportPath, params.report_format) };
    }
    return { results: fileResults };
  } finally {
    activeCalls--;
    await Deno.remove(tmpDir, { recursive: true });
  }
}

async function toolScan(params: {
  content?: string;
  files?: string[];
  archive_filters?: ArchiveFilter[];
  namespace?: string;
  patterns?: InlinePattern[];
  secrets_file?: string;
  profile?: string;
  format?: string;
  app?: string[];
  allow?: string[];
  fail_on_match?: boolean;
  force_text?: boolean;
  include_binary?: boolean;
  hidden?: boolean;
  exclude_path?: string[];
  include_path?: string[];
  max_archive_depth?: number;
  entropy_threshold?: number;
  strict?: boolean;
}): Promise<unknown> {
  const hasContent = params.content !== undefined;
  const hasFiles = params.files !== undefined && params.files.length > 0;

  if (!hasContent && !hasFiles) {
    throw new Error("Either 'content' or 'files' must be provided");
  }
  if (hasContent && hasFiles) {
    throw new Error("'content' and 'files' are mutually exclusive — provide one or the other");
  }
  if (hasFiles) {
    for (const f of params.files!) {
      if (f.startsWith("-")) throw new Error(`files entry '${f}' must not start with '-' (flag injection)`);
      validatePath(f, "files", true);
      validateFilesPath(f);
    }
  } else {
    checkContentSize(params.content!);
  }
  for (const af of params.archive_filters ?? []) {
    for (const p of af.only ?? []) {
      if (p.startsWith("-")) throw new Error(`archive_filters only pattern '${p}' must not start with '-'`);
    }
    for (const p of af.exclude ?? []) {
      if (p.startsWith("-")) throw new Error(`archive_filters exclude pattern '${p}' must not start with '-'`);
    }
  }
  if (params.secrets_file) validatePath(params.secrets_file, "secrets_file");
  if (params.profile) validatePath(params.profile, "profile");

  if (activeCalls >= MAX_CONCURRENT) {
    throw new Error(`Too many concurrent requests (max ${MAX_CONCURRENT}). Retry after current calls complete.`);
  }
  activeCalls++;
  const tmpDir = await Deno.makeTempDir({ prefix: TEMP_PREFIX });
  try {
    const reportPath = join(tmpDir, "report.json");

    const env: Record<string, string> = {};
    const commonArgs: string[] = ["--dry-run", "--report", reportPath, NO_STRUCTURED_HANDOFF_ARG];

    if (params.format) commonArgs.push("--format", params.format);

    let nsSettings: NsSettings | undefined;
    if (params.namespace) {
      const ns = await resolveNamespace(params.namespace);
      commonArgs.push("-s", ns.secretsFile);
      if (ns.encrypted) {
        commonArgs.push("--encrypted-secrets");
        env.SCOUR_SECRETS_PASSWORD = ns.password!;
      }
      // Explicit profile param overrides namespace profile.
      const profileToUse = params.profile ?? ns.profileFile;
      if (profileToUse) commonArgs.push("--profile", profileToUse);
      // Apply per-namespace behavior defaults before per-call params.
      nsSettings = ns.settings;
      if (nsSettings) appendNsSettingsArgs(commonArgs, nsSettings);
    } else {
      if (params.profile) commonArgs.push("--profile", params.profile);
      if (params.secrets_file) {
        commonArgs.push("-s", params.secrets_file);
      } else if (params.patterns && params.patterns.length > 0) {
        const secretsPath = await writeTempFile(tmpDir, "secrets.json", buildSecretsJson(params.patterns));
        commonArgs.push("-s", secretsPath);
      }
    }

    if (params.app?.length) {
      for (const a of params.app) {
        if (a.startsWith("-")) throw new Error(`app '${a}' must not start with '-' (flag injection)`);
      }
      commonArgs.push("--app", params.app.join(","));
    }
    if (params.allow?.length) {
      for (const pattern of params.allow) {
        if (pattern.startsWith("-")) throw new Error(`allow pattern '${pattern}' must not start with '-' (flag injection)`);
        commonArgs.push("--allow", pattern);
      }
    }
    if (params.fail_on_match) commonArgs.push("--fail-on-match");
    if (params.force_text) commonArgs.push("--force-text");
    if (params.include_binary) commonArgs.push("--include-binary");
    if (params.hidden) commonArgs.push("--hidden");
    if (params.exclude_path?.length) {
      for (const pattern of params.exclude_path) {
        if (pattern.startsWith("-")) throw new Error(`exclude_path '${pattern}' must not start with '-' (flag injection)`);
        commonArgs.push("--exclude-path", pattern);
      }
    }
    if (params.include_path?.length) {
      for (const pattern of params.include_path) {
        if (pattern.startsWith("-")) throw new Error(`include_path '${pattern}' must not start with '-' (flag injection)`);
        commonArgs.push("--include-path", pattern);
      }
    }
    if (params.entropy_threshold !== undefined) {
      commonArgs.push("--entropy-threshold", String(params.entropy_threshold));
    }
    if (params.strict) commonArgs.push("--strict");
    const effectiveMaxArchiveDepth = params.max_archive_depth ?? nsSettings?.max_archive_depth ?? MAX_ARCHIVE_DEPTH;
    commonArgs.push("--max-archive-depth", String(effectiveMaxArchiveDepth));
    commonArgs.push(...THREADS_ARGS);

    let inputArgs: string[];
    let stdinData: string | null;

    if (hasContent) {
      inputArgs = ["-"];
      stdinData = params.content!;
    } else {
      stdinData = null;
      const filterMap = new Map<string, ArchiveFilter>();
      for (const f of params.archive_filters ?? []) filterMap.set(f.path, f);

      inputArgs = [];
      for (const filePath of params.files!) {
        inputArgs.push(filePath);
        const filter = filterMap.get(filePath);
        if (filter?.only?.length) inputArgs.push("--only", ...filter.only);
        if (filter?.exclude?.length) inputArgs.push("--exclude", ...filter.exclude);
      }
    }

    const result = await runSanitize([...inputArgs, ...commonArgs], stdinData, env);

    // Exit code 2 means matches found when --fail-on-match is active — not an error.
    if (result.exitCode === 2 && params.fail_on_match) {
      return { secrets_detected: true, report: JSON.parse(await Deno.readTextFile(reportPath)) };
    }
    if (result.exitCode !== 0) {
      throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
    }

    const report = JSON.parse(await Deno.readTextFile(reportPath));
    return params.fail_on_match ? { secrets_detected: false, report } : report;
  } finally {
    activeCalls--;
    await Deno.remove(tmpDir, { recursive: true });
  }
}

async function toolStripConfigValues(params: {
  content?: string;
  files?: string[];
  delimiter?: string;
  comment_prefix?: string;
}): Promise<string | FileResult[]> {
  const hasContent = params.content !== undefined;
  const hasFiles = params.files !== undefined && params.files.length > 0;

  if (!hasContent && !hasFiles) {
    throw new Error("Either 'content' or 'files' must be provided");
  }
  if (hasContent && hasFiles) {
    throw new Error("'content' and 'files' are mutually exclusive — provide one or the other");
  }
  if (hasFiles) {
    for (const f of params.files!) {
      if (f.startsWith("-")) throw new Error(`files entry '${f}' must not start with '-' (flag injection)`);
      validatePath(f, "files", true);
      validateFilesPath(f);
    }
  } else {
    checkContentSize(params.content!);
  }

  if (activeCalls >= MAX_CONCURRENT) {
    throw new Error(`Too many concurrent requests (max ${MAX_CONCURRENT}). Retry after current calls complete.`);
  }
  activeCalls++;
  const tmpDir = await Deno.makeTempDir({ prefix: TEMP_PREFIX });
  try {
    const delim = params.delimiter ?? "=";
    const commentPfx = params.comment_prefix ?? "#";
    if (delim.startsWith("-")) throw new Error(`delimiter '${delim}' must not start with '-' (flag injection)`);
    if (commentPfx.startsWith("-")) throw new Error(`comment_prefix '${commentPfx}' must not start with '-' (flag injection)`);
    const stripArgs = [
      "--strip-values",
      "--strip-delimiter",
      delim,
      "--strip-comment-prefix",
      commentPfx,
    ];

    if (hasContent) {
      const outputPath = join(tmpDir, "output.txt");
      const result = await runSanitize(["-", "--output", outputPath, ...stripArgs], params.content!);
      if (result.exitCode !== 0) {
        throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
      }
      return await Deno.readTextFile(outputPath);
    }

    const outputDir = join(tmpDir, "out");
    await Deno.mkdir(outputDir);
    const result = await runSanitize([...params.files!, "--output", outputDir, ...stripArgs], null);
    if (result.exitCode !== 0) {
      throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
    }

    const usedNames = new Set<string>();
    const fileResults: FileResult[] = [];
    for (const inputPath of params.files!) {
      const outputName = uniquifyName(predictOutputName(inputPath), usedNames);
      fileResults.push({ input: inputPath, file: outputName, content: await Deno.readTextFile(join(outputDir, outputName)) });
    }
    return fileResults;
  } finally {
    activeCalls--;
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
    if (pat.startsWith("-")) throw new Error(`allow pattern '${pat}' must not start with '-' (flag injection)`);
    args.push("--allow", pat);
  }
  for (const val of params.values) {
    if (val.startsWith("-")) throw new Error(`test value '${val}' must not start with '-' (flag injection)`);
  }
  args.push(...params.values);

  if (activeCalls >= MAX_CONCURRENT) {
    throw new Error(`Too many concurrent requests (max ${MAX_CONCURRENT}). Retry after current calls complete.`);
  }
  activeCalls++;
  try {
    const result = await runSanitize(args, null);
    if (result.exitCode !== 0) {
      throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
    }
    return JSON.parse(result.stdout);
  } finally {
    activeCalls--;
  }
}

async function toolListApps(): Promise<string> {
  if (activeCalls >= MAX_CONCURRENT) {
    throw new Error(`Too many concurrent requests (max ${MAX_CONCURRENT}). Retry after current calls complete.`);
  }
  activeCalls++;
  try {
    const result = await runSanitize(["apps"], null);
    if (result.exitCode !== 0) {
      throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
    }
    return result.stdout;
  } finally {
    activeCalls--;
  }
}

interface BuildSecretsEntry {
  label: string;
  pattern: string;
  kind?: "regex" | "literal" | "entropy";
  category?: string;
}

async function toolBuildSecrets(params: {
  output_path: string;
  entries?: BuildSecretsEntry[];
  preset?: string;
  overwrite?: boolean;
}): Promise<string> {
  validatePath(params.output_path, "output_path");
  validateFilesPath(params.output_path);

  if (!params.overwrite && await fileExists(params.output_path)) {
    throw new Error(
      `File already exists: ${params.output_path}. Pass overwrite: true to replace it.`,
    );
  }

  if (activeCalls >= MAX_CONCURRENT) {
    throw new Error(`Too many concurrent requests (max ${MAX_CONCURRENT}). Retry after current calls complete.`);
  }
  activeCalls++;
  try {
    let content: string;

    if (params.preset) {
      const args = ["template", params.preset, "--output", params.output_path];
      if (params.overwrite) args.push("--overwrite");
      const result = await runSanitize(args, null);
      if (result.exitCode !== 0) {
        throw new Error(`scour-secrets template failed: ${safeStderr(result)}`);
      }
      content = await Deno.readTextFile(params.output_path);
    } else {
      content =
        "# scour secrets file\n" +
        "# Generated by build_secrets. Edit patterns as needed.\n" +
        "# Run: scour-secrets <input> -s " +
        params.output_path +
        " -o <output>\n";
    }

    if (params.entries && params.entries.length > 0) {
      content += "\n# Custom entries\n";
      for (const e of params.entries) {
        const kind = e.kind ?? "literal";
        const patEscaped = e.pattern.replace(/\0/g, '').replace(/'/g, "''");
        content += `- label: ${yamlQuoteString(e.label)}\n`;
        content += `  kind: ${kind}\n`;
        content += `  pattern: '${patEscaped}'\n`;
        if (e.category) content += `  category: ${yamlQuoteString(e.category)}\n`;
        content += "\n";
      }
    }

    await Deno.writeTextFile(params.output_path, content);
    return content;
  } finally {
    activeCalls--;
  }
}

async function toolTestPattern(params: {
  values: string[];
  secrets_file?: string;
  app?: string[];
  patterns?: InlinePattern[];
  namespace?: string;
}): Promise<unknown> {
  if (params.values.length === 0) {
    throw new Error("at least one value is required");
  }
  if (params.secrets_file) validatePath(params.secrets_file, "secrets_file");
  if (
    params.namespace &&
    (params.secrets_file || (params.patterns && params.patterns.length > 0))
  ) {
    throw new Error("namespace cannot be combined with secrets_file or patterns");
  }

  if (activeCalls >= MAX_CONCURRENT) {
    throw new Error(`Too many concurrent requests (max ${MAX_CONCURRENT}). Retry after current calls complete.`);
  }
  activeCalls++;
  const tmpDir = await Deno.makeTempDir({ prefix: TEMP_PREFIX });
  try {
    const env: Record<string, string> = {};
    const args: string[] = ["test-pattern", "--json"];

    if (params.namespace) {
      const ns = await resolveNamespace(params.namespace);
      args.push("-s", ns.secretsFile);
      if (ns.encrypted) {
        args.push("--encrypted-secrets");
        env.SCOUR_SECRETS_PASSWORD = ns.password!;
      }
    } else {
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

    if (params.app?.length) {
      for (const a of params.app) {
        if (a.startsWith("-")) throw new Error(`app '${a}' must not start with '-' (flag injection)`);
      }
      args.push("--app", params.app.join(","));
    }
    for (const val of params.values) {
      if (val.startsWith("-")) throw new Error(`test value '${val}' must not start with '-' (flag injection)`);
    }
    args.push(...params.values);

    const result = await runSanitize(args, null, env);
    // Exit code 1 means some values didn't match — the JSON output is still valid.
    // Detect this by attempting to parse stdout; a real error produces no JSON.
    if (result.exitCode !== 0) {
      if (result.exitCode === 1) {
        try {
          return JSON.parse(result.stdout);
        } catch { /* fall through */ }
      }
      throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
    }
    return JSON.parse(result.stdout);
  } finally {
    activeCalls--;
    await Deno.remove(tmpDir, { recursive: true });
  }
}

// ---------------------------------------------------------------------------
// Shared Zod schemas
// ---------------------------------------------------------------------------

const InlinePatternSchema = z.object({
  name: z.string().describe("Human-readable label for this pattern"),
  pattern: z.string().describe('Regular expression (or literal string when kind is "literal"). For kind "allow", supports exact strings and * glob wildcards.'),
  category: z
    .string()
    .optional()
    .describe(
      'Replacement category. Required when kind is "regex" or "literal"; ignored (and may be omitted) when kind is "allow". Built-in: "email", "name", "phone", "ipv4", "ipv6", "hostname", "mac_address", "uuid", "jwt", "auth_token", "credit_card", "ssn", "container_id", "file_path", "windows_sid", "url", "aws_arn", "azure_resource_id". Use "custom:<tag>" for anything else.',
    ),
  kind: z
    .enum(["regex", "literal", "allow"])
    .optional()
    .describe('Match kind: "literal" (default) for exact string matching, "regex" for regular expression matching, or "allow" to pass the value through unchanged without replacement or recording. Omit to get literal matching.'),
});

const FormatSchema = z
  .enum(["text", "json", "jsonl", "ndjson", "yaml", "yml", "xml", "csv", "tsv", "key-value", "toml", "env", "ini", "log"])
  .optional()
  .describe(
    "Force input format, overriding file-extension detection. Required when the content type cannot be inferred from a filename. When used with `files`, applies to every file in the list — only set this when all inputs are the same format. Aliases: `yml` = `yaml`, `ndjson` = `jsonl`, `tsv` = `csv` with tab delimiter. Supported formats: json, yaml, toml, xml, csv, jsonl, key-value, env, ini, log, text.",
  );

const NamespaceSchema = z
  .string()
  .optional()
  .describe(
    "Customer or tenant namespace for operator/multi-tenant deployments where each customer or environment has its own pre-configured secrets file. Resolves secrets, profile, and password from $SCOUR_SECRETS_SECRETS_DIR/{namespace}/. Takes priority over secrets_file and patterns. Must be alphanumeric with hyphens/underscores only. Requires SCOUR_SECRETS_SECRETS_DIR to be set.",
  );

const ArchiveFilterSchema = z.object({
  path: z.string().describe(
    "Path to the archive file this filter applies to. Must match exactly how the path appears in `files`.",
  ),
  only: z.array(z.string()).optional().describe(
    "Glob patterns for archive entries to include. Only entries matching at least one pattern are processed. Directory prefixes end with '/' (e.g. 'logs/'). Equivalent to the CLI --only flag.",
  ),
  exclude: z.array(z.string()).optional().describe(
    "Glob patterns for archive entries to exclude. Matched entries are skipped entirely. Equivalent to the CLI --exclude flag.",
  ),
});

const SanitizeSchema = {
  content: z.string().optional().describe(
    "Inline text content to sanitize. Only use this when you already have the text in your context and there is no file path available. If you have a file path, use `files` instead — it is safer, handles binary and archive formats correctly, and avoids loading raw bytes into the LLM context. Mutually exclusive with `files`. Either this or `files` must be provided.",
  ),
  files: z.array(z.string()).optional().describe(
    "PREFERRED: one or more file paths to sanitize (absolute or relative). Use this whenever a file path is available instead of reading the file and passing its content inline. Accepts plain files, archives (.zip, .tar.gz, etc.), or a mix. Archives are extracted and sanitized recursively. Use `archive_filters` to restrict which entries inside an archive are processed. Mutually exclusive with `content`. Raw file content never enters the LLM context — the sanitize engine processes files directly.",
  ),
  output_file: z.string().optional().describe(
    "Write the sanitized output directly to this file path. The sanitized content is NOT returned in the response — only the output path and byte size are reported. Mirrors `scour-secrets <input> -o <file>`. Valid for a single `files` entry or `content` input. Mutually exclusive with `output_dir`.",
  ),
  output_dir: z.string().optional().describe(
    "Write sanitized outputs directly into this directory. The sanitized content is NOT returned in the response — only the output paths are reported. Mirrors `scour-secrets <inputs> -o <dir>`. Valid for any number of `files` inputs or `content` input. The directory is created if it does not exist. Mutually exclusive with `output_file`.",
  ),
  archive_filters: z.array(ArchiveFilterSchema).optional().describe(
    "Per-archive entry filters. Each entry pairs an archive path (must match exactly what appears in `files`) with --only and/or --exclude glob patterns. Non-archive paths in `files` are unaffected.",
  ),
  namespace: NamespaceSchema,
  seed: z
    .string()
    .optional()
    .describe(
      "Optional seed string for deterministic replacements. Same seed → same replacements across calls on the same input. Without a seed, replacements are randomised per call. Treat the seed as a secret — it makes the token mapping predictable, which could allow reconstruction of original values if the seed is leaked.",
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
  app: z
    .array(z.string())
    .optional()
    .describe(
      "Built-in app bundle names to load (e.g. ['gitlab', 'nginx']). Each bundle adds app-specific secrets patterns and a structured field profile. Additive with secrets_file and profile.",
    ),
  allow: z
    .array(z.string())
    .optional()
    .describe(
      "Values to pass through unchanged (not replaced, not recorded in the mapping store). Supports exact strings, * glob patterns, and regex:<pattern> for full regex matching — e.g. 'localhost', '*.internal', '192.168.1.*', 'regex:^10\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+'.",
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
      "Additional keywords to flag. Merged with built-in defaults (error, failure, warning, warn, fatal, exception, critical) unless context_keywords_replace is true. Only used when extract_context is true.",
    ),
  context_keywords_replace: z
    .boolean()
    .optional()
    .describe(
      "When true, context_keywords replaces the built-in default keyword list entirely instead of being merged with it. Only used when extract_context and context_keywords are both set.",
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
  llm_template: z
    .string()
    .optional()
    .describe(
      "Format the sanitized output as an LLM-ready prompt and return it instead of raw sanitized bytes. Built-in templates: 'troubleshoot' (incident triage), 'review-config' (configuration audit), 'review-security' (security posture review). Pass a filesystem path for a custom template file. Combine with extract_context to include notable log events in the prompt.",
    ),
  force_text: z
    .boolean()
    .optional()
    .describe(
      "Bypass all structured processors (JSON, YAML, XML, TOML, etc.) and run only the streaming scanner on every file. Use when format is uncertain or when guaranteed full-byte pattern coverage is required.",
    ),
  include_binary: z
    .boolean()
    .optional()
    .describe(
      "Process binary entries inside archives (default: skip). Enable when archives contain binary files that should be scanned.",
    ),
  hidden: z
    .boolean()
    .optional()
    .describe(
      "Also walk hidden files and directories (names starting with '.'). By default dot-files are skipped when expanding directories.",
    ),
  exclude_path: z
    .array(z.string())
    .optional()
    .describe(
      "Glob patterns for paths to exclude from processing. Matched relative to the input; patterns without '/' also match the basename. E.g. ['*.test.yaml', 'fixtures/**']. When both exclude_path and include_path match a file, exclusion wins.",
    ),
  include_path: z
    .array(z.string())
    .optional()
    .describe(
      "Glob patterns for paths to include during directory walks. Only files matching at least one pattern are processed; all others are skipped. Patterns without '/' also match the bare filename. Has no effect on explicitly named file arguments or archive entries. When both include_path and exclude_path match a file, exclusion wins. E.g. ['**/*.log', '**/*.conf'].",
    ),
  entropy_threshold: z
    .number()
    .min(0)
    .max(8)
    .optional()
    .describe(
      "Shannon entropy threshold for high-entropy token detection (0–8 bits per character). Strings whose entropy exceeds this value are treated as secrets and replaced. Typical secrets sit above 4.5; random UUIDs sit around 3.8. Only applied when no secrets entry with kind: entropy already exists.",
    ),
  max_archive_depth: z
    .number()
    .int()
    .min(1)
    .max(10)
    .optional()
    .describe(
      `Maximum nesting depth for recursive archive processing (default: ${MAX_ARCHIVE_DEPTH}). Increase for deeply nested archives; decrease to tighten zip-bomb protection.`,
    ),
  report: z
    .boolean()
    .optional()
    .describe(
      "When true, also generate a scan report alongside the sanitized output. The response becomes { content/results, report } instead of plain text. Use extract_context instead if you also want per-match log context.",
    ),
  report_format: z
    .enum(["json", "sarif", "html"])
    .optional()
    .describe(
      "Output format for the report (requires report: true). json (default): structured JSON; sarif: SARIF 2.1.0 for GitHub Advanced Security / VS Code / SIEMs; html: self-contained human-readable summary.",
    ),
  strict: z
    .boolean()
    .optional()
    .describe(
      "Abort on the first processing error instead of skipping and continuing. Useful in CI pipelines where a partial result is worse than a failure.",
    ),
};

const ScanSchema = {
  content: z.string().optional().describe(
    "Inline text content to scan. Only use this when you already have the text in your context and there is no file path available. If you have a file path, use `files` instead. Mutually exclusive with `files`. Either this or `files` must be provided.",
  ),
  files: z.array(z.string()).optional().describe(
    "PREFERRED: one or more file paths to scan (absolute or relative). Use this whenever a file path is available instead of reading the file and passing its content inline. Accepts plain files, archives, or a mix. Use `archive_filters` to restrict which archive entries are scanned. Mutually exclusive with `content`.",
  ),
  archive_filters: z.array(ArchiveFilterSchema).optional().describe(
    "Per-archive entry filters applied during scanning. Same semantics as on the sanitize tool.",
  ),
  namespace: NamespaceSchema,
  patterns: z
    .array(InlinePatternSchema)
    .optional()
    .describe("Inline regex/literal/allow patterns to scan for. Use kind: 'allow' entries to suppress known-safe values from the report."),
  secrets_file: z
    .string()
    .optional()
    .describe("Path to a secrets file. Takes priority over patterns."),
  profile: z
    .string()
    .optional()
    .describe(
      "Path to a field-level profile YAML/JSON file defining which structured fields to scan. Overrides the namespace profile when both are present.",
    ),
  app: z
    .array(z.string())
    .optional()
    .describe(
      "Built-in app bundle names to load (e.g. ['gitlab', 'nginx']). Each bundle adds app-specific secrets patterns and a structured field profile. Additive with secrets_file. Call list_apps to see all available names.",
    ),
  allow: z
    .array(z.string())
    .optional()
    .describe(
      "Values to exclude from the scan report. Supports exact strings, * glob patterns, and regex:<pattern> for full regex matching. Useful for suppressing known-safe values that would otherwise appear as false positives. Use test_allowlist to verify patterns before applying them.",
    ),
  format: FormatSchema,
  fail_on_match: z
    .boolean()
    .optional()
    .describe(
      "When true, the response includes a `secrets_detected` boolean flag. If any secrets are found the flag is true (CLI exits with code 2); if none are found it is false. Useful for security-gate workflows where callers need a simple yes/no without parsing the full report.",
    ),
  force_text: z
    .boolean()
    .optional()
    .describe(
      "Bypass all structured processors and run only the streaming scanner. Use when format is uncertain or guaranteed full-byte coverage is required.",
    ),
  include_binary: z
    .boolean()
    .optional()
    .describe("Process binary entries inside archives (default: skip)."),
  hidden: z
    .boolean()
    .optional()
    .describe(
      "Also walk hidden files and directories (names starting with '.'). By default dot-files are skipped when expanding directories.",
    ),
  exclude_path: z
    .array(z.string())
    .optional()
    .describe(
      "Glob patterns for paths to exclude from scanning. Matched relative to the input; patterns without '/' also match the basename. When both exclude_path and include_path match a file, exclusion wins.",
    ),
  include_path: z
    .array(z.string())
    .optional()
    .describe(
      "Glob patterns for paths to include during directory walks. Only files matching at least one pattern are scanned; all others are skipped. Patterns without '/' also match the bare filename. Has no effect on explicitly named file arguments or archive entries. When both include_path and exclude_path match a file, exclusion wins.",
    ),
  entropy_threshold: z
    .number()
    .min(0)
    .max(8)
    .optional()
    .describe(
      "Shannon entropy threshold for high-entropy token detection (0–8 bits per character). Strings whose entropy exceeds this value are flagged as secrets.",
    ),
  max_archive_depth: z
    .number()
    .int()
    .min(1)
    .max(10)
    .optional()
    .describe(
      `Maximum nesting depth for recursive archive processing (default: ${MAX_ARCHIVE_DEPTH}).`,
    ),
  strict: z
    .boolean()
    .optional()
    .describe(
      "Abort on the first processing error instead of skipping and continuing.",
    ),
};

const StripSchema = {
  content: z.string().optional().describe(
    "Inline configuration content to strip values from. Mutually exclusive with `files`. Either this or `files` must be provided.",
  ),
  files: z.array(z.string()).optional().describe(
    "One or more paths to strip values from (absolute or relative). Mutually exclusive with `content`.",
  ),
  delimiter: z.string().max(10).optional().describe('Key-value delimiter (default: "=")'),
  comment_prefix: z.string().max(20).optional().describe('Comment prefix character (default: "#")'),
};

type SanitizeParams = z.infer<z.ZodObject<typeof SanitizeSchema>>;
type ScanParams = z.infer<z.ZodObject<typeof ScanSchema>>;
type StripParams = z.infer<z.ZodObject<typeof StripSchema>>;

// ---------------------------------------------------------------------------
// Server setup
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "scour-secrets-engine",
  version: SERVER_VERSION,
});

server.tool(
  "sanitize",
  "Replace sensitive values in text content or files with safe placeholders before the LLM reads them. This tool MODIFIES content — run scan first if you want to preview what will be replaced without committing. Prefer `files` (file paths) over `content` (inline text) whenever you have a path — the engine processes files directly so raw bytes never enter the LLM context, and binary/archive inputs are handled correctly. Zero-config start: omit secrets_file, namespace, and patterns and the engine automatically applies built-in patterns covering API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic), JWTs, emails, IPs, and more. The primary MCP use case: pipe logs or configs through this tool, then reason over the safe output. Set `llm_template: 'troubleshoot'` to get a fully-formatted incident-triage prompt ready to paste; set `llm_template: 'review-config'` for a configuration-audit prompt — these are the two most common end-to-end workflows. Structured fields (passwords, tokens, API keys) are replaced with __SANITIZED-<hash>__ markers; typed values (emails, IPs) get realistic-looking substitutes of the same format. Archives are extracted and sanitized recursively. Supply a `seed` for consistent replacements across multiple calls in a session.",
  SanitizeSchema,
  async (params: SanitizeParams) => {
    try {
      const result = await toolSanitize(params);
      // Inline content-mode returns plain text; everything else (files-mode,
      // write-to-disk mode, report responses) is serialised as JSON.
      const text = result.content !== undefined && result.results === undefined && result.report === undefined && !result.written
        ? result.content
        : JSON.stringify(result, null, 2);
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
  "Read-only audit — detects sensitive values and returns a structured JSON report without modifying any files. Run this before sanitize to preview what will be replaced, or as a security gate in CI pipelines. Prefer `files` (file paths) over `content` (inline text) whenever a path is available. Zero-config start: omit secrets_file, namespace, and patterns and the engine automatically applies built-in detection patterns (API keys, JWTs, emails, IPs, and more). Use `fail_on_match` for binary yes/no security-gate workflows: the response includes a `secrets_detected` boolean so callers can branch without parsing the full report. Typical workflow: scan with no pattern source → observe gaps → build_secrets to add missing patterns → sanitize with the new file.",
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
  "Strip ALL values from key=value configuration files, preserving only keys, comments, section headers, and delimiters. Use this when you want to share configuration structure without any values — the result is not suitable for LLM reasoning (values are gone, not replaced). Use sanitize instead when you need values replaced with realistic-looking substitutes so the LLM can reason about the content. Accepts inline `content` or one or more file paths via `files`.",
  StripSchema,
  async (params: StripParams) => {
    try {
      const stripped = await toolStripConfigValues(params);
      const text = typeof stripped === "string" ? stripped : JSON.stringify(stripped, null, 2);
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
  "test_allowlist",
  "Verify that allowlist patterns cover the expected values before passing them to sanitize or scan via the `allow` parameter. Returns a per-value match result showing which pattern matched (or that no pattern matched), plus a summary count. Use this when you are seeing false positives in scan output and want to confirm that your allow patterns would suppress them correctly.",
  {
    patterns: z
      .array(z.string())
      .min(1)
      .describe("Allowlist patterns to test. Supports exact strings, * glob wildcards, and regex:<pattern> for full regex matching — e.g. 'localhost', '*.internal', '192.168.1.*', 'regex:^10\\\\.[0-9]+'."),
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
  "list_apps",
  "List all available app bundles (built-in and user-defined) that can be passed to the `app` parameter of sanitize or scan. Call this before using `app` to confirm the bundle name — passing an unknown name to sanitize/scan will error. Shows bundle names, descriptions, and the user apps directory path.",
  {},
  async () => {
    try {
      const text = await toolListApps();
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
  "init",
  "One-step project setup: create a starter secrets file on disk from a built-in preset. Use this when a user wants to start using scour-secrets-engine — it generates a ready-to-use YAML secrets file they can run immediately. For more control (adding patterns discovered by scan), use build_secrets instead. Call init when the user asks how to create a secrets file or wants to get started quickly.",
  {
    output_path: z
      .string()
      .describe("Relative path where the secrets YAML file should be written (e.g. 'secrets.yaml' or 'config/secrets.yaml')."),
    preset: z
      .enum(["balanced", "aggressive", "generic", "web", "k8s", "database", "aws"])
      .optional()
      .describe("Pattern preset to use. balanced (default — mirrors the built-in runtime detection set, fully editable), aggressive (balanced + entropy/bearer/container-ID patterns), generic (minimal), web (JWTs/sessions/emails), k8s (service accounts/tokens), database (passwords/connection strings), aws (access keys/ARNs)."),
    overwrite: z
      .boolean()
      .optional()
      .describe("Overwrite the file if it already exists. Defaults to false."),
  },
  async (params: {
    output_path: string;
    preset?: "balanced" | "aggressive" | "generic" | "web" | "k8s" | "database" | "aws";
    overwrite?: boolean;
  }) => {
    try {
      validatePath(params.output_path, "output_path");
      validateFilesPath(params.output_path);
      const args = ["template", "--output", params.output_path];
      if (params.preset) args.push(params.preset);
      if (params.overwrite) args.push("--overwrite");
      if (activeCalls >= MAX_CONCURRENT) {
        throw new Error(`Too many concurrent requests (max ${MAX_CONCURRENT}). Retry after current calls complete.`);
      }
      activeCalls++;
      let result: RunResult;
      try {
        result = await runSanitize(args, null);
      } finally {
        activeCalls--;
      }
      if (result.exitCode !== 0) {
        throw new Error(`scour-secrets exited with code ${result.exitCode}: ${safeStderr(result)}`);
      }
      const preset = params.preset ?? "generic";
      let fileContent = "";
      try {
        fileContent = await Deno.readTextFile(params.output_path);
      } catch {
        // Non-fatal: file read failure just omits the content preview.
      }
      const preview = fileContent ? `\n\n--- ${params.output_path} ---\n${fileContent}` : "";
      const text = `Created secrets file: ${params.output_path}\nPreset: ${preset}\n\nNext steps:\n  1. Edit the file to add patterns specific to your environment\n  2. Run: scour-secrets <files> -s ${params.output_path}\n  3. Or encrypt it: scour-secrets encrypt ${params.output_path} ${params.output_path}.enc --password${preview}`;
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
  "test_pattern",
  "WARNING: test values are echoed back verbatim in the response — never pass real secrets. Use synthetic or anonymised examples only. — Test which values are matched and replaced by a given secrets file, app bundle, or inline pattern set, without modifying any files. Returns a per-value result showing which pattern matched and what replacement category was applied. Typical workflow: build_secrets → test_pattern with synthetic examples → sanitize with confidence.",
  {
    values: z
      .array(z.string())
      .min(1)
      .describe("Synthetic or anonymised values to test against the active patterns. These are returned verbatim in the response — never pass real secrets here."),
    secrets_file: z
      .string()
      .optional()
      .describe("Path to a secrets YAML/JSON/TOML file. Takes priority over patterns."),
    app: z
      .array(z.string())
      .optional()
      .describe("Built-in app bundle names to load (e.g. ['gitlab', 'nginx'])."),
    patterns: z
      .array(InlinePatternSchema)
      .optional()
      .describe("Inline patterns to test against. Ignored when secrets_file is supplied."),
    namespace: NamespaceSchema,
  },
  async (params: {
    values: string[];
    secrets_file?: string;
    app?: string[];
    patterns?: InlinePattern[];
    namespace?: string;
  }) => {
    try {
      const report = await toolTestPattern(params);
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
  "build_secrets",
  "Build a tailored secrets file from specific patterns and write it to disk. Use this after scanning content and identifying what the default patterns missed — supply the exact literals or regexes you need and optionally start from a preset template. Returns the written file content. For a quick no-customisation start, use init instead. Recommended workflow: scan with no pattern source (auto-defaults) → observe gaps in the report → build_secrets with the missing patterns → test_pattern with synthetic examples → sanitize with the new file.",
  {
    output_path: z
      .string()
      .describe("Relative path where the secrets YAML file should be written (e.g. 'secrets.yaml')."),
    entries: z
      .array(
        z.object({
          label: z.string().describe("Human-readable name shown in reports."),
          pattern: z.string().describe("The literal string or regex pattern to match."),
          kind: z
            .enum(["literal", "regex", "entropy"])
            .optional()
            .describe("Match kind. 'literal' (default) for exact strings, 'regex' for patterns, 'entropy' for high-entropy token detection."),
          category: z
            .string()
            .optional()
            .describe(
              "Replacement category. Required for regex/literal. Built-in: email, name, ipv4, ipv6, hostname, uuid, jwt, auth_token, url, aws_arn, custom:<tag>.",
            ),
        }),
      )
      .optional()
      .describe("Specific patterns to include. Can be combined with a preset — custom entries are appended after the preset patterns."),
    preset: z
      .enum(["balanced", "aggressive", "generic", "web", "k8s", "database", "aws"])
      .optional()
      .describe("Start from this built-in template. balanced = runtime defaults (recommended starting point); aggressive = balanced + entropy/bearer patterns. Omit to create a file with only the entries you specify."),
    overwrite: z
      .boolean()
      .optional()
      .describe("Overwrite the file if it already exists. Defaults to false."),
  },
  async (params: {
    output_path: string;
    entries?: BuildSecretsEntry[];
    preset?: "balanced" | "aggressive" | "generic" | "web" | "k8s" | "database" | "aws";
    overwrite?: boolean;
  }) => {
    try {
      const content = await toolBuildSecrets(params);
      const preset = params.preset ? `\nPreset: ${params.preset}` : "";
      const custom = params.entries?.length
        ? `\nCustom entries added: ${params.entries.length}`
        : "";
      const text = `Created secrets file: ${params.output_path}${preset}${custom}\n\n--- ${params.output_path} ---\n${content}`;
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
  "list_processors",
  "List all supported input format processors (json, yaml, toml, csv, jsonl, etc.) and the format_flag value to pass as the `format` parameter to sanitize or scan. Most file types are auto-detected by extension — only call this when format detection fails (e.g. extensionless files, stdin input, or an unfamiliar extension).",
  {},
  async () => {
    const processors = [
      { name: "json",       format_flag: "json",      description: "JSON objects and arrays" },
      { name: "yaml",       format_flag: "yaml",      description: "YAML documents" },
      { name: "toml",       format_flag: "toml",      description: "TOML configuration files" },
      { name: "xml",        format_flag: "xml",       description: "XML documents" },
      { name: "csv",        format_flag: "csv",       description: "Comma-separated values" },
      { name: "jsonl",      format_flag: "jsonl",     description: "Newline-delimited JSON (one object per line)" },
      { name: "key_value",  format_flag: "key-value", description: "Key=value pairs (e.g. .env files)" },
      { name: "env",        format_flag: "env",       description: "Shell environment files (KEY=VALUE)" },
      { name: "ini",        format_flag: "ini",       description: "INI configuration files with [sections]" },
      { name: "log",        format_flag: "log",       description: "Unstructured log files (scanner only)" },
      { name: "text",       format_flag: "text",      description: "Plain text (scanner only; default for unknown extensions)" },
    ];
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          processors,
          note: "Pass the format_flag value as the `format` parameter to sanitize or scan when auto-detection is insufficient.",
        }, null, 2),
      }],
    };
  },
);

server.tool(
  "list_templates",
  "List the built-in LLM prompt templates available via the `llm_template` parameter of the sanitize tool. Each template wraps the sanitized output in a ready-to-use prompt for a specific analysis task (troubleshooting, config review, security review). Call this when the user asks what templates are available or wants to know what llm_template values are valid.",
  {},
  async () => {
    const templates = [
      {
        name: "troubleshoot",
        description: "Incident triage: asks the LLM to identify root cause, event sequence, and remediation steps from sanitized logs.",
      },
      {
        name: "review-config",
        description: "Configuration audit: asks the LLM to flag misconfigurations, security concerns, and best-practice violations.",
      },
      {
        name: "review-security",
        description: "Security posture review: asks the LLM to assess authentication, network exposure, TLS settings, hardcoded secrets, and known CVEs.",
      },
    ];
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          templates,
          note: "Pass the template name as llm_template to the sanitize tool, e.g. { llm_template: 'troubleshoot' }.",
        }, null, 2),
      }],
    };
  },
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const httpFlagIdx = Deno.args.indexOf("--http");
let httpPort = NaN;
if (httpFlagIdx !== -1) {
  const nextArg = Deno.args[httpFlagIdx + 1];
  if (nextArg !== undefined && !nextArg.startsWith("-")) {
    const parsed = parseInt(nextArg, 10);
    if (isNaN(parsed)) {
      console.error(`error: --http requires a numeric port, got "${nextArg}"`);
      Deno.exit(1);
    }
    httpPort = parsed;
  } else {
    httpPort = DEFAULT_HTTP_PORT;
  }
}

if (!isNaN(httpPort)) {
  if (httpPort < 1 || httpPort > 65535) {
    console.error(`error: --http port must be between 1 and 65535, got ${httpPort}`);
    Deno.exit(1);
  }
  const token = Deno.env.get("SCOUR_SECRETS_MCP_HTTP_TOKEN");
  if (!token) {
    console.error("error: SCOUR_SECRETS_MCP_HTTP_TOKEN must be set when using --http");
    Deno.exit(1);
  }

  const expectedAuth = `Bearer ${token}`;
  // Constant-time comparison over fixed-length SHA-256 digests: avoids both the
  // short-circuit timing oracle of `!==` and leaking the token length.
  const tokensMatch = async (provided: string | null): Promise<boolean> => {
    if (provided === null) return false;
    const enc = new TextEncoder();
    const [a, b] = await Promise.all([
      crypto.subtle.digest("SHA-256", enc.encode(provided)),
      crypto.subtle.digest("SHA-256", enc.encode(expectedAuth)),
    ]);
    const av = new Uint8Array(a);
    const bv = new Uint8Array(b);
    let diff = 0;
    for (let i = 0; i < av.length; i++) diff |= av[i] ^ bv[i];
    return diff === 0;
  };
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
    onsessionclosed: () => {
      // Client sent DELETE — exit cleanly so the service manager restarts the
      // daemon and it can accept a new session on reconnect.
      console.error("scour-secrets-mcp: session closed, restarting for reconnection");
      Deno.exit(0);
    },
  });
  await server.connect(transport);

  Deno.serve({
    hostname: "127.0.0.1",
    port: httpPort,
    onListen: ({ port }) => {
      // Explicit startup message to stderr; suppresses Deno's default stdout line.
      console.error(`scour-secrets-mcp daemon ready on 127.0.0.1:${port}`);
    },
    onError: (err) => {
      // Log only the error class name — never the message or stack, which may
      // contain JSON-RPC payload data (file paths, etc.).
      console.error(`scour-secrets-mcp: unhandled error: ${(err as Error).name}`);
      return new Response("Internal Server Error", { status: 500 });
    },
  }, async (req) => {
    if (new URL(req.url).pathname !== "/mcp") {
      return new Response("Not Found", { status: 404 });
    }
    if (!(await tokensMatch(req.headers.get("Authorization")))) {
      return new Response("Unauthorized", { status: 401 });
    }
    return transport.handleRequest(req);
  });
} else {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
