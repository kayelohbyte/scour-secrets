/**
 * Subprocess environment scrubbing.
 *
 * The sanitize subprocess receives only runtime essentials and SANITIZE_* vars.
 * The rest of the parent environment — which may hold secrets like
 * AWS_SECRET_ACCESS_KEY, DATABASE_URL, or GITHUB_TOKEN — is dropped so it never
 * reaches the child process. Pure and parameterised so it can be unit-tested
 * without spawning the server.
 */

/** Non-secret runtime variables forwarded to the subprocess when present. */
export const SUBPROCESS_ENV_ALLOWLIST = [
  "PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TEMP", "TMP",
  "LANG", "LC_ALL", "LC_CTYPE", "TERM", "SystemRoot", "USERPROFILE",
] as const;

/**
 * Filter `parent` down to the allowlisted runtime vars plus every SANITIZE_*
 * var. SANITIZE_LOG is then forced to "error" (overridable only by extraEnv) so
 * a parent SANITIZE_LOG can't make the subprocess chatty on stdio.
 */
export function scrubEnv(
  parent: Record<string, string>,
  extraEnv: Record<string, string> = {},
): Record<string, string> {
  const allowed: Record<string, string> = {};
  for (const k of SUBPROCESS_ENV_ALLOWLIST) {
    if (parent[k] !== undefined) allowed[k] = parent[k];
  }
  for (const [k, v] of Object.entries(parent)) {
    if (k.startsWith("SANITIZE_")) allowed[k] = v;
  }
  return { ...allowed, SANITIZE_LOG: "error", ...extraEnv };
}
