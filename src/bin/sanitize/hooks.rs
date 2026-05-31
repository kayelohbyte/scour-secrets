use crate::cli_args::{HookMode, HookType, InstallHookArgs};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

// ─── install-hook implementation ─────────────────────────────────────────────

/// Sentinel embedded in every installed hook so we can identify and remove it.
pub(crate) const HOOK_MARKER: &str = "# installed-by: rust-sanitize";

/// Minimum version string embedded in the hook for runtime compatibility checks.
const HOOK_MIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run `git <args>` and return trimmed stdout, or an error string.
fn git_output(args: &[&str]) -> Result<String, String> {
    let out = process::Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Returns the per-user sanitize config directory.
///
/// - **Windows**: `%APPDATA%\sanitize\` (falls back to `%USERPROFILE%\.config\sanitize\`).
/// - **Unix/macOS**: `$XDG_CONFIG_HOME/sanitize/` (falls back to `~/.config/sanitize/`).
pub(crate) fn sanitize_config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        // Prefer %APPDATA% (roaming profile — survives account moves).
        // Fall back to %USERPROFILE%\.config to match XDG-like tooling in Git Bash.
        let base = std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::var("USERPROFILE")
                    .map(|p| PathBuf::from(p).join(".config"))
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
        return base.join("sanitize");
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
            });
        base.join("sanitize")
    }
}

/// Returns the path to the global default secrets file.
/// Auto-loaded when no explicit `--secrets-file` is given.
pub(crate) fn global_default_secrets_path() -> PathBuf {
    sanitize_config_dir().join("secrets.yaml")
}

/// Returns the path to the global settings file.
pub(crate) fn global_settings_path() -> PathBuf {
    sanitize_config_dir().join("settings.yaml")
}

/// Locate the .git/hooks directory for the current repository.
pub(crate) fn find_project_hooks_dir() -> Result<PathBuf, (String, i32)> {
    let git_dir = git_output(&["rev-parse", "--git-dir"])
        .map_err(|_| ("not inside a git repository".to_string(), 1))?;
    Ok(PathBuf::from(git_dir).join("hooks"))
}

/// Locate the global git hooks directory.
///
/// Uses `git config --global core.hooksPath` if set (recommended on all
/// platforms). Otherwise falls back to the platform-specific default:
///
/// - **Windows**: `%APPDATA%\git\hooks` (falls back to `%USERPROFILE%\.config\git\hooks`).
/// - **Unix/macOS**: `$XDG_CONFIG_HOME/git/hooks` → `~/.config/git/hooks`.
pub(crate) fn find_global_hooks_dir() -> Result<PathBuf, (String, i32)> {
    if let Ok(p) = git_output(&["config", "--global", "core.hooksPath"]) {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    #[cfg(windows)]
    {
        let base = std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::var("USERPROFILE")
                    .map(|p| PathBuf::from(p).join(".config"))
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
        return Ok(base.join("git").join("hooks"));
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(".config")
            });
        Ok(base.join("git").join("hooks"))
    }
}

/// Find the root of the current git repository (the directory containing .git).
pub(crate) fn find_git_root() -> Result<PathBuf, (String, i32)> {
    git_output(&["rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        .map_err(|_| ("not inside a git repository".to_string(), 1))
}

/// Shell-quote a string value for safe embedding in a POSIX sh script.
pub(crate) fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Build the sanitize flags string for the hook invocation, based on the
/// configured options.  Values are shell-quoted so paths with spaces work.
pub(crate) fn build_hook_flags(args: &InstallHookArgs) -> String {
    let mut flags: Vec<String> = Vec::new();
    if let Some(ref app) = args.app {
        flags.push(format!("--app {}", sh_quote(app)));
    }
    if let Some(ref s) = args.secrets_file {
        flags.push(format!("-s {}", sh_quote(&s.to_string_lossy())));
    }
    flags.join(" ")
}

/// Build the complete POSIX sh hook script for pre-commit scan mode.
pub(crate) fn hook_script_pre_commit_scan(flags: &str) -> String {
    format!(
        r#"#!/bin/sh
{marker}
# requires sanitize >= {min_version}
# Scans staged files for secrets before each commit.
# Skip for one commit:  SANITIZE_SKIP=1 git commit ...
# Uninstall:            sanitize install-hook --remove

[ "${{SANITIZE_SKIP:-0}}" = "1" ] && exit 0

STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)
[ -z "$STAGED" ] && exit 0

if ! command -v sanitize >/dev/null 2>&1; then
  printf 'sanitize: not found in PATH — hook skipped\n' >&2
  exit 0
fi

_ver=$(sanitize --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
_req="{min_version}"
if [ -n "$_ver" ] && [ "$(printf '%s\n' "$_req" "$_ver" | sort -V | head -1)" != "$_req" ]; then
  printf 'sanitize: hook requires >= %s but found %s — update with: cargo install rust-sanitize\n' "$_req" "$_ver" >&2
  exit 1
fi

# shellcheck disable=SC2086
printf '%s\n' "$STAGED" | tr '\n' '\0' | xargs -0 \
  sanitize --dry-run --fail-on-match {flags}

EXIT=$?
if [ "$EXIT" -eq 2 ]; then
  printf '\nsanitize: secrets detected in staged files — commit blocked.\n' >&2
  printf '  Sanitize the file(s), then re-stage and commit.\n' >&2
  printf '  Skip once with:  SANITIZE_SKIP=1 git commit ...\n' >&2
  exit 1
fi
[ "$EXIT" -ne 0 ] && printf 'sanitize: unexpected exit code %d\n' "$EXIT" >&2
exit 0
"#,
        marker = HOOK_MARKER,
        min_version = HOOK_MIN_VERSION,
        flags = flags,
    )
}

/// Build the complete POSIX sh hook script for pre-commit sanitize mode.
fn hook_script_pre_commit_sanitize(flags: &str) -> String {
    format!(
        r#"#!/bin/sh
{marker}
# requires sanitize >= {min_version}
# Sanitizes staged files in place before each commit, then re-stages them.
# WARNING: the committed content will differ from what you typed.
# Skip for one commit:  SANITIZE_SKIP=1 git commit ...
# Uninstall:            sanitize install-hook --remove

[ "${{SANITIZE_SKIP:-0}}" = "1" ] && exit 0

STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)
[ -z "$STAGED" ] && exit 0

if ! command -v sanitize >/dev/null 2>&1; then
  printf 'sanitize: not found in PATH — hook skipped\n' >&2
  exit 0
fi

_ver=$(sanitize --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
_req="{min_version}"
if [ -n "$_ver" ] && [ "$(printf '%s\n' "$_req" "$_ver" | sort -V | head -1)" != "$_req" ]; then
  printf 'sanitize: hook requires >= %s but found %s — update with: cargo install rust-sanitize\n' "$_req" "$_ver" >&2
  exit 1
fi

# shellcheck disable=SC2086
printf '%s\n' "$STAGED" | tr '\n' '\0' | xargs -0 \
  sanitize --output . {flags}

EXIT=$?
if [ "$EXIT" -ne 0 ]; then
  printf 'sanitize: failed to sanitize staged files (exit %d) — commit blocked\n' "$EXIT" >&2
  exit 1
fi

printf '%s\n' "$STAGED" | tr '\n' '\0' | xargs -0 git add
exit 0
"#,
        marker = HOOK_MARKER,
        min_version = HOOK_MIN_VERSION,
        flags = flags,
    )
}

/// Build the complete POSIX sh hook script for pre-push scan mode.
fn hook_script_pre_push_scan(flags: &str) -> String {
    format!(
        r#"#!/bin/sh
{marker}
# requires sanitize >= {min_version}
# Scans files changed in commits about to be pushed for secrets.
# Skip for one push:  SANITIZE_SKIP=1 git push ...
# Uninstall:          sanitize install-hook --hook pre-push --remove

[ "${{SANITIZE_SKIP:-0}}" = "1" ] && exit 0

if ! command -v sanitize >/dev/null 2>&1; then
  printf 'sanitize: not found in PATH — hook skipped\n' >&2
  exit 0
fi

_ver=$(sanitize --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
_req="{min_version}"
if [ -n "$_ver" ] && [ "$(printf '%s\n' "$_req" "$_ver" | sort -V | head -1)" != "$_req" ]; then
  printf 'sanitize: hook requires >= %s but found %s — update with: cargo install rust-sanitize\n' "$_req" "$_ver" >&2
  exit 1
fi

while IFS=' ' read -r local_ref local_sha remote_ref remote_sha; do
  # Skip branch deletions.
  [ "$local_sha" = "0000000000000000000000000000000000000000" ] && continue

  if [ "$remote_sha" = "0000000000000000000000000000000000000000" ]; then
    FILES=$(git diff-tree --no-commit-id -r --name-only "$local_sha" 2>/dev/null)
  else
    FILES=$(git diff --name-only "$remote_sha" "$local_sha" 2>/dev/null)
  fi

  [ -z "$FILES" ] && continue

  # Build a NUL-delimited list of files that exist on disk.
  EXISTING=$(printf '%s\n' "$FILES" | while IFS= read -r f; do
    [ -f "$f" ] && printf '%s\0' "$f"
  done)
  [ -z "$EXISTING" ] && continue

  # shellcheck disable=SC2086
  printf '%s' "$EXISTING" | xargs -0 \
    sanitize --dry-run --fail-on-match {flags}

  EXIT=$?
  if [ "$EXIT" -eq 2 ]; then
    printf '\nsanitize: secrets detected — push blocked.\n' >&2
    printf '  Skip once with:  SANITIZE_SKIP=1 git push ...\n' >&2
    exit 1
  fi
  [ "$EXIT" -ne 0 ] && printf 'sanitize: unexpected exit code %d\n' "$EXIT" >&2
done
exit 0
"#,
        marker = HOOK_MARKER,
        min_version = HOOK_MIN_VERSION,
        flags = flags,
    )
}

pub(crate) fn build_hook_script(args: &InstallHookArgs) -> String {
    let flags = build_hook_flags(args);
    match (&args.hook, &args.mode) {
        (HookType::PreCommit, HookMode::Scan) => hook_script_pre_commit_scan(&flags),
        (HookType::PreCommit, HookMode::Sanitize) => hook_script_pre_commit_sanitize(&flags),
        (HookType::PrePush, _) => hook_script_pre_push_scan(&flags),
    }
}

/// Check for known hook frameworks (husky, lefthook, pre-commit) in the repo
/// root.  Returns the path to the target hook file if the framework handles
/// the write itself (husky), or `None` with a printed advisory for frameworks
/// that require manual config edits (lefthook, pre-commit).
fn detect_framework_hooks_dir(repo_root: &Path, hook_name: &str) -> Option<PathBuf> {
    // ── husky ────────────────────────────────────────────────────────────────
    let husky_dir = repo_root.join(".husky");
    if husky_dir.is_dir() {
        eprintln!("Detected husky — writing to .husky/{hook_name}");
        return Some(husky_dir);
    }

    // ── lefthook ─────────────────────────────────────────────────────────────
    let lefthook_files = ["lefthook.yml", "lefthook.yaml", "lefthook.toml"];
    if lefthook_files.iter().any(|f| repo_root.join(f).exists()) {
        eprintln!("Detected lefthook — add the following to your lefthook config manually:");
        eprintln!();
        eprintln!("  {hook_name}:");
        eprintln!("    commands:");
        eprintln!("      sanitize:");
        eprintln!("        run: sanitize --dry-run --fail-on-match {{staged_files}}");
        eprintln!("        glob: '*.{{yaml,yml,json,toml,env,conf,rb,py,go,ts,js}}'");
        eprintln!();
        eprintln!("Then re-run `sanitize install-hook` without the lefthook config to install a fallback raw hook,");
        eprintln!("or skip and rely on lefthook alone.");
    }

    // ── pre-commit framework ─────────────────────────────────────────────────
    let precommit_cfg = ["pre-commit-config.yaml", "pre-commit-config.yml"]
        .iter()
        .map(|f| repo_root.join(format!(".{f}")))
        .find(|p| p.exists());
    if precommit_cfg.is_some() {
        eprintln!("Detected pre-commit framework — add the following to .pre-commit-config.yaml manually:");
        eprintln!();
        eprintln!("  - repo: local");
        eprintln!("    hooks:");
        eprintln!("      - id: sanitize-scan");
        eprintln!("        name: Scan for secrets (rust-sanitize)");
        eprintln!("        entry: sanitize --dry-run --fail-on-match");
        eprintln!("        language: system");
        eprintln!("        pass_filenames: true");
        eprintln!();
    }

    None
}

/// Remove a hook installed by `sanitize install-hook`.
/// If the file only contains the sanitize hook (single hook), the file is
/// deleted.  If it was appended to an existing hook, the sanitize block is
/// excised and the rest of the file is preserved.
pub(crate) fn remove_hook(hook_path: &Path, _hook_name: &str) -> Result<(), (String, i32)> {
    if !hook_path.exists() {
        eprintln!("No hook found at {}", hook_path.display());
        return Ok(());
    }
    let content = fs::read_to_string(hook_path)
        .map_err(|e| (format!("failed to read {}: {e}", hook_path.display()), 1))?;

    if !content.contains(HOOK_MARKER) {
        return Err((
            format!(
                "{} was not installed by sanitize (marker not found) — not removing.\n\
                 Delete it manually if you want to remove it.",
                hook_path.display()
            ),
            1,
        ));
    }

    // Count meaningful lines that appear *before* the sanitize marker.
    // If there are none (only a shebang or whitespace before our block),
    // the file is entirely ours and should be deleted outright.
    let lines_before_marker = content
        .lines()
        .take_while(|l| !l.contains(HOOK_MARKER))
        .filter(|l| !l.trim().is_empty() && *l != "#!/bin/sh")
        .count();

    if lines_before_marker == 0 {
        fs::remove_file(hook_path)
            .map_err(|e| (format!("failed to remove {}: {e}", hook_path.display()), 1))?;
        println!("Removed {}", hook_path.display());
    } else {
        // Another hook owns this file — excise only our block (from the
        // marker line to end-of-file) and leave the rest intact.
        let trimmed = content
            .lines()
            .take_while(|l| !l.contains(HOOK_MARKER))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(hook_path, trimmed.trim_end().to_string() + "\n")
            .map_err(|e| (format!("failed to write {}: {e}", hook_path.display()), 1))?;
        println!("Removed sanitize block from {}", hook_path.display());
    }

    Ok(())
}

pub(crate) fn run_install_hook(args: &InstallHookArgs) -> Result<(), (String, i32)> {
    let hook_name = args.hook.hook_name();

    // ── determine target hooks directory ─────────────────────────────────────
    let hooks_dir = if args.global {
        find_global_hooks_dir()?
    } else {
        // Check for known frameworks first; they may redirect the write path.
        let repo_root = find_git_root()?;
        let framework_dir = detect_framework_hooks_dir(&repo_root, hook_name);
        framework_dir.unwrap_or_else(|| {
            find_project_hooks_dir().unwrap_or_else(|_| repo_root.join(".git").join("hooks"))
        })
    };

    let hook_path = hooks_dir.join(hook_name);

    // ── remove mode ───────────────────────────────────────────────────────────
    if args.remove {
        return remove_hook(&hook_path, hook_name);
    }

    // ── dry-run ───────────────────────────────────────────────────────────────
    let script = build_hook_script(args);
    if args.dry_run {
        println!("# Would write to: {}", hook_path.display());
        println!("{script}");
        return Ok(());
    }

    // ── check for pre-existing hook ───────────────────────────────────────────
    if hook_path.exists() && !args.force {
        let existing = fs::read_to_string(&hook_path).unwrap_or_default();
        if !existing.contains(HOOK_MARKER) {
            return Err((
                format!(
                    "{} already exists and was not installed by sanitize.\n\
                     Inspect it first, then use --force to overwrite.",
                    hook_path.display()
                ),
                1,
            ));
        }
        // Our hook — update in place (fall through to write).
    }

    // ── write the hook ────────────────────────────────────────────────────────
    fs::create_dir_all(&hooks_dir)
        .map_err(|e| (format!("failed to create {}: {e}", hooks_dir.display()), 1))?;

    fs::write(&hook_path, &script)
        .map_err(|e| (format!("failed to write {}: {e}", hook_path.display()), 1))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))
            .map_err(|e| (format!("failed to chmod {}: {e}", hook_path.display()), 1))?;
    }

    // ── success output ────────────────────────────────────────────────────────
    let mode_label = match args.mode {
        HookMode::Scan => "scan — blocks commit on detection (staged files not modified)",
        HookMode::Sanitize => "sanitize — modifies staged files in place before committing",
    };
    println!("Installed {hook_name} hook → {}", hook_path.display());
    println!("  Mode:     {mode_label}");
    println!("  Patterns: {}", global_default_secrets_path().display());
    if let Some(ref app) = args.app {
        println!("  Apps:     {app}");
    }
    if let Some(ref s) = args.secrets_file {
        println!("  Secrets:  {}", s.display());
    }
    println!();
    println!("Skip one commit:  SANITIZE_SKIP=1 git commit ...");
    let remove_extra = if args.global { " --global" } else { "" };
    let hook_extra = if args.hook == HookType::PrePush {
        " --hook pre-push"
    } else {
        ""
    };
    println!("Uninstall:        sanitize install-hook --remove{hook_extra}{remove_extra}");

    #[cfg(windows)]
    println!(
        "\nNote: the hook script uses POSIX sh syntax and requires Git for Windows \
         (Git Bash) to execute. It will not run under cmd.exe or PowerShell directly."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_args::{HookMode, HookType};

    // ── sh_quote ─────────────────────────────────────────────────────────────

    #[test]
    fn sh_quote_plain_string() {
        assert_eq!(sh_quote("hello"), "'hello'");
    }

    #[test]
    fn sh_quote_string_with_spaces() {
        assert_eq!(sh_quote("/path/to my/file.yaml"), "'/path/to my/file.yaml'");
    }

    #[test]
    fn sh_quote_string_with_single_quote() {
        // The standard POSIX sh escaping: ' → '\''
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn sh_quote_multiple_single_quotes() {
        assert_eq!(sh_quote("a'b'c"), "'a'\\''b'\\''c'");
    }

    #[test]
    fn sh_quote_empty_string() {
        assert_eq!(sh_quote(""), "''");
    }

    #[test]
    fn sh_quote_special_shell_chars_do_not_escape() {
        // Dollar signs, backticks, etc. are safe inside single quotes.
        assert_eq!(sh_quote("$VAR`cmd`"), "'$VAR`cmd`'");
    }

    // ── build_hook_flags ─────────────────────────────────────────────────────

    fn base_args() -> InstallHookArgs {
        InstallHookArgs {
            hook: HookType::PreCommit,
            mode: HookMode::Scan,
            global: false,
            force: false,
            remove: false,
            app: None,
            secrets_file: None,
            dry_run: false,
        }
    }

    #[test]
    fn build_hook_flags_no_args() {
        let args = base_args();
        assert_eq!(build_hook_flags(&args), "");
    }

    #[test]
    fn build_hook_flags_with_app() {
        let args = InstallHookArgs {
            app: Some("gitlab".into()),
            ..base_args()
        };
        assert_eq!(build_hook_flags(&args), "--app 'gitlab'");
    }

    #[test]
    fn build_hook_flags_with_secrets_file() {
        let args = InstallHookArgs {
            secrets_file: Some(PathBuf::from("/home/user/secrets.yaml")),
            ..base_args()
        };
        assert_eq!(build_hook_flags(&args), "-s '/home/user/secrets.yaml'");
    }

    #[test]
    fn build_hook_flags_with_secrets_file_with_spaces() {
        let args = InstallHookArgs {
            secrets_file: Some(PathBuf::from("/my secrets/file.yaml")),
            ..base_args()
        };
        assert_eq!(build_hook_flags(&args), "-s '/my secrets/file.yaml'");
    }

    #[test]
    fn build_hook_flags_app_and_secrets_file() {
        let args = InstallHookArgs {
            app: Some("kubernetes".into()),
            secrets_file: Some(PathBuf::from("secrets.yaml")),
            ..base_args()
        };
        assert_eq!(
            build_hook_flags(&args),
            "--app 'kubernetes' -s 'secrets.yaml'"
        );
    }
}
