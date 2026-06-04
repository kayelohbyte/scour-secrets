use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use rust_sanitize::ArchiveFormat;

use crate::apps::{builtin_app_names, user_apps_dir, BUILTIN_APPS};
use crate::cli_args::Cli;
use crate::scanner_builder::build_scan_config;

/// All format names accepted by `--format`. Must stay in sync with the
/// format-parsing logic in `ProcessorRegistry`.
pub(crate) const VALID_FORMATS: &[&str] = &[
    "text",
    "json",
    "jsonl",
    "ndjson",
    "yaml",
    "yml",
    "xml",
    "csv",
    "tsv",
    "key-value",
    "toml",
    "env",
    "ini",
    "log",
];

/// Initialise the `tracing` subscriber based on the `--log-format` flag.
pub(crate) fn init_logging(log_format: &str, log_level: &str) {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_env("SANITIZE_LOG").unwrap_or_else(|_| EnvFilter::new(log_level));

    match log_format {
        "json" => {
            let _ = fmt()
                .json()
                .with_env_filter(filter)
                .with_target(true)
                .with_writer(io::stderr)
                .try_init();
        }
        _ => {
            let _ = fmt()
                .compact()
                .with_env_filter(filter)
                .with_target(false)
                .with_writer(io::stderr)
                .try_init();
        }
    }
}

/// Returns `true` when input should be read from stdin.
pub(crate) fn has_stdin_input(cli: &Cli) -> bool {
    cli.input.is_empty() || cli.input.iter().any(|p| p.as_os_str() == "-")
}

/// Returns `true` when stdin is an OS-level pipe (FIFO).
#[cfg(unix)]
fn stdin_is_pipe() -> bool {
    use nix::sys::stat::fstat;
    use std::os::unix::io::AsRawFd;
    fstat(io::stdin().as_raw_fd())
        .map(|s| {
            nix::sys::stat::SFlag::from_bits_truncate(s.st_mode)
                .contains(nix::sys::stat::SFlag::S_IFIFO)
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn stdin_is_pipe() -> bool {
    use std::os::windows::io::AsRawHandle;
    extern "system" {
        fn GetFileType(hFile: *mut std::ffi::c_void) -> u32;
    }
    const FILE_TYPE_PIPE: u32 = 3;
    let handle = io::stdin().as_raw_handle();
    // SAFETY: stdin handle is valid for the lifetime of the process.
    unsafe { GetFileType(handle as *mut _) == FILE_TYPE_PIPE }
}

#[cfg(not(any(unix, windows)))]
fn stdin_is_pipe() -> bool {
    !io::stdin().is_terminal()
}

/// Returns file-path inputs, excluding explicit stdin markers ("-").
pub(crate) fn file_inputs(cli: &Cli) -> Vec<&PathBuf> {
    cli.input.iter().filter(|p| p.as_os_str() != "-").collect()
}

/// Map the `--format` value to extension-like string for structured processor lookup.
pub(crate) fn format_to_ext(fmt: &str) -> Option<&str> {
    match fmt {
        "json" => Some("json"),
        "jsonl" | "ndjson" => Some("jsonl"),
        "yaml" | "yml" => Some("yaml"),
        "xml" => Some("xml"),
        "csv" => Some("csv"),
        "tsv" => Some("tsv"),
        "key-value" | "key_value" | "kv" => Some("conf"),
        "toml" => Some("toml"),
        "env" => Some("env"),
        "ini" => Some("ini"),
        "log" => Some("log"),
        _ => None,
    }
}

/// Returns `true` if `filename` should be processed by a structured processor
/// rather than the streaming scanner.  Checks both the extension and `.env`-style
/// dot-prefixed names.
pub(crate) fn is_structured_filename(filename: &str) -> bool {
    matches!(
        filename.rsplit('.').next().unwrap_or(""),
        "json"
            | "jsonl"
            | "ndjson"
            | "yaml"
            | "yml"
            | "xml"
            | "csv"
            | "tsv"
            | "rb"
            | "conf"
            | "cfg"
            | "ini"
            | "env"
            | "properties"
            | "toml"
    ) || filename
        .rsplit('/')
        .next()
        .unwrap_or(filename)
        .starts_with(".env")
}

/// Derive a default output path for archive files.
pub(crate) fn default_archive_output(input: &Path, fmt: ArchiveFormat) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = match fmt {
        ArchiveFormat::Zip => "zip",
        ArchiveFormat::Tar => "tar",
        ArchiveFormat::TarGz => "tar.gz",
    };
    let base = if matches!(fmt, ArchiveFormat::TarGz) {
        stem.strip_suffix(".tar").unwrap_or(stem)
    } else {
        stem
    };
    input.with_file_name(format!("{base}.sanitized.{ext}"))
}

fn default_plain_output(input: &Path) -> PathBuf {
    let name = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output");

    let output_name = if let Some((stem, ext)) = name.rsplit_once('.') {
        format!("{stem}-sanitized.{ext}")
    } else {
        format!("{name}-sanitized")
    };

    input.with_file_name(output_name)
}

fn split_name_for_suffix(name: &str) -> (String, String) {
    if let Some(stem) = name.strip_suffix(".tar.gz") {
        return (stem.to_string(), ".tar.gz".to_string());
    }
    if let Some((stem, ext)) = name.rsplit_once('.') {
        return (stem.to_string(), format!(".{ext}"));
    }
    (name.to_string(), String::new())
}

fn uniquify_output_path(path: PathBuf, used: &mut HashSet<PathBuf>) -> PathBuf {
    if !path.exists() && !used.contains(&path) {
        used.insert(path.clone());
        return path;
    }

    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output")
        .to_string();
    let (stem, ext) = split_name_for_suffix(&name);

    let mut idx = 1usize;
    loop {
        let candidate = parent.join(format!("{stem}-{idx}{ext}"));
        if !candidate.exists() && !used.contains(&candidate) {
            used.insert(candidate.clone());
            return candidate;
        }
        idx += 1;
    }
}

/// Derive a report path when none was explicitly given.
pub(crate) fn derive_auto_report_path(targets: &[InputTarget], ext: &str) -> Option<PathBuf> {
    let files: Vec<(&Path, &Path)> = targets
        .iter()
        .filter_map(|t| match t {
            InputTarget::File { input, output } => Some((input.as_path(), output.as_path())),
            InputTarget::Stdin { .. } => None,
        })
        .collect();

    if files.is_empty() {
        return None;
    }

    if files.len() == 1 {
        let (input, output) = files[0];
        let stem = input.file_stem()?.to_str()?;
        let dir = output.parent().unwrap_or(Path::new("."));
        Some(dir.join(format!("{stem}.extracted.{ext}")))
    } else {
        let first_dir = files[0].1.parent().unwrap_or(Path::new("."));
        let all_same_dir = files
            .iter()
            .all(|(_, o)| o.parent().unwrap_or(Path::new(".")) == first_dir);
        let dir = if all_same_dir {
            first_dir
        } else {
            Path::new(".")
        };
        Some(dir.join(format!("sanitize-extracted.{ext}")))
    }
}

pub(crate) enum InputTarget {
    Stdin { output: Option<PathBuf> },
    File { input: PathBuf, output: PathBuf },
}

const SKIP_VCS_DIRS: &[&str] = &[".git", ".hg", ".svn", ".bzr"];

struct ExpandedInput {
    path: PathBuf,
    dir_root: Option<PathBuf>,
}

/// Recursively collect all files under `dir`, skipping VCS dirs and hidden entries.
pub(crate) fn walk_dir(dir: &Path, include_hidden: bool) -> Result<Vec<PathBuf>, String> {
    use walkdir::WalkDir;
    let mut files = Vec::new();
    let walker = WalkDir::new(dir).follow_links(false).sort_by_file_name();

    for entry in walker {
        let entry = entry.map_err(|e| format!("error walking {}: {e}", dir.display()))?;
        let name = entry.file_name().to_str().unwrap_or("");

        if entry.file_type().is_dir() && SKIP_VCS_DIRS.contains(&name) {
            continue;
        }

        if !include_hidden && entry.depth() > 0 && name.starts_with('.') {
            continue;
        }

        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    Ok(files)
}

/// Compiled glob pattern list used for both exclude and include-path filtering.
///
/// Empty-list semantics differ: an empty `GlobList` used as an exclude filter
/// excludes nothing (`is_excluded` returns `false`), while one used as an
/// include filter includes everything (`is_included` returns `true`).
struct GlobList {
    patterns: Vec<(glob::Pattern, bool)>,
}

impl GlobList {
    fn new(raw: &[String], label: &str) -> Self {
        let mut patterns = Vec::with_capacity(raw.len());
        for p in raw {
            let is_subtree = p.ends_with('/');
            let trimmed = p.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            match glob::Pattern::new(trimmed) {
                Ok(compiled) => patterns.push((compiled, is_subtree)),
                Err(e) => eprintln!("warning: invalid {label} pattern '{p}': {e} — skipping"),
            }
        }
        Self { patterns }
    }

    /// Returns `true` if any pattern matches `path` relative to `root`.
    fn any_match(&self, path: &Path, root: &Path) -> bool {
        let opts = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: false,
        };
        let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let rel = canon_path.strip_prefix(&canon_root).unwrap_or(&canon_path);
        let rel_str = rel.to_string_lossy();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();

        for (pat, is_subtree) in &self.patterns {
            if *is_subtree {
                let prefix = pat.as_str();
                if rel_str.starts_with(prefix)
                    && (rel_str.len() == prefix.len()
                        || rel_str.as_bytes().get(prefix.len()) == Some(&b'/'))
                {
                    return true;
                }
            } else {
                if pat.matches_with(&rel_str, opts) {
                    return true;
                }
                if !pat.as_str().contains('/') && pat.matches_with(&filename, opts) {
                    return true;
                }
            }
        }
        false
    }

    fn is_excluded(&self, path: &Path, root: &Path) -> bool {
        !self.patterns.is_empty() && self.any_match(path, root)
    }

    fn is_included(&self, path: &Path, root: &Path) -> bool {
        self.patterns.is_empty() || self.any_match(path, root)
    }
}

/// Returns true when sanitized output will be written to stdout rather than to files.
pub(crate) fn cli_writes_to_stdout(cli: &Cli) -> bool {
    let explicit_stdout_out = cli.output.as_deref() == Some(Path::new("-"));
    let stdin_only = cli.input.is_empty() || cli.input.iter().all(|p| p.as_os_str() == "-");
    explicit_stdout_out || (stdin_only && cli.output.is_none())
}

pub(crate) fn plan_input_targets(cli: &Cli) -> Result<Vec<InputTarget>, String> {
    use crate::config::{find_project_config, load_project_config};

    let explicit_stdin_count = cli.input.iter().filter(|p| p.as_os_str() == "-").count();

    if explicit_stdin_count > 1 {
        return Err("stdin marker '-' can be specified at most once".into());
    }

    let has_piped_stdin = explicit_stdin_count == 0 && stdin_is_pipe();

    if cli.input.is_empty() {
        return Ok(vec![InputTarget::Stdin {
            output: cli.output.clone(),
        }]);
    }

    let (ignore_patterns, ignore_root): (Vec<String>, PathBuf) = {
        let mut patterns: Vec<String> = Vec::new();
        let root = if let Some(ref cfg_path) = find_project_config() {
            let (pc, cfg_dir) = load_project_config(cfg_path);
            patterns.extend(pc.exclude);
            cfg_dir
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        };
        patterns.extend(cli.exclude_path.iter().cloned());
        (patterns, root)
    };
    let ignore_list = GlobList::new(&ignore_patterns, "exclude");
    let include_list = GlobList::new(&cli.include_path, "include-path");

    let mut expanded: Vec<ExpandedInput> = Vec::new();

    for input in &cli.input {
        if input.as_os_str() == "-" {
            continue;
        }
        if input.is_dir() {
            let files = walk_dir(input, cli.hidden)?;
            if files.is_empty() {
                warn!(dir = %input.display(), "directory contains no processable files");
                continue;
            }
            let before = files.len();
            let walk_root = input.canonicalize().unwrap_or_else(|_| input.to_path_buf());
            let files: Vec<PathBuf> = files
                .into_iter()
                .filter(|f| {
                    if ignore_list.is_excluded(f, &walk_root) {
                        info!(path = %f.display(), "excluded by ignore pattern");
                        return false;
                    }
                    if !include_list.is_included(f, &walk_root) {
                        info!(path = %f.display(), "excluded by include-path filter");
                        return false;
                    }
                    true
                })
                .collect();
            if files.is_empty() {
                warn!(dir = %input.display(), excluded = before, "all files in directory excluded by path filters");
                continue;
            }
            let excluded = before - files.len();
            info!(dir = %input.display(), files = files.len(), excluded, "expanding directory input");
            if cli.effective_log_format() != "json" {
                if excluded > 0 {
                    eprintln!(
                        "  {} files in {} ({} excluded)",
                        files.len(),
                        input.display(),
                        excluded
                    );
                } else {
                    eprintln!("  {} files in {}", files.len(), input.display());
                }
            }
            for f in files {
                expanded.push(ExpandedInput {
                    path: f,
                    dir_root: Some(input.clone()),
                });
            }
        } else {
            if ignore_list.is_excluded(input, &ignore_root) {
                warn!(path = %input.display(), "explicitly specified file matches an exclude pattern — skipping");
                continue;
            }
            expanded.push(ExpandedInput {
                path: input.clone(),
                dir_root: None,
            });
        }
    }

    let multi_input = expanded.len() + explicit_stdin_count + (has_piped_stdin as usize) > 1;
    let mut used_outputs = HashSet::new();
    let mut units = Vec::new();

    let output_dir: Option<PathBuf> = if multi_input {
        if let Some(path) = &cli.output {
            if path.exists() && !path.is_dir() {
                return Err(format!(
                    "--output must be a directory when multiple inputs are provided: {}",
                    path.display()
                ));
            }
            if !path.exists() {
                fs::create_dir_all(path).map_err(|e| {
                    format!("failed to create output directory {}: {e}", path.display())
                })?;
            }
            Some(path.clone())
        } else {
            None
        }
    } else {
        None
    };

    for ei in expanded {
        let planned_out = if let Some(ref root) = ei.dir_root {
            let rel = ei.path.strip_prefix(root).unwrap_or(&ei.path);
            if let Some(out_root) = &cli.output {
                let dest = out_root.join(rel);
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
                }
                uniquify_output_path(dest, &mut used_outputs)
            } else {
                let dir_name = root
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("sanitized");
                let peer_dir = root
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(format!("{dir_name}-sanitized"));
                let dest = peer_dir.join(rel);
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
                }
                uniquify_output_path(dest, &mut used_outputs)
            }
        } else if multi_input {
            let default_out = match ArchiveFormat::from_path(&ei.path.to_string_lossy()) {
                Some(fmt) => default_archive_output(&ei.path, fmt),
                None => default_plain_output(&ei.path),
            };
            let out_name = default_out
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("output")
                .to_string();
            if let Some(dir) = &output_dir {
                uniquify_output_path(dir.join(out_name), &mut used_outputs)
            } else {
                uniquify_output_path(default_out, &mut used_outputs)
            }
        } else {
            let default_out = match ArchiveFormat::from_path(&ei.path.to_string_lossy()) {
                Some(fmt) => default_archive_output(&ei.path, fmt),
                None => default_plain_output(&ei.path),
            };
            if let Some(out) = &cli.output {
                if out.is_dir() {
                    let out_name = default_out
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("output")
                        .to_string();
                    uniquify_output_path(out.join(out_name), &mut used_outputs)
                } else {
                    out.clone()
                }
            } else {
                default_out
            }
        };

        units.push(InputTarget::File {
            input: ei.path,
            output: planned_out,
        });
    }

    if explicit_stdin_count > 0 || has_piped_stdin {
        let stdin_out = if multi_input {
            Some(
                output_dir
                    .as_ref()
                    .map(|d| d.join("input-sanitized.txt"))
                    .unwrap_or_else(|| PathBuf::from("input-sanitized.txt")),
            )
        } else {
            cli.output.clone()
        };
        units.push(InputTarget::Stdin { output: stdin_out });
    }

    Ok(units)
}

/// Pre-parse `--only` / `--exclude` flags interleaved with archive paths.
#[allow(clippy::type_complexity)]
pub(crate) fn parse_archive_filters(
    args: &[OsString],
) -> Result<(HashMap<PathBuf, (Vec<String>, Vec<String>)>, Vec<OsString>), String> {
    #[derive(PartialEq)]
    enum State {
        Global,
        AfterArchive,
        CollectingOnly,
        CollectingExclude,
    }

    let mut state = State::Global;
    let mut current_archive: Option<PathBuf> = None;
    let mut filter_map: HashMap<PathBuf, (Vec<String>, Vec<String>)> = HashMap::new();
    let mut cleaned: Vec<OsString> = Vec::with_capacity(args.len());

    let validate_pattern = |p: &str| -> Result<(), String> {
        if !p.ends_with('/') {
            glob::Pattern::new(p).map_err(|e| format!("invalid glob pattern '{p}': {e}"))?;
        }
        Ok(())
    };

    for arg in args {
        let s = arg.to_string_lossy();

        match s.as_ref() {
            "--only" => {
                if state == State::Global {
                    return Err(
                        "--only must follow an archive path (e.g. archive.zip --only PATTERN)"
                            .into(),
                    );
                }
                state = State::CollectingOnly;
            }
            "--exclude" => {
                if state == State::Global {
                    return Err(
                        "--exclude must follow an archive path (e.g. archive.zip --exclude PATTERN)"
                            .into(),
                    );
                }
                state = State::CollectingExclude;
            }
            _ if (state == State::CollectingOnly || state == State::CollectingExclude)
                && !s.starts_with('-') =>
            {
                let candidate = PathBuf::from(s.as_ref());
                if ArchiveFormat::from_path(&s).is_some() && candidate.is_file() {
                    filter_map
                        .entry(candidate.clone())
                        .or_insert_with(|| (Vec::new(), Vec::new()));
                    current_archive = Some(candidate.clone());
                    state = State::AfterArchive;
                    cleaned.push(arg.clone());
                } else if candidate.is_file() {
                    return Err(format!(
                        "non-archive path '{}' cannot appear between filter flags; \
                         move it before or after the archive+filter group",
                        candidate.display()
                    ));
                } else {
                    validate_pattern(&s)?;
                    let key = current_archive
                        .as_ref()
                        .expect("state machine guarantees archive is set before pattern args");
                    let entry = filter_map.entry(key.clone()).or_default();
                    if state == State::CollectingOnly {
                        entry.0.push(s.into_owned());
                    } else {
                        entry.1.push(s.into_owned());
                    }
                }
            }
            _ if (state == State::CollectingOnly || state == State::CollectingExclude)
                && s.starts_with('-') =>
            {
                state = State::AfterArchive;
                cleaned.push(arg.clone());
            }
            _ => {
                let candidate = PathBuf::from(s.as_ref());
                if ArchiveFormat::from_path(&s).is_some() {
                    filter_map
                        .entry(candidate.clone())
                        .or_insert_with(|| (Vec::new(), Vec::new()));
                    current_archive = Some(candidate.clone());
                    state = State::AfterArchive;
                }
                cleaned.push(arg.clone());
            }
        }
    }

    Ok((filter_map, cleaned))
}

pub(crate) fn validate_args(cli: &Cli) -> Result<(), String> {
    if has_stdin_input(cli) && io::stdin().is_terminal() {
        return Err("stdin was requested but stdin is a terminal.\n\
             Provide file path(s) only, or pipe data into sanitize when using '-'.\n\n\
             Usage: sanitize [OPTIONS] [INPUT]...\n       \
             command | sanitize -s secrets.yaml"
            .into());
    }

    let explicit_stdin_count = cli.input.iter().filter(|p| p.as_os_str() == "-").count();
    if explicit_stdin_count > 1 {
        return Err("stdin marker '-' can be specified at most once".into());
    }

    for input in file_inputs(cli) {
        if !input.exists() {
            return Err(format!("input path not found: {}", input.display()));
        }
        if !input.is_file() && !input.is_dir() {
            return Err(format!(
                "input path is not a file or directory: {}",
                input.display()
            ));
        }
    }

    if let Some(ref fmt) = cli.format {
        if !VALID_FORMATS.contains(&fmt.as_str()) {
            return Err(format!(
                "invalid --format '{}': must be one of: {}",
                fmt,
                VALID_FORMATS.join(", ")
            ));
        }
    }

    if let Some(ref sf) = cli.secrets_file {
        if !sf.exists() && !cli.deterministic {
            return Err(format!("secrets file not found: {}", sf.display()));
        }
        if sf.exists() && !sf.is_file() {
            return Err(format!(
                "secrets path is not a regular file: {}",
                sf.display()
            ));
        }
    }

    build_scan_config(cli.chunk_size)?;

    if let Some(t) = cli.threads {
        if t == 0 {
            return Err("--threads must be ≥ 1".into());
        }
    }

    if cli.max_archive_depth > 10 {
        return Err(format!(
            "--max-archive-depth {} exceeds maximum of 10 (each nesting level \
             may buffer up to 256 MiB of archive data)",
            cli.max_archive_depth
        ));
    }
    if cli.max_archive_depth == 0 {
        return Err("--max-archive-depth must be ≥ 1".into());
    }

    if !matches!(cli.effective_log_format(), "human" | "json") {
        return Err(format!(
            "invalid --log-format '{}': must be 'human' or 'json'",
            cli.effective_log_format()
        ));
    }

    if !matches!(
        cli.effective_log_level(),
        "off" | "error" | "warn" | "info" | "debug" | "trace"
    ) {
        return Err(format!(
            "invalid --log-level '{}': must be one of off, error, warn, info, debug, trace",
            cli.effective_log_level()
        ));
    }

    if cli.progress_interval_ms == 0 {
        return Err("--progress-interval-ms must be greater than 0".into());
    }

    let has_password_source = cli.password
        || cli.password_file.is_some()
        || std::env::var("SANITIZE_PASSWORD").is_ok_and(|v| !v.is_empty());
    if has_password_source && !cli.encrypted_secrets && !cli.deterministic {
        return Err(
            "password input (--password, --password-file, or SANITIZE_PASSWORD) \
             was provided but --encrypted-secrets is not set.\n\
             Add --encrypted-secrets to decrypt the secrets file, or remove \
             password inputs to use a plaintext file."
                .into(),
        );
    }

    for app in &cli.app {
        let is_builtin = BUILTIN_APPS.iter().any(|a| a.name == app.as_str());
        let is_user = user_apps_dir()
            .map(|d| d.join(app).is_dir())
            .unwrap_or(false);
        if !is_builtin && !is_user {
            return Err(format!(
                "unknown --app '{}'. Built-in apps: {}. \
                 Add a custom app at $SANITIZE_APPS_DIR/{} (secrets.yaml / profile.yaml).",
                app,
                builtin_app_names().join(", "),
                app,
            ));
        }
    }

    if let Some(ref template) = cli.llm {
        if cli.dry_run {
            return Err(
                "--llm and --dry-run cannot be combined: dry-run does not produce \
                 sanitized output, so the generated prompt would have no content."
                    .into(),
            );
        }

        let known = matches!(
            template.as_str(),
            "troubleshoot" | "review-config" | "review-security"
        );
        if !known {
            let path = Path::new(template);
            if !path.exists() {
                return Err(format!(
                    "--llm template '{}' is not a known template name and the path \
                     does not exist.\n\
                     Built-in templates: troubleshoot, review-config, review-security\n\
                     To use a custom template, provide a path to an existing file.",
                    template
                ));
            }
            if !path.is_file() {
                return Err(format!(
                    "--llm template '{}' exists but is not a regular file.",
                    template
                ));
            }
        }
    }

    Ok(())
}

/// Resolve and cap thread count to available parallelism.
pub(crate) fn resolve_thread_count(requested: Option<usize>) -> usize {
    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    match requested {
        Some(n) => n.min(available),
        None => available,
    }
}
