//! Progress reporting for the CLI binary.
//!
//! Provides [`ProgressReporter`] which renders a live spinner in interactive
//! terminals and falls back to milestone log lines in CI / non-TTY environments.

use clap::ValueEnum;
use rust_sanitize::{ArchiveProgress, ScanProgress};
use std::env;
use std::io::{self, IsTerminal, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::info;

pub(crate) type SharedProgressReporter = Arc<Mutex<ProgressReporter>>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ProgressMode {
    Auto,
    On,
    Off,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProgressPolicy {
    pub(crate) live_updates: bool,
    pub(crate) milestone_updates: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProgressContext {
    pub(crate) stderr_is_terminal: bool,
    pub(crate) stdout_is_terminal: bool,
    /// True when sanitized output is actually being written to stdout (not to
    /// files). Only in this case does a stdout TTY conflict with the spinner.
    pub(crate) stdout_is_output: bool,
    pub(crate) is_ci: bool,
    pub(crate) term_is_dumb: bool,
    pub(crate) json_logs: bool,
}

impl ProgressContext {
    pub(crate) fn detect(log_format: &str) -> Self {
        let term = env::var("TERM").unwrap_or_default();
        let ci = env::var_os("CI").is_some();

        Self {
            stderr_is_terminal: io::stderr().is_terminal(),
            stdout_is_terminal: io::stdout().is_terminal(),
            stdout_is_output: false, // caller sets this based on CLI output destination
            is_ci: ci,
            term_is_dumb: term.eq_ignore_ascii_case("dumb"),
            json_logs: log_format == "json",
        }
    }
}

impl ProgressPolicy {
    pub(crate) fn from_mode(mode: ProgressMode, context: ProgressContext) -> Self {
        match mode {
            ProgressMode::Off => Self {
                live_updates: false,
                milestone_updates: false,
            },
            ProgressMode::On => Self {
                live_updates: context.stderr_is_terminal && !context.json_logs,
                milestone_updates: true,
            },
            ProgressMode::Auto => {
                // Live spinner uses \r to overwrite the current line. Only
                // suppress it when output is actually going to stdout — that's
                // when the shared cursor would cause interleaving. A stdout
                // that is a TTY but isn't receiving output (e.g. writing to
                // files) is fine.
                let writing_to_tty_stdout = context.stdout_is_terminal && context.stdout_is_output;
                let allow_live = context.stderr_is_terminal
                    && !writing_to_tty_stdout
                    && !context.is_ci
                    && !context.term_is_dumb
                    && !context.json_logs;
                Self {
                    live_updates: allow_live,
                    // Milestone lines are plain eprintln! — useful in non-TTY
                    // and background runs even when live spinner is suppressed.
                    milestone_updates: !context.json_logs,
                }
            }
        }
    }
}

pub(crate) struct ProgressReporter {
    policy: ProgressPolicy,
    json_logs: bool,
    interval: Duration,
    spinner_index: usize,
    last_emit: Option<Instant>,
    last_scan_units: u64,
    last_archive_units: u64,
    rendered_line_len: usize,
}

impl ProgressReporter {
    pub(crate) fn new(policy: ProgressPolicy, json_logs: bool, progress_interval_ms: u64) -> Self {
        Self {
            policy,
            json_logs,
            interval: Duration::from_millis(progress_interval_ms),
            spinner_index: 0,
            last_emit: None,
            last_scan_units: 0,
            last_archive_units: 0,
            rendered_line_len: 0,
        }
    }

    pub(crate) fn start_task(&mut self, label: &str) {
        self.spinner_index = 0;
        self.last_emit = None;
        self.last_scan_units = 0;
        self.last_archive_units = 0;
        if self.policy.live_updates {
            let frame = self.spinner_frame();
            self.render_live_line(format!("{} {}", frame, label));
        } else if self.policy.milestone_updates {
            self.emit_milestone(label, None);
        }
    }

    pub(crate) fn update_scan(&mut self, label: &str, progress: &ScanProgress) {
        let min_delta = 8 * 1024 * 1024;
        if !self.should_emit_scan(progress.bytes_processed, min_delta) {
            return;
        }

        if self.policy.live_updates {
            let frame = self.spinner_frame();
            self.render_live_line(format!(
                "{} {}: {}",
                frame,
                label,
                format_scan_progress(progress)
            ));
        } else {
            // In non-TTY / milestone mode, per-chunk updates are too noisy.
            // Route to debug so SANITIZE_LOG=debug still surfaces them.
            tracing::debug!(task = label, progress = %format_scan_progress(progress), "scan progress");
        }
    }

    pub(crate) fn update_archive(&mut self, label: &str, progress: &ArchiveProgress) {
        if !self.should_emit_archive(progress.entries_seen, 1) {
            return;
        }

        let detail = match progress.total_entries {
            Some(total) => format!(
                "entry {}/{} ({})",
                progress.entries_seen, total, progress.current_entry
            ),
            None => format!(
                "entry {} ({})",
                progress.entries_seen, progress.current_entry
            ),
        };

        if self.policy.live_updates {
            let frame = self.spinner_frame();
            self.render_live_line(format!("{} {}: {}", frame, label, detail));
        } else {
            tracing::debug!(task = label, detail = %detail, "archive progress");
        }
    }

    pub(crate) fn finish_task(&mut self, label: &str) {
        if self.policy.live_updates {
            self.render_final_line(format!("done: {}", label));
        } else if self.policy.milestone_updates {
            self.emit_milestone(label, Some("done".into()));
        }
    }

    pub(crate) fn fail_task(&mut self, label: &str) {
        if self.policy.live_updates {
            self.render_final_line(format!("stopped: {}", label));
        } else if self.policy.milestone_updates {
            self.emit_milestone(label, Some("stopped".into()));
        }
    }

    fn should_emit_scan(&mut self, units: u64, min_delta: u64) -> bool {
        let now = Instant::now();
        let elapsed_ready = self.last_emit.map_or(true, |last_emit| {
            now.duration_since(last_emit) >= self.interval
        });
        let delta_ready = units >= self.last_scan_units.saturating_add(min_delta);

        if elapsed_ready || delta_ready {
            self.last_emit = Some(now);
            self.last_scan_units = units;
            true
        } else {
            false
        }
    }

    fn should_emit_archive(&mut self, units: u64, min_delta: u64) -> bool {
        let now = Instant::now();
        let elapsed_ready = self.last_emit.map_or(true, |last_emit| {
            now.duration_since(last_emit) >= self.interval
        });
        let delta_ready = units >= self.last_archive_units.saturating_add(min_delta);

        if elapsed_ready || delta_ready {
            self.last_emit = Some(now);
            self.last_archive_units = units;
            true
        } else {
            false
        }
    }

    fn emit_milestone(&mut self, label: &str, detail: Option<String>) {
        if self.json_logs {
            if let Some(detail) = detail {
                info!(task = label, detail = %detail, "progress update");
            } else {
                info!(task = label, "progress update");
            }
            return;
        }

        self.clear_live_line();
        match detail {
            Some(detail) => eprintln!("{}: {}", label, detail),
            None => eprintln!("{}", label),
        }
    }

    fn spinner_frame(&mut self) -> char {
        const FRAMES: [char; 4] = ['|', '/', '-', '\\'];
        let frame = FRAMES[self.spinner_index % FRAMES.len()];
        self.spinner_index = (self.spinner_index + 1) % FRAMES.len();
        frame
    }

    fn render_live_line(&mut self, line: String) {
        let padded_line = if line.len() < self.rendered_line_len {
            format!(
                "{}{}",
                line,
                " ".repeat(self.rendered_line_len - line.len())
            )
        } else {
            line
        };
        self.rendered_line_len = padded_line.len();
        let mut stderr = io::stderr().lock();
        let _ = write!(stderr, "\r{}", padded_line);
        let _ = stderr.flush();
    }

    fn render_final_line(&mut self, line: String) {
        self.render_live_line(line);
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr);
        let _ = stderr.flush();
        self.rendered_line_len = 0;
    }

    pub(crate) fn clear_live_line(&mut self) {
        if self.rendered_line_len == 0 {
            return;
        }

        let mut stderr = io::stderr().lock();
        let _ = write!(stderr, "\r{}\r", " ".repeat(self.rendered_line_len));
        let _ = stderr.flush();
        self.rendered_line_len = 0;
    }
}

fn format_scan_progress(progress: &ScanProgress) -> String {
    match progress.total_bytes {
        Some(total_bytes) if total_bytes > 0 => format!(
            "{} / {} ({:.0}%)",
            format_bytes(progress.bytes_processed),
            format_bytes(total_bytes),
            (progress.bytes_processed as f64 / total_bytes as f64) * 100.0
        ),
        _ => format_bytes(progress.bytes_processed),
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

    let mut value = bytes as f64;
    let mut unit_index = 0;
    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{value:.1} {}", UNITS[unit_index])
    }
}

pub(crate) fn with_progress_scope<T, F>(
    progress: Option<&SharedProgressReporter>,
    label: &str,
    action: F,
) -> Result<T, String>
where
    F: FnOnce(Option<SharedProgressReporter>) -> Result<T, String>,
{
    let progress = progress.cloned();

    if let Some(reporter) = &progress {
        reporter
            .lock()
            .expect("progress reporter lock")
            .start_task(label);
    }

    let result = action(progress.clone());

    if let Some(reporter) = &progress {
        let mut reporter = reporter.lock().expect("progress reporter lock");
        if result.is_ok() {
            reporter.finish_task(label);
        } else {
            reporter.fail_task(label);
        }
    }

    result
}
