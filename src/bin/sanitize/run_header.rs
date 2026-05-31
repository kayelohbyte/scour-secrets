use tracing::info;

use crate::cli_args::Cli;

pub(crate) struct CliConfigSnapshot {
    had_secrets: bool,
    had_profile: bool,
    apps: Vec<String>,
    allow: Vec<String>,
    strict: bool,
    fail_on_match: bool,
    no_structured_handoff: bool,
    deterministic: bool,
    dry_run: bool,
}

impl CliConfigSnapshot {
    pub(crate) fn capture(cli: &Cli) -> Self {
        Self {
            had_secrets: cli.secrets_file.is_some(),
            had_profile: cli.profile.is_some(),
            apps: cli.app.clone(),
            allow: cli.allow.clone(),
            strict: cli.strict,
            fail_on_match: cli.fail_on_match,
            no_structured_handoff: cli.no_structured_handoff,
            deterministic: cli.deterministic,
            dry_run: cli.dry_run,
        }
    }
}

/// Print a one-time run configuration summary to stderr so the user can see
/// exactly what secrets file, profile, and apps are active — and whether any
/// of them came from a config file rather than the command line.
pub(crate) fn print_run_header(cli: &Cli, snap: &CliConfigSnapshot, json_logs: bool) {
    if json_logs {
        info!(
            secrets = cli.secrets_file.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            profile = cli.profile.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            apps    = %cli.app.join(","),
            "run config"
        );
        return;
    }

    match &cli.secrets_file {
        Some(p) => {
            let ann = if !snap.had_secrets { "  [config]" } else { "" };
            eprintln!("  secrets:  {}{}", p.display(), ann);
        }
        None => {
            eprintln!("  secrets:  (none — built-in patterns only)");
        }
    }

    if let Some(p) = &cli.profile {
        let ann = if !snap.had_profile { "  [config]" } else { "" };
        eprintln!("  profile:  {}{}", p.display(), ann);
    }

    if !cli.app.is_empty() {
        let parts: Vec<String> = cli
            .app
            .iter()
            .map(|a| {
                if snap.apps.contains(a) {
                    a.clone()
                } else {
                    format!("{a}  [config]")
                }
            })
            .collect();
        eprintln!("  apps:     {}", parts.join(", "));
    }

    if !cli.allow.is_empty() {
        let parts: Vec<String> = cli
            .allow
            .iter()
            .map(|v| {
                if snap.allow.contains(v) {
                    format!("{v:?}")
                } else {
                    format!("{v:?}  [config]")
                }
            })
            .collect();
        eprintln!("  allow:    {}", parts.join(", "));
    }

    let mut flags: Vec<String> = Vec::new();
    if cli.strict {
        flags.push(if !snap.strict {
            "--strict  [config]".into()
        } else {
            "--strict".into()
        });
    }
    if cli.fail_on_match {
        flags.push(if !snap.fail_on_match {
            "--fail-on-match  [config]".into()
        } else {
            "--fail-on-match".into()
        });
    }
    if cli.no_structured_handoff {
        flags.push(if !snap.no_structured_handoff {
            "--no-structured-handoff  [config]".into()
        } else {
            "--no-structured-handoff".into()
        });
    }
    if cli.deterministic {
        flags.push(if !snap.deterministic {
            "--deterministic  [config]".into()
        } else {
            "--deterministic".into()
        });
    }
    if cli.dry_run {
        flags.push(if !snap.dry_run {
            "--dry-run  [config]".into()
        } else {
            "--dry-run".into()
        });
    }
    if !flags.is_empty() {
        eprintln!("  flags:    {}", flags.join(", "));
    }
    eprintln!();
}
