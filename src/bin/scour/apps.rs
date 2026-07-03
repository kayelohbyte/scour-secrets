use crate::cli_args::{AppsAddArgs, AppsArgs, AppsEditArgs, AppsRemoveArgs, AppsSubCommand};
use scour_secrets::processor::FileTypeProfile;
use scour_secrets::secrets::SecretEntry;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Built-in app bundles
// ---------------------------------------------------------------------------
//
// Each app lives in  src/bin/apps/<name>/
//   secrets.yaml  — Vec<SecretEntry>  (optional; omit when the app has none)
//   profile.yaml  — Vec<FileTypeProfile> (optional)
//
// User-defined apps follow the same two-file convention in a directory
// specified by the SCOUR_SECRETS_APPS_DIR environment variable, falling back to
// ~/.config/sanitize/apps  (XDG-compatible).
//
// The first YAML comment line (# ...) in either file is shown as the
// description in  `scour-secrets apps`.

/// Compiled content loaded from an app bundle directory.
pub(crate) struct AppBundle {
    pub(crate) secrets: Vec<SecretEntry>,
    pub(crate) profiles: Vec<FileTypeProfile>,
}

pub(crate) struct BuiltinApp {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    /// `Vec<SecretEntry>` YAML; None when the app has no unique secrets patterns.
    pub(crate) secrets_yaml: Option<&'static str>,
    /// `Vec<FileTypeProfile>` YAML; None when the app has no profile rules.
    pub(crate) profile_yaml: Option<&'static str>,
}

pub(crate) const BUILTIN_APPS: &[BuiltinApp] = &[
    BuiltinApp {
        name: "ansible",
        description: "Ansible — group_vars, host_vars, vault credentials",
        secrets_yaml: Some(include_str!("../../../apps/ansible/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/ansible/profile.yaml")),
    },
    BuiltinApp {
        name: "aws-cli",
        description: "AWS CLI — ~/.aws/credentials, ~/.aws/config access keys",
        secrets_yaml: Some(include_str!("../../../apps/aws-cli/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/aws-cli/profile.yaml")),
    },
    BuiltinApp {
        name: "circleci",
        description: "CircleCI — .circleci/config.yml job/step environment variables, docker auth",
        secrets_yaml: Some(include_str!("../../../apps/circleci/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/circleci/profile.yaml")),
    },
    BuiltinApp {
        name: "datadog",
        description: "Datadog Agent — datadog.yaml API keys, proxy credentials, SNMP auth, cluster agent tokens",
        secrets_yaml: Some(include_str!("../../../apps/datadog/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/datadog/profile.yaml")),
    },
    BuiltinApp {
        name: "dataiku",
        description: "Dataiku DSS — diagnosis bundle: connection creds, user password hashes, DB server keys, LDAP/SSO settings, license, API keys",
        secrets_yaml: Some(include_str!("../../../apps/dataiku/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/dataiku/profile.yaml")),
    },
    BuiltinApp {
        name: "django",
        description: "Django — .env files, SECRET_KEY, database credentials, third-party API keys",
        secrets_yaml: Some(include_str!("../../../apps/django/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/django/profile.yaml")),
    },
    BuiltinApp {
        name: "docker-compose",
        description: "Docker Compose — compose.yml environment variables, image credentials",
        secrets_yaml: Some(include_str!("../../../apps/docker-compose/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/docker-compose/profile.yaml")),
    },
    BuiltinApp {
        name: "elasticsearch",
        description: "Elasticsearch — elasticsearch.yml, Kibana/Logstash credentials",
        secrets_yaml: Some(include_str!("../../../apps/elasticsearch/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/elasticsearch/profile.yaml")),
    },
    BuiltinApp {
        name: "fstab",
        description: "fstab — /etc/fstab CIFS/SMB credentials, NFS and iSCSI server addresses",
        secrets_yaml: Some(include_str!("../../../apps/fstab/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/fstab/profile.yaml")),
    },
    BuiltinApp {
        name: "github-actions",
        description: "GitHub Actions — workflow env vars, step inputs, container registry credentials",
        secrets_yaml: Some(include_str!("../../../apps/github-actions/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/github-actions/profile.yaml")),
    },
    BuiltinApp {
        name: "gitlab",
        description: "GitLab — CI/CD logs, runner output, .gitlab-ci.yml variables",
        secrets_yaml: Some(include_str!("../../../apps/gitlab/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/gitlab/profile.yaml")),
    },
    BuiltinApp {
        name: "grafana",
        description: "Grafana — grafana.ini admin credentials, provisioning datasource secrets",
        secrets_yaml: Some(include_str!("../../../apps/grafana/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/grafana/profile.yaml")),
    },
    BuiltinApp {
        name: "bruno",
        description: "Bruno — .bru collections and OpenCollection YAML (Bruno 3.0+) credentials",
        secrets_yaml: Some(include_str!("../../../apps/bruno/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/bruno/profile.yaml")),
    },
    BuiltinApp {
        name: "har",
        description: "HAR (HTTP Archive) — browser-captured request/response traffic, auth headers, cookies",
        secrets_yaml: Some(include_str!("../../../apps/har/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/har/profile.yaml")),
    },
    BuiltinApp {
        name: "insomnia",
        description: "Insomnia — workspace exports, request auth, environment variables",
        secrets_yaml: Some(include_str!("../../../apps/insomnia/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/insomnia/profile.yaml")),
    },
    BuiltinApp {
        name: "heroku",
        description: "Heroku — app.json env values, add-on credentials (Postgres, Redis, SendGrid, Mailgun, Cloudinary…)",
        secrets_yaml: Some(include_str!("../../../apps/heroku/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/heroku/profile.yaml")),
    },
    BuiltinApp {
        name: "kubernetes",
        description: "Kubernetes — kubeconfig credentials, Secret manifests, Helm values",
        secrets_yaml: Some(include_str!("../../../apps/kubernetes/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/kubernetes/profile.yaml")),
    },
    BuiltinApp {
        name: "laravel",
        description: "Laravel — .env files, APP_KEY, Pusher, Passport, Stripe secrets",
        secrets_yaml: Some(include_str!("../../../apps/laravel/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/laravel/profile.yaml")),
    },
    BuiltinApp {
        name: "mongodb",
        description: "MongoDB — mongod.conf TLS passwords, .env connection strings",
        secrets_yaml: Some(include_str!("../../../apps/mongodb/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/mongodb/profile.yaml")),
    },
    BuiltinApp {
        name: "mysql",
        description: "MySQL / MariaDB — my.cnf credentials, .env DATABASE_URL",
        secrets_yaml: Some(include_str!("../../../apps/mysql/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/mysql/profile.yaml")),
    },
    BuiltinApp {
        name: "postman",
        description: "Postman — collection credentials, environment variables, auth configs",
        secrets_yaml: Some(include_str!("../../../apps/postman/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/postman/profile.yaml")),
    },
    BuiltinApp {
        name: "nginx",
        description: "Nginx — nginx.conf virtual hosts, proxy upstreams, access/error logs",
        secrets_yaml: Some(include_str!("../../../apps/nginx/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/nginx/profile.yaml")),
    },
    BuiltinApp {
        name: "postgresql",
        description: "PostgreSQL — postgresql.conf, connection strings, pg logs",
        secrets_yaml: Some(include_str!("../../../apps/postgresql/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/postgresql/profile.yaml")),
    },
    BuiltinApp {
        name: "rails",
        description: "Ruby on Rails — database.yml, .env, config/secrets.yml",
        secrets_yaml: Some(include_str!("../../../apps/rails/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/rails/profile.yaml")),
    },
    BuiltinApp {
        name: "redis",
        description: "Redis — redis.conf requirepass/masterauth, .env credentials",
        secrets_yaml: Some(include_str!("../../../apps/redis/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/redis/profile.yaml")),
    },
    BuiltinApp {
        name: "splunk",
        description: "Splunk — outputs.conf, inputs.conf, authentication.conf credentials",
        secrets_yaml: Some(include_str!("../../../apps/splunk/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/splunk/profile.yaml")),
    },
    BuiltinApp {
        name: "spring-boot",
        description:
            "Spring Boot — application.yml, application.properties, datasource credentials",
        secrets_yaml: Some(include_str!("../../../apps/spring-boot/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/spring-boot/profile.yaml")),
    },
    BuiltinApp {
        name: "terraform",
        description: "Terraform — *.tfvars variable files, terraform.tfstate sensitive outputs",
        secrets_yaml: Some(include_str!("../../../apps/terraform/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/terraform/profile.yaml")),
    },
];

/// Return a sorted list of all built-in app names.
pub(crate) fn builtin_app_names() -> Vec<&'static str> {
    BUILTIN_APPS.iter().map(|a| a.name).collect()
}

/// Resolve the user-defined apps directory.
///
/// Checks `SCOUR_SECRETS_APPS_DIR` first, then falls back to
/// `~/.config/sanitize/apps` (XDG base directory convention).
pub(crate) fn user_apps_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("SCOUR_SECRETS_APPS_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    std::env::var("HOME").ok().map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("scour")
            .join("apps")
    })
}

/// Parse a YAML file as `T`, returning a clear error on failure.
fn parse_yaml_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_yaml_ng::from_str(&content)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

/// Read the first `# description` comment line from a YAML file, if present.
fn read_app_description(app_dir: &Path) -> String {
    for filename in &["secrets.yaml", "profile.yaml"] {
        let path = app_dir.join(filename);
        if let Ok(content) = fs::read_to_string(&path) {
            if let Some(line) = content.lines().next() {
                if let Some(rest) = line.strip_prefix('#') {
                    let desc = rest.trim().to_string();
                    if !desc.is_empty() {
                        return desc;
                    }
                }
            }
        }
    }
    String::new()
}

/// Ensure a local user copy of a built-in app bundle exists.
///
/// Called automatically when `--app <name>` is used. If the user app directory
/// for `name` does not yet exist, both `profile.yaml` and `secrets.yaml` are
/// copied from the built-in bundle so that:
///
/// - The profile and secrets files are editable without running `scour-secrets apps edit`.
/// - Discovered literal values from the profile pass can be persisted back into
///   `secrets.yaml` by subsequent runs.
///
/// Returns the path to the user `secrets.yaml` on success, or `None` when the
/// app is not a built-in or the directory could not be created.
///
/// If the directory already exists this is a no-op; existing customisations are
/// never overwritten.
pub(crate) fn ensure_user_app_copy(name: &str) -> Option<PathBuf> {
    let apps_dir = user_apps_dir()?;
    let app_dir = apps_dir.join(name);

    // Already provisioned — return the secrets file path (may or may not exist yet).
    if app_dir.is_dir() {
        return Some(app_dir.join("secrets.yaml"));
    }

    // Only provision built-in apps; custom apps have no source to copy from.
    let entry = BUILTIN_APPS.iter().find(|a| a.name == name)?;

    if let Err(e) = fs::create_dir_all(&app_dir) {
        eprintln!(
            "warning: could not create app directory {}: {e}",
            app_dir.display()
        );
        return None;
    }

    let mut ok = true;

    if let Some(yaml) = entry.profile_yaml {
        let dst = app_dir.join("profile.yaml");
        if let Err(e) = fs::write(&dst, yaml) {
            eprintln!("warning: could not write {}: {e}", dst.display());
            ok = false;
        }
    }

    if let Some(yaml) = entry.secrets_yaml {
        let dst = app_dir.join("secrets.yaml");
        if let Err(e) = fs::write(&dst, yaml) {
            eprintln!("warning: could not write {}: {e}", dst.display());
            ok = false;
        }
    }

    if !ok {
        let _ = fs::remove_dir_all(&app_dir);
        return None;
    }

    Some(app_dir.join("secrets.yaml"))
}

/// Load an app bundle by name.
///
/// Resolution order:
///   1. User apps directory (`SCOUR_SECRETS_APPS_DIR` or `~/.config/sanitize/apps/<name>/`)
///   2. Built-in apps embedded in the binary
pub(crate) fn load_app_bundle(name: &str) -> Result<AppBundle, String> {
    // 1. User-defined app takes precedence over built-in.
    if let Some(apps_dir) = user_apps_dir() {
        let app_dir = apps_dir.join(name);
        if app_dir.is_dir() {
            let secrets_path = app_dir.join("secrets.yaml");
            let profile_path = app_dir.join("profile.yaml");

            let secrets: Vec<SecretEntry> = if secrets_path.exists() {
                parse_yaml_file(&secrets_path)?
            } else {
                vec![]
            };
            let profiles: Vec<FileTypeProfile> = if profile_path.exists() {
                parse_yaml_file(&profile_path)?
            } else {
                vec![]
            };
            return Ok(AppBundle { secrets, profiles });
        }
    }

    // 2. Built-in app.
    let entry = BUILTIN_APPS
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| {
            format!(
                "unknown app '{}'. Built-in apps: {}. \
                 Add a custom app at $SCOUR_SECRETS_APPS_DIR/{} (secrets.yaml / profile.yaml).",
                name,
                builtin_app_names().join(", "),
                name,
            )
        })?;

    let secrets: Vec<SecretEntry> = match entry.secrets_yaml {
        Some(yaml) => serde_yaml_ng::from_str(yaml)
            .map_err(|e| format!("failed to parse built-in secrets for '{}': {e}", name))?,
        None => vec![],
    };
    let profiles: Vec<FileTypeProfile> = match entry.profile_yaml {
        Some(yaml) => serde_yaml_ng::from_str(yaml)
            .map_err(|e| format!("failed to parse built-in profile for '{}': {e}", name))?,
        None => vec![],
    };

    Ok(AppBundle { secrets, profiles })
}

pub(crate) fn validate_app_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("app name cannot be empty".into());
    }
    if !name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(format!(
            "app name '{name}' must start with a letter or digit"
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
    {
        return Err(format!(
            "app name '{name}' contains invalid character '{bad}'; \
             only letters, digits, hyphens, and underscores are allowed"
        ));
    }
    Ok(())
}

pub(crate) fn run_apps(args: &AppsArgs) -> Result<(), (String, i32)> {
    match &args.command {
        None => run_apps_list(),
        Some(AppsSubCommand::Add(a)) => run_apps_add(a),
        Some(AppsSubCommand::Remove(a)) => run_apps_remove(a),
        Some(AppsSubCommand::Edit(a)) => run_apps_edit(a),
        Some(AppsSubCommand::Dir) => run_apps_dir(),
    }
}

fn run_apps_list() -> Result<(), (String, i32)> {
    let overridden: std::collections::HashSet<String> = user_apps_dir()
        .filter(|d| d.is_dir())
        .map(|d| {
            fs::read_dir(&d)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();

    println!("Built-in app bundles (use with --app <name>):\n");
    for app in BUILTIN_APPS {
        if overridden.contains(app.name) {
            println!(
                "  {:<18} {} (overridden by user copy)",
                app.name, app.description
            );
        } else {
            println!("  {:<18} {}", app.name, app.description);
        }
    }

    let apps_dir = user_apps_dir();
    let dir_display = apps_dir
        .as_ref()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "~/.config/scour/apps".into());

    if let Some(ref dir) = apps_dir {
        if dir.is_dir() {
            let mut user_apps: Vec<(String, String)> = fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                        .map(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            let desc = read_app_description(&e.path());
                            (name, desc)
                        })
                        .collect()
                })
                .unwrap_or_default();
            user_apps.sort_by(|a, b| a.0.cmp(&b.0));

            if !user_apps.is_empty() {
                println!("\nUser-defined apps (from {dir_display}):\n");
                for (name, desc) in &user_apps {
                    if desc.is_empty() {
                        println!("  {name}");
                    } else {
                        println!("  {:<18} {}", name, desc);
                    }
                }
            }
        }
    }

    println!("\nCombine multiple apps:  sanitize file.zip --app gitlab,nginx,postgresql");
    println!(
        "Manage custom apps:     sanitize apps edit <name>        # copy built-in for editing"
    );
    println!("                        sanitize apps add <name> --profile p.yaml --secrets s.yaml");
    println!("                        sanitize apps remove <name> --yes");
    println!("                        sanitize apps dir");
    Ok(())
}

fn run_apps_add(args: &AppsAddArgs) -> Result<(), (String, i32)> {
    validate_app_name(&args.name).map_err(|e| (e, 1))?;

    if args.profile.is_none() && args.secrets_file.is_none() {
        return Err((
            "at least one of --profile or --secrets-file must be provided".into(),
            1,
        ));
    }

    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".into(),
            1,
        )
    })?;

    let target_dir = apps_dir.join(&args.name);

    if target_dir.exists() && !args.overwrite {
        return Err((
            format!(
                "app '{}' already exists at {}.\nUse --overwrite to replace it.",
                args.name,
                target_dir.display()
            ),
            1,
        ));
    }

    // Validate files parse correctly before touching the filesystem.
    if let Some(ref path) = args.profile {
        let _profiles: Vec<FileTypeProfile> =
            parse_yaml_file(path).map_err(|e| (format!("--profile: {e}"), 1))?;
    }
    if let Some(ref path) = args.secrets_file {
        let _secrets: Vec<SecretEntry> =
            parse_yaml_file(path).map_err(|e| (format!("--secrets-file: {e}"), 1))?;
    }

    fs::create_dir_all(&target_dir)
        .map_err(|e| (format!("failed to create {}: {e}", target_dir.display()), 1))?;

    if let Some(ref src) = args.profile {
        let dst = target_dir.join("profile.yaml");
        fs::copy(src, &dst).map_err(|e| {
            (
                format!("failed to copy profile to {}: {e}", dst.display()),
                1,
            )
        })?;
    }
    if let Some(ref src) = args.secrets_file {
        let dst = target_dir.join("secrets.yaml");
        fs::copy(src, &dst).map_err(|e| {
            (
                format!("failed to copy secrets to {}: {e}", dst.display()),
                1,
            )
        })?;
    }

    println!("Installed app '{}' → {}", args.name, target_dir.display());
    if args.profile.is_some() {
        println!("  profile.yaml  ✓");
    }
    if args.secrets_file.is_some() {
        println!("  secrets.yaml  ✓");
    }
    println!("\nUse it with:  sanitize <file> --app {}", args.name);
    Ok(())
}

fn run_apps_remove(args: &AppsRemoveArgs) -> Result<(), (String, i32)> {
    validate_app_name(&args.name).map_err(|e| (e, 1))?;

    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".into(),
            1,
        )
    })?;

    let target_dir = apps_dir.join(&args.name);

    // Only a user copy (in the apps dir) can be removed.  Refuse when the
    // name is a built-in AND there is no user copy to revert.
    if !target_dir.is_dir() {
        if BUILTIN_APPS.iter().any(|a| a.name == args.name.as_str()) {
            return Err((
                format!(
                    "'{}' is a built-in app — nothing to remove.\n\
                     Use `scour-secrets apps edit {}` first to create a local copy.",
                    args.name, args.name
                ),
                1,
            ));
        }
        return Err((
            format!(
                "no custom app '{}' found at {}",
                args.name,
                target_dir.display()
            ),
            1,
        ));
    }

    if !args.yes {
        return Err((
            format!(
                "this will permanently delete {}\nRe-run with --yes to confirm.",
                target_dir.display()
            ),
            1,
        ));
    }

    fs::remove_dir_all(&target_dir)
        .map_err(|e| (format!("failed to remove {}: {e}", target_dir.display()), 1))?;

    let is_builtin = BUILTIN_APPS.iter().any(|a| a.name == args.name.as_str());
    println!("Removed app '{}'  ({})", args.name, target_dir.display());
    if is_builtin {
        println!("Built-in '{}' is now active again.", args.name);
    }
    Ok(())
}

fn run_apps_edit(args: &AppsEditArgs) -> Result<(), (String, i32)> {
    validate_app_name(&args.name).map_err(|e| (e, 1))?;

    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".into(),
            1,
        )
    })?;

    let target_dir = apps_dir.join(&args.name);

    // Already a user-defined app — just show the path.
    if target_dir.is_dir() {
        println!("'{}' is already in your user apps directory:", args.name);
        println!("  {}", target_dir.display());
        for file in &["profile.yaml", "secrets.yaml"] {
            let p = target_dir.join(file);
            if p.exists() {
                println!("  {}", p.display());
            }
        }
        println!("\nEdits here already override the built-in.");
        println!("To revert:  sanitize apps remove {} --yes", args.name);
        return Ok(());
    }

    // Must be a built-in.
    let entry = BUILTIN_APPS
        .iter()
        .find(|a| a.name == args.name.as_str())
        .ok_or_else(|| {
            format!(
                "unknown app '{}'. Built-in apps: {}.",
                args.name,
                builtin_app_names().join(", ")
            )
        })
        .map_err(|e| (e, 1))?;

    fs::create_dir_all(&target_dir)
        .map_err(|e| (format!("failed to create {}: {e}", target_dir.display()), 1))?;

    let mut wrote: Vec<PathBuf> = vec![];

    if let Some(yaml) = entry.profile_yaml {
        let dst = target_dir.join("profile.yaml");
        fs::write(&dst, yaml)
            .map_err(|e| (format!("failed to write {}: {e}", dst.display()), 1))?;
        wrote.push(dst);
    }
    if let Some(yaml) = entry.secrets_yaml {
        let dst = target_dir.join("secrets.yaml");
        fs::write(&dst, yaml)
            .map_err(|e| (format!("failed to write {}: {e}", dst.display()), 1))?;
        wrote.push(dst);
    }

    println!(
        "Copied built-in '{}' to your user apps directory:",
        args.name
    );
    for path in &wrote {
        println!("  {}", path.display());
    }
    println!(
        "\nEdits here override the built-in — use --app {} as usual.",
        args.name
    );
    println!("To revert:  sanitize apps remove {} --yes", args.name);

    Ok(())
}

fn run_apps_dir() -> Result<(), (String, i32)> {
    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".into(),
            1,
        )
    })?;

    println!("{}", apps_dir.display());

    if !apps_dir.exists() {
        eprintln!(
            "note: directory does not exist yet — it will be created automatically by `scour-secrets apps add`"
        );
    }

    Ok(())
}
