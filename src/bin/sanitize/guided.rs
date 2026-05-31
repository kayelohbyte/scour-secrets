use crate::scanner_builder::common_allow_patterns;
use sanitize_engine::processor::FileTypeProfile;
use sanitize_engine::secrets::SecretEntry;
use sanitize_engine::{Category, FieldRule};
use std::collections::HashSet;
use std::io::{self, Write};

pub(crate) fn parse_template_preset(s: &str) -> Result<TemplatePreset, String> {
    match s {
        "generic" => Ok(TemplatePreset::Generic),
        "web" => Ok(TemplatePreset::Web),
        "k8s" | "kubernetes" => Ok(TemplatePreset::K8s),
        "database" | "db" => Ok(TemplatePreset::Database),
        "aws" => Ok(TemplatePreset::Aws),
        other => Err(format!(
            "unknown preset '{}' (choices: generic, web, k8s, database, aws)",
            other
        )),
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum TemplatePreset {
    Generic,
    Web,
    K8s,
    Database,
    Aws,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum GuidedPreset {
    Balanced,
    Aggressive,
    WebApp,
    Kubernetes,
    Database,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

/// Structured file formats to include in the generated profile.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum GuidedFormat {
    YamlJson,
    JsonLines,
    Env,
    Toml,
    IniConf,
}

#[derive(Clone, Debug)]
pub(crate) struct GuidedOptions {
    pub(crate) preset: GuidedPreset,
    pub(crate) domains: Vec<String>,
    pub(crate) providers: Vec<CloudProvider>,
    pub(crate) exclude_noise_ids: bool,
    pub(crate) formats: Vec<GuidedFormat>,
}

pub(crate) fn prompt_line(prompt: &str) -> Result<String, String> {
    let mut stdout = io::stdout();
    write!(stdout, "{}", prompt).map_err(|e| format!("failed to write prompt: {e}"))?;
    stdout
        .flush()
        .map_err(|e| format!("failed to flush prompt: {e}"))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("failed to read input: {e}"))?;
    Ok(input.trim().to_string())
}

pub(crate) fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool, String> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        let answer = prompt_line(&format!("{} {} ", prompt, suffix))?;
        if answer.is_empty() {
            return Ok(default_yes);
        }
        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("Please answer 'y' or 'n'."),
        }
    }
}

fn sanitize_domain(input: &str) -> Option<String> {
    let trimmed = input.trim().trim_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some(trimmed)
}

pub(crate) fn prompt_domains() -> Result<Vec<String>, String> {
    let raw = prompt_line(
        "Company domains (comma-separated, up to 3, optional; e.g. corp.internal,example.com): ",
    )?;
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in raw.split(',') {
        let Some(domain) = sanitize_domain(item) else {
            return Err(format!("invalid domain value: '{}'", item.trim()));
        };
        if seen.insert(domain.clone()) {
            out.push(domain);
        }
    }

    if out.len() > 3 {
        return Err("please provide at most 3 domains".into());
    }
    Ok(out)
}

pub(crate) fn prompt_cloud_providers() -> Result<Vec<CloudProvider>, String> {
    eprintln!("Cloud providers in scope:");
    eprintln!("  1) AWS");
    eprintln!("  2) Azure");
    eprintln!("  3) GCP");
    eprintln!("  4) None");
    let raw = prompt_line("Select one or more (comma-separated numbers, default: 4): ")?;
    if raw.trim().is_empty() || raw.trim() == "4" {
        return Ok(vec![]);
    }

    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    for token in raw.split(',').map(|s| s.trim()) {
        let provider = match token {
            "1" => CloudProvider::Aws,
            "2" => CloudProvider::Azure,
            "3" => CloudProvider::Gcp,
            "4" => continue,
            _ => return Err(format!("invalid selection: '{token}'")),
        };
        if seen.insert(provider) {
            selected.push(provider);
        }
    }
    Ok(selected)
}

pub(crate) const ALL_FORMATS: &[GuidedFormat] = &[
    GuidedFormat::YamlJson,
    GuidedFormat::JsonLines,
    GuidedFormat::Env,
    GuidedFormat::Toml,
    GuidedFormat::IniConf,
];

pub(crate) fn prompt_formats() -> Result<Vec<GuidedFormat>, String> {
    eprintln!("Structured file formats to include in profile (controls field-level redaction):");
    eprintln!("  1) YAML / JSON    — k8s manifests, docker-compose, app configs");
    eprintln!("  2) JSON Lines     — NDJSON structured logs (.jsonl, .ndjson)");
    eprintln!("  3) .env files     — twelve-factor app secrets, CI variables");
    eprintln!("  4) TOML           — Rust, Hugo, and other TOML configs");
    eprintln!("  5) INI / conf     — system services, databases, legacy apps");
    eprintln!("  6) All of the above (default)");
    eprintln!("  7) None           — secrets file only, no profile");
    let raw = prompt_line("Select one or more (comma-separated, default: 6): ")?;

    if raw.trim().is_empty() || raw.trim() == "6" {
        return Ok(ALL_FORMATS.to_vec());
    }
    if raw.trim() == "7" {
        return Ok(vec![]);
    }

    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    for token in raw.split(',').map(|s| s.trim()) {
        let fmt = match token {
            "1" => GuidedFormat::YamlJson,
            "2" => GuidedFormat::JsonLines,
            "3" => GuidedFormat::Env,
            "4" => GuidedFormat::Toml,
            "5" => GuidedFormat::IniConf,
            "6" => return Ok(ALL_FORMATS.to_vec()),
            "7" => return Ok(vec![]),
            _ => return Err(format!("invalid selection: '{token}'")),
        };
        if seen.insert(fmt) {
            selected.push(fmt);
        }
    }
    Ok(selected)
}

fn make_regex_entry(pattern: &str, category: &str, label: &str) -> SecretEntry {
    SecretEntry {
        pattern: pattern.to_string(),
        kind: "regex".to_string(),
        category: category.to_string(),
        label: Some(label.to_string()),
        values: vec![],
        min_length: None,
        max_length: None,
        threshold: None,
        charset: None,
    }
}

pub(crate) fn build_guided_entries(opts: &GuidedOptions) -> Vec<SecretEntry> {
    let mut entries = vec![
        // Emails — low false-positive, high value across all use cases.
        make_regex_entry(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "email",
            "email",
        ),
        // IPv4 addresses — pods, services, client IPs in logs.
        make_regex_entry(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ipv4", "ipv4"),
        // IPv6 — full form: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        make_regex_entry(
            r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b",
            "ipv6",
            "ipv6_full",
        ),
        // IPv6 — compressed form: fe80::1, ::1, 2001:db8::1, ::ffff:10.0.0.1
        make_regex_entry(
            r"\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{0,4}\b|\b::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b",
            "ipv6",
            "ipv6_compressed",
        ),
        // UUIDs — request IDs, pod IDs, resource IDs.
        make_regex_entry(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
            "uuid",
            "uuid",
        ),
        // JWTs — service account tokens, OIDC, bearer tokens.
        make_regex_entry(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            "jwt",
            "jwt",
        ),
        // URLs including query strings (may contain tokens or credentials).
        make_regex_entry(r#"https?://[^\s"'<>;]+"#, "url", "url"),
        // Non-HTTP URLs with embedded credentials: postgres://user:pass@host, redis://:pass@host.
        make_regex_entry(
            r#"[a-z][a-z0-9+.-]+://[^:@\s]{1,128}:[^@\s]{1,128}@[^\s"'<>]+"#,
            "url",
            "credential_url",
        ),
        // PEM / private key headers — appears in certs, k8s secrets, CI vars.
        // Near-zero false positives.
        make_regex_entry(
            r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----",
            "auth_token",
            "private_key_header",
        ),
        // Generic secret key=value in any text format.
        // Matches: api_key=..., client_secret: ..., access_token: ..., etc.
        make_regex_entry(
            r#"(?i)(?:api_key|api_secret|access_token|client_secret|private_key|secret_key|auth_key|signing_key|jwt_secret|jwt_key)[\s:="']+[A-Za-z0-9._~+/=-]{16,}"#,
            "auth_token",
            "secret_kv",
        ),
        // Password in key=value / YAML / env form (broader than db_password).
        make_regex_entry(
            r#"(?i)(?:password|passwd|pwd)[\s:="']+[^\s"']{6,}"#,
            "custom:password",
            "password_kv",
        ),
        // File paths that expose usernames (/home/alice, /Users/alice).
        make_regex_entry(
            r"/(?:home|Users)/[A-Za-z0-9_.-]+",
            "file_path",
            "user_home_path",
        ),
        // Docker / OCI image digests (sha256:...) — exact 64-char hex after prefix.
        make_regex_entry(r"\bsha256:[a-f0-9]{64}\b", "container_id", "image_digest"),
        // MAC addresses.
        make_regex_entry(
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            "mac_address",
            "mac_address",
        ),
        // GitHub tokens — personal access (ghp_), OAuth (gho_), user-to-server (ghu_),
        // server-to-server/Actions (ghs_), refresh (ghr_).
        make_regex_entry(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b",
            "auth_token",
            "github_token",
        ),
        make_regex_entry(
            r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
            "auth_token",
            "github_pat_fine_grained",
        ),
        // GCP API keys — AIza prefix, near-zero false positives.
        make_regex_entry(r"\bAIza[A-Za-z0-9_-]{35}\b", "auth_token", "gcp_api_key"),
        // AWS Access Key IDs — specific prefixes, near-zero false positives.
        // Applies to all workspace types; AWS credentials appear in any log or config.
        make_regex_entry(
            r"\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b",
            "auth_token",
            "aws_access_key_id",
        ),
        // OpenAI API keys — old format (sk-...) and new project-scoped (sk-proj-...).
        make_regex_entry(
            r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b",
            "auth_token",
            "openai_api_key",
        ),
        // Anthropic API keys.
        make_regex_entry(
            r"\bsk-ant-[A-Za-z0-9_-]{93,}\b",
            "auth_token",
            "anthropic_api_key",
        ),
        // Slack tokens — bot (xoxb-), user (xoxp-), workspace (xoxa-/xoxr-).
        make_regex_entry(
            r"\bxox[bpars]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b",
            "auth_token",
            "slack_token",
        ),
        // npm access tokens.
        make_regex_entry(r"\bnpm_[A-Za-z0-9]{36}\b", "auth_token", "npm_token"),
        // HuggingFace access tokens.
        make_regex_entry(r"\bhf_[A-Za-z0-9]{34}\b", "auth_token", "huggingface_token"),
        // Stripe secret/publishable/restricted keys — live and test.
        make_regex_entry(
            r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b",
            "auth_token",
            "stripe_key",
        ),
        // GitLab personal/project/group access tokens.
        make_regex_entry(r"\bglpat-[A-Za-z0-9_-]{20}\b", "auth_token", "gitlab_token"),
        // SendGrid API keys — two-segment dot-separated format.
        make_regex_entry(
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
            "auth_token",
            "sendgrid_api_key",
        ),
        // Twilio Account SIDs — AC prefix + 32 hex chars.
        make_regex_entry(r"\bAC[a-f0-9]{32}\b", "auth_token", "twilio_account_sid"),
    ];

    // Hostname regex is intentionally NOT in the base set — it matches any
    // dotted word (log.level, db.name, fmt.Println) and creates too much noise
    // in application logs. User-specified domain literals are added below,
    // and cloud-specific host patterns are added per-provider.
    // Enable it explicitly with the Aggressive preset.
    if matches!(opts.preset, GuidedPreset::Aggressive) {
        entries.push(make_regex_entry(
            r"\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.){2,}(?:[a-zA-Z]{2,63})\b",
            "hostname",
            "hostname",
        ));
        // Short container IDs (docker ps short form — 12 hex chars).
        // Aggressive-only because bare 12-hex-char strings appear frequently
        // in hex color codes, version hashes, and other non-container contexts.
        entries.push(make_regex_entry(
            r"\b[a-f0-9]{12}\b",
            "container_id",
            "container_id_short",
        ));
    }

    if matches!(
        opts.preset,
        GuidedPreset::Aggressive
            | GuidedPreset::WebApp
            | GuidedPreset::Kubernetes
            | GuidedPreset::Database
    ) {
        // Catches "Bearer <token>" regardless of surrounding context, including
        // "Authorization: Bearer <token>" HTTP headers.
        entries.push(make_regex_entry(
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b",
            "auth_token",
            "bearer_token",
        ));
        // Catches "authorization: <direct_value>" in configs/env where the value
        // is not prefixed with "Bearer".
        entries.push(make_regex_entry(
            r#"(?i)\bauthorization[\s:="']+[A-Za-z0-9._~+/=-]{16,}\b"#,
            "auth_token",
            "authorization_kv",
        ));
        // 32-char minimum filters most legitimate log identifiers (class names,
        // method names, log fields) while still catching real tokens. 20 chars
        // was too low and fired on common words and identifiers in stack traces.
        entries.push(make_regex_entry(
            r"\b[A-Za-z0-9_\-]{32,}\b",
            "custom:high_entropy_token",
            "high_entropy_token",
        ));
    }

    // Web-app specific: session cookies, OAuth tokens, refresh tokens.
    if matches!(opts.preset, GuidedPreset::WebApp) {
        entries.push(make_regex_entry(
            r"(?i)\bsess(?:ion)?[_-]?(?:id|token|key)[\s:=]+[A-Za-z0-9._~+/=-]{8,}\b",
            "auth_token",
            "session_id",
        ));
        entries.push(make_regex_entry(
            r"(?i)(?:refresh|access)[_-]?token[\s:=]+[A-Za-z0-9._~+/=-]{16,}",
            "auth_token",
            "oauth_token",
        ));
    }

    // Kubernetes specific: service account tokens, namespaces.
    if matches!(opts.preset, GuidedPreset::Kubernetes) {
        entries.push(make_regex_entry(
            r"(?i)token[\s:]+[A-Za-z0-9._~+/=-]{20,}",
            "auth_token",
            "k8s_token",
        ));
        entries.push(make_regex_entry(
            r"\bnamespace[:\s]+[a-z][a-z0-9-]{2,62}\b",
            "custom:k8s_namespace",
            "k8s_namespace",
        ));
        // Full SHA256 image digests in pod specs.
        entries.push(make_regex_entry(
            r"\b[a-f0-9]{64}\b",
            "container_id",
            "k8s_image_sha",
        ));
        // Short container IDs are common in kubectl/docker output; safe to
        // include here because K8s logs heavily feature these 12-char hashes.
        entries.push(make_regex_entry(
            r"\b[a-f0-9]{12}\b",
            "container_id",
            "container_id_short",
        ));
    }

    // Database specific: connection strings with embedded credentials.
    if matches!(opts.preset, GuidedPreset::Database) {
        entries.push(make_regex_entry(
            r#"(?i)(?:postgres|mysql|mongodb|redis|amqp|jdbc:[^:]+)://[^\s"'>]+"#,
            "url",
            "db_connection_string",
        ));
        entries.push(make_regex_entry(
            r#"(?i)(?:user|username|login)[\s:="']+[^\s"']{3,}"#,
            "name",
            "db_username",
        ));
    }

    // User-specified domain literals: email and hostname patterns anchored
    // to the domain, so they only fire on that org's addresses/hosts.
    for domain in &opts.domains {
        let escaped = regex::escape(domain);
        entries.push(make_regex_entry(
            &format!(r"[A-Za-z0-9._%+-]+@{}", escaped),
            "email",
            &format!("email_{}", domain.replace('.', "_")),
        ));
        entries.push(make_regex_entry(
            &format!(r"\b(?:[A-Za-z0-9-]+\.)*{}\b", escaped),
            "hostname",
            &format!("host_{}", domain.replace('.', "_")),
        ));
    }

    let has_aws = opts.providers.contains(&CloudProvider::Aws);
    let has_azure = opts.providers.contains(&CloudProvider::Azure);
    let has_gcp = opts.providers.contains(&CloudProvider::Gcp);

    if has_aws {
        entries.push(make_regex_entry(
            r"\barn:aws:[^\s]+\b",
            "aws_arn",
            "aws_arn",
        ));
        // Access key ID is already in the base set; the AWS provider block adds
        // the secret access key (too noisy without the KV context anchor).
        entries.push(make_regex_entry(
            r#"(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)[\s:="']+[A-Za-z0-9/+=]{40}\b"#,
            "auth_token",
            "aws_secret_access_key",
        ));
        // AWS account IDs in ARNs are already covered; standalone 12-digit
        // numbers are too noisy to match globally.
        entries.push(make_regex_entry(
            r"\bi-[0-9a-f]{8,17}\b",
            "container_id",
            "ec2_instance_id",
        ));
    }
    if has_azure {
        entries.push(make_regex_entry(
            r"/subscriptions/[0-9a-fA-F-]{8,}/resourceGroups/[^\s/]+(?:/providers/[^\s]+)?",
            "azure_resource_id",
            "azure_resource_id",
        ));
    }
    if has_gcp {
        entries.push(make_regex_entry(
            r"\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b",
            "custom:gcp_service_account",
            "gcp_service_account",
        ));
        entries.push(make_regex_entry(
            r"\bprojects/[a-z][a-z0-9-]{4,30}/[A-Za-z0-9/_-]+\b",
            "custom:gcp_resource",
            "gcp_resource",
        ));
    }

    if opts.exclude_noise_ids {
        entries.retain(|entry| entry.label.as_deref() != Some("high_entropy_token"));
    }

    // Common allow entries — included in every preset so the guided wizard
    // writes them to the output secrets file and users start with a sane baseline.
    entries.push(SecretEntry {
        pattern: String::new(),
        kind: "allow".into(),
        category: String::new(),
        label: Some("common_safe_values".into()),
        values: common_allow_patterns(),
        min_length: None,
        max_length: None,
        threshold: None,
        charset: None,
    });

    entries
}

/// YAML comment header written at the top of every generated profile file.
pub(crate) const PROFILE_HEADER: &str = "\
# =============================================================================
# sanitize profile — structured field rules
# =============================================================================
#
# PURPOSE
#   This file tells sanitize which fields to redact inside structured files
#   (YAML, JSON, .env, TOML, INI, NDJSON) before sending to an LLM or
#   external service. It works alongside the secrets file: the secrets file
#   covers free-text patterns; this file covers key=value fields.
#
# HOW TO USE
#   sanitize input/ -s secrets.yaml --profile profile.yaml -o output/
#
# SAFE TO COMMIT
#   This file contains no secrets — only field name patterns. Commit it
#   alongside your sanitize secrets file (which you should encrypt).
#
# FIELD REFERENCE
#   processor   string   Required. Processor name: yaml, json, jsonl, env, toml, ini.
#   extensions  list     File extensions this profile applies to.
#   fields      list     Field rules: pattern (glob) + category.
#   options     map      Processor-specific options (e.g. compact, skip_invalid).
#
# WARNING: REVIEW OUTPUT BEFORE SENDING TO AN LLM.
#          Field rules redact exact keys — add regex patterns in secrets.yaml
#          to catch values that appear outside structured fields.
# =============================================================================
";

pub(crate) fn build_guided_profiles(opts: &GuidedOptions) -> Vec<FileTypeProfile> {
    // Shared sensitive field patterns applicable to most structured formats.
    let credential_fields = || -> Vec<FieldRule> {
        vec![
            FieldRule::new("*.password").with_category(Category::Custom("password".into())),
            FieldRule::new("*.passwd").with_category(Category::Custom("password".into())),
            FieldRule::new("*.secret").with_category(Category::AuthToken),
            FieldRule::new("*.secret_key").with_category(Category::AuthToken),
            FieldRule::new("*.api_key").with_category(Category::AuthToken),
            FieldRule::new("*.api_token").with_category(Category::AuthToken),
            FieldRule::new("*.access_token").with_category(Category::AuthToken),
            FieldRule::new("*.auth_token").with_category(Category::AuthToken),
            FieldRule::new("*.token").with_category(Category::AuthToken),
            FieldRule::new("*.private_key").with_category(Category::AuthToken),
            FieldRule::new("*.connection_string").with_category(Category::Url),
            FieldRule::new("*.database_url").with_category(Category::Url),
            FieldRule::new("*.dsn").with_category(Category::Url),
        ]
    };

    let mut profiles = Vec::new();

    for fmt in &opts.formats {
        match fmt {
            GuidedFormat::YamlJson => {
                // YAML — k8s manifests, Helm values, docker-compose, app configs.
                let mut yaml_fields = credential_fields();
                yaml_fields.push(FieldRule::new("*.email").with_category(Category::Email));
                yaml_fields.push(FieldRule::new("*.username").with_category(Category::Name));
                // k8s Secret objects store values under data.* (base64) and
                // stringData.* (plaintext).
                if matches!(opts.preset, GuidedPreset::Kubernetes) {
                    yaml_fields.push(FieldRule::new("data.*").with_category(Category::AuthToken));
                    yaml_fields
                        .push(FieldRule::new("stringData.*").with_category(Category::AuthToken));
                }
                profiles.push(
                    FileTypeProfile::new("yaml", yaml_fields)
                        .with_extension(".yaml")
                        .with_extension(".yml"),
                );

                // JSON — API responses, config files.
                let mut json_fields = credential_fields();
                json_fields.push(FieldRule::new("*.email").with_category(Category::Email));
                json_fields.push(FieldRule::new("*.username").with_category(Category::Name));
                json_fields.push(FieldRule::new("*.ip").with_category(Category::IpV4));
                profiles.push(
                    FileTypeProfile::new("json", json_fields)
                        .with_extension(".json")
                        .with_option("compact", "true"),
                );
            }

            GuidedFormat::JsonLines => {
                // NDJSON / JSON Lines — structured application and system logs.
                let mut fields = credential_fields();
                fields.push(FieldRule::new("*.email").with_category(Category::Email));
                fields.push(FieldRule::new("*.user").with_category(Category::Name));
                fields.push(FieldRule::new("*.username").with_category(Category::Name));
                fields.push(FieldRule::new("*.ip").with_category(Category::IpV4));
                fields.push(FieldRule::new("*.client_ip").with_category(Category::IpV4));
                fields.push(FieldRule::new("*.remote_addr").with_category(Category::IpV4));
                fields.push(FieldRule::new("*.host").with_category(Category::Hostname));
                profiles.push(
                    FileTypeProfile::new("jsonl", fields)
                        .with_extension(".jsonl")
                        .with_extension(".ndjson")
                        // skip_invalid passes non-JSON lines (plain-text
                        // interleaved with structured log lines) through
                        // unchanged rather than failing.
                        .with_option("skip_invalid", "true"),
                );
            }

            GuidedFormat::Env => {
                // .env files — twelve-factor app secrets and CI variables.
                let fields = vec![
                    FieldRule::new("*_PASSWORD").with_category(Category::Custom("password".into())),
                    FieldRule::new("*_PASSWD").with_category(Category::Custom("password".into())),
                    FieldRule::new("*_SECRET").with_category(Category::AuthToken),
                    FieldRule::new("*_KEY").with_category(Category::AuthToken),
                    FieldRule::new("*_TOKEN").with_category(Category::AuthToken),
                    FieldRule::new("*_DSN").with_category(Category::Url),
                    FieldRule::new("*_URL").with_category(Category::Url),
                    FieldRule::new("DATABASE_URL").with_category(Category::Url),
                    FieldRule::new("REDIS_URL").with_category(Category::Url),
                    FieldRule::new("*_EMAIL").with_category(Category::Email),
                    FieldRule::new("*_USER").with_category(Category::Name),
                    FieldRule::new("*_USERNAME").with_category(Category::Name),
                ];
                profiles.push(FileTypeProfile::new("env", fields).with_extension(".env"));
            }

            GuidedFormat::Toml => {
                let mut fields = credential_fields();
                fields.push(FieldRule::new("*.email").with_category(Category::Email));
                fields.push(FieldRule::new("*.username").with_category(Category::Name));
                profiles.push(FileTypeProfile::new("toml", fields).with_extension(".toml"));
            }

            GuidedFormat::IniConf => {
                let fields = vec![
                    FieldRule::new("*.password").with_category(Category::Custom("password".into())),
                    FieldRule::new("*.passwd").with_category(Category::Custom("password".into())),
                    FieldRule::new("*.secret").with_category(Category::AuthToken),
                    FieldRule::new("*.token").with_category(Category::AuthToken),
                    FieldRule::new("*.api_key").with_category(Category::AuthToken),
                    FieldRule::new("*.email").with_category(Category::Email),
                    FieldRule::new("*.username").with_category(Category::Name),
                    FieldRule::new("*.user").with_category(Category::Name),
                ];
                profiles.push(
                    FileTypeProfile::new("ini", fields)
                        .with_extension(".ini")
                        .with_extension(".conf")
                        .with_extension(".cfg"),
                );
            }
        }
    }

    profiles
}

// ---------------------------------------------------------------------------
// Template subcommand
// ---------------------------------------------------------------------------

/// YAML comment header printed at the top of every generated template.
pub(crate) const TEMPLATE_HEADER: &str = "\
# =============================================================================
# sanitize secrets template
# =============================================================================
#
# PURPOSE
#   This file tells sanitize which patterns to detect and replace before
#   you send logs, configs, or other data to an LLM or external service.
#
# RELIABILITY FIRST
#   Every replacement preserves the original byte length so structured
#   formats (JSON, YAML, TOML, …) remain parseable after sanitization.
#   Run `sanitize --force-text` to bypass structured processing entirely.
#
# HOW TO USE
#   1. Edit this file to add your own patterns and literals.
#   2. Encrypt: sanitize encrypt this-file.yaml this-file.yaml.enc
#   3. Sanitize: sanitize input.log -s this-file.yaml.enc -o output.log
#
# FIELD REFERENCE
#   pattern   string  Required. Regex or literal to match.
#   kind      string  \"regex\" (default) or \"literal\".
#   category  string  Controls the replacement style. See docs/categories.md.
#   label     string  Optional. Human-readable name shown in reports.
#
# WARNING: REVIEW OUTPUT BEFORE SENDING TO AN LLM.
#          No automated tool catches everything — always spot-check.
# =============================================================================
";

pub(crate) fn template_body_generic() -> &'static str {
    r#"secrets:
  # --- Tokens & credentials ---
  - pattern: '(?i)\b(?:bearer|token|api[_-]?key|secret)[\s:=]+[A-Za-z0-9._~+/=-]{16,}\b'
    kind: regex
    category: auth_token
    label: auth_token_context

  - pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    kind: regex
    category: jwt
    label: jwt

  # --- Network identifiers ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: ipv4

  - pattern: '\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b'
    kind: regex
    category: ipv6
    label: ipv6

  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    kind: regex
    category: email
    label: email

  - pattern: '\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b'
    kind: regex
    category: hostname
    label: hostname

  - pattern: 'https?://[^\s"''<>]+'
    kind: regex
    category: url
    label: url

  # --- Identifiers ---
  - pattern: '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'
    kind: regex
    category: uuid
    label: uuid

  - pattern: '\b[a-f0-9]{12,64}\b'
    kind: regex
    category: container_id
    label: container_id

  # --- Add your own literals below ---
  # - pattern: 'my-internal-hostname.corp.example.com'
  #   kind: literal
  #   category: hostname
  #   label: corp_hostname
"#
}

pub(crate) fn template_body_web() -> &'static str {
    r#"secrets:
  # --- JWTs and session tokens ---
  - pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    kind: regex
    category: jwt
    label: jwt

  - pattern: '(?i)\bsess(?:ion)?[_-]?(?:id|token|key)[\s:=]+[A-Za-z0-9._~+/=-]{8,}\b'
    kind: regex
    category: auth_token
    label: session_id

  - pattern: '(?i)(?:refresh|access)[_-]?token[\s:=]+[A-Za-z0-9._~+/=-]{16,}'
    kind: regex
    category: auth_token
    label: oauth_token

  - pattern: '(?i)\b(?:bearer|authorization)[\s:]+[A-Za-z0-9._~+/=-]{16,}\b'
    kind: regex
    category: auth_token
    label: bearer_token

  # --- User identifiers ---
  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    kind: regex
    category: email
    label: email

  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: client_ip

  # --- URLs (may contain query params with tokens) ---
  - pattern: 'https?://[^\s"''<>]+'
    kind: regex
    category: url
    label: url

  # --- Add domain-specific literals ---
  # - pattern: 'users.myapp.com'
  #   kind: literal
  #   category: hostname
  #   label: app_domain
"#
}

pub(crate) fn template_body_k8s() -> &'static str {
    r#"secrets:
  # --- Service account tokens (base64, JWT) ---
  - pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    kind: regex
    category: jwt
    label: k8s_service_account_jwt

  - pattern: '(?i)token[\s:]+[A-Za-z0-9._~+/=-]{20,}'
    kind: regex
    category: auth_token
    label: k8s_token

  # --- Namespace and pod names ---
  - pattern: '\bnamespace[\s:]+[a-z][a-z0-9-]{2,62}\b'
    kind: regex
    category: custom:k8s_namespace
    label: k8s_namespace

  # --- IPs assigned to pods and services ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: pod_or_svc_ip

  # --- Cluster hostnames / DNS names ---
  - pattern: '\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b'
    kind: regex
    category: hostname
    label: k8s_dns

  # --- UUIDs (pod IDs, request IDs, etc.) ---
  - pattern: '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'
    kind: regex
    category: uuid
    label: uid

  # --- Docker / container image digests ---
  - pattern: '\b[a-f0-9]{64}\b'
    kind: regex
    category: container_id
    label: image_digest

  # --- Add your cluster name as a literal ---
  # - pattern: 'prod-cluster-1'
  #   kind: literal
  #   category: hostname
  #   label: cluster_name
"#
}

pub(crate) fn template_body_database() -> &'static str {
    r#"secrets:
  # --- Connection strings (contain embedded credentials) ---
  - pattern: '(?i)(?:postgres|mysql|mongodb|redis|amqp|jdbc:[^:]+)://[^\s"''>]+'
    kind: regex
    category: url
    label: db_connection_string

  # --- Inline passwords / secrets ---
  - pattern: '(?i)(?:password|passwd|pwd)[\s:=]+[^\s"'']{6,}'
    kind: regex
    category: custom:db_password
    label: db_password

  - pattern: '(?i)(?:user|username|login)[\s:=]+[^\s"'']{3,}'
    kind: regex
    category: name
    label: db_username

  # --- Host / IP for database servers ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: db_host_ip

  - pattern: '\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b'
    kind: regex
    category: hostname
    label: db_hostname

  # --- TLS certificate fingerprints / hashes ---
  - pattern: '\b[a-f0-9]{40}\b'
    kind: regex
    category: container_id
    label: cert_fingerprint

  # --- Add database-specific literals ---
  # - pattern: 'prod-db.internal.example.com'
  #   kind: literal
  #   category: hostname
  #   label: prod_db_host
"#
}

pub(crate) fn template_body_aws() -> &'static str {
    r#"secrets:
  # --- AWS access key IDs ---
  - pattern: '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'
    kind: regex
    category: auth_token
    label: aws_access_key_id

  # --- ARNs (may reveal account IDs, resource names) ---
  - pattern: '\barn:aws:[^\s]+'
    kind: regex
    category: aws_arn
    label: aws_arn

  # --- AWS account IDs (12-digit numbers in ARNs or standalone) ---
  - pattern: '\b\d{12}\b'
    kind: regex
    category: custom:aws_account_id
    label: aws_account_id

  # --- S3 bucket names and keys in URLs ---
  - pattern: 'https://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[^\s"''<>]+'
    kind: regex
    category: url
    label: s3_url

  # --- EC2 / ECS instance IDs ---
  - pattern: '\bi-[0-9a-f]{8,17}\b'
    kind: regex
    category: container_id
    label: ec2_instance_id

  # --- IPs for EC2 instances ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: ec2_ip

  # --- Emails in IAM roles, SES, etc. ---
  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    kind: regex
    category: email
    label: email

  # --- Add your AWS account ID as a literal for exact matching ---
  # - pattern: '123456789012'
  #   kind: literal
  #   category: custom:aws_account_id
  #   label: my_account_id
"#
}
