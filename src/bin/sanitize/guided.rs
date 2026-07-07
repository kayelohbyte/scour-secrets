/// Template preset names accepted by `scour-secrets template`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum TemplatePreset {
    Balanced,
    Aggressive,
    Generic,
    Web,
    K8s,
    Database,
    Aws,
}

pub(crate) fn parse_template_preset(s: &str) -> Result<TemplatePreset, String> {
    match s {
        "balanced" => Ok(TemplatePreset::Balanced),
        "aggressive" => Ok(TemplatePreset::Aggressive),
        "generic" => Ok(TemplatePreset::Generic),
        "web" => Ok(TemplatePreset::Web),
        "k8s" | "kubernetes" => Ok(TemplatePreset::K8s),
        "database" | "db" => Ok(TemplatePreset::Database),
        "aws" => Ok(TemplatePreset::Aws),
        other => Err(format!(
            "unknown preset '{other}' (choices: balanced, aggressive, generic, web, k8s, database, aws)"
        )),
    }
}

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
#   kind      string  \"regex\" (default), \"literal\", or \"entropy\".
#   category  string  Controls the replacement style. See docs/categories.md.
#   label     string  Optional. Human-readable name shown in reports.
#
# WARNING: REVIEW OUTPUT BEFORE SENDING TO AN LLM.
#          No automated tool catches everything — always spot-check.
# =============================================================================
";

pub(crate) fn template_body_balanced() -> &'static str {
    r#"# Balanced preset — well-known token formats with a low false-positive rate.
# Matches the same patterns loaded automatically when no secrets file is given.
# Edit: remove patterns you don't need; add your own literals at the bottom.

# --- Cloud provider keys (near-zero false positives) ---
- pattern: '\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b'
  kind: regex
  category: auth_token
  label: aws_access_key_id

- pattern: '\bAIza[A-Za-z0-9_-]{35}\b'
  kind: regex
  category: auth_token
  label: gcp_api_key

- pattern: '\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b'
  kind: regex
  category: auth_token
  label: github_token

- pattern: '\bgithub_pat_[A-Za-z0-9_]{82}\b'
  kind: regex
  category: auth_token
  label: github_pat

- pattern: '\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b'
  kind: regex
  category: auth_token
  label: openai_api_key

- pattern: '\bsk-ant-[A-Za-z0-9_-]{93,}\b'
  kind: regex
  category: auth_token
  label: anthropic_api_key

- pattern: '\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b'
  kind: regex
  category: auth_token
  label: stripe_key

- pattern: '\bglpat-[A-Za-z0-9_-]{20}\b'
  kind: regex
  category: auth_token
  label: gitlab_token

- pattern: '\bxox[bpars]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b'
  kind: regex
  category: auth_token
  label: slack_token

- pattern: '\bnpm_[A-Za-z0-9]{36}\b'
  kind: regex
  category: auth_token
  label: npm_token

- pattern: '\bhf_[A-Za-z0-9]{34}\b'
  kind: regex
  category: auth_token
  label: huggingface_token

- pattern: '\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b'
  kind: regex
  category: auth_token
  label: sendgrid_api_key

- pattern: '\bAC[a-f0-9]{32}\b'
  kind: regex
  category: auth_token
  label: twilio_account_sid

# --- Generic secret key=value patterns ---
- pattern: '(?i)(?:api_key|api_secret|access_token|client_secret|private_key|secret_key|auth_key|signing_key|jwt_secret|jwt_key)[\s:="'']+[A-Za-z0-9._~+/=-]{16,}'
  kind: regex
  category: auth_token
  label: secret_kv

- pattern: '(?i)(?:password|passwd|pwd)[\s:="'']+[^\s"'']{6,}'
  kind: regex
  category: custom:password
  label: password_kv

- pattern: '-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----'
  kind: regex
  category: auth_token
  label: private_key_header

# --- JWTs ---
- pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
  kind: regex
  category: jwt
  label: jwt

# --- Network identifiers ---
- pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
  kind: regex
  category: email
  label: email

- pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
  kind: regex
  category: ipv4
  label: ipv4

- pattern: '\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b'
  kind: regex
  category: ipv6
  label: ipv6_full

- pattern: 'https?://[^\s"''<>;]+'
  kind: regex
  category: url
  label: url

- pattern: '[a-z][a-z0-9+.-]+://[^:@\s]{1,128}:[^@\s]{1,128}@[^\s"''<>]+'
  kind: regex
  category: url
  label: credential_url

# --- Unique identifiers ---
- pattern: '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'
  kind: regex
  category: uuid
  label: uuid

- pattern: '\bsha256:[a-f0-9]{64}\b'
  kind: regex
  category: container_id
  label: image_digest

- pattern: '\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
  kind: regex
  category: mac_address
  label: mac_address

- pattern: '/(?:home|Users)/([A-Za-z0-9_-]+)'
  kind: regex
  category: file_path
  label: user_home_path

# --- Add your own literals below ---
# - pattern: 'my-specific-secret-value'
#   kind: literal
#   category: auth_token
#   label: my_secret
"#
}

pub(crate) fn template_body_aggressive() -> &'static str {
    r#"# Aggressive preset — balanced patterns plus entropy-based and broad token detection.
# Suitable for LLM context where over-capture is better than under-capture.
# Expect more false positives than balanced. Review output before sending.

# --- All balanced patterns ---
- pattern: '\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b'
  kind: regex
  category: auth_token
  label: aws_access_key_id

- pattern: '\bAIza[A-Za-z0-9_-]{35}\b'
  kind: regex
  category: auth_token
  label: gcp_api_key

- pattern: '\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b'
  kind: regex
  category: auth_token
  label: github_token

- pattern: '\bgithub_pat_[A-Za-z0-9_]{82}\b'
  kind: regex
  category: auth_token
  label: github_pat

- pattern: '\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b'
  kind: regex
  category: auth_token
  label: openai_api_key

- pattern: '\bsk-ant-[A-Za-z0-9_-]{93,}\b'
  kind: regex
  category: auth_token
  label: anthropic_api_key

- pattern: '\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b'
  kind: regex
  category: auth_token
  label: stripe_key

- pattern: '\bglpat-[A-Za-z0-9_-]{20}\b'
  kind: regex
  category: auth_token
  label: gitlab_token

- pattern: '\bxox[bpars]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b'
  kind: regex
  category: auth_token
  label: slack_token

- pattern: '\bnpm_[A-Za-z0-9]{36}\b'
  kind: regex
  category: auth_token
  label: npm_token

- pattern: '\bhf_[A-Za-z0-9]{34}\b'
  kind: regex
  category: auth_token
  label: huggingface_token

- pattern: '\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b'
  kind: regex
  category: auth_token
  label: sendgrid_api_key

- pattern: '\bAC[a-f0-9]{32}\b'
  kind: regex
  category: auth_token
  label: twilio_account_sid

- pattern: '(?i)(?:api_key|api_secret|access_token|client_secret|private_key|secret_key|auth_key|signing_key|jwt_secret|jwt_key)[\s:="'']+[A-Za-z0-9._~+/=-]{16,}'
  kind: regex
  category: auth_token
  label: secret_kv

- pattern: '(?i)(?:password|passwd|pwd)[\s:="'']+[^\s"'']{6,}'
  kind: regex
  category: custom:password
  label: password_kv

- pattern: '-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----'
  kind: regex
  category: auth_token
  label: private_key_header

- pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
  kind: regex
  category: jwt
  label: jwt

- pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
  kind: regex
  category: email
  label: email

- pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
  kind: regex
  category: ipv4
  label: ipv4

- pattern: '\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b'
  kind: regex
  category: ipv6
  label: ipv6_full

- pattern: 'https?://[^\s"''<>;]+'
  kind: regex
  category: url
  label: url

- pattern: '[a-z][a-z0-9+.-]+://[^:@\s]{1,128}:[^@\s]{1,128}@[^\s"''<>]+'
  kind: regex
  category: url
  label: credential_url

- pattern: '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'
  kind: regex
  category: uuid
  label: uuid

- pattern: '\bsha256:[a-f0-9]{64}\b'
  kind: regex
  category: container_id
  label: image_digest

- pattern: '\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
  kind: regex
  category: mac_address
  label: mac_address

- pattern: '/(?:home|Users)/([A-Za-z0-9_-]+)'
  kind: regex
  category: file_path
  label: user_home_path

# --- Aggressive additions ---

# Entropy-based detection: catches unstructured tokens not covered above.
# Lower threshold = more aggressive. Tune to your noise tolerance.
- kind: entropy
  category: auth_token
  label: high_entropy_token
  min_length: 20
  max_length: 200
  threshold: 4.5
  charset: alphanumeric

# Authorization headers in HTTP logs and API request dumps.
- pattern: '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b'
  kind: regex
  category: auth_token
  label: bearer_token

- pattern: '(?i)\bauthorization[\s:="'']+[A-Za-z0-9._~+/=-]{16,}\b'
  kind: regex
  category: auth_token
  label: authorization_kv

# Short container IDs (12 hex chars — common in docker/kubectl output).
# Aggressive-only: fires on hex color codes and version hashes too.
- pattern: '\b[a-f0-9]{12}\b'
  kind: regex
  category: container_id
  label: container_id_short

# Add your own patterns below.
"#
}

pub(crate) fn template_body_generic() -> &'static str {
    r#"# --- Tokens & credentials ---
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
    r#"# --- JWTs and session tokens ---
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
    r#"# --- Service account tokens (base64, JWT) ---
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
    r#"# --- Connection strings (contain embedded credentials) ---
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
    r#"# --- AWS access key IDs ---
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
