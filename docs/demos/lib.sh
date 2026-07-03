#!/usr/bin/env bash
# Shared setup for the scour-secrets demo recordings (VHS tapes + asciinema casts).
#
# Builds a clean, hermetic work directory full of sample inputs that contain
# ONLY clearly-fake secrets — AWS's published example access key, the Stripe
# documentation key, and example.com / RFC-5737 / RFC-1918 addresses. Nothing
# here is a real credential.
#
# Reproducibility: every recording regenerates the work dir from scratch, and
# HOME is redirected into the work dir so a recording never shows the operator's
# real home path or depends on their personal ~/.config/scour/secrets.yaml.
#
# NOTE: this file is meant to be *sourced* by the recording shell, so it must
# not enable `set -e` at top level — a deliberately non-zero exit (e.g. the
# --fail-on-match CI-gate demo) would otherwise kill the interactive session.
# Strict mode is enabled only when the file is executed directly (see bottom).

# Repo root = two levels up from this file (docs/demos/lib.sh).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)"

# Binary under test. Override with SCOUR_SECRETS_BIN; defaults to the release build.
export SCOUR_SECRETS_BIN="${SCOUR_SECRETS_BIN:-$REPO_ROOT/target/release/scour-secrets}"

# Ephemeral work dir. Override with DEMO if you want it elsewhere.
export DEMO="${DEMO:-/tmp/sanitize-demo-work}"

# Hermetic, throwaway HOME so recordings never leak the operator's config/home.
export HOME="$DEMO/home"

# Make the typed command read as a bare `scour-secrets`, not an absolute path.
export PATH="$(dirname "$SCOUR_SECRETS_BIN"):$PATH"

# Quiet, predictable prompts for both bash and zsh.
export PS1='$ '
export PROMPT='$ '

prepare_workdir() {
  rm -rf "$DEMO"
  mkdir -p "$DEMO" "$HOME"
  cd "$DEMO"
  _write_samples
}

_write_samples() {
  # --- An application log: email, IPs, AWS key, GitHub token, and a credential
  #     connection string — the everyday log-sharing case.
  cat > server.log <<'EOF'
2026-06-26T08:14:02Z INFO  auth: login ok user=alice@example.com ip=192.168.4.27
2026-06-26T08:14:03Z DEBUG aws: assume-role key=AKIAIOSFODNN7EXAMPLE region=us-east-1
2026-06-26T08:14:05Z INFO  webhook: POST https://api.example.com token=ghp_16C7e42F292c6912E7710c838347Ae178B4a
2026-06-26T08:14:09Z WARN  db: pool reconnect postgres://admin:s3cr3tP%40ss@10.0.0.5:5432/app
2026-06-26T08:14:11Z ERROR auth: token revoked for session 5f3e9c2a-1b7d-4e8a-9c0f-2a6b8d4e1f33
EOF

  # --- A service config: structured fields the --profile demo targets.
  cat > app-config.yaml <<'EOF'
service: checkout
database:
  host: 10.0.0.5
  username: admin
  password: s3cr3tP@ss
api:
  github_token: ghp_16C7e42F292c6912E7710c838347Ae178B4a
admin_email: alice@example.com
EOF

  # --- A field profile for the structured demo: rename specific keys only,
  #     preserving comments / ordering / indentation exactly.
  cat > fields.yaml <<'EOF'
- processor: yaml
  extensions: [".yaml", ".yml"]
  fields:
    - pattern: "*.password"
      category: "custom:password"
    - pattern: "*.admin_email"
      category: email
    - pattern: "*.host"
      category: ipv4
EOF

  # --- An nginx config for the app-bundle demo (zero-config field profile).
  cat > nginx.conf <<'EOF'
server {
    listen 80;
    server_name checkout.internal;
    # ops escalation contact
    set $oncall "alice@example.com";

    location /api/ {
        proxy_pass http://10.0.0.5:8080;
        proxy_set_header Authorization "Bearer ghp_16C7e42F292c6912E7710c838347Ae178B4a";
    }
}
EOF
}

# When executed directly (not sourced), prepare the work dir under strict mode.
if [[ "${BASH_SOURCE[0]:-}" == "${0:-}" ]]; then
  set -euo pipefail
  prepare_workdir
  echo "Prepared demo work dir at $DEMO (HOME=$HOME, scour-secrets=$SCOUR_SECRETS_BIN)"
fi
