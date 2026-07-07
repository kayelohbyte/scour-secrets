#!/usr/bin/env bash
# Regenerate every demo recording: VHS GIFs (docs/demos/out/*.gif) and
# asciinema casts (docs/demos/out/*.cast). Run from anywhere.
#
#   docs/demos/render.sh            # uses target/release/scour-secrets
#   SCOUR_SECRETS_BIN=/path/to/scour-secrets docs/demos/render.sh
#
# Requires: vhs, asciinema, ffmpeg, ttyd, jq on PATH.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

export SCOUR_SECRETS_BIN="${SCOUR_SECRETS_BIN:-$REPO/target/release/scour-secrets}"
if [[ ! -x "$SCOUR_SECRETS_BIN" ]]; then
  echo "error: scour-secrets binary not found at $SCOUR_SECRETS_BIN" >&2
  echo "       build it first:  cargo build --release" >&2
  exit 1
fi

for tool in vhs asciinema; do
  command -v "$tool" >/dev/null || { echo "error: $tool not on PATH" >&2; exit 1; }
done

echo "Using scour-secrets: $SCOUR_SECRETS_BIN"

# --- VHS GIFs ---
for tape in docs/demos/tapes/*.tape; do
  echo ">> vhs $tape"
  vhs "$tape"
done

# --- asciinema casts ---
for drv in docs/demos/drivers/[0-9]*.sh; do
  name="$(basename "$drv" .sh)"
  echo ">> asciinema $name"
  asciinema rec --overwrite --headless --window-size 120x32 \
    --title "scour-secrets — ${name#[0-9][0-9]-}" \
    -c "bash $drv" "docs/demos/out/$name.cast"
done

echo "Done. Output in docs/demos/out/"
