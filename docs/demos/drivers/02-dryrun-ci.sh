#!/usr/bin/env bash
# asciinema driver — dry-run, NDJSON findings, CI gate
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_driver.sh"

note "# Dry-run: see what WOULD be replaced — nothing is written"
run "scour-secrets server.log --dry-run"
note "# Stream per-match findings as NDJSON for jq / SIEM ingest"
run "scour-secrets server.log --dry-run --findings | jq -c '.patterns // empty'"
note "# CI gate: non-zero exit when secrets are found"
run "scour-secrets server.log --fail-on-match >/dev/null; echo exit=\$?"
sleep 1
