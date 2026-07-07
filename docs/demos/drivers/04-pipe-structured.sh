#!/usr/bin/env bash
# asciinema driver — stdin pipe + structured field rules
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_driver.sh"

note "# Pipe from any command — stdin in, sanitized stdout out"
run "grep ERROR server.log | scour-secrets -f log"
note "# --profile targets named fields; the scanner sweeps the rest"
run "scour-secrets app-config.yaml --profile fields.yaml -o -"
sleep 1
