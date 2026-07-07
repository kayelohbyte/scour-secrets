#!/usr/bin/env bash
# asciinema driver — zero-config app bundles
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_driver.sh"

note "# 28 built-in bundles pair secret patterns with structured field profiles"
run "scour-secrets apps | head -n 12"
note "# Point --app at the matching bundle — no profile authoring needed"
run "scour-secrets nginx.conf --app nginx"
note "# Secrets gone; comments, directives, and layout preserved exactly"
run "cat nginx-sanitized.conf"
sleep 1
