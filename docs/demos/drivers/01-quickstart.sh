#!/usr/bin/env bash
# asciinema driver — zero-config scan (before / after)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_driver.sh"

note "# A real-looking app log — emails, IPs, AWS / GitHub / Stripe keys, a DB URL"
run "cat server.log"
note "# No secrets file, no flags — built-in patterns just work"
run "scour-secrets server.log"
note "# Every secret is gone; structure and timestamps stay intact"
run "cat server-sanitized.log"
sleep 1
