# scour-secrets demo 01 — zero-config scan (before / after)
# Render from the repo root:  vhs docs/demos/tapes/01-quickstart.tape
Output docs/demos/out/01-quickstart.gif

Set Shell "bash"
Set FontSize 18
Set Width 1400
Set Height 760
Set Padding 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# --- hidden setup: hermetic work dir + sample inputs, then clear ---
Hide
Type "source docs/demos/lib.sh && prepare_workdir && clear" Enter
Sleep 800ms
Show

Sleep 800ms
Type "# A real-looking app log — emails, IPs, AWS / GitHub / Stripe keys, a DB URL" Enter
Sleep 600ms
Type "cat server.log" Sleep 500ms Enter
Sleep 2.5s

Type "# No secrets file, no flags — built-in patterns just work" Enter
Sleep 600ms
Type "scour-secrets server.log" Sleep 500ms Enter
Sleep 3s

Type "# Every secret is gone; structure and timestamps stay intact" Enter
Sleep 600ms
Type "cat server-sanitized.log" Sleep 500ms Enter
Sleep 4.5s
