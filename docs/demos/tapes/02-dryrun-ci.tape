# scour-secrets demo 02 — dry-run, NDJSON findings, and the CI gate
# Render from the repo root:  vhs docs/demos/tapes/02-dryrun-ci.tape
Output docs/demos/out/02-dryrun-ci.gif

Set Shell "bash"
Set FontSize 18
Set Width 1400
Set Height 720
Set Padding 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "source docs/demos/lib.sh && prepare_workdir && clear" Enter
Sleep 800ms
Show

Sleep 800ms
Type "# Dry-run: see what WOULD be replaced — nothing is written" Enter
Sleep 600ms
Type "scour-secrets server.log --dry-run" Sleep 500ms Enter
Sleep 3s

Type "# Stream per-match findings as NDJSON for jq / SIEM ingest" Enter
Sleep 600ms
Type "scour-secrets server.log --dry-run --findings | jq -c '.patterns // empty'" Sleep 500ms Enter
Sleep 3s

Type "# CI gate: non-zero exit when secrets are found" Enter
Sleep 600ms
Type "scour-secrets server.log --fail-on-match >/dev/null; echo exit=$?" Sleep 500ms Enter
Sleep 3.5s
