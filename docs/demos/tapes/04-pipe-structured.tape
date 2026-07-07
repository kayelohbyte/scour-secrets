# scour-secrets demo 04 — stdin pipe + structured field rules
# Render from the repo root:  vhs docs/demos/tapes/04-pipe-structured.tape
Output docs/demos/out/04-pipe-structured.gif

Set Shell "bash"
Set FontSize 18
Set Width 1400
Set Height 800
Set Padding 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "source docs/demos/lib.sh && prepare_workdir && clear" Enter
Sleep 800ms
Show

Sleep 800ms
Type "# Pipe from any command — stdin in, sanitized stdout out" Enter
Sleep 600ms
Type "grep ERROR server.log | scour-secrets -f log" Sleep 500ms Enter
Sleep 3s

Type "# --profile targets named fields; the scanner sweeps the rest" Enter
Sleep 600ms
Type "scour-secrets app-config.yaml --profile fields.yaml -o -" Sleep 500ms Enter
Sleep 4.5s
