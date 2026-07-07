# scour-secrets demo 03 — zero-config app bundles
# Render from the repo root:  vhs docs/demos/tapes/03-app-bundles.tape
Output docs/demos/out/03-app-bundles.gif

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
Type "# 28 built-in bundles pair secret patterns with structured field profiles" Enter
Sleep 600ms
Type "scour-secrets apps | head -n 12" Sleep 500ms Enter
Sleep 3s

Type "# Point --app at the matching bundle — no profile authoring needed" Enter
Sleep 600ms
Type "scour-secrets nginx.conf --app nginx" Sleep 500ms Enter
Sleep 3s

Type "# Secrets gone; comments, directives, and layout preserved exactly" Enter
Sleep 600ms
Type "cat nginx-sanitized.conf" Sleep 500ms Enter
Sleep 4.5s
