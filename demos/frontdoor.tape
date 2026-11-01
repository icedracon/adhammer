# WS-DEMO-GIF (1.5.1) — the no-credential front door: bare `adhammer` -> goal picker ->
# Recon -> black-box discovery. VHS drives a real terminal, so the interactive dialoguer
# prompts work (where scripted expect races on raw-mode). Synthetic data only:
# corp.local + RFC-5737 192.0.2.x (never a lab identifier — enforced by `make scrub`).
Output site/assets/frontdoor.gif

Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 820
Set Padding 18
Set Theme "Dracula"

# Requires: `cargo install --path cli` beforehand (see scan.tape header).

# PATH shim + ISOLATED APPDATA so the demo starts cold (no saved session loaded —
# otherwise the dev-machine's session.json would leak lab identifiers into the GIF).
Hide
Type 'd="${LOCALAPPDATA}/Temp/adhammer_demo_fd"; mkdir -p "${d//\\\\//}" && rm -rf "${d//\\\\//}"/*'
Enter
# WSLENV="APPDATA/w" — /w = Win32-direction only (WSL->Win32); APPDATA is already Windows-formatted so no path translation is needed.
Type 'export WSLENV="APPDATA/w" APPDATA="${LOCALAPPDATA}\\Temp\\adhammer_demo_fd"'
Enter
Type 'adhammer() { adhammer.exe "$@"; }; export -f adhammer; clear'
Enter
Show

Type "adhammer"
Enter
Sleep 2s
Type "1"
Enter
Sleep 1500ms
Enter
Sleep 1s
Type "192.0.2.10"
Enter
Sleep 1s
Enter
Sleep 1s
Type "n"
Enter
Sleep 3s
