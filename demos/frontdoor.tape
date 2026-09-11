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
