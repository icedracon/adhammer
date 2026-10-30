# WS-DEMO-GIF (1.5.1) — zero-to-first-win: examples, completions, man page.
# Renders anywhere (no target needed). Synthetic data only.
Output site/assets/quickstart.gif

Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 18
Set Theme "Dracula"

# Requires: `cargo install --path cli` beforehand (see scan.tape header).

# PATH shim: VHS spawns WSL bash (no PATHEXT) — wrap adhammer.exe as adhammer.
Hide
Type 'adhammer() { adhammer.exe "$@"; }; export -f adhammer; clear'
Enter
Show

Type "adhammer --examples"
Enter
Sleep 3s

Type "adhammer completions bash | head -3"
Enter
Sleep 2s

Type "adhammer man | head -12"
Enter
Sleep 3s
