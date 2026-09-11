# WS-DEMO-GIF (1.5.1) — doctor preflight: TCP matrix + classified bind + named fixes.
# Synthetic target (dc.corp.local). The ✓/✗ checklist and fix lines render whether or not
# the host is reachable — that IS the point (no more "os error 104 / data 52e, now what").
Output site/assets/doctor.gif

Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 760
Set Padding 18
Set Theme "Dracula"

Type "adhammer doctor --domain corp.local --dc dc.corp.local --user alice"
Enter
Sleep 5s
