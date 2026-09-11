# WS-DEMO-GIF (1.5.1) — the S-1 showcase: scan -> findings, each ending with a
# copy-paste NEXT command (the guided kill-chain).
#
# Needs a target: a disposable lab DC OR a canned fixture on the render host. The checked-in
# GIF must show ONLY synthetic data — render against corp.local in a throwaway lab, or replay
# a scrubbed JSON fixture. NEVER render this against the real lab and commit the result.
Output site/assets/scan.gif

Set Shell bash
Set FontSize 15
Set Width 1280
Set Height 820
Set Padding 18
Set Theme "Dracula"

# Example invocation (fill in the disposable-lab DC / creds via @file at render time):
Type "adhammer scan --url ldaps://dc.corp.local --user alice --password @file:./.pw --out report.html"
Enter
Sleep 6s
# The terminal card + report.html show each finding's `-> next: adhammer attack ...` footer.
Type "echo 'each finding above ends with its own copy-paste next command'"
Enter
Sleep 2s
