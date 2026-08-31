# Signing-key rotation log

Append-only log of every crates.io API-token rotation. Each entry
names the date, the reason, and the previous-token's stated
compromise-window if any. Do NOT ever paste the token itself here.

Format:

    ## <YYYY-MM-DD> — <reason>
    - previous-token stated compromise window: <start> to <end> (if any)
    - notes: <freeform>

Policy: SECURITY.md § "crates.io publishes — maintainer API token".

---

## 2026-08-31 — initial policy landed

- previous-token compromise window: none suspected
- notes: policy formally documented in SECURITY.md as part of
  1.4.9 WS-DOC-TRUST. Token remains the current one. Next mandatory
  rotation: 2027-08-31 at latest, or immediately on suspected
  compromise / maintainer handoff.
