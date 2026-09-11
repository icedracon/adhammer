# ADhammer demo GIFs (WS-DEMO-GIF, 1.5.1)

Reproducible terminal demos rendered with **[VHS](https://github.com/charmbracelet/vhs)**
(charmbracelet). The `.tape` scripts are the **reviewable source**; the GIFs are build
artifacts regenerated from them — never hand-edited, never committed with real data.

## Render

```sh
make -C demos            # renders every demos/*.tape -> site/assets/*.gif
make -C demos scrub      # fails if any .tape leaks a lab identifier (CI gate)
```

VHS is a **dev dependency only** (not a crate/runtime dep). Install it on the render host
(`go install github.com/charmbracelet/vhs@latest`, plus `ttyd` + `ffmpeg`). If VHS is
unavailable, record with `asciinema` and render with `agg`.

## Tapes

| Tape | Shows | Needs a target? |
|------|-------|-----------------|
| `frontdoor.tape` | interactive goal picker → no-credential reconnaissance | no — uses synthetic input |
| `quickstart.tape` | `--examples`, `completions`, `man` | no — renders anywhere |
| `doctor.tape` | `doctor` preflight checklist + named fixes | reaches a host (fixes render even when unreachable) |
| `scan.tape` | `scan` → findings with **copy-paste next-actions** (the S-1 showcase) | yes — a lab DC **or** a canned JSON fixture (`--baseline`/replay) |

## Hard rules (enforced by `make scrub`)

- **Synthetic targets only**: `corp.local`, `dc.corp.local`, `alice`, RFC-5737 IPs
  (`192.0.2.0/24`). **Never** a lab IP/hostname/cred/SID (`feedback-never-leak-lab-identifiers`).
- **No competitor names** in any tape (`feedback-no-competitor-mentions`).
- The DC-backed tapes (`doctor`, `scan`) render against a disposable lab or a fixture on the
  CI runner — the checked-in artifact must contain only synthetic data.
