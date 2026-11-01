# WS-DEMO-GIF (1.5.1). Render demo GIFs from the .tape sources with VHS, and gate the
# sources against lab-identifier leakage. VHS is a dev-only dependency (see README.md).

TAPES := $(wildcard *.tape)
GIFS  := $(patsubst %.tape,../site/assets/%.gif,$(TAPES))

.PHONY: demos scrub clean
demos: scrub $(GIFS)

../site/assets/%.gif: %.tape
	@command -v vhs >/dev/null || { echo "vhs not installed — see demos/README.md"; exit 1; }
	vhs $<

# CI gate 1: the checked-in .tape sources must carry ONLY synthetic data.
# feedback-never-leak-lab-identifiers + feedback-no-competitor-mentions.
scrub:
	@echo "scrub: checking demos/*.tape for lab identifiers…"
	@! grep -REniH \
	  -e '192\.168\.' -e '172\.(1[6-9]|2[0-9]|3[01])\.' -e '10\.10\.10\.' \
	  -e 'WIN-[A-Z0-9]{8,}' -e 'S-1-5-21-[0-9]' -e 'testlab' -e 'Zikurat' \
	  -e 'DC0[0-9]' \
	  -e 'TestPass' -e 'LabPass' \
	  -- *.tape \
	  && echo "scrub: clean (synthetic data only)" \
	  || { echo "scrub: BLOCKED — a .tape contains a lab identifier (redact to corp.local / 192.0.2.x)"; exit 1; }

clean:
	rm -f $(GIFS)

# CI gate 2: scrub RENDERED GIFs via frame-extract + OCR. The source-tape scrub
# above only catches identifiers Claude typed into the tape; this catches
# identifiers that leaked through adhammer's own OUTPUT (resolver chatter,
# $PS1 if VHS ever propagates it, env-var inlines). Byte-level grep is useless
# on LZW-compressed GIF pixel data — must OCR the frames.
#
# Dependencies (install on render host): ffmpeg + tesseract (`apt install
# tesseract-ocr` / `choco install tesseract` / `brew install tesseract`).
# MUST run before any `git add site/assets/*.gif`.
RENDERED_GIFS := $(wildcard site/assets/*.gif)
scrub-rendered:
	@command -v ffmpeg >/dev/null || { echo "scrub-rendered: ffmpeg not installed"; exit 1; }
	@command -v tesseract >/dev/null || { echo "scrub-rendered: tesseract not installed (apt/brew/choco install tesseract)"; exit 1; }
	@echo "scrub-rendered: OCR-scanning every frame of every GIF…"
	@tmpdir=$$(mktemp -d); \
	for g in $(RENDERED_GIFS); do \
	  echo "  → $$g"; \
	  ffmpeg -i "$$g" -vf fps=2 "$$tmpdir/f_%03d.png" -y >/dev/null 2>&1; \
	  for png in $$tmpdir/f_*.png; do \
	    tesseract "$$png" - 2>/dev/null | grep -EiH -f .scrub-terms-local 2>/dev/null \
	      || tesseract "$$png" - 2>/dev/null | grep -EiH '192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|10\.10\.10\.|WIN-[A-Z0-9]{8,}|S-1-5-21-[0-9]{8,}|testlab|Zikurat|DC0[0-9]' \
	      && { echo "LEAK in $$g (frame $$png)"; rm -rf "$$tmpdir"; exit 1; }; \
	  done; \
	  rm -f $$tmpdir/f_*.png; \
	done; \
	rm -rf "$$tmpdir"; \
	echo "scrub-rendered: clean (every frame OCR'd, no lab identifiers)"
