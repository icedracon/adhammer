# WS-DEMO-GIF (1.5.1). Render demo GIFs from the .tape sources with VHS, and gate the
# sources against lab-identifier leakage. VHS is a dev-only dependency (see README.md).

TAPES := $(wildcard *.tape)
GIFS  := $(patsubst %.tape,../site/assets/%.gif,$(TAPES))

.PHONY: demos scrub clean
demos: scrub $(GIFS)

../site/assets/%.gif: %.tape
	@command -v vhs >/dev/null || { echo "vhs not installed — see demos/README.md"; exit 1; }
	vhs $<

# CI gate: the checked-in .tape sources must carry ONLY synthetic data.
# feedback-never-leak-lab-identifiers + feedback-no-competitor-mentions.
scrub:
	@echo "scrub: checking demos/*.tape for lab identifiers…"
	@! grep -REniH \
	  -e '192\.168\.' -e '172\.(1[6-9]|2[0-9]|3[01])\.' -e '10\.10\.10\.' \
	  -e 'WIN-[A-Z0-9]{8,}' -e 'S-1-5-21-[0-9]' -e 'testlab' -e 'Zikurat' \
	  -e 'TestPass' -e 'LabPass' \
	  -- *.tape \
	  && echo "scrub: clean (synthetic data only)" \
	  || { echo "scrub: BLOCKED — a .tape contains a lab identifier (redact to corp.local / 192.0.2.x)"; exit 1; }

clean:
	rm -f $(GIFS)
