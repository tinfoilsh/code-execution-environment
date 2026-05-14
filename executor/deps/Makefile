.PHONY: lock lock-python lock-node

# What ships into the executor image vs what lives here only for locking:
#
#   Shipped (COPYed by ../Dockerfile):
#     - requirements.txt
#     - package.json
#     - package-lock.json
#
#   Local-only (never reaches the image):
#     - requirements.in        (unpinned source for requirements.txt)
#     - Makefile               (this file)
#
# Bump every dep to its latest stable release and regenerate the locked
# outputs. Run after editing requirements.in or NPM_PACKAGES.
#
# Requires: uv (https://github.com/astral-sh/uv) and npm.

# Quarantine cutoff — refuse versions published on or after this date.
# Sliding 7-day window: anything published in the past week is treated as
# unproven and excluded. uv reads it via --exclude-newer; npm via --before.
CUTOFF := $(shell python3 -c "from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(days=7)).date())")

NPM_PACKAGES := \
	docx \
	markdownlint \
	marked \
	pdf-lib \
	pdfjs-dist \
	pptxgenjs \
	remark \
	sharp \
	ts-node \
	tsx \
	typescript

lock: lock-python lock-node

lock-python:
	uv pip compile --generate-hashes \
		--python-version 3.12 \
		--python-platform x86_64-unknown-linux-gnu \
		--exclude-newer $(CUTOFF) \
		-o requirements.txt requirements.in

lock-node:
	# Delete the existing lockfile so --before drives a fresh resolution.
	# Without this, npm treats the existing tree as authoritative and the
	# cutoff has no effect on transitive picks.
	rm -f package-lock.json
	npm install --save-exact --package-lock-only --omit=dev \
		--before $(CUTOFF) \
		$(addsuffix @latest,$(NPM_PACKAGES))
