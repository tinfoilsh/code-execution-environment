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
#     - scripts/filter-hashes.py  (prunes uv's per-version hash list to
#                                  artifacts compatible with the deploy
#                                  target — cpython 3.12, linux x86_64 glibc)
#     - Makefile               (this file)
#
# Bump every dep to its latest stable release and regenerate the locked
# outputs. Run after editing requirements.in or NPM_PACKAGES.
#
# Requires: uv (https://github.com/astral-sh/uv) and npm.

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
		-o requirements.txt requirements.in
	python3 scripts/filter-hashes.py requirements.txt

lock-node:
	npm install --save-exact --package-lock-only --omit=dev $(addsuffix @latest,$(NPM_PACKAGES))
