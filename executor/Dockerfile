FROM golang:1.26.2-alpine3.23@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS build
WORKDIR /src

COPY go.* ./
RUN go mod download && go mod verify

COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -mod=readonly -o /executor .

FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b
ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/tmp

# NodeSource's apt signing key, committed at executor/nodesource.gpg.
# Fingerprint 6F71 F525 2828 41EE DAF8 51B4 2F59 B5F9 9B1B E0B4 (NSolid).
# Refresh: curl https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
#          | gpg --dearmor > executor/nodesource.gpg
# Trust root lives in the repo rather than in whatever HTTPS endpoint
# resolves at build time, so the image is reproducible from source alone.
COPY nodesource.gpg /etc/apt/keyrings/nodesource.gpg

# System tooling + Python 3.12 + Node.js 22. Two-phase apt to handle the
# CA bootstrap: the base ubuntu:24.04 image has no CA bundle, so the first
# `apt-get update` would fail TLS verification on NodeSource's https
# Release file and silently fall back to Ubuntu universe (which ships an
# older nodejs without npm). Install ca-certificates from the http-signed
# Ubuntu archive first, then enable the NodeSource repo, then install
# everything in one second pass.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ffmpeg \
        g++ \
        gcc \
        git \
        jq \
        make \
        nodejs \
        pandoc \
        python3 \
        python3-pip \
        tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Python deps — pinned + hashed (regenerate via `cd deps && make lock`).
# Only the locked output (requirements.txt) is copied in; deps/requirements.in
# and deps/Makefile are inputs to `make lock` and never reach the image.
# --require-hashes makes pip refuse any wheel whose SHA256 doesn't match.
COPY deps/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages --require-hashes \
        -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# Node deps — pinned via package-lock.json. `npm ci` refuses to run if
# package.json and the lockfile disagree, and verifies each tarball
# against the lockfile's sha512 integrity field.
COPY deps/package.json deps/package-lock.json /opt/node-tools/
RUN cd /opt/node-tools && npm ci --omit=dev && npm cache clean --force
# PATH puts npm-installed CLIs (tsc, tsx, marked, ...) on the agent's PATH.
# NODE_PATH lets `require()` from any cwd resolve modules under /opt/node-tools/
# (docx, pdf-lib, sharp, etc.); without it Node only searches ./node_modules.
ENV PATH="/opt/node-tools/node_modules/.bin:${PATH}" \
    NODE_PATH=/opt/node-tools/node_modules

COPY --from=build /executor /executor
RUN mkdir -p /workspace /run/execsock \
    && chown 1000:1000 /workspace /run/execsock
VOLUME /run/execsock
WORKDIR /workspace
CMD ["/executor"]
