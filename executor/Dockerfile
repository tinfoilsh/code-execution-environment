FROM golang:1.26.2-alpine3.23@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS build
WORKDIR /src

COPY go.* ./
RUN go mod download && go mod verify

COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -mod=readonly -o /executor .

FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b
ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/tmp

# System tooling + Python 3.12. curl/gnupg are transient — only needed to
# pull NodeSource's apt repo, then purged so the runtime image has no
# network-fetching tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        ffmpeg \
        g++ \
        gcc \
        git \
        gnupg \
        imagemagick \
        jq \
        make \
        pandoc \
        python3 \
        python3-pip \
        tesseract-ocr \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get purge -y curl gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Single-purpose container; PEP 668 doesn't earn its keep here.
RUN pip3 install --no-cache-dir --break-system-packages \
        Pillow \
        matplotlib \
        numpy \
        openpyxl \
        pandas \
        pdfplumber \
        pypdf \
        pypdfium2 \
        python-docx \
        python-pptx \
        reportlab \
        sympy

RUN npm install -g --omit=dev \
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
        typescript \
    && npm cache clean --force

COPY --from=build /executor /executor
RUN mkdir -p /workspace /run/execsock \
    && chown 1000:1000 /workspace /run/execsock
VOLUME /run/execsock
WORKDIR /workspace
CMD ["/executor"]
