Simple code execution environment containers.

Executor <-> api server

## Available in the executor image

**Runtimes**

- Python 3.12 (with pip)
- Node.js 22 (with npm)
- gcc / g++, make

**System CLI tools**

- ffmpeg
- pandoc
- tesseract (OCR)
- jq

**Python packages** (direct, pinned in [`executor/deps/requirements.in`](executor/deps/requirements.in); full transitive lock in [`requirements.txt`](executor/deps/requirements.txt))

- Pillow
- matplotlib
- numpy
- openpyxl
- pandas
- pdfplumber
- pypdf
- pypdfium2
- python-docx
- python-pptx
- reportlab
- sympy

**Node packages** (direct, pinned in [`executor/deps/package.json`](executor/deps/package.json); full transitive lock in [`package-lock.json`](executor/deps/package-lock.json))

- docx
- markdownlint
- marked
- pdf-lib
- pdfjs-dist
- pptxgenjs
- remark
- sharp
- ts-node
- tsx
- typescript
