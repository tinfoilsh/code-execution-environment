#!/usr/bin/env python3
"""Prune requirements.txt hashes to the deployment target.

uv pip compile --generate-hashes emits every SHA256 PyPI publishes for a
release: macOS, Windows, ARM, musllinux, PyPy, plus the sdist. Our
Dockerfile will only ever download one of those, so the rest are review
noise. This script keeps only hashes for artifacts compatible with
CPython 3.12 on linux_x86_64 glibc. Sdists are kept only when no
compatible wheel exists.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

PY_TAG = 312  # cp312

# {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
WHEEL_TAG_RE = re.compile(r"-cp(\d+)-(abi3|cp\d+)-")
SPEC_RE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;\\]+)")


def is_compatible_wheel(filename: str) -> bool:
    if not filename.endswith(".whl"):
        return False
    if filename.endswith("-py3-none-any.whl") or filename.endswith(
        "-py2.py3-none-any.whl"
    ):
        return True
    if "x86_64" not in filename:
        return False
    if "musllinux" in filename:
        return False
    if "manylinux" not in filename and "-linux_" not in filename:
        return False
    m = WHEEL_TAG_RE.search(filename)
    if not m:
        return False
    py_ver, abi = int(m.group(1)), m.group(2)
    if abi == "abi3":
        return py_ver <= PY_TAG
    return py_ver == PY_TAG


def is_sdist(filename: str) -> bool:
    return filename.endswith(".tar.gz") or filename.endswith(".zip")


def compatible_hashes_for(pkg: str, version: str) -> set[str]:
    url = f"https://pypi.org/pypi/{pkg}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as resp:
        files = json.load(resp).get("urls", [])
    wheels: set[str] = set()
    sdist: str | None = None
    for f in files:
        sha = f["digests"]["sha256"]
        fn = f["filename"]
        if is_compatible_wheel(fn):
            wheels.add(sha)
        elif is_sdist(fn) and sdist is None:
            sdist = sha
    if wheels:
        return wheels
    return {sdist} if sdist else set()


def filter_file(text: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        spec = SPEC_RE.match(line)
        if not spec:
            out.append(line)
            i += 1
            continue

        pkg, version = spec.group(1), spec.group(2)
        hash_lines: list[str] = []
        post_lines: list[str] = []
        j = i + 1
        while j < len(lines):
            jl = lines[j]
            if jl.lstrip().startswith("--hash="):
                hash_lines.append(jl)
                j += 1
            elif jl.startswith("    #") or jl.startswith("        "):
                post_lines.append(jl)
                j += 1
            else:
                break

        keep = compatible_hashes_for(pkg, version)
        kept_lines: list[str] = []
        for h in hash_lines:
            sha = h.strip().removeprefix("--hash=sha256:").rstrip(" \\")
            if sha in keep:
                kept_lines.append(h.rstrip(" \\"))

        if not kept_lines:
            print(
                f"warning: no compatible artifact for {pkg}=={version}",
                file=sys.stderr,
            )

        out.append(line.rstrip(" \\") + (" \\" if kept_lines else ""))
        for idx, h in enumerate(kept_lines):
            out.append(h + (" \\" if idx < len(kept_lines) - 1 else ""))
        out.extend(post_lines)
        i = j

    return "\n".join(out) + "\n"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: filter-hashes.py <requirements.txt>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    path.write_text(filter_file(path.read_text()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
