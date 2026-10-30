"""Bundle the existing compiler for the website; never fetch subscription data."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tarfile
from urllib.request import urlopen

from subscriptions import substore


PYTHON_URL = "https://github.com/astral-sh/python-build-standalone/releases/download/20261021/cpython-3.12.15%2B20261021-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
PYTHON_SHA256 = "6d7521138fd33afddc1ccd08abb007d9a2829e38117c2576f9efdc0ec73ce772"


def bundle(root: Path) -> None:
    destination = root / "web/generated/runtime"
    destination.mkdir(parents=True, exist_ok=True)
    python = destination / "python/bin/python3"
    if not python.exists():
        archive = root / "build/python-runtime.tar.gz"
        archive.parent.mkdir(parents=True, exist_ok=True)
        with urlopen(PYTHON_URL, timeout=60) as response:
            content = response.read()
        if hashlib.sha256(content).hexdigest() != PYTHON_SHA256:
            raise ValueError("Python runtime checksum verification failed")
        archive.write_bytes(content)
        # The checksum pins a trusted install-only archive with a single python directory.
        with tarfile.open(archive) as package:
            package.extractall(destination)
        archive.unlink()
    packages = destination / "packages"
    certificate = destination / "ca-bundle.pem"
    certificate.unlink(missing_ok=True)
    shutil.copyfile(ssl.get_default_verify_paths().cafile, certificate)
    subprocess.run([
        sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", "--target", str(packages),
        "--platform", "manylinux2014_x86_64", "--python-version", "3.12", "--only-binary=:all:",
        "jinja2==3.1.6", "markupsafe==3.0.3", "pyyaml==6.0.3", "urllib3==2.8.0",
    ], check=True)
    code = destination / "subscriptions"
    code.mkdir(exist_ok=True)
    for path in (root / "subscriptions").iterdir():
        if path.suffix in {".py", ".j2", ".mjs"}:
            shutil.copy2(path, code / path.name)
    converter = substore.ensure_bundle()
    target = destination / "build/substore"
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(converter, target / converter.name)


if __name__ == "__main__":
    os.umask(0o077)
    from reef.core import ROOT, load_model, prepare_web

    prepare_web(load_model())
    bundle(ROOT)
