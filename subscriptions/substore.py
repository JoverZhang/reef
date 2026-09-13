from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.request import urlopen


VERSION = "2.39.6"
SHA256 = "0b3f15b1ca3dd5c8575be7360a154e012a66f2e3b0e207ea37c10c8f8a741f54"
URL = f"https://github.com/sub-store-org/Sub-Store/releases/download/{VERSION}/proxy-utils.esm.mjs"
ROOT = Path(__file__).resolve().parents[1]


def convert(proxies: list[dict]) -> list[str]:
    """Run the pinned official parser/producer with node data on stdin, offline."""
    cache = ROOT / "build" / "substore"
    cache.mkdir(parents=True, exist_ok=True)
    bundle = cache / f"proxy-utils-{VERSION}.mjs"
    try:
        if not bundle.exists():
            with urlopen(URL, timeout=30) as response:
                content = response.read()
            if hashlib.sha256(content).hexdigest() != SHA256:
                raise ValueError("checksum mismatch")
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as pending:
                pending.write(content)
            Path(pending.name).replace(bundle)
        if hashlib.sha256(bundle.read_bytes()).hexdigest() != SHA256:
            raise ValueError("checksum mismatch")
    except Exception:
        raise ValueError("Sub-Store download or checksum verification failed") from None

    try:
        result = subprocess.run(
            ["node", "--experimental-vm-modules", str(ROOT / "subscriptions" / "substore.mjs"), str(bundle)],
            input=json.dumps({"proxies": proxies}),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
            check=True,
            # The converter never receives Reef's environment or subscription URLs.
            env={"PATH": os.environ.get("PATH", os.defpath)},
            cwd=cache,
        )
        lines = json.loads(result.stdout)
        if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines):
            raise ValueError("invalid converter output")
        return lines
    except Exception:
        # Sub-Store diagnostics may contain an entire node including its password.
        raise ValueError("Sub-Store conversion failed (details withheld)") from None
