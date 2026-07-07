from __future__ import annotations

import argparse
import base64
from pathlib import Path


def upsert_env(path: Path, key: str, value: str) -> None:
    lines = path.read_text().splitlines() if path.exists() else []
    out: list[str] = []
    found = False
    for line in lines:
        if line.startswith(f"{key}="):
            out.append(f"{key}={value}")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"{key}={value}")
    path.write_text("\n".join(out).rstrip() + "\n")
    path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", default=".env")
    parser.add_argument("key_path")
    args = parser.parse_args()
    raw = Path(args.key_path).read_bytes()
    if b"PRIVATE KEY" not in raw:
        raise SystemExit(f"{args.key_path} does not look like an OpenSSH private key")
    encoded = base64.b64encode(raw).decode()
    upsert_env(Path(args.env), "REEF_SSH_PRIVATE_KEY_B64", encoded)
    print(f"wrote REEF_SSH_PRIVATE_KEY_B64 to {args.env}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
