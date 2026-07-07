from __future__ import annotations

import argparse
import secrets
from pathlib import Path


def upsert_env(path: Path, key: str, value: str, *, overwrite: bool = False) -> None:
    lines = path.read_text().splitlines() if path.exists() else []
    out: list[str] = []
    found = False
    for line in lines:
        if line.startswith(f"{key}="):
            found = True
            if not overwrite:
                raise SystemExit(f"{key} already exists in {path}")
            out.append(f"{key}={value}")
        else:
            out.append(line)
    if not found:
        out.append(f"{key}={value}")
    path.write_text("\n".join(out).rstrip() + "\n")
    path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", default=".env")
    args = parser.parse_args()
    upsert_env(Path(args.env), "REEF_SECRET", secrets.token_hex(32))
    print(f"wrote REEF_SECRET to {args.env}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
