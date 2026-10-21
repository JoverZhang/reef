from __future__ import annotations

import secrets
import sys

from reef.core import config_path, load_config, write_config


def main() -> int:
    try:
        path = config_path()
        document = load_config(path) if path.exists() else {}
        if "secret" in document:
            raise ValueError("secret already exists in config.yaml")
        document["secret"] = secrets.token_hex(32)
        write_config(document, path)
    except (ValueError, OSError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else "could not write config.yaml"
        print(f"gen-secret: {message}", file=sys.stderr)
        return 1
    print("wrote secret to config.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
