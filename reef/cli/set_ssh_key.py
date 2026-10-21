from __future__ import annotations

import argparse
import sys
from pathlib import Path

from reef.core import config_path, load_config, validate_ssh_private_key, write_config


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("key_path")
    args = parser.parse_args()
    try:
        key = Path(args.key_path).read_text()
        validate_ssh_private_key(key)
        path = config_path()
        document = load_config(path) if path.exists() else {}
        document["ssh_private_key"] = key
        write_config(document, path)
    except UnicodeError:
        print("set-ssh-key: key must be UTF-8 OpenSSH text", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else "could not read the key or write config.yaml"
        print(f"set-ssh-key: {message}", file=sys.stderr)
        return 1
    print("wrote ssh_private_key to config.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
