from __future__ import annotations

import sys

from reef.core import dump_config, is_ci, load_config, parse_config


def main() -> int:
    if is_ci():
        print("config-yaml: refusing to output the root seed in CI", file=sys.stderr)
        return 1
    try:
        document = load_config()
        document.pop("ssh_private_key", None)
        parse_config(document)
    except ValueError as exc:
        print(f"config-yaml: {exc}", file=sys.stderr)
        return 1
    print(dump_config(document), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
