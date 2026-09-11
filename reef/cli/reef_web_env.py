from __future__ import annotations

import sys

from reef.core import is_ci, load_env, parse_config


def main() -> int:
    if is_ci():
        print("reef-web-env: refusing to output the root seed in CI", file=sys.stderr)
        return 1

    values = load_env()
    values.pop("REEF_SSH_PRIVATE_KEY_B64", None)
    config = parse_config(values)
    lines = [
        f"REEF_SECRET={config.secret_hex}",
        f"REEF_ENTRY_PORT_BASE={config.entry_port_base}",
        f"REEF_EXIT_PORT={config.exit_port}",
    ]
    if config.entry_override_base_domain:
        lines.append(f"REEF_ENTRY_OVERRIDE_BASE_DOMAIN={config.entry_override_base_domain}")
    for kind, nodes in (("ENTRY", config.entries), ("EXIT", config.exits)):
        lines.extend(f"REEF_{kind}_{node.index}={node.id},{node.ip}" for node in nodes)
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"reef-web-env: {exc}", file=sys.stderr)
        raise SystemExit(1)
