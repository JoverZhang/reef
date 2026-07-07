from __future__ import annotations

import argparse
import sys

from reef.core import load_model, render_ansible, render_subscriptions, render_web


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="+", choices=["ansible", "subscriptions", "web"])
    args = parser.parse_args()

    require_ssh = "ansible" in args.targets
    model = load_model(require_ssh=require_ssh)
    if "ansible" in args.targets:
        render_ansible(model)
    if "subscriptions" in args.targets:
        render_subscriptions(model)
    if "web" in args.targets:
        render_web(model)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"render: {exc}", file=sys.stderr)
        raise SystemExit(1)
