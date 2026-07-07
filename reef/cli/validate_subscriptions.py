from __future__ import annotations

from reef.core import load_model, render_subscriptions


def main() -> int:
    render_subscriptions(load_model())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
