from __future__ import annotations

from reef.core import is_ci, load_model, render_subscriptions


def main() -> int:
    model = load_model()
    hide_tokens = is_ci()
    for profile in render_subscriptions(model):
        if hide_tokens:
            print(f"{profile['id']:<14} <hidden in CI>")
        else:
            print(f"{profile['id']:<14} /{profile['token']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
