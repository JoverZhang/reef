from __future__ import annotations

import sys

from reef.core import is_ci, load_model, render_web


def main() -> int:
    model = load_model()
    hide_tokens = is_ci()
    for profile in render_web(model):
        if hide_tokens:
            print(f"{profile['id']:<14} <hidden in CI>")
        else:
            print(f"{profile['id']:<14} /{profile['token']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        message = "generation failed (details hidden in CI)" if is_ci() else str(exc)
        print(f"urls: {message}", file=sys.stderr)
        raise SystemExit(1)
