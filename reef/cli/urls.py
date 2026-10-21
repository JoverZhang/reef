from __future__ import annotations

import argparse
import sys

from reef.core import is_ci, load_model, render_subscriptions, render_web


def main(target: str = "all") -> int:
    model = load_model()
    if target == "mihomo":
        for profile in render_subscriptions(model, mihomo_only=True):
            print(f"{profile['id']:<14} {profile['output']}")
        print("Local Mihomo preview generated; import these files to try the relay.", file=sys.stderr)
        return 0
    hide_tokens = is_ci()
    for profile in render_web(model):
        if hide_tokens:
            print(f"{profile['id']:<14} <hidden in CI>")
        else:
            print(f"{profile['id']:<14} /{profile['token']}")
    return 0


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("target", nargs="?", choices=["all", "mihomo"], default="all")
        raise SystemExit(main(parser.parse_args().target))
    except Exception as exc:
        message = "generation failed (details hidden in CI)" if is_ci() else str(exc)
        print(f"urls: {message}", file=sys.stderr)
        raise SystemExit(1)
