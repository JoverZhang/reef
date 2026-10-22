"""Private stdin/stdout protocol used by the website's refresh worker."""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
from types import SimpleNamespace

from subscriptions.compiler import compile_profiles
from subscriptions.rules import compile_resources
from subscriptions.snapshot import compile_snapshot
from subscriptions import substore


def refresh(payload: dict) -> dict:
    config = SimpleNamespace(**payload["config"])
    profiles, context = compile_profiles(config, payload["context"], hosted_rules=True)
    snapshot = compile_snapshot(config, profiles, context)
    compile_resources(snapshot)
    snapshot["updatedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
    return snapshot


def main() -> None:
    if len(sys.argv) > 1:
        substore.NODE = sys.argv[1]
    try:
        snapshot = refresh(json.load(sys.stdin))
    except Exception as error:
        message = str(error)
        if not re.fullmatch(
            r"(?:upstream URL #\d+(?: \(proxy-provider #\d+\))?|Rule resource (?:qx|clash-geo)/[a-z0-9_-]+) "
            r"(?:fetch failed|must be valid YAML|must contain a proxies list|returned an empty proxies list|"
            r"contains no rules|contains an unsupported rule|must be UTF-8 text|"
            r"must contain a nonempty YAML rule payload)", message,
        ):
            message = "Subscription compilation failed; check node and policy configuration."
        print(json.dumps({"error": message}))
        raise SystemExit(1) from None
    print(json.dumps({"snapshot": snapshot}, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
