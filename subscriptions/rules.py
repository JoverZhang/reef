"""Fetch and compile the templates' rule resources as one snapshot."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from urllib.request import urlopen

import yaml


def qx_rules(body: bytes, policy: str, reinject: bool, label: str) -> list[str]:
    try:
        lines = body.decode("utf-8-sig").splitlines()
    except UnicodeError:
        raise ValueError(f"{label} must be UTF-8 text") from None
    rules = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith(("#", ";", "//")):
            continue
        fields = [part.strip() for part in line.split(",")]
        if len(fields) != 3 or not fields[1] or fields[0].lower() not in {
            "host", "host-suffix", "host-keyword", "host-wildcard", "user-agent",
            "ip-cidr", "ip6-cidr", "ip-asn", "geoip",
        }:
            raise ValueError(f"{label} contains an unsupported rule")
        rule = f"{fields[0].lower()}, {fields[1]}, {policy}"
        rules.append(rule + (", via-interface=%TUN%" if reinject else ""))
    if not rules:
        raise ValueError(f"{label} contains no rules")
    return list(dict.fromkeys(rules))


def compile_resources(snapshot: dict) -> None:
    from subscriptions.quantumult_x import _sections

    pending = []
    template = snapshot["templates"]["clash-geo"]
    policies = {parts[1]: parts[2] for rule in template["rules"]
                if (parts := rule.split(","))[0] == "RULE-SET"}
    for name, provider in template.get("rule-providers", {}).items():
        resource_id = f"clash-geo/{name}"
        pending.append({"id": resource_id, "name": name, "profile": "clash-geo",
                        "policy": policies[name], "url": provider["url"], "reinject": False})
        provider.update(url=f"reef-resource:{resource_id}", interval=3600)

    qx = snapshot["qx"]
    sections = qx["relay"]["sections"] if qx["relay"] else _sections(qx["body"] or "")
    remote = []
    for line in sections.get("filter_remote", []):
        url, *options = [part.strip() for part in line.split(",")]
        values = dict(option.split("=", 1) for option in options if "=" in option)
        name, policy = values["tag"], values["force-policy"]
        resource_id = f"qx/{name}"
        pending.append({"id": resource_id, "name": name, "profile": "qx", "policy": policy,
                        "url": url, "reinject": bool(qx["relay"]) and policy != "direct"})
        options = [option for option in options if not option.startswith("update-interval=")]
        remote.append(", ".join([f"reef-resource:{resource_id}", *options, "update-interval=3600"]))
    if sections:
        sections["filter_remote"] = remote
        if not qx["relay"]:
            qx["body"] = "\n\n".join(f"[{name}]\n" + "\n".join(lines)
                                        for name, lines in sections.items()) + "\n"

    def fetch(url: str) -> bytes:
        with urlopen(url, timeout=30) as response:
            body = response.read(16 * 1024 * 1024 + 1)
        if len(body) > 16 * 1024 * 1024:
            raise ValueError("oversized resource")
        return body

    resources = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        responses = {url: executor.submit(fetch, url) for url in dict.fromkeys(r["url"] for r in pending)}
        for item in pending:
            label = f"Rule resource {item['id']}"
            try:
                body = responses[item["url"]].result()
            except Exception:
                raise ValueError(f"{label} fetch failed") from None
            if item["profile"] == "qx":
                lines = qx_rules(body, item["policy"], item["reinject"], label)
            else:
                try:
                    document = yaml.safe_load(body)
                    lines = document["payload"]
                    if not isinstance(lines, list) or not lines or any(
                        not isinstance(line, str) or not line.strip() or "\n" in line or "\r" in line
                        for line in lines
                    ):
                        raise ValueError()
                except Exception:
                    raise ValueError(f"{label} must contain a nonempty YAML rule payload") from None
            resources.append({key: value for key, value in item.items() if key != "url"} | {"lines": lines})
    snapshot["resources"] = resources
