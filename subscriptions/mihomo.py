from __future__ import annotations

import copy
import re
from typing import Any
from urllib.parse import urlsplit

from subscriptions.upstream import fetch_nodes, validate_nodes


INPUT_KEYS = {"proxies", "proxy-providers", "proxy-groups"}
PROBE_URL = "https://www.gstatic.com/generate_204"


def _name(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or any(
        ord(c) < 32 or c in ",=\x7f\x85\u2028\u2029" for c in value
    ):
        raise ValueError(f"{label} must be a name representable in both clients")


def _mapping(value: Any, fields: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) - fields:
        raise ValueError(f"{label} contains unsupported fields or is not a mapping")


def _patterns(value: Any, label: str) -> list[re.Pattern]:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a regular expression string")
    try:
        return [re.compile(pattern) for pattern in value.split("`") if pattern]
    except re.error:
        raise ValueError(f"{label} has an unsupported regular expression") from None


def _url(value: Any, label: str) -> None:
    try:
        parsed = urlsplit(value) if isinstance(value, str) else None
        valid = (
            parsed and parsed.scheme in {"http", "https"} and parsed.hostname
            and (parsed.port is None or 1 <= parsed.port <= 65535)
            and not any(c.isspace() or ord(c) < 32 for c in value)
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(f"{label} must be an HTTP(S) URL")


def validate_input(values: dict[str, Any]) -> None:
    proxies = values.get("proxies", [])
    if not isinstance(proxies, list):
        raise ValueError("proxies must be a list")
    validate_nodes(proxies, "proxies", set(), allow_dialer=True)
    providers = values.get("proxy-providers", {})
    if not isinstance(providers, dict):
        raise ValueError("proxy-providers must be a mapping")
    for index, (name, spec) in enumerate(providers.items(), start=1):
        label = f"proxy-provider #{index}"
        _name(name, label)
        _mapping(spec, {
            "type", "url", "upstreams", "interval", "payload", "filter", "exclude-filter",
            "exclude-type", "override",
        }, label)
        if spec.get("type") not in ("http", "inline"):
            raise ValueError(f"{label} type must be http or inline")
        if spec["type"] == "http":
            if ("url" in spec) == ("upstreams" in spec):
                raise ValueError(f"{label} requires either url or upstreams")
            if "upstreams" in spec:
                if not isinstance(spec["upstreams"], list) or not spec["upstreams"]:
                    raise ValueError(f"{label} upstreams must be a nonempty list")
                for position, source in enumerate(spec["upstreams"], start=1):
                    source_label = f"{label} upstream #{position}"
                    _mapping(source, {"name", "url"}, source_label)
                    _name(source.get("name"), f"{source_label} name")
                    _url(source.get("url"), f"{source_label} url")
            else:
                _url(spec["url"], f"{label} url")
            if "payload" in spec:
                raise ValueError(f"{label} HTTP fallback payload is not supported")
        elif not isinstance(spec.get("payload"), list) or {"url", "upstreams"}.intersection(spec):
            raise ValueError(f"{label} inline type requires payload and no upstream URLs")
        else:
            validate_nodes(spec["payload"], label, set(), allow_dialer=True)
        if "interval" in spec and (type(spec["interval"]) is not int or spec["interval"] < 0):
            raise ValueError(f"{label} interval must be a nonnegative integer")
        for key in ("filter", "exclude-filter"):
            _patterns(spec.get(key, ""), f"{label} {key}")
        if not isinstance(spec.get("exclude-type", ""), str):
            raise ValueError(f"{label} exclude-type must be a string")
        override = spec.get("override", {})
        _mapping(override, {"additional-prefix", "additional-suffix", "dialer-proxy"}, f"{label} override")
        if any(not isinstance(value, str) for value in override.values()):
            raise ValueError(f"{label} name overrides must be strings")
        if "dialer-proxy" in override:
            _name(override["dialer-proxy"], f"{label} dialer-proxy")

    groups = values.get("proxy-groups", [])
    if not isinstance(groups, list):
        raise ValueError("proxy-groups must be a list")
    names = set()
    for index, group in enumerate(groups, start=1):
        label = f"proxy-group #{index}"
        _mapping(group, {
            "name", "type", "proxies", "use", "url", "interval", "timeout", "tolerance",
            "lazy", "include-all", "include-all-proxies", "include-all-providers",
        }, label)
        name = group.get("name")
        _name(name, label)
        if name in names or name in {"Reef", "DIRECT", "REJECT", "GLOBAL", "direct", "reject"}:
            raise ValueError(f"{label} has a duplicate or reserved name")
        names.add(name)
        if group.get("type") not in ("select", "url-test"):
            raise ValueError(f"{label} type must be select or url-test")
        for key in ("proxies", "use"):
            members = group.get(key, [])
            if not isinstance(members, list):
                raise ValueError(f"{label} {key} must be a list")
            for member in members:
                _name(member, f"{label} {key}")
        for key in ("lazy", "include-all", "include-all-proxies", "include-all-providers"):
            if key in group and type(group[key]) is not bool:
                raise ValueError(f"{label} {key} must be a boolean")
        for key in ("interval", "timeout", "tolerance"):
            if key in group and (
                type(group[key]) is not int or group[key] < (0 if key == "tolerance" else 1)
            ):
                raise ValueError(f"{label} {key} must be a valid integer")
        if "url" in group:
            _url(group["url"], f"{label} url")
    if groups and "PROXY" not in names:
        raise ValueError("proxy-groups must define PROXY for the three profile templates")


def provider_upstreams(spec: dict) -> list[dict]:
    if spec["type"] != "http":
        return []
    return spec["upstreams"] if "upstreams" in spec else [{"url": spec["url"]}]


def load_providers(specs: dict[str, dict]) -> tuple[list[dict], dict[str, list[str]]]:
    nodes: dict[str, dict] = {}
    members = {}
    cache = {}
    for index, (name, spec) in enumerate(specs.items(), start=1):
        label = f"proxy-provider #{index}"
        include = _patterns(spec.get("filter", ""), f"{label} filter")
        exclude = _patterns(spec.get("exclude-filter", ""), f"{label} exclude-filter")
        excluded_types = spec.get("exclude-type", "").split("|")
        selected = {}
        override = spec.get("override", {})
        sources = provider_upstreams(spec) if spec["type"] == "http" else [{}]
        for source in sources:
            if spec["type"] == "http":
                url = source["url"]
                if url not in cache:
                    cache[url] = fetch_nodes(url, f"upstream URL #{len(cache) + 1} ({label})")
                candidates = cache[url]
            else:
                candidates = spec["payload"]
            prefix = f"{source['name']} | " if "name" in source else ""
            for candidate in candidates:
                if (
                    (include and not any(pattern.search(candidate["name"]) for pattern in include))
                    or any(pattern.search(candidate["name"]) for pattern in exclude)
                    or candidate["type"] in excluded_types
                ):
                    continue
                node = copy.deepcopy(candidate)
                node["name"] = (
                    override.get("additional-prefix", "") + prefix + node["name"]
                    + override.get("additional-suffix", "")
                )
                if "dialer-proxy" in override:
                    node["dialer-proxy"] = override["dialer-proxy"]
                if node["name"] in selected and node != selected[node["name"]]:
                    raise ValueError(f"{label} has a conflicting node name")
                selected.setdefault(node["name"], node)
        if not selected:
            raise ValueError(f"{label} has no nodes after filtering")
        validate_nodes(list(selected.values()), label, set(), allow_dialer=True)
        for node in selected.values():
            if node["name"] in nodes and node != nodes[node["name"]]:
                raise ValueError(f"{label} has a conflicting node name")
            nodes.setdefault(node["name"], node)
        members[name] = list(selected)
    return list(nodes.values()), members


def resolve_groups(
    groups: list[dict], providers: dict[str, list[str]], top_names: list[str], all_names: list[str],
) -> list[dict]:
    group_names = {group["name"] for group in groups}
    if group_names.intersection(all_names):
        raise ValueError("proxy-group name conflicts with a node")
    result = []
    for index, group in enumerate(groups, start=1):
        label = f"proxy-group #{index}"
        selected = list(group.get("proxies", []))
        if group.get("include-all") or group.get("include-all-proxies"):
            selected.extend(sorted(top_names))
        uses = group.get("use", [])
        if group.get("include-all") or group.get("include-all-providers"):
            uses = sorted(providers)
        for name in uses:
            if name not in providers:
                raise ValueError(f"{label} references an unknown proxy-provider")
            selected.extend(providers[name])
        selected = list(dict.fromkeys(selected))
        if not selected:
            raise ValueError(f"{label} has no members")
        if set(selected) - set(all_names) - group_names - {"DIRECT", "REJECT"}:
            raise ValueError(f"{label} references an unknown node or group")
        resolved = {key: value for key, value in group.items() if key not in {
            "use", "include-all", "include-all-proxies", "include-all-providers",
        }}
        resolved["proxies"] = selected
        if group["type"] == "url-test":
            for key, value in {"url": PROBE_URL, "interval": 300, "timeout": 5000,
                               "tolerance": 50, "lazy": True}.items():
                resolved.setdefault(key, value)
        result.append(resolved)
    return result


def validate_chains(proxies: list[dict], groups: list[dict], managed_names: list[str]) -> None:
    edges = {group["name"]: group["proxies"] for group in groups}
    known = set(edges) | {node["name"] for node in proxies} | set(managed_names) | {"DIRECT", "REJECT"}
    for index, node in enumerate(proxies, start=1):
        if "dialer-proxy" not in node:
            continue
        if not groups:
            raise ValueError("client-side relay requires explicit proxy-groups including PROXY")
        target = node["dialer-proxy"]
        if target not in known:
            raise ValueError(f"proxy node #{index} dialer-proxy references an unknown node or group")
        edges[node["name"]] = [target]
    visited, active = set(), set()

    def visit(name: str) -> None:
        if name in active:
            raise ValueError("proxy/group references contain a cycle")
        if name in visited:
            return
        active.add(name)
        for child in edges[name]:
            if child in edges:
                visit(child)
        active.remove(name)
        visited.add(name)

    for name in edges:
        visit(name)


def qx_policies(groups: list[dict], node_aliases: dict[str, str]) -> tuple[list[str], str, int]:
    aliases = {**node_aliases, "DIRECT": "direct", "REJECT": "reject"}
    aliases.update({group["name"]: group["name"] for group in groups})
    aliases["PROXY"] = "Reef"
    lines, probes = [], set()
    for index, group in enumerate(groups, start=1):
        if group["type"] == "select" and {"url", "interval", "timeout", "tolerance", "lazy"}.intersection(group):
            raise ValueError(f"proxy-group #{index} health-check options require url-test for QX conversion")
        if group["type"] == "url-test":
            if group["timeout"] > 5000:
                raise ValueError(f"proxy-group #{index} timeout exceeds the QX limit of 5000 ms")
            if set(group["proxies"]) & {item["name"] for item in groups}:
                raise ValueError(f"proxy-group #{index}: QX latency groups cannot contain other groups")
        members = list(dict.fromkeys(aliases[name] for name in group["proxies"] if name in aliases))
        if not members:
            raise ValueError(f"proxy-group #{index} has no Quantumult X-compatible members")
        kind = "static" if group["type"] == "select" else "url-latency-benchmark"
        line = f"{kind}={aliases[group['name']]}, " + ", ".join(members)
        if kind == "url-latency-benchmark":
            probes.add((group["url"], group["timeout"]))
            line += f", check-interval={group['interval']}, tolerance={group['tolerance']}"
            line += ", alive-checking=" + ("false" if group["lazy"] else "true")
        lines.append(line)
    if len(probes) > 1:
        raise ValueError("Quantumult X latency groups require one common probe URL and timeout")
    url, timeout = next(iter(probes), (PROBE_URL, 5000))
    return lines, url, timeout
