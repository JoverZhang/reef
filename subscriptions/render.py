from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined


SUBSCRIPTIONS_DIR = Path(__file__).resolve().parent
REQUIRED_CONTEXT = {
    "provider_ids", "profiles", "routes", "entries", "exits", "upstream_proxies", "qx_upstream",
}
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
QX_TAG_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PROVIDER_TRANSPORTS = {
    "hysteria2": {
        "transport": "hysteria2",
        "mihomo_suffix": "",
        "quantumult_x": False,
    },
    "trojan": {
        "transport": "trojan",
        "mihomo_suffix": " trojan",
        "quantumult_x": True,
    },
}


def render(context: dict[str, Any]) -> list[dict[str, str]]:
    _require_context(context)
    env = Environment(
        loader=FileSystemLoader(str(SUBSCRIPTIONS_DIR)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
    )
    # YAML readers do not combine JSON surrogate escapes used for emoji names.
    env.policies["json.dumps_kwargs"] = {"ensure_ascii": False, "sort_keys": True}
    pairs = proxy_metadata(context, profile_id="client")
    qx_pairs = proxy_metadata(context, profile_id="quantumult-x")
    upstream = context["upstream_proxies"]
    qx_upstream = context["qx_upstream"]
    if not qx_pairs and not qx_upstream:
        raise ValueError("subscription-only mode requires a Quantumult X-compatible upstream node")
    reserved_names = (
        {"PROXY", "Reef", "AUTO", "DIRECT", "REJECT", "direct", "reject"}
        | {pair["name"] for pair in pairs + qx_pairs}
        | {f"entry-{node['id']}" for node in context["entries"]}
    )
    for index, proxy in enumerate(upstream, start=1):
        if proxy["name"] in reserved_names:
            raise ValueError(f"upstream node {index} name conflicts with a local node or policy")
    if len(qx_upstream) < len(upstream):
        print(
            f"quantumult-x: skipped {len(upstream) - len(qx_upstream)} upstream node(s) "
            "with unsupported protocols or options",
            file=sys.stderr,
        )
    proxy_names = [node["name"] for node in pairs + upstream]
    qx_proxy_names = [node["name"] for node in qx_pairs + qx_upstream]
    entry_groups = _entry_groups(context["entries"], pairs)
    qx_entry_groups = _entry_groups(context["entries"], qx_pairs)
    entry_override_rules = _entry_override_rules(entry_groups)
    qx_entry_override_rules = _qx_entry_override_rules(qx_entry_groups)
    entry_direct_rules = [
        f"IP-CIDR,{server}/32,DIRECT,no-resolve"
        for server in sorted({pair["server_host"] for pair in pairs})
    ]
    qx_entry_direct_rules = [
        f"ip-cidr, {server}/32, direct"
        for server in sorted({pair["server_host"] for pair in qx_pairs})
    ]

    profiles = []
    for profile in context["profiles"]:
        template = env.get_template(profile["template"])
        body = template.render(
            {
                "profile": profile,
                "pairs": pairs,
                "qx_pairs": qx_pairs,
                "upstream_proxies": upstream,
                "qx_upstream": qx_upstream,
                "proxy_names": proxy_names,
                "qx_proxy_names": qx_proxy_names,
                "entry_groups": entry_groups,
                "qx_entry_groups": qx_entry_groups,
                "entry_override_rules": entry_override_rules,
                "qx_entry_override_rules": qx_entry_override_rules,
                "entry_direct_rules": entry_direct_rules,
                "qx_entry_direct_rules": qx_entry_direct_rules,
                "mixed_port": int(profile.get("mixed_port", 7890)),
            }
        )
        profiles.append(
            {
                "id": profile["id"],
                "output": profile["output"],
                "content_type": profile.get("content_type", "text/plain; charset=utf-8"),
                "body": body,
            }
        )
    return profiles


def validate(profiles: list[dict[str, str]], context: dict[str, Any]) -> None:
    _require_context(context)
    by_id = {profile["id"]: profile for profile in profiles}
    pairs = proxy_metadata(context, profile_id="client")
    qx_pairs = proxy_metadata(context, profile_id="quantumult-x")
    upstream = context["upstream_proxies"]
    qx_upstream = context["qx_upstream"]
    proxy_names = [node["name"] for node in pairs + upstream]
    entry_groups = _entry_groups(context["entries"], pairs)
    qx_entry_groups = _entry_groups(context["entries"], qx_pairs)

    client = yaml.safe_load(by_id["client"]["body"])
    _check_mihomo_proxy_shape(client, [pair["name"] for pair in pairs], upstream)
    _check_groups(client, proxy_names, "client.yaml")
    _check_entry_groups(client, entry_groups, "client.yaml")
    expected_entry_rules = _entry_override_rules(entry_groups)
    expected_direct_rules = _direct_rules(pairs)
    _expect(
        client["rules"][: len(expected_entry_rules)],
        expected_entry_rules,
        "client entry override rules mismatch",
    )
    direct_start = len(expected_entry_rules)
    _expect(
        client["rules"][direct_start : direct_start + len(expected_direct_rules)],
        expected_direct_rules,
        "client direct rules mismatch",
    )

    linux = yaml.safe_load(by_id["linux-server"]["body"])
    _check_mihomo_proxy_shape(linux, [pair["name"] for pair in pairs], upstream)
    _check_groups(linux, proxy_names, "linux-server.yaml")

    _check_quantumult_x(
        by_id["quantumult-x"]["body"],
        qx_pairs,
        qx_entry_groups,
        qx_upstream,
    )


def _require_context(context: dict[str, Any]) -> None:
    missing = sorted(REQUIRED_CONTEXT - set(context))
    if missing:
        raise ValueError(f"missing subscription context: {', '.join(missing)}")


def proxy_metadata(context: dict[str, Any], *, profile_id: str = "client") -> list[dict[str, Any]]:
    _require_context(context)
    if profile_id in {"client", "linux-server"}:
        return _mihomo_pairs(context)
    if profile_id == "quantumult-x":
        return _quantumult_x_pairs(context)
    raise ValueError(f"unsupported subscription profile for proxy metadata: {profile_id}")


def _provider_ids(context: dict[str, Any]) -> set[str]:
    provider_ids = set(context["provider_ids"])
    unsupported = sorted(provider_ids - set(PROVIDER_TRANSPORTS))
    if unsupported:
        raise ValueError(
            "subscription renderer does not support provider(s): " + ", ".join(unsupported)
        )
    return provider_ids


def _mihomo_pairs(context: dict[str, Any]) -> list[dict[str, Any]]:
    provider_ids = _provider_ids(context)
    pairs = []
    for route in context["routes"]:
        for provider_id in sorted(provider_ids):
            spec = PROVIDER_TRANSPORTS[provider_id]
            pairs.append(
                _pair(
                    route,
                    provider_id=provider_id,
                    transport=str(spec["transport"]),
                    name=f"{route['name']}{spec['mihomo_suffix']}",
                )
            )
    return pairs


def _quantumult_x_pairs(context: dict[str, Any]) -> list[dict[str, Any]]:
    provider_ids = _provider_ids(context)
    pairs = []
    for route in context["routes"]:
        for provider_id in sorted(provider_ids):
            spec = PROVIDER_TRANSPORTS[provider_id]
            if not spec["quantumult_x"]:
                continue
            pairs.append(
                _pair(
                    route,
                    provider_id=provider_id,
                    transport=str(spec["transport"]),
                    name=route["id"],
                )
            )
    return pairs


def _pair(
    route: dict[str, Any],
    *,
    provider_id: str,
    transport: str,
    name: str,
) -> dict[str, Any]:
    server = route["server"]
    connect = route["connect"]
    fingerprint = server["fingerprint"]
    return {
        "provider_id": provider_id,
        "id": route["id"],
        "route_id": route["id"],
        "name": name,
        "transport": transport,
        "exit_name": route["exit"]["id"],
        "exit_id": route["exit"]["id"],
        "entry_name": route["entry"]["id"] if route["entry"] else None,
        "entry_id": route["entry"]["id"] if route["entry"] else None,
        "entry_override_host": (
            route["entry"]["entry_override_host"] if route["entry"] else None
        ),
        "kind": route["kind"],
        "expected_exit_ip": route["exit"]["ip"],
        "server_host": connect["host"],
        "server_port": connect["port"],
        "password": server["password"],
        "cert_fingerprint": fingerprint,
        "cert_fingerprint_hex": fingerprint.replace(":", ""),
        "sni": server["ip"],
    }


def _entry_groups(entries: list[dict[str, Any]], pairs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = []
    for entry in entries:
        host = entry.get("entry_override_host")
        if not host:
            continue
        groups.append(
            {
                "name": f"entry-{entry['id']}",
                "entry_name": entry["id"],
                "entry_id": entry["id"],
                "host": host,
                "proxies": [
                    pair["name"]
                    for pair in pairs
                    if pair["kind"] == "relay" and pair["entry_id"] == entry["id"]
                ],
            }
        )
    return groups


def _expect(value: object, expected: object, message: str) -> None:
    if value != expected:
        raise ValueError(message)


def _group_by_name(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {group["name"]: group for group in doc["proxy-groups"]}


def _direct_rules(pairs: list[dict[str, Any]]) -> list[str]:
    return [
        f"IP-CIDR,{server}/32,DIRECT,no-resolve"
        for server in sorted({pair["server_host"] for pair in pairs})
    ]


def _entry_override_rules(entry_groups: list[dict[str, Any]]) -> list[str]:
    return [f"DOMAIN,{group['host']},{group['name']}" for group in entry_groups]


def _qx_entry_override_rules(entry_groups: list[dict[str, Any]]) -> list[str]:
    return [f"host, {group['host']}, {group['name']}" for group in entry_groups]


def _check_mihomo_proxy_shape(
    doc: dict[str, Any], expected_names: list[str], upstream: list[dict[str, Any]]
) -> None:
    _expect(
        [proxy["name"] for proxy in doc["proxies"]],
        expected_names + [proxy["name"] for proxy in upstream],
        "proxy order mismatch",
    )
    _expect(doc["proxies"][len(expected_names) :], upstream, "upstream proxy fields mismatch")
    for proxy in doc["proxies"][: len(expected_names)]:
        for key in ["server", "port", "password", "sni", "fingerprint"]:
            if not proxy.get(key):
                raise ValueError(f"{proxy['name']} must include {key}")
        if proxy["type"] not in {"hysteria2", "trojan"}:
            raise ValueError(f"{proxy['name']} has unsupported type {proxy['type']!r}")


def _check_groups(
    doc: dict[str, Any],
    proxy_names: list[str],
    label: str,
) -> None:
    groups = _group_by_name(doc)
    _expect(groups["PROXY"]["type"], "select", f"{label} PROXY must be manual")
    _expect(groups["PROXY"]["proxies"], ["AUTO"] + proxy_names, f"{label} PROXY choices mismatch")
    _expect(groups["AUTO"]["type"], "url-test", f"{label} AUTO must test latency")
    _expect(groups["AUTO"]["proxies"], proxy_names, f"{label} AUTO choices mismatch")


def _check_entry_groups(
    doc: dict[str, Any],
    entry_groups: list[dict[str, Any]],
    label: str,
) -> None:
    groups = _group_by_name(doc)
    for entry_group in entry_groups:
        group = groups.get(entry_group["name"])
        if not group:
            raise ValueError(f"{label} missing {entry_group['name']} group")
        _expect(
            group["proxies"],
            entry_group["proxies"],
            f"{label} {entry_group['name']} routes mismatch",
        )


def _check_quantumult_x(
    body: str,
    pairs: list[dict[str, Any]],
    entry_groups: list[dict[str, Any]],
    upstream: list[dict[str, str]],
) -> None:
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    required_sections = {
        "[general]",
        "[dns]",
        "[server_local]",
        "[server_remote]",
        "[policy]",
        "[filter_local]",
        "[rewrite_remote]",
        "[rewrite_local]",
        "[mitm]",
    }
    missing_sections = sorted(required_sections - set(lines))
    if missing_sections:
        raise ValueError("quantumult-x missing section(s): " + ", ".join(missing_sections))

    local_start = lines.index("[server_local]") + 1
    local_lines = lines[local_start : lines.index("[server_remote]")]
    _expect(local_lines[len(pairs) :], [node["line"] for node in upstream], "QX upstream mismatch")
    server_lines = local_lines[: len(pairs)]
    _expect(len(server_lines), len(pairs), "quantumult-x trojan count mismatch")
    for line, pair in zip(server_lines, pairs, strict=True):
        if not QX_TAG_RE.match(pair["name"]):
            raise ValueError(f"quantumult-x invalid tag for {pair['name']}")
        if f"tag={pair['name']}" not in line:
            raise ValueError(f"quantumult-x missing tag for {pair['name']}")
        if f"password={pair['password']}" not in line:
            raise ValueError(f"quantumult-x missing password for {pair['name']}")
        if f"tls-host={pair['sni']}" not in line:
            raise ValueError(f"quantumult-x missing tls-host for {pair['name']}")
        if not HEX_SHA256_RE.match(pair["cert_fingerprint_hex"]):
            raise ValueError(f"quantumult-x invalid fingerprint for {pair['name']}")
        if f"tls-cert-sha256={pair['cert_fingerprint_hex']}" not in line:
            raise ValueError(f"quantumult-x missing tls-cert-sha256 for {pair['name']}")

    top_policy = next((line for line in lines if line.startswith("static=Reef,")), "")
    proxy_names = [node["name"] for node in pairs + upstream]
    _expect(
        top_policy,
        "static=Reef, AUTO, " + ", ".join(proxy_names),
        "quantumult-x Reef choices mismatch",
    )

    policy_lines = [line for line in lines if line.startswith("url-latency-benchmark=")]
    _expect(
        len(policy_lines),
        1 + len(entry_groups),
        "quantumult-x policy count mismatch",
    )
    auto_policy = next(
        (line for line in policy_lines if line.startswith("url-latency-benchmark=AUTO,")), ""
    )
    _expect(
        auto_policy.split(", ")[1:-2],
        proxy_names,
        "quantumult-x AUTO choices mismatch",
    )

    for entry_group in entry_groups:
        matching = [
            line
            for line in policy_lines
            if line.startswith(f"url-latency-benchmark={entry_group['name']},")
        ]
        if len(matching) != 1:
            raise ValueError(f"quantumult-x missing policy for {entry_group['name']}")
        for proxy_name in entry_group["proxies"]:
            if proxy_name not in matching[0]:
                raise ValueError(
                    f"quantumult-x {entry_group['name']} policy missing {proxy_name}"
                )

    entry_rules = _qx_entry_override_rules(entry_groups)
    filter_start = lines.index("[filter_local]") + 1
    _expect(
        lines[filter_start : filter_start + len(entry_rules)],
        entry_rules,
        "quantumult-x entry override rules mismatch",
    )

    if "final, Reef" not in lines:
        raise ValueError("quantumult-x final rule must use Reef policy")
