from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined


SUBSCRIPTIONS_DIR = Path(__file__).resolve().parent
REQUIRED_CONTEXT = {"provider_ids", "profiles", "routes", "exits"}
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
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
    pairs = proxy_metadata(context, profile_id="client")
    qx_pairs = proxy_metadata(context, profile_id="quantumult-x")
    exit_groups = _exit_groups(context["exits"], pairs)
    qx_exit_groups = _exit_groups(context["exits"], qx_pairs)
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
                "exit_groups": exit_groups,
                "qx_exit_groups": qx_exit_groups,
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
    expected_exits = [node["id"] for node in context["exits"]]
    pairs = proxy_metadata(context, profile_id="client")
    qx_pairs = proxy_metadata(context, profile_id="quantumult-x")
    route_names_by_exit = _route_names_by_exit(expected_exits, pairs)

    client = yaml.safe_load(by_id["client"]["body"])
    _expect(len(client["proxies"]), len(pairs), "client proxy count mismatch")
    _check_mihomo_proxy_shape(client, [pair["name"] for pair in pairs])
    _check_groups(client, expected_exits, route_names_by_exit, "client.yaml")
    expected_direct_rules = _direct_rules(pairs)
    _expect(
        client["rules"][: len(expected_direct_rules)],
        expected_direct_rules,
        "client direct rules mismatch",
    )

    linux = yaml.safe_load(by_id["linux-server"]["body"])
    _expect(len(linux["proxies"]), len(pairs), "linux-server proxy count mismatch")
    _check_mihomo_proxy_shape(linux, [pair["name"] for pair in pairs])
    _check_groups(linux, expected_exits, route_names_by_exit, "linux-server.yaml")

    _check_quantumult_x(by_id["quantumult-x"]["body"], qx_pairs, expected_exits)


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
                    name=route["name"],
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
        "expected_exit_ip": route["exit"]["ip"],
        "server_host": connect["host"],
        "server_port": connect["port"],
        "password": server["password"],
        "cert_fingerprint": fingerprint,
        "cert_fingerprint_hex": fingerprint.replace(":", ""),
        "sni": server["ip"],
    }


def _exit_groups(exits: list[dict[str, Any]], pairs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": exit_node["id"],
            "exit_name": exit_node["id"],
            "proxies": [pair["name"] for pair in pairs if pair["exit_name"] == exit_node["id"]],
        }
        for exit_node in exits
    ]


def _route_names_by_exit(
    exits: list[str],
    pairs: list[dict[str, Any]],
) -> dict[str, list[str]]:
    return {
        exit_name: [pair["name"] for pair in pairs if pair["exit_name"] == exit_name]
        for exit_name in exits
    }


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


def _check_mihomo_proxy_shape(doc: dict[str, Any], expected_names: list[str]) -> None:
    _expect([proxy["name"] for proxy in doc["proxies"]], expected_names, "proxy order mismatch")
    for proxy in doc["proxies"]:
        for key in ["server", "port", "password", "sni", "fingerprint"]:
            if not proxy.get(key):
                raise ValueError(f"{proxy['name']} must include {key}")
        if proxy["type"] not in {"hysteria2", "trojan"}:
            raise ValueError(f"{proxy['name']} has unsupported type {proxy['type']!r}")


def _check_groups(
    doc: dict[str, Any],
    exits: list[str],
    route_names_by_exit: dict[str, list[str]],
    label: str,
) -> None:
    groups = _group_by_name(doc)
    _expect(groups["PROXY"]["proxies"], exits, f"{label} PROXY choices mismatch")
    for exit_name in exits:
        group = groups[exit_name]
        _expect(
            group["proxies"],
            route_names_by_exit[exit_name],
            f"{label} {exit_name} routes mismatch",
        )


def _check_quantumult_x(body: str, pairs: list[dict[str, Any]], exits: list[str]) -> None:
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

    server_lines = [line for line in lines if line.startswith("trojan=")]
    _expect(len(server_lines), len(pairs), "quantumult-x trojan count mismatch")
    for line, pair in zip(server_lines, pairs, strict=True):
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
    if not top_policy:
        raise ValueError("quantumult-x missing Reef policy")

    policy_lines = [line for line in lines if line.startswith("url-latency-benchmark=")]
    _expect(len(policy_lines), len(exits), "quantumult-x exit policy count mismatch")
    for exit_name in exits:
        expected = [pair["name"] for pair in pairs if pair["exit_name"] == exit_name]
        matching = [
            line
            for line in policy_lines
            if line.startswith(f"url-latency-benchmark={exit_name},")
        ]
        if len(matching) != 1:
            raise ValueError(f"quantumult-x missing policy for {exit_name}")
        if exit_name not in top_policy:
            raise ValueError(f"quantumult-x Reef policy missing {exit_name}")
        for proxy_name in expected:
            if proxy_name not in matching[0]:
                raise ValueError(f"quantumult-x {exit_name} policy missing {proxy_name}")

    if "final, Reef" not in lines:
        raise ValueError("quantumult-x final rule must use Reef policy")
