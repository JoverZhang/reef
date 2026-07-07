from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined


PROVIDER_DIR = Path(__file__).resolve().parents[1]
REQUIRED_CONTEXT = {"profiles", "routes", "exits"}


def render(context: dict[str, Any]) -> list[dict[str, str]]:
    _require_context(context)
    env = Environment(
        loader=FileSystemLoader(str(PROVIDER_DIR)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
    )
    pairs = [_pair(route) for route in context["routes"]]
    exit_groups = [
        {
            "name": exit_node["id"],
            "exit_name": exit_node["id"],
            "proxies": [pair["name"] for pair in pairs if pair["exit_name"] == exit_node["id"]],
        }
        for exit_node in context["exits"]
    ]
    entry_direct_rules = [
        f"IP-CIDR,{server}/32,DIRECT,no-resolve"
        for server in sorted({pair["entry_ip"] for pair in pairs})
    ]

    profiles = []
    for profile in context["profiles"]:
        template = env.get_template(profile["template"])
        body = template.render(
            {
                "profile": profile,
                "pairs": pairs,
                "exit_groups": exit_groups,
                "entry_direct_rules": entry_direct_rules,
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
    expected_route_names = [route["name"] for route in context["routes"]]
    route_names_by_exit = {
        exit_name: [route["name"] for route in context["routes"] if route["exit"]["id"] == exit_name]
        for exit_name in expected_exits
    }

    client = yaml.safe_load(by_id["client"]["body"])
    _expect(len(client["proxies"]), len(context["routes"]), "client proxy count mismatch")
    _check_proxy_shape(client, expected_route_names)
    _check_groups(client, expected_exits, route_names_by_exit, "client.yaml")
    expected_direct_rules = _direct_rules(context)
    _expect(
        client["rules"][: len(expected_direct_rules)],
        expected_direct_rules,
        "client direct rules mismatch",
    )

    linux = yaml.safe_load(by_id["linux-server"]["body"])
    _expect(len(linux["proxies"]), len(context["routes"]), "linux-server proxy count mismatch")
    _check_proxy_shape(linux, expected_route_names)
    _check_groups(linux, expected_exits, route_names_by_exit, "linux-server.yaml")


def _require_context(context: dict[str, Any]) -> None:
    missing = sorted(REQUIRED_CONTEXT - set(context))
    if missing:
        raise ValueError(f"missing subscription context: {', '.join(missing)}")


def _pair(route: dict[str, Any]) -> dict[str, Any]:
    server = route["server"]
    connect = route["connect"]
    return {
        "id": route["id"],
        "name": route["name"],
        "exit_name": route["exit"]["id"],
        "entry_ip": connect["host"],
        "entry_port": connect["port"],
        "entry_password": server["password"],
        "entry_cert_fingerprint": server["fingerprint"],
        "sni": server["ip"],
    }


def _expect(value: object, expected: object, message: str) -> None:
    if value != expected:
        raise ValueError(message)


def _group_by_name(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {group["name"]: group for group in doc["proxy-groups"]}


def _direct_rules(context: dict[str, Any]) -> list[str]:
    return [
        f"IP-CIDR,{server}/32,DIRECT,no-resolve"
        for server in sorted({route["connect"]["host"] for route in context["routes"]})
    ]


def _check_proxy_shape(doc: dict[str, Any], expected_names: list[str]) -> None:
    _expect([proxy["name"] for proxy in doc["proxies"]], expected_names, "proxy order mismatch")
    for proxy in doc["proxies"]:
        for key in ["server", "port", "password", "sni", "fingerprint"]:
            if not proxy.get(key):
                raise ValueError(f"{proxy['name']} must include {key}")


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
        _expect(group["proxies"], route_names_by_exit[exit_name], f"{label} {exit_name} routes mismatch")
