"""Compile automatic two-hop paths into QX's address-based relay rules."""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.request import urlopen

from subscriptions.upstream import quantumult_x_nodes, qx_supported
from subscriptions.rules import qx_rules


class UnsupportedRelay(ValueError):
    """A topology QX cannot represent; Mihomo remains available."""


def _pin_address(node: dict, addresses: dict[str, str]) -> dict:
    server = node["server"].strip("[]")
    try:
        address = str(ipaddress.ip_address(server))
    except ValueError:
        key = server.lower().rstrip(".")
        if key not in addresses:
            try:
                records = socket.getaddrinfo(server, None, type=socket.SOCK_STREAM)
                candidates = {ipaddress.ip_address(record[4][0]) for record in records}
                addresses[key] = str(min(candidates, key=lambda ip: (ip.version, int(ip))))
            except (OSError, ValueError):
                raise UnsupportedRelay("QX could not resolve a node address. Republish after checking node DNS.") from None
        address = addresses[key]
    pinned = {**node, "server": address}
    if address != server and (node.get("tls") or node["type"] in {"trojan", "anytls"}):
        # Changing the dial address must not change TLS identity or certificate checks.
        if not node.get("sni") and not node.get("servername"):
            host = node.get("ws-opts", {}).get("headers", {}).get("Host", server)
            pinned["servername" if node["type"] == "vless" else "sni"] = host
    return pinned


def _sections(body: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = None
    for line in body.splitlines():
        if re.fullmatch(r"\[[a-z_]+\]", line):
            current = line[1:-1]
            sections[current] = []
        elif current and line.strip():
            sections[current].append(line)
    return sections


def _proxy_rules(resources: list[str]) -> tuple[list[str], list[str]]:
    """Inline proxy rules so no parser failure can silently remove a relay hop."""
    remote, local = [], []
    for index, resource in enumerate(resources, 1):
        parts = [part.strip() for part in resource.split(",")]
        if "force-policy=Reef" not in parts:
            remote.append(resource)
            continue
        try:
            with urlopen(parts[0], timeout=30) as response:
                body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise ValueError()
        except Exception:
            raise ValueError(f"QX rule resource #{index} fetch failed") from None
        local.extend(qx_rules(body, "Reef", True, f"QX rule resource #{index}"))
    return remote, list(dict.fromkeys(local))


def serialize(plan: dict) -> str:
    sections = {key: list(lines) for key, lines in plan["sections"].items()}
    sections["server_local"] = [node["line"] for node in plan["nodes"]]
    sections["policy"] = [
        f"{policy['kind']}={policy['name']}, " + ", ".join(policy["members"] + policy["options"])
        for policy in plan["policies"]
    ]
    sections["filter_local"] = list(dict.fromkeys(node["rule"] for node in plan["nodes"])) + sections["filter_local"]
    return "\n\n".join(f"[{key}]\n" + "\n".join(lines) for key, lines in sections.items()) + "\n"


def compile_relay(context: dict, exits: list[str], pools: list[str], profile: dict, renderer,
                  relay_pools: list[str]) -> tuple[dict, dict]:
    providers = context["provider_members"]
    by_name = {node["name"]: node for node in context["provider_nodes"]}
    memberships = {}
    for name in exits + pools:
        candidates = [by_name[member] for member in providers[name]]
        if any("dialer-proxy" in node for node in candidates):
            raise UnsupportedRelay("QX relay conversion requires ordinary endpoints in exits and pools; nested dialer-proxy is unsupported.")
        memberships[name] = [node for node in candidates if qx_supported(node)]
        if not memberships[name]:
            raise UnsupportedRelay("A QX exit or pool has no compatible endpoints. Check the greyed-out nodes.")

    pool_groups = [f"POOL | {name}" for name in pools]
    choices = [f"EXIT | {name}" for name in exits] + pool_groups
    groups = [{"name": "PROXY", "type": "select", "proxies": choices}]
    nodes, metadata, owners, addresses, names_seen = [], [], {}, {}, {}

    def add_node(node: dict, name: str, owner: str, policy: str) -> None:
        pinned = _pin_address(node, addresses)
        address = pinned["server"]
        if address in owners and owners[address] != owner:
            raise UnsupportedRelay("QX exits must have distinct addresses and cannot share an address with a pool.")
        owners[address] = owner
        if name in names_seen:
            # A shared subscription node belongs to more than one pool.
            if names_seen[name] != (owner, node["name"]):
                raise UnsupportedRelay("QX generated node names conflict. Rename the conflicting collection or endpoint.")
            return
        names_seen[name] = (owner, node["name"])
        nodes.append({**pinned, "name": name})
        ip = ipaddress.ip_address(address)
        rule_type = "ip-cidr" if ip.version == 4 else "ip6-cidr"
        metadata.append({
            "name": name, "sourceName": node["name"],
            "rule": f"{rule_type}, {address}/{ip.max_prefixlen}, {policy}",
        })

    for name in exits:
        members = memberships[name]
        endpoint = f"EXIT | {name}"
        names = [endpoint if len(members) == 1 else f"{endpoint} | {node['name'].removeprefix(name + ' | ')}"
                 for node in members]
        for node, tag in zip(members, names):
            add_node(node, tag, endpoint, f"RELAY | {name}")
        if len(names) > 1:
            groups.append({"name": endpoint, "type": "url-test", "proxies": names})
    relay_groups = [f"POOL | {name}" for name in pools if name in relay_pools]
    groups.extend({"name": f"RELAY | {name}", "type": "select", "proxies": relay_groups + ["DIRECT"]} for name in exits)
    for name in pools:
        for node in memberships[name]:
            add_node(node, node["name"], "pool", "direct")
        groups.append({"name": f"POOL | {name}", "type": "url-test",
                       "proxies": [node["name"] for node in memberships[name]]})

    converted = quantumult_x_nodes(nodes)
    if len(converted) != len(nodes):
        raise ValueError("QX address normalization changed endpoint compatibility")
    qx_context = {
        **context, "profiles": [profile], "routes": [], "entries": [], "exits": [],
        "upstream_proxies": nodes, "qx_upstream": converted, "proxy_groups": groups,
        "provider_members": {}, "top_proxy_names": [],
    }
    try:
        rendered = renderer.render(qx_context)[0]
    except ValueError:
        raise UnsupportedRelay("QX generated node and policy names conflict. Rename the conflicting collection or endpoint.") from None
    sections = _sections(rendered["body"])
    policies = []
    for line in sections["policy"]:
        head, *items = line.split(", ")
        kind, name = head.split("=", 1)
        policies.append({"name": name, "kind": kind, "members": [item for item in items if "=" not in item],
                         "options": [item for item in items if "=" in item]})
    remote, rules = ((sections["filter_remote"], []) if context.get("hosted_rules")
                     else _proxy_rules(sections["filter_remote"]))
    sections["filter_remote"] = remote
    sections["filter_local"] = rules + [
        line + ", via-interface=%TUN%" if line == "final, Reef" else line
        for line in sections["filter_local"]
    ]
    sections["general"].insert(0, "# Use filter mode. Select an EXIT in Reef, then its RELAY pool (or direct).")
    sections["server_local"], sections["policy"] = [], []
    plan = {"sections": sections, "nodes": [{**meta, "line": node["line"]} for meta, node in zip(metadata, converted)],
            "policies": policies}
    return {**rendered, "body": serialize(plan)}, plan
