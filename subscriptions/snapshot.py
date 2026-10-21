from __future__ import annotations

import datetime as dt
import hashlib

import yaml

from subscriptions.upstream import qx_supported


def compile_snapshot(config, profiles: list[dict], context: dict) -> dict:
    """Compile the validated graph once; requests only select pool memberships."""
    documents = {p["id"]: p["body"] for p in profiles}
    client = yaml.safe_load(documents["client"])
    global_profile = yaml.safe_load(documents["linux-server"])
    proxies = client.pop("proxies")
    groups = client.pop("proxy-groups")
    if global_profile.pop("proxies") != proxies or global_profile.pop("proxy-groups") != groups:
        raise ValueError("Mihomo profiles must share one node and group snapshot")
    provider_nodes = {node["name"]: node for node in context["provider_nodes"]}

    def metadata(node: dict, original_name: str | None = None) -> dict:
        # Protocol compatibility is independent of the client's relay mechanism.
        endpoint = {key: value for key, value in node.items() if key != "dialer-proxy"}
        try:
            supported = qx_supported(endpoint)
        except ValueError:
            supported = False
        return {
            "name": node["name"], "originalName": original_name or node["name"],
            "protocol": node["type"], "qxSupported": supported,
        }

    def members(name: str) -> list[dict]:
        return [metadata(provider_nodes[node], context["original_names"][name][node])
                for node in context["provider_members"][name]]

    pools = [{
        "id": pool_id, "name": name,
        "group": next(group["name"] for group in context["proxy_groups"] if group.get("use") == [name]),
        "nodes": members(name),
    } for pool_id, name in config.pools.items()]
    pool_nodes = {node["name"] for pool in pools for node in pool["nodes"]}
    qx_body = documents.get("quantumult-x")
    qx_policy = next((line for line in (qx_body or "").splitlines()
                      if line.startswith(("static=Reef,", "url-latency-benchmark=Reef,"))), "")
    # Non-pool nodes include generated paths and any pre-existing standalone nodes.
    # Only pool membership is request-filterable in this version.
    return {
        "updatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "passwordHash": hashlib.sha256(config.web_password.encode()).hexdigest(),
        "exits": [{"name": name, "nodes": members(name)} for name in config.exit_providers],
        "pools": pools,
        "otherNodes": [] if config.exit_providers else [metadata(node) for node in proxies if node["name"] not in pool_nodes],
        "proxies": proxies,
        "groups": groups,
        "templates": {"clash": global_profile, "clash-geo": client},
        "qx": {
            "body": None if context.get("qx_relay") else qx_body,
            "relay": context.get("qx_relay"),
            "choices": [member for member in qx_policy.split(", ")[1:] if "=" not in member],
            "error": None if "quantumult-x" in documents else
                context.get("qx_error", "Quantumult X relay conversion requires automatic exits/pools. Native dialer-proxy chains require a Mihomo profile."),
        },
    }
