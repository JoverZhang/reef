"""The shared subscription compiler for local rendering and runtime refreshes."""
from __future__ import annotations

from copy import deepcopy

from subscriptions import render
from subscriptions.mihomo import load_providers, relay_groups
from subscriptions.upstream import load_nodes, quantumult_x_nodes


def compile_profiles(config, context: dict, *, mihomo_only: bool = False,
                     hosted_rules: bool = False, renderer=render, tunnel: dict | None = None) -> tuple[list[dict], dict]:
    context = deepcopy(context)
    context["hosted_rules"] = hosted_rules
    context["upstream_proxies"] = load_nodes(config.upstream_urls, config.extend_proxies, tunnel=tunnel)
    context["top_proxy_names"] = [node["name"] for node in context["upstream_proxies"]]
    context["original_names"] = {}
    provider_nodes, context["provider_members"] = load_providers(
        config.proxy_providers, config.exit_providers, original_names=context["original_names"], tunnel=tunnel,
    )
    context["provider_nodes"] = provider_nodes
    pools = [pool["name"] for pool in config.pools.values()]
    relay_pools = [pool["name"] for pool in config.pools.values() if pool["relay"]]
    if config.exit_providers:
        provider_nodes, context["proxy_groups"] = relay_groups(
            provider_nodes, context["provider_members"], config.exit_providers, pools, relay_pools,
        )
    nodes_by_name = {node["name"]: node for node in context["upstream_proxies"]}
    for node in provider_nodes:
        if node["name"] in nodes_by_name and nodes_by_name[node["name"]] != node:
            raise ValueError("proxy-provider node conflicts with a top-level proxy")
        nodes_by_name.setdefault(node["name"], node)
    context["upstream_proxies"] = list(nodes_by_name.values())
    has_chain = any("dialer-proxy" in node for node in context["upstream_proxies"])
    qx_profile = next(p for p in context["profiles"] if p["id"] == "quantumult-x")
    if mihomo_only or has_chain or config.exit_providers:
        context["profiles"] = [p for p in context["profiles"] if p["id"] != "quantumult-x"]
    else:
        context["qx_upstream"] = quantumult_x_nodes(context["upstream_proxies"])
    rendered = renderer.render(context)
    renderer.validate(rendered, context)
    if config.exit_providers and not mihomo_only:
        from subscriptions.quantumult_x import UnsupportedRelay, compile_relay

        try:
            qx_rendered, context["qx_relay"] = compile_relay(
                context, config.exit_providers, pools, qx_profile, renderer, relay_pools,
            )
        except UnsupportedRelay as error:
            context["qx_error"] = str(error)
        else:
            rendered.append(qx_rendered)
    return rendered, context
