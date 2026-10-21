from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from subscriptions.upstream import validate_nodes


def parse_extend_nodes(nodes: Any) -> list[dict[str, Any]]:
    """Normalize Reef's VLESS input for Mihomo and the shared QX converter."""
    if not isinstance(nodes, list):
        raise ValueError("subscriptions.nodes must be a list")
    proxies = [_vless(node, index) for index, node in enumerate(nodes, start=1)]
    if proxies:
        validate_nodes(proxies, "subscription extension", set())
    return proxies


def _mapping(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - fields:
        raise ValueError(f"{label} must be a mapping containing only documented fields")
    return value


def _text(value: Any, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not empty) or value != value.strip() or any(
        ord(c) < 32 or c in "\x7f\x85\u2028\u2029" for c in value
    ):
        raise ValueError(f"{label} must be a valid string")
    return value


def _vless(value: Any, index: int) -> dict[str, Any]:
    label = f"subscription extension node {index}"
    node = _mapping(value, {
        "name", "protocol", "server", "port", "uuid", "transport", "tls",
        "flow", "udp", "packet_encoding", "encryption",
    }, label)
    if node.get("protocol") != "vless":
        raise ValueError(f"{label} protocol must be vless")
    proxy = {
        "type": "vless",
        **{key: _text(node.get(key), f"{label} {key}") for key in ("name", "server", "uuid")},
        "port": node.get("port"),
        "udp": node.get("udp", True),
        "tls": "tls" in node,
    }
    try:
        UUID(proxy["uuid"])
    except ValueError:
        raise ValueError(f"{label} uuid must be a valid UUID") from None
    if any(c.isspace() for c in proxy["server"]):
        raise ValueError(f"{label} server must not contain whitespace")
    if not isinstance(proxy["udp"], bool):
        raise ValueError(f"{label} udp must be a boolean")

    transport = _mapping(node.get("transport", {}), {
        "type", "path", "host", "service_name",
    }, f"{label} transport")
    network = transport.get("type", "tcp")
    if network not in ("tcp", "ws", "grpc"):
        raise ValueError(f"{label} transport.type must be tcp, ws, or grpc")
    options = {"tcp": set(), "ws": {"path", "host"}, "grpc": {"service_name"}}[network]
    _mapping(transport, {"type"} | options, f"{label} transport")
    proxy["network"] = network
    if network == "ws":
        proxy["ws-opts"] = {"path": _text(transport.get("path", "/"), f"{label} transport.path")}
        if "host" in transport:
            proxy["ws-opts"]["headers"] = {
                "Host": _text(transport["host"], f"{label} transport.host"),
            }
    elif network == "grpc":
        proxy["grpc-opts"] = {
            "grpc-service-name": _text(
                transport.get("service_name", ""), f"{label} transport.service_name", empty=True,
            ),
        }

    if "flow" in node:
        if node["flow"] != "xtls-rprx-vision" or network != "tcp" or not proxy["tls"]:
            raise ValueError(f"{label} flow requires xtls-rprx-vision with TCP and TLS")
        proxy["flow"] = node["flow"]
    if "packet_encoding" in node:
        if node["packet_encoding"] not in ("xudp", "packetaddr"):
            raise ValueError(f"{label} packet_encoding must be xudp or packetaddr")
        proxy["packet-encoding"] = node["packet_encoding"]
    if "encryption" in node:
        encryption = _text(node["encryption"], f"{label} encryption", empty=True)
        if encryption not in ("", "none"):
            proxy["encryption"] = encryption

    if "tls" in node:
        tls = _mapping(node["tls"], {
            "sni", "verify", "client_fingerprint", "alpn", "reality",
        }, f"{label} tls")
        verify = tls.get("verify", True)
        if not isinstance(verify, bool):
            raise ValueError(f"{label} tls.verify must be a boolean")
        proxy["skip-cert-verify"] = not verify
        proxy["servername"] = _text(tls.get("sni", proxy["server"]), f"{label} tls.sni")
        if "client_fingerprint" in tls:
            proxy["client-fingerprint"] = _text(
                tls["client_fingerprint"], f"{label} tls.client_fingerprint",
            )
        if "alpn" in tls:
            alpn = tls["alpn"]
            if not isinstance(alpn, list) or not alpn or any(
                not isinstance(item, str) or not 1 <= len(item.encode()) <= 255 for item in alpn
            ):
                raise ValueError(f"{label} tls.alpn must be a nonempty list of protocol strings")
            if "reality" in tls or (network == "ws" and alpn != ["http/1.1"]) or (
                network == "grpc" and alpn != ["h2"]
            ):
                raise ValueError(f"{label} tls.alpn cannot be preserved with these transport or Reality settings")
            proxy["alpn"] = alpn
        if "reality" in tls:
            if network == "ws":
                raise ValueError(f"{label} Reality requires TCP or gRPC in the common format")
            reality = _mapping(tls["reality"], {"public_key", "short_id"}, f"{label} tls.reality")
            public_key = _text(reality.get("public_key"), f"{label} tls.reality.public_key")
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
                raise ValueError(f"{label} tls.reality.public_key must be a base64url X25519 key")
            proxy["reality-opts"] = {"public-key": public_key}
            proxy.setdefault("client-fingerprint", "chrome")
            if "short_id" in reality:
                short_id = _text(reality["short_id"], f"{label} tls.reality.short_id", empty=True)
                if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id):
                    raise ValueError(f"{label} tls.reality.short_id must be an even-length hex string up to 16 digits")
                proxy["reality-opts"]["short-id"] = short_id
    if network == "ws":
        proxy["ws-opts"].setdefault("headers", {"Host": proxy.get("servername", proxy["server"])})
    return proxy
