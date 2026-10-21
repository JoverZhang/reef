from __future__ import annotations

import re
from http.client import HTTPException
from typing import Any
from urllib.request import Request, urlopen

import yaml

from subscriptions.substore import convert


def load_nodes(
    urls: list[str], extend_proxies: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    nodes = []
    names = set()
    for source_index, url in enumerate(urls, start=1):
        source = f"upstream URL #{source_index}"
        fetched = fetch_nodes(url, source)
        validate_nodes(fetched, source, names)
        nodes.extend(fetched)
    if extend_proxies:
        validate_nodes(extend_proxies, "subscription extension", names, allow_dialer=True)
        nodes.extend(extend_proxies)
    return nodes


def fetch_nodes(url: str, source: str) -> list[dict[str, Any]]:
    try:
        request = Request(url, headers={"User-Agent": "clash.meta", "Accept": "text/yaml"})
        with urlopen(request, timeout=30) as response:
            body = response.read()
    except (OSError, ValueError, HTTPException):
        # Network errors can include the private subscription URL.
        raise ValueError(f"{source} fetch failed") from None
    return _parse_nodes(body, source, set())


def _parse_nodes(body: str | bytes, source: str, names: set[str]) -> list[dict[str, Any]]:
    try:
        document = yaml.safe_load(body)
    except (yaml.YAMLError, UnicodeError):
        # YAML parser errors can include lines containing credentials.
        raise ValueError(f"{source} must be valid YAML") from None
    proxies = document.get("proxies") if isinstance(document, dict) else None
    if not isinstance(proxies, list):
        raise ValueError(f"{source} must contain a proxies list")
    if not proxies:
        raise ValueError(f"{source} returned an empty proxies list")
    validate_nodes(proxies, source, names)
    return proxies


def validate_nodes(
    proxies: list[dict[str, Any]], source: str, names: set[str], *, allow_dialer: bool = False,
) -> None:
    for index, proxy in enumerate(proxies, start=1):
        label = f"{source} node {index}"
        if not isinstance(proxy, dict):
            raise ValueError(f"{label} must be a mapping")
        for key in ("name", "type", "server"):
            value = proxy.get(key)
            if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
                raise ValueError(f"{label} must have a valid {key}")
        port = proxy.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(f"{label} must have a valid port")
        if proxy["name"] in names:
            raise ValueError(f"{label} has a duplicate name")
        names.add(proxy["name"])
        if "dialer-proxy" in proxy:
            if not allow_dialer:
                raise ValueError(f"{label} cannot depend on an upstream proxy or policy")
            dialer = proxy["dialer-proxy"]
            if not isinstance(dialer, str) or not dialer.strip() or any(ord(c) < 32 for c in dialer):
                raise ValueError(f"{label} must have a valid dialer-proxy name")


def quantumult_x_nodes(proxies: list[dict[str, Any]]) -> list[dict[str, str]]:
    if any("dialer-proxy" in proxy for proxy in proxies):
        raise ValueError(
            "Quantumult X relay conversion is not supported; use a Mihomo subscription"
        )
    compatible = [
        proxy for index, proxy in enumerate(proxies, start=1)
        if qx_supported(proxy, index)
    ]
    if not compatible:
        return []
    lines = convert(compatible)
    # Sub-Store can silently omit a node on a producer error. Never publish a
    # partial conversion of nodes we promised to support.
    names = [
        part.removeprefix("tag=")
        for line in lines for part in line.split(", ") if part.startswith("tag=")
    ]
    if len(lines) != len(compatible) or names != [proxy["name"] for proxy in compatible]:
        raise ValueError("Sub-Store conversion dropped or renamed supported nodes")
    return [{"name": name, "line": line} for name, line in zip(names, lines, strict=True)]


def qx_supported(proxy: dict[str, Any], index: int = 1) -> bool:
    kind = proxy["type"]
    if kind not in {"http", "socks5", "anytls", "vless", "trojan"}:
        return False
    network = proxy.get("network", "tcp")
    if network != "tcp" and not (kind == "vless" and network == "ws"):
        return False
    # Fail closed on options outside the verified conversion contract; the
    # original node remains intact in both Mihomo profiles.
    supported = {
        "name", "type", "server", "port", "network", "tls", "sni", "servername",
        "skip-cert-verify", "client-fingerprint", "fingerprint", "alpn", "udp", "tfo",
        "reality-opts",
    }
    supported.update(
        {"uuid", "flow", "encryption"} if kind == "vless" else {"username", "password"}
    )
    ws_values = []
    if network == "ws":
        supported.add("ws-opts")
        ws = proxy.get("ws-opts", {})
        if not isinstance(ws, dict) or set(ws) - {"path", "headers"}:
            return False
        headers = ws.get("headers", {})
        if not isinstance(headers, dict) or set(headers) != {"Host"} or not headers["Host"]:
            return False
        ws_values = list(headers.values()) + ([ws["path"]] if "path" in ws else [])
        if any(not isinstance(value, str) for value in ws_values):
            return False
        sni = proxy.get("servername") or proxy.get("sni") or headers["Host"]
        if proxy.get("tls") and headers["Host"] != sni:
            # QX's obfs-host is both TLS SNI and WebSocket Host.
            return False
    if (
        set(proxy) - supported
        or proxy.get("flow", "") not in ("", "xtls-rprx-vision")
        or (proxy.get("flow") and (network != "tcp" or not proxy.get("tls")))
        or proxy.get("encryption", "none") not in ("", "none")
    ):
        return False
    reality = proxy.get("reality-opts", {})
    if not isinstance(reality, dict) or set(reality) - {"public-key", "short-id"}:
        return False
    if reality and (not proxy.get("tls") or not reality.get("public-key")):
        return False
    for key in ("tls", "skip-cert-verify", "udp", "tfo"):
        if key in proxy and not isinstance(proxy[key], bool):
            raise ValueError(f"upstream node {index} must have a boolean {key}")
    credential = "uuid" if kind == "vless" else "password"
    if kind in {"vless", "trojan", "anytls"} and not proxy.get(credential):
        raise ValueError(f"upstream node {index} is missing {credential}")
    if "fingerprint" in proxy:
        fingerprint = proxy["fingerprint"]
        if not isinstance(fingerprint, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", fingerprint.replace(":", "")
        ):
            raise ValueError(f"upstream node {index} has invalid fingerprint")
    if "alpn" in proxy:
        alpn = proxy["alpn"]
        if not isinstance(alpn, list) or any(
            not isinstance(item, str) or not 1 <= len(item.encode()) <= 255 for item in alpn
        ):
            raise ValueError(f"upstream node {index} has invalid alpn")
    # QX has no quoting/escaping for commas, line separators, or policy option
    # names. Check values before handing them to a third-party formatter.
    values = [
        proxy[key] for key in ("name", "server", "username", "password", "uuid", "sni", "servername")
        if key in proxy
    ] + ws_values
    for value in values:
        if not isinstance(value, (str, int)) or any(
            c == "," or ord(c) < 32 or c in "\x7f\x85\u2028\u2029" for c in str(value)
        ) or str(value) != str(value).strip():
            raise ValueError(f"upstream node {index} has an unrepresentable QX value")
    if "=" in proxy["name"] or any(c.isspace() for c in proxy["server"]):
        raise ValueError(f"upstream node {index} has an unrepresentable QX name or server")
    for value in reality.values():
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_+/=-]*", value):
            raise ValueError(f"upstream node {index} has an unrepresentable QX Reality value")
    return True
