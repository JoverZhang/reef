"""End-to-end HTTPS downloads through an independently authenticated byte tunnel."""
from __future__ import annotations

import ssl
from urllib.parse import urljoin, urlsplit

import urllib3

MAX_BODY = 16 * 1024 * 1024


def validate_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        valid = parsed.scheme == "https" and parsed.hostname and parsed.port in (None, 443)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("fetch tunnel requires HTTPS subscription URLs on port 443") from None


def fetch(url: str, tunnel: dict) -> bytes:
    # Never add the tunnel CA to the target trust store. A hostile tunnel can
    # redirect TCP connections, but cannot authenticate as an upstream server.
    proxy_context = ssl.create_default_context(cadata=tunnel["ca"])
    manager = urllib3.ProxyManager(
        tunnel["url"], proxy_ssl_context=proxy_context,
        ssl_context=ssl.create_default_context(), use_forwarding_for_https=False,
        proxy_headers={"Proxy-Authorization": "Bearer " + tunnel["token"]},
        timeout=urllib3.Timeout(connect=15, read=30), retries=False,
    )
    try:
        for redirect in range(6):
            validate_url(url)
            response = manager.request("GET", url, redirect=False, preload_content=False,
                                       headers={"User-Agent": "clash.meta", "Accept": "text/yaml"})
            try:
                if response.status in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location or redirect == 5:
                        raise ValueError("invalid redirect")
                    url = urljoin(url, location)
                    continue
                if response.status != 200:
                    raise ValueError("unexpected status")
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise ValueError("response too large")
                return body
            finally:
                response.close()
    except (urllib3.exceptions.HTTPError, OSError, ValueError):
        raise OSError("tunnel fetch failed") from None
    finally:
        manager.clear()
    raise OSError("tunnel fetch failed")
