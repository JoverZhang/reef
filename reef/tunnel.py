"""Deployment inputs for the opaque HTTPS CONNECT service."""
from __future__ import annotations

import hashlib
import json

PORT = 24443


def validate_sources(urls, providers):
    from subscriptions.mihomo import provider_upstreams
    from subscriptions.tunnel import validate_url

    for url in [*urls, *(source["url"] for spec in providers.values()
                        for source in provider_upstreams(spec))]:
        validate_url(url)


def client_input(model) -> dict:
    from reef.core import derive_text

    node = next(node for node in model.nodes if node.id == model.config.fetch_tunnel)
    host = f"[{node.ip}]" if ":" in node.ip else node.ip
    return {
        "url": f"https://{host}:{PORT}",
        "ca": model.secrets[node.id].cert_pem,
        "token": derive_text(bytes.fromhex(model.config.secret_hex), "fetch-tunnel-auth", node.id),
    }


def render_service(model, node, add) -> None:
    from reef.core import REMOTE_DIR, project_path

    directory = f"{REMOTE_DIR}/fetch-tunnel"
    config = {
        "port": PORT,
        "auth_sha256": hashlib.sha256(("Bearer " + client_input(model)["token"]).encode()).hexdigest(),
        "cert": f"{REMOTE_DIR}/certs/server.crt",
        "key": f"{REMOTE_DIR}/certs/server.key",
    }
    add("fetch-tunnel/server.py", f"{directory}/server.py", project_path("reef/tunnel_server.py").read_text())
    add("fetch-tunnel/config.json", f"{directory}/config.json", json.dumps(config), "0600")
    add("fetch-tunnel/service", "/etc/systemd/system/reef-fetch-tunnel.service", f"""[Unit]
Description=Reef HTTPS byte tunnel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 -B {directory}/server.py {directory}/config.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitCORE=0
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
""")
