from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

from reef.core import ROOT, _env_path, _require_test_mode, is_ci, load_model, render_subscriptions


API_SECRET = "reef-smoke"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_http(url: str, headers: dict[str, str], timeout: float = 15) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=1):
                return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for {url}")


def api_put(base: str, selector: str, name: str) -> None:
    body = json.dumps({"name": name}).encode()
    req = urllib.request.Request(
        f"{base}/proxies/{urllib.parse.quote(selector)}",
        data=body,
        method="PUT",
        headers={
            "Authorization": f"Bearer {API_SECRET}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        if response.status not in {200, 204}:
            raise RuntimeError(f"selector API returned {response.status}")


def curl_through(proxy_port: int, url: str) -> str:
    out = subprocess.run(
        [
            "curl",
            "-fsS",
            "--connect-timeout",
            "6",
            "--max-time",
            "15",
            "-x",
            f"http://127.0.0.1:{proxy_port}",
            url,
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if out.returncode != 0:
        raise RuntimeError(f"curl failed\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    return out.stdout.strip()


def main() -> int:
    model = load_model()
    profiles = render_subscriptions(model, _env_path("TEST_HOST_MAP"))
    client = next(p for p in profiles if p["id"] == "client")
    doc = yaml.safe_load(client["body"])

    mixed_port = free_port()
    api_port = free_port()
    doc["mixed-port"] = mixed_port
    doc["external-controller"] = f"127.0.0.1:{api_port}"
    doc["secret"] = API_SECRET
    doc.pop("rule-providers", None)
    doc["rules"] = ["MATCH,PROXY"]
    if isinstance(doc.get("dns"), dict):
        doc["dns"].pop("nameserver-policy", None)
    for group in doc.get("proxy-groups", []):
        if group.get("name") != "PROXY" and group.get("type") == "url-test":
            group["type"] = "select"

    smoke_dir = ROOT / "build" / "smoke"
    smoke_dir.mkdir(parents=True, exist_ok=True)
    smoke_dir.chmod(0o700)
    config_path = smoke_dir / "client.yaml"
    config_path.write_text(yaml.safe_dump(doc, sort_keys=False))
    config_path.chmod(0o600)
    smoke_config = model.provider.get("smoke", {})
    if not isinstance(smoke_config, dict) or not smoke_config.get("client_path"):
        raise SystemExit("provider.yaml must declare smoke.client_path")
    log_path = smoke_dir / smoke_config.get("log_name", "client.log")
    client_bin = ROOT / smoke_config["client_path"]
    if not client_bin.exists():
        raise SystemExit(f"missing {client_bin.relative_to(ROOT)}; run `just vendor`")

    with log_path.open("w") as log:
        proc = subprocess.Popen(
            [str(client_bin), "-f", str(config_path), "-d", str(smoke_dir)],
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    try:
        api_base = f"http://127.0.0.1:{api_port}"
        wait_http(f"{api_base}/proxies", {"Authorization": f"Bearer {API_SECRET}"})
        expected_by_name = {route.name: route.exit.ip for route in model.routes}
        exit_by_name = {route.name: route.exit.id for route in model.routes}
        smoke_url = os.environ.get("TEST_SMOKE_URL")
        if smoke_url:
            _require_test_mode("TEST_SMOKE_URL")
        else:
            smoke_url = model.config.smoke_url
        for proxy in doc["proxies"]:
            name = proxy["name"]
            expected = expected_by_name[name]
            exit_group = exit_by_name[name]
            print(f"smoke {name} -> expect {expected}")
            api_put(api_base, exit_group, name)
            time.sleep(0.2)
            api_put(api_base, "PROXY", exit_group)
            time.sleep(0.2)
            observed = curl_through(mixed_port, smoke_url)
            if observed != expected:
                raise RuntimeError(f"{name}: expected {expected}, got {observed!r}")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        if proc.returncode not in {0, -15, -9, None} and not is_ci():
            print(log_path.read_text()[-4000:], file=sys.stderr)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"smoke failed: {exc}", file=sys.stderr)
        log = ROOT / "build" / "smoke" / "client.log"
        if log.exists() and not is_ci():
            print("--- client log tail ---", file=sys.stderr)
            print(log.read_text()[-4000:], file=sys.stderr)
        raise SystemExit(1)
