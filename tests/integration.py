from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "test"
PROJECT = f"reef-test-{os.getpid()}"
IMAGE = f"reef-test-node:{os.getpid()}"


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, env=env, check=True)


def run_output(cmd: list[str], *, env: dict[str, str] | None = None) -> str:
    print("+", " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(result.stdout, end="")
    result.check_returncode()
    return result.stdout


def run_expect_failure(
    cmd: list[str],
    *,
    env: dict[str, str],
    expected: str,
) -> None:
    print("+", " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(result.stdout, end="")
    if result.returncode == 0:
        raise RuntimeError("command should have failed")
    if expected not in result.stdout:
        raise RuntimeError(f"expected failure output to contain {expected!r}")


def wait_tcp(port: int, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(1)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.5)
    raise RuntimeError(f"127.0.0.1:{port} did not open")


def write_context() -> tuple[Path, str]:
    ctx = BUILD / "docker-context"
    if ctx.exists():
        shutil.rmtree(ctx)
    ctx.mkdir(parents=True)
    key = BUILD / "id_ed25519"
    if not key.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    shutil.copy(ROOT / "tests" / "Dockerfile.node", ctx / "Dockerfile")
    shutil.copy(ROOT / "tests" / "fixtures" / "echo_ip.py", ctx / "echo_ip.py")
    shutil.copy(key.with_suffix(".pub"), ctx / "id_ed25519.pub")
    return ctx, key.read_text()


def write_config(
    private_key: str,
    *,
    name: str = "config.yaml",
    include_uk: bool = True,
) -> tuple[Path, Path, Path]:
    config_path = BUILD / name
    exits = [{"name": "us", "ip": "172.28.0.20"}]
    if include_uk:
        exits.append({"name": "uk", "ip": "172.28.0.21"})
    document = {
        "secret": "11" * 32,
        "ssh_private_key": private_key,
        "cluster": {
            "entry_port_base": 20000,
            "exit_port": 443,
            "entry_override_base_domain": "example.test",
            "entries": [{"name": "sg", "ip": "172.28.0.10"}, {"name": "jp", "ip": "172.28.0.11"}],
            "exits": exits,
        },
    }
    config_path.touch(mode=0o600, exist_ok=True)
    config_path.write_text(yaml.safe_dump(document))
    ssh_map = BUILD / "ssh-map.json"
    ssh_map.write_text(
        json.dumps(
            {
                "sg": {"host": "127.0.0.1", "port": 2210},
                "jp": {"host": "127.0.0.1", "port": 2211},
                "us": {"host": "172.28.0.20", "port": 22},
                "uk": {"host": "172.28.0.21", "port": 22},
            },
            indent=2,
        )
    )
    host_map = BUILD / "host-map.json"
    host_map.write_text(
        json.dumps(
            {
                "sg-us": {"host": "127.0.0.1", "port": 12000},
                "sg-uk": {"host": "127.0.0.1", "port": 12001},
                "jp-us": {"host": "127.0.0.1", "port": 12100},
                "jp-uk": {"host": "127.0.0.1", "port": 12101},
                "us-direct": {"host": "127.0.0.1", "port": 12443},
                "uk-direct": {"host": "127.0.0.1", "port": 12444},
            },
            indent=2,
        )
    )
    return config_path, ssh_map, host_map


def recipe_env(config_path: Path, ssh_map: Path, host_map: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not (key.startswith("REEF_") or key.startswith("TEST_") or key == "CI")
    }
    env.update(
        {
            "TEST_CONFIG_FILE": str(config_path),
            "REEF_TEST_MODE": "1",
            "TEST_SSH_MAP": str(ssh_map),
            "TEST_HOST_MAP": str(host_map),
            "TEST_SMOKE_URL": "http://172.28.0.30:8080/ip",
            "TEST_ENTRY_OVERRIDE_ECHO_PORT": "18080",
            "TEST_DISABLE_SSH_HOST_KEY_CHECK": "1",
            "CI": "1",
        }
    )
    return env


def write_no_entry_override_config() -> Path:
    config_path = BUILD / "config.no-entry-override.yaml"
    config_path.touch(mode=0o600, exist_ok=True)
    config_path.write_text(yaml.safe_dump({
        "secret": "11" * 32,
        "cluster": {
            "entry_override_base_domain": "example.test",
            "exits": [{"name": "us", "ip": "172.28.0.20"}],
        },
    }))
    return config_path


def start_entry_override_echo(env: dict[str, str]) -> None:
    script = r"""set -eu
cat > /tmp/reef_entry_override_echo.py <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

entry_id = sys.argv[1]
port = int(sys.argv[2])


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"{entry_id}\n".encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class Server(ThreadingHTTPServer):
    allow_reuse_address = True


Server(("127.0.0.1", port), Handler).serve_forever()
PY
if [ -f /tmp/reef_entry_override_echo.pid ]; then
  kill "$(cat /tmp/reef_entry_override_echo.pid)" 2>/dev/null || true
fi
nohup python3 /tmp/reef_entry_override_echo.py __ENTRY_ID__ 18080 >/tmp/reef_entry_override_echo.log 2>&1 &
echo "$!" >/tmp/reef_entry_override_echo.pid
"""
    ansible = ROOT / ".venv" / "bin" / "ansible"
    inventory = ROOT / "build" / "ansible" / "inventory.yml"
    for entry_id in ["sg", "jp"]:
        run(
            [
                str(ansible),
                entry_id,
                "-i",
                str(inventory),
                "-m",
                "shell",
                "-a",
                script.replace("__ENTRY_ID__", entry_id),
            ],
            env=env,
        )


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    BUILD.chmod(0o700)
    ctx, private_key = write_context()
    config_path, ssh_map, host_map = write_config(private_key)
    reduced_config_path, _, _ = write_config(private_key, name="config.reduced.yaml", include_uk=False)
    no_entry_config_path = write_no_entry_override_config()
    no_entry_env = recipe_env(no_entry_config_path, ssh_map, host_map)
    run_expect_failure(
        [
            str(ROOT / ".venv" / "bin" / "python"),
            "-m",
            "reef.cli.render",
            "subscriptions",
        ],
        env=no_entry_env,
        expected="generation failed (details hidden in CI)",
    )
    run(
        [
            "docker",
            "buildx",
            "build",
            "--load",
            "-f",
            str(ctx / "Dockerfile"),
            "-t",
            IMAGE,
            str(ctx),
        ]
    )

    compose_env = os.environ.copy()
    compose_env["REEF_TEST_NODE_IMAGE"] = IMAGE
    run(
        ["docker", "compose", "-p", PROJECT, "-f", "tests/compose.yml", "up", "-d"],
        env=compose_env,
    )
    full_recipe_env = recipe_env(config_path, ssh_map, host_map)
    reduced_recipe_env = recipe_env(reduced_config_path, ssh_map, host_map)
    try:
        for port in [2210, 2211, 2220, 2221]:
            wait_tcp(port)
        run(["just", "doctor"], env=full_recipe_env)
        run(["just", "plan"], env=full_recipe_env)
        run(["just", "apply"], env=full_recipe_env)
        noop_apply = run_output(["just", "apply"], env=full_recipe_env)
        if re.search(r"changed=[1-9]", noop_apply):
            raise RuntimeError("second apply should not change any node")
        run(["just", "urls"], env=full_recipe_env)
        run(
            [
                str(ROOT / ".venv" / "bin" / "python"),
                "-m",
                "reef.cli.validate_subscriptions",
            ],
            env=full_recipe_env,
        )
        start_entry_override_echo(full_recipe_env)
        run(["just", "smoke"], env=full_recipe_env)
        run(["just", "web-build"], env=full_recipe_env)
        reduced_apply = run_output(["just", "apply"], env=reduced_recipe_env)
        if (
            "bin/hysteria-linux-amd64" in reduced_apply
            or "bin/sing-box-linux-amd64" in reduced_apply
        ):
            raise RuntimeError("reduced apply should not upload unchanged runtime binaries")
        run(
            [
                str(ROOT / ".venv" / "bin" / "ansible"),
                "sg:jp",
                "-i",
                str(ROOT / "build" / "ansible" / "inventory.yml"),
                "-m",
                "shell",
                "-a",
                "test ! -e /opt/reef/config/server-uk.yaml && "
                "test ! -e /opt/reef/config/client-uk.yaml && "
                "test ! -e /opt/reef/config/trojan-uk.json && "
                "test ! -e /opt/reef/certs/exit-uk.crt && "
                "! systemctl is-active --quiet reef-gateway-server@uk.service && "
                "! systemctl is-active --quiet reef-gateway-client@uk.service && "
                "! systemctl is-active --quiet reef-trojan@uk.service",
            ],
            env=reduced_recipe_env,
        )
        run(["just", "smoke"], env=reduced_recipe_env)
        run(["just", "delete"], env=full_recipe_env)
    finally:
        run(
            ["docker", "compose", "-p", PROJECT, "-f", "tests/compose.yml", "down", "-v"],
            env=compose_env,
        )
        subprocess.run(["docker", "rmi", "-f", IMAGE], cwd=ROOT, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
