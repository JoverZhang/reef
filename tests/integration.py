from __future__ import annotations

import base64
import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path


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
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(result.stdout, end="")
    return result.stdout


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
    key_b64 = base64.b64encode(key.read_bytes()).decode()
    return ctx, key_b64


def write_env(
    key_b64: str,
    *,
    name: str = ".env",
    include_uk: bool = True,
) -> tuple[Path, Path, Path]:
    env_path = BUILD / name
    lines = [
        "REEF_SECRET=1111111111111111111111111111111111111111111111111111111111111111",
        f"REEF_SSH_PRIVATE_KEY_B64={key_b64}",
        "REEF_ENTRY_PORT_BASE=20000",
        "REEF_EXIT_PORT=443",
        "REEF_ENTRY_1=sg,172.28.0.10",
        "REEF_ENTRY_2=jp,172.28.0.11",
        "REEF_EXIT_1=us,172.28.0.20",
    ]
    if include_uk:
        lines.append("REEF_EXIT_2=uk,172.28.0.21")
    env_path.write_text(
        "\n".join(lines) + "\n"
    )
    env_path.chmod(0o600)
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
    return env_path, ssh_map, host_map


def recipe_env(env_path: Path, ssh_map: Path, host_map: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not (key.startswith("REEF_") or key.startswith("TEST_") or key == "CI")
    }
    env.update(
        {
            "REEF_ENV_FILE": str(env_path),
            "REEF_TEST_MODE": "1",
            "TEST_SSH_MAP": str(ssh_map),
            "TEST_HOST_MAP": str(host_map),
            "TEST_SMOKE_URL": "http://172.28.0.30:8080/ip",
            "TEST_DISABLE_SSH_HOST_KEY_CHECK": "1",
            "CI": "1",
        }
    )
    return env


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    BUILD.chmod(0o700)
    ctx, key_b64 = write_context()
    env_path, ssh_map, host_map = write_env(key_b64)
    reduced_env_path, _, _ = write_env(key_b64, name=".env.reduced", include_uk=False)
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
    full_recipe_env = recipe_env(env_path, ssh_map, host_map)
    reduced_recipe_env = recipe_env(reduced_env_path, ssh_map, host_map)
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
