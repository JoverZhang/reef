from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import PurePosixPath

from reef.core import REMOTE_DIR, ROOT, load_model, provider_runtimes, routes_for_node


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def require(name: str) -> None:
    if shutil.which(name) is None:
        raise SystemExit(f"missing required command: {name}")


def main() -> int:
    for name in ["ssh", "curl", "just"]:
        require(name)
    model = load_model(require_ssh=True)
    for runtime in provider_runtimes(model):
        runtime_path = ROOT / runtime["src"]
        if not runtime_path.exists():
            raise SystemExit(f"missing {runtime_path.relative_to(ROOT)}; run `just vendor`")

    inventory = ROOT / "build" / "ansible" / "inventory.yml"
    ansible = ROOT / ".venv" / "bin" / "ansible"
    remote_parent = str(PurePosixPath(REMOTE_DIR).parent)
    run([str(ansible), "all", "-i", str(inventory), "-m", "ping"])
    remote_check = (
        "test -d /run/systemd/system && "
        "systemctl --version >/dev/null && "
        f"test -d {remote_parent} && "
        "command -v ss >/dev/null"
    )
    run(
        [
            str(ansible),
            "all",
            "-i",
            str(inventory),
            "-m",
            "shell",
            "-a",
            remote_check,
        ]
    )
    for node in model.nodes:
        checks = sorted(_port_checks(model, node))
        if not checks:
            continue
        check_list = " ".join(f"{protocol}:{port}" for protocol, port in checks)
        script = f"""set -eu
for check in {check_list}; do
  proto="${{check%:*}}"
  port="${{check#*:}}"
  flags="t"
  if [ "$proto" = "udp" ]; then
    flags="u"
  fi
  rows="$(ss -H -ln$flags "sport = :$port" 2>/dev/null || true)"
  if [ -n "$rows" ]; then
    proc="$(ss -H -ln${{flags}}p "sport = :$port" 2>/dev/null || true)"
    if printf '%s\\n' "$proc" | grep -Eq 'transport|sing-box'; then
      reef_owned=""
      pids="$(printf '%s\\n' "$proc" | sed -nE 's/.*pid=([0-9]+).*/\\1/p')"
      for pid in $pids; do
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
        case "$exe" in
          {REMOTE_DIR}/bin/transport*|{REMOTE_DIR}/bin/sing-box*) reef_owned=1 ;;
        esac
      done
      if [ -n "$reef_owned" ]; then
        continue
      fi
    fi
    echo "$proto port $port is already in use"
    printf '%s\\n' "$rows"
    exit 1
  fi
done"""
        run([str(ansible), node.id, "-i", str(inventory), "-m", "shell", "-a", script])
    return 0


def _port_checks(model, node) -> set[tuple[str, int]]:
    checks: set[tuple[str, int]] = set()
    routes = routes_for_node(model, node)
    for provider in model.providers:
        service_templates = provider.get("services", {})
        if not isinstance(service_templates, dict):
            raise SystemExit(f"{provider['id']} provider.yaml services must be a mapping")
        protocols = provider.get("route_protocols", {})
        if not isinstance(protocols, dict):
            raise SystemExit(f"{provider['id']} provider.yaml route_protocols must be a mapping")
        for route in routes:
            if not service_templates.get(route.kind):
                continue
            if route.kind not in protocols:
                raise SystemExit(
                    f"{provider['id']} route_protocols.{route.kind} is required"
                )
            protocol = str(protocols[route.kind])
            if protocol not in {"tcp", "udp"}:
                raise SystemExit(
                    f"{provider['id']} route_protocols.{route.kind} must be tcp or udp"
                )
            checks.add((protocol, route.port))
    return checks


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"doctor failed: {exc}", file=sys.stderr)
        raise SystemExit(exc.returncode)
