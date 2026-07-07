from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import PurePosixPath

from reef.core import REMOTE_DIR, ROOT, load_model, routes_for_node


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
    runtime = model.provider.get("runtime", {})
    if not isinstance(runtime, dict) or not runtime.get("local_path"):
        raise SystemExit("provider.yaml must declare runtime.local_path")
    runtime_path = ROOT / runtime["local_path"]
    if not runtime_path.exists():
        raise SystemExit(f"missing {runtime_path.relative_to(ROOT)}; run `just vendor`")

    inventory = ROOT / "build" / "ansible" / "inventory.yml"
    ansible = ROOT / ".venv" / "bin" / "ansible"
    remote_parent = str(PurePosixPath(REMOTE_DIR).parent)
    run([str(ansible), "all", "-i", str(inventory), "-m", "ping"])
    run(
        [
            str(ansible),
            "all",
            "-i",
            str(inventory),
            "-m",
            "shell",
            "-a",
            f"test -d /run/systemd/system && systemctl --version >/dev/null && test -d {remote_parent} && command -v ss >/dev/null",
        ]
    )
    for node in model.nodes:
        ports = sorted({route.port for route in routes_for_node(model, node)})
        if not ports:
            continue
        port_list = " ".join(str(port) for port in ports)
        script = f"""set -eu
for port in {port_list}; do
  rows="$(ss -H -lntu "sport = :$port" 2>/dev/null || true)"
  if [ -n "$rows" ]; then
    proc="$(ss -H -lntup "sport = :$port" 2>/dev/null || true)"
    if printf '%s\\n' "$proc" | grep -q 'transport'; then
      continue
    fi
    echo "port $port is already in use"
    printf '%s\\n' "$rows"
    exit 1
  fi
done"""
        run([str(ansible), node.id, "-i", str(inventory), "-m", "shell", "-a", script])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"doctor failed: {exc}", file=sys.stderr)
        raise SystemExit(exc.returncode)
