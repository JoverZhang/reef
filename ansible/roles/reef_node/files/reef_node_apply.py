#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


SERVICE_RE = re.compile(r"^reef-[A-Za-z0-9_.@-]+\.service$")


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1] not in {"check", "apply"}:
        return fail("usage: reef_node_apply.py check <desired-b64> | apply <desired-b64> <stage-dir>")

    desired = json.loads(base64.b64decode(sys.argv[2]).decode())
    if sys.argv[1] == "check":
        return check(desired)
    if len(sys.argv) != 4:
        return fail("usage: reef_node_apply.py apply <desired-b64> <stage-dir>")
    return apply(desired, Path(sys.argv[3]))


def check(desired: dict[str, Any]) -> int:
    old_marker = read_old_marker(desired)
    if old_marker is None:
        return 1
    validate_desired(desired, old_marker)
    return emit(build_plan(desired, old_marker))


def apply(desired: dict[str, Any], stage_dir: Path) -> int:
    old_marker = read_old_marker(desired)
    if old_marker is None:
        return 1
    validate_desired(desired, old_marker)
    plan = build_plan(desired, old_marker)
    if not plan["changed"]:
        cleanup_stage(stage_dir)
        return emit(plan)

    remote_dir = desired["remoteDir"]
    marker = desired["marker"]
    items_by_id = {item["id"]: item for item in desired["items"]}
    changed = False
    reasons: list[str] = []

    for service in plan["stale_services"]:
        run(["systemctl", "disable", "--now", service], check=False)
        changed = True
        reasons.append(f"removed service {service}")

    for path in plan["stale_files"]:
        remove_path(path)
        changed = True
        reasons.append(f"removed file {path}")

    for path in plan["stale_runtimes"]:
        remove_path(path)
        changed = True
        reasons.append(f"removed runtime {path}")

    for path in [
        remote_dir,
        f"{remote_dir}/bin",
        f"{remote_dir}/certs",
        f"{remote_dir}/config",
    ]:
        Path(path).mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o755)

    for item_id in plan["uploads"]:
        item = items_by_id[item_id]
        staged = stage_dir / item_id
        if not staged.exists():
            raise RuntimeError(f"missing staged item {item_id}")
        if sha256(staged) != item["sha256"]:
            raise RuntimeError(f"staged item checksum mismatch: {item['dest']}")
        if install_staged_item(staged, item):
            changed = True
            reasons.append(f"installed {item['dest']}")

    if plan["unit_changed"]:
        run(["systemctl", "daemon-reload"])
        changed = True
        reasons.append("reloaded systemd")

    for service in marker["services"]:
        if enable_service(service):
            changed = True
            reasons.append(f"enabled service {service}")

    restart_services = set(plan["restart_services"])
    for service in marker["services"]:
        if service in restart_services:
            run(["systemctl", "restart", service])
            changed = True
            reasons.append(f"restarted service {service}")
        elif not service_active(service):
            run(["systemctl", "start", service])
            changed = True
            reasons.append(f"started service {service}")

    cleanup_stage(stage_dir)
    plan.update({"changed": changed, "up_to_date": not changed, "reasons": reasons})
    return emit(plan)


def build_plan(desired: dict[str, Any], old_marker: dict[str, Any]) -> dict[str, Any]:
    marker = desired["marker"]
    desired_services = set(marker["services"])
    desired_files = set(marker["files"])
    desired_runtimes = {item["dest"] for item in marker["runtimes"]}

    stale_services = [
        service for service in old_marker.get("services", []) if service not in desired_services
    ]
    stale_files = [path for path in old_marker.get("files", []) if path not in desired_files]
    stale_runtimes = [
        path for path in old_runtime_paths(old_marker) if path not in desired_runtimes
    ]

    uploads = []
    restart_services: set[str] = set()
    unit_changed = any(is_unit_path(path) for path in stale_files)
    reasons = []
    for item in desired["items"]:
        if file_matches(item):
            continue
        uploads.append(item["id"])
        reasons.append(f"drift: {item['dest']}")
        restart_services.update(item.get("services", []))
        if item.get("systemd"):
            unit_changed = True

    service_drift = []
    for service in marker["services"]:
        if not service_enabled(service):
            service_drift.append(f"service disabled: {service}")
        if not service_active(service):
            service_drift.append(f"service inactive: {service}")

    changed = bool(
        uploads
        or stale_services
        or stale_files
        or stale_runtimes
        or service_drift
    )
    return {
        "changed": changed,
        "up_to_date": not changed,
        "uploads": uploads,
        "restart_services": sorted(restart_services),
        "unit_changed": unit_changed,
        "stale_services": stale_services,
        "stale_files": stale_files,
        "stale_runtimes": stale_runtimes,
        "reasons": reasons + service_drift,
    }


def read_old_marker(desired: dict[str, Any]) -> dict[str, Any] | None:
    marker_path = Path(desired["remoteDir"]) / ".managed.json"
    if not marker_path.exists():
        return {}
    try:
        marker = json.loads(marker_path.read_text())
    except Exception as exc:
        fail(f"invalid Reef marker: {exc}")
        return None
    desired_marker = desired["marker"]
    if (
        marker.get("managedBy") != "reef"
        or marker.get("nodeId") != desired_marker["nodeId"]
    ):
        fail("refusing to manage non-matching Reef marker")
        return None
    return marker


def validate_desired(desired: dict[str, Any], old_marker: dict[str, Any]) -> None:
    remote_dir = desired["remoteDir"]
    for service in list(old_marker.get("services", [])) + desired["marker"]["services"]:
        if not SERVICE_RE.fullmatch(service):
            raise RuntimeError(f"refusing unsafe Reef service name {service}")
    for item in desired["items"]:
        if not is_safe_item_path(item["dest"], remote_dir):
            raise RuntimeError(f"refusing unsafe Reef path {item['dest']}")
    for path in old_marker.get("files", []):
        if not is_safe_file_path(path, remote_dir):
            raise RuntimeError(f"refusing unsafe Reef managed file path {path}")
    for path in old_runtime_paths(old_marker):
        if not is_under(path, remote_dir):
            raise RuntimeError(f"refusing unsafe Reef runtime path {path}")


def install_staged_item(staged: Path, item: dict[str, Any]) -> bool:
    if file_matches(item):
        return False
    dest = Path(item["dest"])
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() or dest.is_symlink():
        if dest.is_dir() and not dest.is_symlink():
            shutil.rmtree(dest)
        else:
            dest.unlink()
    tmp = dest.with_name(f".{dest.name}.reef-tmp-{os.getpid()}")
    shutil.copyfile(staged, tmp)
    os.chmod(tmp, int(str(item["mode"]), 8))
    os.replace(tmp, dest)
    return True


def file_matches(item: dict[str, Any]) -> bool:
    path = Path(item["dest"])
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    if stat.S_IMODE(st.st_mode) != int(str(item["mode"]), 8):
        return False
    return sha256(path) == item["sha256"]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def old_runtime_paths(old_marker: dict[str, Any]) -> list[str]:
    paths = [item["dest"] for item in old_marker.get("runtimes", [])]
    runtime = old_marker.get("runtime")
    if isinstance(runtime, dict) and runtime.get("dest"):
        paths.append(runtime["dest"])
    return sorted(set(paths))


def remove_path(path: str) -> None:
    target = Path(path)
    try:
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
    except FileNotFoundError:
        pass


def enable_service(service: str) -> bool:
    if not service_enabled(service):
        run(["systemctl", "enable", service])
        return True
    return False


def service_enabled(service: str) -> bool:
    return run(["systemctl", "is-enabled", "--quiet", service], check=False).returncode == 0


def service_active(service: str) -> bool:
    return run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{' '.join(cmd)} failed with exit {result.returncode}: {result.stderr.strip()}"
        )
    return result


def cleanup_stage(stage_dir: Path) -> None:
    if stage_dir.exists():
        shutil.rmtree(stage_dir)


def is_safe_item_path(path: str, remote_dir: str) -> bool:
    return is_safe_file_path(path, remote_dir) or is_under(path, remote_dir)


def is_safe_file_path(path: str, remote_dir: str) -> bool:
    return is_under(path, remote_dir) or is_unit_path(path)


def is_unit_path(path: str) -> bool:
    return re.fullmatch(r"/etc/systemd/system/reef-[A-Za-z0-9_.@-]+\.service", path) is not None


def is_under(path: str, root: str) -> bool:
    path_real = os.path.realpath(path)
    root_real = os.path.realpath(root)
    return path_real == root_real or path_real.startswith(root_real + os.sep)


def emit(data: dict[str, Any]) -> int:
    print(json.dumps(data, sort_keys=True))
    return 0


def fail(message: str) -> int:
    print(json.dumps({"failed": True, "msg": message}, sort_keys=True))
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        raise SystemExit(fail(str(exc)))
