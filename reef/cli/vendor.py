from __future__ import annotations

import gzip
import json
import shutil
import subprocess
import time
import urllib.request

from reef.core import ROOT, load_provider


def download(url: str, dest, *, executable: bool = True) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    print(f"download {url}")
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as response, tmp.open("wb") as f:
                shutil.copyfileobj(response, f)
            break
        except Exception:
            if tmp.exists():
                tmp.unlink()
            if attempt == 2:
                raise
            time.sleep(attempt + 1)
    tmp.replace(dest)
    if executable:
        dest.chmod(0o755)


def latest_asset(repo: str, predicate) -> str:
    with urllib.request.urlopen(f"https://api.github.com/repos/{repo}/releases/latest", timeout=30) as r:
        data = json.load(r)
    for asset in data["assets"]:
        name = asset["name"]
        if predicate(name):
            return asset["browser_download_url"]
    raise RuntimeError(f"no matching asset in {repo} latest release")


def main() -> int:
    provider = load_provider()
    assets = provider.get("vendor", {}).get("assets", [])
    if not isinstance(assets, list):
        raise SystemExit("provider.yaml vendor.assets must be a list")
    for asset in assets:
        install_asset(asset)
    return 0


def install_asset(asset: dict) -> None:
    dest = ROOT / asset["path"]
    if dest.exists():
        run_check(dest, asset)
        return
    url = asset_url(asset)
    if asset.get("gzip"):
        gz_path = dest.with_suffix(dest.suffix + ".gz")
        download(url, gz_path, executable=False)
        with gzip.open(gz_path, "rb") as src, dest.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        dest.chmod(0o755)
        gz_path.unlink()
    else:
        download(url, dest)
    run_check(dest, asset)


def run_check(dest, asset: dict) -> None:
    check_args = asset.get("check_args", [])
    if check_args:
        subprocess.run([str(dest), *[str(arg) for arg in check_args]], check=True)


def asset_url(asset: dict) -> str:
    if "url" in asset:
        return asset["url"]
    latest = asset["github_latest"]
    starts_with = latest.get("starts_with", "")
    ends_with = latest.get("ends_with", "")
    reject_contains = latest.get("reject_contains", [])
    return latest_asset(
        latest["repo"],
        lambda name: (
            (not starts_with or name.startswith(starts_with))
            and (not ends_with or name.endswith(ends_with))
            and not any(item in name for item in reject_contains)
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
