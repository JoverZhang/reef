from __future__ import annotations

import yaml

from reef.core import is_ci


def main() -> int:
    if is_ci():
        return 0
    with open("build/ansible/inventory.yml") as f:
        inventory = yaml.safe_load(f)
    hosts = inventory["all"]["hosts"]
    print(f"Delete Reef deployment from {len(hosts)} nodes?")
    for name, data in hosts.items():
        print(f"- {name} {data['ansible_host']} {data['reef_node']['remote_dir']}")
    answer = input('Type "delete" to continue: ')
    if answer != "delete":
        raise SystemExit("delete cancelled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
