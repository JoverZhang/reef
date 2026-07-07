set dotenv-load := false

env_file := env_var_or_default("REEF_ENV_FILE", ".env")
python := ".venv/bin/python"
ansible := ".venv/bin/ansible"
ansible_playbook := ".venv/bin/ansible-playbook"

setup:
    test -x .venv/bin/python || uv venv --python 3.10 .venv
    uv pip install --python .venv/bin/python -r requirements.txt

gen-secret:
    python3 -m reef.cli.gen_secret --env "{{env_file}}"

set-ssh-key path:
    python3 -m reef.cli.set_ssh_key --env "{{env_file}}" "{{path}}"

vendor:
    python3 -m reef.cli.vendor

doctor: setup
    {{python}} -m reef.cli.render ansible
    {{python}} -m reef.cli.doctor

plan: setup
    {{python}} -m reef.cli.render ansible
    {{ansible_playbook}} -i build/ansible/inventory.yml ansible/apply.yml --check --diff

apply: setup
    {{python}} -m reef.cli.render ansible subscriptions web
    {{ansible_playbook}} -i build/ansible/inventory.yml ansible/apply.yml --diff

smoke: setup
    {{python}} -m reef.cli.render subscriptions
    {{python}} -m reef.cli.smoke

delete: setup
    {{python}} -m reef.cli.render ansible
    {{python}} -m reef.cli.confirm_delete
    {{ansible_playbook}} -i build/ansible/inventory.yml ansible/delete.yml --diff

urls: setup
    {{python}} -m reef.cli.render subscriptions web
    {{python}} -m reef.cli.urls

web-build: setup
    cd web && pnpm install --frozen-lockfile
    cd web && pnpm build

web-dev: setup
    {{python}} -m reef.cli.render web
    cd web && pnpm install --frozen-lockfile
    cd web && pnpm dev

test: setup vendor
    {{python}} tests/integration.py
