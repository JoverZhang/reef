set dotenv-load := false

python := ".venv/bin/python"
ansible := ".venv/bin/ansible"
ansible_playbook := ".venv/bin/ansible-playbook"

setup:
    test -x .venv/bin/python || uv venv --python 3.10 .venv
    uv pip install --python .venv/bin/python -r requirements.txt

gen-secret: setup
    {{python}} -m reef.cli.gen_secret

set-ssh-key path: setup
    {{python}} -m reef.cli.set_ssh_key "{{path}}"

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
    {{python}} -m reef.cli.smoke

delete: setup
    {{python}} -m reef.cli.render ansible
    {{python}} -m reef.cli.confirm_delete
    {{ansible_playbook}} -i build/ansible/inventory.yml ansible/delete.yml --diff

config-yaml: setup
    {{python}} -m reef.cli.config_yaml

web-deploy gh-command="gh": setup
    #!/usr/bin/env -S zsh -il
    set -euo pipefail
    reef_repo=JoverZhang/reef
    reef_config_yaml="$({{python}} -m reef.cli.config_yaml)"
    if [[ "$(git branch --show-current)" != master ]] || ! git diff --quiet || ! git diff --cached --quiet; then
        print -u2 'web-deploy requires master with no uncommitted tracked changes'
        exit 1
    fi
    reef_git_helper={{quote("!zsh -lic " + quote(gh-command + ' auth git-credential "$@"') + " --")}}
    git -c credential.helper= -c credential.helper="$reef_git_helper" fetch "https://github.com/$reef_repo.git" master
    if [[ "$(git rev-parse HEAD)" != "$(git rev-parse FETCH_HEAD)" ]]; then
        print -u2 'web-deploy requires local master to match the remote master commit'
        exit 1
    fi
    printf '%s\n' "$reef_config_yaml" | {{gh-command}} secret set CONFIG_YAML --repo "$reef_repo"
    reef_version="$(date -u +%Y%m%d%H%M%S)"
    printf '%s\n' "$reef_version" > VERSION
    git commit --only -m "chore: publish website $reef_version" -- VERSION
    git -c credential.helper= -c credential.helper="$reef_git_helper" push "https://github.com/$reef_repo.git" HEAD:refs/heads/master

web-build: setup
    cd web && pnpm install --frozen-lockfile
    cd web && pnpm build

web-dev: setup
    {{python}} -m reef.cli.render web
    cd web && pnpm install --frozen-lockfile
    cd web && pnpm dev

test: setup vendor
    cd web && pnpm install --frozen-lockfile
    {{python}} -m unittest discover -s tests
    {{python}} tests/integration.py
