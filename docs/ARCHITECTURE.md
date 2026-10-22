# Architecture

## Product Shape

Reef is a small declarative cluster deployment system. The operator maintains a private `config.yaml` with one root seed; Reef derives the full cluster from those inputs, renders deployment artifacts, applies them to remote nodes, and generates subscription files.

The first-phase product shape:

- Use `just` as the only user entry point.
- Use Python for configuration parsing, secret derivation, and snapshot compilation.
- Use Ansible for remote deployment, upgrade, and deletion.
- Use Next.js on Vercel and shared Redis snapshots to serve authenticated previews, subscriptions, and rules.
- Use Docker-compatible Compose to run the local four-node integration test.

## Repository Layout

```text
.
├── AGENTS.md
├── justfile
├── config.example.yaml
├── config.mihomo.example.yaml
├── ansible/
│   ├── apply.yml
│   ├── delete.yml
│   └── roles/
│       └── reef_node/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CODING_RULES.md
│   └── DESIGN.md
├── providers/
│   └── <provider-id>/
│       ├── provider.yaml
│       └── node/
├── subscriptions/
│   ├── profiles.yaml
│   ├── extension.py
│   ├── mihomo.py
│   ├── quantumult_x.py
│   ├── render.py
│   ├── upstream.py
│   ├── substore.py
│   ├── substore.mjs
│   └── <profile-template>.j2
├── reef/
│   ├── core.py
│   └── cli/
├── tests/
│   ├── Dockerfile.node
│   ├── integration.py
│   ├── compose.yml
│   └── fixtures/
└── web/
    ├── app/
    │   ├── route.ts
    │   ├── dump/route.ts
    │   ├── refresh/route.ts
    │   └── rules/[profile]/[resource]/route.ts
    └── generated/
        ├── bootstrap.ts
        ├── input.json
        └── runtime/
```

`reef/` contains the core derived model and the thin command entry points used by `justfile`.

`providers/<provider-id>/` is the only place that maintains concrete node-side transport implementation details. Reef loads every provider bundle in deterministic directory-name order.

`subscriptions/` owns the generated subscription profile set and the rendering logic that translates the core route model plus loaded providers into subscription documents.
`reef/core.py` reads the root `config.yaml` and validates the shared local/CI
configuration schema. `subscriptions/mihomo.py` owns native proxy/provider/group
validation, fetching and filtering provider snapshots, resolving group references,
validating proxy/group relay dependencies, and converting supported selection
policies to Quantumult X. HTTP collections can combine named upstreams; shared
URLs use one fetch per generation and the names prefix the selected nodes.
Ordered `exits` and stable-ID `pools` generate all direct/relayed endpoint
copies and groups from provider display names. Every exit/pool path appears in
`PROXY`; single-endpoint paths use proxies and multi-endpoint paths use automatic
groups. `subscriptions/extension.py` owns legacy standalone VLESS normalization.
`subscriptions/upstream.py` owns fetching and QX compatibility; the pinned offline
Sub-Store adapter owns supported QX node conversion.
`subscriptions/quantumult_x.py` compiles automatic exits/pools into QX's separate
EXIT, RELAY, and POOL choices. It resolves QX endpoint addresses on refresh
while preserving TLS identity and rejects ambiguous address ownership.
`subscriptions/rules.py` fetches the templates' resources and applies QX policy
and TUN reinjection requirements. Native manual chains remain unsupported.

The Python compiler preserves original provider node names alongside display
names and validates the full path graph once per refresh. `subscriptions/compiler.py`
is shared by local rendering and the runtime worker in `subscriptions/runtime.py`.
It emits proxy/group data, fixed profile settings, preview metadata, the password
digest, and QX output or its incompatibility reason.
For automatic QX relays it stores converted node lines, socket-routing rules,
policies, and static sections; request-time filtering selects pool memberships
and serializes the same structure without invoking the converter again.
The root seed, SSH key, upstream URLs, and plaintext web password never enter the snapshot.
The static subscription templates remain the sole owners of DNS and traffic rules.

`reef/core.py:prepare_web` writes a server-only bootstrap and private compiler
input without fetching subscriptions or rules. `subscriptions/runtime_bundle.py`
bundles pinned Linux amd64 Python, dependencies, compiler sources, and Sub-Store
for the Node function. The input excludes the root seed, SSH key, and plaintext
web password. It retains source URLs and credentials needed by the compiler.

`web/lib/cache.ts` coordinates a compressed snapshot and owner-token refresh lock
in Upstash Redis. A deployment-specific namespace makes each deployment start
empty. `web/lib/runtime.ts` invokes the bundled compiler with private stdin and
suppressed stderr. Only a complete successful refresh replaces shared data.

`web/lib/subscription.ts` owns authentication, query parsing, pool filtering,
preview metadata selection, and dump serialization. `web/lib/service.ts` authenticates
before calling the snapshot loader and serves preview, dump, refresh, and rule routes;
there is no second browser-side filtering implementation. The homepage returns
server-rendered HTML only after authentication. `web/lib/preview.ts` renders only
safe metadata; small static assets handle form submission and copying the dump
link, forced refresh, and paginated rule searches. Authorized requests refresh
expired data on demand. HTTP responses are never publicly cached.
The old token route and `just urls` are removed. Internal file rendering remains
for smoke and integration checks. Unsupported QX topologies or filters that leave
no compatible members fail explicitly with HTTP 422 while preview stays available.
With subscription nodes or providers and no cluster nodes, the core model has no
routes or node secrets; the same subscription and Web rendering path works without deployment.
`config.yaml` is the only private configuration input and is ignored by git.
`config.example.yaml` documents its shape. The website workflow restores it from
`CONFIG_YAML`; `just config-yaml` exports that payload without the SSH private key.

## Generated Artifacts

These files are generated by tools and are not maintained by hand:

```text
build/
├── ansible/
│   └── inventory.yml
├── nodes/
├── ssh/
│   ├── known_hosts
│   └── reef_id
└── subscriptions/
    ├── client.yaml
    └── <profile-output>

web/generated/
├── bootstrap.ts
├── input.json
└── runtime/
```

`build/` and `web/generated/` do not go into git. They may contain remote connection information and subscription content.

## Managed Node Layout

Reef manages only a fixed remote directory and the service files it installs:

```text
/opt/reef/
├── bin/
├── certs/
├── config/
└── .managed.json
```

`/opt/reef/.managed.json` is a non-secret marker. It records only ownership, version, node identity, managed file lists, and render hashes. It must not contain the root seed, node passwords, subscription tokens, or private keys.

System services are declared by the provider manifest. Ansible runs the Reef node apply script, uploads only files that the remote plan reports as missing or drifted, starts or restarts affected services, and deletes managed state through the delete playbook.

## Test Layout

`just test` uses four gateway nodes and one internal echo target. An illustrative
topology with placeholder node names:

```text
entries: entry-a, entry-b
exits:   exit-a, exit-b
```

Test containers run real `systemd` and `sshd` without `privileged: true`:

```yaml
cap_add:
  - SYS_ADMIN
tmpfs:
  - /run
  - /run/lock
```

Test-only SSH address mappings live inside `tests/` and are not part of the production configuration model.
