# Design

## Operator Interface

Reef exposes these recipes:

```text
just gen-secret
just set-ssh-key <path>
just vendor
just doctor
just plan
just apply
just smoke
just delete
just test
just urls
just web-build
just web-dev
```

Their purpose:

- `gen-secret`: generate a new `REEF_SECRET` and write it to `.env`. It refuses to overwrite an existing secret.
- `set-ssh-key <path>`: base64-encode an OpenSSH private key and write `REEF_SSH_PRIVATE_KEY_B64` to `.env`.
- `vendor`: download Linux amd64 runtime binaries into `bin/`.
- `doctor`: validate local configuration, local tools, SSH connectivity, jump paths, remote systemd availability, permissions, and remote port availability.
- `plan`: render locally, then run Ansible check mode and diff. It may connect to nodes but must not change them.
- `apply`: render locally and converge the remote nodes.
- `smoke`: verify deployed routes through the generated client configuration.
- `delete`: remove Reef-managed remote services and files. It asks for confirmation in an interactive shell and skips confirmation when `CI=1`.
- `test`: run the local integration test matrix.
- `urls`: render subscription artifacts and print path-only subscription URLs.
- `web-build`: install Web dependencies and run a production build.
- `web-dev`: render Web artifacts, install Web dependencies, and start the local development server.

There is no standalone `render` recipe. Rendering is an internal step used by recipes that need fresh artifacts.

`just smoke` verifies every generated client proxy through generated client configuration:

- select one generated client proxy at a time
- request to `https://api.ipify.org`
- assert the returned IP equals the configured exit IP

This intentionally assumes the configured exit IP is also the observed egress IP. If a provider or cloud network violates that assumption, the first phase should fail loudly rather than add extra configuration.

## Cluster Architecture

The source of truth is environment variables plus one root seed:

```text
REEF_SECRET
REEF_ENTRY_N
REEF_EXIT_N
REEF_ENTRY_PORT_BASE
REEF_EXIT_PORT
REEF_SSH_PRIVATE_KEY_B64
```

There is no user-maintained topology file and no local per-node secret state.

### Configuration Contract

```env
REEF_SECRET=<64 lowercase hex chars>
REEF_SSH_PRIVATE_KEY_B64=<base64-encoded OpenSSH private key>

REEF_ENTRY_PORT_BASE=20000
REEF_EXIT_PORT=443

REEF_ENTRY_1=sg,1.2.3.4
REEF_ENTRY_2=jp,2.3.4.5

REEF_EXIT_1=us,3.4.5.6
REEF_EXIT_2=uk,4.5.6.7
```

Rules:

- `REEF_SECRET` is exactly 64 lowercase hex characters.
- SSH user is always `root`.
- `REEF_SSH_PRIVATE_KEY_B64` is the only supported SSH credential input.
- Entry and exit values use `name,ip`.
- Node names are stable identities. Changing a node name creates a different node identity.
- First phase supports a global SSH key only.
- First phase supports all entries connected to all exits.

### Derived Model

Reef derives:

- entries: every `REEF_ENTRY_N`
- exits: every `REEF_EXIT_N`
- relay routes: every entry paired with every exit
- direct routes: every exit

For `M` entries and `N` exits:

```text
relay routes  = M * N
direct routes = N
client routes = M * N + N
```

Example:

```env
REEF_ENTRY_1=sg,1.2.3.4
REEF_ENTRY_2=jp,2.3.4.5
REEF_EXIT_1=us,3.4.5.6
REEF_EXIT_2=uk,4.5.6.7
```

Derived client routes:

```text
sg -> us
sg -> uk
jp -> us
jp -> uk
us direct
uk direct
```

### Ports

Entry relay ports are deterministic:

```text
relay port for exit index N = REEF_ENTRY_PORT_BASE + N - 1
```

Exit direct ports are fixed:

```text
direct exit port = REEF_EXIT_PORT
```

For two exits and `REEF_ENTRY_PORT_BASE=20000`:

```text
sg -> us  sg:20000
sg -> uk  sg:20001
jp -> us  jp:20000
jp -> uk  jp:20001
us direct us:443
uk direct uk:443
```

Reef checks port availability but does not auto-select or mutate ports.

### Deployment Path

When entries exist:

```text
local -> each entry
local -> first entry -> each exit
```

The first entry is `REEF_ENTRY_1` and is the only deployment jump host in the first phase.

When no entries exist:

```text
local -> each exit
```

### Deterministic Secrets

All cluster secrets are derived from `REEF_SECRET`, node identity, profile identity, and purpose-specific labels.

This exists for one reason: local rendering, CI rendering, deployed node configuration, and subscription Web rendering must produce the same result without reading mutable state.

Derived material includes:

- per-node transport password
- per-node deterministic TLS private key and certificate
- per-route local secrets required by the provider
- per-profile subscription URL token

TLS certificates must be deterministic:

- one certificate per node
- P-256 ECDSA key and SHA-256 signature
- deterministic certificate signature
- SAN contains the node IP
- serial number is derived, not random
- validity window is fixed, not based on current time
- fingerprint is derived from the rendered certificate

P-256 is used for broad TLS client compatibility. The private scalar is derived
from `REEF_SECRET` with HKDF and reduced into the P-256 scalar range; Reef does
not generate or store mutable TLS key state.

### Provider Boundary

Concrete node-side transport rendering lives in provider bundles:

```text
providers/<provider-id>/
├── provider.yaml
└── node/
```

Reef loads every provider bundle under `providers/` that contains `provider.yaml`. Directory-name order is used only to keep rendering deterministic. There is no provider selection configuration in the first phase.

`provider.yaml` is a Reef manifest read by Python. Python turns it into generated files and Ansible inputs. It is not an Ansible playbook.

The provider manifest may declare:

- node files to render
- provider-specific route variables required by node templates
- remote destinations
- services to install and manage
- route protocols used for local port availability checks

The provider manifest must not define the core route matrix, SSH model, or secret derivation rules. Those belong to Reef.

### Out Of Scope

Not in the first phase:

- partial route matrices
- per-node SSH users or keys
- non-root SSH
- non-Linux-amd64 nodes
- automatic port selection
- deploying the Web app through Ansible
- storing mutable local topology or per-node secret state

## Subscription Web

The subscription Web is a Vercel-hosted Next.js app. It is not deployed by Ansible and does not SSH into nodes.

Build-time flow:

```text
Vercel env
  -> Python render
  -> web/generated/subscriptions.ts
  -> Next.js build
```

Runtime flow:

```text
GET /<token>
  -> match generated subscription
  -> return body
```

There is no query token and no separate subscription hash variable. Each profile has a deterministic opaque token:

```text
token = derive(REEF_SECRET, "subscription-url", profile_id)
```

`subscription-url` is a derivation label, not a domain name. Reef does not store or render the public domain. `just urls` prints path-only URLs:

```text
<profile-id>  /<token>
```

Subscription profiles are declared by `subscriptions/profiles.yaml` and rendered by `subscriptions/render.py`:

```text
subscriptions/
├── profiles.yaml
├── render.py
└── <profile-template>.j2
```

The subscription renderer receives the derived route model and the loaded provider ids. It is the single owner of subscription proxy naming and profile-specific output formatting.

`web/generated/subscriptions.ts` is generated and ignored by git because it contains full subscription contents.

### Website Deployment

The website deployment workflow runs after changes land on `master`. It can also be triggered manually with GitHub Actions `workflow_dispatch`. It deploys the Vercel project from the repository root so Vercel can apply the Web app root directory setting.

Required GitHub Secrets:

```text
REEF_WEB_ENV
VERCEL_TOKEN
VERCEL_ORG_ID
VERCEL_PROJECT_ID
```

`REEF_WEB_ENV` is a multiline `.env` payload for the subscription website. It must include the root seed and public topology values. It must not include `REEF_SSH_PRIVATE_KEY_B64` or test-only variables.
