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
just reef-web-env
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
- `reef-web-env`: print the effective website configuration as a multiline `.env` payload for `REEF_WEB_ENV`, without modifying files or uploading secrets. Refuse to output in CI because the payload includes the root seed.
- `web-build`: install Web dependencies and run a production build.
- `web-dev`: render Web artifacts, install Web dependencies, and start the local development server.

There is no standalone `render` recipe. Rendering is an internal step used by recipes that need fresh artifacts.

`just smoke` verifies every Reef-managed client proxy through generated client configuration:

- select one generated client proxy at a time
- request to `https://api.ipify.org`
- assert the returned IP equals the configured exit IP

This intentionally assumes the configured exit IP is also the observed egress IP. If a provider or cloud network violates that assumption, the first phase should fail loudly rather than add extra configuration.
Upstream subscription nodes are excluded because Reef does not know their egress IPs.

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
REEF_ENTRY_OVERRIDE_BASE_DOMAIN=example.com

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
- `REEF_ENTRY_OVERRIDE_BASE_DOMAIN` is optional. When set, at least one entry is required.
- `REEF_ENTRY_OVERRIDE_BASE_DOMAIN` is a base domain only. It must not include a scheme, path, wildcard, or trailing dot.
- A Reef cluster requires at least one exit; entries are optional. With
  upstream subscriptions, both entries and exits may be omitted for subscription-only
  use. `REEF_SECRET` is still required to derive private subscription URL tokens.
- Deployment recipes and `smoke` require a Reef cluster. Subscription-only use
  requires no SSH key, runtime binaries, or remote nodes.

### Derived Model

Reef derives:

- entries: every `REEF_ENTRY_N`
- exits: every `REEF_EXIT_N`
- relay routes: every entry paired with every exit
- direct routes: every exit
- entry override hosts: `<entry-name>.<REEF_ENTRY_OVERRIDE_BASE_DOMAIN>` when the base domain is set

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

When `REEF_ENTRY_OVERRIDE_BASE_DOMAIN=example.com`, the same entries also derive:

```text
sg.example.com
jp.example.com
```

Generated Mihomo and Quantumult X subscriptions route each derived host only to
relay routes for the matching entry. They do not fall back to other entries or
direct exit routes. On the matching entry node, the destination address is
overridden to `127.0.0.1`; the original destination port is preserved.

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

### Upstream Subscription Nodes

`REEF_UPSTREAM_URL_N` optionally supplies multiple HTTP(S) Clash/Mihomo YAML
subscriptions, numbered consecutively from 1. The existing `REEF_UPSTREAM_URL`
is still accepted and, when combined with numbered URLs, is read first.
Each subscription generation fetches every configured subscription once and
merges only their inline `proxies` lists. The existing Reef nodes remain available.
Upstream nodes are not managed deployment nodes and do not change the cluster
topology or derived secrets.

The output set remains `client.yaml`, `linux-server.yaml`, and `quantumult-x.conf`.
All three use the templates in `subscriptions/`: DNS, rules, listeners, and policy
behavior remain locally maintained. Upstream rules, DNS, groups, and remote
providers are ignored.
Reef nodes come first, followed by upstream subscriptions in numeric order,
preserving each subscription's node order.

The two general-purpose groups are:

- `PROXY` (`select`): `AUTO` first, then every concrete node. Select `AUTO` for
  automatic choice, or pin one node manually for a stable egress location.
- `AUTO` (`url-test`): all Reef and upstream nodes, testing every 300 seconds
  with a 5-second timeout and a 50ms switching tolerance. Latency tests do not
  establish access to a particular service or preserve an egress country.

Quantumult X has the same structure with the existing `Reef` manual policy and
an `AUTO` latency policy; only QX-compatible nodes appear in either.
Per-exit and `UPSTREAM` groups are replaced by these two groups. Optional
`entry-<name>` policies in the client and QX profiles remain separate, contain
only that entry's relay routes, and retain their higher-priority domain rules. Client rules still send the AI
and proxy rule sets to the main selector, China destinations directly, and
remaining traffic to the selector. Linux server rules send all traffic to it.

Without a Reef cluster, the same two groups contain only upstream nodes. At least one
upstream node must be convertible to Quantumult X in this mode; otherwise
generation fails rather than publishing an empty Quantumult X selector.

Both Mihomo profiles preserve upstream node fields and names. Quantumult X
uses the official Sub-Store 2.39.6 `proxy-utils.esm.mjs`, pinned by SHA-256,
to convert HTTP, SOCKS5, AnyTLS, VLESS TCP, and Trojan TCP nodes with supported
options, preserving credentials, TLS verification, SNI, and Reality parameters.
Reef runs the parser and QX producer offline under Node.js 22 using an isolated
browser context (`--experimental-vm-modules`). The release bundle is downloaded
once into `build/substore/` and its checksum is checked before every run. No
converter service or extra Secret is needed. Only the merged node snapshot
crosses stdin; the converter receives neither the upstream URLs nor Reef's
environment, and its raw diagnostics are never printed. Each generation converts
once, then uses the same result for rendering and validation.
Unsupported protocols or options are omitted from Quantumult X together with
their group references; generation reports only the skipped count. TUIC remains
available in Mihomo. Certificate pins enable TLS verification in Quantumult X,
even with upstream `skip-cert-verify`, so the pin remains enforced. Quantumult X
uses its own TLS client fingerprint; the upstream `client-fingerprint` is not
transferred. Unspecified UDP and SNI values follow Sub-Store's defaults; VLESS
TLS/Reality SNI uses `obfs-host` as in the official QX examples. Unexpected node
loss or renaming by the converter fails generation. Conversion follows the
[official Quantumult X node syntax](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf).

Invalid or empty node lists, duplicate names within or across subscriptions,
names conflicting with local nodes or policies, dependencies on
upstream policy groups, and unrepresentable values fail generation without
printing subscription URLs, bodies, or credentials. Fetch or parse failures do
not replace previously generated subscription files. There is no background
poller: `just urls`, website builds, and other subscription rendering steps fetch
fresh nodes; hosted contents change after the next successful website deployment.
An upstream URL may contain credentials and must stay in `.env` / `REEF_WEB_ENV`.

### Website Deployment

The website deployment workflow runs after changes land on `master`. It can also be triggered manually with GitHub Actions `workflow_dispatch`. It deploys the Vercel project from the repository root so Vercel can apply the Web app root directory setting.

Required GitHub Secrets:

```text
REEF_WEB_ENV
VERCEL_TOKEN
VERCEL_ORG_ID
VERCEL_PROJECT_ID
```

`REEF_WEB_ENV` is the single multiline `.env` payload for all subscription website
configuration, including all upstream Clash URLs. It must include the root seed
and either public topology values or upstream URLs (or both). It must not
include `REEF_SSH_PRIVATE_KEY_B64` or test-only variables. No separate upstream
GitHub Secret or Vercel setting is needed.

For subscription-only use, the complete payload can be:

```env
REEF_SECRET=<64 lowercase hex chars>
REEF_UPSTREAM_URL_1=https://subscription.example.com/private-clash-url
REEF_UPSTREAM_URL_2=https://another.example.com/private-clash-url
```

Run `just reef-web-env` to generate this payload. It reads `.env` (or
`REEF_ENV_FILE`) with environment variables taking precedence, validates the
website configuration, and outputs only `REEF_SECRET`, both port settings
(including defaults), the optional entry override base domain, all upstream URLs
(normalized to `REEF_UPSTREAM_URL_N`), and all `REEF_ENTRY_N` / `REEF_EXIT_N` nodes.
Copy the output into the GitHub Secret `REEF_WEB_ENV`, then run the website
deployment workflow to publish changes.
