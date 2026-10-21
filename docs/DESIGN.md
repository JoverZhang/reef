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
just urls mihomo
just config-yaml
just web-deploy [gh-command]
just web-build
just web-dev
```

Their purpose:

- `gen-secret`: generate a new `secret` in `config.yaml`. It refuses to overwrite an existing secret.
- `set-ssh-key <path>`: write an OpenSSH private key as the multiline `ssh_private_key` in `config.yaml`.
- `vendor`: download Linux amd64 runtime binaries into `bin/`.
- `doctor`: validate local configuration, local tools, SSH connectivity, jump paths, remote systemd availability, permissions, and remote port availability.
- `plan`: render locally, then run Ansible check mode and diff. It may connect to nodes but must not change them.
- `apply`: render locally and converge the remote nodes.
- `smoke`: verify deployed routes through the generated client configuration.
- `delete`: remove Reef-managed remote services and files. It asks for confirmation in an interactive shell and skips confirmation when `CI=1`.
- `test`: run the local integration test matrix.
- `urls`: render subscription artifacts and print path-only subscription URLs.
- `urls mihomo`: render only the two Mihomo profiles into
  `build/subscriptions/mihomo/` and print their local paths for importing into a
  client. This local preview does not update the website or Quantumult X files.
- `config-yaml`: print website configuration as YAML for `CONFIG_YAML`, excluding `ssh_private_key`, without modifying files or uploading secrets. Refuse to output in CI because the payload includes the root seed.
- `web-deploy [gh-command]`: export website configuration, update `CONFIG_YAML` in `JoverZhang/reef`, update the `VERSION` timestamp, and commit and push it to `master`. The push triggers `deploy-website.yml`. The optional command defaults to `gh` and supplies the GitHub API and Git credentials. The system `git commit` uses the operator's existing Git identity. Requires zsh and an authenticated GitHub CLI command. Run in an interactive login zsh so configured aliases and functions are available. Requires clean tracked files on `master` at the current remote commit. Stop on failure and pass configuration through stdin without printing it or putting it in command arguments. Returns after push; deployment runs asynchronously in GitHub Actions.
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

The source of truth is the private root `config.yaml`, containing one root seed,
cluster settings, upstream URLs, and standalone subscription nodes.
There is no local per-node secret state. `.env`, `REEF_*` configuration overrides,
and `subscriptions/extend.yaml` are not read. CI materializes the same file from
the `CONFIG_YAML` Secret.

### Configuration Contract

```yaml
secret: "<64 lowercase hex chars>"
ssh_private_key: |
  <OpenSSH private key>
cluster:
  entry_port_base: 20000
  exit_port: 443
  entries:
    - {name: entry-a, ip: 192.0.2.10}
    - {name: entry-b, ip: 192.0.2.11}
  exits:
    - {name: exit-a, ip: 192.0.2.20}
    - {name: exit-b, ip: 192.0.2.21}
proxies: []
proxy-providers:
  upstream:
    type: http
    url: "https://subscription.example.com/private-clash-url"
    filter: "Sample-A|Sample-B"
    exclude-filter: "Sample-Excluded"
# Optional: omit these groups to keep the existing PROXY/AUTO defaults.
proxy-groups:
  - name: PROXY
    type: select
    proxies: [AUTO]
    include-all: true
  - name: AUTO
    type: url-test
    include-all: true
    url: https://www.gstatic.com/generate_204
    interval: 300
```

Rules:

- `secret` is a quoted string of exactly 64 lowercase hex characters.
- SSH user is always `root`.
- `ssh_private_key` is the only supported SSH credential input and contains the
  unencrypted OpenSSH private key as multiline text. It is optional for subscriptions.
- Entry and exit lists contain `{name, ip}` mappings. Their order determines indices.
- Node names are stable identities. Changing a node name creates a different node identity.
- First phase supports a global SSH key only.
- First phase supports all entries connected to all exits.
- A Reef cluster requires at least one exit; entries are optional. With
  upstream subscriptions or extension nodes, both entries and exits may be omitted
  for subscription-only use. `secret` is still required to derive private
  subscription URL tokens.
- Deployment recipes and `smoke` require a Reef cluster. Subscription-only use
  requires no SSH key, runtime binaries, or remote nodes.
- `cluster` and legacy `subscriptions` are optional mappings. Their lists default to empty.
  Ports default to 20000 and 443. Unknown fields, duplicate YAML keys, incorrect
  types, invalid nodes, and malformed YAML fail without echoing credentials.
- `config.yaml` is ignored by git and written with mode `0600`.
  `config.example.yaml` is the public template. Test processes may use
  `TEST_CONFIG_FILE` only when `REEF_TEST_MODE=1`.

### Derived Model

Reef derives:

- entries: the ordered `cluster.entries` list
- exits: the ordered `cluster.exits` list
- relay routes: every entry paired with every exit
- direct routes: every exit

For `M` entries and `N` exits:

```text
relay routes  = M * N
direct routes = N
client routes = M * N + N
```

Example:

```yaml
cluster:
  entries:
    - {name: entry-a, ip: 192.0.2.10}
    - {name: entry-b, ip: 192.0.2.11}
  exits:
    - {name: exit-a, ip: 192.0.2.20}
    - {name: exit-b, ip: 192.0.2.21}
```

Derived client routes:

```text
entry-a -> exit-a
entry-a -> exit-b
entry-b -> exit-a
entry-b -> exit-b
exit-a direct
exit-b direct
```

### Ports

Entry relay ports are deterministic:

```text
relay port for exit index N = cluster.entry_port_base + N - 1
```

Exit direct ports are fixed:

```text
direct exit port = cluster.exit_port
```

For two exits and `cluster.entry_port_base=20000`:

```text
entry-a -> exit-a  entry-a:20000
entry-a -> exit-b  entry-a:20001
entry-b -> exit-a  entry-b:20000
entry-b -> exit-b  entry-b:20001
exit-a direct exit-a:443
exit-b direct exit-b:443
```

Reef checks port availability but does not auto-select or mutate ports.

### Deployment Path

When entries exist:

```text
local -> each entry
local -> first entry -> each exit
```

The first entry is `cluster.entries[0]` and is the only deployment jump host in the first phase.

When no entries exist:

```text
local -> each exit
```

### Deterministic Secrets

All cluster secrets are derived from `secret`, node identity, profile identity, and purpose-specific labels.

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
from `secret` with HKDF and reduced into the P-256 scalar range; Reef does
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
CONFIG_YAML Secret
  -> config.yaml
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
token = derive(secret, "subscription-url", profile_id)
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

### Native Mihomo Input

The preferred subscription input is the native Mihomo `proxies`,
`proxy-providers`, and `proxy-groups` keys at the root of `config.yaml`, beside
`secret` and the optional deployment `cluster`. No `sources`, multi-document
YAML, custom routing language, or configurable output registry is introduced.
The existing three profile IDs, filenames, URL tokens, DNS, and rule templates
remain unchanged. `linux-server.yaml` routes all traffic through `PROXY` using
`MATCH,PROXY`; `client.yaml` and `quantumult-x.conf` retain their rules.

This first version accepts:

- `proxies`: a list of ordinary Mihomo proxy mappings.
- `proxy-providers`: named `http` or `inline` collections. HTTP providers use
  either the native single `url` or Reef's nonempty `upstreams` list of
  `{name, url}` mappings; inline providers use `payload`. Each named upstream
  adds `name | ` to its nodes. Names must be nonempty and representable in both
  clients. `filter` and `exclude-filter` match
  names using regular expressions; `exclude-type` lists protocol types separated
  by `|`. `override.additional-prefix` and `override.additional-suffix` can
  disambiguate node names. `override.dialer-proxy` applies the same intermediate
  proxy or group to every selected node. HTTP `interval` is accepted, but Reef fetches on each
  generation rather than running a background refresh timer.
- `proxy-groups`: `select` and `url-test` groups, with `proxies` for node/group
  names and `use` for provider names. The native `include-all`,
  `include-all-proxies`, and `include-all-providers` selectors are also accepted.
  Custom groups must contain `PROXY`, which is the existing templates' target.
  With no custom groups or `relay` mapping, the existing `PROXY` and `AUTO`
  defaults remain.
- `relay`: an optional mapping from inline exit provider names to ordered lists
  of intermediate provider names. It generates the exit, relay, and pool groups
  described below. It cannot be combined with nonempty `proxy-groups`.

For example, each collection explicitly lists its upstream subscriptions:

```yaml
proxy-providers:
  pool-a:
    type: http
    upstreams:
      - &source_a {name: source-a, url: "https://source-a.example.invalid/subscription"}
      - &source_b {name: source-b, url: "https://source-b.example.invalid/subscription"}
  pool-b:
    type: http
    upstreams:
      - &source_c {name: source-c, url: "https://source-c.example.invalid/subscription"}
  pool-c:
    type: http
    upstreams: [*source_a, *source_b, *source_c]
```

`pool-c` is an ordinary collection name, with no implicit membership. YAML aliases
are optional; repeating the same `{name, url}` mappings has the same behavior.
Filters run against original node names, before the upstream name prefix and
then `override.additional-prefix` / `additional-suffix` are applied. Reusing
the same upstream name preserves node identities across collections; different
subscriptions with colliding node names should use different upstream names.
Repeated identical nodes within a collection are included once.

Reef resolves collections once per generation, filters before combining them,
and embeds the resulting nodes and expanded group memberships in every output.
Repeated references to the same HTTP URL share one response. Identical nodes
with the same name can appear in multiple collections; conflicting definitions
fail. Provider URLs never appear in generated subscriptions. Empty collections,
empty groups, missing references, and cyclic group references fail before
replacing artifacts. Fetch failures identify `upstream URL #N` and provider
position, never the URL, credentials, or response body.
HTTP requests use a 30-second socket timeout; an unavailable source still fails
generation instead of falling back to an older snapshot.

Quantumult X keeps the existing supported-node conversion contract below.
Unsupported nodes and their group memberships are omitted with a count; a group
left empty fails generation. `select` maps to `static`, and `url-test` to
`url-latency-benchmark`. `PROXY` maps to the existing QX policy `Reef`. Latency
groups support `url`, `interval`, `timeout` (up to 5000 ms), `tolerance`, and
`lazy`; they must use one common probe URL and timeout for QX's general settings.
These QX restrictions are checked only when generating QX; the Mihomo preview
allows independent probe settings and latency groups containing other groups.
Other provider/group options, including provider health checks and file
providers, remain unsupported and fail explicitly.

### Mihomo Client-side Relay

The first relay milestone publishes Mihomo profiles with independently selectable
intermediate and exit proxies. Nodes are ordinary protocol endpoints, regardless
of which side of a chain uses them. A proxy's native `dialer-proxy` names another
proxy or a selection group. It belongs on the **exit** endpoint:

```text
client -> RELAY's selected node -> PROXY's selected exit -> destination
```

This follows [Mihomo's native dialer-proxy semantics](https://wiki.metacubex.one/config/proxies/dialer-proxy/).
`config.mihomo.example.yaml` illustrates two fictional exits with separate direct
and relayed paths. Public examples use independent placeholder names, addresses,
and credentials; they must not disclose private operator names or locations.

Use `proxy-providers` for filtered subscription collections and inline endpoint
collections. For automatic groups, each exit is one inline provider whose key is
the node's display name, such as `Endpoint A`. Its payload contains the ordinary
protocol endpoints, named for example `Trojan` and `Hysteria2`. The optional
`relay` mapping specifies only which pools each exit can use:

```yaml
relay:
  Endpoint A: [pool-a, pool-b, pool-c]
  Endpoint B: [pool-c, pool-a, pool-b]
```

There is no separate group display name or region alias. All referenced providers
must exist. The mapping and each pool list must be nonempty; repeated pools and
using an exit provider as a pool are rejected. Exit providers must be inline and
must not already set `dialer-proxy` in their payload or override. Pools can use
inline or HTTP providers. Rename the provider key and its reference together;
the generated names follow automatically.

For each exit, Reef prefixes filtered endpoint names with `<provider name> | `,
then makes separate ` | DIRECT` and ` | RELAY` copies. DIRECT copies have no
`dialer-proxy`; RELAY copies point to `RELAY | <provider name>`. This keeps protocol
selection and probe history independent for the two paths. The generated groups
are:

- `PROXY`: each exit's RELAY option followed by its DIRECT option, in mapping
  order, then the referenced pools in provider declaration order.
- `EXIT | <provider name> | RELAY`: an automatic `url-test` group of relayed
  endpoints, including when there is only one endpoint.
- `EXIT | <provider name> | DIRECT`: an automatic `url-test` group only when the
  filtered collection has multiple endpoints. With one endpoint, `PROXY`
  references the DIRECT node itself, without an extra group. Empty collections
  fail. This decision is recalculated on every generation.
- `RELAY | <provider name>`: a `select` group of that exit's pools in the supplied
  order. The first pool is the default; there is no DIRECT option.
- `POOL | <provider name>`: one shared `url-test` group for each referenced pool.
  Selecting it in `PROXY` uses its node as the final exit, without an owned exit.

These automatic groups use the existing probe defaults. Pool and endpoint names
may be localized in private configuration; public examples use English.
DIRECT exit paths still use the exit server as their public exit. They are
unrelated to Mihomo's built-in `DIRECT`, which bypasses proxying entirely.

Without `relay`, explicit native `proxy-groups` including `PROXY` remain supported
for manually defined chains. Only the native `dialer-proxy` field creates the
connection; group names alone have no chaining behavior. Inline and HTTP providers
can use `override.dialer-proxy` to share a defined relay group. The generator
preserves the resulting fields in both Mihomo outputs. Do not use `include-all`
for relay selectors: it can create a cycle or offer an unintended exit. A manual
relay can be a concrete node, a manual group, or a `url-test` group. Both node and
group references are checked together for missing targets and cycles, including
candidates that are not selected initially. There is no implicit direct fallback.

Each generated relay selector keeps its own manual choice, so switching `PROXY`
also switches to the corresponding intermediate without resetting it. Automatic
groups remain visible so a client can pin a particular member. All references to
the same pool share its current node, whether used as an exit or as an
intermediate. Combined pools keep their own selection across their explicitly
listed subscriptions. Automatic pool tests measure the intermediate's own
connection, not every possible intermediate/exit combination.

The fictional endpoints demonstrate VLESS Reality, Trojan, and Hysteria2.
Protocol selection is independent for direct and relayed paths. Hysteria2 exits
require a relay capable of carrying their UDP transport. Exit probes include
the currently selected intermediate; they do not search every possible pairing.
Actual protocol, destination-port, and UDP support still depend on both services;
successful configuration validation is not an end-to-end connectivity test.
Existing Reef-managed entry ports already forward through a fixed exit and are
not used as ordinary intermediates in this example. A standalone exit definition
must match the deployed endpoint; if its server credentials change, update it.

Run `just urls mihomo` for a local preview, or `just web-deploy` to publish the
two Mihomo subscriptions at their existing URLs. The fixed global and rule-based Mihomo
templates keep their existing behavior. The rule-based profile can still route
China destinations directly; only traffic assigned to `PROXY` uses the chain.
When the resolved snapshot contains any `dialer-proxy`, normal generation renders
only the two Mihomo profiles and reports that QX relay conversion is unavailable.
After successful validation, it removes any stale local QX subscription file.
The existing QX URL returns HTTP 503 with an explicit unsupported-relay message,
so clients cannot mistake an unchained configuration for a successful update.
It never strips the intermediate hop or silently drops chained exits.
`just urls` prints only available subscription paths. Non-chain configurations
retain all three outputs, including the same QX URL when relay settings are removed.

The previous `subscriptions.upstream_urls` and `subscriptions.nodes` input
continues to work for existing installations. It cannot be mixed with the new
root subscription keys. New configurations should use the native keys.

### Legacy Upstream Subscription Nodes

`subscriptions.upstream_urls` optionally supplies an ordered list of HTTP(S)
Clash/Mihomo YAML subscriptions.
Each subscription generation fetches every configured subscription once and
merges only their inline `proxies` lists. The existing Reef nodes remain available.
Upstream nodes are not managed deployment nodes and do not change the cluster
topology or derived secrets.

The output set remains `client.yaml`, `linux-server.yaml`, and `quantumult-x.conf`.
All three use the templates in `subscriptions/`: DNS, rules, listeners, and policy
behavior remain locally maintained. Upstream rules, DNS, groups, and remote
providers are ignored.
Reef nodes come first, followed by upstream subscriptions in list order,
then extension nodes, preserving each source's node order.

The two general-purpose groups are:

- `PROXY` (`select`): `AUTO` first, then every concrete node. Select `AUTO` for
  automatic choice, or pin one node manually for a stable egress location.
- `AUTO` (`url-test`): all Reef and upstream nodes, testing every 300 seconds
  with a 5-second timeout and a 50ms switching tolerance. Latency tests do not
  establish access to a particular service or preserve an egress country.

Quantumult X has the same structure with the existing `Reef` manual policy and
an `AUTO` latency policy; only QX-compatible nodes appear in either.
Per-exit and `UPSTREAM` groups are replaced by these two groups. Client rules still send the AI
and proxy rule sets to the main selector, China destinations directly, and
remaining traffic to the selector. Linux server rules send all traffic to it.

Without a Reef cluster, the same two groups contain only upstream nodes. At least one
upstream node must be convertible to Quantumult X in this mode; otherwise
generation fails rather than publishing an empty Quantumult X selector.

Both Mihomo profiles preserve upstream node fields and names. Quantumult X
uses the official Sub-Store 2.39.6 `proxy-utils.esm.mjs`, pinned by SHA-256,
to convert HTTP, SOCKS5, AnyTLS, VLESS TCP/WebSocket, and Trojan TCP nodes with supported
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
TLS/Reality SNI uses `obfs-host` as in the official QX examples. For VLESS over
TLS WebSocket, QX shares one host value between SNI and the HTTP Host header;
nodes requiring different values or custom WebSocket headers are omitted.
WebSocket conversion requires an explicit Host header; Reef supplies it when
normalizing the common extension format so client defaults cannot diverge.
VLESS encryption other than `none`, explicit XUDP/packetaddr encoding, and gRPC
are outside the verified QX conversion contract and are omitted. Unexpected node
loss or renaming by the converter fails generation. Conversion follows the
[official Quantumult X node syntax](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf).

Invalid or empty node lists, duplicate names within or across subscriptions,
names conflicting with local nodes or policies, dependencies on
upstream policy groups, and unrepresentable values fail generation without
printing subscription URLs, bodies, or credentials. Fetch or parse failures do
not skip the failed source or replace previously generated subscription files.
Errors identify the source as `upstream URL #N`, numbered from 1 in fetch order
(the order of `subscriptions.upstream_urls`), and distinguish a failed
request, invalid response format, and an empty node list. There is no background
poller: `just urls`, website builds, and other subscription rendering steps fetch
fresh nodes; hosted contents change after the next successful website deployment.
Upstream URLs may contain credentials and stay in private `config.yaml` / `CONFIG_YAML`.

### Legacy Subscription Extension

`subscriptions.nodes` in `config.yaml` is the legacy optional list of standalone
VLESS nodes. New configurations use ordinary Mihomo `proxies` instead.
This is Reef's client-independent input format; it describes the endpoint and
protocol settings once, then Reef generates Mihomo and Quantumult X syntax.
No encoding or subscription hosting is required.

```yaml
subscriptions:
  nodes:
    - name: extra-vless
      protocol: vless
      server: proxy.example.com
      port: 443
      uuid: 00000000-0000-4000-8000-000000000001
      transport:
        type: tcp
      tls:
        sni: certificate.example.com
        verify: true
```

The `nodes` list defaults to empty. Each node requires `name`,
`protocol: vless`, `server`, `port`, and a valid `uuid`. Unknown fields, invalid
types, and incompatible combinations fail validation without echoing values.
Client-specific `proxies`, `network`, `grpc-opts`, and `reality-opts` inputs are
not accepted in this list. Remote upstream subscriptions keep their Clash format.

Optional fields:

| Field | Meaning and default |
| --- | --- |
| `transport.type` | `tcp` (default), `ws`, or `grpc` |
| `transport.path`, `transport.host` | WebSocket only; path defaults to `/`, host defaults to TLS SNI or `server` without TLS |
| `transport.service_name` | gRPC only; defaults to an empty service name |
| `tls` | A mapping enables TLS; omitting it disables TLS |
| `tls.sni`, `tls.verify` | SNI defaults to `server`; certificate verification defaults to `true` |
| `tls.client_fingerprint` | Mihomo TLS client fingerprint; defaults to `chrome` with Reality; QX uses its own fingerprint |
| `tls.alpn` | Optional list for standard TLS; WebSocket requires `[http/1.1]`, gRPC requires `[h2]`; omit for Reality, whose ALPN is client-selected |
| `tls.reality.public_key`, `tls.reality.short_id` | Enable Reality over TCP/gRPC; public key is required and short ID is optional, quoted hexadecimal |
| `flow` | Optional `xtls-rprx-vision`, requiring TCP and TLS |
| `udp` | UDP relay, default `true` |
| `packet_encoding` | Optional `xudp` or `packetaddr`; available in Mihomo only |
| `encryption` | Optional VLESS encryption string; omitted, empty, or `none` means no protocol encryption |

For gRPC, for example, use `transport: {type: grpc, service_name: my-service}`.
For WebSocket use `transport: {type: ws, path: /ws, host: certificate.example.com}`.
These values must match the server. A TLS WebSocket node with a Host header
different from its SNI remains available only in Mihomo because QX cannot preserve
both values independently.
The common format rejects WebSocket with Reality: the bundled Mihomo transport
does not apply Reality to its WebSocket handshake. This avoids accepting a
combination whose generated Mihomo settings would silently lose Reality.

Extension nodes use the same ordering, automatic group membership, and QX
conversion as upstream nodes. Duplicate names across all sources fail generation.
Static client settings stay in the templates; extensions do not change deployment
routes or managed nodes.

Maintain each node once: both Mihomo profiles receive the mapped settings, while
Quantumult X receives the converted node and policy references when supported.
Transports outside the QX conversion contract, such as gRPC, are omitted with the
existing skipped-node report. Rendering must never change a node's transport
to work around a client limitation. Subscription-only use still requires at
least one Quantumult X-compatible node across all sources.

These nodes stay in the same private `config.yaml` as upstream URLs. The website
export includes them in `CONFIG_YAML`; no separate extension Secret is needed.

### Website Deployment

The website deployment workflow runs after changes land on `master`. It can also be triggered manually with GitHub Actions `workflow_dispatch`. It deploys the Vercel project from the repository root so Vercel can apply the Web app root directory setting.

Required GitHub Secrets:

```text
CONFIG_YAML
VERCEL_TOKEN
VERCEL_ORG_ID
VERCEL_PROJECT_ID
```

`CONFIG_YAML` is the single multiline YAML payload for the website: root seed,
cluster settings, upstream URLs, and standalone nodes. It uses the same schema
as local `config.yaml`, excluding `ssh_private_key`. Test-only and unknown fields
are rejected. At least one source of nodes is required.

Run `just config-yaml` locally to validate and export this payload without
fetching upstreams, changing local files, or uploading secrets. Copy its stdout
into the GitHub Secret `CONFIG_YAML`. Export is refused in CI. The old
`REEF_WEB_ENV` and `REEF_EXTEND_YAML` Secrets are no longer used.

For routine publishing, run `just web-deploy` from `master` with clean tracked
files and no local commits ahead of or behind `JoverZhang/reef`'s `master`.
It validates and exports configuration, fetches and checks the remote commit,
and uploads `CONFIG_YAML` before changing `VERSION`. Configuration stays in
memory and goes to `gh secret set` through stdin; the command does not print it.
`VERSION` records the UTC publication time as `YYYYMMDDHHMMSS`. Only that file
is committed, using the system `git commit` with the operator's existing Git
name and email. The recipe does not override the commit identity or change Git
configuration.
The recipe pushes the new commit directly to `JoverZhang/reef`'s `master` without
force. The existing push trigger starts the website workflow; the recipe does
not also dispatch a duplicate run. Check the resulting deployment in GitHub
Actions. Commit and publish application changes before running this recipe.
Private `config.yaml` stays untracked. If the push fails, the local publication
commit remains available for inspection and retry; the recipe does not reset it.

To choose a different GitHub account wrapper, run `just web-deploy gh-reef`.
The recipe loads interactive login zsh configuration, so `gh-reef` can be an
executable, function, or alias. The default remains `just web-deploy` using `gh`.
The selected credentials need repository Contents write access for Git pushes
and Secrets write access to update `CONFIG_YAML`. Actions write access is only
needed to dispatch workflows manually.

The workflow parses and validates the payload with the same configuration reader,
registers masks for scalar values and decoded upstream URL credentials/tokens,
and writes `config.yaml` with mode `0600` before building. CI suppresses raw
generation exceptions and hides subscription URL tokens. Vercel build diagnostics
are captured privately because compiler errors can quote generated source
containing credentials; CI reports only build status. Configuration, Vercel
environment files, and the captured build log are removed even on failure.
No subscription bodies are uploaded as workflow artifacts. The generated Web
module is marked `server-only` so a client component cannot import its credentials.

For subscription-only use, the complete payload can be:

```yaml
secret: "<64 lowercase hex chars>"
proxy-providers:
  upstream-a:
    type: http
    url: "https://subscription.example.com/private-clash-url"
  upstream-b:
    type: http
    url: "https://another.example.com/private-clash-url"
```
