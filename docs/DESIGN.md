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
  for subscription-only use. `secret` remains the cluster seed; it is never
  used as the website password.
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

Build-time flow (no upstream or rule downloads):

```text
CONFIG_YAML -> config.yaml -> validated private runtime input and bundled compiler
```

Request-time flow:

```text
GET /?password=...&type=clash-geo&include1=Alpha,Beta
  -> authenticate -> load or refresh shared snapshot -> filter -> preview
GET /dump?password=...&type=clash-geo&include1=Alpha,Beta
  -> authenticate -> load or refresh the same snapshot -> select -> serialize
POST /refresh
  -> authenticate the password in the JSON body -> force a shared refresh
GET /rules/<type>/<resource>?password=...
  -> authenticate -> load or refresh snapshot -> serve the compiled rule resource
```

`web.password` is an independent random access key of at least 32 characters.
It is required for website builds, must differ from `secret`, and is stored only
as a SHA-256 digest in the server-only bootstrap and snapshot. Missing, repeated, or incorrect
passwords return a real HTTP 404 before any preview data is returned. The previous
opaque subscription paths are removed and return 404. There is no `dump=1` alias.
`just urls` is removed; use the preview's copy-link or download action. Use
`just web-dev` to preview locally and `just web-deploy` to refresh production.

One type selector chooses `clash` (global Mihomo), `clash-geo` (rule-based Mihomo,
the default), or `qx` (rule-based Quantumult X). These map to the existing static
profile templates. The templates remain the sole owners of DNS and rules.

Each `includeN` filters the pool with stable ID N. Missing or empty values select
all nodes. Nonempty values are comma-separated literal substring alternatives,
trimmed and matched case-insensitively against original node names, before source
prefixes. They are not regular expressions or inferred locations. Configuration
provider filters apply first; request filters cannot restore excluded nodes.
Unknown or repeated parameters, unknown pool IDs, and invalid types return 400.
A nonempty filter that selects no nodes produces a visible pool-specific preview
error and a 422 dump response; it never silently removes a pool or changes paths.

Snapshots are shared through Upstash Redis, using the Marketplace-provided
`KV_REST_API_URL` and `KV_REST_API_TOKEN` (or Upstash's standard
`UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`). These are hosting
credentials, not subscription configuration. There is no in-memory production
fallback. Cache keys include the deployment identity; a new deployment starts
with no usable snapshot. The first authenticated preview, dump, or rule request
loads upstreams and rule resources. Incorrect passwords never contact Redis or
upstreams. Snapshots are fresh for one hour from successful completion; reads do
not extend freshness. Expired snapshots refresh on demand, without a scheduler.

Force update uses authenticated POST and refreshes the whole snapshot, including
node DNS used by QX. A shared expiring lock coalesces refreshes across instances.
Only the lock owner can publish or release its work. All required sources must
succeed before atomically replacing the snapshot. Failures identify source
positions or rule resource names without URLs or credentials, preserve the last
snapshot and its original timestamp, and return an error for the refresh. Fresh
older data remains usable. Expired older data may be displayed with a clear
error but never exported as a successful subscription or rule response.
Snapshots are retained for up to one day for this stale preview behavior.
Refresh workers have a three-minute compiler timeout and a four-minute lock.
Other requests wait up to one minute for an active refresh, then return a retry
error. A failed or expired worker cannot overwrite a newer snapshot.

The preview shows the snapshot time, freshness, refresh errors, a Force update
button, all exit endpoints and pool nodes, selected
counts, and the resulting PROXY choices. Unmatched nodes remain visible and grey
with a reason. Filter/type edits update the URL. Preview responses contain only
node names, protocols, and selection/compatibility metadata, not connection
credentials, addresses, or upstream URLs. The dump includes the selected nodes'
connection details. Both routes use the same selection function and snapshot.

The preview is one continuous page: exit endpoints, relay pools, client choices,
then rules. The sole profile selector lives in Client choices. Pool filters and
profile changes update immediately without navigation or upstream requests.
Literal, case-insensitive matches move first in the displayed pool, retaining
their original relative order; unmatched nodes remain grey. This presentation
order never changes exported node priority. Composition input applies after IME
completion. Browser and server use the same selection implementation over a
whitelisted metadata graph; credentials, addresses and source URLs stay server-side.
All three profiles' safe metadata are included after authentication. The URL,
compatibility errors, export links and rules follow the current selection.
Force update replaces this metadata in place and preserves filters and profile.
Rules show the configured rule order and target policies, resource counts, and timestamps.
Resource contents are loaded on expansion with literal search and pagination,
using the authenticated resource route with `format=json`, `q`, and `page`.
Generated endpoint rules are described without revealing node addresses in HTML.
Mihomo rule-providers and QX filter_remote reference Reef's authenticated rule
resources. QX proxy resources contain their required TUN reinjection flags;
direct resources do not. Client resource intervals are one hour. Refreshing Reef
does not push updates to clients; clients fetch configurations and resources on
their own schedules. Include filters affect nodes only.

### Update History

Redis retains a comparison baseline and the most recent 50 successful updates
that actually changed content. These keys are separate from deployment snapshots:
redeployment still fetches fresh data, while the production baseline and history
survive. Project/environment scopes isolate production, local development and
preview deployments. The initial refresh establishes a baseline without adding a
change record. An unchanged refresh updates the check time and one-hour freshness
only: it neither consumes a history slot nor evicts the last real change. A failed
refresh preserves the baseline and history. Refresh locks protect publication of
the snapshot, baseline and any history entry in one Redis operation.

Compare original protocol endpoints once, before generated DIRECT/RELAY copies.
Compare normalized fields, collection memberships, rule resource contents and
effective rule order. Formatting, comments, object-key order and timestamps are
not changes. Node renames appear as removal/addition. QX endpoint resolution
changes are labeled separately from source changes. Only allowlisted public
fields appear as values in history; credentials, addresses, source URLs and
arbitrary protocol options are represented by redacted changes. The server-only
baseline uses fingerprints to detect those changes without retaining old secrets.

The preview distinguishes Last checked from Last changed and opens History in a
drawer. Each entry is a timestamp and a compact expandable diff code block with
literal `+`/`-` lines and context; there is no separate change-card interface.
`GET /history?password=...&page=1` lists ten entries at a time.
Adding `id=<entry-id>` returns a page of 200 diff lines for that retained entry.
History reads authenticate before Redis access and never refresh upstreams.
History remains available when snapshots expire or refresh fails. Large diffs
are loaded in pages. Only actual diffs count toward the 50-entry retention limit.

The local interaction prototype also illustrates path latency. Live path probes
are deferred until a measurement location and execution host are chosen; the
production page does not display simulated measurements.

Every exit is paired with every pool. Path compilation and validation happen on
snapshot refresh; requests select pool memberships from the compiled graph and
serialize only the selected nodes. Shared nodes survive when selected by another pool, while each pool
retains its own filtered membership. Static settings are identical to the existing
profile templates. A displayed path is a configuration option, not proof of live
connectivity; clients perform their own probes.

QX previews show unsupported endpoints and the QX-specific selectors described
below. Automatic exits/pools support QX relay export; unsupported manual chains,
ambiguous relay addresses, or empty compatible collections return HTTP 422.
Never strip a hop, silently use a direct path, or publish a partially unchained
configuration.

All preview, dump, and error responses use `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, and no-index headers. Application and development
request logging must not print full URLs. URL keys can still enter browser history
or hosting-platform access logs. Filters are not access controls: anyone with the
key can change them and obtain the complete allowed snapshot.

`web/generated/` is ignored by git. Its server-only bootstrap contains the password
digest and pool IDs; private runtime input also contains upstream URLs and derived
node credentials needed for refreshing. Neither contains the root seed, SSH key,
or plaintext web password. The website bundles a pinned standalone Python runtime,
minimal compiler dependencies, and the pinned Sub-Store converter. Node invokes
that same Python compiler with private input on stdin and suppressed diagnostics;
there is no second subscription compiler in TypeScript. Internal file rendering
continues to use the same compiler for smoke and integration checks.
Website builds target Linux amd64, matching the Vercel Node runtime.
Connect an Upstash Redis database to the Vercel project's Production environment
through Marketplace, then redeploy so the function receives the integration's
environment variables. Local development needs the same REST URL/token pair in
its environment; these credentials are never committed or placed in `config.yaml`.

### Native Mihomo Input

The preferred subscription input is the native Mihomo `proxies`,
`proxy-providers`, and `proxy-groups` keys at the root of `config.yaml`, beside
`secret` and the optional deployment `cluster`. No `sources`, multi-document
YAML, custom routing language, or configurable output registry is introduced.
The existing three profile IDs, filenames, DNS, and rule templates remain unchanged. `linux-server.yaml` routes all traffic through `PROXY` using
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
  With no custom groups or automatic exit/pool configuration, the existing `PROXY` and `AUTO`
  defaults remain.
- `exits`: an optional nonempty ordered list of inline provider names.
- `pools`: a nonempty mapping from stable positive numeric IDs to provider names,
  configured together with `exits`. IDs may be quoted or unquoted in YAML; they
  cannot have leading zeros or be reused. Provider names cannot repeat. Reordering
  this mapping does not change which collection an `includeN` parameter filters.
  Explicit `proxy-groups` cannot be combined with automatic exits/pools.

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
the refresh. Previously successful snapshots follow the freshness policy above.

Quantumult X keeps the existing supported-node conversion contract below.
Unsupported nodes and their group memberships are omitted with a count; a group
left empty fails generation. `select` maps to `static`, and `url-test` to
`url-latency-benchmark`. `PROXY` maps to the existing QX policy `Reef`. Latency
groups support `url`, `interval`, `timeout` (up to 5000 ms), `tolerance`, and
`lazy`; they must use one common probe URL and timeout for QX's general settings.
QX's `server_check_url` requires HTTP. Reef maps its built-in
`https://www.gstatic.com/generate_204` probe to the HTTP version for QX only;
Mihomo retains HTTPS. Other custom probe URLs must use HTTP for QX export.
An unsupported HTTPS probe fails generation without printing its URL or
replacing artifacts; it is never silently downgraded.
These QX restrictions are checked only when generating QX; the Mihomo preview
allows independent probe settings and latency groups containing other groups.
Other provider/group options, including provider health checks and file
providers, remain unsupported and fail explicitly.

### DNS Routing and Bootstrapping

Both Mihomo profiles use `https://1.1.1.1/dns-query#PROXY` and
`https://8.8.8.8/dns-query#PROXY` for application destination DNS. The explicit
group binding sends Mihomo's DoH connections through the complete selected path:
the intermediate, if any, then the selected exit, then the DNS service. Selecting
a DIRECT exit path still sends DNS through that exit server. Failed proxy paths
must fail DNS resolution rather than retry through a direct resolver. There is
no direct `fallback` or application `nameserver-policy` override.

Startup resolution is separate to avoid circular dependencies. The encrypted,
IP-addressed `default-nameserver`, `https://223.5.5.5/dns-query`, resolves DNS
server hostnames. `proxy-server-nameserver` resolves proxy hostnames through
`https://223.5.5.5/dns-query#DIRECT` and `https://doh.pub/dns-query#DIRECT`.
These explicit direct queries are limited to bootstrapping and proxy addresses;
neither resolver list is a fallback for application DNS. Proxy startup must not
require direct access to Cloudflare/Google DoH, which may be unreachable locally.

The rule-based profile also uses those two direct DoH services as
`direct-nameserver`, only for resolution by an outbound already routed to the
built-in `DIRECT` policy. It does not send domain queries directly based on a
domestic `nameserver-policy` before deciding the traffic route. The global
profile has no direct application resolver. Existing traffic rules and fake-IP
behavior remain unchanged.

This contract covers DNS issued by Mihomo. It does not configure DNS on remote
proxy servers when a protocol sends them a destination hostname, or an
application's independent DNS implementation. Verify the generated settings
with native Mihomo tests for domain-based proxy startup, direct and two-hop exit
paths, and failure without direct DNS fallback. These settings follow
[Mihomo's DNS routing semantics](https://wiki.metacubex.one/en/config/dns/).

### Mihomo Client-side Relay

The first relay milestone publishes Mihomo profiles with selectable exit/pool
paths. Nodes are ordinary protocol endpoints, regardless of which side of a chain
uses them. A proxy's native `dialer-proxy` names another
proxy or a selection group. It belongs on the **exit** endpoint:

```text
client -> selected path's pool node -> selected path's exit -> destination
```

This follows [Mihomo's native dialer-proxy semantics](https://wiki.metacubex.one/config/proxies/dialer-proxy/).
`config.mihomo.example.yaml` illustrates two fictional exits with separate direct
and relayed paths. Public examples use independent placeholder names, addresses,
and credentials; they must not disclose private operator names or locations.

Use `proxy-providers` for filtered subscription collections and inline endpoint
collections. For automatic groups, each exit is one inline provider whose key is
its display name, such as `Endpoint A`. The payload contains ordinary endpoints,
for example `Trojan` and `Hysteria2`. Define collection roles once:

```yaml
web:
  password: "replace-with-an-independent-random-access-key"
exits: [Endpoint A, Endpoint B]
pools:
  1: pool-a
  2: pool-b
```

There is no per-exit `relay` mapping or separate display alias. Every exit uses
every listed pool, in configuration order. All providers must exist. An exit
cannot also be a pool and must not already set `dialer-proxy` in its payload or
override. Pools can be inline or HTTP providers. Rename a provider key and its
reference together; generated names follow automatically.

For each exit, Reef makes one copy of its filtered endpoints for each configured
pool, plus one direct copy. DIRECT copies have no `dialer-proxy`; each RELAY copy
points directly to `POOL | <pool name>`. Protocol selection and probe history are
independent for every exit/pool path and the direct path. The generated choices
are:

- `PROXY`: each exit's RELAY paths in the supplied pool order, followed by its
  DIRECT path, in exit-list order, then the pools in configured
  pool order. The first path is the default. It is the only generated `select` group;
  there is no separate intermediate selector or implicit direct fallback.
- `RELAY | <provider name> | <pool name>`: connects to this exit through this pool.
- `DIRECT | <provider name>`: connects to this exit without an intermediate.
- `POOL | <provider name>`: one shared `url-test` group for each referenced pool.
  Selecting it in `PROXY` uses its node as the final exit, without an owned exit.

Both RELAY and DIRECT paths follow the same cardinality rule after filtering:
one endpoint produces a proxy with the path's display name; multiple endpoints
produce a `url-test` group with that name. Group members use
`<path name> | <endpoint name>` and preserve each endpoint's protocol settings.
The path's display name stays stable when its endpoint count changes. Empty
collections fail. This decision is recalculated on every generation, without
adding a group around a single endpoint.

Automatic groups use the existing probe defaults. Pool and endpoint names
may be localized in private configuration; public examples use English.
DIRECT exit paths still use the exit server as their public exit. They are
unrelated to Mihomo's built-in `DIRECT`, which bypasses proxying entirely.

Without automatic exits/pools, explicit native `proxy-groups` including `PROXY` remain supported
for manually defined chains. Only the native `dialer-proxy` field creates the
connection; group names alone have no chaining behavior. Inline and HTTP providers
can use `override.dialer-proxy` to share a defined relay group. The generator
preserves the resulting fields in both Mihomo outputs. Do not use `include-all`
for relay selectors: it can create a cycle or offer an unintended exit. A manual
relay can be a concrete node, a manual group, or a `url-test` group. Both node and
group references are checked together for missing targets and cycles, including
candidates that are not selected initially. There is no implicit direct fallback.

Selecting one path in `PROXY` determines both the exit and its intermediate pool.
Automatic groups remain visible so a client can pin a particular member. All
references to the same pool share its current node, whether used as an exit or as an
intermediate. Combined pools keep their own selection across their explicitly
listed subscriptions. Automatic pool tests measure the intermediate's own
connection, not every possible intermediate/exit combination.

The fictional endpoints demonstrate VLESS Reality, Trojan, and Hysteria2.
Protocol selection is independent for direct paths and each exit/pool path.
Hysteria2 exits require a relay capable of carrying their UDP transport. Exit
probes include the pool's currently selected intermediate; they do not search
every possible pairing.
Actual protocol, destination-port, and UDP support still depend on both services;
successful configuration validation is not an end-to-end connectivity test.
Existing Reef-managed entry ports already forward through a fixed exit and are
not used as ordinary intermediates in this example. A standalone exit definition
must match the deployed endpoint; if its server credentials change, update it.

Use `just web-dev` for local preview and `just web-deploy` to publish configuration
changes. Force update refreshes subscription data without deployment.
The global and rule-based Mihomo templates keep their existing behavior.
The rule-based profile can still route China destinations directly; only traffic
assigned to `PROXY` uses the chain. Non-chain configurations retain QX export
using the existing conversion contract.

### Quantumult X Client-side Relay

Automatic `exits` and `pools` also generate a QX configuration. QX uses three
selection levels because its rule-based relay cannot distinguish copies of the
same exit address by node tag:

- `Reef` selects `EXIT | <exit name>` or `POOL | <pool name>`.
- `RELAY | <exit name>` selects any configured pool or `direct`. The first pool
  is the default; direct is an explicit choice, never a failure fallback.
- Each `POOL | <pool name>` automatically selects one compatible member. This
  group is shared between exits and can itself be selected in `Reef`.

An EXIT with one compatible endpoint is a node. With multiple compatible
endpoints it is a `url-latency-benchmark` group. Unsupported protocols/options
are omitted visibly. Every exit and every request-filtered pool must retain at
least one compatible endpoint. The preview shows the exported choices and relay
selectors, while unsupported endpoints remain visible. The same `includeN`
filters apply before QX compatibility filtering; a resulting empty pool blocks
export rather than changing the chain.

Proxy traffic rules use `via-interface=%TUN%`. Endpoint-address rules route the
resulting exit connection through its RELAY selector without reinjecting it.
Pool-address rules use `direct`, so selecting a pool in Reef does not recurse.
All rule resources listed by the existing template are fetched during the shared
refresh and served by authenticated Reef URLs, with their assigned policies and
relay flags. No client-side resource parser is required. Fetch/parse failures
abort the refresh. Internal offline rendering retains embedded proxy rules.
Node domains are resolved once per refresh to one IPv4 address, or IPv6 when
IPv4 is unavailable, preserving the original TLS SNI and WebSocket Host. These
QX-only address snapshots avoid routing loops caused by endpoint DNS changes;
Force update refreshes them. Mihomo retains its original node addresses and DNS.

Different exits cannot share a resolved address, and an exit cannot share one
with a pool. Such ambiguous topologies block QX export without exposing addresses
in preview errors. Multiple protocols of the same exit may share an address.
Only automatic two-hop paths are compiled; arbitrary native `dialer-proxy`
chains still require Mihomo.

Use QX filter mode. Its internal endpoint probes do not establish that a complete
relay path works; automatic choices are based on QX's own measurements. Native
client verification must check network activity for both hops and the observed
exit address. This does not change QX's existing DNS settings or promise Mihomo's
explicit DoH-through-PROXY contract: QX uses its own remote destination resolution
and local DNS for rule evaluation. No claim of native connectivity is made by
the preview or generator tests.

This follows the [QX relay mechanism](https://github.com/crossutility/Quantumult-X/issues/100)
and [QX policy/node syntax](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf).

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
poller: authenticated requests refresh expired hosted data, while internal
subscription rendering fetches fresh nodes directly. Website builds only package
inputs. Upstream URLs may contain credentials and stay in private configuration
and server-only compiler input.

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
cluster settings, web password, upstream URLs, and standalone nodes. It uses the same schema
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
web:
  password: "replace-with-an-independent-random-access-key"
proxy-providers:
  upstream-a:
    type: http
    url: "https://subscription.example.com/private-clash-url"
  upstream-b:
    type: http
    url: "https://another.example.com/private-clash-url"
```
