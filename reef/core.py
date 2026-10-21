from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from subscriptions.extension import parse_extend_nodes
from subscriptions.mihomo import INPUT_KEYS, load_providers as load_proxy_providers, validate_input
from subscriptions.upstream import (
    load_nodes as load_upstream_nodes,
    quantumult_x_nodes,
)


ROOT = Path(__file__).resolve().parents[1]
REMOTE_DIR = "/opt/reef"
SECRET_RE = re.compile(r"^[0-9a-f]{64}$")
ENTRY_OVERRIDE_ADDRESS = "127.0.0.1"
CONFIG_FIELDS = {"secret", "ssh_private_key", "cluster", "subscriptions"} | INPUT_KEYS
# NIST P-256 group order. cryptography exposes SECP256R1(), but not the scalar
# field order needed to derive a deterministic private key from the root seed.
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


@dataclass(frozen=True)
class Node:
    id: str
    ip: str
    index: int
    role: str


@dataclass(frozen=True)
class NodeSecret:
    password: str
    cert_pem: str
    key_pem: str
    fingerprint: str


@dataclass(frozen=True)
class Route:
    id: str
    name: str
    kind: str
    server: Node
    exit: Node
    port: int
    entry: Node | None = None


@dataclass(frozen=True)
class Config:
    secret_hex: str
    entries: list[Node]
    exits: list[Node]
    entry_port_base: int
    exit_port: int
    ssh_private_key: str | None
    smoke_url: str
    entry_override_base_domain: str | None
    upstream_urls: list[str]
    extend_proxies: list[dict[str, Any]]
    proxy_providers: dict[str, dict[str, Any]]
    proxy_groups: list[dict[str, Any]]


@dataclass(frozen=True)
class Model:
    config: Config
    nodes: list[Node]
    routes: list[Route]
    secrets: dict[str, NodeSecret]
    providers: list[dict[str, Any]]


def project_path(*parts: str) -> Path:
    return ROOT.joinpath(*parts)


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def _write_private(path: Path, content: str | bytes, mode: int = 0o600) -> None:
    _ensure_private_dir(path.parent)
    data = content if isinstance(content, bytes) else content.encode()
    path.write_bytes(data)
    path.chmod(mode)


def _sha256(content: str | bytes) -> str:
    data = content if isinstance(content, bytes) else content.encode()
    return hashlib.sha256(data).hexdigest()


def is_ci() -> bool:
    value = os.environ.get("CI", "").strip().lower()
    return value not in {"", "0", "false", "no"}


def _require_test_mode(name: str) -> None:
    if os.environ.get("REEF_TEST_MODE") != "1":
        raise ValueError(f"{name} is only allowed when REEF_TEST_MODE=1")


class _ConfigLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict:
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("config.yaml keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


class _ConfigDumper(yaml.SafeDumper):
    pass


def _config_string(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_ConfigDumper.add_representer(str, _config_string)


def config_path() -> Path:
    return _env_path("TEST_CONFIG_FILE") or project_path("config.yaml")


def parse_config_yaml(content: str | bytes) -> dict[str, Any]:
    try:
        document = yaml.load(content, Loader=_ConfigLoader)
    except (yaml.YAMLError, UnicodeError):
        raise ValueError("config.yaml must be valid YAML") from None
    return _config_mapping(document, CONFIG_FIELDS, "config.yaml")


def load_config(path: Path | None = None) -> dict[str, Any]:
    try:
        content = (path or config_path()).read_bytes()
    except OSError:
        raise ValueError("config.yaml could not be read") from None
    return parse_config_yaml(content)


def dump_config(document: dict[str, Any]) -> str:
    return yaml.dump(document, Dumper=_ConfigDumper, sort_keys=False, allow_unicode=True)


def write_config(document: dict[str, Any], path: Path | None = None) -> None:
    content = dump_config(document)
    fd = os.open(path or config_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(content)


def _config_mapping(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - fields:
        raise ValueError(f"{label} must be a mapping containing only documented fields")
    return value


def parse_config(values: dict[str, Any], *, require_ssh: bool = False) -> Config:
    values = _config_mapping(values, CONFIG_FIELDS, "config.yaml")
    secret = values.get("secret")
    if not isinstance(secret, str) or not SECRET_RE.fullmatch(secret):
        raise ValueError("secret must be a string of exactly 64 lowercase hex characters")
    cluster = _config_mapping(values.get("cluster", {}), {
        "entries", "exits", "entry_port_base", "exit_port", "entry_override_base_domain",
    }, "cluster")
    subscriptions = _config_mapping(values.get("subscriptions", {}), {"upstream_urls", "nodes"}, "subscriptions")
    if "subscriptions" in values and INPUT_KEYS.intersection(values):
        raise ValueError("subscriptions cannot be mixed with native Mihomo input keys")
    validate_input(values)
    entries = _parse_nodes(cluster.get("entries", []), "entry")
    exits = _parse_nodes(cluster.get("exits", []), "exit")
    upstream_urls = _parse_upstream_urls(subscriptions.get("upstream_urls", []))
    extend_proxies = parse_extend_nodes(subscriptions.get("nodes", []))
    extend_proxies.extend(values.get("proxies", []))
    proxy_providers = values.get("proxy-providers", {})
    if not exits and (entries or not (upstream_urls or extend_proxies or proxy_providers)):
        raise ValueError("cluster.exits requires at least one node unless using standalone subscriptions")
    if require_ssh and not exits:
        raise ValueError("deployment recipes require a Reef cluster with at least one node in cluster.exits")

    names = [n.id for n in [*entries, *exits]]
    if len(set(names)) != len(names):
        raise ValueError("cluster node names must be unique")

    entry_port_base = _parse_port(cluster.get("entry_port_base", 20000), "cluster.entry_port_base")
    exit_port = _parse_port(cluster.get("exit_port", 443), "cluster.exit_port")
    ssh_key = values.get("ssh_private_key")
    if "ssh_private_key" in values:
        validate_ssh_private_key(ssh_key)
    if require_ssh and not ssh_key:
        raise ValueError("ssh_private_key is required for deployment recipes")

    entry_override_base_domain = _parse_optional_domain(
        cluster.get("entry_override_base_domain", ""), "cluster.entry_override_base_domain",
    )
    if entry_override_base_domain and not entries:
        raise ValueError("cluster.entry_override_base_domain requires at least one entry")

    return Config(
        secret_hex=secret,
        entries=entries,
        exits=exits,
        entry_port_base=entry_port_base,
        exit_port=exit_port,
        ssh_private_key=ssh_key,
        smoke_url="https://api.ipify.org",
        entry_override_base_domain=entry_override_base_domain,
        upstream_urls=upstream_urls,
        extend_proxies=extend_proxies,
        proxy_providers=proxy_providers,
        proxy_groups=values.get("proxy-groups", []),
    )


def _parse_upstream_urls(values: Any) -> list[str]:
    if not isinstance(values, list):
        raise ValueError("subscriptions.upstream_urls must be a list")
    urls = []
    for index, value in enumerate(values, start=1):
        url = value.strip() if isinstance(value, str) else ""
        try:
            parsed_url = urlsplit(url)
            valid_url = (
                parsed_url.scheme in {"http", "https"}
                and parsed_url.hostname
                and (parsed_url.port is None or 1 <= parsed_url.port <= 65535)
            )
        except ValueError:
            valid_url = False
        if not valid_url or any(c.isspace() or ord(c) < 32 for c in url):
            raise ValueError(f"upstream URL #{index} must be an HTTP(S) subscription URL")
        urls.append(url)
    return urls


def _parse_nodes(values: Any, role: str) -> list[Node]:
    label = "cluster.entries" if role == "entry" else "cluster.exits"
    if not isinstance(values, list):
        raise ValueError(f"{label} must be a list")
    nodes = []
    for index, value in enumerate(values, start=1):
        node = _config_mapping(value, {"name", "ip"}, f"{label} node {index}")
        name, ip = node.get("name"), node.get("ip")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise ValueError(f"{label} node {index} name must match [a-z][a-z0-9-]*")
        try:
            if not isinstance(ip, str):
                raise ValueError
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"{label} node {index} must have a valid IP address") from None
        nodes.append(Node(id=name, ip=ip, index=index, role=role))
    return nodes


def _parse_port(value: Any, name: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    if not 1 <= value <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return value


def _parse_optional_domain(value: str, name: str) -> str | None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a domain name like example.com")
    domain = value.strip().lower()
    if not domain:
        return None
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253:
        raise ValueError(f"{name} must be a domain name like example.com")
    for label in labels:
        if (
            not 1 <= len(label) <= 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.match(r"^[a-z0-9-]+$", label)
        ):
            raise ValueError(f"{name} must be a domain name like example.com")
    if labels[-1].isdigit():
        raise ValueError(f"{name} must be a domain name like example.com")
    return domain


def validate_ssh_private_key(value: Any) -> None:
    try:
        if not isinstance(value, str):
            raise ValueError
        serialization.load_ssh_private_key(value.encode(), password=None)
    except (ValueError, TypeError):
        raise ValueError("ssh_private_key must be an unencrypted OpenSSH private key") from None


def detect_provider_ids() -> list[str]:
    provider_root = project_path("providers")
    ids = sorted(
        path.name
        for path in provider_root.iterdir()
        if path.is_dir() and (path / "provider.yaml").exists()
    )
    if not ids:
        raise ValueError("no provider bundle found")
    return ids


def load_provider(provider_id: str) -> dict[str, Any]:
    path = project_path("providers", provider_id, "provider.yaml")
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a mapping")
    if data.get("id") != provider_id:
        raise ValueError(f"{path} id must match provider directory name")
    return data


def load_providers(provider_ids: list[str] | None = None) -> list[dict[str, Any]]:
    return [load_provider(provider_id) for provider_id in (provider_ids or detect_provider_ids())]


def build_model(config: Config, provider_ids: list[str] | None = None) -> Model:
    nodes = [*config.entries, *config.exits]
    providers = load_providers(provider_ids)
    routes: list[Route] = []
    for entry in config.entries:
        for exit_node in config.exits:
            route_id = f"{entry.id}-{exit_node.id}"
            routes.append(
                Route(
                    id=route_id,
                    name=f"{entry.id} -> {exit_node.id}",
                    kind="relay",
                    entry=entry,
                    exit=exit_node,
                    server=entry,
                    port=config.entry_port_base + exit_node.index - 1,
                )
            )
    for exit_node in config.exits:
        routes.append(
            Route(
                id=f"{exit_node.id}-direct",
                name=f"{exit_node.id} direct",
                kind="direct",
                server=exit_node,
                exit=exit_node,
                port=config.exit_port,
            )
        )

    validate_providers(providers, routes)
    secret_bytes = bytes.fromhex(config.secret_hex)
    secrets = {node.id: derive_node_secret(secret_bytes, node) for node in nodes}
    return Model(config=config, nodes=nodes, routes=routes, secrets=secrets, providers=providers)


def derive_bytes(secret: bytes, label: str, *parts: str, length: int = 32) -> bytes:
    info = "reef/v1/" + label
    if parts:
        info += "/" + "/".join(parts)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"reef",
        info=info.encode(),
    )
    return hkdf.derive(secret)


def derive_text(secret: bytes, label: str, *parts: str, length: int = 32) -> str:
    raw = derive_bytes(secret, label, *parts, length=length)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def derive_node_secret(secret: bytes, node: Node) -> NodeSecret:
    password = derive_text(secret, "node-password", node.id, length=32)
    # Use a 384-bit HKDF output before reducing into the P-256 scalar range.
    # That keeps the modulo bias negligible while preserving deterministic
    # rendering across local, CI, remote node, and Web subscription builds.
    key_seed = derive_bytes(secret, "node-tls-key", node.id, length=48)
    private_value = int.from_bytes(key_seed, "big") % (P256_ORDER - 1) + 1
    key = ec.derive_private_key(private_value, ec.SECP256R1())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, node.id),
        ]
    )
    serial_raw = bytearray(derive_bytes(secret, "node-tls-serial", node.id, length=20))
    serial_raw[0] &= 0x7F
    serial = int.from_bytes(serial_raw, "big") or 1
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2126, 1, 1, tzinfo=dt.timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(node.ip))]),
            critical=False,
        )
        .sign(key, algorithm=hashes.SHA256(), ecdsa_deterministic=True)
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    der = cert.public_bytes(serialization.Encoding.DER)
    digest = hashlib.sha256(der).hexdigest()
    fingerprint = ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
    return NodeSecret(
        password=password,
        cert_pem=cert_pem,
        key_pem=key_pem,
        fingerprint=fingerprint,
    )


def provider_runtimes(model: Model) -> list[dict[str, str]]:
    runtimes = []
    seen_dests: dict[str, str] = {}
    for provider in model.providers:
        runtime = provider.get("runtime")
        if not isinstance(runtime, dict):
            raise ValueError(f"{provider['id']} provider.yaml must declare runtime")
        runtime_src = project_path(runtime["local_path"])
        runtime_dest = _render_inline(runtime["remote_path"], {"remote_dir": REMOTE_DIR})
        previous = seen_dests.get(runtime_dest)
        if previous:
            raise ValueError(
                f"providers {previous} and {provider['id']} both install runtime to {runtime_dest}"
            )
        seen_dests[runtime_dest] = str(provider["id"])
        runtimes.append(
            {
                "id": str(provider["id"]),
                "src": str(runtime_src),
                "dest": runtime_dest,
            }
        )
    return runtimes


def validate_providers(providers: list[dict[str, Any]], routes: list[Route]) -> None:
    ids = [str(provider["id"]) for provider in providers]
    duplicate_ids = sorted({provider_id for provider_id in ids if ids.count(provider_id) > 1})
    if duplicate_ids:
        raise ValueError(f"duplicate provider id(s): {', '.join(duplicate_ids)}")

    runtime_dests: dict[str, str] = {}
    port_claims: dict[tuple[str, str, int], str] = {}
    for provider in providers:
        provider_id = str(provider["id"])
        runtime = provider.get("runtime")
        if not isinstance(runtime, dict):
            raise ValueError(f"{provider_id} provider.yaml must declare runtime")
        runtime_dest = _render_inline(runtime["remote_path"], {"remote_dir": REMOTE_DIR})
        previous_runtime = runtime_dests.get(runtime_dest)
        if previous_runtime:
            raise ValueError(
                f"providers {previous_runtime} and {provider_id} both install runtime to "
                f"{runtime_dest}"
            )
        runtime_dests[runtime_dest] = provider_id

        service_templates = provider.get("services", {})
        if not isinstance(service_templates, dict):
            raise ValueError(f"{provider_id} provider.yaml services must be a mapping")
        for kind, templates in service_templates.items():
            if kind not in {"relay", "direct"}:
                raise ValueError(f"{provider_id} provider.yaml services.{kind} is unsupported")
            if not isinstance(templates, list):
                raise ValueError(f"{provider_id} provider.yaml services.{kind} must be a list")
            if templates:
                _provider_route_protocol(provider, kind)

        for route in routes:
            templates = service_templates.get(route.kind, [])
            if not templates:
                continue
            protocol = _provider_route_protocol(provider, route.kind)
            claim_key = (route.server.id, protocol, route.port)
            previous_provider = port_claims.get(claim_key)
            if previous_provider:
                raise ValueError(
                    f"providers {previous_provider} and {provider_id} both claim "
                    f"{protocol} {route.server.id}:{route.port}"
                )
            port_claims[claim_key] = provider_id


def render_ansible(model: Model, ssh_map_path: Path | None = None) -> None:
    build = project_path("build")
    ansible_dir = build / "ansible"
    nodes_dir = build / "nodes"
    _ensure_private_dir(build)
    _ensure_private_dir(ansible_dir)
    _ensure_private_dir(nodes_dir)
    ssh_map = _load_json_file(ssh_map_path or _env_path("TEST_SSH_MAP"))

    runtimes = provider_runtimes(model)

    ssh_dir = build / "ssh"
    _ensure_private_dir(ssh_dir)
    known_hosts = ssh_dir / "known_hosts"
    if not known_hosts.exists():
        _write_private(known_hosts, "")

    if model.config.ssh_private_key:
        key_path = ssh_dir / "reef_id"
        _write_private(key_path, model.config.ssh_private_key)
    else:
        key_path = ssh_dir / "reef_id"

    ssh_common_args = _ssh_common_args(known_hosts)

    inventory: dict[str, Any] = {
        "all": {
            "vars": {
                "ansible_user": "root",
                "ansible_python_interpreter": "auto_silent",
                "ansible_ssh_private_key_file": str(key_path),
                "ansible_ssh_common_args": ssh_common_args,
            },
            "hosts": {},
        }
    }

    for node in model.nodes:
        host = _node_ssh_host(node, ssh_map)
        files, services, desired, deploy_items = render_node_files(
            model,
            node,
            nodes_dir / node.id,
        )
        manifest_prefix = desired["marker"]["manifestHash"].removeprefix("sha256:")[:16]
        host_vars: dict[str, Any] = {
            "ansible_host": host["host"],
            "ansible_port": host["port"],
            "reef_node": {
                "id": node.id,
                "role": node.role,
                "remote_dir": REMOTE_DIR,
                "runtimes": runtimes,
                "files": files,
                "services": services,
                "desired": desired,
                "deploy_items": deploy_items,
                "stage_dir": f"/tmp/reef-{node.id}-{manifest_prefix}",
            },
        }
        if node.role == "exit" and model.config.entries:
            jump = _node_ssh_host(model.config.entries[0], ssh_map)
            proxy = (
                f"ssh -i {key_path} {ssh_common_args} "
                f"-W %h:%p -p {jump['port']} root@{jump['host']}"
            )
            host_vars["ansible_ssh_common_args"] = (
                f"{ssh_common_args} -o ProxyCommand=\"{proxy}\""
            )
        inventory["all"]["hosts"][node.id] = host_vars

    _write_private(ansible_dir / "inventory.yml", yaml.safe_dump(inventory, sort_keys=False))


def render_node_files(
    model: Model,
    node: Node,
    out_dir: Path,
) -> tuple[list[dict[str, str]], list[str], dict[str, Any], list[dict[str, str]]]:
    if out_dir.exists():
        for path in sorted(out_dir.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
    _ensure_private_dir(out_dir)

    node_secret = model.secrets[node.id]
    files: list[dict[str, str]] = []
    file_manifest: list[dict[str, str]] = []
    seen_dests: dict[str, tuple[str, str]] = {}
    seen_sources: dict[Path, tuple[str, str]] = {}

    def add(rel: str, dest: str, content: str | bytes, mode: str = "0644") -> None:
        src = out_dir / rel
        content_hash = _sha256(content)
        signature = (mode, content_hash)
        existing_dest = seen_dests.get(dest)
        if existing_dest:
            if existing_dest != signature:
                raise ValueError(f"{node.id}: generated file destination conflict: {dest}")
            existing_source = seen_sources.get(src)
            if existing_source and existing_source != signature:
                raise ValueError(f"{node.id}: generated file source conflict: {src}")
            seen_sources[src] = signature
            return
        existing_source = seen_sources.get(src)
        if existing_source and existing_source != signature:
            raise ValueError(f"{node.id}: generated file source conflict: {src}")
        _write_private(src, content)
        seen_dests[dest] = signature
        seen_sources[src] = signature
        files.append(
            {
                "id": _deploy_item_id(dest),
                "src": str(src),
                "dest": dest,
                "mode": mode,
                "sha256": content_hash,
            }
        )
        file_manifest.append({"dest": dest, "mode": mode, "sha256": content_hash})

    add("certs/server.crt", f"{REMOTE_DIR}/certs/server.crt", node_secret.cert_pem)
    add("certs/server.key", f"{REMOTE_DIR}/certs/server.key", node_secret.key_pem, "0600")

    routes = routes_for_node(model, node)

    for exit_node in model.config.exits:
        if node.role == "entry":
            exit_secret = model.secrets[exit_node.id]
            add(
                f"certs/exit-{exit_node.id}.crt",
                f"{REMOTE_DIR}/certs/exit-{exit_node.id}.crt",
                exit_secret.cert_pem,
            )

    for provider in model.providers:
        provider_dir = project_path("providers", str(provider["id"]))
        env = Environment(
            loader=FileSystemLoader(str(provider_dir)),
            undefined=StrictUndefined,
            keep_trailing_newline=True,
            autoescape=False,
        )
        context_base = {
            "remote_dir": REMOTE_DIR,
            "node": _node_dict(node, model),
            "routes": [_route_dict(model, r, provider) for r in routes],
            "all_routes": [_route_dict(model, r, provider) for r in model.routes],
        }
        context_base.update(_provider_template_vars(provider, context_base))

        for spec in provider.get("node_files", []):
            role = spec.get("role", "all")
            if role not in {"all", node.role}:
                continue
            per = spec.get("per", "node")
            if per == "node":
                items = [None]
            elif per == "relay":
                items = [r for r in routes if r.kind == "relay"]
            elif per == "direct":
                items = [r for r in routes if r.kind == "direct"]
            else:
                raise ValueError(f"unsupported provider per={per!r}")
            template = env.get_template(spec["template"])
            for route in items:
                ctx = dict(context_base)
                if route is not None:
                    ctx["route"] = _route_dict(model, route, provider)
                rel = _render_inline(spec["output"], ctx)
                dest = _render_inline(spec["dest"], ctx)
                add(rel, dest, template.render(ctx), spec.get("mode", "0644"))

    services = service_names_for_node(model, node)
    runtime_manifest = []
    deploy_runtimes = []
    for provider in model.providers:
        runtime = provider["runtime"]
        runtime_path = project_path(runtime["local_path"])
        if not runtime_path.exists():
            raise ValueError(f"missing runtime {runtime_path}; run just vendor")
        runtime_hash = hashlib.sha256(runtime_path.read_bytes()).hexdigest()
        runtime_dest = _render_inline(runtime["remote_path"], {"remote_dir": REMOTE_DIR})
        runtime_manifest.append(
            {
                "id": str(provider["id"]),
                "dest": runtime_dest,
                "sha256": runtime_hash,
            }
        )
        deploy_runtimes.append(
            {
                "id": _deploy_item_id(runtime_dest),
                "src": str(runtime_path),
                "dest": runtime_dest,
                "mode": "0755",
                "sha256": runtime_hash,
            }
        )
    marker = {
        "managedBy": "reef",
        "schemaVersion": 1,
        "nodeId": node.id,
        "role": node.role,
        "services": services,
        "files": [item["dest"] for item in files],
        "fileManifest": file_manifest,
        "runtimes": runtime_manifest,
    }
    marker["manifestHash"] = "sha256:" + hashlib.sha256(
        json.dumps(
            {
                "files": file_manifest,
                "runtimes": marker["runtimes"],
                "services": services,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    add("managed.json", f"{REMOTE_DIR}/.managed.json", json.dumps(marker, indent=2) + "\n")
    item_services = _infer_item_services(files, deploy_runtimes, services)
    deploy_items = [*files, *deploy_runtimes]
    desired = {
        "remoteDir": REMOTE_DIR,
        "marker": marker,
        "items": [
            {
                "id": item["id"],
                "dest": item["dest"],
                "mode": item["mode"],
                "sha256": item["sha256"],
                "services": sorted(item_services.get(item["dest"], set())),
                "systemd": _is_systemd_unit_path(item["dest"]),
            }
            for item in deploy_items
        ],
    }
    return files, services, desired, deploy_items


def _deploy_item_id(dest: str) -> str:
    return "item-" + hashlib.sha256(dest.encode()).hexdigest()[:16]


def _infer_item_services(
    files: list[dict[str, str]],
    runtimes: list[dict[str, str]],
    services: list[str],
) -> dict[str, set[str]]:
    items = [*files, *runtimes]
    by_dest = {item["dest"]: item for item in items}
    all_dests = set(by_dest)
    result: dict[str, set[str]] = {dest: set() for dest in all_dests}

    for service in services:
        direct = set()
        unit_dest = _unit_dest_for_service(service)
        if unit_dest in by_dest:
            direct.add(unit_dest)
            direct.update(
                _referenced_dests(
                    Path(by_dest[unit_dest]["src"]),
                    all_dests,
                    instance=_service_instance(service),
                )
            )

        seen = set()
        pending = list(direct)
        while pending:
            dest = pending.pop()
            if dest in seen:
                continue
            seen.add(dest)
            item = by_dest.get(dest)
            if item and item.get("src") and not _is_systemd_unit_path(dest):
                pending.extend(_referenced_dests(Path(item["src"]), all_dests) - seen)

        for dest in seen:
            result.setdefault(dest, set()).add(service)

    return result


def _referenced_dests(path: Path, dests: set[str], *, instance: str | None = None) -> set[str]:
    try:
        content = path.read_text(errors="ignore")
    except UnicodeDecodeError:
        return set()
    if instance is not None:
        content = content.replace("%i", instance).replace("%I", instance)
    return {dest for dest in dests if dest in content}


def _unit_dest_for_service(service: str) -> str:
    name = service.removesuffix(".service")
    if "@" in name:
        prefix = name.split("@", 1)[0]
        return f"/etc/systemd/system/{prefix}@.service"
    return f"/etc/systemd/system/{name}.service"


def _service_instance(service: str) -> str | None:
    name = service.removesuffix(".service")
    if "@" not in name:
        return None
    return name.split("@", 1)[1]


def _is_systemd_unit_path(path: str) -> bool:
    return re.fullmatch(r"/etc/systemd/system/reef-[A-Za-z0-9_.@-]+\.service", path) is not None


def routes_for_node(model: Model, node: Node) -> list[Route]:
    if node.role == "entry":
        return [r for r in model.routes if r.entry and r.entry.id == node.id]
    return [r for r in model.routes if r.kind == "direct" and r.exit.id == node.id]


def service_names_for_node(model: Model, node: Node) -> list[str]:
    services: list[str] = []
    for provider in model.providers:
        service_templates = provider.get("services", {})
        if not isinstance(service_templates, dict):
            raise ValueError(f"{provider['id']} provider.yaml services must be a mapping")
        for route in routes_for_node(model, node):
            templates = service_templates.get(route.kind, [])
            if not isinstance(templates, list):
                raise ValueError(
                    f"{provider['id']} provider.yaml services.{route.kind} must be a list"
                )
            route_data = _route_dict(model, route, provider)
            for template in templates:
                context = {"route": route_data, "node": _node_dict(node, model)}
                services.append(
                    _render_inline(str(template), context)
                )
    return services


def render_subscriptions(
    model: Model, host_map_path: Path | None = None, *, mihomo_only: bool = False,
) -> list[dict[str, str]]:
    build_dir = project_path("build", "subscriptions")
    _ensure_private_dir(project_path("build"))
    _ensure_private_dir(build_dir)
    if mihomo_only:
        build_dir = build_dir / "mihomo"
        _ensure_private_dir(build_dir)
    host_map = _load_json_file(host_map_path or _env_path("TEST_HOST_MAP"))
    renderer = load_subscription_renderer()
    context = subscription_context(model, host_map)
    context["upstream_proxies"] = load_upstream_nodes(
        model.config.upstream_urls, model.config.extend_proxies
    )
    context["top_proxy_names"] = [node["name"] for node in context["upstream_proxies"]]
    provider_nodes, context["provider_members"] = load_proxy_providers(model.config.proxy_providers)
    nodes_by_name = {node["name"]: node for node in context["upstream_proxies"]}
    for node in provider_nodes:
        if node["name"] in nodes_by_name and nodes_by_name[node["name"]] != node:
            raise ValueError("proxy-provider node conflicts with a top-level proxy")
        nodes_by_name.setdefault(node["name"], node)
    context["upstream_proxies"] = list(nodes_by_name.values())
    has_chain = any("dialer-proxy" in node for node in context["upstream_proxies"])
    omitted = []
    if mihomo_only or has_chain:
        omitted = [p for p in context["profiles"] if p["id"] == "quantumult-x"]
        context["profiles"] = [p for p in context["profiles"] if p not in omitted]
    else:
        context["qx_upstream"] = quantumult_x_nodes(context["upstream_proxies"])
    rendered = renderer.render(context)
    if hasattr(renderer, "validate"):
        renderer.validate(rendered, context)

    profiles = []
    for profile in rendered:
        body = profile["body"]
        output = build_dir / profile["output"]
        _write_private(output, body)
        profiles.append(
            {
                "id": profile["id"],
                "token": _subscription_token(model, profile["id"]),
                "output": str(output),
                "content_type": profile.get("content_type", "text/plain; charset=utf-8"),
                "body": body,
            }
        )
    for profile in omitted:
        (build_dir / profile["output"]).unlink(missing_ok=True)
    if has_chain and not mihomo_only:
        print("Quantumult X relay conversion is unavailable; generated Mihomo subscriptions only.", file=sys.stderr)
    return profiles


def _subscription_token(model: Model, profile_id: str) -> str:
    return derive_text(bytes.fromhex(model.config.secret_hex), "subscription-url", profile_id, length=24)


def subscription_proxy_metadata(
    model: Model,
    host_map_path: Path | None = None,
    *,
    profile_id: str = "client",
) -> list[dict[str, Any]]:
    renderer = load_subscription_renderer()
    if not hasattr(renderer, "proxy_metadata"):
        raise ValueError("subscription renderer must define proxy_metadata(context, profile_id)")
    host_map = _load_json_file(host_map_path or _env_path("TEST_HOST_MAP"))
    context = subscription_context(model, host_map)
    metadata = renderer.proxy_metadata(context, profile_id=profile_id)
    if not isinstance(metadata, list):
        raise ValueError("subscription proxy metadata must be a list")
    return metadata


def subscription_context(model: Model, host_map: dict[str, Any] | None = None) -> dict[str, Any]:
    routes = []
    for route in model.routes:
        item = _route_dict(model, route)
        mapped = host_map.get(route.id) if host_map else None
        if mapped:
            item["connect"] = {"host": mapped["host"], "port": int(mapped["port"])}
        else:
            item["connect"] = {"host": route.server.ip, "port": route.port}
        routes.append(item)

    return {
        "provider_ids": [str(provider["id"]) for provider in model.providers],
        "profiles": load_subscription_profiles(),
        "routes": routes,
        "entries": [_node_dict(node, model) for node in model.config.entries],
        "exits": [_node_dict(node, model) for node in model.config.exits],
        "entry_override_base_domain": model.config.entry_override_base_domain,
        "upstream_proxies": [],
        "qx_upstream": [],
        "proxy_groups": model.config.proxy_groups,
        "provider_members": {},
        "top_proxy_names": [],
    }


def load_subscription_profiles() -> list[dict[str, Any]]:
    path = project_path("subscriptions", "profiles.yaml")
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict) or not isinstance(data.get("profiles"), list):
        raise ValueError(f"{path} must contain profiles list")
    return data["profiles"]


def load_subscription_renderer():
    path = project_path("subscriptions", "render.py")
    if not path.exists():
        raise ValueError(f"missing subscription renderer: {path}")
    spec = importlib.util.spec_from_file_location(
        "reef_subscription_renderer",
        path,
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load provider subscription renderer: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "render"):
        raise ValueError(f"{path} must define render(context)")
    return module


def render_web(model: Model) -> list[dict[str, str]]:
    profiles = render_subscriptions(model)
    out = project_path("web", "generated", "subscriptions.ts")
    _ensure_private_dir(out.parent)
    items = [
        {
            "id": p["id"],
            "token": p["token"],
            "contentType": p["content_type"],
            "body": p["body"],
            "status": 200,
        }
        for p in profiles
    ]
    if not any(p["id"] == "quantumult-x" for p in profiles):
        items.append({
            "id": "quantumult-x",
            "token": _subscription_token(model, "quantumult-x"),
            "contentType": "text/plain; charset=utf-8",
            "body": "Quantumult X relay conversion is not supported yet. Use a Mihomo subscription.\n",
            "status": 503,
        })
    _write_private(
        out,
        "import 'server-only';\n\n"
        "export type GeneratedSubscription = {\n"
        "  id: string;\n"
        "  token: string;\n"
        "  contentType: string;\n"
        "  body: string;\n"
        "  status: 200 | 503;\n"
        "};\n\n"
        f"export const subscriptions: GeneratedSubscription[] = {json.dumps(items, indent=2)};\n",
    )
    return profiles


def load_model(*, require_ssh: bool = False) -> Model:
    return build_model(parse_config(load_config(), require_ssh=require_ssh))


def _route_dict(
    model: Model,
    route: Route,
    provider: dict[str, Any] | None = None,
) -> dict[str, Any]:
    exit_secret = model.secrets[route.exit.id]
    server_secret = model.secrets[route.server.id]
    data = {
        "id": route.id,
        "name": route.name,
        "kind": route.kind,
        "port": route.port,
        "exit_port": model.config.exit_port,
        "server": _node_dict(route.server, model),
        "entry": _node_dict(route.entry, model) if route.entry else None,
        "exit": _node_dict(route.exit, model),
        "server_password": server_secret.password,
        "server_fingerprint": server_secret.fingerprint,
        "exit_password": exit_secret.password,
        "exit_fingerprint": exit_secret.fingerprint,
        "exit_ca_path": f"{REMOTE_DIR}/certs/exit-{route.exit.id}.crt",
        "stats_secret": derive_text(
            bytes.fromhex(model.config.secret_hex),
            "stats-secret",
            route.id,
            length=24,
        ),
    }
    if provider is not None:
        data.update(_provider_route_vars(provider, route.kind, data))
    return data


def _provider_route_vars(
    provider: dict[str, Any],
    kind: str,
    route_data: dict[str, Any],
) -> dict[str, Any]:
    vars_by_kind = provider.get("route_vars", {})
    vars_for_kind = vars_by_kind.get(kind, {})
    if not isinstance(vars_for_kind, dict):
        raise ValueError(f"{provider['id']} provider route_vars.{kind} must be a mapping")
    rendered: dict[str, Any] = {}
    for key, template in vars_for_kind.items():
        if key in route_data:
            raise ValueError(f"provider route var {key!r} conflicts with core route field")
        rendered[key] = _render_inline(str(template), {"route": route_data})
    return rendered


def _provider_route_protocol(provider: dict[str, Any], kind: str) -> str:
    protocols = provider.get("route_protocols", {})
    if not isinstance(protocols, dict):
        raise ValueError(f"{provider['id']} provider.yaml route_protocols must be a mapping")
    if kind not in protocols:
        raise ValueError(f"{provider['id']} provider.yaml route_protocols.{kind} is required")
    protocol = str(protocols[kind])
    if protocol not in {"tcp", "udp"}:
        raise ValueError(f"{provider['id']} route_protocols.{kind} must be tcp or udp")
    return protocol


def _provider_template_vars(
    provider: dict[str, Any],
    context_base: dict[str, Any],
) -> dict[str, Any]:
    values = provider.get("template_vars", {})
    if not isinstance(values, dict):
        raise ValueError(f"{provider['id']} provider.yaml template_vars must be a mapping")
    conflicts = sorted(set(values) & set(context_base))
    if conflicts:
        raise ValueError(
            f"{provider['id']} provider template var conflicts with core context: "
            f"{', '.join(conflicts)}"
        )
    return values


def _node_dict(node: Node | None, model: Model) -> dict[str, Any] | None:
    if node is None:
        return None
    secret = model.secrets[node.id]
    entry_override_host = None
    entry_override_address = None
    if node.role == "entry" and model.config.entry_override_base_domain:
        entry_override_host = f"{node.id}.{model.config.entry_override_base_domain}"
        entry_override_address = ENTRY_OVERRIDE_ADDRESS
    return {
        "id": node.id,
        "ip": node.ip,
        "index": node.index,
        "role": node.role,
        "password": secret.password,
        "fingerprint": secret.fingerprint,
        "entry_override_host": entry_override_host,
        "entry_override_address": entry_override_address,
    }


def _render_inline(template: str, context: dict[str, Any]) -> str:
    return (
        Environment(undefined=StrictUndefined, autoescape=False)
        .from_string(template)
        .render(context)
    )


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    if value and name.startswith("TEST_"):
        _require_test_mode(name)
    return Path(value) if value else None


def _load_json_file(path: Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    return json.loads(path.read_text())


def _ssh_common_args(known_hosts: Path) -> str:
    if os.environ.get("TEST_DISABLE_SSH_HOST_KEY_CHECK") == "1":
        _require_test_mode("TEST_DISABLE_SSH_HOST_KEY_CHECK")
        return "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes"
    return (
        "-o StrictHostKeyChecking=accept-new "
        f"-o UserKnownHostsFile={known_hosts} "
        "-o IdentitiesOnly=yes"
    )


def _node_ssh_host(node: Node, ssh_map: dict[str, Any] | None) -> dict[str, Any]:
    if ssh_map and node.id in ssh_map:
        item = ssh_map[node.id]
        return {"host": item["host"], "port": int(item.get("port", 22))}
    return {"host": node.ip, "port": 22}
