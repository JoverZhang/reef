from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from jinja2 import Environment, FileSystemLoader, StrictUndefined


ROOT = Path(__file__).resolve().parents[1]
REMOTE_DIR = "/opt/reef"
SECRET_RE = re.compile(r"^[0-9a-f]{64}$")
NODE_RE = re.compile(r"^REEF_(ENTRY|EXIT)_(\d+)$")
# NIST P-256 group order. cryptography exposes SECP256R1(), but not the scalar
# field order needed to derive a deterministic private key from REEF_SECRET.
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
    ssh_private_key_b64: str | None
    smoke_url: str


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


def load_env(path: Path | None = None) -> dict[str, str]:
    env_path = path or Path(os.environ.get("REEF_ENV_FILE", ".env"))
    values: dict[str, str] = {}
    if env_path.exists():
        for line_no, raw in enumerate(env_path.read_text().splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"{env_path}:{line_no}: expected KEY=VALUE")
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in {"'", '"'}
            ):
                value = value[1:-1]
            values[key] = value

    for key, value in os.environ.items():
        if key.startswith("REEF_") or key in {"CI"}:
            values[key] = value
    return values


def parse_config(values: dict[str, str], *, require_ssh: bool = False) -> Config:
    secret = values.get("REEF_SECRET", "")
    if not SECRET_RE.match(secret):
        raise ValueError("REEF_SECRET must be exactly 64 lowercase hex characters")

    entries = _parse_nodes(values, "ENTRY")
    exits = _parse_nodes(values, "EXIT")
    if not exits:
        raise ValueError("at least one REEF_EXIT_N is required")

    names = [n.id for n in [*entries, *exits]]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"duplicate node name(s): {', '.join(duplicates)}")

    entry_port_base = _parse_port(
        values.get("REEF_ENTRY_PORT_BASE", "20000"),
        "REEF_ENTRY_PORT_BASE",
    )
    exit_port = _parse_port(values.get("REEF_EXIT_PORT", "443"), "REEF_EXIT_PORT")
    ssh_key = values.get("REEF_SSH_PRIVATE_KEY_B64")
    if require_ssh and not ssh_key:
        raise ValueError("REEF_SSH_PRIVATE_KEY_B64 is required for deployment recipes")
    if ssh_key:
        _decode_private_key(ssh_key)

    return Config(
        secret_hex=secret,
        entries=entries,
        exits=exits,
        entry_port_base=entry_port_base,
        exit_port=exit_port,
        ssh_private_key_b64=ssh_key,
        smoke_url="https://api.ipify.org",
    )


def _parse_nodes(values: dict[str, str], kind: str) -> list[Node]:
    found: dict[int, str] = {}
    for key, value in values.items():
        m = NODE_RE.match(key)
        if not m or m.group(1) != kind:
            continue
        found[int(m.group(2))] = value
    if not found:
        return []
    expected = list(range(1, max(found) + 1))
    actual = sorted(found)
    if actual != expected:
        raise ValueError(f"REEF_{kind}_N must be consecutive from 1; got {actual}")

    role = "entry" if kind == "ENTRY" else "exit"
    nodes = []
    for index in expected:
        raw = found[index]
        parts = [p.strip() for p in raw.split(",")]
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"REEF_{kind}_{index} must be name,ip")
        name, ip = parts
        if not re.match(r"^[a-z][a-z0-9-]*$", name):
            raise ValueError(f"node name {name!r} must match [a-z][a-z0-9-]*")
        ipaddress.ip_address(ip)
        nodes.append(Node(id=name, ip=ip, index=index, role=role))
    return nodes


def _parse_port(value: str, name: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return port


def _decode_private_key(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("REEF_SSH_PRIVATE_KEY_B64 must be valid base64") from exc


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
        .sign(key, algorithm=hashes.SHA256())
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

    if model.config.ssh_private_key_b64:
        key_path = ssh_dir / "reef_id"
        _write_private(key_path, _decode_private_key(model.config.ssh_private_key_b64))
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
        files, services = render_node_files(model, node, nodes_dir / node.id)
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
) -> tuple[list[dict[str, str]], list[str]]:
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
        files.append({"src": str(src), "dest": dest, "mode": mode})
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
    runtimes = []
    for provider in model.providers:
        runtime = provider["runtime"]
        runtime_path = project_path(runtime["local_path"])
        runtime_hash = (
            hashlib.sha256(runtime_path.read_bytes()).hexdigest() if runtime_path.exists() else ""
        )
        runtimes.append(
            {
                "id": str(provider["id"]),
                "dest": _render_inline(runtime["remote_path"], {"remote_dir": REMOTE_DIR}),
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
        "runtimes": runtimes,
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
    return files, services


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


def render_subscriptions(model: Model, host_map_path: Path | None = None) -> list[dict[str, str]]:
    build_dir = project_path("build", "subscriptions")
    _ensure_private_dir(project_path("build"))
    _ensure_private_dir(build_dir)
    host_map = _load_json_file(host_map_path or _env_path("TEST_HOST_MAP"))
    renderer = load_subscription_renderer()
    context = subscription_context(model, host_map)
    rendered = renderer.render(context)
    if hasattr(renderer, "validate"):
        renderer.validate(rendered, context)

    profiles = []
    secret = bytes.fromhex(model.config.secret_hex)
    for profile in rendered:
        body = profile["body"]
        output = build_dir / profile["output"]
        _write_private(output, body)
        token = derive_text(secret, "subscription-url", profile["id"], length=24)
        profiles.append(
            {
                "id": profile["id"],
                "token": token,
                "output": str(output),
                "content_type": profile.get("content_type", "text/plain; charset=utf-8"),
                "body": body,
            }
        )
    return profiles


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
        "exits": [_node_dict(node, model) for node in model.config.exits],
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


def render_web(model: Model) -> None:
    profiles = render_subscriptions(model)
    out = project_path("web", "generated", "subscriptions.ts")
    _ensure_private_dir(out.parent)
    items = [
        {
            "id": p["id"],
            "token": p["token"],
            "contentType": p["content_type"],
            "body": p["body"],
        }
        for p in profiles
    ]
    _write_private(
        out,
        "export type GeneratedSubscription = {\n"
        "  id: string;\n"
        "  token: string;\n"
        "  contentType: string;\n"
        "  body: string;\n"
        "};\n\n"
        f"export const subscriptions: GeneratedSubscription[] = {json.dumps(items, indent=2)};\n",
    )


def load_model(*, require_ssh: bool = False) -> Model:
    values = load_env()
    return build_model(parse_config(values, require_ssh=require_ssh))


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
    return {
        "id": node.id,
        "ip": node.ip,
        "index": node.index,
        "role": node.role,
        "password": secret.password,
        "fingerprint": secret.fingerprint,
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
