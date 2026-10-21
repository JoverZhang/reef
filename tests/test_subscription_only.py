from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.client import BadStatusLine
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import yaml

from reef import core
from reef.cli import config_yaml, render, smoke, urls
from subscriptions import extension, upstream


SECRET = "12" * 32
VLESS = {**next(
    proxy for proxy in yaml.safe_load(
        (Path(__file__).parent / "fixtures" / "upstream.yaml").read_text()
    )["proxies"] if proxy["type"] == "vless"
), "skip-cert-verify": False}
EXTENSION = yaml.safe_load(
    (Path(__file__).parent / "fixtures" / "extension.yaml").read_text()
)["nodes"][0]


class SubscriptionOnlyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        project_path = core.project_path
        self.addCleanup(patch.stopall)

        def isolated_path(*parts):
            return (
                self.root.joinpath(*parts)
                if parts[0] in {"build", "web"} or parts == ("config.yaml",)
                else project_path(*parts)
            )

        patch.object(core, "project_path", side_effect=isolated_path).start()
        patch.dict(os.environ, {}, clear=True).start()
        self.proxies = [
            {
                "name": "Hong Kong 🇭🇰 TLS",
                "type": "http",
                "server": "proxy.example.com",
                "port": 443,
                "tls": True,
                "username": "test-user",
                "password": "test-password",
            },
            {
                "name": "TUIC example",
                "type": "tuic",
                "server": "tuic.example.com",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000001",
                "password": "tuic-test-password",
            },
        ]
        self.payload = yaml.safe_dump({
            "proxies": self.proxies,
            "proxy-groups": [{"name": "ignored-upstream-group"}],
            "rules": ["MATCH,ignored-upstream-group"],
            "dns": {"nameserver": ["ignored-upstream-dns"]},
        }).encode()
        self.requests = 0
        test = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                test.requests += 1
                self.send_response(200)
                self.end_headers()
                self.wfile.write(test.payload)

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.url = f"http://127.0.0.1:{self.server.server_port}/private-test-subscription"
        self.values = {"secret": SECRET, "subscriptions": {"upstream_urls": [self.url]}}

    def stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def model(self, *, cluster=None, upstream_urls=None, nodes=None) -> core.Model:
        values = {
            **self.values,
            "cluster": cluster or {},
            "subscriptions": {
                "upstream_urls": [self.url] if upstream_urls is None else upstream_urls,
                "nodes": nodes or [],
            },
        }
        return core.build_model(core.parse_config(values))

    def generate(self, model: core.Model | None = None) -> list[dict[str, str]]:
        with contextlib.redirect_stderr(io.StringIO()):
            return core.render_web(model or self.model())

    def artifacts(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }

    def test_minimal_config_has_no_cluster_or_node_secrets(self) -> None:
        model = self.model()
        self.assertEqual(model.nodes, [])
        self.assertEqual(model.routes, [])
        self.assertEqual(model.secrets, {})
        self.assertIsNone(model.config.ssh_private_key)

    def test_config_requires_an_upstream_or_a_complete_cluster(self) -> None:
        for values in (
            {"secret": SECRET},
            {"secret": SECRET, "subscriptions": {"upstream_urls": [], "nodes": []}},
            {**self.values, "cluster": {"entries": [{"name": "sg", "ip": "192.0.2.1"}]}},
        ):
            with self.subTest(values=list(values)), self.assertRaisesRegex(ValueError, "cluster.exits"):
                core.parse_config(values)
        with self.assertRaisesRegex(ValueError, "requires at least one entry"):
            self.model(cluster={"entry_override_base_domain": "example.com"})
        with self.assertRaisesRegex(ValueError, "secret"):
            core.parse_config({"subscriptions": {"upstream_urls": [self.url]}})

    def test_invalid_upstream_urls_are_rejected_without_echoing_them(self) -> None:
        for url in ("file:///private", "https://host:bad/private", "https://host:99999/private"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, r"HTTP\(S\)") as error:
                self.model(upstream_urls=[url])
            self.assertNotIn(url, str(error.exception))

    def test_upstream_only_keeps_templates_and_three_profiles(self) -> None:
        profiles = self.generate()
        self.assertEqual(self.requests, 1)
        self.assertEqual([p["id"] for p in profiles], ["client", "linux-server", "quantumult-x"])
        for profile in profiles[:2]:
            doc = yaml.safe_load(profile["body"])
            self.assertEqual(doc["proxies"], self.proxies)
            groups = {group["name"]: group for group in doc["proxy-groups"]}
            names = [p["name"] for p in self.proxies]
            self.assertEqual(set(groups), {"PROXY", "AUTO"})
            self.assertEqual(groups["PROXY"]["proxies"], ["AUTO"] + names)
            self.assertEqual(groups["AUTO"]["proxies"], names)
            self.assertNotIn("ignored-upstream", profile["body"])
        qx = profiles[2]["body"]
        self.assertIn("static=Reef, AUTO, Hong Kong 🇭🇰 TLS", qx)
        self.assertIn("tag=Hong Kong 🇭🇰 TLS", qx)
        self.assertIn("over-tls=true", qx)
        self.assertIn("tls-verification=true", qx)
        self.assertNotIn("TUIC example", qx)
        self.assertNotIn("ignored-upstream", qx)
        generated = (self.root / "web/generated/subscriptions.ts").read_text()
        web_profiles = json.loads(generated.split("GeneratedSubscription[] = ", 1)[1].rstrip(";\n"))
        for profile, web_profile in zip(profiles, web_profiles, strict=True):
            self.assertEqual(web_profile["body"], Path(profile["output"]).read_text())
            self.assertEqual(web_profile["token"], profile["token"])
        self.assertFalse((self.root / "build/ansible").exists())
        self.assertFalse((self.root / "build/ssh").exists())

    def test_mixed_mode_appends_upstream_and_keeps_smoke_metadata_local(self) -> None:
        model = self.model(cluster={"entries": [{"name": "sg", "ip": "192.0.2.1"}], "exits": [{"name": "us", "ip": "192.0.2.2"}]})
        profiles = self.generate(model)
        for profile in profiles[:2]:
            doc = yaml.safe_load(profile["body"])
            self.assertEqual(len(doc["proxies"]), 6)
            self.assertEqual(doc["proxies"][-2:], self.proxies)
            self.assertEqual(doc["proxy-groups"][0]["proxies"], ["AUTO"] + [p["name"] for p in doc["proxies"]])
        self.assertEqual(len(core.subscription_proxy_metadata(model)), 4)
        self.assertEqual(self.requests, 1)
        self.assertIn("static=Reef, AUTO, sg-us, us-direct, Hong Kong 🇭🇰 TLS", profiles[2]["body"])

    def test_updated_upstream_keeps_subscription_tokens_stable(self) -> None:
        first = self.generate()
        self.proxies[0]["password"] = "changed-test-password"
        self.payload = yaml.safe_dump({"proxies": self.proxies}).encode()
        second = self.generate()
        self.assertEqual(self.requests, 2)
        self.assertEqual([p["token"] for p in first], [p["token"] for p in second])
        self.assertTrue(all(a["body"] != b["body"] for a, b in zip(first, second, strict=True)))

    def test_removing_cluster_preserves_all_three_subscription_urls(self) -> None:
        mixed = self.generate(self.model(cluster={"entries": [{"name": "sg", "ip": "192.0.2.1"}], "exits": [{"name": "us", "ip": "192.0.2.2"}]}))
        upstream_only = self.generate()
        self.assertEqual(
            [(p["id"], p["token"]) for p in mixed],
            [(p["id"], p["token"]) for p in upstream_only],
        )
        generated = (self.root / "web/generated/subscriptions.ts").read_text()
        self.assertTrue(generated.startswith("import 'server-only';"))
        for value in (SECRET, self.url, "ssh_private_key"):
            self.assertNotIn(value, generated)

    def test_invalid_or_qx_incompatible_upstream_preserves_existing_artifacts(self) -> None:
        self.generate()
        before = self.artifacts()
        for payload in (
            b"proxies: [malformed-private-content",
            b"proxies: []",
            yaml.safe_dump({"proxies": [self.proxies[1]]}).encode(),
        ):
            self.payload = payload
            with self.assertRaises(ValueError) as error:
                self.generate()
            self.assertNotIn("malformed-private-content", str(error.exception))
            self.assertEqual(self.artifacts(), before)

    def test_policy_option_names_and_control_characters_cannot_be_imported(self) -> None:
        for key, value in (("name", "check-interval=30"), ("password", "secret\u2028[policy]")):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "unrepresentable"):
                upstream.quantumult_x_nodes([{**self.proxies[0], key: value}])

    def test_http_protocol_errors_do_not_expose_response_contents(self) -> None:
        with (
            patch.object(upstream, "urlopen", side_effect=BadStatusLine("private-response")),
            self.assertRaisesRegex(ValueError, "fetch failed$") as error,
        ):
            upstream.load_nodes([self.url])
        self.assertNotIn("private-response", str(error.exception))

    def test_render_cli_fetches_once_for_subscriptions_and_web(self) -> None:
        with (
            patch.object(render, "load_model", return_value=self.model()),
            patch("sys.argv", ["render", "subscriptions", "web"]),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(render.main(), 0)
        self.assertEqual(self.requests, 1)

    def test_urls_fetches_once_and_hides_tokens_in_ci(self) -> None:
        output = io.StringIO()
        with (
            patch.object(urls, "load_model", return_value=self.model()),
            patch.dict(os.environ, {"CI": "1"}),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(urls.main(), 0)
        self.assertEqual(self.requests, 1)
        self.assertEqual(output.getvalue().count("<hidden in CI>"), 3)
        self.assertNotIn("private-test-subscription", output.getvalue())

    def test_config_yaml_exports_subscription_only_config_without_fetching(self) -> None:
        core.write_config({**self.values, "ssh_private_key": "deployment-only-test-key"})
        before = (self.root / "config.yaml").read_bytes()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(config_yaml.main(), 0)
        payload = output.getvalue()
        self.assertNotIn("deployment-only", payload)
        self.assertNotIn("ssh_private_key", payload)
        self.assertEqual(core.parse_config_yaml(payload), self.values)
        self.assertEqual((self.root / "config.yaml").read_bytes(), before)
        self.assertEqual(self.requests, 0)

    def test_extension_only_generates_all_profiles_without_fetching(self) -> None:
        values = {"secret": SECRET, "subscriptions": {"nodes": [EXTENSION]}}
        core.write_config(values)
        model = core.load_model()
        profiles = self.generate(model)
        self.assertEqual(self.requests, 0)
        self.assertEqual(model.nodes, [])
        self.assertEqual(model.routes, [])
        self.assertEqual(model.secrets, {})
        for profile in profiles[:2]:
            document = yaml.safe_load(profile["body"])
            self.assertEqual(document["proxies"], [VLESS])
            self.assertEqual(document["proxy-groups"][0]["proxies"], ["AUTO", VLESS["name"]])
            self.assertEqual(document["proxy-groups"][1]["proxies"], [VLESS["name"]])
        self.assertIn(f"tag={VLESS['name']}", profiles[2]["body"])
        for option in (
            f"password={EXTENSION['uuid']}", "obfs=over-tls", "tls-verification=true",
            "obfs-host=reality.example.test", "reality-base64-pubkey=" + "A" * 43,
            "udp-relay=true",
        ):
            self.assertIn(option, profiles[2]["body"])
        self.assertTrue((self.root / "web/generated/subscriptions.ts").exists())
        with self.assertRaisesRegex(ValueError, "deployment recipes require a Reef cluster"):
            core.parse_config(values, require_ssh=True)

    def test_extension_grpc_is_appended_to_mihomo_and_skipped_in_qx(self) -> None:
        node = {
            **EXTENSION, "transport": {"type": "grpc", "service_name": "test-service"},
            "packet_encoding": "xudp", "encryption": "none",
        }
        grpc = {
            **VLESS, "network": "grpc", "grpc-opts": {"grpc-service-name": "test-service"},
            "packet-encoding": "xudp",
        }
        model = self.model(
            cluster={"entries": [{"name": "sg", "ip": "192.0.2.1"}], "exits": [{"name": "us", "ip": "192.0.2.2"}]},
            nodes=[node],
        )
        profiles = self.generate(model)
        self.assertEqual(self.requests, 1)
        for profile in profiles[:2]:
            document = yaml.safe_load(profile["body"])
            self.assertEqual(document["proxies"][-3:], self.proxies + [grpc])
            self.assertEqual(len(document["proxies"]), 7)
            for group in document["proxy-groups"]:
                self.assertIn(grpc["name"], group["proxies"])
        self.assertNotIn(grpc["name"], profiles[2]["body"])
        self.assertIn(self.proxies[0]["name"], profiles[2]["body"])

        self.payload = yaml.safe_dump({"proxies": [grpc]}).encode()
        previous = self.artifacts()
        with self.assertRaisesRegex(ValueError, "duplicate name"):
            self.generate(model)
        self.assertEqual(self.artifacts(), previous)

    def test_common_vless_transports_and_tls_generate_both_clients(self) -> None:
        plain = {key: value for key, value in EXTENSION.items() if key not in {"tls", "transport"}}
        nodes = [
            {**plain, "name": "plain"},
            {**plain, "name": "ws", "transport": {"type": "ws", "path": "/socket", "host": "ws.example.test"}},
            {**plain, "name": "wss", "transport": {"type": "ws", "path": "/socket"}, "tls": {"sni": "wss.example.test"}},
            {**plain, "name": "wss-host", "transport": {
                "type": "ws", "host": "ws.example.test",
            }, "tls": {"sni": "ws.example.test"}},
            {**EXTENSION, "name": "vision", "flow": "xtls-rprx-vision", "tls": {
                **EXTENSION["tls"],
                "reality": {**EXTENSION["tls"]["reality"], "short_id": "0123456789abcdef"},
            }},
            {**plain, "name": "tls-defaults", "tls": {}, "udp": False},
            {**plain, "name": "tls-alpn", "tls": {"alpn": ["h2", "http/1.1"], "verify": False}},
        ]
        profiles = self.generate(self.model(
            upstream_urls=[], nodes=nodes,
        ))
        by_name = {node["name"]: node for node in yaml.safe_load(profiles[0]["body"])["proxies"]}
        self.assertFalse(by_name["plain"]["tls"])
        self.assertEqual(by_name["plain"]["network"], "tcp")
        self.assertEqual(by_name["ws"]["ws-opts"], {"path": "/socket", "headers": {"Host": "ws.example.test"}})
        self.assertEqual(by_name["wss"]["servername"], "wss.example.test")
        self.assertEqual(by_name["wss"]["ws-opts"]["headers"], {"Host": "wss.example.test"})
        self.assertEqual(by_name["vision"]["reality-opts"]["short-id"], "0123456789abcdef")
        self.assertEqual(by_name["tls-defaults"]["servername"], EXTENSION["server"])
        qx_lines = {
            next(part.removeprefix("tag=") for part in line.split(", ") if part.startswith("tag=")): line
            for line in profiles[2]["body"].splitlines() if line.startswith("vless=")
        }
        self.assertEqual(set(qx_lines), set(by_name))
        self.assertNotIn("obfs=", qx_lines["plain"])
        for name, obfs, host in (
            ("ws", "ws", "ws.example.test"),
            ("wss", "wss", "wss.example.test"),
            ("wss-host", "wss", "ws.example.test"),
        ):
            self.assertIn(f"obfs={obfs},", qx_lines[name])
            self.assertIn(f"obfs-host={host}", qx_lines[name])
            self.assertEqual(qx_lines[name].count("obfs-host="), 1)
            self.assertNotIn("tls-host=", qx_lines[name])
        self.assertIn("obfs-uri=/socket", qx_lines["wss"])
        self.assertIn("obfs-uri=/", qx_lines["wss-host"])
        for option in (
            "vless-flow=xtls-rprx-vision", "reality-hex-shortid=0123456789abcdef",
        ):
            self.assertIn(option, qx_lines["vision"])
        self.assertIn("tls-verification=true", qx_lines["tls-defaults"])
        self.assertIn("udp-relay=false", qx_lines["tls-defaults"])
        self.assertIn("tls-alpn=02683208687474702f312e31", qx_lines["tls-alpn"])
        self.assertIn("tls-verification=false", qx_lines["tls-alpn"])

    def test_qx_incompatible_extension_options_are_never_silently_changed(self) -> None:
        nodes = [
            {**EXTENSION, "name": "grpc", "transport": {"type": "grpc", "service_name": "service"}},
            {**EXTENSION, "name": "split-host", "transport": {
                "type": "ws", "host": "different.example.test",
            }, "tls": {"sni": "certificate.example.test"}},
            {**EXTENSION, "name": "xudp", "packet_encoding": "xudp"},
            {**EXTENSION, "name": "encryption", "encryption": "test-vless-encryption"},
        ]
        proxies = extension.parse_extend_nodes(nodes)
        profiles = self.generate(self.model(nodes=nodes))
        for profile in profiles[:2]:
            self.assertEqual(yaml.safe_load(profile["body"])["proxies"][-len(proxies):], proxies)
        for node in nodes:
            self.assertNotIn(f"tag={node['name']}", profiles[2]["body"])
        before = self.artifacts()
        with self.assertRaisesRegex(ValueError, "Quantumult X"):
            self.generate(self.model(upstream_urls=[], nodes=nodes))
        self.assertEqual(self.artifacts(), before)

    def test_invalid_extension_nodes_do_not_echo_credentials(self) -> None:
        for nodes in (
            None,
            {"proxies": [VLESS]},
            ["private-credential"],
            [{**EXTENSION, "port": 0}],
            [EXTENSION, EXTENSION],
            [{**EXTENSION, "uuid": "private-credential"}],
            [{**EXTENSION, "tls": True}],
            [{**EXTENSION, "transport": {"type": "ws"}}],
            [{**EXTENSION, "tls": {**EXTENSION["tls"], "alpn": ["h2"]}}],
            [{**EXTENSION, "udp": "true"}],
            [{**EXTENSION, "dialer-proxy": "private-credential"}],
            [{**EXTENSION, "transport": {"type": "tcp", "service_name": "private-credential"}}],
            [{**EXTENSION, "tls": {"reality": {"public_key": "A" * 43, "short_id": 123456}}}],
        ):
            with self.assertRaises(ValueError) as error:
                extension.parse_extend_nodes(nodes)
            self.assertNotIn("private-credential", str(error.exception))

    def test_extension_only_export_includes_nodes_without_fetching(self) -> None:
        values = {"secret": SECRET, "subscriptions": {"nodes": [EXTENSION]}}
        core.write_config(values)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(config_yaml.main(), 0)
        exported = core.parse_config_yaml(output.getvalue())
        self.assertEqual(exported, values)
        self.assertEqual(core.parse_config(exported), core.parse_config(values))
        self.assertEqual(self.requests, 0)

    def test_deployment_and_smoke_require_a_cluster(self) -> None:
        with self.assertRaisesRegex(ValueError, "deployment recipes require a Reef cluster"):
            core.parse_config(self.values, require_ssh=True)
        with (
            patch.object(smoke, "load_model", return_value=self.model()),
            self.assertRaisesRegex(SystemExit, "smoke requires a Reef cluster"),
        ):
            smoke.main()
        self.assertEqual(self.requests, 0)


if __name__ == "__main__":
    unittest.main()
