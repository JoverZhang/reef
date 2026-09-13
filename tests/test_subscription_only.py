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
from reef.cli import reef_web_env, render, smoke, urls
from subscriptions import upstream


SECRET = "12" * 32


class SubscriptionOnlyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        project_path = core.project_path
        self.addCleanup(patch.stopall)
        patch.object(
            core,
            "project_path",
            side_effect=lambda *parts: (
                self.root.joinpath(*parts)
                if parts[0] in {"build", "web"}
                else project_path(*parts)
            ),
        ).start()
        patch.dict(os.environ, {}, clear=True).start()
        self.proxies = [
            {
                "name": "香港 🇭🇰 TLS",
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
        self.values = {"REEF_SECRET": SECRET, "REEF_UPSTREAM_URL": self.url}

    def stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def model(self, **extra: str) -> core.Model:
        return core.build_model(core.parse_config({**self.values, **extra}))

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
        self.assertIsNone(model.config.ssh_private_key_b64)

    def test_config_requires_an_upstream_or_a_complete_cluster(self) -> None:
        for values in (
            {"REEF_SECRET": SECRET},
            {"REEF_SECRET": SECRET, "REEF_UPSTREAM_URL": " "},
            {**self.values, "REEF_ENTRY_1": "sg,192.0.2.1"},
        ):
            with self.subTest(values=list(values)), self.assertRaisesRegex(ValueError, "REEF_EXIT_N"):
                core.parse_config(values)
        with self.assertRaisesRegex(ValueError, "requires at least one REEF_ENTRY_N"):
            self.model(REEF_ENTRY_OVERRIDE_BASE_DOMAIN="example.com")
        with self.assertRaisesRegex(ValueError, "REEF_SECRET"):
            core.parse_config({"REEF_UPSTREAM_URL": self.url})

    def test_invalid_upstream_urls_are_rejected_without_echoing_them(self) -> None:
        for url in ("file:///private", "https://host:bad/private", "https://host:99999/private"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "HTTP\\(S\\)") as error:
                core.parse_config({**self.values, "REEF_UPSTREAM_URL": url})
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
        self.assertIn("static=Reef, AUTO, 香港 🇭🇰 TLS", qx)
        self.assertIn("tag=香港 🇭🇰 TLS", qx)
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
        model = self.model(REEF_ENTRY_1="sg,192.0.2.1", REEF_EXIT_1="us,192.0.2.2")
        profiles = self.generate(model)
        for profile in profiles[:2]:
            doc = yaml.safe_load(profile["body"])
            self.assertEqual(len(doc["proxies"]), 6)
            self.assertEqual(doc["proxies"][-2:], self.proxies)
            self.assertEqual(doc["proxy-groups"][0]["proxies"], ["AUTO"] + [p["name"] for p in doc["proxies"]])
        self.assertEqual(len(core.subscription_proxy_metadata(model)), 4)
        self.assertEqual(self.requests, 1)
        self.assertIn("static=Reef, AUTO, sg-us, us-direct, 香港 🇭🇰 TLS", profiles[2]["body"])

    def test_updated_upstream_keeps_subscription_tokens_stable(self) -> None:
        first = self.generate()
        self.proxies[0]["password"] = "changed-test-password"
        self.payload = yaml.safe_dump({"proxies": self.proxies}).encode()
        second = self.generate()
        self.assertEqual(self.requests, 2)
        self.assertEqual([p["token"] for p in first], [p["token"] for p in second])
        self.assertTrue(all(a["body"] != b["body"] for a, b in zip(first, second, strict=True)))

    def test_removing_cluster_preserves_all_three_subscription_urls(self) -> None:
        mixed = self.generate(self.model(REEF_ENTRY_1="sg,192.0.2.1", REEF_EXIT_1="us,192.0.2.2"))
        upstream_only = self.generate()
        self.assertEqual(
            [(p["id"], p["token"]) for p in mixed],
            [(p["id"], p["token"]) for p in upstream_only],
        )
        generated = (self.root / "web/generated/subscriptions.ts").read_text()
        self.assertTrue(generated.startswith("import 'server-only';"))
        for value in (SECRET, self.url, "REEF_SSH_PRIVATE_KEY_B64"):
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

    def test_web_env_exports_subscription_only_config_without_fetching(self) -> None:
        output = io.StringIO()
        with (
            patch.object(reef_web_env, "load_env", return_value={
                **self.values, "REEF_SSH_PRIVATE_KEY_B64": "deployment-only-test-key",
                "REEF_TEST_MODE": "1", "TEST_HOST_MAP": "test-only-path",
            }),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(reef_web_env.main(), 0)
        payload = output.getvalue()
        self.assertIn(f"={self.url}\n", payload)
        self.assertNotIn("REEF_EXIT_1", payload)
        self.assertNotIn("REEF_ENTRY_1", payload)
        self.assertNotIn("deployment-only", payload)
        self.assertNotIn("TEST_", payload)
        env_path = self.root / "website.env"
        env_path.write_text(payload)
        self.assertEqual(core.parse_config(core.load_env(env_path)), core.parse_config(self.values))
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
