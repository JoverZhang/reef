from __future__ import annotations

import copy
import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import yaml

from reef import core
from reef.cli import reef_web_env, render as render_cli, urls
from subscriptions import render, upstream


FIXTURE = Path(__file__).parent / "fixtures" / "upstream.yaml"
ENV = {
    "REEF_SECRET": "11" * 32,
    "REEF_ENTRY_1": "sg,192.0.2.10",
    "REEF_ENTRY_2": "jp,192.0.2.11",
    "REEF_EXIT_1": "us,192.0.2.20",
    "REEF_EXIT_2": "uk,192.0.2.21",
    "REEF_ENTRY_OVERRIDE_BASE_DOMAIN": "example.test",
}


@contextmanager
def subscription_server():
    state = {"body": FIXTURE.read_bytes(), "requests": 0, "status": 200}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"] += 1
            self.send_response(state["status"])
            self.end_headers()
            self.wfile.write(state["body"])

        def log_message(self, *args):
            pass

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/private-token", state
        finally:
            server.shutdown()
            thread.join()


class SubscriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = core.build_model(core.parse_config(ENV))

    def setUp(self):
        self.context = core.subscription_context(self.model)
        self.proxies = yaml.safe_load(FIXTURE.read_text())["proxies"]

    def render_profiles(self, proxies):
        context = {
            **self.context,
            "upstream_proxies": proxies,
            "qx_upstream": upstream.quantumult_x_nodes(proxies),
        }
        with redirect_stderr(io.StringIO()):
            profiles = render.render(context)
        render.validate(profiles, context)
        return {profile["id"]: profile["body"] for profile in profiles}

    def test_only_nodes_change_and_all_local_templates_survive(self):
        baseline = self.render_profiles([])
        imported = self.render_profiles(self.proxies)
        self.assertEqual(set(imported), {"client", "linux-server", "quantumult-x"})
        for profile_id in ("client", "linux-server"):
            before = yaml.safe_load(baseline[profile_id])
            after = yaml.safe_load(imported[profile_id])
            managed = before.pop("proxies")
            self.assertEqual(after.pop("proxies"), managed + self.proxies)
            groups = after.pop("proxy-groups")
            original_groups = before.pop("proxy-groups")
            names = [p["name"] for p in managed + self.proxies]
            self.assertEqual(groups[0]["name"], "PROXY")
            self.assertEqual(groups[0]["type"], "select")
            self.assertEqual(groups[0]["proxies"], ["AUTO"] + names)
            self.assertEqual(groups[1]["name"], "AUTO")
            self.assertEqual(groups[1]["type"], "url-test")
            self.assertEqual(groups[1]["proxies"], names)
            # Entry overrides must remain confined to the matching Reef entry.
            self.assertEqual(groups[2:], original_groups[2:])
            self.assertEqual(after, before)
        body = imported["quantumult-x"]
        self.assertIn("tag=🇸🇬 HTTP: [TLS] #1", body)
        self.assertNotIn("tag=TUIC", body)
        self.assertIn("static=Reef, AUTO, sg-us", body)
        self.assertNotIn(
            "TUIC",
            next(
                line
                for line in body.splitlines()
                if line.startswith("url-latency-benchmark=AUTO,")
            ),
        )
        for text in ("upstream-dns.example.test", "upstream-policy-must-not-be-imported"):
            self.assertTrue(all(text not in output for output in imported.values()))
        self.assertEqual(
            body.split("[filter_remote]", 1)[1],
            baseline["quantumult-x"].split("[filter_remote]", 1)[1],
        )

    def test_qx_preserves_tls_reality_and_credentials(self):
        nodes = upstream.quantumult_x_nodes(self.proxies)
        self.assertEqual(len(nodes), 5)
        by_name = {node["name"]: node["line"] for node in nodes}
        for name in (self.proxies[0]["name"], "SOCKS TLS"):
            self.assertIn("over-tls=true", by_name[name])
            self.assertIn("tls-verification=true", by_name[name])
            self.assertIn("username=example-user", by_name[name])
        self.assertIn('password=example "password"', by_name[self.proxies[0]["name"]])
        self.assertIn("tls-host=certificate.example.test", by_name["SOCKS TLS"])
        self.assertIn("tls-verification=false", by_name["AnyTLS"])
        self.assertIn("obfs=over-tls", by_name["Reality"])
        self.assertIn("obfs-host=reality.example.test", by_name["Reality"])
        self.assertIn("reality-base64-pubkey=" + "A" * 43, by_name["Reality"])
        self.assertIn("udp-relay=true", by_name["Reality"])
        self.assertNotIn("reality-hex-shortid", by_name["Reality"])
        self.assertNotIn("vless-flow", by_name["Reality"])
        self.assertIn("tls-alpn=02683208687474702f312e31", by_name["Trojan"])
        reality = copy.deepcopy(self.proxies[3])
        reality["flow"] = "xtls-rprx-vision"
        reality["reality-opts"]["short-id"] = "0123456789abcdef"
        line = upstream.quantumult_x_nodes([reality])[0]["line"]
        self.assertIn("vless-flow=xtls-rprx-vision", line)
        self.assertIn("reality-hex-shortid=0123456789abcdef", line)

    def test_certificate_pins_remain_enforced_when_skip_cert_verify_is_set(self):
        proxies = [
            {**proxy, "fingerprint": ":".join(["AB"] * 32), "skip-cert-verify": True}
            for proxy in self.proxies[:-1]
        ]
        profiles = self.render_profiles(proxies)
        self.assertEqual(yaml.safe_load(profiles["client"])["proxies"][-len(proxies) :], proxies)
        lines = (
            profiles["quantumult-x"].split("[server_local]", 1)[1].split("[server_remote]", 1)[0]
        )
        for proxy in proxies:
            line = next(
                line for line in lines.splitlines() if f"tag={proxy['name']}" in line.split(", ")
            )
            self.assertIn("tls-verification=true", line)
            self.assertIn("tls-cert-sha256=" + "AB" * 32, line)
        for fingerprint in ("private-invalid-pin", "AB" * 31, ["private-invalid-pin"]):
            with (
                self.subTest(fingerprint=fingerprint),
                self.assertRaisesRegex(ValueError, "^upstream node 1 has invalid fingerprint$"),
            ):
                self.render_profiles([{**self.proxies[0], "fingerprint": fingerprint}])

    def test_unsupported_nodes_have_no_qx_policy_references(self):
        unsupported = [self.proxies[-1], {**self.proxies[3], "network": "grpc"}]
        profiles = self.render_profiles(unsupported)
        for node in unsupported:
            self.assertNotIn(node["name"], profiles["quantumult-x"])
        self.assertEqual(yaml.safe_load(profiles["client"])["proxies"][-2:], unsupported)

    def test_names_and_values_cannot_break_local_policies(self):
        for name in ("PROXY", "AUTO", "Reef", "entry-sg", "sg-us"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "conflicts"):
                self.render_profiles([{**self.proxies[0], "name": name}])
        for key, value in (
            ("name", "node, injected"),
            ("password", "secret\n[policy]"),
            ("skip-cert-verify", "false"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError) as error:
                self.render_profiles([{**self.proxies[0], key: value}])
            self.assertNotIn(value, str(error.exception))

    def test_fetch_validation_and_error_messages_do_not_expose_secrets(self):
        bad_documents = [
            b"proxies: [private-password",
            b"<html>private-password</html>",
            b"proxies: []",
            yaml.safe_dump({"proxies": self.proxies[:1] * 2}).encode(),
            yaml.safe_dump({"proxies": [{**self.proxies[0], "port": 0}]}).encode(),
            yaml.safe_dump(
                {"proxies": [{**self.proxies[0], "dialer-proxy": "private-password"}]}
            ).encode(),
        ]
        for body in bad_documents:
            with patch.object(upstream, "urlopen", return_value=io.BytesIO(body)):
                with self.assertRaises(ValueError) as error:
                    upstream.load_nodes(["https://example.test/private-token"])
                self.assertNotIn("private-password", str(error.exception))
                self.assertNotIn("private-token", str(error.exception))
        with (
            patch.object(upstream, "urlopen", side_effect=URLError("private-token")),
            self.assertRaisesRegex(ValueError, "^upstream subscription 1 fetch failed$"),
        ):
            upstream.load_nodes(["https://example.test/private-token"])

    def test_render_fetches_once_updates_nodes_and_preserves_files_on_failure(self):
        with (
            subscription_server() as (url, state),
            subscription_server() as (second_url, second_state),
            tempfile.TemporaryDirectory() as directory,
        ):
            document = yaml.safe_load(FIXTURE.read_text())
            state["body"] = yaml.safe_dump({**document, "proxies": self.proxies[:3]}).encode()
            second_state["body"] = yaml.safe_dump(
                {**document, "proxies": self.proxies[3:]}
            ).encode()
            model = replace(
                self.model,
                config=core.parse_config(
                    {
                        **ENV,
                        "REEF_UPSTREAM_URL_2": second_url,
                        "REEF_UPSTREAM_URL_1": url,
                    }
                ),
            )
            original_path = core.project_path

            def project_path(*parts):
                if parts[0] in {"build", "web"}:
                    return Path(directory).joinpath(*parts)
                return original_path(*parts)

            with (
                patch.object(core, "project_path", side_effect=project_path),
                patch.object(render_cli, "load_model", return_value=model),
                redirect_stderr(io.StringIO()),
            ):
                with patch("sys.argv", ["render", "subscriptions", "web"]):
                    self.assertEqual(render_cli.main(), 0)
                self.assertEqual(state["requests"], 1)
                self.assertEqual(second_state["requests"], 1)
                web_file = project_path("web", "generated", "subscriptions.ts")
                items = json.loads(
                    web_file.read_text().split("GeneratedSubscription[] = ", 1)[1].rstrip(";\n")
                )
                for item in items:
                    output = (
                        "quantumult-x.conf"
                        if item["id"] == "quantumult-x"
                        else item["id"] + ".yaml"
                    )
                    self.assertEqual(
                        item["body"], project_path("build", "subscriptions", output).read_text()
                    )
                    if item["id"] == "quantumult-x":
                        self.assertNotIn("TUIC", item["body"])
                        for proxy in self.proxies[:-1]:
                            self.assertIn(f"tag={proxy['name']}", item["body"])
                    else:
                        self.assertEqual(
                            yaml.safe_load(item["body"])["proxies"][-len(self.proxies) :],
                            self.proxies,
                        )
                second_state["body"] = yaml.safe_dump(
                    {"proxies": [{**self.proxies[4], "password": "changed-password"}]}
                ).encode()
                with (
                    patch.object(urls, "load_model", return_value=model),
                    redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(urls.main(), 0)
                self.assertEqual(state["requests"], 2)
                self.assertEqual(second_state["requests"], 2)
                client = yaml.safe_load(
                    project_path("build", "subscriptions", "client.yaml").read_text()
                )
                self.assertEqual(client["proxies"][-1]["password"], "changed-password")
                self.assertNotIn("TUIC", [p["name"] for p in client["proxies"]])
                files = [p for p in Path(directory).rglob("*") if p.is_file()]
                previous = {p: p.read_bytes() for p in files}
                for status, body in ((503, b"unavailable"), (200, b"proxies: [private-password")):
                    second_state.update(status=status, body=body)
                    with self.assertRaises(ValueError):
                        core.render_web(model)
                    self.assertEqual({p: p.read_bytes() for p in files}, previous)

    def test_duplicate_names_across_subscriptions_are_rejected(self):
        body = yaml.safe_dump({"proxies": self.proxies[:1]}).encode()
        with (
            patch.object(upstream, "urlopen", side_effect=[io.BytesIO(body), io.BytesIO(body)]),
            self.assertRaisesRegex(
                ValueError, "^upstream subscription 2 node 1 has a duplicate name$"
            ),
        ):
            upstream.load_nodes(
                [
                    "https://example.test/private-token-1",
                    "https://example.test/private-token-2",
                ]
            )

    def test_subscription_only_uses_compatible_nodes_from_later_sources(self):
        config = core.parse_config(
            {
                "REEF_SECRET": ENV["REEF_SECRET"],
                "REEF_UPSTREAM_URL_1": "https://first.example.test/private-token",
                "REEF_UPSTREAM_URL_2": "https://second.example.test/private-token",
            }
        )
        self.context = core.subscription_context(core.build_model(config))
        proxies = [self.proxies[-1], self.proxies[0]]
        responses = [io.BytesIO(yaml.safe_dump({"proxies": [proxy]}).encode()) for proxy in proxies]
        with patch.object(upstream, "urlopen", side_effect=responses) as fetch:
            profiles = self.render_profiles(upstream.load_nodes(config.upstream_urls))
        self.assertEqual(fetch.call_count, 2)
        for profile_id in ("client", "linux-server"):
            document = yaml.safe_load(profiles[profile_id])
            self.assertEqual(document["proxies"], proxies)
            self.assertEqual(document["proxy-groups"][0]["proxies"], ["AUTO"] + [p["name"] for p in proxies])
        self.assertIn(f"tag={proxies[1]['name']}", profiles["quantumult-x"])
        self.assertNotIn(proxies[0]["name"], profiles["quantumult-x"])

    def test_numbered_urls_use_numeric_order_after_the_legacy_url(self):
        numbered = {
            f"REEF_UPSTREAM_URL_{index}": f"https://example.test/private-token-{index}"
            for index in range(10, 0, -1)
        }
        legacy = "https://example.test/private-legacy"
        config = core.parse_config({**ENV, **numbered, "REEF_UPSTREAM_URL": legacy})
        self.assertEqual(
            config.upstream_urls,
            [legacy] + [numbered[f"REEF_UPSTREAM_URL_{index}"] for index in range(1, 11)],
        )
        self.assertEqual(core.parse_config(ENV).upstream_urls, [])

    def test_numbered_urls_must_be_consecutive_and_valid(self):
        valid = "https://example.test/private-token"
        for values in (
            {"REEF_UPSTREAM_URL_0": valid},
            {"REEF_UPSTREAM_URL_2": valid},
            {"REEF_UPSTREAM_URL_1": valid, "REEF_UPSTREAM_URL_3": valid},
        ):
            with self.subTest(keys=list(values)), self.assertRaisesRegex(ValueError, "consecutive"):
                core.parse_config({**ENV, **values})
        for url in ("", " ", "file:///private-token", "https://host:bad/private-token"):
            with (
                self.subTest(url=url),
                self.assertRaisesRegex(
                    ValueError, r"^REEF_UPSTREAM_URL_2 must be an HTTP\(S\) subscription URL$"
                ),
            ):
                core.parse_config(
                    {
                        **ENV,
                        "REEF_UPSTREAM_URL_1": valid,
                        "REEF_UPSTREAM_URL_2": url,
                    }
                )

    def test_web_env_includes_upstream_and_round_trips(self):
        values = {
            **ENV,
            "REEF_UPSTREAM_URL": "https://example.test/private-token?format=clash&x=1",
            "REEF_UPSTREAM_URL_2": "https://second.example.test/private-token?format=clash&x=2",
            "REEF_UPSTREAM_URL_1": "https://first.example.test/private-token?format=clash&x=1",
        }
        output = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(reef_web_env, "load_env", return_value=values.copy()),
            redirect_stdout(output),
        ):
            self.assertEqual(reef_web_env.main(), 0)
        exported = dict(line.split("=", 1) for line in output.getvalue().splitlines())
        self.assertEqual(core.parse_config(exported), core.parse_config(values))
        self.assertEqual(exported["REEF_UPSTREAM_URL_1"], values["REEF_UPSTREAM_URL"])
        self.assertEqual(exported["REEF_UPSTREAM_URL_2"], values["REEF_UPSTREAM_URL_1"])
        self.assertEqual(exported["REEF_UPSTREAM_URL_3"], values["REEF_UPSTREAM_URL_2"])
        with (
            patch.dict(os.environ, {"CI": "1"}, clear=True),
            redirect_stdout(io.StringIO()) as stdout,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(reef_web_env.main(), 1)
            self.assertEqual(stdout.getvalue(), "")
        for url in ("file:///private-token", "https://", "https://example.test/\nprivate-token"):
            with self.assertRaisesRegex(ValueError, "HTTP\\(S\\)"):
                core.parse_config({**ENV, "REEF_UPSTREAM_URL": url})
