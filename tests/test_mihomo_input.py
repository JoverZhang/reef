from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import yaml

from reef import core
from reef.cli import config_yaml, urls
from subscriptions import upstream


SECRET = "34" * 32
URL = "https://user:private-password@example.test/private-path?token=private-query"
LOCAL = {
    "name": "own-trojan", "type": "trojan", "server": "owned.example.test",
    "port": 443, "password": "test-password", "sni": "owned.example.test",
}
NODES = [
    {"name": name, "type": "http", "server": "proxy.example.test", "port": 443}
    for name in ("新加坡 01", "美国 02", "香港 03")
]
CONFIG = {
    "secret": SECRET,
    "proxies": [LOCAL],
    "proxy-providers": {
        "overseas": {
            "type": "http", "url": URL, "interval": 3600,
            "filter": "新加坡|美国|香港", "exclude-filter": "香港",
        },
        "singapore": {"type": "http", "url": URL, "filter": "新加坡"},
        "owned": {"type": "inline", "payload": [{**LOCAL, "name": "own-backup"}]},
    },
    "proxy-groups": [
        {"name": "PROXY", "type": "select", "proxies": ["AUTO", "own-trojan"],
         "use": ["owned", "singapore"]},
        {"name": "AUTO", "type": "url-test", "use": ["overseas", "owned"],
         "url": "https://www.gstatic.com/generate_204", "interval": 300,
         "tolerance": 50, "lazy": False},
    ],
}


class MihomoInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        original = core.project_path

        def isolated(*parts):
            return self.root.joinpath(*parts) if parts[0] in {"build", "web", "config.yaml"} else original(*parts)

        patcher = patch.object(core, "project_path", side_effect=isolated)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.config = copy.deepcopy(CONFIG)

    def generate(self, document=None, *, mihomo_only=False):
        model = core.build_model(core.parse_config(document or self.config))
        with redirect_stderr(io.StringIO()):
            if mihomo_only:
                return core.render_subscriptions(model, mihomo_only=True)
            return core.render_web(model)

    def response(self, nodes=None):
        return io.BytesIO(yaml.safe_dump({"proxies": nodes or NODES}).encode())

    def artifacts(self):
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob("*") if path.is_file()}

    def test_collections_filters_and_groups_render_all_three_outputs_from_one_fetch(self):
        with patch.object(upstream, "urlopen", return_value=self.response()) as fetch:
            profiles = self.generate()
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual([p["id"] for p in profiles], ["client", "linux-server", "quantumult-x"])
        expected_names = ["own-trojan", "新加坡 01", "美国 02", "own-backup"]
        for profile in profiles[:2]:
            document = yaml.safe_load(profile["body"])
            self.assertEqual([node["name"] for node in document["proxies"]], expected_names)
            groups = document["proxy-groups"]
            self.assertEqual(groups[0]["proxies"], ["AUTO", "own-trojan", "own-backup", "新加坡 01"])
            self.assertEqual(groups[1]["proxies"], ["新加坡 01", "美国 02", "own-backup"])
            self.assertFalse(any("use" in group for group in groups))
            self.assertNotIn("proxy-providers", document)
        self.assertEqual(yaml.safe_load(profiles[1]["body"])["rules"], ["MATCH,PROXY"])
        self.assertIn("RULE-SET,bm_proxy,PROXY", yaml.safe_load(profiles[0]["body"])["rules"])
        qx = profiles[2]["body"]
        self.assertIn("static=Reef, AUTO, own-trojan, own-backup, 新加坡 01", qx)
        self.assertIn("url-latency-benchmark=AUTO, 新加坡 01, 美国 02, own-backup, check-interval=300, tolerance=50, alive-checking=true", qx)
        self.assertIn("server_check_url=https://www.gstatic.com/generate_204", qx)
        self.assertIn("final, Reef", qx)
        self.assertIn("force-policy=Reef", qx)
        for profile in profiles:
            for private in (URL, "private-password", "private-path", "private-query", "香港 03"):
                self.assertNotIn(private, profile["body"])
            self.assertEqual(Path(profile["output"]).read_text(), profile["body"])
        generated = (self.root / "web/generated/subscriptions.ts").read_text()
        web = json.loads(generated.split("GeneratedSubscription[] = ", 1)[1].rstrip(";\n"))
        self.assertEqual([item["body"] for item in web], [item["body"] for item in profiles])
        self.assertTrue(all(item["status"] == 200 for item in web))

    def test_inline_and_top_level_nodes_work_without_network_and_tokens_stay_stable(self):
        native = {"secret": SECRET, "proxy-providers": {"owned": {"type": "inline", "payload": [LOCAL]}}}
        with patch.object(upstream, "urlopen", side_effect=AssertionError("unexpected fetch")):
            profiles = self.generate(native)
            top_level = self.generate({"secret": SECRET, "proxies": [LOCAL]})
        self.assertEqual([p["token"] for p in profiles], [p["token"] for p in top_level])
        self.assertEqual(yaml.safe_load(profiles[0]["body"])["proxies"], [LOCAL])

    def test_provider_prefixes_type_exclusion_and_native_include_all(self):
        self.config["proxy-providers"] = {
            "a": {"type": "inline", "payload": [LOCAL], "override": {"additional-prefix": "A-"}},
            "b": {"type": "inline", "payload": [LOCAL, NODES[0]], "exclude-type": "http",
                  "override": {"additional-prefix": "B-", "additional-suffix": "-backup"}},
        }
        self.config["proxy-groups"] = [{"name": "PROXY", "type": "select", "include-all": True}]
        document = yaml.safe_load(self.generate()[0]["body"])
        self.assertEqual(document["proxy-groups"][0]["proxies"], ["own-trojan", "A-own-trojan", "B-own-trojan-backup"])

    def test_schema_rejects_unsupported_options_and_private_values_without_echoing(self):
        cases = [
            {"subscriptions": {}},
            {"proxies": None},
            {"proxy-providers": {"private-name": {"type": "file", "path": "private-path"}}},
            {"proxy-providers": {"private-name": {"type": "http", "url": "private-url"}}},
            {"proxy-providers": {"private-name": {"type": "inline", "payload": [LOCAL], "filter": "[private-regex"}}},
            {"proxy-groups": [{"name": "private-name", "type": "load-balance"}]},
            {"proxy-groups": [{"name": "PROXY", "type": "select", "private-option": True}]},
            {"proxy-groups": [{"name": "private-name", "type": "select", "proxies": ["DIRECT"]}]},
            {"proxies": [{**LOCAL, "dialer-proxy": ["private-relay"]}]},
            {"proxies": [{**LOCAL, "dialer-proxy": ""}]},
            {"proxy-providers": {"a": {"type": "inline", "payload": [LOCAL], "override": {"dialer-proxy": ""}}}},
        ]
        for changes in cases:
            with self.subTest(keys=list(changes)), self.assertRaises(ValueError) as error:
                core.parse_config({**self.config, **changes})
            self.assertNotIn("private-", str(error.exception))

    def test_failure_does_not_replace_existing_artifacts_or_echo_subscription(self):
        with patch.object(upstream, "urlopen", return_value=self.response()):
            self.generate()
        before = self.artifacts()
        failures = [
            URLError(URL),
            io.BytesIO(b"proxies: [private-password"),
            io.BytesIO(b"proxies: []"),
        ]
        for failure in failures:
            arguments = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
            with patch.object(upstream, "urlopen", **arguments), self.assertRaises(ValueError) as error:
                self.generate()
            self.assertIn("upstream URL #1 (proxy-provider #1)", str(error.exception))
            self.assertNotIn("private-", str(error.exception))
            self.assertEqual(self.artifacts(), before)

    def test_later_url_failure_reports_its_position(self):
        self.config["proxy-providers"]["singapore"]["url"] = URL + "-second"
        with patch.object(upstream, "urlopen", side_effect=[self.response(), URLError(URL)]):
            with self.assertRaisesRegex(ValueError, r"^upstream URL #2 \(proxy-provider #2\) fetch failed$"):
                self.generate()

    def test_missing_references_cycles_and_empty_qx_groups_fail(self):
        unsupported = {"name": "unsupported", "type": "tuic", "server": "tuic.example.test", "port": 443}
        base = {"secret": SECRET, "proxies": [LOCAL, unsupported]}
        cases = [
            [{"name": "PROXY", "type": "select", "use": ["missing"]}],
            [{"name": "PROXY", "type": "select", "proxies": ["missing"]}],
            [{"name": "PROXY", "type": "select", "proxies": ["PROXY"]}],
            [{"name": "PROXY", "type": "select", "proxies": ["other"]},
             {"name": "other", "type": "select", "proxies": ["PROXY"]}],
            [{"name": "PROXY", "type": "select", "proxies": []}],
            [{"name": "PROXY", "type": "select", "proxies": ["unsupported"]}],
            [{"name": "PROXY", "type": "url-test", "proxies": ["other"]},
             {"name": "other", "type": "select", "proxies": ["own-trojan"]}],
            [{"name": "PROXY", "type": "url-test", "proxies": ["own-trojan"], "url": "https://a.example.test"},
             {"name": "other", "type": "url-test", "proxies": ["own-trojan"], "url": "https://b.example.test"}],
            [{"name": "PROXY", "type": "url-test", "proxies": ["own-trojan"], "timeout": 6000}],
            [{"name": "PROXY", "type": "select", "proxies": ["own-trojan"], "url": "https://private-probe.test"}],
        ]
        for groups in cases:
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                self.generate({**base, "proxy-groups": groups})
        self.assertEqual(self.artifacts(), {})

    def test_empty_collection_and_conflicting_names_fail(self):
        for providers in (
            {"a": {"type": "inline", "payload": [LOCAL], "filter": "unmatched"}},
            {"a": {"type": "inline", "payload": [LOCAL]},
             "b": {"type": "inline", "payload": [{**LOCAL, "port": 8443}]}},
        ):
            with self.assertRaises(ValueError):
                self.generate({"secret": SECRET, "proxy-providers": providers})

    def test_managed_node_references_keep_qx_names_and_entry_rules(self):
        document = {
            "secret": SECRET,
            "cluster": {"entries": [{"name": "sg", "ip": "192.0.2.10"}],
                        "exits": [{"name": "us", "ip": "192.0.2.20"}],
                        "entry_override_base_domain": "example.test"},
        }
        model = core.build_model(core.parse_config(document))
        local = core.subscription_proxy_metadata(model)
        document["proxy-groups"] = [{"name": "PROXY", "type": "select", "include-all": True}]
        profiles = self.generate(document)
        self.assertEqual(set(yaml.safe_load(profiles[0]["body"])["proxy-groups"][0]["proxies"]), {node["name"] for node in local})
        self.assertIn("static=Reef, sg-us, us-direct", profiles[2]["body"])
        self.assertIn("host, sg.example.test, entry-sg", profiles[2]["body"])
        document["proxy-groups"] = [{
            "name": "PROXY", "type": "url-test", "include-all": True,
            "url": "https://probe.example.test/check", "timeout": 3000,
        }]
        profiles = self.generate(document)
        entry = yaml.safe_load(profiles[0]["body"])["proxy-groups"][1]
        self.assertEqual(entry["url"], "https://probe.example.test/check")
        self.assertEqual(entry["timeout"], 3000)
        self.assertIn("server_check_timeout=3000", profiles[2]["body"])

    def test_config_export_preserves_native_fields_without_fetching(self):
        core.write_config(self.config, self.root / "config.yaml")
        output = io.StringIO()
        with patch.object(upstream, "urlopen", side_effect=AssertionError("unexpected fetch")), redirect_stdout(output):
            self.assertEqual(config_yaml.main(), 0)
        self.assertEqual(core.parse_config_yaml(output.getvalue()), self.config)

    def relay_config(self):
        return {
            "secret": SECRET,
            "proxy-providers": {
                "relays": {"type": "http", "url": URL, "filter": "新加坡|香港",
                           "override": {"additional-prefix": "relay | "}},
                "exits": {"type": "inline", "payload": [
                    {**LOCAL, "name": "sg1"},
                    {"name": "MEGABOX", "type": "vless", "server": "megabox.example.test",
                     "port": 8881, "uuid": "00000000-0000-4000-8000-000000000001",
                     "tls": True, "flow": "xtls-rprx-vision", "network": "tcp"},
                ], "override": {"dialer-proxy": "RELAY"}},
            },
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "use": ["exits"]},
                {"name": "RELAY", "type": "select", "proxies": ["RELAY-AUTO"], "use": ["relays"]},
                {"name": "RELAY-AUTO", "type": "url-test", "use": ["relays"]},
            ],
        }

    def test_mihomo_preview_chains_two_exits_through_subscription_selection(self):
        with patch.object(upstream, "urlopen", return_value=self.response()):
            self.generate()
        before = self.artifacts()
        with (
            patch.object(upstream, "urlopen", return_value=self.response()) as fetch,
            patch.object(core, "quantumult_x_nodes", side_effect=AssertionError("QX must not run")),
        ):
            profiles = self.generate(self.relay_config(), mihomo_only=True)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual([p["id"] for p in profiles], ["client", "linux-server"])
        for profile in profiles:
            self.assertEqual(Path(profile["output"]).parent, self.root / "build/subscriptions/mihomo")
            doc = yaml.safe_load(profile["body"])
            nodes = {node["name"]: node for node in doc["proxies"]}
            for name in ("MEGABOX", "sg1"):
                self.assertEqual(nodes[name]["dialer-proxy"], "RELAY")
            for name in ("relay | 新加坡 01", "relay | 香港 03"):
                self.assertNotIn("dialer-proxy", nodes[name])
            self.assertEqual(doc["proxy-groups"][0]["proxies"], ["sg1", "MEGABOX"])
            self.assertEqual(doc["proxy-groups"][1]["proxies"], ["RELAY-AUTO", "relay | 新加坡 01", "relay | 香港 03"])
            self.assertNotIn(URL, profile["body"])
        after = self.artifacts()
        self.assertTrue(all(after[path] == body for path, body in before.items()))

    def test_website_publishes_chains_and_explicitly_disables_qx_at_stable_urls(self):
        with patch.object(upstream, "urlopen", return_value=self.response()):
            original = self.generate()
        with (
            patch.object(upstream, "urlopen", return_value=self.response()) as fetch,
            patch.object(core, "quantumult_x_nodes", side_effect=AssertionError("QX must not run")),
        ):
            profiles = self.generate(self.relay_config())
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual([p["id"] for p in profiles], ["client", "linux-server"])
        self.assertEqual([p["token"] for p in profiles], [p["token"] for p in original[:2]])
        for profile in profiles:
            self.assertEqual(Path(profile["output"]).parent, self.root / "build/subscriptions")
            nodes = yaml.safe_load(profile["body"])["proxies"]
            self.assertEqual({p["name"] for p in nodes if p.get("dialer-proxy") == "RELAY"}, {"sg1", "MEGABOX"})
        self.assertFalse(Path(original[2]["output"]).exists())
        generated = (self.root / "web/generated/subscriptions.ts").read_text()
        web = json.loads(generated.split("GeneratedSubscription[] = ", 1)[1].rstrip(";\n"))
        self.assertEqual([p["token"] for p in web], [p["token"] for p in original])
        self.assertEqual([p["status"] for p in web], [200, 200, 503])
        self.assertEqual([p["body"] for p in web[:2]], [p["body"] for p in profiles])
        self.assertIn("relay conversion is not supported", web[2]["body"])
        self.assertNotIn("[server_local]", web[2]["body"])
        self.assertNotIn(URL, generated)
        # Removing chains restores the QX subscription without changing its URL.
        with patch.object(upstream, "urlopen", return_value=self.response()):
            restored = self.generate()
        self.assertEqual(restored, original)
        self.assertTrue(Path(original[2]["output"]).exists())

    def test_top_level_fixed_dialer_and_http_exit_override(self):
        config = {
            "secret": SECRET, "proxies": [LOCAL, {**LOCAL, "name": "exit", "dialer-proxy": LOCAL["name"]}],
            "proxy-providers": {"exits": {"type": "http", "url": URL,
                                          "override": {"dialer-proxy": LOCAL["name"]}}},
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["exit"], "use": ["exits"]}],
        }
        with patch.object(upstream, "urlopen", return_value=self.response()):
            doc = yaml.safe_load(self.generate(config, mihomo_only=True)[0]["body"])
        self.assertNotIn("dialer-proxy", doc["proxies"][0])
        self.assertTrue(all(node["dialer-proxy"] == LOCAL["name"] for node in doc["proxies"][1:]))

    def test_chain_cycles_and_missing_dialers_fail_before_replacing_preview(self):
        config = self.relay_config()
        with patch.object(upstream, "urlopen", return_value=self.response()):
            self.generate(config, mihomo_only=True)
        before = self.artifacts()
        cases = []
        for target in ("missing", "sg1", "PROXY"):
            changed = copy.deepcopy(config)
            changed["proxy-providers"]["exits"]["override"]["dialer-proxy"] = target
            cases.append(changed)
        changed = copy.deepcopy(config)
        changed["proxy-groups"][1]["include-all"] = True
        cases.append(changed)
        cases.append({"secret": SECRET, "proxies": [{**LOCAL, "dialer-proxy": "DIRECT"}]})
        cases.append({"secret": SECRET, "proxies": [
            {**LOCAL, "name": "a", "dialer-proxy": "b"},
            {**LOCAL, "name": "b", "dialer-proxy": "a"},
        ], "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["a"]}]})
        # The cycle is present even when the first relay candidate is valid.
        changed = copy.deepcopy(config)
        changed["proxy-groups"][1]["proxies"].append("sg1")
        cases.append(changed)
        for changed in cases:
            for mihomo_only in (True, False):
                with self.subTest(config=changed, preview=mihomo_only), patch.object(upstream, "urlopen", return_value=self.response()):
                    with self.assertRaises(ValueError) as error:
                        self.generate(changed, mihomo_only=mihomo_only)
                self.assertNotIn(URL, str(error.exception))
                self.assertEqual(self.artifacts(), before)

    def test_mihomo_preview_allows_independent_latency_groups_and_qx_incompatible_nodes(self):
        config = {
            "secret": SECRET, "proxies": [{**LOCAL, "type": "hysteria2"}],
            "proxy-groups": [
                {"name": "PROXY", "type": "url-test", "proxies": ["AUTO"], "timeout": 8000},
                {"name": "AUTO", "type": "url-test", "proxies": [LOCAL["name"]], "url": "https://probe.example.test"},
            ],
        }
        profiles = self.generate(config, mihomo_only=True)
        self.assertEqual(yaml.safe_load(profiles[0]["body"])["proxy-groups"][0]["timeout"], 8000)

    def test_urls_mihomo_prints_paths_without_updating_website(self):
        model = core.build_model(core.parse_config(self.relay_config()))
        output = io.StringIO()
        with (
            patch.object(urls, "load_model", return_value=model),
            patch.object(upstream, "urlopen", return_value=self.response()),
            redirect_stdout(output), redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(urls.main("mihomo"), 0)
        self.assertIn("build/subscriptions/mihomo/client.yaml", output.getvalue())
        self.assertNotIn(URL, output.getvalue())
        self.assertFalse((self.root / "web").exists())
