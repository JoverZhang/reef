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
from reef.cli import config_yaml
from subscriptions import quantumult_x, upstream


SECRET = "34" * 32
URL = "https://user:private-password@example.test/private-path?token=private-query"
LOCAL = {
    "name": "own-trojan", "type": "trojan", "server": "owned.example.test",
    "port": 443, "password": "test-password", "sni": "owned.example.test",
}
NODES = [
    {"name": name, "type": "http", "server": "proxy.example.test", "port": 443}
    for name in ("Sample-A 01", "Sample-B 02", "Sample-C 03")
]
CONFIG = {
    "secret": SECRET,
    "proxies": [LOCAL],
    "proxy-providers": {
        "overseas": {
            "type": "http", "url": URL, "interval": 3600,
            "filter": "Sample-A|Sample-B|Sample-C", "exclude-filter": "Sample-C",
        },
        "sample-a": {"type": "http", "url": URL, "filter": "Sample-A"},
        "owned": {"type": "inline", "payload": [{**LOCAL, "name": "own-backup"}]},
    },
    "proxy-groups": [
        {"name": "PROXY", "type": "select", "proxies": ["AUTO", "own-trojan"],
         "use": ["owned", "sample-a"]},
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
        resolver = patch.object(quantumult_x.socket, "getaddrinfo", side_effect=OSError("Fictional node DNS"))
        resolver.start()
        self.addCleanup(resolver.stop)
        self.config = copy.deepcopy(CONFIG)

    def generate(self, document=None, *, mihomo_only=False):
        model = core.build_model(core.parse_config({"web": {"password": "test-web-key-" * 4}, **(document or self.config)}))
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
        expected_names = ["own-trojan", "Sample-A 01", "Sample-B 02", "own-backup"]
        for profile in profiles[:2]:
            document = yaml.safe_load(profile["body"])
            self.assertEqual([node["name"] for node in document["proxies"]], expected_names)
            groups = document["proxy-groups"]
            self.assertEqual(groups[0]["proxies"], ["AUTO", "own-trojan", "own-backup", "Sample-A 01"])
            self.assertEqual(groups[1]["proxies"], ["Sample-A 01", "Sample-B 02", "own-backup"])
            self.assertFalse(any("use" in group for group in groups))
            self.assertNotIn("proxy-providers", document)
        self.assertEqual(yaml.safe_load(profiles[1]["body"])["rules"], ["MATCH,PROXY"])
        self.assertIn("RULE-SET,bm_proxy,PROXY", yaml.safe_load(profiles[0]["body"])["rules"])
        qx = profiles[2]["body"]
        self.assertIn("static=Reef, AUTO, own-trojan, own-backup, Sample-A 01", qx)
        self.assertIn("url-latency-benchmark=AUTO, Sample-A 01, Sample-B 02, own-backup, check-interval=300, tolerance=50, alive-checking=true", qx)
        self.assertIn("server_check_url=http://www.gstatic.com/generate_204", qx)
        self.assertIn("final, Reef", qx)
        self.assertIn("force-policy=Reef", qx)
        for profile in profiles:
            for private in (URL, "private-password", "private-path", "private-query", "Sample-C 03"):
                self.assertNotIn(private, profile["body"])
            self.assertEqual(Path(profile["output"]).read_text(), profile["body"])
        generated = (self.root / "web/generated/snapshot.ts").read_text()
        web = json.loads(generated.split("snapshot: Snapshot = ", 1)[1].rstrip(";\n"))
        self.assertEqual(web["proxies"], yaml.safe_load(profiles[0]["body"])["proxies"])
        self.assertEqual(web["qx"]["body"], profiles[2]["body"])
        self.assertIsNone(web["qx"]["error"])

    def test_inline_and_top_level_nodes_work_without_network(self):
        native = {"secret": SECRET, "proxy-providers": {"owned": {"type": "inline", "payload": [LOCAL]}}}
        with patch.object(upstream, "urlopen", side_effect=AssertionError("unexpected fetch")):
            profiles = self.generate(native)
            top_level = self.generate({"secret": SECRET, "proxies": [LOCAL]})
        self.assertEqual([p["id"] for p in profiles], [p["id"] for p in top_level])
        self.assertEqual(yaml.safe_load(profiles[0]["body"])["proxies"], [LOCAL])

    def named_collections(self):
        sources = [{"name": name, "url": URL + f"-{name}"} for name in ("source-a", "source-b", "source-c")]
        return {
            "secret": SECRET,
            "proxy-providers": {
                "source-a": {"type": "http", "upstreams": sources[:2], "filter": "^Sample-A"},
                "source-c": {"type": "http", "upstreams": sources[2:], "filter": "^Sample-A"},
                "all": {"type": "http", "upstreams": sources + sources[:1], "filter": "^Sample-A"},
            },
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": ["source-a", "source-c", "all"]},
                *[{"name": name, "type": "url-test", "use": [name]} for name in ("source-a", "source-c", "all")],
            ],
        }

    def test_named_upstreams_combine_deduplicate_and_preserve_names_in_both_clients(self):
        config = self.named_collections()
        with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: self.response()) as fetch:
            profiles = self.generate(config)
        self.assertEqual(fetch.call_count, 3)
        names = [f"{name} | Sample-A 01" for name in ("source-a", "source-b", "source-c")]
        for profile in profiles[:2]:
            doc = yaml.safe_load(profile["body"])
            self.assertEqual([node["name"] for node in doc["proxies"]], names)
            groups = {g["name"]: g for g in doc["proxy-groups"]}
            self.assertEqual(groups["source-a"]["proxies"], names[:2])
            self.assertEqual(groups["source-c"]["proxies"], names[2:])
            self.assertEqual(groups["all"]["proxies"], names)
            self.assertNotIn("proxy-providers", doc)
        for name in names:
            self.assertIn(f"tag={name}", profiles[2]["body"])
        for profile in profiles:
            self.assertNotIn("private-", profile["body"])
        # Membership is explicit, even for a collection named all.
        config["proxy-providers"]["all"]["upstreams"] = config["proxy-providers"]["source-c"]["upstreams"]
        with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: self.response()):
            doc = yaml.safe_load(self.generate(config)[0]["body"])
        self.assertEqual(doc["proxy-groups"][-1]["proxies"], names[2:])

    def test_three_exits_choose_named_automatic_collections_independently(self):
        config = self.named_collections()
        exits = [
            {**LOCAL, "name": name, "dialer-proxy": f"RELAY-{key}"}
            for name, key in (("Endpoint A", "endpoint-a"), ("Endpoint B", "endpoint-b"), ("Endpoint C", "endpoint-c"))
        ]
        config["proxy-providers"]["exits"] = {"type": "inline", "payload": exits}
        config["proxy-groups"][0] = {"name": "PROXY", "type": "select", "use": ["exits"]}
        config["proxy-groups"].extend(
            {"name": node["dialer-proxy"], "type": "select", "proxies": ["all", "source-a", "source-c"]}
            for node in exits
        )
        with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: self.response()) as fetch:
            profiles = self.generate(config)
        self.assertEqual(fetch.call_count, 3)
        self.assertEqual(len(profiles), 2)
        for profile in profiles:
            doc = yaml.safe_load(profile["body"])
            self.assertEqual(doc["proxy-groups"][0]["proxies"], [n["name"] for n in exits])
            self.assertEqual(doc["proxies"][-3:], exits)
            self.assertEqual(len(doc["proxy-groups"]), 7)
            self.assertTrue(all(g["proxies"] == ["all", "source-a", "source-c"] for g in doc["proxy-groups"][-3:]))

    def test_named_upstream_failure_does_not_replace_artifacts_or_echo_urls(self):
        config = self.named_collections()
        with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: self.response()):
            self.generate(config)
        before = self.artifacts()
        with patch.object(upstream, "urlopen", side_effect=[self.response(), URLError(URL)]):
            with self.assertRaisesRegex(ValueError, r"^upstream URL #2 \(proxy-provider #1\) fetch failed$"):
                self.generate(config)
        self.assertEqual(self.artifacts(), before)

    def test_named_sources_reject_conflicts_and_apply_filters_before_prefixes(self):
        config = self.named_collections()
        config["proxy-providers"] = {"a": {
            "type": "http", "upstreams": [{"name": "feed", "url": URL}, {"name": "feed", "url": URL + "2"}],
            "filter": "^Sample-A", "override": {"additional-prefix": "[", "additional-suffix": "]"},
        }}
        config["proxy-groups"] = [{"name": "PROXY", "type": "select", "use": ["a"]}]
        with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: self.response()):
            doc = yaml.safe_load(self.generate(config)[0]["body"])
        self.assertEqual([n["name"] for n in doc["proxies"]], ["[feed | Sample-A 01]"])
        with patch.object(upstream, "urlopen", side_effect=[self.response(), self.response([{**NODES[0], "port": 8443}])]):
            with self.assertRaisesRegex(ValueError, "conflicting node name"):
                self.generate(config)

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
        for spec in (
            {"type": "http", "upstreams": []},
            {"type": "http", "upstreams": "private-value"},
            {"type": "http", "upstreams": ["private-value"]},
            {"type": "http", "url": URL, "upstreams": [{"name": "source", "url": URL}]},
            {"type": "inline", "payload": [LOCAL], "upstreams": [{"name": "source", "url": URL}]},
            *[{"type": "http", "upstreams": [source]} for source in (
                {"url": URL}, {"name": "source"}, {"name": "", "url": URL},
                {"name": "private,invalid", "url": URL}, {"name": "source", "url": "private-url"},
                {"name": "source", "url": URL, "private-unsupported": True},
            )],
        ):
            cases.append({"proxy-providers": {"private-name": spec}})
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
        self.config["proxy-providers"]["sample-a"]["url"] = URL + "-second"
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

    def test_managed_node_references_keep_qx_names_without_extra_entry_groups(self):
        document = {
            "secret": SECRET,
            "cluster": {"entries": [{"name": "sg", "ip": "192.0.2.10"}],
                        "exits": [{"name": "us", "ip": "192.0.2.20"}]},
        }
        model = core.build_model(core.parse_config(document))
        local = core.subscription_proxy_metadata(model)
        document["proxy-groups"] = [{"name": "PROXY", "type": "select", "include-all": True}]
        profiles = self.generate(document)
        self.assertEqual(set(yaml.safe_load(profiles[0]["body"])["proxy-groups"][0]["proxies"]), {node["name"] for node in local})
        self.assertIn("static=Reef, sg-us, us-direct", profiles[2]["body"])
        self.assertEqual(len(yaml.safe_load(profiles[0]["body"])["proxy-groups"]), 1)
        self.assertNotIn("entry-sg", profiles[2]["body"])
        document["proxy-groups"] = [{
            "name": "PROXY", "type": "url-test", "include-all": True,
            "url": "http://probe.example.test/check", "timeout": 3000,
        }]
        profiles = self.generate(document)
        self.assertIn("server_check_url=http://probe.example.test/check", profiles[2]["body"])
        self.assertIn("server_check_timeout=3000", profiles[2]["body"])

    def test_custom_https_probe_fails_qx_generation_without_replacing_artifacts(self):
        document = {
            "secret": SECRET, "proxies": [LOCAL],
            "proxy-groups": [{"name": "PROXY", "type": "url-test", "include-all": True,
                              "url": "http://probe.example.test/check"}],
        }
        self.generate(document)
        before = self.artifacts()
        document["proxy-groups"][0]["url"] = "https://probe.example.test/private?token=private"
        with self.assertRaisesRegex(ValueError, "^Quantumult X server_check_url requires an HTTP probe URL$"):
            self.generate(document)
        self.assertEqual(self.artifacts(), before)
        profiles = self.generate(document, mihomo_only=True)
        for profile in profiles:
            self.assertEqual(yaml.safe_load(profile["body"])["proxy-groups"][0]["url"],
                             document["proxy-groups"][0]["url"])

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
                "relays": {"type": "http", "url": URL, "filter": "Sample-A|Sample-C",
                           "override": {"additional-prefix": "relay | "}},
                "exits": {"type": "inline", "payload": [
                    {**LOCAL, "name": "endpoint-b"},
                    {"name": "endpoint-a", "type": "vless", "server": "endpoint-a.example.test",
                     "port": 8443, "uuid": "00000000-0000-4000-8000-000000000001",
                     "tls": True, "flow": "xtls-rprx-vision", "network": "tcp"},
                ], "override": {"dialer-proxy": "RELAY"}},
            },
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "use": ["exits"]},
                {"name": "RELAY", "type": "select", "proxies": ["RELAY-AUTO"], "use": ["relays"]},
                {"name": "RELAY-AUTO", "type": "url-test", "use": ["relays"]},
            ],
        }

    def automatic_relay_config(self):
        return {
            "secret": SECRET,
            "proxy-providers": {
                "pool-a": {"type": "http", "url": URL, "filter": "Sample-A"},
                "pool-b": {"type": "http", "url": URL, "filter": "Sample-B"},
                "Endpoint A": {"type": "inline", "payload": [{**LOCAL, "name": "Trojan"}]},
                "Endpoint B": {"type": "inline", "payload": [
                    {**LOCAL, "name": "Trojan", "server": "endpoint-b.example.test"},
                    {"name": "Hysteria2", "type": "hysteria2", "server": "endpoint-b.example.test",
                     "port": 8443, "password": "test-password"},
                ]},
            },
            "exits": ["Endpoint A", "Endpoint B"], "pools": {1: "pool-a", 2: "pool-b"},
        }

    def test_single_endpoint_paths_are_nodes_in_both_profiles(self):
        config = {
            "secret": SECRET,
            "proxy-providers": {
                "pool-a": {"type": "inline", "payload": [NODES[0]]},
                "Endpoint A": {"type": "inline", "payload": [LOCAL]},
            },
            "exits": ["Endpoint A"], "pools": {1: "pool-a"},
        }
        for profile in self.generate(config, mihomo_only=True):
            doc = yaml.safe_load(profile["body"])
            nodes = {node["name"]: node for node in doc["proxies"]}
            groups = {group["name"]: group for group in doc["proxy-groups"]}
            for choice in groups["PROXY"]["proxies"]:
                if not choice.startswith("POOL | "):
                    self.assertIn(choice, nodes, "single-endpoint paths must not wrap a node in a group")
            self.assertEqual(set(groups), {"PROXY", "POOL | pool-a"})

    def test_automatic_relay_flattens_paths_and_collapses_single_endpoints(self):
        config = self.automatic_relay_config()
        original = copy.deepcopy(config)
        with patch.object(upstream, "urlopen", return_value=self.response()) as fetch:
            profiles = self.generate(config)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(config, original)
        self.assertEqual([p["id"] for p in profiles], ["client", "linux-server"])
        for profile in profiles:
            doc = yaml.safe_load(profile["body"])
            groups = {g["name"]: g for g in doc["proxy-groups"]}
            nodes = {n["name"]: n for n in doc["proxies"]}
            self.assertEqual(groups["PROXY"]["proxies"], [
                "RELAY | Endpoint A | pool-a", "RELAY | Endpoint A | pool-b", "DIRECT | Endpoint A",
                "RELAY | Endpoint B | pool-a", "RELAY | Endpoint B | pool-b", "DIRECT | Endpoint B",
                "POOL | pool-a", "POOL | pool-b",
            ])
            self.assertEqual([g["name"] for g in groups.values() if g["type"] == "select"], ["PROXY"])
            for endpoint in config["exits"]:
                pools = list(config["pools"].values())
                spec = config["proxy-providers"][endpoint]
                for pool in [*pools, None]:
                    path = f"RELAY | {endpoint} | {pool}" if pool else f"DIRECT | {endpoint}"
                    members = []
                    for source in spec["payload"]:
                        name = path if len(spec["payload"]) == 1 else f"{path} | {source['name']}"
                        expected = {**source, "name": name}
                        if pool:
                            expected["dialer-proxy"] = f"POOL | {pool}"
                        self.assertEqual(nodes[name], expected)
                        members.append(name)
                    if len(members) > 1:
                        group = groups[path]
                        self.assertEqual(group["type"], "url-test")
                        self.assertEqual(group["proxies"], members)
                        self.assertEqual(group["interval"], 300)
                    else:
                        self.assertNotIn(path, groups)
                    self.assertIn(path, groups["PROXY"]["proxies"])
            self.assertEqual(groups["POOL | pool-a"]["proxies"], [NODES[0]["name"]])
            self.assertEqual(groups["POOL | pool-b"]["proxies"], [NODES[1]["name"]])
            self.assertEqual(nodes[NODES[0]["name"]], NODES[0])
            self.assertEqual(len(nodes), 11)
            self.assertNotIn(URL, profile["body"])
        generated = (self.root / "web/generated/snapshot.ts").read_text()
        web = json.loads(generated.split("snapshot: Snapshot = ", 1)[1].rstrip(";\n"))
        self.assertIsNone(web["qx"]["body"])
        self.assertIn("could not resolve", web["qx"]["error"])

    def test_automatic_groups_follow_renaming_and_filtered_endpoint_counts(self):
        config = self.automatic_relay_config()
        providers = config["proxy-providers"]
        providers["Endpoint C"] = providers.pop("Endpoint A")
        config["exits"][0] = "Endpoint C"
        providers["Endpoint C"]["payload"].append({**NODES[0], "name": "HTTP"})
        providers["Endpoint B"]["exclude-type"] = "hysteria2"
        with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: self.response()):
            doc = yaml.safe_load(self.generate(config)[0]["body"])
        groups = {g["name"]: g for g in doc["proxy-groups"]}
        self.assertNotIn("Endpoint A", str(doc))
        self.assertEqual(groups["DIRECT | Endpoint C"]["proxies"], [
            "DIRECT | Endpoint C | Trojan", "DIRECT | Endpoint C | HTTP",
        ])
        self.assertEqual(groups["PROXY"]["proxies"][:3], [
            "RELAY | Endpoint C | pool-a", "RELAY | Endpoint C | pool-b", "DIRECT | Endpoint C",
        ])
        for path in ("DIRECT | Endpoint B", "RELAY | Endpoint B | pool-a", "RELAY | Endpoint B | pool-b"):
            self.assertIn(path, groups["PROXY"]["proxies"])
            self.assertNotIn(path, groups)
        choices = groups["PROXY"]["proxies"]
        # Filtering to one endpoint removes every path group but preserves its display name.
        providers["Endpoint C"]["filter"] = "^Trojan$"
        with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: self.response()):
            doc = yaml.safe_load(self.generate(config)[0]["body"])
        self.assertEqual(doc["proxy-groups"][0]["proxies"], choices)
        self.assertEqual({g["name"] for g in doc["proxy-groups"]}, {"PROXY", "POOL | pool-a", "POOL | pool-b"})
        self.assertTrue(set(choices[:-2]).issubset({node["name"] for node in doc["proxies"]}))
        before = self.artifacts()
        providers["Endpoint C"]["filter"] = "^unmatched$"
        with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: self.response()):
            with self.assertRaisesRegex(ValueError, "no nodes after filtering"):
                self.generate(config)
        self.assertEqual(self.artifacts(), before)

    def test_automatic_relay_rejects_invalid_relations_without_echoing_names(self):
        for changes in (
            {"exits": None}, {"exits": []}, {"exits": ["private-exit"]},
            {"exits": ["pool-a"]}, {"exits": ["Endpoint A", "Endpoint A"]},
            {"pools": None}, {"pools": {}}, {"pools": {1: "private-pool"}},
            {"pools": {1: "Endpoint A"}}, {"pools": {1: "pool-a", 2: "pool-a"}},
            {"pools": {0: "pool-a"}}, {"pools": {"01": "pool-a"}},
            {"pools": {1: "pool-a", "1": "pool-b"}}, {"pools": {True: "pool-a"}},
            {"relay": {"private-exit": ["pool-a"]}},
        ):
            config = {**self.automatic_relay_config(), **changes}
            with self.subTest(changes=changes), self.assertRaises(ValueError) as error:
                core.parse_config(config)
            self.assertNotIn("private-", str(error.exception))
        for setting in ("override", "payload", "proxy-groups"):
            config = self.automatic_relay_config()
            spec = config["proxy-providers"]["Endpoint A"]
            if setting == "override":
                spec["override"] = {"dialer-proxy": "private-target"}
            elif setting == "payload":
                spec["payload"][0]["dialer-proxy"] = "private-target"
            else:
                config[setting] = [{"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}]
            with self.subTest(setting=setting), self.assertRaises(ValueError) as error:
                core.parse_config(config)
            self.assertNotIn("private-", str(error.exception))
        self.assertEqual(self.artifacts(), {})

    def test_automatic_relay_detects_generated_name_conflicts_and_cycles(self):
        for name, changes in (
            ("DIRECT | Endpoint A", {"port": 9443}),
            ("RELAY | Endpoint A | pool-a", {"port": 9443}),
            ("RELAY | Endpoint B | pool-a", {}),
            ("DIRECT | Endpoint B | Trojan", {"port": 9443}),
            ("Sample-A 01", {"dialer-proxy": "RELAY | Endpoint A | pool-a"}),
            ("Sample-A 01", {"dialer-proxy": "RELAY | Endpoint B | pool-a"}),
        ):
            config = self.automatic_relay_config()
            config["proxy-providers"]["pool-a"] = {
                "type": "inline", "payload": [{**LOCAL, "name": name, **changes}],
            }
            with patch.object(upstream, "urlopen", return_value=self.response()), self.assertRaises(ValueError):
                self.generate(config)
        self.assertEqual(self.artifacts(), {})

    def test_automatic_relay_exports_and_public_example_uses_the_same_schema(self):
        config = self.automatic_relay_config()
        core.write_config(config, self.root / "config.yaml")
        output = io.StringIO()
        with patch.object(upstream, "urlopen", side_effect=AssertionError("unexpected fetch")), redirect_stdout(output):
            self.assertEqual(config_yaml.main(), 0)
        self.assertEqual(core.parse_config_yaml(output.getvalue()), config)
        example = core.load_config(core.ROOT / "config.mihomo.example.yaml")
        example["secret"] = SECRET
        with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: self.response()):
            doc = yaml.safe_load(self.generate(example)[0]["body"])
        self.assertIn("DIRECT | Endpoint A", doc["proxy-groups"][0]["proxies"])
        self.assertIn("DIRECT | Endpoint B", doc["proxy-groups"][0]["proxies"])

    def test_mihomo_preview_chains_two_exits_through_subscription_selection(self):
        with patch.object(upstream, "urlopen", return_value=self.response()):
            self.generate()
        before = self.artifacts()
        with (
            patch.object(upstream, "urlopen", return_value=self.response()) as fetch,
            patch("subscriptions.compiler.quantumult_x_nodes", side_effect=AssertionError("QX must not run")),
        ):
            profiles = self.generate(self.relay_config(), mihomo_only=True)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual([p["id"] for p in profiles], ["client", "linux-server"])
        for profile in profiles:
            self.assertEqual(Path(profile["output"]).parent, self.root / "build/subscriptions/mihomo")
            doc = yaml.safe_load(profile["body"])
            nodes = {node["name"]: node for node in doc["proxies"]}
            for name in ("endpoint-a", "endpoint-b"):
                self.assertEqual(nodes[name]["dialer-proxy"], "RELAY")
            for name in ("relay | Sample-A 01", "relay | Sample-C 03"):
                self.assertNotIn("dialer-proxy", nodes[name])
            self.assertEqual(doc["proxy-groups"][0]["proxies"], ["endpoint-b", "endpoint-a"])
            self.assertEqual(doc["proxy-groups"][1]["proxies"], ["RELAY-AUTO", "relay | Sample-A 01", "relay | Sample-C 03"])
            self.assertNotIn(URL, profile["body"])
        after = self.artifacts()
        self.assertTrue(all(after[path] == body for path, body in before.items()))

    def test_website_snapshot_preserves_chains_and_explicitly_disables_qx(self):
        with patch.object(upstream, "urlopen", return_value=self.response()):
            original = self.generate()
        with (
            patch.object(upstream, "urlopen", return_value=self.response()) as fetch,
            patch("subscriptions.compiler.quantumult_x_nodes", side_effect=AssertionError("QX must not run")),
        ):
            profiles = self.generate(self.relay_config())
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual([p["id"] for p in profiles], ["client", "linux-server"])
        for profile in profiles:
            self.assertEqual(Path(profile["output"]).parent, self.root / "build/subscriptions")
            nodes = yaml.safe_load(profile["body"])["proxies"]
            self.assertEqual({p["name"] for p in nodes if p.get("dialer-proxy") == "RELAY"}, {"endpoint-b", "endpoint-a"})
        self.assertFalse(Path(original[2]["output"]).exists())
        generated = (self.root / "web/generated/snapshot.ts").read_text()
        web = json.loads(generated.split("snapshot: Snapshot = ", 1)[1].rstrip(";\n"))
        self.assertIsNone(web["qx"]["body"])
        self.assertIn("relay conversion", web["qx"]["error"])
        self.assertEqual(web["proxies"], yaml.safe_load(profiles[0]["body"])["proxies"])
        self.assertNotIn(URL, generated)
        # Removing chains restores QX export.
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
        for target in ("missing", "endpoint-b", "PROXY"):
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
        changed["proxy-groups"][1]["proxies"].append("endpoint-b")
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
