from __future__ import annotations

import copy
import hashlib
import io
import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from reef import core
from subscriptions import quantumult_x, upstream


PASSWORD = "fictional-preview-key-" * 3
URL = "https://source.example.invalid/private-upstream-token"
NODE = {"type": "http", "server": "198.51.100.10", "port": 8443,
        "password": "fictional-node-password"}
NODES = [{**NODE, "name": name} for name in ("Alpha 01", "Beta 02", "Gamma 03", "Removed 04")]
CONFIG = {
    "secret": "ab" * 32,
    "web": {"password": PASSWORD},
    "proxy-providers": {
        "pool-a": {"type": "http", "upstreams": [{"name": "source-a", "url": URL}],
                   "exclude-filter": "Removed"},
        "pool-b": {"type": "http", "upstreams": [{"name": "source-a", "url": URL}],
                   "exclude-filter": "Removed"},
        "Endpoint A": {"type": "inline", "payload": [{**NODE, "name": "HTTP", "server": "192.0.2.10"}]},
        "Endpoint B": {"type": "inline", "payload": [
            {**NODE, "name": "HTTP", "server": "192.0.2.11"},
            {**NODE, "name": "Hysteria2", "type": "hysteria2", "server": "192.0.2.11"},
        ]},
    },
    "exits": ["Endpoint A", "Endpoint B"],
    "pools": {1: "pool-a", 7: "pool-b"},
}


class WebSnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        original = core.project_path
        patcher = patch.object(core, "project_path", side_effect=lambda *parts:
                             self.root.joinpath(*parts) if parts[0] in {"build", "web"} else original(*parts))
        patcher.start()
        self.addCleanup(patcher.stop)
        rules = patch.object(quantumult_x, "urlopen", side_effect=lambda *a, **kw: io.BytesIO(
            b"# Fictional rules\nHOST-SUFFIX,service.example.invalid,Proxy\nIP-CIDR,203.0.113.0/24,Proxy\n"))
        rules.start()
        self.addCleanup(rules.stop)
        self.snapshot = self.build(CONFIG)

    def build(self, config):
        with patch.object(upstream, "urlopen", return_value=io.BytesIO(yaml.safe_dump({"proxies": NODES}).encode())) as fetch:
            core.render_web(core.build_model(core.parse_config(config)))
        if config.get("pools"):
            self.assertEqual(fetch.call_count, 1, "Shared upstream must be fetched once per snapshot")
        self.generated = (self.root / "web/generated/snapshot.ts").read_text()
        return json.loads(self.generated.split("snapshot: Snapshot = ", 1)[1].rstrip(";\n"))

    def request(self, query=None, *, download=False, snapshot=None):
        query = {"password": PASSWORD, **(query or {})} if not isinstance(query, list) else query
        result = subprocess.run(
            ["node", "--experimental-strip-types", str(core.ROOT / "tests/web_request.mjs")],
            input=json.dumps({"snapshot": snapshot or self.snapshot, "query": query, "download": download}),
            text=True, capture_output=True, timeout=15, check=True,
        )
        return json.loads(result.stdout)

    def test_snapshot_keeps_original_names_and_only_the_password_digest(self):
        for private in (PASSWORD, CONFIG["secret"], URL, "ssh_private_key", "Removed 04"):
            self.assertNotIn(private, self.generated)
        self.assertTrue(self.generated.startswith("import 'server-only';"))
        self.assertEqual(self.snapshot["passwordHash"], hashlib.sha256(PASSWORD.encode()).hexdigest())
        self.assertEqual(self.snapshot["pools"][0]["nodes"][0]["originalName"], "Alpha 01")
        self.assertEqual(self.snapshot["pools"][0]["nodes"][0]["name"], "source-a | Alpha 01")

    def test_authentication_precedes_parameter_validation(self):
        for query in ([], {"password": "wrong", "include999": "Alpha"},
                      [("password", PASSWORD), ("password", PASSWORD)]):
            for download in (False, True):
                result = self.request(query, download=download)
                self.assertEqual(result, {"status": 404, "body": "Not found"})
        for query in ({"type": "invalid"}, {"include2": "Alpha"}, {"include01": "Alpha"},
                      {"dump": "1"}, {"include1": ", ,"},
                      [("password", PASSWORD), ("type", "clash"), ("type", "qx")]):
            self.assertEqual(self.request(query)["status"], 400)

    def test_filters_are_literal_or_case_insensitive_and_pool_specific(self):
        query = {"include1": " alpha, BETA ", "include7": "Gamma"}
        preview = self.request(query)["preview"]
        self.assertEqual([pool["selected"] for pool in preview["pools"]], [
            ["source-a | Alpha 01", "source-a | Beta 02"], ["source-a | Gamma 03"],
        ])
        document = yaml.safe_load(self.request(query, download=True)["body"])
        groups = {group["name"]: group for group in document["proxy-groups"]}
        for pool in preview["pools"]:
            self.assertEqual(groups[pool["group"]]["proxies"], pool["selected"])
        self.assertEqual(groups["PROXY"]["proxies"], preview["choices"])
        for term in ("source-a", "Alpha|Beta", ".*", "Removed"):
            self.assertEqual(self.request({"include1": term}, download=True)["status"], 422)

    def test_empty_filter_selects_all_and_requests_do_not_mutate_the_snapshot(self):
        baseline = self.request(download=True)
        self.assertEqual(baseline, self.request({"include1": "", "include7": "  "}, download=True))
        self.request({"include1": "Alpha", "include7": "Beta"}, download=True)
        self.assertEqual(baseline, self.request(download=True))

    def test_shared_nodes_survive_only_in_the_pools_that_select_them(self):
        document = yaml.safe_load(self.request({"include1": "Alpha", "include7": "Beta"}, download=True)["body"])
        nodes = {node["name"] for node in document["proxies"]}
        self.assertIn("source-a | Alpha 01", nodes)
        self.assertIn("source-a | Beta 02", nodes)
        self.assertNotIn("source-a | Gamma 03", nodes)
        groups = {group["name"]: group for group in document["proxy-groups"]}
        self.assertEqual(groups["POOL | pool-a"]["proxies"], ["source-a | Alpha 01"])
        self.assertEqual(groups["POOL | pool-b"]["proxies"], ["source-a | Beta 02"])

    def test_stable_pool_ids_survive_reordering_and_yaml_roundtrip(self):
        config = copy.deepcopy(CONFIG)
        config["pools"] = {"7": "pool-b", 1: "pool-a"}
        config = core.parse_config_yaml(core.dump_config(config))
        reordered = self.build(config)
        result = self.request({"include1": "Alpha", "include7": "Beta"}, snapshot=reordered)
        selections = {pool["id"]: pool["selected"] for pool in result["preview"]["pools"]}
        self.assertEqual(selections, {"1": ["source-a | Alpha 01"], "7": ["source-a | Beta 02"]})

    def test_zero_match_preview_is_visible_but_export_never_falls_back(self):
        preview = self.request({"include1": "no-such-node"})
        self.assertEqual(preview["status"], 200)
        self.assertIn("include1 selects no nodes in pool-a", preview["body"])
        self.assertIn("Excluded by include1", preview["body"])
        self.assertEqual(len(preview["preview"]["pools"][0]["nodes"]), 3)
        result = self.request({"include1": "no-such-node"}, download=True)
        self.assertEqual(result["status"], 422)
        self.assertNotIn("proxies:", result["body"])

    def test_dump_preserves_dns_rules_credentials_and_path_cardinality(self):
        for profile in ("clash", "clash-geo"):
            document = yaml.safe_load(self.request({"type": profile, "include1": "Alpha", "include7": "Beta"}, download=True)["body"])
            for key, value in self.snapshot["templates"][profile].items():
                self.assertEqual(document[key], value)
            nodes = {node["name"]: node for node in document["proxies"]}
            groups = {group["name"]: group for group in document["proxy-groups"]}
            self.assertIn("DIRECT | Endpoint A", nodes)
            self.assertNotIn("DIRECT | Endpoint A", groups)
            self.assertEqual(groups["DIRECT | Endpoint B"]["type"], "url-test")
            self.assertEqual(nodes["RELAY | Endpoint A | pool-a"]["dialer-proxy"], "POOL | pool-a")
            self.assertNotIn("dialer-proxy", nodes["DIRECT | Endpoint A"])
            self.assertEqual(nodes["RELAY | Endpoint A | pool-a"]["password"], NODE["password"])

    def test_yaml_keeps_strings_that_legacy_readers_mistake_for_booleans(self):
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["proxies"][0]["password"] = "off"
        snapshot["proxies"][0]["username"] = "yes"
        document = yaml.safe_load(self.request(download=True, snapshot=snapshot)["body"])
        self.assertEqual(document["proxies"][0]["password"], "off")
        self.assertEqual(document["proxies"][0]["username"], "yes")

    def test_qx_server_check_uses_http_without_changing_mihomo_probes(self):
        result = self.request({"type": "qx"}, download=True)
        self.assertEqual(result["status"], 200)
        checks = [line for line in result["body"].splitlines() if line.startswith("server_check_url=")]
        self.assertEqual(checks, ["server_check_url=http://www.gstatic.com/generate_204"])
        for kind in ("clash", "clash-geo"):
            document = yaml.safe_load(self.request({"type": kind}, download=True)["body"])
            urls = {group["url"] for group in document["proxy-groups"] if group["type"] == "url-test"}
            self.assertEqual(urls, {"https://www.gstatic.com/generate_204"})

    def test_qx_uses_three_selection_levels_and_collapses_supported_exit_protocols(self):
        preview = self.request({"type": "qx"})
        self.assertEqual(preview["status"], 200)
        self.assertFalse(preview["preview"]["errors"])
        self.assertIn("Protocol/options unavailable in QX", preview["body"])
        self.assertEqual(preview["preview"]["choices"], ["EXIT | Endpoint A", "EXIT | Endpoint B", "POOL | pool-a", "POOL | pool-b"])
        self.assertEqual(preview["preview"]["relays"], [
            {"name": f"RELAY | Endpoint {name}", "choices": ["POOL | pool-a", "POOL | pool-b", "direct"]}
            for name in ("A", "B")
        ])
        result = self.request({"type": "qx"}, download=True)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body"], (self.root / "build/subscriptions/quantumult-x.conf").read_text())
        self.assertIn("tag=EXIT | Endpoint B", result["body"])
        self.assertNotIn("url-latency-benchmark=EXIT", result["body"])
        self.assertNotIn("Hysteria2", result["body"])

    def test_qx_business_rules_reinject_once_and_endpoint_rules_select_the_intermediate(self):
        body = self.request({"type": "qx"}, download=True)["body"]
        sections = quantumult_x._sections(body)
        rules = sections["filter_local"]
        for exit_name, address in (("A", "192.0.2.10"), ("B", "192.0.2.11")):
            self.assertIn(f"ip-cidr, {address}/32, RELAY | Endpoint {exit_name}", rules)
        self.assertIn("ip-cidr, 198.51.100.10/32, direct", rules)
        self.assertIn("host-suffix, service.example.invalid, Reef, via-interface=%TUN%", rules)
        self.assertIn("ip-cidr, 203.0.113.0/24, Reef, via-interface=%TUN%", rules)
        self.assertEqual(rules[-1], "final, Reef, via-interface=%TUN%")
        for rule in rules:
            fields = rule.split(", ")
            if "Reef" in fields:
                self.assertEqual(fields[-1], "via-interface=%TUN%")
            else:
                self.assertNotIn("via-interface=", rule)
        self.assertTrue(all("force-policy=direct" in line for line in sections["filter_remote"]))
        self.assertNotIn("resource_parser_url", body)

    def test_qx_filters_shared_nodes_independently_without_mutating_the_snapshot(self):
        all_nodes = self.request({"type": "qx"}, download=True)
        result = self.request({"type": "qx", "include1": "Alpha", "include7": "Beta"}, download=True)
        body = result["body"]
        self.assertEqual(result["status"], 200)
        self.assertIn("url-latency-benchmark=POOL | pool-a, source-a | Alpha 01, check-interval", body)
        self.assertIn("url-latency-benchmark=POOL | pool-b, source-a | Beta 02, check-interval", body)
        self.assertNotIn("Gamma 03", body)
        self.assertEqual(body.count("tag=source-a | Alpha 01"), 1)
        self.assertEqual(all_nodes, self.request({"type": "qx"}, download=True))

    def test_qx_filter_matching_only_unsupported_protocols_blocks_export(self):
        nodes = NODES + [{**NODE, "name": "Unsupported", "type": "hysteria2"}]
        with patch(__name__ + ".NODES", nodes):
            snapshot = self.build(CONFIG)
        query = {"type": "qx", "include1": "Unsupported"}
        preview = self.request(query, snapshot=snapshot)
        self.assertEqual(preview["preview"]["pools"][0]["selected"], [])
        self.assertIn("Protocol/options unavailable in QX", preview["body"])
        self.assertEqual(self.request(query, snapshot=snapshot, download=True)["status"], 422)
        self.assertEqual(self.request({**query, "type": "clash"}, snapshot=snapshot, download=True)["status"], 200)

    def test_qx_multiple_supported_protocols_share_the_exit_relay_selector(self):
        config = copy.deepcopy(CONFIG)
        config["proxy-providers"]["Endpoint B"]["payload"].append({
            **NODE, "type": "trojan", "name": "Trojan", "server": "192.0.2.11", "port": 443,
        })
        snapshot = self.build(config)
        result = self.request({"type": "qx"}, snapshot=snapshot, download=True)
        self.assertEqual(result["status"], 200)
        self.assertIn("url-latency-benchmark=EXIT | Endpoint B, EXIT | Endpoint B | HTTP, EXIT | Endpoint B | Trojan,", result["body"])
        self.assertEqual(result["body"].count("ip-cidr, 192.0.2.11/32, RELAY | Endpoint B"), 1)

    def test_qx_ambiguous_addresses_and_empty_exits_block_only_qx(self):
        for changes in ({"server": "192.0.2.10"}, {"server": NODE["server"]}, {"type": "hysteria2"}):
            config = copy.deepcopy(CONFIG)
            config["proxy-providers"]["Endpoint B"]["payload"][0].update(changes)
            snapshot = self.build(config)
            result = self.request({"type": "qx"}, snapshot=snapshot, download=True)
            self.assertEqual(result["status"], 422)
            self.assertNotIn("192.0.2.", result["body"])
            self.assertNotIn(NODE["server"], result["body"])
            self.assertEqual(self.request({"type": "clash"}, snapshot=snapshot, download=True)["status"], 200)

    def test_qx_rule_failure_preserves_artifacts_and_redacts_response_details(self):
        before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        for response in (b"private-response", b"", b"FINAL,private-response,Proxy", b"HOST,example.invalid,Proxy,unexpected"):
            with patch.object(quantumult_x, "urlopen", side_effect=lambda *a, **kw: io.BytesIO(response)):
                with self.assertRaisesRegex(ValueError, "QX rule resource #1") as error:
                    self.build(CONFIG)
            self.assertNotIn("private-response", str(error.exception))
            self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})

    def test_qx_pins_dns_once_preserving_tls_identity_and_certificate_pins(self):
        config = copy.deepcopy(CONFIG)
        config["proxy-providers"]["Endpoint A"]["payload"] = [
            {**NODE, "name": "Trojan", "type": "trojan", "server": "exit.example.invalid", "fingerprint": "ab" * 32},
            {**NODE, "name": "HTTPS", "tls": True, "server": "exit.example.invalid", "port": 443},
        ]
        records = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
        ]
        with patch.object(quantumult_x.socket, "getaddrinfo", return_value=records) as lookup:
            snapshot = self.build(config)
        self.assertEqual(lookup.call_count, 1)
        qx = self.request({"type": "qx"}, snapshot=snapshot, download=True)
        self.assertEqual(qx["status"], 200)
        lines = quantumult_x._sections(qx["body"])["server_local"]
        owned = [line for line in lines if "tag=EXIT | Endpoint A | " in line]
        self.assertEqual(len(owned), 2)
        self.assertTrue(all("=192.0.2.10:" in line and "tls-host=exit.example.invalid" in line for line in owned))
        self.assertIn("tls-cert-sha256=" + "ab" * 32, owned[0])
        self.assertIn("tls-verification=true", owned[0])
        mihomo = yaml.safe_load(self.request({"type": "clash"}, snapshot=snapshot, download=True)["body"])
        self.assertTrue(any(node["server"] == "exit.example.invalid" for node in mihomo["proxies"]))

    def test_qx_ipv6_socket_routes_and_websocket_host_survive_pinning(self):
        config = copy.deepcopy(CONFIG)
        config["proxy-providers"]["Endpoint A"]["payload"] = [{
            "name": "WebSocket", "type": "vless", "server": "exit.example.invalid", "port": 443,
            "uuid": "11111111-2222-4333-8444-555555555555", "tls": True, "network": "ws",
            "ws-opts": {"path": "/tunnel", "headers": {"Host": "websocket.example.invalid"}},
        }]
        records = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 0, 0, 0))]
        with patch.object(quantumult_x.socket, "getaddrinfo", return_value=records):
            snapshot = self.build(config)
        result = self.request({"type": "qx"}, snapshot=snapshot, download=True)
        self.assertEqual(result["status"], 200)
        self.assertIn("vless=[2001:db8::10]:443", result["body"])
        self.assertIn("ip6-cidr, 2001:db8::10/128, RELAY | Endpoint A", result["body"])
        self.assertIn("obfs-host=websocket.example.invalid", result["body"])
        self.assertIn("obfs-uri=/tunnel", result["body"])

    def test_qx_dns_failure_does_not_expose_hostnames_or_create_a_direct_fallback(self):
        config = copy.deepcopy(CONFIG)
        config["proxy-providers"]["Endpoint A"]["payload"][0]["server"] = "private-host.example.invalid"
        with patch.object(quantumult_x.socket, "getaddrinfo", side_effect=OSError("private-host.example.invalid")):
            snapshot = self.build(config)
        result = self.request({"type": "qx"}, snapshot=snapshot, download=True)
        self.assertEqual(result["status"], 422)
        self.assertIn("could not resolve", result["body"])
        self.assertNotIn("private-host", result["body"])

    def test_qx_generated_names_cannot_silently_replace_a_pool_node(self):
        config = copy.deepcopy(CONFIG)
        config["proxy-providers"]["pool-a"] = {
            "type": "inline", "payload": [{**NODE, "name": "EXIT | Endpoint A"}],
        }
        snapshot = self.build(config)
        result = self.request({"type": "qx"}, snapshot=snapshot, download=True)
        self.assertEqual(result["status"], 422)
        self.assertIn("names conflict", result["body"])

    def test_non_chain_qx_export_is_unchanged(self):
        direct = self.build({"secret": CONFIG["secret"], "web": CONFIG["web"], "proxies": NODES[:1]})
        qx = self.request({"type": "qx"}, download=True, snapshot=direct)
        self.assertEqual(qx["status"], 200)
        self.assertIn("[server_local]", qx["body"])

    def test_preview_exposes_no_connection_credentials_and_escapes_names(self):
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["exits"][0]["name"] = '<script>alert("example")</script>'
        preview = self.request(snapshot=snapshot)
        for private in (NODE["password"], NODE["server"], CONFIG["secret"], URL, self.snapshot["passwordHash"]):
            self.assertNotIn(private, preview["body"])
            self.assertNotIn(private, json.dumps(preview["preview"]))
        self.assertNotIn('<script>alert("example")</script>', preview["body"])
        self.assertIn("&lt;script&gt;", preview["body"])

    def test_web_password_is_required_and_must_be_independent(self):
        for value in (None, "short", CONFIG["secret"], " " * 40):
            with self.subTest(password=value), self.assertRaises(ValueError):
                core.parse_config({**CONFIG, "web": {"password": value}})
        config = {key: value for key, value in CONFIG.items() if key != "web"}
        with patch.object(upstream, "urlopen", side_effect=AssertionError("Do not fetch before checking web config")):
            with self.assertRaisesRegex(ValueError, "web.password is required"):
                core.render_web(core.build_model(core.parse_config(config)))

    def test_pool_ids_reject_ambiguous_yaml_numbers(self):
        for key in ("01", "0x1", "-1", "0", "1_0"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                core.parse_config_yaml(core.dump_config(CONFIG).replace("  1: pool-a", f"  {key}: pool-a"))
