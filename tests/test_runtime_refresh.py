from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from reef import core
from subscriptions import rules, runtime, upstream
from test_web_snapshot import CONFIG, NODES, PASSWORD, URL


class RuntimeRefreshTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        original = core.project_path
        patcher = patch.object(core, "project_path", side_effect=lambda *parts:
                             self.root.joinpath(*parts) if parts[0] in {"build", "web"} else original(*parts))
        patcher.start()
        self.addCleanup(patcher.stop)

    def prepare(self, config=CONFIG):
        core.prepare_web(core.build_model(core.parse_config(config)))
        return json.loads((self.root / "web/generated/input.json").read_text())

    def test_build_prepares_only_private_inputs_without_network_or_root_credentials(self):
        config = {**CONFIG, "cluster": {"exits": [{"name": "exit-a", "ip": "192.0.2.21"}]}}
        with patch.object(upstream, "urlopen", side_effect=AssertionError("Build fetched an upstream")), \
                patch.object(rules, "urlopen", side_effect=AssertionError("Build fetched rules")):
            payload = self.prepare(config)
        serialized = json.dumps(payload)
        for value in (PASSWORD, config["secret"], "ssh_private_key", "stats_secret"):
            self.assertNotIn(value, serialized)
        self.assertIn(URL, serialized)
        bootstrap = (self.root / "web/generated/bootstrap.ts").read_text()
        self.assertNotIn(URL, bootstrap)
        self.assertNotIn(PASSWORD, bootstrap)
        self.assertIn('"poolIds": ["1", "7"]', bootstrap)
        for path in (self.root / "web/generated").iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.prepare(config)
        self.assertNotEqual(bootstrap, (self.root / "web/generated/bootstrap.ts").read_text())

    @staticmethod
    def rule_response(url, **kwargs):
        if "/QuantumultX/" in url:
            return io.BytesIO(b"# Fictional resource\nHOST-SUFFIX,service.example.invalid,Proxy\n")
        return io.BytesIO(b"payload:\n  - DOMAIN-SUFFIX,service.example.invalid\n")

    def test_runtime_compiles_nodes_and_all_hosted_rules_together(self):
        payload = self.prepare()
        with patch.object(upstream, "urlopen", return_value=io.BytesIO(yaml.safe_dump({"proxies": NODES}).encode())) as nodes, \
                patch.object(rules, "urlopen", side_effect=self.rule_response) as resources:
            snapshot = runtime.refresh(payload)
        self.assertEqual(nodes.call_count, 1)
        self.assertEqual(resources.call_count, 10)
        self.assertEqual(len(snapshot["resources"]), 10)
        self.assertEqual(len(snapshot["qx"]["relay"]["sections"]["filter_remote"]), 5)
        for resource in snapshot["resources"]:
            self.assertNotIn("url", resource)
            if resource["profile"] == "qx":
                expected = resource["policy"] != "direct"
                self.assertEqual(resource["reinject"], expected)
                self.assertEqual("via-interface=%TUN%" in resource["lines"][0], expected)
                self.assertIn(resource["policy"], resource["lines"][0])
        for provider in snapshot["templates"]["clash-geo"]["rule-providers"].values():
            self.assertTrue(provider["url"].startswith("reef-resource:"))
            self.assertEqual(provider["interval"], 3600)
        self.assertNotIn(URL, json.dumps(snapshot))

    def test_rule_failures_abort_the_refresh_and_identify_only_the_resource(self):
        for bad in (OSError("https://source.example.invalid/private-credential"), io.BytesIO(b"invalid")):
            def response(url, **kwargs):
                if "/Clash/OpenAI/" in url:
                    if isinstance(bad, Exception):
                        raise bad
                    return bad
                return self.rule_response(url, **kwargs)
            with patch.object(upstream, "urlopen", side_effect=lambda *a, **kw: io.BytesIO(yaml.safe_dump({"proxies": NODES}).encode())), \
                    patch.object(rules, "urlopen", side_effect=response), \
                    self.assertRaisesRegex(ValueError, r"^Rule resource clash-geo/bm_openai (fetch failed|must contain a nonempty YAML rule payload)$"):
                runtime.refresh(self.prepare())

    def test_rule_parser_deduplicates_and_rejects_unrepresentable_rules(self):
        body = b"\xef\xbb\xbf# Comment\nHOST-SUFFIX,a.example.invalid,Original\nHOST-SUFFIX,a.example.invalid,Original\n"
        self.assertEqual(rules.qx_rules(body, "Reef", True, "resource"),
                         ["host-suffix, a.example.invalid, Reef, via-interface=%TUN%"])
        for body in (b"# empty", b"DOMAIN,a.example.invalid,Policy", b"HOST,a.example.invalid,Policy,unknown"):
            with self.assertRaises(ValueError):
                rules.qx_rules(body, "direct", False, "resource")

    def test_worker_errors_never_expose_private_diagnostics(self):
        for error, expected in (
            ("upstream URL #2 (proxy-provider #1) fetch failed", "upstream URL #2 (proxy-provider #1) fetch failed"),
            ("private-node-password https://source.example.invalid/secret", "Subscription compilation failed; check node and policy configuration."),
        ):
            output = io.StringIO()
            with patch.object(runtime, "refresh", side_effect=ValueError(error)), \
                    patch("sys.stdin", io.StringIO("{}")), patch("sys.argv", ["runtime"]), \
                    contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
                runtime.main()
            self.assertEqual(json.loads(output.getvalue()), {"error": expected})

    def test_web_runtime_contract(self):
        # The optional Redis suite performs over 100 refreshes through docker exec.
        timeout = 360 if os.environ.get("REEF_TEST_REDIS_CONTAINER") else 120
        result = subprocess.run(["node", "--experimental-strip-types", "--test", "tests/web_runtime.mjs"],
                                cwd=core.ROOT, capture_output=True, text=True, timeout=timeout, env=os.environ.copy())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
