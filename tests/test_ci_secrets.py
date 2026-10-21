from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from reef import core
from subscriptions import substore, upstream


ROOT = Path(__file__).resolve().parents[1]
SECRET = "ab" * 32
URL = "https://user:private-password@example.test/subs/private-path?token=private-query"


class CISecretTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("REEF_", "TEST_"))
        }
        self.env["CI"] = "true"
        self.env["PATH"] = f"{Path(sys.executable).parent}:{self.env.get('PATH', os.defpath)}"
        self.env["PYTHONPATH"] = str(ROOT)
        workflow = yaml.safe_load((ROOT / ".github/workflows/deploy-website.yml").read_text())
        self.steps = {step["name"]: step for step in workflow["jobs"]["deploy"]["steps"]}

    def run_step(self, name, **env):
        return subprocess.run(
            ["bash", "-c", self.steps[name]["run"]],
            cwd=self.root, env={**self.env, **env}, text=True, capture_output=True, timeout=10,
        )

    def test_workflow_masks_values_and_url_tokens_and_writes_private_config(self):
        node = yaml.safe_load((ROOT / "tests/fixtures/extension.yaml").read_text())["nodes"][0]
        document = {
            "secret": SECRET,
            "subscriptions": {"upstream_urls": [URL], "nodes": [node]},
        }
        payload = core.dump_config(document)
        result = self.run_step("Write configuration", CONFIG_YAML=payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertTrue(all(line.startswith("::add-mask::") for line in lines))
        for value in (SECRET, URL, "private-password", "private-path", "private-query", node["uuid"], node["server"]):
            self.assertIn("::add-mask::" + value, lines)
        path = self.root / "config.yaml"
        self.assertEqual(core.load_config(path), document)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.run_step("Remove private build inputs").returncode, 0)
        self.assertFalse(path.exists())

    def test_workflow_rejects_invalid_and_deployment_configuration_without_echoing(self):
        valid = core.dump_config({"secret": SECRET, "subscriptions": {"upstream_urls": [URL]}})
        for payload in (
            valid + "ssh_private_key: private-key\n",
            valid + "REEF_TEST_MODE: private-value\n",
            valid + "TEST_HOST_MAP: private-value\n",
            valid + "NODE_OPTIONS: private-value\n",
            valid + "private-value: [broken\n",
            valid + f"secret: '{SECRET}'\n",
            "secret: private-value\n",
            valid.replace("subscriptions:", "subscriptions:\n  private-value: bad"),
            "",
        ):
            result = self.run_step("Write configuration", CONFIG_YAML=payload)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("private-", result.stdout + result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
            self.assertFalse((self.root / "config.yaml").exists())

    def test_workflow_supports_standalone_nodes_without_cluster_or_upstreams(self):
        nodes = yaml.safe_load((ROOT / "tests/fixtures/extension.yaml").read_text())["nodes"]
        document = {"secret": SECRET, "subscriptions": {"nodes": nodes}}
        result = self.run_step("Write configuration", CONFIG_YAML=core.dump_config(document))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(core.load_config(self.root / "config.yaml"), document)

    def test_workflow_masks_native_provider_credentials_and_round_trips_config(self):
        document = {
            "secret": SECRET,
            "proxy-providers": {"upstream": {"type": "http", "url": URL, "filter": "Singapore|United States"}},
            "proxy-groups": [{"name": "PROXY", "type": "select", "use": ["upstream"]}],
        }
        result = self.run_step("Write configuration", CONFIG_YAML=core.dump_config(document))
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertTrue(all(line.startswith("::add-mask::") for line in lines))
        for value in (URL, "private-password", "private-path", "private-query"):
            self.assertIn("::add-mask::" + value, lines)
        self.assertEqual(core.load_config(self.root / "config.yaml"), document)

    def test_mask_commands_escape_newlines_in_decoded_url_tokens(self):
        document = {"secret": SECRET, "subscriptions": {"upstream_urls": [
            "https://user:private%0Dpassword@example.test/private%0A::error::injection",
        ]}}
        result = self.run_step("Write configuration", CONFIG_YAML=core.dump_config(document))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(line.startswith("::add-mask::") for line in result.stdout.splitlines()))
        self.assertIn("::add-mask::private%0A::error::injection", result.stdout)
        self.assertIn("::add-mask::private%0Dpassword", result.stdout)

    def test_workflow_masks_every_named_upstream_in_multiple_collections(self):
        sources = [
            {"name": "a", "url": URL},
            {"name": "b", "url": "https://user:encoded%2Dpassword@example.test/encoded%2Dpath?token=encoded%2Dquery"},
        ]
        document = {
            "secret": SECRET,
            "proxy-providers": {
                "a": {"type": "http", "upstreams": sources[:1]},
                "combined": {"type": "http", "upstreams": sources},
            },
        }
        result = self.run_step("Write configuration", CONFIG_YAML=core.dump_config(document))
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertTrue(all(line.startswith("::add-mask::") for line in lines))
        for value in (URL, sources[1]["url"], "private-password", "private-path", "private-query",
                      "encoded-password", "encoded-path", "encoded-query"):
            self.assertIn("::add-mask::" + value.replace("%", "%25"), lines)
        self.assertEqual(core.load_config(self.root / "config.yaml"), document)

    def test_vercel_build_diagnostics_stay_private_on_success_and_failure(self):
        binary = self.root / "vercel"
        for status in (0, 1):
            binary.write_text(f"#!/bin/sh\necho private-generated-password\necho private-url >&2\nexit {status}\n")
            binary.chmod(0o700)
            result = self.run_step("Build", PATH=f"{self.root}:{self.env.get('PATH', os.defpath)}")
            self.assertEqual(result.returncode, status)
            self.assertNotIn("private-generated-password", result.stdout + result.stderr)
            self.assertNotIn("private-url", result.stdout + result.stderr)
            log = self.root / "build/website-build.log"
            self.assertIn("private-generated-password", log.read_text())
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.run_step("Remove private build inputs").returncode, 0)
            self.assertFalse(log.exists())

    def test_cli_errors_hide_values_that_python_exception_messages_echo(self):
        config_file = self.root / "config.yaml"
        core.write_config({
            "secret": SECRET,
            "cluster": {"exits": [{"name": "us", "ip": "private-invalid-ip"}]},
        }, config_file)
        for module in ("render", "urls"):
            command = [sys.executable, "-m", f"reef.cli.{module}"]
            if module == "render":
                command.append("web")
            result = subprocess.run(
                command, cwd=ROOT, env={**self.env, "TEST_CONFIG_FILE": str(config_file), "REEF_TEST_MODE": "1"},
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("private-invalid-ip", result.stdout + result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_converter_suppresses_failures_and_does_not_inherit_secrets(self):
        content = b"test-only-converter"
        bundle = self.root / "build/substore" / f"proxy-utils-{substore.VERSION}.mjs"
        bundle.parent.mkdir(parents=True)
        bundle.write_bytes(content)
        failure = subprocess.CalledProcessError(1, ["node"], output="private-node-password")
        with (
            patch.object(substore, "ROOT", self.root),
            patch.object(substore, "SHA256", hashlib.sha256(content).hexdigest()),
            patch.dict(os.environ, {"CONFIG_YAML": core.dump_config({"secret": SECRET, "subscriptions": {"upstream_urls": [URL]}})}),
            patch.object(substore.subprocess, "run", side_effect=failure) as run,
            self.assertRaisesRegex(ValueError, "^Sub-Store conversion failed") as error,
        ):
            substore.convert([{"name": "test-node", "password": "private-node-password"}])
        self.assertNotIn("private-node-password", str(error.exception))
        self.assertEqual(set(run.call_args.kwargs["env"]), {"PATH"})
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn("private-node-password", " ".join(run.call_args.args[0]))

    def test_converter_checksum_and_silent_drops_fail_closed(self):
        bundle = self.root / "build/substore" / f"proxy-utils-{substore.VERSION}.mjs"
        bundle.parent.mkdir(parents=True)
        bundle.write_bytes(b"tampered")
        with (
            patch.object(substore, "ROOT", self.root),
            patch.object(substore.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "checksum"),
        ):
            substore.convert([])
        run.assert_not_called()
        with (
            patch.object(upstream, "convert", return_value=[]),
            self.assertRaisesRegex(ValueError, "dropped or renamed"),
        ):
            upstream.quantumult_x_nodes([{
                "name": "test-node", "type": "http", "server": "example.test", "port": 443,
            }])
