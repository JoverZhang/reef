from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from reef import core


ROOT = Path(__file__).resolve().parents[1]
CONFIG = {
    "secret": "ab" * 32,
    "ssh_private_key": "deployment-only-private-key",
    "subscriptions": {"upstream_urls": ["https://example.test/private-token?format=clash&x=1"]},
}


class WebDeployTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "config.yaml"
        core.write_config(CONFIG, self.config)
        self.calls = self.root / "calls.jsonl"
        gh = self.root / "gh"
        gh.write_text(f"#!{sys.executable}\n" + '''import json
import os
import sys
from pathlib import Path

upload = sys.argv[1:3] == ["secret", "set"]
call = {"args": sys.argv[1:], "input": sys.stdin.read() if upload else None}
with Path(os.environ["TEST_GH_CALLS"]).open("a") as output:
    output.write(json.dumps(call) + "\\n")
sys.exit(int(os.environ.get("TEST_GH_UPLOAD_STATUS" if upload else "TEST_GH_DISPATCH_STATUS", "0")))
''')
        gh.chmod(0o700)
        self.env = {
            key: value for key, value in os.environ.items()
            if key != "CI" and not key.startswith(("REEF_", "TEST_", "JUST_"))
        }
        self.env.update({
            "PATH": f"{self.root}:{os.environ.get('PATH', os.defpath)}",
            "PYTHONPATH": str(ROOT),
            "REEF_TEST_MODE": "1",
            "TEST_CONFIG_FILE": str(self.config),
            "TEST_GH_CALLS": str(self.calls),
        })

    def deploy(self, **env):
        result = subprocess.run(
            ["just", "--no-deps", "--justfile", str(ROOT / "justfile"),
             "--working-directory", str(self.root), "--set", "python", sys.executable, "web-deploy"],
            env={**self.env, **env}, capture_output=True, text=True, timeout=10,
        )
        for value in (CONFIG["secret"], CONFIG["ssh_private_key"], CONFIG["subscriptions"]["upstream_urls"][0]):
            self.assertNotIn(value, result.stdout + result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []
        return result, calls

    def test_uploads_export_via_stdin_before_dispatching_master(self):
        result, calls = self.deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["args"] for call in calls], [
            ["secret", "set", "CONFIG_YAML", "--repo", "JoverZhang/reef"],
            ["workflow", "run", "deploy-website.yml", "--repo", "JoverZhang/reef", "--ref", "master"],
        ])
        self.assertEqual(yaml.safe_load(calls[0]["input"]), {
            key: value for key, value in CONFIG.items() if key != "ssh_private_key"
        })
        self.assertIsNone(calls[1]["input"])
        self.assertEqual(core.load_config(self.config), CONFIG)

    def test_export_failure_does_not_touch_github(self):
        self.config.write_text("secret: [private-broken-config")
        result, calls = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertNotIn("private-broken-config", result.stderr)

    def test_upload_failure_does_not_dispatch_workflow(self):
        result, calls = self.deploy(TEST_GH_UPLOAD_STATUS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["args"][:2], ["secret", "set"])

    def test_dispatch_failure_is_reported(self):
        result, calls = self.deploy(TEST_GH_DISPATCH_STATUS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
