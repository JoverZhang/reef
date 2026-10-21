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
        self.remote = self.root / "remote.git"
        self.git("init", "--initial-branch=master")
        self.git("config", "user.name", "Other Account")
        self.git("config", "user.email", "other@example.test")
        (self.root / "VERSION").write_text("202607081433\n")
        (self.root / "README.md").write_text("Original content\n")
        self.git("add", "VERSION", "README.md")
        self.git("commit", "-m", "Initial commit")
        self.initial_commit = self.git("rev-parse", "HEAD")
        self.git("clone", "--bare", str(self.root), str(self.remote))
        self.git("config", f"url.{self.remote.as_uri()}.insteadOf", "https://github.com/JoverZhang/reef.git")
        self.calls = self.root / "calls.jsonl"
        gh = self.root / "gh"
        gh.write_text(f"#!{sys.executable}\n" + '''import json
import os
import sys
from pathlib import Path

upload = sys.argv[1:3] == ["secret", "set"]
call = {"command": Path(sys.argv[0]).name, "args": sys.argv[1:], "input": sys.stdin.read() if upload else None}
with Path(os.environ["TEST_GH_CALLS"]).open("a") as output:
    output.write(json.dumps(call) + "\\n")
if sys.argv[1:3] == ["api", "user"]:
    print("test-owner\\t12345+test-owner@users.noreply.github.com")
sys.exit(int(os.environ.get("TEST_GH_UPLOAD_STATUS" if upload else "TEST_GH_IDENTITY_STATUS", "0")))
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
            "ZDOTDIR": str(self.root),
        })

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.root, check=True, capture_output=True, text=True,
        ).stdout.strip()

    def deploy(self, *args, **env):
        result = subprocess.run(
            ["just", "--no-deps", "--justfile", str(ROOT / "justfile"),
             "--working-directory", str(self.root), "--set", "python", sys.executable, "web-deploy", *args],
            env={**self.env, **env}, capture_output=True, text=True, timeout=10,
        )
        for value in (CONFIG["secret"], CONFIG["ssh_private_key"], CONFIG["subscriptions"]["upstream_urls"][0]):
            self.assertNotIn(value, result.stdout + result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []
        return result, calls

    def test_uploads_export_and_pushes_only_version_with_selected_identity(self):
        result, calls = self.deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["args"][:2] for call in calls], [["api", "user"], ["secret", "set"]])
        self.assertEqual(calls[1]["args"], ["secret", "set", "CONFIG_YAML", "--repo", "JoverZhang/reef"])
        self.assertEqual(yaml.safe_load(calls[1]["input"]), {
            key: value for key, value in CONFIG.items() if key != "ssh_private_key"
        })
        self.assertIsNone(calls[0]["input"])
        self.assertEqual(core.load_config(self.config), CONFIG)
        self.assertEqual(self.git("diff", "--name-only", "HEAD~", "HEAD"), "VERSION")
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "master"), self.git("rev-parse", "HEAD"))
        self.assertRegex((self.root / "VERSION").read_text(), r"^\d{14}\n$")
        self.assertEqual(self.git("log", "-1", "--format=%an|%ae|%cn|%ce"),
                         "test-owner|12345+test-owner@users.noreply.github.com|"
                         "test-owner|12345+test-owner@users.noreply.github.com")
        self.assertEqual(self.git("config", "user.email"), "other@example.test")

    def test_custom_command_handles_identity_and_upload(self):
        command = self.root / "custom-gh"
        command.write_bytes((self.root / "gh").read_bytes())
        command.chmod(0o700)
        result, calls = self.deploy("custom-gh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["command"] for call in calls], ["custom-gh", "custom-gh"])
        self.assertEqual(yaml.safe_load(calls[1]["input"]), {
            key: value for key, value in CONFIG.items() if key != "ssh_private_key"
        })

    def test_custom_alias_loads_zsh_login_and_interactive_configuration(self):
        command = self.root / "custom-gh"
        command.write_bytes((self.root / "gh").read_bytes())
        command.chmod(0o700)
        (self.root / ".zprofile").write_text("export TEST_GH_COMMAND=custom-gh\n")
        (self.root / ".zshrc").write_text('alias gh-reef="$TEST_GH_COMMAND"\n')
        result, calls = self.deploy("gh-reef")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["command"] for call in calls], ["custom-gh", "custom-gh"])

    def test_export_failure_does_not_touch_github(self):
        self.config.write_text("secret: [private-broken-config")
        result, calls = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertNotIn("private-broken-config", result.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.initial_commit)

    def test_upload_failure_does_not_commit_or_push(self):
        result, calls = self.deploy(TEST_GH_UPLOAD_STATUS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1]["args"][:2], ["secret", "set"])
        self.assertEqual(self.git("rev-parse", "HEAD"), self.initial_commit)
        self.assertEqual((self.root / "VERSION").read_text(), "202607081433\n")
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "master"), self.initial_commit)

    def test_identity_failure_does_not_upload_or_commit(self):
        result, calls = self.deploy(TEST_GH_IDENTITY_STATUS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.initial_commit)

    def test_uncommitted_changes_stop_before_upload(self):
        (self.root / "README.md").write_text("Unrelated change\n")
        for staged in (False, True):
            with self.subTest(staged=staged):
                if staged:
                    self.git("add", "README.md")
                result, calls = self.deploy()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertEqual(self.git("rev-parse", "HEAD"), self.initial_commit)
                self.assertEqual((self.root / "README.md").read_text(), "Unrelated change\n")

    def test_other_branch_cannot_publish_to_master(self):
        self.git("switch", "-c", "feature")
        result, calls = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertEqual(self.git("rev-parse", "HEAD"), self.initial_commit)

    def test_unpublished_commits_stop_before_upload(self):
        self.git("commit", "--allow-empty", "-m", "Unpublished work")
        result, calls = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call["args"][:2] for call in calls], [["api", "user"]])
        self.assertIn("match the remote master", result.stderr)
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "master"), self.initial_commit)

    def test_push_failure_preserves_local_publication_commit(self):
        hook = self.remote / "hooks/pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o700)
        result, calls = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(self.git("rev-parse", "HEAD"), self.initial_commit)
        self.assertEqual(self.git("diff", "--name-only", "HEAD~", "HEAD"), "VERSION")
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "master"), self.initial_commit)
