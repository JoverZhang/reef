from __future__ import annotations

import copy
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from reef import core
from reef.cli import config_yaml, gen_secret, set_ssh_key


CONFIG = {
    "secret": "11" * 32,
    "cluster": {
        "entries": [{"name": "jp", "ip": "192.0.2.11"}, {"name": "sg", "ip": "192.0.2.10"}],
        "exits": [{"name": "us", "ip": "192.0.2.20"}, {"name": "uk", "ip": "192.0.2.21"}],
    },
    "subscriptions": {"upstream_urls": ["https://example.test/private-token"]},
}


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "config.yaml"
        environment = patch.dict(os.environ, {
            "REEF_TEST_MODE": "1", "TEST_CONFIG_FILE": str(self.path),
        }, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def key(self):
        return ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        ).decode()

    def test_defaults_order_and_round_trip_preserve_model(self):
        document = {**CONFIG, "ssh_private_key": self.key()}
        model = core.build_model(core.parse_config(document, require_ssh=True))
        core.write_config(document)
        self.assertEqual(core.load_config(), document)
        self.assertEqual(core.load_model(require_ssh=True), model)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertIn("ssh_private_key: |\n", self.path.read_text())
        self.assertEqual([node.id for node in model.config.entries], ["jp", "sg"])
        self.assertEqual([route.port for route in model.routes[:4]], [20000, 20001, 20000, 20001])
        self.assertEqual(model.config.exit_port, 443)

    def test_environment_and_legacy_files_do_not_override_config(self):
        core.write_config(CONFIG)
        (self.root / ".env").write_text("REEF_SECRET=private-old-seed\n")
        with patch.dict(os.environ, {
            "REEF_SECRET": "22" * 32,
            "REEF_UPSTREAM_URL_1": "https://ignored.test/private-token",
            "REEF_ENV_FILE": str(self.root / ".env"),
            "CONFIG_YAML": "private-unmaterialized-payload",
        }):
            self.assertEqual(core.load_model().config, core.parse_config(CONFIG))
            self.path.unlink()
            with self.assertRaisesRegex(ValueError, "could not be read"):
                core.load_config()

    def test_config_file_override_requires_test_mode(self):
        with patch.dict(os.environ, {"REEF_TEST_MODE": ""}):
            with self.assertRaisesRegex(ValueError, "only allowed when REEF_TEST_MODE=1"):
                core.load_config()

    def test_invalid_yaml_and_duplicate_keys_never_echo_input(self):
        for payload in (
            b"\xffprivate-credential",
            "secret: [private-credential",
            "secret: private-credential\nsecret: other",
            "cluster:\n  entries: []\n  entries: private-credential",
            "subscriptions:\n  nodes:\n    - name: private-credential\n      name: repeated",
            "? [private-credential]\n: value",
            "private-credential",
            "",
        ):
            with self.assertRaises(ValueError) as error:
                core.parse_config_yaml(payload)
            self.assertNotIn("private-credential", str(error.exception))

    def test_schema_rejects_unknown_fields_and_wrong_types_without_values(self):
        for path, value in (
            (("private-credential",), True),
            (("secret",), 123),
            (("cluster",), None),
            (("cluster", "entries"), "private-credential"),
            (("cluster", "exits"), [{"name": "private-credential", "ip": "bad-private-credential"}]),
            (("cluster", "entry_port_base"), True),
            (("cluster", "exit_port"), "443"),
            (("cluster", "exit_port"), 65536),
            (("cluster", "entry_override_base_domain"), "example.test"),
            (("cluster", "private-credential"), True),
            (("subscriptions", "upstream_urls"), "private-credential"),
            (("subscriptions", "nodes"), None),
            (("subscriptions", "private-credential"), True),
            (("ssh_private_key",), "private-credential"),
            (("ssh_private_key",), None),
        ):
            document = copy.deepcopy(CONFIG)
            target = document
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError) as error:
                core.parse_config(document)
            self.assertNotIn("private-credential", str(error.exception))

    def test_secret_generation_preserves_sections_and_refuses_overwrite(self):
        document = {key: value for key, value in CONFIG.items() if key != "secret"}
        core.write_config(document)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(gen_secret.main(), 0)
        result = core.load_config()
        self.assertRegex(result.pop("secret"), r"^[0-9a-f]{64}$")
        self.assertEqual(result, document)
        before = self.path.read_bytes()
        with redirect_stderr(io.StringIO()):
            self.assertEqual(gen_secret.main(), 1)
        self.assertEqual(self.path.read_bytes(), before)
        self.path.unlink()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(gen_secret.main(), 0)
        self.assertEqual(set(core.load_config()), {"secret"})

    def test_ssh_key_command_preserves_config_and_export_removes_only_key(self):
        core.write_config(CONFIG)
        key_path = self.root / "id_ed25519"
        key = self.key()
        key_path.write_text(key)
        output = io.StringIO()
        with patch("sys.argv", ["set-ssh-key", str(key_path)]), redirect_stdout(output):
            self.assertEqual(set_ssh_key.main(), 0)
        self.assertNotIn(key, output.getvalue())
        self.assertEqual(core.load_config(), {**CONFIG, "ssh_private_key": key})
        before = self.path.read_bytes()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(config_yaml.main(), 0)
        self.assertEqual(core.parse_config_yaml(output.getvalue()), CONFIG)
        self.assertEqual(self.path.read_bytes(), before)
        for content in (b"private-credential", b"\xffprivate-credential"):
            key_path.write_bytes(content)
            error = io.StringIO()
            with patch("sys.argv", ["set-ssh-key", str(key_path)]), redirect_stderr(error):
                self.assertEqual(set_ssh_key.main(), 1)
            self.assertNotIn("private-credential", error.getvalue())
            self.assertEqual(self.path.read_bytes(), before)
