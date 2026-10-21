from __future__ import annotations

import http.client
import json
import select
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.request import ProxyHandler, Request, build_opener

import yaml

from reef import core


BINARY = core.ROOT / "bin/mihomo-linux-amd64"


class ProxyHandlerForTest(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        if self.server.unavailable:
            self.send_error(502)
            return
        host, port = self.path.rsplit(":", 1)
        self.server.calls.append((host, int(port)))
        with socket.create_connection((host, int(port)), timeout=2) as remote:
            self.send_response(200)
            self.end_headers()
            self.wfile.flush()
            streams = [self.connection, remote]
            while True:
                ready, _, _ = select.select(streams, [], [], 3)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (remote if source is self.connection else self.connection).sendall(data)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@unittest.skipUnless(BINARY.exists(), "run just vendor to test relay traffic with the Mihomo binary")
class MihomoRelayTests(unittest.TestCase):
    def test_switching_both_hops_and_failed_relay_never_bypasses_it(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        servers = []
        for _ in range(5):
            server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandlerForTest)
            server.calls, server.unavailable = [], False
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            servers.append(server)
        relay_a, relay_b, exit_a, exit_b, target = servers

        def node(name, server):
            return {"name": name, "type": "http", "server": "127.0.0.1", "port": server.server_port}

        config = {
            "secret": "12" * 32,
            "proxy-providers": {
                "relays": {"type": "inline", "payload": [node("relay-a", relay_a), node("relay-b", relay_b)]},
                "exits": {"type": "inline", "payload": [node("exit-a", exit_a), node("exit-b", exit_b)],
                          "override": {"dialer-proxy": "RELAY"}},
            },
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "use": ["exits"]},
                {"name": "RELAY", "type": "select", "use": ["relays"]},
            ],
        }
        original_path = core.project_path
        with patch.object(core, "project_path", side_effect=lambda *parts: (
            root.joinpath(*parts) if parts[0] == "build" else original_path(*parts)
        )):
            profiles = core.render_subscriptions(core.build_model(core.parse_config(config)), mihomo_only=True)
        doc = yaml.safe_load(next(p["body"] for p in profiles if p["id"] == "linux-server"))

        def free_port():
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        mixed_port, api_port = free_port(), free_port()
        doc.update({"mixed-port": mixed_port, "allow-lan": False,
                    "external-controller": f"127.0.0.1:{api_port}", "secret": "test",
                    "dns": {"enable": False}})
        doc.pop("listeners")
        path = root / "runtime.yaml"
        path.write_text(yaml.safe_dump(doc))
        with (root / "mihomo.log").open("w") as log:
            proc = subprocess.Popen([str(BINARY), "-d", str(root), "-f", str(path)], stdout=log, stderr=log)

        def stop():
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

        self.addCleanup(stop)
        opener = build_opener(ProxyHandler({}))

        def api(path, value=None):
            request = Request(f"http://127.0.0.1:{api_port}" + path,
                              data=None if value is None else json.dumps({"name": value}).encode(),
                              method="GET" if value is None else "PUT",
                              headers={"Authorization": "Bearer test", "Content-Type": "application/json"})
            with opener.open(request, timeout=1):
                pass

        deadline = time.monotonic() + 10
        while True:
            try:
                api("/version")
                break
            except OSError:
                if time.monotonic() >= deadline or proc.poll() is not None:
                    self.fail("Mihomo failed to start")
                time.sleep(0.05)

        def request_target():
            connection = http.client.HTTPConnection("127.0.0.1", mixed_port, timeout=5)
            try:
                connection.request("GET", f"http://127.0.0.1:{target.server_port}/")
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

        for relay_name, relay in (("relay-a", relay_a), ("relay-b", relay_b)):
            api("/proxies/RELAY", relay_name)
            for exit_name, exit_node in (("exit-a", exit_a), ("exit-b", exit_b)):
                api("/proxies/PROXY", exit_name)
                before_relay, before_exit = len(relay.calls), len(exit_node.calls)
                self.assertEqual(request_target(), (200, b"ok"))
                self.assertEqual(relay.calls[before_relay:], [("127.0.0.1", exit_node.server_port)])
                self.assertEqual(exit_node.calls[before_exit:], [("127.0.0.1", target.server_port)])

        relay_b.unavailable = True
        before_exit = len(exit_b.calls)
        try:
            self.assertNotEqual(request_target()[0], 200)
        except (OSError, http.client.HTTPException):
            pass
        self.assertEqual(len(exit_b.calls), before_exit)
