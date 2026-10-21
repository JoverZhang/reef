from __future__ import annotations

import http.client
import json
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.request import ProxyHandler, Request, build_opener

import yaml

from reef import core
from test_mihomo_relay import ProxyHandlerForTest


BINARY = core.ROOT / "bin/mihomo-linux-amd64"
BOOTSTRAP_RESOLVERS = {
    "223.5.5.5", "119.29.29.29",
    "https://223.5.5.5/dns-query", "https://doh.pub/dns-query",
}


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        end = data.index(b"\0", 12) + 5
        question_type = struct.unpack("!H", data[end - 4:end - 2])[0]
        self.server.queries.append(data[12:end])
        answer = self.server.available and question_type == 1
        flags = 0x8180 if self.server.available else 0x8182
        reply = data[:2] + struct.pack("!5H", flags, 1, int(answer), 0, 0) + data[12:end]
        if answer:
            reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
        sock.sendto(reply, self.client_address)


@unittest.skipUnless(BINARY.exists(), "run just vendor to test proxy DNS with the Mihomo binary")
class MihomoDNSTests(unittest.TestCase):
    def test_domain_proxy_bootstraps_when_public_doh_is_unreachable(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        resolvers = []
        for available in (True, False):
            server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), DNSHandler)
            server.available, server.queries = available, []
            resolvers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandlerForTest)
        proxy.calls, proxy.unavailable = [], False
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)
        config = {
            "secret": "12" * 32,
            "proxies": [
                {"name": "ip-endpoint", "type": "http", "server": "127.0.0.1", "port": proxy.server_port},
                {"name": "domain-endpoint", "type": "http", "server": "proxy.example.test", "port": proxy.server_port},
            ],
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["ip-endpoint", "domain-endpoint"]}],
        }
        original = core.project_path
        with patch.object(core, "project_path", side_effect=lambda *parts: (
            root.joinpath(*parts) if parts[0] == "build" else original(*parts)
        )):
            profiles = core.render_subscriptions(core.build_model(core.parse_config(config)), mihomo_only=True)

        def free_port():
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        for profile in profiles:
            with self.subTest(profile=profile["id"]):
                doc = yaml.safe_load(profile["body"])
                work = root / profile["id"]
                work.mkdir()
                mixed, controller = free_port(), free_port()
                doc.update({"mixed-port": mixed, "allow-lan": False,
                            "external-controller": f"127.0.0.1:{controller}", "secret": "test",
                            "rules": ["MATCH,PROXY"]})
                doc.pop("listeners", None)
                doc.pop("rule-providers", None)
                doc["dns"].pop("listen", None)
                doc["dns"].pop("nameserver-policy", None)
                # Keep the rendered resolver choice; substitute only network reachability.
                for key in ("default-nameserver", "nameserver", "proxy-server-nameserver"):
                    doc["dns"][key] = list(dict.fromkeys(
                        f"127.0.0.1:{resolvers[0 if value in BOOTSTRAP_RESOLVERS else 1].server_address[1]}"
                        for value in doc["dns"][key]
                    ))
                path = work / "runtime.yaml"
                path.write_text(yaml.safe_dump(doc))
                with (work / "runtime.log").open("w") as log:
                    process = subprocess.Popen([str(BINARY), "-d", str(work), "-f", str(path)], stdout=log, stderr=log)
                opener = build_opener(ProxyHandler({}))

                def api(path, selection=None):
                    request = Request(f"http://127.0.0.1:{controller}" + path,
                                      data=None if selection is None else json.dumps({"name": selection}).encode(),
                                      method="GET" if selection is None else "PUT",
                                      headers={"Authorization": "Bearer test", "Content-Type": "application/json"})
                    with opener.open(request, timeout=1):
                        pass

                try:
                    deadline = time.monotonic() + 10
                    while True:
                        try:
                            api("/version")
                            break
                        except OSError:
                            if time.monotonic() > deadline or process.poll() is not None:
                                self.fail("Mihomo did not start")
                            time.sleep(0.05)
                    for name in ("ip-endpoint", "domain-endpoint"):
                        api("/proxies/PROXY", name)
                        connection = http.client.HTTPConnection("127.0.0.1", mixed, timeout=6)
                        try:
                            connection.request("GET", f"http://127.0.0.1:{proxy.server_port}/")
                            response = connection.getresponse()
                            self.assertEqual((response.status, response.read()), (200, b"ok"), name)
                        finally:
                            connection.close()
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        self.assertTrue(resolvers[0].queries)
        self.assertFalse(resolvers[1].queries)
