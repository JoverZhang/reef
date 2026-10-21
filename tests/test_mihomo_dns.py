from __future__ import annotations

import base64
import http.client
import json
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
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


class DoHHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        encoded = parse_qs(urlsplit(self.path).query)["dns"][0]
        data = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        end = data.index(b"\0", 12) + 5
        self.server.queries.append(data[12:end])
        reply = data[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + data[12:end]
        reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.1")
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


@unittest.skipUnless(BINARY.exists(), "run just vendor to test proxy DNS with the Mihomo binary")
class MihomoDNSTests(unittest.TestCase):
    def test_business_doh_uses_selected_exit_and_fails_closed(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        certificate = core.derive_node_secret(bytes.fromhex("12" * 32), core.Node("dns", "127.0.0.1", 1, "exit"))
        (root / "cert.pem").write_text(certificate.cert_pem)
        (root / "key.pem").write_text(certificate.key_pem)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / "cert.pem", root / "key.pem")
        servers = []
        for handler in (ProxyHandlerForTest, ProxyHandlerForTest, DoHHandler):
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            server.calls, server.queries, server.unavailable = [], [], False
            if handler is DoHHandler:
                server.socket = tls.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            servers.append(server)
        relay, exit_node, doh = servers
        bootstrap = socketserver.ThreadingUDPServer(("127.0.0.1", 0), DNSHandler)
        bootstrap.available, bootstrap.queries = True, []
        threading.Thread(target=bootstrap.serve_forever, daemon=True).start()
        self.addCleanup(bootstrap.server_close)
        self.addCleanup(bootstrap.shutdown)
        config = {
            "secret": "12" * 32,
            "proxies": [
                {"name": "relay", "type": "http", "server": "relay.example.test", "port": relay.server_port},
                {"name": "direct-exit", "type": "http", "server": "exit.example.test", "port": exit_node.server_port},
                {"name": "relayed-exit", "type": "http", "server": "127.0.0.1",
                 "port": exit_node.server_port, "dialer-proxy": "relay"},
            ],
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["direct-exit", "relayed-exit"]}],
        }
        original = core.project_path
        with patch.object(core, "project_path", side_effect=lambda *parts: (
            root.joinpath(*parts) if parts[0] == "build" else original(*parts)
        )):
            profiles = core.render_subscriptions(core.build_model(core.parse_config(config)), mihomo_only=True)

        for profile in profiles:
            for selection, failed in (("direct-exit", False), ("relayed-exit", False), ("relayed-exit", True)):
                with self.subTest(profile=profile["id"], selection=selection, failed=failed):
                    work = root / f"{profile['id']}-{selection}-{failed}"
                    work.mkdir()
                    relay.calls.clear()
                    exit_node.calls.clear()
                    doh.queries.clear()
                    bootstrap.queries.clear()
                    relay.unavailable = failed
                    doc = yaml.safe_load(profile["body"])
                    with socket.socket() as sock:
                        sock.bind(("127.0.0.1", 0))
                        controller = sock.getsockname()[1]
                    doc.update({"mixed-port": 0, "external-controller": f"127.0.0.1:{controller}",
                                "secret": "test", "rules": ["MATCH,PROXY"]})
                    doc.pop("listeners", None)
                    doc.pop("rule-providers", None)
                    doc["dns"].pop("listen", None)
                    doc["dns"].pop("nameserver-policy", None)
                    for key in ("default-nameserver", "proxy-server-nameserver", "direct-nameserver"):
                        if key in doc["dns"]:
                            doc["dns"][key] = [f"127.0.0.1:{bootstrap.server_address[1]}"]
                    # Preserve the template's routing; only replace the remote DoH
                    # address and trust the local fixture's self-signed certificate.
                    doc["dns"]["nameserver"] = list(dict.fromkeys(
                        f"https://127.0.0.1:{doh.server_port}/dns-query#"
                        + (value.partition("#")[2] + "&" if "#" in value else "")
                        + "skip-cert-verify=true" for value in doc["dns"]["nameserver"]
                    ))
                    path = work / "runtime.yaml"
                    path.write_text(yaml.safe_dump(doc))
                    with (work / "runtime.log").open("w") as log:
                        process = subprocess.Popen([str(BINARY), "-d", str(work), "-f", str(path)], stdout=log, stderr=log)
                    opener = build_opener(ProxyHandler({}))

                    def api(path, choice=None):
                        request = Request(f"http://127.0.0.1:{controller}" + path,
                                          data=None if choice is None else json.dumps({"name": choice}).encode(),
                                          method="GET" if choice is None else "PUT",
                                          headers={"Authorization": "Bearer test", "Content-Type": "application/json"})
                        with opener.open(request, timeout=10) as response:
                            return response.read()

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
                        api("/proxies/PROXY", selection)
                        if failed:
                            with self.assertRaises(HTTPError):
                                api("/dns/query?name=target.example.test&type=A")
                            self.assertFalse(doh.queries, "DNS bypassed the failed relay")
                            self.assertFalse(exit_node.calls, "DNS skipped the failed relay")
                        else:
                            answer = json.loads(api("/dns/query?name=target.example.test&type=A"))
                            self.assertEqual(answer["Answer"][0]["data"], "192.0.2.1")
                            self.assertTrue(doh.queries)
                            self.assertEqual(exit_node.calls, [("127.0.0.1", doh.server_port)])
                            expected = [("127.0.0.1", exit_node.server_port)] if selection == "relayed-exit" else []
                            self.assertEqual(relay.calls, expected)
                        self.assertTrue(bootstrap.queries)
                        self.assertFalse(any(b"target" in query for query in bootstrap.queries),
                                         "Business DNS fell back to a direct resolver")
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()

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
                for key in ("default-nameserver", "nameserver", "proxy-server-nameserver", "direct-nameserver"):
                    if key not in doc["dns"]:
                        continue
                    doc["dns"][key] = list(dict.fromkeys(
                        f"127.0.0.1:{resolvers[0 if value.partition('#')[0] in BOOTSTRAP_RESOLVERS else 1].server_address[1]}"
                        + ("#" + value.partition("#")[2] if "#" in value else "")
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
