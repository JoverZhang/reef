from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

from reef import core, tunnel_server
from subscriptions import tunnel, upstream


class TunnelTLSTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().set_debug(False)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        node = core.Node("gateway-test", "127.0.0.1", 1, "exit")
        self.proxy = core.derive_node_secret(bytes.fromhex("34" * 32), node)
        self.target = core.derive_node_secret(bytes.fromhex("56" * 32), node)
        self.wire = bytearray()
        self.requests = []
        self.status = b"200 OK"
        self.redirect_once = False
        self.extra_headers = b""
        self.body = b"proxies:\n- {name: sample, type: trojan, server: sample.invalid, port: 443, password: node-secret}\n"
        self.target_server = await asyncio.start_server(self.respond, "127.0.0.1", 0,
                                                       ssl=self.context("target", self.target))
        self.addAsyncCleanup(self.close_server, self.target_server)
        self.target_port = self.target_server.sockets[0].getsockname()[1]
        original = asyncio.open_connection

        async def connect(host, port, **kwargs):
            self.assertEqual((host, port), ("127.0.0.1", 443))
            return await original(host, self.target_port, **kwargs)

        patcher = patch.object(tunnel_server.asyncio, "open_connection", side_effect=connect)
        patcher.start()
        self.addCleanup(patcher.stop)
        digest = hashlib.sha256(b"Bearer tunnel-only-key").hexdigest()
        wire = self.wire

        class ObservedReader:
            async def read(self, n):
                data = await self.reader.read(n)
                wire.extend(data)
                return data

            async def readuntil(self, marker):
                data = await self.reader.readuntil(marker)
                wire.extend(data)
                return data

            def __init__(self, reader):
                self.reader = reader

        class ObservedWriter:
            def __init__(self, writer):
                self.writer = writer

            def write(self, data):
                wire.extend(data)
                return self.writer.write(data)

            def __getattr__(self, name):
                return getattr(self.writer, name)

        self.proxy_server = await asyncio.start_server(
            lambda r, w: tunnel_server.handle(ObservedReader(r), ObservedWriter(w), digest),
            "127.0.0.1", 0, ssl=self.context("proxy", self.proxy), limit=16384,
        )
        self.addAsyncCleanup(self.close_server, self.proxy_server)
        port = self.proxy_server.sockets[0].getsockname()[1]
        self.config = {"url": f"https://127.0.0.1:{port}", "ca": self.proxy.cert_pem, "token": "tunnel-only-key"}
        self.url = "https://127.0.0.1/private-path?token=subscription-secret"
        patcher = patch.dict(os.environ, {"SSL_CERT_FILE": str(self.root / "target.crt"),
                                         "SSL_CERT_DIR": str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)

    async def asyncTearDown(self):
        await asyncio.sleep(0.05)

    def context(self, name, secret):
        cert, key = self.root / f"{name}.crt", self.root / f"{name}.key"
        cert.write_text(secret.cert_pem)
        key.write_text(secret.key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        return ctx

    async def close_server(self, server):
        server.close()
        await server.wait_closed()

    async def respond(self, reader, writer):
        try:
            self.requests.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 " + self.status + b"\r\nContent-Length: " +
                         str(len(self.body)).encode() + b"\r\nConnection: close\r\n" +
                         self.extra_headers + b"\r\n" + self.body)
            await writer.drain()
            if self.redirect_once:
                self.status = b"200 OK"
                self.extra_headers = b""
                self.redirect_once = False
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def test_nested_tls_hides_path_token_body_and_keeps_auth_separate(self):
        body = await asyncio.to_thread(tunnel.fetch, self.url, self.config)
        self.assertEqual(body, self.body)
        self.assertIn(b"CONNECT 127.0.0.1:443", self.wire)
        for secret in (b"private-path", b"subscription-secret", b"node-secret", self.body):
            self.assertNotIn(secret, self.wire)
        self.assertIn(b"subscription-secret", self.requests[0])
        self.assertNotIn(b"tunnel-only-key", self.requests[0])
        self.assertNotIn(b"Proxy-Authorization", self.requests[0])

    async def test_trusted_proxy_cannot_impersonate_target(self):
        await self.close_server(self.target_server)
        self.target_server = await asyncio.start_server(self.respond, "127.0.0.1", 0,
                                                       ssl=self.context("forged", self.proxy))
        self.addAsyncCleanup(self.close_server, self.target_server)
        self.target_port = self.target_server.sockets[0].getsockname()[1]
        with self.assertRaisesRegex(OSError, "^tunnel fetch failed$"):
            await asyncio.to_thread(tunnel.fetch, self.url, self.config)
        self.assertEqual(self.requests, [])
        self.assertNotIn(b"subscription-secret", self.wire)

    async def test_bad_proxy_auth_or_certificate_never_reaches_target(self):
        for config in ({**self.config, "token": "wrong"}, {**self.config, "ca": self.target.cert_pem}):
            with self.assertRaises(OSError):
                await asyncio.to_thread(tunnel.fetch, self.url, config)
        self.assertEqual(self.requests, [])

    async def test_http_redirect_is_rejected_before_any_plaintext_request(self):
        self.status = b"302 Found"
        self.extra_headers = b"Location: http://127.0.0.1/redirect-secret\r\n"
        with self.assertRaises(OSError):
            await asyncio.to_thread(tunnel.fetch, self.url, self.config)
        self.assertEqual(len(self.requests), 1)
        self.assertNotIn(b"redirect-secret", self.wire)

    async def test_https_relative_redirect_stays_in_tunnel(self):
        self.status = b"302 Found"
        self.extra_headers = b"Location: /redirected-secret\r\n"
        self.redirect_once = True
        self.assertEqual(await asyncio.to_thread(tunnel.fetch, self.url, self.config), self.body)
        self.assertEqual(len(self.requests), 2)
        self.assertIn(b"/redirected-secret", self.requests[1])
        self.assertNotIn(b"redirected-secret", self.wire)
        self.assertNotIn(self.body, self.wire)

    async def test_https_redirect_and_response_limit(self):
        self.status = b"302 Found"
        self.extra_headers = b"Location: /another-secret\r\n"
        with self.assertRaises(OSError):
            await asyncio.to_thread(tunnel.fetch, self.url, self.config)
        self.assertEqual(len(self.requests), 6)
        self.assertNotIn(b"another-secret", self.wire)
        self.status = b"200 OK"
        with patch.object(tunnel, "MAX_BODY", 8), self.assertRaises(OSError):
            await asyncio.to_thread(tunnel.fetch, self.url, self.config)


class TunnelContractTests(unittest.TestCase):
    def test_failure_does_not_use_direct_fetch_and_error_hides_url(self):
        with patch.object(tunnel, "fetch", side_effect=OSError("private-url")), \
                patch.object(upstream, "urlopen") as direct:
            with self.assertRaisesRegex(ValueError, "^upstream URL #1 fetch failed$"):
                upstream.fetch_nodes("https://example.invalid/private", "upstream URL #1", tunnel={})
            direct.assert_not_called()

    def test_config_and_node_artifacts_contain_only_tunnel_credentials(self):
        from reef.tunnel import client_input, render_service
        values = {"secret": "ab" * 32, "web": {"password": "long-web-password" * 3,
                  "fetch_tunnel": "gateway-a"}, "cluster": {"exits": [{"name": "gateway-a", "ip": "192.0.2.40"}]},
                  "proxy-providers": {"source": {"type": "http", "url": "https://example.invalid/private-token"}}}
        model = core.build_model(core.parse_config(values))
        client = client_input(model)
        files = {}
        render_service(model, model.nodes[0], lambda rel, dest, content, mode="0644": files.update({dest: content}))
        remote = json.dumps(files)
        for private in (values["secret"], values["web"]["password"], "private-token", client["token"]):
            self.assertNotIn(private, remote)
        self.assertIn("reef-fetch-tunnel.service", core.service_names_for_node(model, model.nodes[0]))
        for name in (None, "unknown", False):
            values["web"]["fetch_tunnel"] = name
            with self.assertRaises(ValueError):
                core.parse_config(values)
        values["web"]["fetch_tunnel"] = "gateway-a"
        values["proxy-providers"]["source"]["url"] = "http://example.invalid/private-token"
        with self.assertRaises(ValueError):
            core.parse_config(values)
