"""Standard-library HTTPS CONNECT server. Never terminates target TLS."""
import asyncio
import hashlib
import hmac
import json
import re
import socket
import ssl
import sys


async def pipe(reader, writer):
    while True:
        data = await asyncio.wait_for(reader.read(65536), 30)
        if not data:
            return
        writer.write(data)
        await asyncio.wait_for(writer.drain(), 30)


async def handle(reader, writer, auth_digest):
    remote = None
    tasks = []
    try:
        headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        lines = headers.decode("ascii").split("\r\n")
        match = re.fullmatch(r"CONNECT ([A-Za-z0-9.-]+):443 HTTP/1\.[01]", lines[0])
        auth = [line.split(":", 1)[1].strip() for line in lines[1:] if
                line.lower().startswith("proxy-authorization:")]
        if not match or len(auth) != 1 or not hmac.compare_digest(
            hashlib.sha256(auth[0].encode()).hexdigest(), auth_digest,
        ):
            writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        remote_reader, remote = await asyncio.wait_for(
            asyncio.open_connection(match[1], 443, family=socket.AF_INET), 15,
        )
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        tasks = [asyncio.create_task(pipe(reader, remote)),
                 asyncio.create_task(pipe(remote_reader, writer))]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for connection in (remote, writer):
            if connection is not None:
                connection.close()
                try:
                    await asyncio.wait_for(connection.wait_closed(), 2)
                except (OSError, asyncio.TimeoutError):
                    connection.transport.abort()


async def main(config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config["cert"], config["key"])
    server = await asyncio.start_server(
        lambda reader, writer: handle(reader, writer, config["auth_sha256"]),
        "0.0.0.0", config["port"], ssl=context, limit=16384,
        ssl_handshake_timeout=15,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    with open(sys.argv[1]) as source:
        asyncio.run(main(json.load(source)))
