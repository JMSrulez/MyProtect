import asyncio
import json
import logging
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
import uvicorn
from websockets.sync.server import serve

from myprotect.collector import Collector
from myprotect.protect import ProtectClient
from myprotect.server import create_app
from myprotect.settings import Settings
from myprotect.storage import Store
from tls_support import certificate_files


class TLSIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_official_mcp_client_over_verified_https(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = certificate_files(root)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            url = f"https://127.0.0.1:{listener.getsockname()[1]}"
            token = "a" * 43
            settings = Settings("https://uck.test", url, "api-secret", token, root / "data")
            upstream = ProtectClient(settings.protect_url, settings.api_key, ssl.create_default_context(), transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json=[{"id": "camera", "name": "Camera"}])
            ))
            app = create_app(settings, upstream, collect=False)
            ready = threading.Event()

            async def ready_app(scope, receive, send):
                async def signal(message):
                    if message["type"] == "lifespan.startup.complete":
                        ready.set()
                    await send(message)
                await app(scope, receive, signal)

            server = uvicorn.Server(uvicorn.Config(
                ready_app, ssl_certfile=str(cert), ssl_keyfile=str(key), access_log=False,
                log_level="warning", proxy_headers=False,
            ))
            thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
            thread.start()
            try:
                self.assertTrue(await asyncio.to_thread(ready.wait, 10), "HTTPS server did not start")
                context = ssl.create_default_context(cafile=cert)
                async with httpx.AsyncClient(verify=context, trust_env=False, headers={"Authorization": "Bearer " + token}) as http_client:
                    async with streamable_http_client(url + "/mcp", http_client=http_client) as (read, write, unused):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            tools = await session.list_tools()
                            self.assertEqual(len(tools.tools), 6)
                            result = await session.call_tool("list_cameras")
                            self.assertFalse(result.isError)
                            self.assertIn("camera", result.content[0].text)
                            result = await session.call_tool("search_events", {"since_minutes": 60})
                            self.assertFalse(result.isError)
                            self.assertFalse(result.structuredContent["complete_nvr_history"])
                async with httpx.AsyncClient(trust_env=False) as untrusted:
                    with self.assertRaises(httpx.ConnectError):
                        await untrusted.get(url + "/health")
            finally:
                server.should_exit = True
                await asyncio.to_thread(thread.join, 10)
                listener.close()
                self.assertFalse(thread.is_alive(), "HTTPS server did not stop")

    async def test_collector_over_verified_wss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = certificate_files(root)
            server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.load_cert_chain(cert, key)
            headers = []
            received = threading.Event()

            def handler(connection):
                headers.append(connection.request.headers.get("X-API-KEY"))
                connection.send(json.dumps({"type": "add", "item": {
                    "id": "event", "modelKey": "event", "camera": "camera", "type": "motion",
                }}))
                try:
                    connection.recv(timeout=5)
                except Exception:
                    pass

            with serve(handler, "127.0.0.1", 0, ssl=server_tls) as websocket_server:
                thread = threading.Thread(target=websocket_server.serve_forever, daemon=True)
                thread.start()
                port = websocket_server.socket.getsockname()[1]
                client = ProtectClient(f"https://127.0.0.1:{port}", "private-api-key", ssl.create_default_context(cafile=cert))
                store = Store(root / "data")
                original_ingest = store.ingest

                def ingest(message, cameras):
                    result = original_ingest(message, cameras)
                    received.set()
                    return result

                store.ingest = ingest
                collector = Collector(client, store)
                collector.start()
                try:
                    self.assertTrue(await asyncio.to_thread(received.wait, 10), "No event collected")
                    events = store.events(60, 10, None, frozenset())
                    self.assertEqual(events["events"][0]["event"]["type"], "motion")
                    self.assertEqual(headers, ["private-api-key"])
                finally:
                    await asyncio.to_thread(collector.stop)
                    await client.close()
                    store.close()
                    websocket_server.shutdown()
                    await asyncio.to_thread(thread.join, 5)
                    self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    logging.disable(logging.INFO)
    unittest.main()