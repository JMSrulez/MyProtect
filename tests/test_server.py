from pathlib import Path
import ssl
import tempfile
import unittest

import httpx
from starlette.testclient import TestClient

from myprotect.protect import ProtectClient
from myprotect.server import create_app
from myprotect.settings import Settings


TOKEN = "a" * 43
AUTH = {"Authorization": "Bearer " + TOKEN}


class ServerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.requests = []

        def handler(request):
            self.requests.append(request)
            if request.url.path.endswith("/snapshot"):
                return httpx.Response(200, content=b"\xff\xd8\xffphoto", headers={"content-type": "image/jpeg"})
            if request.url.path.endswith("/cameras"):
                return httpx.Response(200, json=[{"id": "camera", "name": "untrusted name"}])
            return httpx.Response(200, json={"applicationVersion": "7.3.70"})

        settings = Settings("https://uck.test", "https://testserver", "api-secret", TOKEN, Path(directory.name))
        protect = ProtectClient(settings.protect_url, settings.api_key, ssl.create_default_context(), transport=httpx.MockTransport(handler))
        self.client = TestClient(create_app(settings, protect, collect=False), base_url="https://testserver")
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def rpc(self, method, params=None, headers=None):
        return self.client.post("/mcp", headers={
            **AUTH, "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25", **(headers or {}),
        }, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})

    def test_auth_required_on_every_route(self):
        for route in ("/health", "/mcp", "/media/" + "a" * 32):
            self.assertEqual(self.client.get(route).status_code, 401)
        self.assertEqual(self.client.get("/health", headers=AUTH).status_code, 200)
        self.assertEqual(self.client.get("/health", headers={"Authorization": "Bearer wrong"}).status_code, 401)
        self.assertEqual(self.requests, [])

    def test_host_origin_and_https(self):
        self.assertEqual(self.client.get("/health", headers={**AUTH, "Host": "attacker.test"}).status_code, 421)
        self.assertEqual(self.client.get("/health", headers={**AUTH, "Origin": "https://attacker.test"}).status_code, 403)
        self.assertEqual(self.client.get("http://testserver/health", headers=AUTH).status_code, 400)
        duplicate = self.client.get("/health", headers=[("Authorization", "Bearer " + TOKEN), ("Authorization", "Bearer " + TOKEN)])
        self.assertEqual(duplicate.status_code, 401)

    def test_mcp_initialize_tools_and_snapshot(self):
        response = self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})
        self.assertEqual(response.status_code, 200, response.text)
        tools = self.rpc("tools/list").json()["result"]["tools"]
        self.assertEqual({tool["name"] for tool in tools}, {
            "list_cameras", "get_nvr_status", "get_collector_status", "search_events", "get_snapshot", "read_snapshot",
        })
        self.assertTrue(all(tool["annotations"]["readOnlyHint"] for tool in tools))
        response = self.rpc("tools/call", {"name": "get_snapshot", "arguments": {"camera_id": "camera"}})
        result = response.json()["result"]
        self.assertFalse(result.get("isError"), result)
        reference = result["structuredContent"]
        url = reference["download_url"]
        self.assertEqual(self.client.get(url).status_code, 401)
        downloaded = self.client.get(url, headers=AUTH)
        self.assertEqual(downloaded.content, b"\xff\xd8\xffphoto")
        self.assertEqual(downloaded.headers["cache-control"], "no-store")
        image = self.rpc("tools/call", {"name": "read_snapshot", "arguments": {"media_id": reference["media_id"]}}).json()["result"]
        self.assertEqual(image["content"][0]["type"], "image")
        self.assertTrue(all(request.method == "GET" for request in self.requests))

    def test_mcp_errors_and_body_limit(self):
        error = self.rpc("tools/call", {"name": "get_snapshot", "arguments": {"camera_id": "../nvrs"}}).json()["result"]
        self.assertTrue(error["isError"])
        self.assertNotIn("api-secret", str(error))
        response = self.client.post("/mcp", headers=AUTH, content=b"x" * (1024 * 1024 + 1))
        self.assertEqual(response.status_code, 413)

    def test_rate_limit(self):
        for unused in range(60):
            self.assertEqual(self.client.get("/health", headers=AUTH).status_code, 200)
        self.assertEqual(self.client.get("/health", headers=AUTH).status_code, 429)