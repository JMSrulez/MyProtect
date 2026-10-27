import json
import ssl
import unittest

import httpx

from myprotect.protect import ProtectClient, ProtectError, origin


class ProtectTests(unittest.IsolatedAsyncioTestCase):
    def client(self, handler, cameras=frozenset()):
        client = ProtectClient(
            "https://uck.test", "private-api-key", ssl.create_default_context(), cameras,
            transport=httpx.MockTransport(handler),
        )
        self.addAsyncCleanup(client.close)
        return client

    async def test_only_allowed_get_routes_and_camera_scope(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, json=[{"id": "allowed"}, {"id": "blocked"}])

        client = self.client(handler, frozenset({"allowed"}))
        self.assertEqual([camera["id"] for camera in await client.cameras()], ["allowed"])
        with self.assertRaises(ProtectError):
            await client.read("/cameras/allowed/reboot", 100)
        with self.assertRaises(ProtectError):
            await client.snapshot("blocked")
        with self.assertRaises(ProtectError):
            await client.snapshot("../nvrs")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].method, "GET")
        self.assertEqual(requests[0].url.host, "uck.test")
        self.assertEqual(requests[0].headers["x-api-key"], "private-api-key")

    async def test_redirect_is_not_followed_and_body_not_leaked(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(302, headers={"location": "https://elsewhere.test"}, text="private-api-key")

        client = self.client(handler)
        with self.assertRaises(ProtectError) as caught:
            await client.cameras()
        self.assertNotIn("private-api-key", str(caught.exception))
        self.assertEqual(len(requests), 1)

    async def test_size_and_json_validation(self):
        client = self.client(lambda request: httpx.Response(200, content=b"12345"))
        with self.assertRaises(ProtectError):
            await client.read("/nvrs", 4)
        for data in ({}, "invalid"):
            client = self.client(lambda request: httpx.Response(200, text=json.dumps(data), headers={"content-type": "application/json"}))
            with self.assertRaises(ProtectError):
                await client.cameras()

    async def test_snapshot_validates_image(self):
        def handler(request):
            if request.url.path.endswith("/snapshot"):
                return httpx.Response(200, content=b"\xff\xd8\xffphoto", headers={"content-type": "image/jpeg"})
            return httpx.Response(200, json=[{"id": "camera"}])

        self.assertEqual(await self.client(handler).snapshot("camera"), ("image/jpeg", b"\xff\xd8\xffphoto"))

    def test_https_origin_only(self):
        for value in ("http://uck", "https://user:pass@uck", "https://uck/api", "https://uck?key=secret"):
            with self.assertRaises(ValueError):
                origin(value)