import asyncio
import json
import re
import ssl
from typing import Any
from urllib.parse import urlsplit

import httpx


BASE = "/proxy/protect/integration/v1"
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}")
READ_ROUTE = re.compile(r"/(?:meta/info|nvrs|cameras|cameras/[A-Za-z0-9_-]{1,128}/snapshot)")


class ProtectError(Exception):
    pass


def origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https" or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or parsed.path not in ("", "/") or parsed.query or parsed.fragment
        or any(ord(character) < 33 for character in value)
        or parsed.port == 0
    ):
        raise ValueError("An HTTPS origin without credentials or path is required.")
    return "https://" + parsed.netloc.lower()


def identifier(value: str) -> str:
    if not IDENTIFIER.fullmatch(value):
        raise ProtectError("Invalid camera identifier.")
    return value


class ProtectClient:
    def __init__(
        self, url: str, api_key: str, context: ssl.SSLContext,
        camera_ids: frozenset[str] = frozenset(),
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = origin(url)
        self.api_key = api_key
        self.context = context
        self.camera_ids = camera_ids
        self.client = httpx.AsyncClient(
            base_url=self.url, verify=context, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(20, connect=5),
            limits=httpx.Limits(max_connections=2), transport=transport,
            headers={"X-API-KEY": api_key},
        )
        self.gate = asyncio.Semaphore(2)

    async def close(self) -> None:
        await self.client.aclose()

    def authorize_camera(self, camera_id: str) -> None:
        identifier(camera_id)
        if self.camera_ids and camera_id not in self.camera_ids:
            raise ProtectError("Camera not permitted.")

    async def read(self, route: str, limit: int) -> tuple[str, bytes]:
        if not READ_ROUTE.fullmatch(route):
            raise ProtectError("Route not permitted.")
        try:
            async with self.gate, asyncio.timeout(25):
                async with self.client.stream("GET", BASE + route) as response:
                    if response.status_code != 200:
                        raise ProtectError(f"Protect HTTP {response.status_code}; no retry performed.")
                    body = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        body.extend(chunk)
                        if len(body) > limit:
                            raise ProtectError("Protect response exceeded the size limit.")
                    return response.headers.get("content-type", "").split(";")[0].lower(), bytes(body)
        except (httpx.HTTPError, TimeoutError):
            raise ProtectError("Protect unavailable or TLS verification failed.") from None

    async def read_json(self, route: str, expected: type) -> Any:
        content_type, payload = await self.read(route, 4 * 1024 * 1024)
        if content_type != "application/json":
            raise ProtectError("Protect returned an unexpected content type.")
        try:
            data = json.loads(payload)
        except ValueError:
            raise ProtectError("Protect returned invalid JSON.") from None
        if not isinstance(data, expected):
            raise ProtectError("Protect returned an unexpected JSON structure.")
        return data

    async def cameras(self) -> list[dict[str, Any]]:
        data = await self.read_json("/cameras", list)
        return [
            {field: camera.get(field) for field in ("id", "name", "state", "modelKey")}
            for camera in data
            if isinstance(camera, dict) and isinstance(camera.get("id"), str)
            and (not self.camera_ids or camera["id"] in self.camera_ids)
        ]

    async def status(self) -> dict[str, Any]:
        application = await self.read_json("/meta/info", dict)
        nvr = await self.read_json("/nvrs", dict)
        return {
            "application_version": application.get("applicationVersion"),
            "nvr": {field: nvr.get(field) for field in ("id", "name", "type")},
            "read_only": True,
            "unsupported": ["system_logs", "recorded_video", "prior_event_history"],
        }

    async def snapshot(self, camera_id: str) -> tuple[str, bytes]:
        self.authorize_camera(camera_id)
        if not any(camera["id"] == camera_id for camera in await self.cameras()):
            raise ProtectError("Camera not available.")
        content_type, payload = await self.read(f"/cameras/{camera_id}/snapshot", 16 * 1024 * 1024)
        if content_type == "image/jpeg" and payload.startswith(b"\xff\xd8\xff"):
            return content_type, payload
        if content_type == "image/png" and payload.startswith(b"\x89PNG\r\n\x1a\n"):
            return content_type, payload
        raise ProtectError("Protect returned an invalid image.")