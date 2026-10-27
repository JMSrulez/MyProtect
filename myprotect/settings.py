from dataclasses import dataclass, field
import os
from pathlib import Path
import ssl

from myprotect.protect import identifier, origin


def secret_file(variable: str) -> str:
    value = Path(os.environ[variable]).read_text(encoding="utf-8").strip()
    if not value or any(ord(character) < 33 or ord(character) > 126 for character in value):
        raise ValueError(f"Invalid secret in {variable}.")
    return value


@dataclass(frozen=True)
class Settings:
    protect_url: str
    public_url: str
    api_key: str = field(repr=False)
    bearer_token: str = field(repr=False)
    data_dir: Path = Path("data")
    ca_file: str | None = None
    camera_ids: frozenset[str] = frozenset()
    event_days: int = 7
    max_events: int = 10000
    media_ttl: int = 3600
    media_quota: int = 256 * 1024 * 1024
    requests_per_minute: int = 60

    def __post_init__(self) -> None:
        origin(self.protect_url)
        origin(self.public_url)
        if (
            len(self.bearer_token) < 43 or self.bearer_token == self.api_key
            or not self.api_key
            or any(ord(character) < 33 or ord(character) > 126 for character in self.bearer_token + self.api_key)
        ):
            raise ValueError("Use distinct printable secrets and a Bearer token of at least 43 characters.")
        for camera in self.camera_ids:
            identifier(camera)
        if not (
            1 <= self.event_days <= 7 and 1 <= self.max_events <= 10000
            and 60 <= self.media_ttl <= 3600 and 16 * 1024 * 1024 <= self.media_quota <= 5 * 1024**3
            and 1 <= self.requests_per_minute <= 120
        ):
            raise ValueError("Retention, quota or rate limit outside supported bounds.")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            protect_url=origin(os.environ["PROTECT_URL"]),
            public_url=origin(os.environ["MCP_PUBLIC_URL"]),
            api_key=secret_file("PROTECT_API_KEY_FILE"),
            bearer_token=secret_file("MCP_TOKEN_FILE"),
            data_dir=Path(os.environ.get("DATA_DIR", "/data")),
            ca_file=os.environ.get("PROTECT_CA_FILE") or None,
            camera_ids=frozenset(part.strip() for part in os.environ.get("PROTECT_CAMERA_IDS", "").split(",") if part.strip()),
            event_days=int(os.environ.get("EVENT_RETENTION_DAYS", "7")),
            max_events=int(os.environ.get("EVENT_MAX_ROWS", "10000")),
            media_ttl=int(os.environ.get("MEDIA_TTL_SECONDS", "3600")),
            media_quota=int(os.environ.get("MEDIA_MAX_BYTES", str(256 * 1024 * 1024))),
            requests_per_minute=int(os.environ.get("REQUESTS_PER_MINUTE", "60")),
        )

    def tls_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=self.ca_file)