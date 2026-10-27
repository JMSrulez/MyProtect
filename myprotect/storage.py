import json
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from typing import Any

from myprotect.protect import IDENTIFIER, ProtectError


class Store:
    def __init__(
        self, directory: Path, retention_seconds: int = 7 * 86400,
        max_events: int = 10000, media_ttl: int = 3600,
        media_quota: int = 256 * 1024 * 1024,
    ) -> None:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.media = directory / "media"
        self.media.mkdir(exist_ok=True, mode=0o700)
        self.retention_seconds = retention_seconds
        self.max_events = max_events
        self.media_ttl = media_ttl
        self.media_quota = media_quota
        self.lock = threading.RLock()
        self.database = sqlite3.connect(directory / "events.sqlite3", check_same_thread=False)
        self.database.execute("PRAGMA auto_vacuum=FULL")
        self.database.execute("PRAGMA secure_delete=ON")
        self.database.execute("PRAGMA max_page_count=32768")
        self.database.executescript(
            "CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, received REAL NOT NULL, payload TEXT NOT NULL);"
            "CREATE INDEX IF NOT EXISTS events_received ON events(received);"
            "CREATE TABLE IF NOT EXISTS audit (at REAL NOT NULL, operation TEXT NOT NULL, outcome TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS media (id TEXT PRIMARY KEY, camera TEXT NOT NULL);"
        )
        self.prune()

    def close(self) -> None:
        with self.lock:
            self.database.close()

    def audit(self, operation: str, outcome: str) -> None:
        with self.lock, self.database:
            self.database.execute("INSERT INTO audit VALUES (?, ?, ?)", (time.time(), operation[:80], outcome[:32]))
            self.database.execute(
                "DELETE FROM audit WHERE rowid NOT IN (SELECT rowid FROM audit ORDER BY rowid DESC LIMIT 20000)"
            )

    def ingest(self, message: Any, allowed_cameras: frozenset[str]) -> bool:
        if not isinstance(message, dict) or message.get("type") not in ("add", "update", "remove"):
            return False
        item = message.get("item")
        if not isinstance(item, dict) or item.get("modelKey") != "event":
            return False
        event_id = item.get("id")
        if not isinstance(event_id, str) or not IDENTIFIER.fullmatch(event_id):
            return False
        with self.lock, self.database:
            previous = self.database.execute("SELECT payload FROM events WHERE id=?", (event_id,)).fetchone()
            data = json.loads(previous[0]) if previous else {"id": event_id}
            for field in ("camera", "type", "start", "end", "score", "smartDetectTypes"):
                if field in item:
                    data[field] = item[field]
            camera_id = data.get("camera")
            if not isinstance(camera_id, str) or not IDENTIFIER.fullmatch(camera_id):
                return False
            if allowed_cameras and camera_id not in allowed_cameras:
                return False
            data["action"] = message["type"]
            encoded = json.dumps(data, ensure_ascii=True, allow_nan=False)
            if len(encoded.encode("utf-8")) > 4096:
                return False
            self.database.execute(
                "INSERT INTO events VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET received=excluded.received, payload=excluded.payload",
                (event_id, time.time(), encoded),
            )
            self._prune_events()
        return True

    def _prune_events(self) -> None:
        self.database.execute("DELETE FROM events WHERE received < ?", (time.time() - self.retention_seconds,))
        self.database.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY received DESC, id DESC LIMIT ?)",
            (self.max_events,),
        )

    def events(self, since_minutes: int, limit: int, camera_id: str | None, allowed_cameras: frozenset[str]) -> dict[str, Any]:
        if not 1 <= since_minutes <= 10080 or not 1 <= limit <= 100:
            raise ProtectError("Use 1..10080 minutes and 1..100 results.")
        with self.lock, self.database:
            self._prune_events()
            rows = self.database.execute(
                "SELECT received, payload FROM events WHERE received >= ? ORDER BY received DESC, id DESC",
                (time.time() - since_minutes * 60,),
            )
            results = []
            for received, payload in rows:
                event = json.loads(payload)
                if allowed_cameras and event["camera"] not in allowed_cameras:
                    continue
                if camera_id and event["camera"] != camera_id:
                    continue
                results.append({"received_at": received, "event": event})
                if len(results) > limit:
                    break
            return {"events": results[:limit], "truncated": len(results) > limit,
                    "time_filter": "local_last_received_time", "complete_nvr_history": False}

    def _media_files(self) -> list[Path]:
        return [path for path in self.media.iterdir() if re.fullmatch(r"[a-f0-9]{32}\.(jpg|png)", path.name) and not path.is_symlink()]

    def _delete_image(self, path: Path) -> None:
        path.unlink()
        self.database.execute("DELETE FROM media WHERE id=?", (path.stem,))

    def prune(self) -> None:
        with self.lock, self.database:
            self._prune_events()
            self.database.execute("DELETE FROM audit WHERE at < ?", (time.time() - 30 * 86400,))
            files = sorted(self._media_files(), key=lambda path: path.stat().st_mtime)
            for path in files:
                if path.stat().st_mtime + self.media_ttl <= time.time():
                    self._delete_image(path)
            files = [path for path in files if path.exists()]
            total = sum(path.stat().st_size for path in files)
            while files and (total > self.media_quota or len(files) > 1000):
                path = files.pop(0)
                total -= path.stat().st_size
                self._delete_image(path)

    def save_image(self, content_type: str, payload: bytes, camera_id: str) -> dict[str, Any]:
        if content_type not in ("image/jpeg", "image/png") or len(payload) > self.media_quota:
            raise ProtectError("Image exceeds the configured quota.")
        with self.lock, self.database:
            self.prune()
            files = sorted(self._media_files(), key=lambda path: path.stat().st_mtime)
            total = sum(path.stat().st_size for path in files)
            while files and (total + len(payload) > self.media_quota or len(files) >= 1000):
                path = files.pop(0)
                total -= path.stat().st_size
                self._delete_image(path)
            media_id = secrets.token_hex(16)
            suffix = ".jpg" if content_type == "image/jpeg" else ".png"
            path = self.media / (media_id + suffix)
            with path.open("xb") as stream:
                stream.write(payload)
            self.database.execute("INSERT INTO media VALUES (?, ?)", (media_id, camera_id))
            return {"media_id": media_id, "mime_type": content_type, "bytes": len(payload),
                    "expires_at": path.stat().st_mtime + self.media_ttl}

    def load_image(self, media_id: str, allowed_cameras: frozenset[str] = frozenset()) -> tuple[str, bytes]:
        if not re.fullmatch(r"[a-f0-9]{32}", media_id):
            raise ProtectError("Invalid media reference.")
        with self.lock:
            self.prune()
            source = self.database.execute("SELECT camera FROM media WHERE id=?", (media_id,)).fetchone()
            if source is None or (allowed_cameras and source[0] not in allowed_cameras):
                raise ProtectError("Media expired or unavailable.")
            for suffix, content_type in ((".jpg", "image/jpeg"), (".png", "image/png")):
                path = self.media / (media_id + suffix)
                if path.is_file() and not path.is_symlink():
                    return content_type, path.read_bytes()
        raise ProtectError("Media expired or unavailable.")