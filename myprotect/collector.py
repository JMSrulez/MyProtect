import json
import threading
import time
from typing import Any

from websockets.exceptions import InvalidStatus, WebSocketException
from websockets.sync.client import connect

from myprotect.protect import BASE, ProtectClient
from myprotect.storage import Store


class Collector:
    def __init__(self, client: ProtectClient, store: Store) -> None:
        self.client = client
        self.store = store
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.state: dict[str, Any] = {
            "connected": False, "started_at": time.time(), "connected_at": None,
            "last_message_at": None, "messages_received": 0, "events_stored": 0,
            "disconnects": 0, "last_error": None, "history_complete": False,
        }
        self.thread = threading.Thread(target=self.run, name="protect-events", daemon=True)

    def status(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.state)

    def update(self, **changes: Any) -> None:
        with self.lock:
            self.state.update(changes)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=20)
        if self.thread.is_alive():
            raise RuntimeError("Event collector did not stop in time.")

    def run(self) -> None:
        delay = 1
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                with connect(
                    self.client.url.replace("https://", "wss://", 1) + BASE + "/subscribe/events",
                    additional_headers={"X-API-KEY": self.client.api_key},
                    ssl=self.client.context, proxy=None, open_timeout=10, close_timeout=2,
                    max_size=65536, max_queue=8, ping_interval=20, ping_timeout=20,
                ) as connection:
                    self.update(connected=True, connected_at=time.time(), last_error=None)
                    while not self.stop_event.is_set():
                        try:
                            message = connection.recv(timeout=1)
                        except TimeoutError:
                            continue
                        state = self.status()
                        self.update(last_message_at=time.time(), messages_received=state["messages_received"] + 1)
                        try:
                            stored = self.store.ingest(json.loads(message), self.client.camera_ids)
                        except (ValueError, TypeError):
                            stored = False
                        if stored:
                            self.update(events_stored=self.status()["events_stored"] + 1)
            except InvalidStatus as error:
                self.update(last_error=f"HTTP {error.response.status_code}")
                if error.response.status_code in (401, 403):
                    self.update(connected=False)
                    self.stop_event.wait()
                    return
            except (OSError, WebSocketException):
                self.update(last_error="Event connection unavailable or TLS failed")
            except Exception:
                self.update(last_error="Event collection failed; check local storage")
            finally:
                self.update(connected=False)
            if self.stop_event.is_set():
                return
            self.update(disconnects=self.status()["disconnects"] + 1)
            if time.monotonic() - started > 60:
                delay = 1
            self.stop_event.wait(delay)
            delay = min(delay * 2, 60)