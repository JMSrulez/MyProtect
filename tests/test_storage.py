import os
from pathlib import Path
import tempfile
import time
import unittest

from myprotect.protect import ProtectError
from myprotect.storage import Store


def event(event_id, camera="camera", **fields):
    return {"type": "add", "item": {"modelKey": "event", "id": event_id, "camera": camera, "type": "motion", **fields}}


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name), max_events=2, media_quota=10)
        self.addCleanup(self.store.close)

    def test_scopes_and_partial_updates(self):
        self.assertFalse(self.store.ingest(event("blocked", "private"), frozenset({"camera"})))
        self.assertTrue(self.store.ingest(event("one", start=123), frozenset({"camera"})))
        self.assertTrue(self.store.ingest({"type": "update", "item": {"modelKey": "event", "id": "one", "end": 456}}, frozenset({"camera"})))
        result = self.store.events(60, 10, None, frozenset({"camera"}))
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["event"]["start"], 123)
        self.assertEqual(result["events"][0]["event"]["end"], 456)
        self.assertFalse(result["complete_nvr_history"])
        self.assertEqual(self.store.events(60, 10, None, frozenset({"other"}))["events"], [])

    def test_event_count_and_ttl(self):
        for event_id in ("one", "two", "three"):
            self.store.ingest(event(event_id), frozenset())
        self.assertEqual(len(self.store.events(60, 10, None, frozenset())["events"]), 2)
        with self.store.database:
            self.store.database.execute("UPDATE events SET received=?", (time.time() - 8 * 86400,))
        self.assertEqual(self.store.events(10080, 10, None, frozenset())["events"], [])

    def test_media_quota_expiration_and_path_traversal(self):
        first = self.store.save_image("image/jpeg", b"123456", "camera")
        second = self.store.save_image("image/jpeg", b"abcdef", "camera")
        with self.assertRaises(ProtectError):
            self.store.load_image(first["media_id"])
        self.assertEqual(self.store.load_image(second["media_id"])[1], b"abcdef")
        with self.assertRaises(ProtectError):
            self.store.load_image(second["media_id"], frozenset({"other"}))
        with self.assertRaises(ProtectError):
            self.store.load_image("../events.sqlite3")
        path = self.store.media / (second["media_id"] + ".jpg")
        os.utime(path, (time.time() - 4000, time.time() - 4000))
        with self.assertRaises(ProtectError):
            self.store.load_image(second["media_id"])

    def test_untrusted_fields_are_not_persisted(self):
        self.store.ingest(event("one", apiKey="secret", thumbnail="https://attacker"), frozenset())
        result = self.store.events(60, 10, None, frozenset())
        self.assertNotIn("apiKey", result["events"][0]["event"])
        self.assertNotIn("thumbnail", result["events"][0]["event"])