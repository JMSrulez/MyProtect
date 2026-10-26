import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from diagnose_protect import ProtectReader, capture, check_json, console_address


class DiagnosticTests(unittest.TestCase):
    def test_only_https_console_origin(self):
        self.assertEqual(console_address("https://uck.local:8443"), ("uck.local", 8443, "uck.local:8443"))
        for value in ("http://uck", "https://user:secret@uck", "https://uck/api", "https://uck?key=secret"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                console_address(value)

    @patch("diagnose_protect.http.client.HTTPSConnection")
    def test_get_only_and_no_redirect_following(self, factory):
        connection = factory.return_value
        response = connection.getresponse.return_value
        response.status = 302
        response.getheader.return_value = "text/html"
        response.read.return_value = b"redirect"
        reader = ProtectReader("uck", 443, "test-secret", MagicMock())
        self.assertEqual(reader.get("/cameras")[0], 302)
        connection.request.assert_called_once_with(
            "GET", "/proxy/protect/integration/v1/cameras",
            headers={"X-API-KEY": "test-secret", "Accept": "*/*"},
        )
        connection.close.assert_called_once()
        for route in ("/../api", "/cameras/id/reboot", "/cameras?x=1", "https://other"):
            with self.assertRaises(ValueError):
                reader.get(route)

    @patch("diagnose_protect.http.client.HTTPSConnection")
    def test_size_limit_closes_connection(self, factory):
        factory.return_value.getresponse.return_value.read.return_value = b"12345"
        reader = ProtectReader("uck", 443, "test-secret", MagicMock())
        with self.assertRaises(ValueError):
            reader.get("/cameras", limit=4)
        factory.return_value.close.assert_called_once()

    def test_wrong_json_and_http_errors_are_not_success(self):
        reader = MagicMock()
        for status, content_type, payload in (
            (200, "text/html", b"login"),
            (200, "application/json", b"{}"),
            (200, "application/json", b"invalid"),
            (401, "application/json", b'{"secret":"do-not-share"}'),
        ):
            reader.get.return_value = status, content_type, payload
            result, data = check_json(reader, "/cameras", list)
            self.assertFalse(result["ok"])
            self.assertIsNone(data)
            self.assertNotIn("do-not-share", json.dumps(result))

    def test_snapshot_rejects_html_and_accepts_jpeg(self):
        reader = MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            reader.get.return_value = 200, "text/html", b"login"
            self.assertFalse(capture(reader, "camera-id", output)["ok"])
            self.assertEqual(list(output.iterdir()), [])
            reader.get.return_value = 200, "image/jpeg", b"\xff\xd8\xffimage"
            self.assertTrue(capture(reader, "camera-id", output)["ok"])
            self.assertEqual((output / "snapshot.jpg").read_bytes(), b"\xff\xd8\xffimage")


if __name__ == "__main__":
    unittest.main()