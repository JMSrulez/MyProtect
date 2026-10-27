from pathlib import Path
import tempfile
import unittest

from scripts.configure_server import prepare
from tls_support import certificate_files


class ConfigureTests(unittest.TestCase):
    def test_prepare_private_files_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = certificate_files(root)
            prepare(root, "https://uck.test", "https://mcp.test:8443", "127.0.0.1", "private-api-key", cert, key, cert, frozenset({"camera"}), 1000, 1000)
            self.assertNotIn("private-api-key", (root / ".env").read_text())
            self.assertEqual((root / ".secrets/protect_api_key").read_text().strip(), "private-api-key")
            token = (root / ".secrets/mcp_token").read_text().strip()
            self.assertGreaterEqual(len(token), 43)
            with self.assertRaises(ValueError):
                prepare(root, "https://uck.test", "https://mcp.test:8443", "127.0.0.1", "replacement", cert, key, cert, frozenset(), 1000, 1000)
            self.assertEqual((root / ".secrets/mcp_token").read_text().strip(), token)

    def test_root_is_refused(self):
        with self.assertRaises(ValueError):
            prepare(Path("."), "https://uck.test", "https://mcp.test", "127.0.0.1", "secret", Path("missing"), Path("missing"), Path("missing"), frozenset(), 0, 0)