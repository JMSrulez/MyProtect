import argparse
import getpass
import ipaddress
import os
from pathlib import Path
import secrets
import ssl
import sys

from myprotect.protect import identifier, origin
from myprotect.settings import Settings


def prepare(
    root: Path, protect_url: str, public_url: str, bind_ip: str,
    api_key: str, certificate: Path, private_key: Path, ca_file: Path,
    camera_ids: frozenset[str], uid: int, gid: int,
) -> None:
    if uid == 0:
        raise ValueError("Run as a non-root account, without sudo.")
    ipaddress.IPv4Address(bind_ip)
    if (root / ".env").exists() or (root / ".secrets").exists():
        raise ValueError("Configuration already exists; edit it deliberately rather than overwriting secrets.")
    protect_url, public_url = origin(protect_url), origin(public_url)
    for camera_id in camera_ids:
        identifier(camera_id)
    token = secrets.token_urlsafe(32)
    Settings(protect_url, public_url, api_key, token)
    ssl.create_default_context(cafile=ca_file)
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(certificate, private_key, password="")
    inputs = {
        "protect_ca.pem": ca_file.read_bytes(), "mcp-server.crt": certificate.read_bytes(),
        "mcp-server.key": private_key.read_bytes(),
        "protect_api_key": (api_key + "\n").encode("ascii"),
        "mcp_token": (token + "\n").encode("ascii"),
    }
    os.umask(0o077)
    directory = root / ".secrets"
    directory.mkdir(mode=0o700)
    for filename, payload in inputs.items():
        with (directory / filename).open("xb") as stream:
            stream.write(payload)
    (root / "data").mkdir(mode=0o700, exist_ok=True)
    values = {
        "PROTECT_URL": protect_url, "MCP_PUBLIC_URL": public_url,
        "MCP_BIND_IP": bind_ip, "MYPROTECT_UID": str(uid), "MYPROTECT_GID": str(gid),
        "PROTECT_CAMERA_IDS": ",".join(sorted(camera_ids)),
    }
    with (root / ".env").open("x", encoding="utf-8", newline="\n") as stream:
        for name, value in values.items():
            if any(character in value for character in ("\n", "\r", "'", '"', "$", "#", "\\")):
                raise ValueError("Unsupported configuration character.")
            stream.write(f"{name}='{value}'\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a non-root Ubuntu Docker deployment without printing secrets.")
    parser.add_argument("--protect-url", required=True)
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--bind-ip", default="127.0.0.1")
    parser.add_argument("--tls-cert", required=True, type=Path)
    parser.add_argument("--tls-key", required=True, type=Path)
    parser.add_argument("--protect-ca", type=Path)
    parser.add_argument("--camera-id", action="append", default=[])
    args = parser.parse_args()
    if not hasattr(os, "getuid") or os.getuid() == 0:
        parser.error("Run on Ubuntu as the deployment account, without sudo.")
    if not sys.stdin.isatty():
        parser.error("An interactive terminal is required for the Protect key.")
    ca_file = args.protect_ca or ssl.get_default_verify_paths().cafile
    if not ca_file:
        parser.error("Specify --protect-ca with the verified NVR CA certificate.")
    try:
        prepare(
            Path.cwd(), args.protect_url, args.public_url, args.bind_ip,
            getpass.getpass("Cle API Protect locale (saisie masquee) : "),
            args.tls_cert, args.tls_key, Path(ca_file), frozenset(args.camera_id), os.getuid(), os.getgid(),
        )
    except Exception:
        raise SystemExit("Configuration failed. Check HTTPS URLs, certificates, non-root ownership and existing files; no secret is printed.") from None
    print("Configuration creee. Jeton Hermes dans .secrets/mcp_token; ne pas le partager dans une conversation.")
    print("Verifier le pare-feu, puis lancer : docker compose up -d --build")


if __name__ == "__main__":
    main()