#!/usr/bin/env python3
"""Read-only checks for the local Protect 7.3.70 Integration API."""

import argparse
import getpass
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
import time
from urllib.parse import quote, urlsplit


BASE = "/proxy/protect/integration/v1"
JSON_LIMIT = 4 * 1024 * 1024
IMAGE_LIMIT = 16 * 1024 * 1024


def console_address(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Utiliser https://adresse-uck[:port], sans chemin ni identifiants.")
    return parsed.hostname, parsed.port or 443, parsed.netloc


class ProtectReader:
    def __init__(self, host, port, key, context):
        self.host = host
        self.port = port
        self.key = key
        self.context = context

    def get(self, route, limit=JSON_LIMIT):
        if not re.fullmatch(
            r"/(?:meta/info|nvrs|cameras|cameras/[A-Za-z0-9_-]+/snapshot)", route
        ):
            raise ValueError("Route de diagnostic non autorisee.")
        connection = http.client.HTTPSConnection(
            self.host, self.port, context=self.context, timeout=20
        )
        try:
            connection.request(
                "GET", BASE + route,
                headers={"X-API-KEY": self.key, "Accept": "*/*"},
            )
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "").split(";")[0].lower()
            payload = response.read(limit + 1)
            if len(payload) > limit:
                raise ValueError("Reponse trop volumineuse.")
            return response.status, content_type, payload
        finally:
            connection.close()


def status_label(status):
    if status == 401:
        return "cle refusee"
    if status == 403:
        return "acces refuse"
    if status == 404:
        return "route indisponible ou masquee"
    if status == 429:
        return "limite de requetes atteinte; ne pas relancer en boucle"
    if 300 <= status < 400:
        return "redirection refusee; verifier l'adresse locale"
    return "reponse HTTP"


def check_json(reader, route, expected_type):
    try:
        status, content_type, payload = reader.get(route)
        result = {"http_status": status, "ok": False}
        if status != 200:
            result["detail"] = status_label(status)
            return result, None
        if content_type != "application/json":
            raise ValueError("Une reponse JSON etait attendue.")
        data = json.loads(payload)
        if not isinstance(data, expected_type):
            raise ValueError("Structure JSON inattendue.")
        result["ok"] = True
        if isinstance(data, list):
            result["count"] = len(data)
        return result, data
    except ssl.SSLCertVerificationError:
        return {"ok": False, "detail": "certificat TLS non approuve ou nom incorrect"}, None
    except (OSError, ValueError, http.client.HTTPException) as error:
        return {"ok": False, "detail": type(error).__name__}, None


def capture(reader, camera_id, output):
    try:
        status, content_type, payload = reader.get(
            "/cameras/" + quote(camera_id, safe="") + "/snapshot", IMAGE_LIMIT
        )
        result = {"ok": False, "http_status": status}
        if status != 200:
            result["detail"] = status_label(status)
            return result
        if content_type == "image/jpeg" and payload.startswith(b"\xff\xd8\xff"):
            filename = "snapshot.jpg"
        elif content_type == "image/png" and payload.startswith(b"\x89PNG\r\n\x1a\n"):
            filename = "snapshot.png"
        else:
            raise ValueError("Reponse image inattendue.")
        (output / filename).write_bytes(payload)
        return {"ok": True, "http_status": status, "bytes": len(payload), "file": filename}
    except (OSError, ValueError, http.client.HTTPException) as error:
        return {"ok": False, "detail": type(error).__name__}


def listen_events(authority, key, context, seconds, output, save_events):
    try:
        from websockets.sync.client import connect
        from websockets.exceptions import WebSocketException
    except ImportError:
        return {"ok": False, "detail": "installer websockets==15.0.1 pour ce test"}
    count = 0
    total = 0
    try:
        with connect(
            "wss://" + authority + BASE + "/subscribe/events",
            additional_headers={"X-API-KEY": key},
            ssl=context, proxy=None, open_timeout=15, close_timeout=3,
            max_size=65536,
        ) as connection:
            deadline = time.monotonic() + seconds
            while count < 100 and total < 1024 * 1024:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    message = connection.recv(timeout=remaining)
                except TimeoutError:
                    break
                data = json.loads(message)
                encoded = json.dumps(data, ensure_ascii=True) + "\n"
                total += len(encoded.encode("utf-8"))
                count += 1
                if save_events:
                    with (output / "events.private.jsonl").open("a", encoding="utf-8") as stream:
                        stream.write(encoded)
        return {"ok": True, "messages": count, "seconds": seconds,
                "detail": "flux connecte; zero message ne signifie pas absence d'alarmes"}
    except (OSError, ValueError, WebSocketException) as error:
        return {"ok": False, "messages": count, "detail": type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--console", required=True, help="https://nom-ou-ip-uck")
    parser.add_argument("--ca-file", type=Path, help="Autorite ou certificat approuve au format PEM")
    parser.add_argument("--camera-id", help="ID de la seule camera dont prendre une photo")
    parser.add_argument("--events-seconds", type=int, default=0, help="Ecoute du flux, 0 a 120 secondes")
    parser.add_argument("--save-events", action="store_true", help="Enregistrer les messages sensibles localement")
    args = parser.parse_args()
    if not 0 <= args.events_seconds <= 120:
        parser.error("--events-seconds doit etre compris entre 0 et 120")
    if args.save_events and not args.events_seconds:
        parser.error("--save-events necessite --events-seconds")
    if args.camera_id and not re.fullmatch(r"[A-Za-z0-9_-]+", args.camera_id):
        parser.error("ID de camera invalide")
    try:
        host, port, authority = console_address(args.console)
        context = ssl.create_default_context(cafile=args.ca_file)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if not sys.stdin.isatty():
        parser.error("Lancer depuis un terminal interactif pour saisir la cle sans affichage.")
    key = getpass.getpass("Cle API Protect locale (saisie masquee) : ")
    if not key or any(ord(character) < 33 or ord(character) > 126 for character in key):
        parser.error("Cle vide ou caracteres invalides")
    os.umask(0o077)
    output = Path(tempfile.mkdtemp(prefix="protect-diagnostic-", dir=Path.cwd()))
    reader = ProtectReader(host, port, key, context)
    report = {"target_version": "7.3.70", "checks": {}, "limitations": {
        "nvr_system_logs": "Pas de route dans l'index officiel 7.3.70; non teste.",
        "historical_events": "Pas de recherche REST dans l'index officiel; non teste.",
        "recorded_video": "Pas d'export dans l'index officiel; non teste. Aucun flux cree.",
    }}
    cameras = None
    for name, route, expected in (
        ("application", "/meta/info", dict),
        ("nvr", "/nvrs", dict),
        ("cameras", "/cameras", list),
    ):
        result, data = check_json(reader, route, expected)
        report["checks"][name] = result
        print(name + ": " + json.dumps(result, ensure_ascii=True))
        if name == "application" and data is not None:
            version = data.get("applicationVersion")
            if isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z.+_-]{1,64}", version):
                report["application_version"] = version
        if name == "cameras":
            cameras = data
        if result.get("http_status") in (401, 403, 429) or (
            not result["ok"] and "http_status" not in result
        ):
            break
    if cameras is not None:
        inventory = [{field: camera.get(field) for field in ("id", "name", "state")}
                     for camera in cameras if isinstance(camera, dict)]
        (output / "cameras.private.json").write_text(
            json.dumps(inventory, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )
        if args.camera_id:
            if any(camera.get("id") == args.camera_id for camera in inventory):
                report["checks"]["snapshot"] = capture(reader, args.camera_id, output)
            else:
                report["checks"]["snapshot"] = {"ok": False, "detail": "camera absente de l'inventaire"}
        if args.events_seconds:
            report["checks"]["events"] = listen_events(
                authority, key, context, args.events_seconds, output, args.save_events
            )
    report["ok"] = all(item["ok"] for item in report["checks"].values())
    (output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    print("Resultats locaux : " + str(output))
    print("Partager uniquement report.json apres relecture; les autres fichiers sont prives.")
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nDiagnostic interrompu.", file=sys.stderr)
        sys.exit(130)