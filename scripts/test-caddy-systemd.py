#!/usr/bin/env python3
"""Real Caddy/root-helper integration, ONLY on an empty disposable hosted runner.

Creates and removes fixed-path test resources; never run on a real proxy.
No provider credentials, production service, or Swamp platform is used.
"""
from contextlib import closing
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid


def command(*args):
    return subprocess.run(args, check=True, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=60)


def main():
    if (sys.argv[1:2] != ["--disposable-hosted-runner"] or os.geteuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("Requires explicit disposable GitHub-hosted runner opt-in and root")
    binary = Path(sys.argv[2]).resolve(strict=True)
    helper = Path(__file__).resolve().parents[1] / "caddy/swamp-caddy.py"
    root = Path("/run/caddy-publication-test")
    config = Path("/etc/caddy")
    installed = Path("/usr/bin/caddy")
    installed_helper = Path("/usr/local/sbin/swamp-caddy")
    unit = Path("/etc/systemd/system/caddy.service")
    # Refuse even inactive/preinstalled resources. This script never adopts them.
    for path in (root, config, installed, installed_helper, unit):
        if path.exists() or path.is_symlink():
            raise RuntimeError("Refusing preexisting Caddy test resource")
    known = subprocess.run(["systemctl", "list-unit-files", "caddy.service", "--no-legend"],
                           check=True, capture_output=True, timeout=20)
    if known.stdout.strip():
        raise RuntimeError("Refusing preexisting Caddy unit")
    for port in (12019, 18443, 18444):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))

    backend = None
    root.mkdir(mode=0o700)
    try:
        config.mkdir(mode=0o755)
        (config / "trust").mkdir(mode=0o755)
        shutil.copyfile(binary, installed)
        installed.chmod(0o755)
        shutil.copyfile(helper, installed_helper)
        installed_helper.chmod(0o755)
        # Generate only throwaway public/private fixture material, never print it.
        for name in ("backend", "unrelated"):
            command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(root / (name + ".key")),
                    "-out", str(root / (name + ".pem")), "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-addext", "basicConstraints=critical,CA:TRUE")
            shutil.copyfile(root / (name + ".pem"), config / "trust" / (name + ".pem"))
            (config / "trust" / (name + ".pem")).chmod(0o644)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"fixture-backend-ok")

            def log_message(self, *_):
                pass

        backend = http.server.ThreadingHTTPServer(("127.0.0.1", 18444), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / "backend.pem", root / "backend.key")
        backend.socket = tls.wrap_socket(backend.socket, server_side=True)
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        caddyfile = config / "Caddyfile"
        original = ("{\n    admin 127.0.0.1:12019\n    https_port 18443\n"
                    "    auto_https disable_redirects\n    skip_install_trust\n"
                    "    storage file_system {\n        root /run/caddy-publication-test/storage\n    }\n}\n"
                    "*.example.com {\n    bind 127.0.0.1\n    tls internal\n"
                    "    respond \"fixture-baseline\" 404\n}\n").encode()
        caddyfile.write_bytes(original)
        caddyfile.chmod(0o640)
        # A one-shot injected ExecReload failure exercises real systemd failure
        # and the helper's second, successful reload of the restored original.
        reloader = root / "reload.py"
        reloader.write_text("import os,pathlib,sys\n"
                            "p=pathlib.Path('/run/caddy-publication-test/fail-next-reload')\n"
                            "if p.exists(): p.unlink();sys.exit(1)\n"
                            "os.execv('/usr/bin/caddy',['caddy','reload','--config',"
                            "'/etc/caddy/Caddyfile','--adapter','caddyfile',"
                            "'--address','127.0.0.1:12019'])\n")
        unit.write_text("[Unit]\nDescription=Disposable publication integration fixture\n"
                        "[Service]\nType=simple\n"
                        "Environment=HOME=/run/caddy-publication-test\n"
                        "Environment=XDG_CONFIG_HOME=/run/caddy-publication-test/config\n"
                        "ExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile\n"
                        "ExecReload=/usr/bin/python3 /run/caddy-publication-test/reload.py\n"
                        "TimeoutStopSec=10\n")
        command("systemctl", "daemon-reload")
        command("systemctl", "start", "caddy")
        ca = root / "storage/pki/authorities/local/root.crt"
        for _ in range(100):
            if ca.exists():
                break
            time.sleep(0.1)
        front_tls = ssl.create_default_context(cafile=str(ca))

        class LocalTLS(http.client.HTTPSConnection):
            def connect(self):
                raw = socket.create_connection(("127.0.0.1", 18443), timeout=5)
                self.sock = front_tls.wrap_socket(raw, server_hostname="notes.example.com")

        def probe(status, body=None):
            for attempt in range(30):
                try:
                    with closing(LocalTLS("notes.example.com", timeout=5)) as connection:
                        connection.request("GET", "/")
                        response = connection.getresponse()
                        received = response.read(4096)
                        if response.status == status and (body is None or received == body):
                            return
                except (OSError, http.client.HTTPException):
                    pass
                if attempt < 29:
                    time.sleep(0.1)
            raise AssertionError("Real TLS endpoint did not return the expected status/body")

        def run(action, fields=None, fail=False):
            payload = dict(action=action, requestId=str(uuid.uuid4()), **(fields or {}))
            output = subprocess.run([str(installed_helper)], input=json.dumps(payload).encode(),
                                    capture_output=True, timeout=60)
            result = json.loads(output.stdout)
            assert bool(output.returncode) == fail, result
            if not fail:
                assert result["action"] == action and result["requestId"] == payload["requestId"]
            return result

        def route():
            return dict(name="notes", hostname="notes.example.com", wildcardDomain="example.com",
                        upstream="127.0.0.1:18444", upstreamScheme="https",
                        upstreamCaFile="/etc/caddy/trust/backend.pem", allowedCidrs=["127.0.0.1/32"],
                        expectedSha256=hashlib.sha256(caddyfile.read_bytes()).hexdigest())

        probe(404, b"fixture-baseline")
        assert run("inspect")["serviceActive"] is True
        planned = run("plan", route())
        assert planned["validated"] and caddyfile.read_bytes() == original
        applied = run("apply", route())
        assert applied["changed"] and Path(applied["backupPath"]).read_bytes() == original
        probe(200, b"fixture-backend-ok")
        assert run("apply", route())["changed"] is False
        good = caddyfile.read_bytes()
        denied = route()
        denied["allowedCidrs"] = ["192.0.2.0/24"]
        run("apply", denied)
        probe(403, b"Forbidden")
        # Caddy preserves address families: neither an IPv4-mapped IPv6
        # prefix nor half of IPv6 may accidentally admit this IPv4 client.
        for prefix in ("::ffff:0:0/96", "::/1"):
            denied_family = route()
            denied_family["allowedCidrs"] = [prefix]
            run("apply", denied_family)
            probe(403, b"Forbidden")
        run("apply", route())
        probe(200, b"fixture-backend-ok")
        bad_trust = route()
        bad_trust["upstreamCaFile"] = "/etc/caddy/trust/unrelated.pem"
        run("apply", bad_trust)
        probe(502)  # A valid but wrong CA must NOT make the backend trusted.
        run("apply", route())
        probe(200, b"fixture-backend-ok")
        (root / "fail-next-reload").touch()
        run("apply", denied, fail=True)
        assert caddyfile.read_bytes() == good
        probe(200, b"fixture-backend-ok")
        for unsupported in ({"arbitrary": "not-a-field"}, {"configPath": "/tmp/Caddyfile"}):
            run("inspect", unsupported, fail=True)
        assert caddyfile.read_bytes() == good
        removal = {key: value for key, value in route().items()
                   if key in ("name", "hostname", "wildcardDomain", "expectedSha256")}
        run("remove", removal)
        assert caddyfile.read_bytes() == original
        probe(404, b"fixture-baseline")
        removal["expectedSha256"] = hashlib.sha256(original).hexdigest()
        assert run("remove", removal)["changed"] is False
        command("systemctl", "stop", "caddy")
        assert run("inspect")["serviceActive"] is False
        print("PASS: real Caddy/systemd plan, verified upstream TLS, wrong-CA rejection, "
              "CIDR deny/allow and address-family isolation, apply/idempotency, reload rollback, strict helper input, "
              "removal/idempotency and inactive inspection")
    finally:
        if unit.exists():
            subprocess.run(["systemctl", "stop", "caddy"], timeout=20, check=False)
            unit.unlink()
            command("systemctl", "daemon-reload")
        if backend is not None:
            backend.shutdown()
            backend.server_close()
        installed.unlink(missing_ok=True)
        installed_helper.unlink(missing_ok=True)
        shutil.rmtree(config, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
