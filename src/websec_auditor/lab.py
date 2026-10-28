"""HTTP and HTTPS loopback labs for educational security checks.

Only bind to 127.0.0.1. Do not expose deliberately weak profiles publicly.
"""

import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LAB_HOST = "127.0.0.1"
LAB_PORT = 8765  # Existing HTTP lab
LAB_TLS_PORT = 8766  # HTTPS lab
LAB_PATHS = frozenset({"/insecure", "/hardened", "/misconfigured"})


class LabHandler(BaseHTTPRequestHandler):
    """Respond with absent, safe or intentionally weak header values."""

    def do_GET(self) -> None:
        if self.path not in LAB_PATHS and self.path != "/":
            self.send_error(404, "Unknown lab path")
            return

        body = (
            b"<html><body><h1>WebSec Auditor local lab</h1>"
            b"<p><a href='/insecure'>Insecure profile</a> | "
            b"<a href='/hardened'>Hardened profile</a> | "
            b"<a href='/misconfigured'>Misconfigured profile</a></p></body></html>"
        )
        using_tls = isinstance(self.connection, ssl.SSLSocket)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")

        if self.path == "/insecure":
            self.send_header("Set-Cookie", "session=lab-only; Path=/")
        elif self.path == "/hardened":
            self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if using_tls:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            attributes = "; Secure; HttpOnly; SameSite=Strict" if using_tls else "; HttpOnly; SameSite=Strict"
            self.send_header("Set-Cookie", "session=lab-only; Path=/" + attributes)
        elif self.path == "/misconfigured":
            # Headers are present, but their *values* weaken their protections.
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-eval'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "unsafe-url")
            if using_tls:
                self.send_header("Strict-Transport-Security", "max-age=0")
            attributes = "; Secure; HttpOnly; SameSite=Strict" if using_tls else "; HttpOnly; SameSite=Strict"
            self.send_header("Set-Cookie", "session=lab-only; Path=/" + attributes)

        self.end_headers()
        self.wfile.write(body)


def serve_lab(
    *,
    https: bool = False,
    cert_file: str | Path | None = None,
    key_file: str | Path | None = None,
) -> None:
    """Serve fixed local routes until Ctrl+C; only the TLS mode loads keys."""
    port = LAB_TLS_PORT if https else LAB_PORT
    with ThreadingHTTPServer((LAB_HOST, port), LabHandler) as server:
        if https:
            if cert_file is None or key_file is None:
                raise ValueError("The HTTPS lab needs a certificate and private key.")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https" if https else "http"
        print(f"Local {scheme.upper()} lab: {scheme}://{LAB_HOST}:{port}/", flush=True)
        print("Use another terminal to scan /insecure, /hardened and /misconfigured. Ctrl+C to stop.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nLab stopped.", flush=True)
