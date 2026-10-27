"""Intentionally misconfigured loopback-only HTTP lab for security education.

Do not deploy this server to a public interface. It is intentionally HTTP
(without TLS), so HTTPS-only checks cannot be exercised in this first lab.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAB_HOST = "127.0.0.1"
LAB_PORT = 8765
LAB_PATHS = frozenset({"/insecure", "/hardened"})


class LabHandler(BaseHTTPRequestHandler):
    """Serve fixed, synthetic pages with different HTTP security settings."""

    def do_GET(self) -> None:
        path = self.path
        if path not in LAB_PATHS and path != "/":
            self.send_error(404, "Unknown lab path")
            return

        body = (
            b"<html><body><h1>WebSec Auditor local lab</h1>"
            b"<p><a href='/insecure'>Insecure profile</a> | "
            b"<a href='/hardened'>Hardened profile</a></p></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if path == "/insecure":
            # Synthetic placeholder, not an actual user session.
            self.send_header("Set-Cookie", "session=lab-only; Path=/")
        elif path == "/hardened":
            self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Set-Cookie", "session=lab-only; Path=/; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(body)


def serve_lab() -> None:
    """Run until Ctrl+C. Binding is fixed to 127.0.0.1, never 0.0.0.0."""
    with ThreadingHTTPServer((LAB_HOST, LAB_PORT), LabHandler) as server:
        print(f"Local HTTP lab: http://{LAB_HOST}:{LAB_PORT}/", flush=True)
        print("Use a second terminal to scan /insecure and /hardened. Ctrl+C to stop.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nLab stopped.", flush=True)
