"""Tests covering the actual local HTTP server and the lab URL guard."""

import threading
from http.server import ThreadingHTTPServer

import httpx
import pytest

from websec_auditor.lab import LAB_HOST, LabHandler
from websec_auditor.checks.headers import check_headers
from websec_auditor.scanner import scan


@pytest.fixture
def running_lab():
    # Ephemeral port avoids collisions with local development instances in CI.
    server = ThreadingHTTPServer((LAB_HOST, 0), LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{LAB_HOST}:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_server_really_returns_different_http_headers(running_lab):
    with httpx.Client(trust_env=False, timeout=3) as client:
        insecure = client.get(running_lab + "/insecure")
        hardened = client.get(running_lab + "/hardened")

    assert insecure.status_code == hardened.status_code == 200
    assert "content-security-policy" not in insecure.headers
    assert hardened.headers["content-security-policy"].startswith("default-src")
    assert "HttpOnly" not in insecure.headers["set-cookie"]
    assert "HttpOnly" in hardened.headers["set-cookie"]


def test_unrecognized_lab_path_is_404(running_lab):
    response = httpx.get(running_lab + "/unknown", trust_env=False, timeout=3)
    assert response.status_code == 404


@pytest.mark.parametrize("url", [
    "http://example.com/insecure",
    "http://127.0.0.1:8000/insecure",
    "http://localhost:8765/insecure",
    "http://127.0.0.1:8765/private",
    "http://127.0.0.1:8765/insecure?next=1",
    "https://example.test/",
])
def test_lab_rejects_any_other_destination(url):
    with pytest.raises(ValueError):
        scan(url, allow_local_http=True, transport=httpx.MockTransport(lambda request: httpx.Response(200)))


def test_local_lab_not_allowed_without_explicit_opt_in():
    with pytest.raises(ValueError):
        scan("http://127.0.0.1:8765/insecure", transport=httpx.MockTransport(lambda request: httpx.Response(200)))


def test_local_http_profile_suppresses_https_only_checks():
    def response(request):
        return httpx.Response(200, headers={"Set-Cookie": "session=lab-only; Path=/"})
    findings = scan("http://127.0.0.1:8765/insecure", allow_local_http=True, transport=httpx.MockTransport(response))["findings"]
    names = {finding["check"] for finding in findings}
    assert names == {
        "content-security-policy", "x-content-type-options", "referrer-policy",
        "cookie-httponly", "cookie-samesite"
    }
    assert "lab-only" not in str(findings)


def test_local_http_misconfigured_profile_suppresses_hsts_values(running_lab):
    with httpx.Client(trust_env=False, timeout=3) as client:
        result = client.get(running_lab + "/misconfigured")
    assert result.status_code == 200
    names = {item.check for item in check_headers(dict(result.headers), https=False)}
    assert names == {"content-security-policy-unsafe-eval", "referrer-policy-unsafe-url"}
