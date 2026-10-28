"""HTTPS integration tests with a short-lived local CA."""

import shutil
import ssl
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from websec_auditor.lab import LAB_HOST, LabHandler
from websec_auditor.scanner import scan


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("OpenSSL CLI required for local HTTPS integration tests.")
    directory = tmp_path_factory.mktemp("tls-lab")
    script = Path(__file__).parents[1] / "scripts" / "create_lab_certs.py"
    subprocess.run(
        [sys.executable, str(script), "--out", str(directory)],
        check=True, capture_output=True, text=True,
    )
    return directory


@pytest.fixture
def tls_lab(certificates, monkeypatch):
    server = ThreadingHTTPServer((LAB_HOST, 0), LabHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=str(certificates / "server.crt"),
        keyfile=str(certificates / "server.key"),
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr("websec_auditor.scanner.LAB_TLS_PORT", server.server_port)
    try:
        yield f"https://{LAB_HOST}:{server.server_port}", certificates / "ca.crt"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_https_scanner_verifies_certificate_and_detects_seven_findings(tls_lab):
    base, ca = tls_lab
    result = scan(base + "/insecure", allow_local_https=True, ca_file=ca)
    assert result["status_code"] == 200
    assert result["tls"] == {"certificate_verified": True, "trust_source": "local_lab_ca"}
    assert len(result["findings"]) == 7
    names = {f["check"] for f in result["findings"]}
    assert "strict-transport-security" in names
    assert "cookie-secure" in names
    assert "lab-only" not in str(result)


def test_https_hardened_profile_passes_current_checks(tls_lab):
    base, ca = tls_lab
    result = scan(base + "/hardened", allow_local_https=True, ca_file=ca)
    assert result["status_code"] == 200
    assert result["findings"] == []
    assert result["tls"]["certificate_verified"] is True


def test_https_certificate_is_not_trusted_without_explicit_local_ca(tls_lab):
    base, _ = tls_lab
    with pytest.raises(httpx.ConnectError):
        httpx.get(base + "/hardened", timeout=3, trust_env=False)


@pytest.mark.parametrize("url", [
    "https://example.org/insecure",
    "https://127.0.0.1:8766/private",
    "http://127.0.0.1:8766/insecure",
    "https://localhost:8766/insecure",
    "https://127.0.0.1:8766/insecure?next=1",
])
def test_https_lab_rejects_other_targets_before_network(url):
    with pytest.raises(ValueError):
        scan(
            url, allow_local_https=True, ca_file=Path("unused-ca.pem"),
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        )


def test_https_lab_requires_ca():
    with pytest.raises(ValueError):
        scan(
            "https://127.0.0.1:8766/insecure", allow_local_https=True,
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        )


def test_regular_https_mode_rejects_custom_lab_ca():
    with pytest.raises(ValueError):
        scan("https://example.org/", ca_file=Path("unused-ca.pem"))


def test_http_and_https_lab_modes_are_mutually_exclusive():
    with pytest.raises(ValueError):
        scan(
            "http://127.0.0.1:8765/insecure",
            allow_local_http=True, allow_local_https=True,
        )


def test_https_misconfigured_profile_detects_bad_values(tls_lab):
    base, ca = tls_lab
    result = scan(base + "/misconfigured", allow_local_https=True, ca_file=ca)
    assert result["status_code"] == 200
    assert result["tls"]["certificate_verified"] is True
    assert {item["check"] for item in result["findings"]} == {
        "content-security-policy-unsafe-eval",
        "referrer-policy-unsafe-url",
        "strict-transport-security-disabled",
    }

def test_real_local_https_report_summarizes_severity_and_scope(tls_lab):
    base, ca = tls_lab
    result = scan(base + "/misconfigured", allow_local_https=True, ca_file=ca)
    assert result["summary"] == {
        "total_findings": 3,
        "by_severity": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 0},
    }
    assert result["methodology"]["mode"] == "local_https_lab"
    assert result["methodology"]["requests_sent"] == 1
    assert result["tls"]["certificate_verified"] is True

def test_local_https_misconfigured_evidence_matches_observations(tls_lab):
    base, ca = tls_lab
    result = scan(base + "/misconfigured", allow_local_https=True, ca_file=ca)
    by_check = {item["check"]: item for item in result["findings"]}
    assert result["summary"]["total_findings"] == 3
    assert by_check["content-security-policy-unsafe-eval"]["evidence"]["effective_directive"] == "script-src"
    assert by_check["referrer-policy-unsafe-url"]["evidence"]["effective_policy"] == "unsafe-url"
    assert by_check["strict-transport-security-disabled"]["evidence"]["max_age_seconds"] == 0
    assert "lab-only" not in str(result)


def test_real_https_json_avoids_document_header_false_positives(tls_lab):
    base, ca = tls_lab
    result = scan(base + "/json", allow_local_https=True, ca_file=ca)
    assert result["status_code"] == 200
    assert result["response_context"] == {
        "kind": "non_html", "document_checks_applied": False,
    }
    assert result["findings"] == []
    assert result["summary"]["total_findings"] == 0
    assert result["methodology"]["skipped_checks"] == [
        "content-security-policy", "referrer-policy",
    ]
    assert result["tls"]["certificate_verified"] is True


def test_real_https_redirect_is_not_followed_and_skips_document_checks(tls_lab):
    base, ca = tls_lab
    result = scan(base + "/redirect", allow_local_https=True, ca_file=ca)
    assert result["status_code"] == 302
    assert result["response_context"]["kind"] == "redirect"
    assert result["findings"] == []
    assert result["methodology"]["requests_sent"] == 1


def test_real_https_html_still_detects_misconfigurations(tls_lab):
    base, ca = tls_lab
    result = scan(base + "/misconfigured", allow_local_https=True, ca_file=ca)
    assert result["response_context"] == {
        "kind": "html_document", "document_checks_applied": True,
    }
    assert "skipped_checks" not in result["methodology"]
    assert result["summary"]["total_findings"] == 3
