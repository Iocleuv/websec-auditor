"""Prevent document-specific heuristics from flagging JSON and redirects."""

import httpx
import pytest

from websec_auditor.response_context import classify_response
from websec_auditor.scanner import scan


@pytest.mark.parametrize("status,content_type,expected", [
    (200, "text/html; charset=UTF-8", "html_document"),
    (200, "application/xhtml+xml", "html_document"),
    (200, "APPLICATION/JSON; charset=utf-8", "non_html"),
    (200, "image/svg+xml", "non_html"),
    (200, "text/plain", "non_html"),
    (200, None, "unknown_content_type"),
    (200, "  ", "unknown_content_type"),
    (204, "text/html", "no_body"),
    (302, "text/html", "redirect"),
    (304, "text/html", "redirect"),
    (404, "text/html", "non_success"),
])
def test_classification(status, content_type, expected):
    assert classify_response(status, content_type) == expected


@pytest.mark.parametrize("status,content_type,expected_kind", [
    (200, "application/json", "non_html"),
    (200, None, "unknown_content_type"),
    (302, "text/html", "redirect"),
    (404, "text/html", "non_success"),
    (204, "text/html", "no_body"),
])
def test_non_document_response_skips_html_only_checks(status, content_type, expected_kind):
    headers = {
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
        "Set-Cookie": "session=SECRET; Secure; HttpOnly; SameSite=Lax",
    }
    if content_type is not None:
        headers["Content-Type"] = content_type
    transport = httpx.MockTransport(
        lambda request: httpx.Response(status, headers=headers, content=b"", request=request)
    )
    result = scan("https://example.test/", transport=transport)
    assert result["response_context"]["kind"] == expected_kind
    assert result["response_context"]["document_checks_applied"] is False
    assert result["findings"] == []
    assert result["methodology"]["skipped_checks"] == [
        "content-security-policy", "referrer-policy",
    ]
    assert "SECRET" not in str(result)


def test_html_response_still_checks_all_security_headers():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, headers={"Content-Type": "text/html"}, request=request,
        )
    )
    result = scan("https://example.test/", transport=transport)
    assert result["response_context"]["kind"] == "html_document"
    assert result["summary"]["total_findings"] == 4
    assert "skipped_checks" not in result["methodology"]


def test_hsts_and_nosniff_still_checked_for_json():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, headers={"Content-Type": "application/json"}, request=request,
        )
    )
    result = scan("https://example.test/", transport=transport)
    assert {f["check"] for f in result["findings"]} == {
        "strict-transport-security", "x-content-type-options",
    }
