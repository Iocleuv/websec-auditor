import httpx
import pytest

from websec_auditor.scanner import scan


def test_scanner_analyzes_mock_response_without_network():
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "example.test"
        return httpx.Response(
            200,
            headers={"Set-Cookie": "sid=secret; Path=/"},
            request=request,
        )

    report = scan("https://example.test/", transport=httpx.MockTransport(respond))
    assert report["status_code"] == 200
    assert {finding["check"] for finding in report["findings"]} >= {
        "cookie-secure", "cookie-httponly", "cookie-samesite"
    }
    assert "secret" not in str(report)


def test_scanner_never_follows_redirects():
    requests = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://another.test/"}, request=request)

    report = scan("https://example.test/", transport=httpx.MockTransport(respond))
    assert report["status_code"] == 302
    assert len(requests) == 1


@pytest.mark.parametrize("url", ["http://example.test", "https://user:pass@example.test/", "https://example.test:8443/"])
def test_scanner_rejects_unsupported_urls(url):
    with pytest.raises(ValueError):
        scan(url, transport=httpx.MockTransport(lambda request: httpx.Response(200)))
