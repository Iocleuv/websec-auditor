"""Single-request passive web security checks."""

from urllib.parse import urlsplit

import httpx

from websec_auditor.checks.cookies import check_cookies
from websec_auditor.checks.headers import check_headers
from websec_auditor.lab import LAB_HOST, LAB_PATHS, LAB_PORT


def scan(
    url: str,
    *,
    transport: httpx.BaseTransport | None = None,
    allow_local_http: bool = False,
) -> dict:
    """Inspect one HTTP response from an authorized target.

    Internet targets must use HTTPS on 443. Unencrypted HTTP is permitted only
    in explicitly enabled lab mode, on a fixed loopback host, port and path.

    This is a local CLI MVP; not hardened for untrusted URLs, SSRF or DNS
    rebinding. Do not expose it as a hosted web service.
    """
    parsed = urlsplit(url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL must have a host and must not contain credentials or a fragment.")

    is_https = parsed.scheme == "https" and parsed.port in (None, 443)
    is_lab_http = (
        allow_local_http
        and parsed.scheme == "http"
        and parsed.hostname == LAB_HOST
        and parsed.port == LAB_PORT
        and parsed.path in LAB_PATHS
        and not parsed.query
    )
    if not (is_https or is_lab_http):
        raise ValueError("Use standard HTTPS, or --lab with http://127.0.0.1:8765/{insecure,hardened}.")
    if allow_local_http and not is_lab_http:
        raise ValueError("--lab only allows the fixed 127.0.0.1 HTTP lab endpoint.")

    with httpx.Client(timeout=8.0, follow_redirects=False, trust_env=False, transport=transport) as client:
        response = client.get(url, headers={"User-Agent": "WebSecAuditor/0.1"})

    findings = check_headers(dict(response.headers), https=is_https)
    findings.extend(check_cookies(response.headers.get_list("set-cookie"), https=is_https))
    return {
        "url": url,
        "status_code": response.status_code,
        "findings": [finding.to_dict() for finding in findings],
    }
