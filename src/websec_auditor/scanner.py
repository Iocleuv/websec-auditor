"""Single-request passive web security checks."""

from urllib.parse import urlsplit

import httpx

from websec_auditor.checks.cookies import check_cookies
from websec_auditor.checks.headers import check_headers


def scan(url: str, *, transport: httpx.BaseTransport | None = None) -> dict:
    """Inspect an authorized HTTPS response; transport permits offline unit tests.

    This is a local CLI MVP, not a safe server-side URL fetcher. In particular it
    does not prevent SSRF or DNS rebinding if untrusted callers choose the URL.
    """
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
    ):
        raise ValueError("MVP accepts only standard HTTPS URLs without credentials or custom ports.")

    with httpx.Client(
        timeout=8.0,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        response = client.get(url, headers={"User-Agent": "WebSecAuditor/0.1"})

    findings = check_headers(dict(response.headers))
    findings.extend(check_cookies(response.headers.get_list("set-cookie")))
    return {
        "url": url,
        "status_code": response.status_code,
        "findings": [finding.to_dict() for finding in findings],
    }
