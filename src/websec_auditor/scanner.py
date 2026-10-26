from urllib.parse import urlsplit
import httpx
from websec_auditor.checks.headers import check_headers
from websec_auditor.checks.cookies import check_cookies


def scan(url: str) -> dict:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("MVP accepts only standard HTTPS URLs without credentials or custom ports.")
    # Deliberately no redirect following. Never expose this function as a public API
    # without DNS/IP egress controls to prevent SSRF and DNS rebinding.
    with httpx.Client(timeout=8.0, follow_redirects=False, trust_env=False) as client:
        response = client.get(url, headers={"User-Agent": "WebSecAuditor/0.1"})
    findings = check_headers(dict(response.headers))
    findings.extend(check_cookies(response.headers.get_list("set-cookie")))
    return {"url": url, "status_code": response.status_code, "findings": [f.to_dict() for f in findings]}
