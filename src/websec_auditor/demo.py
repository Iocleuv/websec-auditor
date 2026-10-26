"""Offline demonstration: synthetic response, no network calls."""

from websec_auditor.checks.cookies import check_cookies
from websec_auditor.checks.headers import check_headers


def demo_report() -> dict:
    """Return reproducible example findings for training and portfolio demos."""
    headers = {
        "content-type": "text/html; charset=utf-8",
        "server": "demo-server",
    }
    cookie_headers = ["session=REDACTED; Path=/"]
    findings = check_headers(headers)
    findings.extend(check_cookies(cookie_headers))
    return {
        "url": "https://demo.example.invalid/",
        "status_code": 200,
        "demo": True,
        "note": "Synthetic sample. No remote site was scanned.",
        "findings": [finding.to_dict() for finding in findings],
    }
