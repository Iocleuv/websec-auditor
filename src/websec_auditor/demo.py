"""Offline security-header and cookie examples; no network traffic."""

from websec_auditor.checks.cookies import check_cookies
from websec_auditor.checks.headers import check_headers
from websec_auditor.reporting import enrich_report


def demo_report(profile: str = "insecure") -> dict:
    """Build reproducible example findings from synthetic HTTP metadata."""
    if profile not in {"insecure", "hardened"}:
        raise ValueError("Demo profile must be 'insecure' or 'hardened'.")

    if profile == "insecure":
        headers = {"content-type": "text/html; charset=utf-8", "server": "demo-server"}
        cookies = ["session=REDACTED; Path=/"]
    else:
        headers = {
            "content-type": "text/html; charset=utf-8",
            "content-security-policy": "default-src 'self'; object-src 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "strict-transport-security": "max-age=31536000",
        }
        cookies = ["session=REDACTED; Path=/; Secure; HttpOnly; SameSite=Lax"]

    findings = check_headers(headers)
    findings.extend(check_cookies(cookies))
    return enrich_report({
        "url": "https://demo.example.invalid/",
        "status_code": 200,
        "demo": True,
        "profile": profile,
        "note": "Synthetic sample. No remote site was scanned. No findings does not mean secure.",
        "findings": [finding.to_dict() for finding in findings],
    }, mode="offline_demo")
