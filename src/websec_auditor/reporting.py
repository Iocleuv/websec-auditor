"""Add auditable context to JSON reports without inventing a security score."""

from collections import Counter
from typing import Literal

ReportMode = Literal["offline_demo", "local_http_lab", "local_https_lab", "authorized_https"]

SEVERITIES = ("critical", "high", "medium", "low", "info")

GENERAL_LIMITATIONS = (
    "Checks inspect one HTTP response, not the whole application or its business logic.",
    "Findings are configuration observations, not confirmed exploitable vulnerabilities.",
    "Zero findings does not prove that a website is secure.",
)
TLS_LIMITATION = "Successful certificate verification is not a complete TLS configuration audit."
LOOPBACK_HSTS_LIMITATION = (
    "HSTS on an IP-literal lab URL is inspected as a header only; browsers do not enforce it for IP hosts."
)


def enrich_report(report: dict, *, mode: ReportMode) -> dict:
    """Return a report with consistent severity totals and explicit methodology.

    Do not copy raw header values or cookie values into the output. Reports
    retain the existing findings and TLS fields for backwards compatibility.
    """
    if mode not in ("offline_demo", "local_http_lab", "local_https_lab", "authorized_https"):
        raise ValueError(f"Unknown report mode: {mode}")

    findings = report["findings"]
    observed = Counter(item["severity"] for item in findings)
    by_severity = {severity: observed.pop(severity, 0) for severity in SEVERITIES}
    by_severity.update(sorted(observed.items()))  # Keep unknown severities visible.

    limitations = list(GENERAL_LIMITATIONS)
    if mode == "offline_demo":
        limitations.insert(0, "Entirely synthetic data: no HTTP requests were sent.")
    if mode in ("local_https_lab", "authorized_https"):
        limitations.append(TLS_LIMITATION)
    if mode == "local_https_lab":
        limitations.append(LOOPBACK_HSTS_LIMITATION)

    return {
        **report,
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
        },
        "methodology": {
            "mode": mode,
            "requests_sent": 0 if mode == "offline_demo" else 1,
            "limitations": limitations,
        },
    }
