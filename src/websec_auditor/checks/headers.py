from websec_auditor.models import Finding


def check_headers(headers: dict[str, str], *, https: bool = True) -> list[Finding]:
    normalized = {k.lower(): v for k, v in headers.items()}
    findings = []
    checks = {
        "content-security-policy": ("medium", "Consider a restrictive Content-Security-Policy."),
        "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("low", "Configure a suitable Referrer-Policy."),
    }
    if https:
        checks["strict-transport-security"] = ("medium", "Consider HSTS after checking subdomain compatibility.")
    for name, (severity, recommendation) in checks.items():
        if name not in normalized:
            findings.append(Finding(name, severity, f"Header {name} not present in response.", recommendation))
    if normalized.get("x-content-type-options", "").lower().strip() not in ("", "nosniff"):
        findings.append(Finding("x-content-type-options-value", "low", "X-Content-Type-Options is not nosniff.", "Set nosniff."))
    return findings
