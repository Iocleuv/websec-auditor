"""Targeted, conservative HTTP security-header checks.

A finding is a configuration observation, NOT a proven exploitable flaw.
Only a limited subset of header semantics is supported.
"""

import re

from websec_auditor.models import Finding


# Browsers select the last *recognized* policy from comma-separated values.
KNOWN_REFERRER_POLICIES = frozenset({
    "no-referrer", "no-referrer-when-downgrade", "origin",
    "origin-when-cross-origin", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin", "unsafe-url",
})
MAX_AGE = re.compile(r'^max-age\s*=\s*(?:"(\d+)"|(\d+))$', re.IGNORECASE)


def _csp_allows_unsafe_eval(value: str) -> bool:
    """Inspect effective script-src, falling back to default-src.

    This is intentionally *not* a comprehensive CSP validator.
    """
    directives: dict[str, list[str]] = {}
    for raw in value.split(";"):
        tokens = raw.strip().lower().split()
        if tokens:
            # A duplicate directive does not override the first one.
            directives.setdefault(tokens[0], tokens[1:])
    script_sources = directives.get("script-src", directives.get("default-src", []))
    return "'unsafe-eval'" in script_sources


def _hsts_max_age(value: str) -> int | None:
    """Read max-age only when exactly one valid nonnegative directive exists."""
    directives = [part.strip() for part in value.split(";")]
    candidates = [part for part in directives if part.split("=", 1)[0].strip().lower() == "max-age"]
    if len(candidates) != 1:
        return None
    match = MAX_AGE.fullmatch(candidates[0])
    return int(match.group(1) or match.group(2)) if match else None


def _effective_referrer_policy(value: str) -> str | None:
    policies = [part.strip().lower() for part in value.split(",")]
    supported = [policy for policy in policies if policy in KNOWN_REFERRER_POLICIES]
    return supported[-1] if supported else None


def check_headers(headers: dict[str, str], *, https: bool = True) -> list[Finding]:
    normalized = {k.lower(): v for k, v in headers.items()}
    findings = []
    checks = {
        "content-security-policy": ("medium", "Consider a restrictive Content-Security-Policy."),
        "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("low", "Configure a suitable Referrer-Policy."),
    }
    if https:
        checks["strict-transport-security"] = (
            "medium", "Consider HSTS after checking subdomain compatibility."
        )

    for name, (severity, recommendation) in checks.items():
        if name not in normalized:
            findings.append(Finding(
                name, severity, f"Header {name} not present in response.", recommendation
            ))

    if "x-content-type-options" in normalized:
        if normalized["x-content-type-options"].strip().lower() != "nosniff":
            findings.append(Finding(
                "x-content-type-options-value", "low",
                "X-Content-Type-Options is not nosniff.", "Set nosniff."
            ))

    csp = normalized.get("content-security-policy")
    if csp and _csp_allows_unsafe_eval(csp):
        findings.append(Finding(
            "content-security-policy-unsafe-eval", "medium",
            "CSP permits JavaScript string evaluation with 'unsafe-eval'.",
            "Remove 'unsafe-eval' from effective script sources if the application permits."
        ))

    policy = normalized.get("referrer-policy")
    if policy is not None:
        selected = _effective_referrer_policy(policy)
        if selected == "unsafe-url":
            findings.append(Finding(
                "referrer-policy-unsafe-url", "low",
                "Referrer-Policy unsafe-url may disclose URL paths and query strings.",
                "Prefer strict-origin-when-cross-origin or a more restrictive policy."
            ))
        elif selected is None:
            findings.append(Finding(
                "referrer-policy-invalid", "low",
                "Referrer-Policy has no recognized value.",
                "Choose a supported Referrer-Policy value."
            ))

    if https and "strict-transport-security" in normalized:
        max_age = _hsts_max_age(normalized["strict-transport-security"])
        if max_age is None:
            findings.append(Finding(
                "strict-transport-security-invalid", "medium",
                "HSTS lacks a valid max-age directive.",
                "Set a valid nonnegative max-age and evaluate rollout compatibility."
            ))
        elif max_age == 0:
            findings.append(Finding(
                "strict-transport-security-disabled", "medium",
                "HSTS max-age=0 disables the policy in browsers that honor it.",
                "Choose a positive max-age when HSTS is appropriate."
            ))

    return findings
