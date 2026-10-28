"""Conservative HTTP header checks with value-safe structured evidence.

Observations are configuration indicators, not proven exploitable weaknesses.
This is a deliberately limited subset of HTTP security header semantics.
"""

import re

from websec_auditor.models import Finding


KNOWN_REFERRER_POLICIES = frozenset({
    "no-referrer", "no-referrer-when-downgrade", "origin",
    "origin-when-cross-origin", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin", "unsafe-url",
})
MAX_AGE = re.compile(r'^max-age\s*=\s*(?:"(\d+)"|(\d+))$', re.IGNORECASE)


def _csp_unsafe_eval_directive(value: str) -> str | None:
    """Return the effective directive that allows 'unsafe-eval', if any."""
    directives: dict[str, list[str]] = {}
    for raw in value.split(";"):
        tokens = raw.strip().lower().split()
        if tokens:
            # Browsers ignore a repeated directive after its first occurrence.
            directives.setdefault(tokens[0], tokens[1:])

    directive = (
        "script-src" if "script-src" in directives else
        "default-src" if "default-src" in directives else None
    )
    if directive is not None and "'unsafe-eval'" in directives[directive]:
        return directive
    return None


def _csp_allows_unsafe_eval(value: str) -> bool:
    """Compatibility helper for the focused CSP heuristic."""
    return _csp_unsafe_eval_directive(value) is not None


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


def _header_evidence(name: str, **facts: str | int) -> dict[str, str | int]:
    """Only store allowlisted facts, never copy untrusted header contents."""
    return {"source": "response_header", "name": name, **facts}


def check_headers(
    headers: dict[str, str],
    *,
    https: bool = True,
    document_checks: bool = True,
) -> list[Finding]:
    """Inspect response headers; document-specific checks need HTML context."""

    normalized = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []
    checks = {
        "content-security-policy": ("medium", "Consider a restrictive Content-Security-Policy."),
        "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("low", "Configure a suitable Referrer-Policy."),
    }
    if not document_checks:
        checks.pop("content-security-policy")
        checks.pop("referrer-policy")
    if https:
        checks["strict-transport-security"] = (
            "medium", "Consider HSTS after checking subdomain compatibility."
        )

    for name, (severity, recommendation) in checks.items():
        if name not in normalized:
            findings.append(Finding(
                name, severity, f"Header {name} not present in response.", recommendation,
                evidence=_header_evidence(name, observed="absent"),
            ))

    if "x-content-type-options" in normalized:
        if normalized["x-content-type-options"].strip().lower() != "nosniff":
            findings.append(Finding(
                "x-content-type-options-value", "low",
                "X-Content-Type-Options is not nosniff.", "Set nosniff.",
                evidence=_header_evidence("x-content-type-options", observed="not_nosniff"),
            ))

    csp = normalized.get("content-security-policy")
    if csp and document_checks:
        directive = _csp_unsafe_eval_directive(csp)
        if directive is not None:
            findings.append(Finding(
                "content-security-policy-unsafe-eval", "medium",
                "CSP permits JavaScript string evaluation with 'unsafe-eval'.",
                "Remove 'unsafe-eval' from effective script sources if the application permits.",
                evidence=_header_evidence(
                    "content-security-policy",
                    effective_directive=directive,
                    matched_token="'unsafe-eval'",
                ),
            ))

    policy = normalized.get("referrer-policy")
    if policy is not None and document_checks:
        selected = _effective_referrer_policy(policy)
        if selected == "unsafe-url":
            findings.append(Finding(
                "referrer-policy-unsafe-url", "low",
                "Referrer-Policy unsafe-url may disclose URL paths and query strings.",
                "Prefer strict-origin-when-cross-origin or a more restrictive policy.",
                evidence=_header_evidence("referrer-policy", effective_policy="unsafe-url"),
            ))
        elif selected is None:
            findings.append(Finding(
                "referrer-policy-invalid", "low",
                "Referrer-Policy has no recognized value.",
                "Choose a supported Referrer-Policy value.",
                evidence=_header_evidence("referrer-policy", observed="no_recognized_policy"),
            ))

    if https and "strict-transport-security" in normalized:
        max_age = _hsts_max_age(normalized["strict-transport-security"])
        if max_age is None:
            findings.append(Finding(
                "strict-transport-security-invalid", "medium",
                "HSTS lacks a valid max-age directive.",
                "Set a valid nonnegative max-age and evaluate rollout compatibility.",
                evidence=_header_evidence(
                    "strict-transport-security", observed="invalid_or_missing_max_age"
                ),
            ))
        elif max_age == 0:
            findings.append(Finding(
                "strict-transport-security-disabled", "medium",
                "HSTS max-age=0 disables the policy in browsers that honor it.",
                "Choose a positive max-age when HSTS is appropriate.",
                evidence=_header_evidence("strict-transport-security", max_age_seconds=0),
            ))

    return findings
