"""Evidence must be specific, actionable and free of secret header values."""

from websec_auditor.checks.cookies import check_cookies
from websec_auditor.checks.headers import check_headers
from websec_auditor.models import Finding


def test_optional_evidence_preserves_legacy_serialization():
    finding = Finding("example", "low", "detail", "fix")
    assert finding.to_dict() == {
        "check": "example",
        "severity": "low",
        "detail": "detail",
        "recommendation": "fix",
    }


def test_absent_header_has_explicit_evidence():
    findings = check_headers({})
    by_check = {finding.check: finding.to_dict() for finding in findings}
    assert by_check["content-security-policy"]["evidence"] == {
        "source": "response_header",
        "name": "content-security-policy",
        "observed": "absent",
    }


def test_csp_reports_effective_directive_only_not_raw_header():
    marker = "private-internal-host.example"
    csp = f"default-src {marker}; script-src 'self' 'unsafe-eval'"
    findings = check_headers({"Content-Security-Policy": csp})
    match = next(f.to_dict() for f in findings if f.check == "content-security-policy-unsafe-eval")
    assert match["evidence"] == {
        "source": "response_header",
        "name": "content-security-policy",
        "effective_directive": "script-src",
        "matched_token": "'unsafe-eval'",
    }
    assert marker not in str(match)


def test_csp_fallback_evidence_identifies_default_src():
    findings = check_headers({"Content-Security-Policy": "default-src 'unsafe-eval'"})
    match = next(f.to_dict() for f in findings if f.check == "content-security-policy-unsafe-eval")
    assert match["evidence"]["effective_directive"] == "default-src"


def test_hsts_zero_seconds_are_structured_not_copied():
    findings = check_headers({"Strict-Transport-Security": "max-age=0; includeSubDomains"})
    match = next(f.to_dict() for f in findings if f.check == "strict-transport-security-disabled")
    assert match["evidence"] == {
        "source": "response_header",
        "name": "strict-transport-security",
        "max_age_seconds": 0,
    }


def test_bad_referrer_policy_is_explicit():
    findings = check_headers({"Referrer-Policy": "no-referrer, unsafe-url"})
    match = next(f.to_dict() for f in findings if f.check == "referrer-policy-unsafe-url")
    assert match["evidence"]["effective_policy"] == "unsafe-url"


def test_invalid_x_content_type_does_not_echo_untrusted_value():
    secret = "sensitive-internal-token"
    findings = check_headers({"X-Content-Type-Options": secret})
    match = next(f.to_dict() for f in findings if f.check == "x-content-type-options-value")
    assert match["evidence"]["observed"] == "not_nosniff"
    assert secret not in str(match)


def test_cookie_value_never_appears_in_evidence_or_findings():
    secret = "SESSION_SECRET_123456"
    findings = check_cookies([f"session={secret}; Path=/"])
    result = [f.to_dict() for f in findings]
    assert len(result) == 3
    assert secret not in str(result)
    assert {item["evidence"]["attribute"] for item in result} == {
        "Secure", "HttpOnly", "SameSite"
    }
    assert all(item["evidence"]["cookie_name"] == "session" for item in result)


def test_http_does_not_claim_missing_secure_cookie():
    findings = check_cookies(["session=hidden; Path=/"], https=False)
    assert "cookie-secure" not in {f.check for f in findings}
