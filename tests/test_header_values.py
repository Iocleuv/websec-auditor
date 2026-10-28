"""Focused tests for security header *values*, not just presence."""

import pytest

from websec_auditor.checks.headers import check_headers


BASE = {
    "Content-Security-Policy": "default-src 'self'; object-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


def names(**replacements):
    headers = {**BASE, **replacements}
    return {finding.check for finding in check_headers(headers)}


def test_good_header_values_have_no_observations():
    assert names() == set()


def test_unsafe_eval_in_effective_script_src_is_reported():
    assert "content-security-policy-unsafe-eval" in names(
        **{"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-eval'"}
    )


def test_unsafe_eval_in_default_src_is_reported_when_script_src_absent():
    assert "content-security-policy-unsafe-eval" in names(
        **{"Content-Security-Policy": "default-src 'self' 'unsafe-eval'"}
    )


def test_script_src_overrides_default_src_for_eval():
    assert "content-security-policy-unsafe-eval" not in names(
        **{"Content-Security-Policy": "default-src 'unsafe-eval'; script-src 'self'"}
    )


def test_other_csp_directives_do_not_trigger_eval_check():
    assert "content-security-policy-unsafe-eval" not in names(
        **{"Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'"}
    )


def test_first_duplicate_csp_directive_takes_precedence():
    assert "content-security-policy-unsafe-eval" in names(
        **{"Content-Security-Policy": "script-src 'unsafe-eval'; script-src 'self'"}
    )


@pytest.mark.parametrize("policy,flag", [
    ("unsafe-url", True),
    ("no-referrer, unsafe-url", True),
    ("unsafe-url, no-referrer", False),
    ("unsafe-url, unknown-policy", True),
    ("unknown-policy", False),
    ("same-origin", False),
])
def test_referrer_policy_uses_last_supported_value(policy, flag):
    report = names(**{"Referrer-Policy": policy})
    assert ("referrer-policy-unsafe-url" in report) is flag
    if policy == "unknown-policy":
        assert "referrer-policy-invalid" in report


@pytest.mark.parametrize("hsts,expected", [
    ("max-age=0", "strict-transport-security-disabled"),
    ('max-age="0"; includeSubDomains', "strict-transport-security-disabled"),
    ("max-age=31536000", None),
    ("max-age=abc", "strict-transport-security-invalid"),
    ("includeSubDomains", "strict-transport-security-invalid"),
    ("max-age=123; max-age=0", "strict-transport-security-invalid"),
    ("max-age=-1", "strict-transport-security-invalid"),
])
def test_hsts_value_validation(hsts, expected):
    result = names(**{"Strict-Transport-Security": hsts})
    if expected:
        assert expected in result
    else:
        assert not {x for x in result if x.startswith("strict-transport-security-")}


def test_hsts_not_checked_on_plain_http():
    headers = {**BASE, "Strict-Transport-Security": "max-age=0"}
    report = {finding.check for finding in check_headers(headers, https=False)}
    assert not {x for x in report if x.startswith("strict-transport-security")}


def test_x_content_type_options_value_still_checked():
    assert "x-content-type-options-value" in names(
        **{"X-Content-Type-Options": "invalid"}
    )


def test_missing_headers_are_still_reported():
    report = {finding.check for finding in check_headers({})}
    assert report == {
        "content-security-policy", "x-content-type-options",
        "referrer-policy", "strict-transport-security",
    }
