from websec_auditor.checks.headers import check_headers


def test_missing_headers_reported():
    names = {f.check for f in check_headers({})}
    assert "content-security-policy" in names
    assert "strict-transport-security" in names


def test_present_headers_not_reported():
    headers = {"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Strict-Transport-Security": "max-age=31536000"}
    assert check_headers(headers) == []
