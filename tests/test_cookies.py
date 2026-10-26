from websec_auditor.checks.cookies import check_cookies


def test_cookie_flags_missing():
    names = {f.check for f in check_cookies(["session=abc; Path=/"])}
    assert names == {"cookie-secure", "cookie-httponly", "cookie-samesite"}


def test_cookie_flags_present():
    assert check_cookies(["session=abc; Secure; HttpOnly; SameSite=Lax"]) == []
