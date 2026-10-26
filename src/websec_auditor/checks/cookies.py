from http.cookies import SimpleCookie
from websec_auditor.models import Finding


def check_cookies(set_cookie_headers: list[str], *, https: bool = True) -> list[Finding]:
    findings = []
    for raw in set_cookie_headers:
        # Inspect attributes without storing cookie values in reports.
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            if https and not morsel["secure"]:
                findings.append(Finding("cookie-secure", "medium", f"Cookie {name} lacks Secure.", "Set Secure on HTTPS cookies."))
            if not morsel["httponly"]:
                findings.append(Finding("cookie-httponly", "low", f"Cookie {name} lacks HttpOnly; assess whether JavaScript access is required.", "Set HttpOnly for cookies not needed by JavaScript."))
            if not morsel["samesite"]:
                findings.append(Finding("cookie-samesite", "low", f"Cookie {name} has no explicit SameSite.", "Choose an appropriate SameSite policy."))
    return findings
