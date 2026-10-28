"""Conservative cookie attribute checks; never record cookie values."""

from http.cookies import SimpleCookie

from websec_auditor.models import Finding


def _cookie_evidence(name: str, attribute: str) -> dict[str, str | int]:
    # The cookie name identifies the finding. Its VALUE is never added.
    return {
        "source": "set-cookie",
        "cookie_name": name,
        "attribute": attribute,
        "observed": "absent",
    }


def check_cookies(set_cookie_headers: list[str], *, https: bool = True) -> list[Finding]:
    findings = []
    for raw in set_cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            if https and not morsel["secure"]:
                findings.append(Finding(
                    "cookie-secure", "medium", f"Cookie {name} lacks Secure.",
                    "Set Secure on HTTPS cookies.",
                    evidence=_cookie_evidence(name, "Secure"),
                ))
            if not morsel["httponly"]:
                findings.append(Finding(
                    "cookie-httponly", "low",
                    f"Cookie {name} lacks HttpOnly; assess whether JavaScript access is required.",
                    "Set HttpOnly for cookies not needed by JavaScript.",
                    evidence=_cookie_evidence(name, "HttpOnly"),
                ))
            if not morsel["samesite"]:
                findings.append(Finding(
                    "cookie-samesite", "low",
                    f"Cookie {name} has no explicit SameSite.",
                    "Choose an appropriate SameSite policy.",
                    evidence=_cookie_evidence(name, "SameSite"),
                ))
    return findings
