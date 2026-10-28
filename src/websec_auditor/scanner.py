"""Passive single-response checks with restricted local learning modes."""

import ssl
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from websec_auditor.checks.cookies import check_cookies
from websec_auditor.checks.headers import check_headers
from websec_auditor.lab import LAB_HOST, LAB_PATHS, LAB_PORT, LAB_TLS_PORT
from websec_auditor.reporting import enrich_report
from websec_auditor.response_context import classify_response


def scan(
    url: str,
    *,
    transport: httpx.BaseTransport | None = None,
    allow_local_http: bool = False,
    allow_local_https: bool = False,
    ca_file: str | Path | None = None,
) -> dict:
    """Perform a single request to an authorized HTTPS site or fixed local lab.

    IMPORTANT: not a hosted URL scanning service. No SSRF/DNS rebinding defense
    for arbitrary user-supplied URLs. Do not expose this function as an API.
    """
    if allow_local_http and allow_local_https:
        raise ValueError("Choose either --lab or --lab-https, not both.")

    parsed = urlsplit(url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL must have a host and must not contain credentials or a fragment.")

    is_regular_https = parsed.scheme == "https" and parsed.port in (None, 443)
    is_lab_http = (
        parsed.scheme == "http"
        and parsed.hostname == LAB_HOST
        and parsed.port == LAB_PORT
        and parsed.path in LAB_PATHS
        and not parsed.query
    )
    is_lab_https = (
        parsed.scheme == "https"
        and parsed.hostname == LAB_HOST
        and parsed.port == LAB_TLS_PORT
        and parsed.path in LAB_PATHS
        and not parsed.query
    )

    if allow_local_http:
        if not is_lab_http or ca_file is not None:
            raise ValueError("--lab permits only http://127.0.0.1:8765/{insecure,hardened,misconfigured}.")
    elif allow_local_https:
        if not is_lab_https or ca_file is None:
            raise ValueError("--lab-https needs a fixed https://127.0.0.1:8766/ lab URL and --ca-file.")
    elif not is_regular_https or ca_file is not None:
        raise ValueError("Use standard HTTPS for authorized targets; local modes require explicit flags.")

    is_https = is_regular_https or allow_local_https
    # Verification is NEVER disabled. Custom trust is limited to the fixed lab.
    verification: bool | ssl.SSLContext = True
    if allow_local_https:
        verification = ssl.create_default_context(cafile=str(ca_file))

    with httpx.Client(
        timeout=8.0, follow_redirects=False, trust_env=False,
        transport=transport, verify=verification,
    ) as client:
        response = client.get(url, headers={"User-Agent": "WebSecAuditor/0.2"})

    response_kind = classify_response(
        response.status_code, response.headers.get("content-type")
    )
    document_checks = response_kind == "html_document"
    findings = check_headers(
        dict(response.headers),
        https=is_https,
        document_checks=document_checks,
    )
    findings.extend(check_cookies(response.headers.get_list("set-cookie"), https=is_https))

    result = {
        "url": url,
        "status_code": response.status_code,
        "response_context": {
            "kind": response_kind,
            "document_checks_applied": document_checks,
        },
        "findings": [finding.to_dict() for finding in findings],
    }
    if is_https:
        # A successful HTTPS request implies the configured TLS verifier
        # accepted the certificate; this is not a full TLS configuration audit.
        result["tls"] = {
            "certificate_verified": True,
            "trust_source": "local_lab_ca" if allow_local_https else "system",
        }
    mode = (
        "local_http_lab" if allow_local_http else
        "local_https_lab" if allow_local_https else "authorized_https"
    )
    return enrich_report(result, mode=mode)
