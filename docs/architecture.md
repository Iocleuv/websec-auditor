# Architecture

WebSec Auditor has three execution paths:

1. **Offline demo**: synthetic headers/cookies -> checks -> JSON findings.
2. **Local HTTP lab**: fixed server on 127.0.0.1:8765 -> explicit --lab -> checks -> report.
3. **Local HTTPS lab**: fixed server on 127.0.0.1:8766, with local CA -> explicit --lab-https + --ca-file -> verified TLS connection -> checks -> report.

Authorized external HTTPS hosts can be analyzed with --authorized, only on standard 443. The CLI does not follow redirects. This is not safe as a publicly accessible, untrusted-URL scanner without network egress policy, asset verification and SSRF/DNS rebinding defenses.

## TLS learning lab

scripts/create_lab_certs.py requires the openssl executable and generates:
- Short-lived private CA, for this lab only.
- Server certificate signed by the local CA, with SAN IP:127.0.0.1.
- Private keys stored under .lab-certs/ (Git-ignored and user-restricted).

Server TLS minimum: TLS 1.2. Client validation: enabled, with an explicit trust root used **only for lab traffic**. No global CA trust installation and no disabling certificate verification.

The tls.certificate_verified field means the configured TLS validation succeeded for the connection. It is not a complete TLS configuration audit. Neither protocol enumeration nor detailed validity periods are reported yet. HSTS on an IP literal is not browser-enforced; checking its presence here is educational only.

## Known limits

- --authorized is an operator confirmation, **not** proof of domain ownership.
- Missing headers or cookie flags require contextual interpretation; no vulnerability exploitability is verified.
- The older certificate-expiry utility is not yet integrated into live response scanning.
- No crawling, port scanning, brute force, exploits or follow-redirects.
- **Do not run the lab servers as root or expose them to the network**.
