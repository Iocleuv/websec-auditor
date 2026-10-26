# Architecture

CLI -> scanner (single HTTPS request, no redirects) -> checks (headers/cookies) -> JSON findings.

## Security limitations

- CLI-only MVP. Do not expose as a hosted multi-user scanner: SSRF, DNS rebinding and egress protections are not implemented.
- Only scan owned or explicitly authorized assets.
- Missing headers are context-dependent indicators, not proven exploitable vulnerabilities.
- TLS expiry checker is an isolated utility, not yet integrated with the scanner.
- No crawling, port scanning or exploit payloads.
