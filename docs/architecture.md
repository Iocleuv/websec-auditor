# Architecture

- Production-intended CLI path: HTTPS URL (authorized operator) -> HTTPX single request (no redirects) -> headers/cookies checks -> JSON findings.
- Learning path: loopback HTTP lab server (127.0.0.1:8765, fixed profiles) -> auditor CLI with --lab -> JSON findings.
- Offline path: --demo -> synthetic response metadata -> checks -> JSON findings.

The local lab server is accessible only from the same machine (IPv4 loopback) and uses no real authentication secrets. Plain HTTP is intentionally used only for this introductory lab. HTTPS-specific header and cookie checks are not run against HTTP.

## Security limitations

- **Do not expose the CLI as a hosted multi-user scanner**: SSRF, DNS rebinding and egress controls are not implemented.
- Only assess assets you own or have explicit authorization to test.
- The --authorized flag does not verify ownership.
- --lab explicitly restricts HTTP to two local paths on 127.0.0.1:8765.
- Header presence is context-dependent and does not prove exploitability or effectiveness.
- TLS certificate expiry remains a standalone utility (not integrated).
- No crawling, port scanning or exploit payloads.
