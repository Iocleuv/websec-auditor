# WebSec Auditor

A small, educational **passive web security configuration auditor** for sites you own or have explicit authorization to assess. Built with Python and HTTPX.

## Features (v0.2 candidate)

- Checks missing HTTP security headers and selected values.
- Checks common cookie security attributes without logging cookie values.
- Generates structured JSON findings and recommendations.
- Includes a **fully offline demo mode** and unit tests with HTTPX MockTransport.
- Does not follow HTTP redirects, crawl sites or send exploit payloads.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
```

## Offline demo (recommended first run)

```bash
websec-auditor --demo
websec-auditor --demo --output report.json
```

The demo uses **synthetic data**, makes no network requests, and is safe to use as a portfolio preview.

## Authorized scan

```bash
websec-auditor https://your-owned-domain.example --authorized --output report.json
```

A missing header or cookie flag is an observation requiring context, not proof of an exploitable vulnerability. The live scanner makes one HTTPS request and does not follow redirects.

## Tests

```bash
python -m pytest -q
```

## Scope and safety

**Never expose this CLI implementation as a public URL-scanning API.** It does not prevent SSRF, DNS rebinding, internal service access or other untrusted-URL issues. A production hosted service requires verified domain ownership, IP/DNS egress controls and rate limits. The `--authorized` option is a statement by the operator, **not** ownership verification.

See [architecture](docs/architecture.md) for limitations and planned improvements.
