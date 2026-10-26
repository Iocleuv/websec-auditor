# WebSec Auditor

An educational, passive HTTPS security configuration auditor for **owned or explicitly authorized** websites.

## Features (v0.1)
- Checks presence of selected HTTP security headers.
- Checks cookie attributes without reporting cookie values.
- Produces JSON findings with severity and remediation guidance.
- No redirects, crawling or exploit attempts.

## Install
```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
```

## Test
```bash
pytest -q
```

## Run
```bash
websec-auditor https://your-owned-domain.example --authorized
```

## Important limitations
Findings are configuration observations, **not** verified vulnerabilities. Some missing headers are acceptable depending on application context. This CLI MVP is **not safe to expose as a public scanning service** without robust SSRF/DNS rebinding defenses, DNS/IP egress policy, authorization verification and rate limiting. See `docs/architecture.md`.

## Roadmap
- Offline fixtures and richer tests
- Structured JSON reports and CI quality checks
- Safe TLS inspection and contextual scoring
- Explicit asset verification before any hosted deployment
