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


## Real local HTTP lab

First, start a real **loopback-only** web server in terminal A:

~~~bash
websec-auditor --lab-server
~~~

Then scan each configuration in terminal B:

~~~bash
websec-auditor http://127.0.0.1:8765/insecure --lab --output insecure-real.json
websec-auditor http://127.0.0.1:8765/hardened --lab --output hardened-real.json
~~~

Expected results: five findings for the insecure HTTP profile; zero for the hardened HTTP profile. Unlike the offline demo, these are real HTTP requests to a local lab server. HTTPS-only checks are intentionally skipped because this lab runs HTTP on loopback.

Read [Laboratorio 02 (español)](docs/learning-02-local-http-lab.md) for instructions, limits and explanations.


## Local HTTPS lab (real TLS)

Generate a **local-only** CA and server certificate using OpenSSL:

~~~bash
python scripts/create_lab_certs.py
~~~

Start the HTTPS server in terminal A:

~~~bash
websec-auditor --lab-https-server --cert-file .lab-certs/server.crt --key-file .lab-certs/server.key
~~~

Run two HTTPS scans in terminal B (certificate verification remains enabled):

~~~bash
websec-auditor https://127.0.0.1:8766/insecure --lab-https --ca-file .lab-certs/ca.crt --output insecure-https.json
websec-auditor https://127.0.0.1:8766/hardened --lab-https --ca-file .lab-certs/ca.crt --output hardened-https.json
~~~

Expected: 7 findings vs 0 for the current checks. The CA is trusted only by this command, never globally. See [Laboratorio 03: HTTPS (español)](docs/learning-03-local-https-lab.md). Do not deploy this training code as a public service.


## Security header value validation

A third local profile contains security headers that are *present* but weakly
configured. Once you update the app, restart the HTTPS lab server and run:

~~~bash
websec-auditor https://127.0.0.1:8766/misconfigured --lab-https \
  --ca-file .lab-certs/ca.crt --output misconfigured-https.json
~~~

Current expected findings (3): CSP 'unsafe-eval', Referrer-Policy unsafe-url,
HSTS max-age=0. This is an intentionally narrow set of heuristic
observations, not a comprehensive CSP/HSTS validator.

See [Laboratorio 04 (español)](docs/learning-04-header-values.md).

## Report quality

All JSON reports now include a simple, deterministic `summary` with a finding
count and severity totals, plus a `methodology` object describing what was
actually tested and what the results **do not** prove.

For example, the HTTPS `/misconfigured` lab returns three observations (two
medium, one low), while `/hardened` returns zero. This is **not** a security
score or proof that the application is safe.

The reporting helper does not include raw cookie values or HTTP headers in
its output. For further details see
[Laboratorio 05 (español)](docs/learning-05-reports.md).

## Sanitized evidence per finding

Findings now include optional structured `evidence` explaining **what**
the rule observed without exporting raw cookie values or full response
headers. This allows report consumers to distinguish an absent header
from an explicitly weak directive. Finding counts and severities are
unchanged, and existing JSON fields remain compatible.

See [Laboratorio 06: evidencias (español)](docs/learning-06-finding-evidence.md).
