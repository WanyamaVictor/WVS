# WVS — Web Vulnerability Scanner

A mini OWASP-style web vulnerability scanner written in Python. It crawls a
target, probes for common issues, and produces a risk-scored report.

> ⚠️ **Authorized use only.** This tool sends test payloads to a target. Only
> scan systems you own or have **explicit written permission** to test.
> Unauthorized scanning may be illegal. Payloads are detection-only and
> non-destructive by design.

## Features / Modules

| Module      | What it does                                              | Type     |
|-------------|-----------------------------------------------------------|----------|
| `headers`   | Flags missing/weak security headers (CSP, HSTS, …)        | Passive  |
| `directory` | Probes for sensitive paths (`/.env`, `/config`, …)        | Active   |
| `admin`     | Discovers admin/login panels                              | Active   |
| `cookies`   | Checks Set-Cookie for HttpOnly / Secure / SameSite        | Passive  |
| `cors`      | Detects permissive CORS (Origin reflection, credentials)  | Active   |
| `tls`       | Certificate expiry, weak protocol, plaintext HTTP         | Passive  |
| `discovery` | robots.txt path disclosure, missing security.txt          | Passive  |
| `sqli`      | Error-based SQL injection detection                       | Active   |
| `xss`       | Reflected XSS detection (marker-based)                    | Active   |
| `redirect`  | Open-redirect detection on redirect-style parameters      | Active   |
| `csrf`      | Flags POST forms with no anti-CSRF token                  | Passive  |

Every finding now carries **remediation guidance** and an **OWASP/CWE reference**
(see [scanner/core/remediation.py](scanner/core/remediation.py)).

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Full scan (all modules), with authorization confirmation
python -m scanner.main https://your-target.example --authorize

# Only run safe/passive checks
python -m scanner.main https://your-target.example --authorize --modules headers,directory

# Save reports
python -m scanner.main https://your-target.example --authorize \
    --json reports/scan.json --html reports/scan.html
```

### Useful flags

- `--modules` — comma-separated: `headers,directory,admin,cookies,cors,tls,discovery,sqli,xss,redirect,csrf` or `all`
- `--max-pages` — crawler page limit (default 40)
- `--delay` — seconds between requests (be polite / avoid rate limits)
- `--timeout` — per-request timeout
- `--no-verify-tls` — disable TLS verification (for self-signed lab targets)

## Web console

A SOC-style web UI is included (Flask). It runs scans live (streamed progress),
stores every run, and lets you browse history, compare two runs, and export
reports.

```bash
pip install -r requirements.txt
python -m web.app            # then open http://127.0.0.1:5000
```

- **Live scans** stream phase-by-phase progress over Server-Sent Events.
- **History** — every scan is saved to `reports/wvs_history.db` (SQLite).
- **Compare** two runs to see new / fixed / unchanged findings.
- **Export** any saved scan as JSON or HTML (or print to PDF from the browser).
- Reuses the CLI engine (`scanner.main.run_scan`), so results are identical.

## Architecture

```
scanner/
 ├── core/        # http_client, crawler, payloads, analyzer, models
 ├── scanners/    # one module per vulnerability class
 ├── report/      # JSON + HTML report generation
 └── main.py      # CLI orchestration
```

Each scanner module returns a list of `Finding` objects (see
[scanner/core/models.py](scanner/core/models.py)); `main.py` aggregates them into
a `ScanResult` with an overall risk score.

## Roadmap

- Stored XSS checks
- Authenticated scanning (session/cookie support)
- Server-side PDF report generation
