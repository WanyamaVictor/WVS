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
| `sqli`      | Error-based SQL injection detection                       | Active   |
| `xss`       | Reflected XSS detection (marker-based)                    | Active   |

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

- `--modules` — comma-separated: `headers,directory,admin,sqli,xss` or `all`
- `--max-pages` — crawler page limit (default 40)
- `--delay` — seconds between requests (be polite / avoid rate limits)
- `--timeout` — per-request timeout
- `--no-verify-tls` — disable TLS verification (for self-signed lab targets)

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

- Optional Laravel dashboard (scans + vulnerabilities tables, web UI)
- Stored XSS and CSRF checks
- Authenticated scanning (session/cookie support)
