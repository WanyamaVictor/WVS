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
- `--workers` — concurrent request workers (default 8; forced to 1 when `--delay` is set)
- `--delay` — seconds between requests (be polite / avoid rate limits)
- `--timeout` — per-request timeout
- `--no-verify-tls` — disable TLS verification (for self-signed lab targets)

Path-based checks and the crawler run **concurrently** (thread pool), so scans
are much faster on remote targets. Set `--delay` to force polite, sequential mode.

## Web console

A SOC-style web UI is included (Flask): a dashboard, live streamed scans,
history, compare, and downloadable reports.

```bash
pip install -r requirements.txt
python -m web.app            # then open http://127.0.0.1:5000
```

- **Dashboard** — total scans, total vulnerabilities, average/peak risk, a
  severity bar chart, a risk-over-time chart, and recent scans.
- **Live scans** stream phase-by-phase progress over Server-Sent Events.
- **History** — every scan is saved to `reports/wvs_history.db` (SQLite).
- **Compare** two runs to see new / fixed / unchanged findings.
- **Export** any saved scan as **PDF**, **HTML**, or **JSON**.
- Findings table is searchable, severity-filterable, and sortable; each finding
  expands to show remediation + an OWASP/CWE reference.
- Reuses the CLI engine (`scanner.main.run_scan`), so results are identical.

### REST API

JSON endpoints for automation / CI:

| Method | Endpoint              | Purpose                              |
|--------|-----------------------|--------------------------------------|
| GET    | `/api/health`         | Liveness + available module list     |
| POST   | `/api/scan`           | Run a scan synchronously, return it   |
| GET    | `/api/scans`          | List saved scans                     |
| GET    | `/api/scans/<id>`     | Fetch one saved scan                 |

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://localhost","authorize":true,"modules":["headers","cookies"]}'
```

## Docker

```bash
docker compose up --build      # then open http://127.0.0.1:5000
```

Scan history persists to `./reports` via a bind mount. The container binds to
`0.0.0.0` inside Docker (`WVS_HOST` / `WVS_PORT` env vars).

## Architecture

```
scanner/
 ├── core/        # http_client (concurrent), crawler, payloads, analyzer,
 │                # models, remediation catalog, storage (SQLite history)
 ├── scanners/    # one module per vulnerability class
 ├── report/      # JSON / HTML / PDF report generation
 └── main.py      # CLI orchestration

web/
 ├── app.py       # Flask routes: dashboard, live scans, history, API, export
 ├── templates/   # base, dashboard, console, scan_view, history, compare
 └── static/      # SOC-themed CSS + vanilla JS (streaming, filters, sort)
```

Each scanner module returns a list of `Finding` objects (see
[scanner/core/models.py](scanner/core/models.py)); `main.py` aggregates them into
a `ScanResult` with an overall risk score.

## Roadmap

- Stored XSS checks (needs a deliberately-vulnerable test lab)
- Authenticated scanning (session/cookie support)
- Dashboard authentication (login / accounts / rate limiting) for non-local deploys
