"""Directory / sensitive-file discovery.

Probes a curated list of common sensitive paths and reports those that appear
to exist. Uses a baseline request to a random path to detect "soft 404" sites
that return 200 for everything, reducing false positives.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.http_client import HttpClient
from ..core.models import Finding, Severity
from ..core.payloads import COMMON_PATHS

# Paths whose exposure is more serious than a generic discovered directory.
HIGH_RISK = {".env", ".git/config", ".git/HEAD", "config.php", "config.bak",
             "db.sql", "database.sql", "phpinfo.php", "info.php"}


def _looks_like_soft_404(client: HttpClient, base: str) -> tuple[bool, int]:
    """Detect sites that return 200 for non-existent paths."""
    probe = urljoin(base.rstrip("/") + "/", "wvs-nonexistent-7f3a91")
    resp = client.get(probe, allow_redirects=False)
    if resp is None:
        return False, 0
    return resp.status_code == 200, len(resp.text or "")


def scan(client: HttpClient, target: str) -> list:
    findings: list = []
    base = target if target.endswith("/") else target + "/"

    soft_404, baseline_len = _looks_like_soft_404(client, base)

    for path in COMMON_PATHS:
        url = urljoin(base, path)
        resp = client.get(url, allow_redirects=False)
        if resp is None:
            continue

        status = resp.status_code
        exists = status in (200, 201, 301, 302, 401, 403)
        if not exists:
            continue

        # If the site soft-404s, only trust 200s that differ markedly in size,
        # or non-200 statuses (401/403/redirects are meaningful regardless).
        if soft_404 and status == 200:
            if abs(len(resp.text or "") - baseline_len) < 64:
                continue

        is_high = path in HIGH_RISK
        if status in (401, 403):
            severity = Severity.LOW
            note = "exists but access is restricted"
        elif is_high:
            severity = Severity.HIGH
            note = "sensitive file is publicly accessible"
        else:
            severity = Severity.MEDIUM if status == 200 else Severity.LOW
            note = "path is accessible"

        findings.append(
            Finding(
                type="Sensitive Path Exposure",
                severity=severity,
                endpoint=resp.url,
                description=f"/{path} {note} (HTTP {status}).",
                evidence=f"HTTP {status}",
            )
        )

    return findings
