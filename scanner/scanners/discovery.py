"""Resource discovery: robots.txt, sitemap, and security.txt (passive).

Fetches well-known resources to surface information exposure (paths an admin
tried to hide via robots.txt) and security-posture signals (presence of a
security.txt). Read-only GETs to standard locations.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.http_client import HttpClient
from ..core.models import Finding, Severity

MAX_DISALLOWED_SHOWN = 12


def _base(target: str) -> str:
    return target if target.endswith("/") else target + "/"


def _scan_robots(client: HttpClient, base: str) -> list:
    resp = client.get(urljoin(base, "robots.txt"), allow_redirects=False)
    if resp is None or resp.status_code != 200 or "text/html" in resp.headers.get("Content-Type", ""):
        return []
    disallowed = [
        line.split(":", 1)[1].strip()
        for line in (resp.text or "").splitlines()
        if line.strip().lower().startswith("disallow:")
        and line.split(":", 1)[1].strip() not in ("", "/")
    ]
    if not disallowed:
        return []
    shown = disallowed[:MAX_DISALLOWED_SHOWN]
    extra = "" if len(disallowed) <= MAX_DISALLOWED_SHOWN else f" (+{len(disallowed) - MAX_DISALLOWED_SHOWN} more)"
    return [
        Finding(
            type="Path Disclosure",
            severity=Severity.INFO,
            endpoint=resp.url,
            parameter="robots.txt",
            description=(
                "robots.txt lists Disallow paths that reveal potentially "
                "sensitive areas to anyone. robots.txt is not an access control."
            ),
            evidence=", ".join(shown) + extra,
        )
    ]


def _scan_security_txt(client: HttpClient, base: str) -> list:
    for path in (".well-known/security.txt", "security.txt"):
        resp = client.get(urljoin(base, path), allow_redirects=False)
        if resp is not None and resp.status_code == 200 \
                and "text/html" not in resp.headers.get("Content-Type", ""):
            return []  # present -- good, no finding
    return [
        Finding(
            type="Missing security.txt",
            severity=Severity.LOW,
            endpoint=urljoin(base, ".well-known/security.txt"),
            parameter="security.txt",
            description=(
                "No /.well-known/security.txt found. Publishing one gives "
                "researchers a clear, standard channel to report issues."
            ),
            evidence="HTTP 404",
        )
    ]


def scan(client: HttpClient, target: str) -> list:
    base = _base(target)
    findings: list = []
    findings.extend(_scan_robots(client, base))
    findings.extend(_scan_security_txt(client, base))
    return findings
