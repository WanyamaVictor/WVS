"""Admin / login panel discovery.

A focused variant of the directory scan that looks specifically for
authentication and administration entry points, and tries to confirm them by
looking for login-form indicators in the response body.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.http_client import HttpClient
from ..core.models import Finding, Severity
from ..core.payloads import ADMIN_PATHS

LOGIN_HINTS = ("type=\"password\"", "type='password'", "name=\"password\"",
               "login", "sign in", "username", "admin")


def scan(client: HttpClient, target: str) -> list:
    findings: list = []
    base = target if target.endswith("/") else target + "/"

    urls = [urljoin(base, path) for path in ADMIN_PATHS]
    responses = client.get_many(urls, allow_redirects=True)

    for path, resp in zip(ADMIN_PATHS, responses):
        if resp is None or resp.status_code not in (200, 301, 302, 401, 403):
            continue

        body = (resp.text or "").lower()
        looks_like_login = any(hint in body for hint in LOGIN_HINTS)

        if resp.status_code in (401, 403):
            severity = Severity.LOW
            desc = f"Protected admin endpoint found at /{path} (HTTP {resp.status_code})."
        elif looks_like_login:
            severity = Severity.MEDIUM
            desc = f"Admin/login panel discovered at /{path} (login form detected)."
        elif resp.status_code == 200:
            severity = Severity.LOW
            desc = f"Possible admin endpoint at /{path} (HTTP 200)."
        else:
            continue

        findings.append(
            Finding(
                type="Admin Panel Exposure",
                severity=severity,
                endpoint=resp.url,
                description=desc,
                evidence=f"HTTP {resp.status_code}",
            )
        )

    return findings
