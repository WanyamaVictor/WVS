"""Cookie security-attribute checks (passive).

Inspects Set-Cookie headers for the Secure, HttpOnly and SameSite attributes.
Missing flags expose session cookies to theft (XSS), transport interception, or
CSRF. Completely passive -- it only reads response headers.
"""

from __future__ import annotations

from ..core.http_client import HttpClient
from ..core.models import Finding, Severity


def _cookie_name(set_cookie: str) -> str:
    return set_cookie.split("=", 1)[0].strip() if set_cookie else "cookie"


def _raw_cookies(resp) -> list:
    """Best-effort list of individual Set-Cookie header values (handles test doubles)."""
    cookies = getattr(resp, "set_cookie", None)
    if cookies:
        return list(cookies)
    single = resp.headers.get("Set-Cookie") or resp.headers.get("set-cookie")
    return [single] if single else []


def scan(client: HttpClient, target: str) -> list:
    findings: list = []
    resp = client.get(target)
    if resp is None:
        return findings

    is_https = (resp.url or target).lower().startswith("https://")

    for raw in _raw_cookies(resp):
        attrs = raw.lower()
        name = _cookie_name(raw)
        missing = []
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "samesite" not in attrs:
            missing.append("SameSite")

        if not missing:
            continue

        # HttpOnly/Secure absence is the most impactful (token theft / interception).
        severity = Severity.MEDIUM if ("HttpOnly" in missing or "Secure" in missing) else Severity.LOW
        findings.append(
            Finding(
                type="Insecure Cookie",
                severity=severity,
                endpoint=resp.url,
                parameter=name,
                description=(
                    f"Cookie '{name}' is set without the "
                    f"{', '.join(missing)} attribute(s), weakening its protection."
                ),
                evidence=raw.strip()[:160],
            )
        )

    return findings
