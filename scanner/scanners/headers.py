"""Security header checks (passive, no payloads).

Inspects response headers of the target for the presence and sanity of common
security headers. This module is completely passive and safe.
"""

from __future__ import annotations

from ..core.http_client import HttpClient
from ..core.models import Finding, Severity

# header (lowercased) -> (severity, human description when missing)
EXPECTED_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Content-Security-Policy is missing; mitigates XSS and data injection.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "X-Frame-Options is missing; protects against clickjacking.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Strict-Transport-Security (HSTS) is missing; enforces HTTPS.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options is missing; should be 'nosniff'.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Referrer-Policy is missing; controls referrer leakage.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "Permissions-Policy is missing; restricts powerful browser features.",
    ),
}


def scan(client: HttpClient, target: str) -> list:
    findings: list = []
    resp = client.get(target)
    if resp is None:
        return findings

    present = {k.lower(): v for k, v in resp.headers.items()}

    for header, (severity, description) in EXPECTED_HEADERS.items():
        if header not in present:
            findings.append(
                Finding(
                    type="Missing Security Header",
                    severity=severity,
                    endpoint=resp.url,
                    parameter=header,
                    description=description,
                )
            )

    # Information-disclosure headers that should ideally be removed.
    for leaky in ("server", "x-powered-by"):
        if leaky in present and present[leaky]:
            findings.append(
                Finding(
                    type="Information Disclosure",
                    severity=Severity.INFO,
                    endpoint=resp.url,
                    parameter=leaky,
                    description=(
                        f"Response exposes '{leaky}: {present[leaky]}', revealing "
                        f"server/technology details useful to an attacker."
                    ),
                    evidence=f"{leaky}: {present[leaky]}",
                )
            )

    # HSTS sanity check when present.
    hsts = present.get("strict-transport-security", "")
    if hsts and "max-age=0" in hsts.replace(" ", ""):
        findings.append(
            Finding(
                type="Weak Security Header",
                severity=Severity.LOW,
                endpoint=resp.url,
                parameter="strict-transport-security",
                description="HSTS is present but disabled (max-age=0).",
                evidence=hsts,
            )
        )

    return findings
