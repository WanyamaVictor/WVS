"""CORS misconfiguration check (active, non-destructive).

Sends a request carrying a forged Origin header and inspects the
Access-Control-Allow-Origin (ACAO) / Access-Control-Allow-Credentials (ACAC)
response headers. Reflecting an arbitrary Origin -- especially together with
credentials -- lets a malicious site read authenticated responses.
"""

from __future__ import annotations

from ..core.http_client import HttpClient
from ..core.models import Finding, Severity

PROBE_ORIGIN = "https://wvs-evil.example"


def scan(client: HttpClient, target: str) -> list:
    findings: list = []
    resp = client.get(target, headers={"Origin": PROBE_ORIGIN})
    if resp is None:
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower() == "true"
    if not acao:
        return findings

    reflected = acao.strip() == PROBE_ORIGIN
    wildcard = acao.strip() == "*"
    null_origin = acao.strip().lower() == "null"

    if reflected and acac:
        sev, detail = Severity.HIGH, (
            "reflects an arbitrary Origin and allows credentials, so any site can "
            "read authenticated responses"
        )
    elif reflected or null_origin:
        sev, detail = Severity.MEDIUM, (
            "reflects an arbitrary/null Origin, exposing responses to untrusted sites"
        )
    elif wildcard:
        sev, detail = Severity.LOW, (
            "uses a wildcard '*' Access-Control-Allow-Origin"
        )
    else:
        return findings

    findings.append(
        Finding(
            type="CORS Misconfiguration",
            severity=sev,
            endpoint=resp.url,
            parameter="Access-Control-Allow-Origin",
            description=f"CORS policy {detail}.",
            evidence=(
                f"Origin: {PROBE_ORIGIN} -> Access-Control-Allow-Origin: {acao}"
                + (" (credentials allowed)" if acac else "")
            ),
        )
    )
    return findings
