"""TLS/SSL transport checks.

For HTTPS targets, inspects the certificate (validity, expiry) and the
negotiated protocol version. For plaintext HTTP targets, flags the lack of
transport encryption. Uses a direct socket so it does not depend on the
HTTP client.
"""

from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from ..core.http_client import HttpClient
from ..core.models import Finding, Severity

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
EXPIRY_WARN_DAYS = 15


def _finding(severity, endpoint, description, evidence="", parameter=""):
    return Finding(
        type="TLS/SSL Issue",
        severity=severity,
        endpoint=endpoint,
        description=description,
        evidence=evidence,
        parameter=parameter,
    )


def scan(client: HttpClient, target: str) -> list:
    findings: list = []
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        return findings

    if parsed.scheme == "http":
        findings.append(
            _finding(
                Severity.MEDIUM,
                target,
                "Site is served over plaintext HTTP; traffic can be read or "
                "modified in transit. Redirect to HTTPS and enable HSTS.",
                evidence="scheme: http",
            )
        )
        return findings

    if parsed.scheme != "https":
        return findings

    port = parsed.port or 443
    timeout = getattr(client, "timeout", 10.0)
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            _finding(
                Severity.MEDIUM,
                target,
                "Certificate failed validation (untrusted, self-signed, expired, "
                "or hostname mismatch). Browsers will warn users.",
                evidence=str(getattr(exc, "verify_message", "") or exc)[:160],
                parameter="certificate",
            )
        )
        return findings
    except (socket.timeout, OSError):
        return findings  # host unreachable on TLS port; nothing to assess

    # --- Protocol strength ---
    if proto in WEAK_PROTOCOLS:
        findings.append(
            _finding(
                Severity.MEDIUM,
                target,
                f"Server negotiated a weak/legacy protocol ({proto}). Disable "
                f"everything below TLS 1.2.",
                evidence=f"protocol: {proto}",
                parameter="protocol",
            )
        )

    # --- Certificate expiry ---
    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            expiry = ssl.cert_time_to_seconds(not_after)
            days_left = (expiry - time.time()) / 86400.0
            if days_left < 0:
                findings.append(
                    _finding(
                        Severity.HIGH,
                        target,
                        f"TLS certificate expired on {not_after}.",
                        evidence=f"notAfter: {not_after}",
                        parameter="certificate",
                    )
                )
            elif days_left < EXPIRY_WARN_DAYS:
                findings.append(
                    _finding(
                        Severity.MEDIUM,
                        target,
                        f"TLS certificate expires in {int(days_left)} day(s) "
                        f"({not_after}); renew it soon.",
                        evidence=f"notAfter: {not_after}",
                        parameter="certificate",
                    )
                )
        except ValueError:
            pass

    return findings
