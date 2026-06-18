"""Open-redirect detection (active, non-destructive).

Injects an external URL into redirect-style parameters and checks whether the
server issues a 3xx whose Location points at the attacker-controlled host. Only
a benign external marker host is used -- nothing is followed or exfiltrated.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..core.concurrency import budgeted_map
from ..core.http_client import HttpClient
from ..core.models import Finding, Severity

PROBE_HOST = "wvs-redirect.example"
PROBE_URL = f"https://{PROBE_HOST}/"

# Parameter names commonly used to drive redirects.
COMMON_REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
    "returnUrl", "return_url", "dest", "destination", "continue", "goto",
    "out", "u", "r",
]


def _is_external_redirect(resp) -> bool:
    if resp is None or resp.status_code not in (301, 302, 303, 307, 308):
        return False
    location = resp.headers.get("Location") or resp.headers.get("location") or ""
    if not location:
        return False
    # Match the probe host whether the value is absolute or scheme-relative.
    netloc = urlparse(location if "//" in location else "//" + location).netloc
    return PROBE_HOST in netloc or location.startswith(PROBE_URL)


def _probe(client: HttpClient, url: str, params: dict, param: str):
    injected = dict(params)
    injected[param] = PROBE_URL
    resp = client.get(url, params=injected, allow_redirects=False)
    if _is_external_redirect(resp):
        location = resp.headers.get("Location") or resp.headers.get("location") or ""
        return Finding(
            type="Open Redirect",
            severity=Severity.MEDIUM,
            endpoint=url,
            parameter=param,
            payload=PROBE_URL,
            description=(
                f"Parameter '{param}' controls the redirect target; supplying an "
                f"external URL redirects the user off-site, enabling phishing."
            ),
            evidence=f"HTTP {resp.status_code} -> Location: {location}",
        )
    return None


def scan(client: HttpClient, pages: list) -> list:
    seen: set = set()
    probes: list = []

    for i, page in enumerate(pages):
        # Real parameters discovered on the page.
        candidates = set(page.params.keys())
        # On the entry page also try well-known redirect parameter names.
        if i == 0:
            candidates.update(COMMON_REDIRECT_PARAMS)

        for param in candidates:
            key = (page.url, param)
            if key in seen:
                continue
            seen.add(key)
            probes.append((page.url, page.params, param))

    results, _ = budgeted_map(
        lambda t: _probe(client, t[0], t[1], t[2]),
        probes,
        workers=getattr(client, "workers", 8),
        deadline_s=12.0,
        sequential=getattr(client, "delay", 0) > 0,
    )
    return [r for r in results if r]
