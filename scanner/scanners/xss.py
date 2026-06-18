"""Reflected XSS detection (non-destructive).

Strategy: inject uniquely-marked payloads into each parameter / form field and
check whether the payload is reflected verbatim (unescaped) in the response.
A verbatim reflection of script-bearing markup indicates the output is not
being properly encoded.

Injection points are probed concurrently and the injectable surface is capped
(see scanner.core.concurrency) to keep scans fast on form-heavy pages.
"""

from __future__ import annotations

from ..core.analyzer import reflects, snippet
from ..core.concurrency import (
    ACTIVE_BUDGET_SECONDS, MAX_FIELDS_PER_FORM, MAX_INJECTION_POINTS, budgeted_map,
)
from ..core.http_client import HttpClient
from ..core.models import Finding, Severity
from ..core.payloads import XSS_PAYLOADS


def _probe(client: HttpClient, point: dict):
    method, url, fields, param, kind = (
        point["method"], point["url"], point["data"], point["param"], point["kind"]
    )
    for payload in XSS_PAYLOADS:
        data = dict(fields)
        data[param] = payload
        resp = client.post(url, data=data) if method == "post" \
            else client.get(url, params=data)
        if resp is None:
            continue
        # A reflection only matters if the dangerous markup survived intact.
        if reflects(resp.text, payload):
            if kind == "query":
                desc = (f"Input from query parameter '{param}' is reflected in the "
                        f"response without proper output encoding, allowing script "
                        f"injection.")
            else:
                desc = (f"Input from form field '{param}' ({method.upper()}) is "
                        f"reflected without output encoding, allowing script injection.")
            return Finding(
                type="Reflected XSS",
                severity=Severity.HIGH,
                endpoint=url,
                parameter=param,
                payload=payload,
                description=desc,
                evidence=snippet(resp.text, payload),
            )
    return None


def _collect_points(pages: list) -> list:
    points: list = []
    seen: set = set()
    for page in pages:
        for param in page.params:
            key = ("GET", page.url, param)
            if key in seen:
                continue
            seen.add(key)
            points.append({"method": "get", "url": page.url,
                           "data": page.params, "param": param, "kind": "query"})
        for form in page.forms:
            for i, param in enumerate(form.inputs):
                if i >= MAX_FIELDS_PER_FORM:
                    break
                key = (form.method.upper(), form.action, param)
                if key in seen:
                    continue
                seen.add(key)
                points.append({"method": form.method, "url": form.action,
                               "data": form.inputs, "param": param, "kind": "form"})
    return points


def scan(client: HttpClient, pages: list) -> list:
    points = _collect_points(pages)
    if len(points) > MAX_INJECTION_POINTS:
        print(f"    [!] xss: capping injection points {len(points)} -> "
              f"{MAX_INJECTION_POINTS}")
        points = points[:MAX_INJECTION_POINTS]

    results, skipped = budgeted_map(
        lambda p: _probe(client, p),
        points,
        workers=getattr(client, "workers", 8),
        deadline_s=ACTIVE_BUDGET_SECONDS,
        sequential=getattr(client, "delay", 0) > 0,
    )
    if skipped:
        print(f"    [!] xss: time budget reached, skipped {skipped} injection "
              f"point(s) (raise with a faster target or fewer pages)")
    return [r for r in results if r]
