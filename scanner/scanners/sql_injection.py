"""SQL injection detection (error-based, non-destructive).

Strategy: inject quote-breaking probes into each query parameter and form
field, then look for database error signatures in the response. This is a
detection technique only -- it never attempts to extract or modify data.

Injection points are probed concurrently (thread pool) and the injectable
surface is capped, so a page with hundreds of form fields can't explode into
thousands of serial requests.
"""

from __future__ import annotations

from ..core.analyzer import find_sql_error, snippet
from ..core.concurrency import (
    ACTIVE_BUDGET_SECONDS, MAX_FIELDS_PER_FORM, MAX_INJECTION_POINTS, budgeted_map,
)
from ..core.http_client import HttpClient
from ..core.models import Finding, Severity
from ..core.payloads import SQLI_PAYLOADS


def _probe(client: HttpClient, point: dict):
    """Try each payload against one injection point; return a Finding or None."""
    method, url, data, param, kind = (
        point["method"], point["url"], point["data"], point["param"], point["kind"]
    )
    for payload in SQLI_PAYLOADS:
        injected = dict(data)
        injected[param] = (data.get(param) or "") + payload
        resp = client.post(url, data=injected) if method == "post" \
            else client.get(url, params=injected)
        if resp is None:
            continue
        err = find_sql_error(resp.text)
        if err:
            if kind == "query":
                desc = (f"Database error triggered when injecting into query "
                        f"parameter '{param}', indicating the input is used in a "
                        f"SQL query without proper sanitization.")
            else:
                desc = (f"Database error triggered when injecting into form field "
                        f"'{param}' ({method.upper()}), indicating unsafe use of "
                        f"the input in a SQL query.")
            return Finding(
                type="SQL Injection",
                severity=Severity.HIGH,
                endpoint=url,
                parameter=param,
                payload=payload,
                description=desc,
                evidence=snippet(resp.text, err),
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
        print(f"    [!] sqli: capping injection points {len(points)} -> "
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
        print(f"    [!] sqli: time budget reached, skipped {skipped} injection "
              f"point(s) (raise with a faster target or fewer pages)")
    return [r for r in results if r]
