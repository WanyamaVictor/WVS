"""SQL injection detection (error-based, non-destructive).

Strategy: inject quote-breaking probes into each query parameter and form
field, then look for database error signatures in the response. This is a
detection technique only -- it never attempts to extract or modify data.
"""

from __future__ import annotations

from ..core.analyzer import find_sql_error, snippet
from ..core.crawler import Page
from ..core.http_client import HttpClient
from ..core.models import Finding, Severity
from ..core.payloads import SQLI_PAYLOADS


def _test_request(client: HttpClient, method: str, url: str, params=None, data=None):
    if method == "post":
        return client.post(url, data=data)
    return client.get(url, params=params)


def scan(client: HttpClient, pages: list) -> list:
    findings: list = []
    seen_endpoints: set = set()  # (url, param) pairs already flagged

    for page in pages:
        # --- Query string parameters ---
        for param, original in page.params.items():
            key = ("GET", page.url, param)
            if key in seen_endpoints:
                continue
            for payload in SQLI_PAYLOADS:
                injected = dict(page.params)
                injected[param] = original + payload
                resp = _test_request(client, "get", page.url, params=injected)
                if resp is None:
                    continue
                err = find_sql_error(resp.text)
                if err:
                    findings.append(
                        Finding(
                            type="SQL Injection",
                            severity=Severity.HIGH,
                            endpoint=page.url,
                            parameter=param,
                            payload=payload,
                            description=(
                                f"Database error triggered when injecting into "
                                f"query parameter '{param}', indicating the input "
                                f"is used in a SQL query without proper sanitization."
                            ),
                            evidence=snippet(resp.text, err),
                        )
                    )
                    seen_endpoints.add(key)
                    break

        # --- Form fields ---
        for form in page.forms:
            for param in form.inputs:
                key = (form.method.upper(), form.action, param)
                if key in seen_endpoints:
                    continue
                for payload in SQLI_PAYLOADS:
                    data = dict(form.inputs)
                    data[param] = (form.inputs.get(param) or "") + payload
                    if form.method == "post":
                        resp = _test_request(client, "post", form.action, data=data)
                    else:
                        resp = _test_request(client, "get", form.action, params=data)
                    if resp is None:
                        continue
                    err = find_sql_error(resp.text)
                    if err:
                        findings.append(
                            Finding(
                                type="SQL Injection",
                                severity=Severity.HIGH,
                                endpoint=form.action,
                                parameter=param,
                                payload=payload,
                                description=(
                                    f"Database error triggered when injecting into "
                                    f"form field '{param}' ({form.method.upper()}), "
                                    f"indicating unsafe use of the input in a SQL query."
                                ),
                                evidence=snippet(resp.text, err),
                            )
                        )
                        seen_endpoints.add(key)
                        break

    return findings
