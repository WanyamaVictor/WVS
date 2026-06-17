"""Reflected XSS detection (non-destructive).

Strategy: inject uniquely-marked payloads into each parameter / form field and
check whether the payload is reflected verbatim (unescaped) in the response.
A verbatim reflection of script-bearing markup indicates the output is not
being properly encoded.
"""

from __future__ import annotations

from ..core.analyzer import reflects, snippet
from ..core.http_client import HttpClient
from ..core.models import Finding, Severity
from ..core.payloads import XSS_PAYLOADS


def scan(client: HttpClient, pages: list) -> list:
    findings: list = []
    seen_endpoints: set = set()

    def probe(method: str, action: str, fields: dict, target_param: str, base_url: str):
        for payload in XSS_PAYLOADS:
            data = dict(fields)
            data[target_param] = payload
            if method == "post":
                resp = client.post(action, data=data)
            else:
                resp = client.get(action, params=data)
            if resp is None:
                continue
            # A reflection only matters if the dangerous markup survived intact.
            if reflects(resp.text, payload):
                return payload, snippet(resp.text, payload)
        return None

    for page in pages:
        for param in page.params:
            key = ("GET", page.url, param)
            if key in seen_endpoints:
                continue
            hit = probe("get", page.url, page.params, param, page.url)
            if hit:
                payload, evidence = hit
                findings.append(
                    Finding(
                        type="Reflected XSS",
                        severity=Severity.HIGH,
                        endpoint=page.url,
                        parameter=param,
                        payload=payload,
                        description=(
                            f"Input from query parameter '{param}' is reflected in "
                            f"the response without proper output encoding, allowing "
                            f"script injection."
                        ),
                        evidence=evidence,
                    )
                )
                seen_endpoints.add(key)

        for form in page.forms:
            for param in form.inputs:
                key = (form.method.upper(), form.action, param)
                if key in seen_endpoints:
                    continue
                hit = probe(form.method, form.action, form.inputs, param, form.action)
                if hit:
                    payload, evidence = hit
                    findings.append(
                        Finding(
                            type="Reflected XSS",
                            severity=Severity.HIGH,
                            endpoint=form.action,
                            parameter=param,
                            payload=payload,
                            description=(
                                f"Input from form field '{param}' "
                                f"({form.method.upper()}) is reflected without "
                                f"output encoding, allowing script injection."
                            ),
                            evidence=evidence,
                        )
                    )
                    seen_endpoints.add(key)

    return findings
