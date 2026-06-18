"""CSRF protection check (passive form analysis).

Examines crawled forms and flags state-changing (POST) forms that do not carry
a recognizable anti-CSRF token field. Without a synchronizer token, such forms
may be submittable cross-site. This is passive -- it only inspects the forms the
crawler already discovered and submits nothing.
"""

from __future__ import annotations

from ..core.models import Finding, Severity

# Substrings that commonly identify an anti-CSRF token input.
TOKEN_HINTS = ("csrf", "xsrf", "_token", "authenticity_token", "nonce",
               "__requestverificationtoken", "anti-forgery", "antiforgery")


def _has_csrf_token(form) -> bool:
    return any(any(h in name.lower() for h in TOKEN_HINTS) for name in form.inputs)


def scan(client, pages: list) -> list:
    findings: list = []
    seen: set = set()

    for page in pages:
        for form in page.forms:
            if form.method.lower() != "post":
                continue  # GET forms are not state-changing; skip to avoid noise
            key = form.action
            if key in seen:
                continue
            seen.add(key)
            if _has_csrf_token(form):
                continue
            findings.append(
                Finding(
                    type="Missing CSRF Protection",
                    severity=Severity.MEDIUM,
                    endpoint=form.action,
                    description=(
                        "POST form has no detectable anti-CSRF token field, so it "
                        "may be forgeable from a malicious cross-origin page."
                    ),
                    evidence=f"fields: {', '.join(form.inputs.keys()) or '(none)'}",
                )
            )

    return findings
