"""Remediation intelligence: fix guidance + OWASP/CWE references per finding type.

Scanner modules only need to set a finding's ``type``; this catalog fills in the
``remediation`` and ``reference`` fields afterwards via :func:`enrich`. Keeping
the guidance in one place means every module (and the web UI) stays consistent,
and adding advice for a new finding type is a one-line change here.

``reference`` is stored as ``"LABEL | URL"`` so the UI can render a link.
"""

from __future__ import annotations

# type -> (remediation, reference_label, reference_url)
CATALOG: dict[str, tuple[str, str, str]] = {
    "Missing Security Header": (
        "Add the missing response header at the web server, reverse proxy, or "
        "application layer. Send a strong Content-Security-Policy, "
        "Strict-Transport-Security, and X-Frame-Options on every response.",
        "OWASP A05:2021 Security Misconfiguration",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ),
    "Weak Security Header": (
        "The header is present but its value is ineffective. Set a meaningful "
        "policy (e.g. HSTS max-age of at least 15552000 with includeSubDomains).",
        "OWASP Secure Headers Project",
        "https://owasp.org/www-project-secure-headers/",
    ),
    "Information Disclosure": (
        "Suppress version/technology banners. Remove or mask Server and "
        "X-Powered-By headers and disable verbose error output in production.",
        "CWE-200 Exposure of Sensitive Information",
        "https://cwe.mitre.org/data/definitions/200.html",
    ),
    "Sensitive Path Exposure": (
        "Remove the file from the web root or block access to it. Never deploy "
        "VCS metadata, backups, .env files, or DB dumps to a public server; "
        "deny dotfiles and known sensitive paths at the web-server level.",
        "OWASP A01:2021 Broken Access Control",
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ),
    "Admin Panel Exposure": (
        "Restrict administrative interfaces to trusted networks/VPN or IP allow "
        "lists, enforce strong authentication and MFA, and avoid predictable "
        "URLs as the only defense.",
        "OWASP A07:2021 Identification and Authentication Failures",
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ),
    "Reflected XSS": (
        "Contextually output-encode all user input (HTML, attribute, JS, URL), "
        "validate input server-side, and deploy a strict Content-Security-Policy "
        "as defense in depth. Prefer framework auto-escaping.",
        "OWASP A03:2021 Injection (XSS)",
        "https://owasp.org/Top10/A03_2021-Injection/",
    ),
    "SQL Injection": (
        "Use parameterized queries / prepared statements for every database "
        "call. Never concatenate user input into SQL. Apply least-privilege DB "
        "accounts and validate input server-side.",
        "OWASP A03:2021 Injection (SQLi)",
        "https://owasp.org/Top10/A03_2021-Injection/",
    ),
    "Insecure Cookie": (
        "Set the Secure, HttpOnly, and SameSite attributes on session cookies. "
        "Secure restricts them to HTTPS, HttpOnly blocks JS access (XSS theft), "
        "and SameSite=Lax/Strict mitigates CSRF.",
        "OWASP Session Management Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    ),
    "CORS Misconfiguration": (
        "Do not reflect arbitrary Origins or combine "
        "Access-Control-Allow-Origin: * with Allow-Credentials. Maintain a "
        "server-side allow list of trusted origins and echo only those.",
        "OWASP A05:2021 Security Misconfiguration (CORS)",
        "https://owasp.org/www-community/attacks/CSRF",
    ),
    "Open Redirect": (
        "Avoid using user-supplied URLs for redirects. If unavoidable, validate "
        "against an allow list of permitted destinations or use mapping keys "
        "instead of raw URLs, and never trust the Location target.",
        "CWE-601 URL Redirection to Untrusted Site",
        "https://cwe.mitre.org/data/definitions/601.html",
    ),
    "Missing CSRF Protection": (
        "Add anti-CSRF tokens to all state-changing forms (synchronizer token "
        "pattern), set SameSite cookies, and verify the Origin/Referer header "
        "for sensitive POST requests.",
        "OWASP CSRF Prevention Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ),
    "TLS/SSL Issue": (
        "Renew expiring certificates, disable legacy protocols (SSLv3/TLS 1.0/1.1) "
        "and weak ciphers, and enable HSTS. Use a tool like SSL Labs to validate "
        "the configuration.",
        "OWASP Transport Layer Security Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ),
    "Path Disclosure": (
        "Review entries exposed via robots.txt or sitemaps; these are public and "
        "must not be relied on to hide sensitive areas. Protect such paths with "
        "real authentication/authorization.",
        "CWE-200 Exposure of Sensitive Information",
        "https://cwe.mitre.org/data/definitions/200.html",
    ),
    "Missing security.txt": (
        "Publish a /.well-known/security.txt describing how to report security "
        "issues. It does not fix a vulnerability but signals a mature security "
        "posture and speeds up responsible disclosure.",
        "RFC 9116 security.txt",
        "https://www.rfc-editor.org/rfc/rfc9116",
    ),
}

_FALLBACK = (
    "Review the affected endpoint and apply the relevant secure-coding and "
    "configuration controls for this issue class.",
    "OWASP Top 10",
    "https://owasp.org/www-project-top-ten/",
)


def for_type(finding_type: str) -> tuple[str, str]:
    """Return (remediation, reference) for a finding type. Reference is 'LABEL | URL'."""
    remediation, label, url = CATALOG.get(finding_type, _FALLBACK)
    return remediation, f"{label} | {url}"


def enrich(findings: list) -> list:
    """Fill remediation/reference on any finding that lacks them. Mutates in place."""
    for f in findings:
        if not getattr(f, "remediation", ""):
            remediation, reference = for_type(f.type)
            f.remediation = remediation
            f.reference = reference
    return findings
