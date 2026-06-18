"""WVS command-line entry point.

Usage:
    python -m scanner.main https://target.example --authorize
    python -m scanner.main https://target.example --authorize --modules headers,xss

Run only against systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
except Exception:  # pragma: no cover - colorama is optional at runtime
    class _Dummy:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Dummy()  # type: ignore

from .core import remediation
from .core.crawler import Crawler
from .core.http_client import HttpClient
from .core.models import ScanResult, Severity
from .report import report_generator
from .scanners import (
    admin_panel_scan,
    cookies as cookies_scan,
    cors as cors_scan,
    csrf as csrf_scan,
    directory_scan,
    discovery as discovery_scan,
    headers as headers_scan,
    open_redirect,
    sql_injection,
    tls as tls_scan,
    xss,
)

# Modules that probe the target URL directly.  key -> (scan_fn, human label)
TARGET_MODULES = {
    "headers":   (headers_scan.scan,     "Checking security headers"),
    "directory": (directory_scan.scan,   "Scanning for sensitive paths"),
    "admin":     (admin_panel_scan.scan, "Looking for admin/login panels"),
    "cookies":   (cookies_scan.scan,     "Inspecting cookie attributes"),
    "cors":      (cors_scan.scan,        "Testing CORS policy"),
    "tls":       (tls_scan.scan,         "Checking TLS/SSL configuration"),
    "discovery": (discovery_scan.scan,   "Discovering robots / security.txt"),
}

# Modules that operate on crawled pages (require a crawl first).
PAGE_MODULES = {
    "sqli":     (sql_injection.scan, "Testing for SQL injection"),
    "xss":      (xss.scan,           "Testing for reflected XSS"),
    "redirect": (open_redirect.scan, "Testing for open redirects"),
    "csrf":     (csrf_scan.scan,     "Checking CSRF protection"),
}

# Canonical execution / display order.
ALL_MODULES = list(TARGET_MODULES) + list(PAGE_MODULES)

SEV_COLOR = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "info": Fore.BLUE,
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="wvs",
        description="Web Vulnerability Scanner (mini OWASP-style tool).",
    )
    p.add_argument("target", help="Target URL, e.g. https://example.com")
    p.add_argument(
        "--authorize",
        action="store_true",
        help="Confirm you are authorized to scan this target (required).",
    )
    p.add_argument(
        "--modules",
        default="all",
        help=f"Comma-separated modules to run. Options: {','.join(ALL_MODULES)} or 'all'.",
    )
    p.add_argument("--max-pages", type=int, default=40, help="Crawler page limit.")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (s).")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests (s).")
    p.add_argument("--workers", type=int, default=8,
                   help="Concurrent request workers (forced to 1 when --delay is set).")
    p.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification.")
    p.add_argument("--json", dest="json_path", help="Write JSON report to this path.")
    p.add_argument("--html", dest="html_path", help="Write HTML report to this path.")
    return p.parse_args(argv)


def _selected_modules(value: str) -> list:
    if value.strip().lower() == "all":
        return list(ALL_MODULES)
    chosen = [m.strip().lower() for m in value.split(",") if m.strip()]
    invalid = [m for m in chosen if m not in ALL_MODULES]
    if invalid:
        raise SystemExit(f"Unknown module(s): {', '.join(invalid)}")
    return chosen


def _print_finding(f) -> None:
    color = SEV_COLOR.get(f.severity.value, "")
    tag = f"{color}[{f.severity.value.upper():^8}]{Style.RESET_ALL}"
    loc = f.endpoint + (f" ({f.parameter})" if f.parameter else "")
    print(f"  {tag} {f.type}: {loc}")
    print(f"           {f.description}")
    if f.payload:
        print(f"           payload: {f.payload}")


def run_scan(args: argparse.Namespace, on_event=None) -> ScanResult:
    """Run the selected modules.

    ``on_event``, if given, is called with structured progress dicts so a UI can
    show live progress: ``{"type": "phase"|"log"|"done", ...}``. The CLI leaves
    it as ``None`` and relies on the printed output below.
    """
    modules = _selected_modules(args.modules)
    client = HttpClient(
        timeout=args.timeout,
        delay=args.delay,
        verify_tls=not args.no_verify_tls,
        workers=getattr(args, "workers", 8),
    )
    result = ScanResult(target=args.target, started_at=_now())

    ordered = [m for m in ALL_MODULES if m in modules]
    needs_crawl = any(m in PAGE_MODULES for m in ordered)
    total_steps = len(ordered) + (1 if needs_crawl else 0)
    counter = {"i": 0}

    def emit(etype, **data):
        if on_event is not None:
            on_event({"type": etype, **data})

    def begin(label, module=None):
        counter["i"] += 1
        emit("phase", index=counter["i"], total=total_steps, label=label, module=module)
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {label}...")

    try:
        pages = []
        if needs_crawl:
            begin(f"Crawling (max {args.max_pages} pages)", "crawl")
            pages = Crawler(client, max_pages=args.max_pages).crawl(args.target)
            result.pages_crawled = len(pages)
            msg = f"discovered {len(pages)} page(s)"
            print(f"    {msg}.")
            emit("log", message=msg)

        for key in ordered:
            if key in TARGET_MODULES:
                scan_fn, label = TARGET_MODULES[key]
                begin(label, key)
                before = len(result.findings)
                result.extend(scan_fn(client, args.target))
            else:
                scan_fn, label = PAGE_MODULES[key]
                begin(label, key)
                before = len(result.findings)
                result.extend(scan_fn(client, pages))
            emit("log", message=f"{label}: {len(result.findings) - before} finding(s)")
    finally:
        client.close()
        result.finished_at = _now()

    remediation.enrich(result.findings)
    emit("done", risk_score=result.risk_score, findings=len(result.findings))
    return result


def main(argv=None) -> int:
    args = parse_args(argv)

    if not args.target.startswith(("http://", "https://")):
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Target must start with http:// or https://")
        return 2

    if not args.authorize:
        print(
            f"{Fore.RED}[!] Authorization required.{Style.RESET_ALL}\n"
            "    This tool sends test payloads to the target. Only scan systems you\n"
            "    own or have explicit written permission to test. Re-run with\n"
            "    --authorize to confirm you have permission for:\n"
            f"        {args.target}"
        )
        return 3

    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Starting scan of {args.target}\n")
    result = run_scan(args)

    # --- Summary ---
    print(f"\n{Style.BRIGHT}=== Results ==={Style.RESET_ALL}")
    if result.findings:
        for f in sorted(result.findings, key=lambda x: -x.severity.score):
            _print_finding(f)
    else:
        print("  No findings.")

    counts = result.counts_by_severity()
    print(f"\n{Style.BRIGHT}Risk score: {result.risk_score}/100{Style.RESET_ALL}")
    print(
        "  "
        + " | ".join(
            f"{s.value}: {counts[s.value]}"
            for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                      Severity.LOW, Severity.INFO)
        )
    )

    if args.json_path:
        report_generator.write_json(result, args.json_path)
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} JSON report: {args.json_path}")
    if args.html_path:
        report_generator.write_html(result, args.html_path)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} HTML report: {args.html_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
