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

from .core.crawler import Crawler
from .core.http_client import HttpClient
from .core.models import ScanResult, Severity
from .report import report_generator
from .scanners import (
    admin_panel_scan,
    directory_scan,
    headers as headers_scan,
    sql_injection,
    xss,
)

ALL_MODULES = ["headers", "directory", "admin", "sqli", "xss"]

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


def run_scan(args: argparse.Namespace) -> ScanResult:
    modules = _selected_modules(args.modules)
    client = HttpClient(
        timeout=args.timeout,
        delay=args.delay,
        verify_tls=not args.no_verify_tls,
    )
    result = ScanResult(target=args.target, started_at=_now())

    try:
        # Crawl first if any module needs request surfaces.
        pages = []
        if any(m in modules for m in ("sqli", "xss")):
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Crawling (max {args.max_pages} pages)...")
            pages = Crawler(client, max_pages=args.max_pages).crawl(args.target)
            result.pages_crawled = len(pages)
            print(f"    discovered {len(pages)} page(s).")

        if "headers" in modules:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking security headers...")
            result.extend(headers_scan.scan(client, args.target))

        if "directory" in modules:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Scanning for sensitive paths...")
            result.extend(directory_scan.scan(client, args.target))

        if "admin" in modules:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Looking for admin/login panels...")
            result.extend(admin_panel_scan.scan(client, args.target))

        if "sqli" in modules:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Testing for SQL injection...")
            result.extend(sql_injection.scan(client, pages))

        if "xss" in modules:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Testing for reflected XSS...")
            result.extend(xss.scan(client, pages))
    finally:
        client.close()
        result.finished_at = _now()

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
