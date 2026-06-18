"""Tests for the premium upgrade: new scanners, remediation, and storage."""

from __future__ import annotations

import os
import tempfile

from scanner.core import remediation, storage
from scanner.core.crawler import Form, Page
from scanner.core.models import Finding, ScanResult, Severity


class _Resp:
    def __init__(self, text="", status=200, headers=None, url="https://example.com/", set_cookie=None):
        self.url = url
        self.status_code = status
        self.headers = headers or {}
        self.text = text
        self.ok = status < 400
        self.set_cookie = set_cookie or []


# --------------------------------------------------------------------------- #
# cookies
# --------------------------------------------------------------------------- #
def test_cookies_flags_missing_attributes(client, mocker):
    from scanner.scanners import cookies
    client.get = mocker.Mock(return_value=_Resp(set_cookie=["sid=abc; Path=/"]))
    out = cookies.scan(client, "https://example.com/")
    assert len(out) == 1
    f = out[0]
    assert f.type == "Insecure Cookie"
    assert "HttpOnly" in f.description and "Secure" in f.description and "SameSite" in f.description
    assert f.severity == Severity.MEDIUM


def test_cookies_clean_when_all_flags_present(client, mocker):
    from scanner.scanners import cookies
    client.get = mocker.Mock(return_value=_Resp(
        set_cookie=["sid=abc; Secure; HttpOnly; SameSite=Strict"]))
    assert cookies.scan(client, "https://example.com/") == []


# --------------------------------------------------------------------------- #
# csrf
# --------------------------------------------------------------------------- #
def test_csrf_flags_post_form_without_token():
    from scanner.scanners import csrf
    page = Page(url="https://x/", forms=[
        Form(action="https://x/save", method="post", inputs={"name": "", "email": ""})
    ])
    out = csrf.scan(None, [page])
    assert len(out) == 1 and out[0].type == "Missing CSRF Protection"


def test_csrf_passes_form_with_token_and_skips_get():
    from scanner.scanners import csrf
    pages = [
        Page(url="https://x/", forms=[
            Form(action="https://x/save", method="post",
                 inputs={"name": "", "csrf_token": "z"})]),
        Page(url="https://x/s", forms=[
            Form(action="https://x/search", method="get", inputs={"q": ""})]),
    ]
    assert csrf.scan(None, pages) == []


# --------------------------------------------------------------------------- #
# remediation enrichment
# --------------------------------------------------------------------------- #
def test_remediation_enriches_known_and_unknown_types():
    findings = [
        Finding(type="SQL Injection", severity=Severity.HIGH, endpoint="x", description="d"),
        Finding(type="Totally Unknown", severity=Severity.LOW, endpoint="x", description="d"),
    ]
    remediation.enrich(findings)
    assert "parameterized" in findings[0].remediation.lower()
    assert " | http" in findings[0].reference          # "LABEL | URL"
    assert findings[1].remediation                       # fallback still populated


# --------------------------------------------------------------------------- #
# storage round-trip + compare
# --------------------------------------------------------------------------- #
def test_storage_save_get_compare_delete():
    db = os.path.join(tempfile.gettempdir(), "wvs_pytest_history.db")
    if os.path.exists(db):
        os.remove(db)

    r1 = ScanResult(target="http://x", started_at="a", finished_at="b")
    r1.add(Finding(type="SQL Injection", severity=Severity.HIGH, endpoint="http://x/p",
                   description="d", parameter="id"))
    r1.add(Finding(type="Insecure Cookie", severity=Severity.MEDIUM, endpoint="http://x/",
                   description="d", parameter="sid"))
    id1 = storage.save_scan(r1, modules="all", db_path=db)

    r2 = ScanResult(target="http://x", started_at="c", finished_at="d")
    r2.add(Finding(type="Insecure Cookie", severity=Severity.MEDIUM, endpoint="http://x/",
                   description="d", parameter="sid"))
    id2 = storage.save_scan(r2, modules="all", db_path=db)

    assert {s["id"] for s in storage.list_scans(db_path=db)} == {id1, id2}
    assert storage.get_scan(id1, db_path=db)["risk_score"] == r1.risk_score

    diff = storage.compare(id1, id2, db_path=db)
    assert len(diff["removed"]) == 1   # SQLi fixed
    assert len(diff["unchanged"]) == 1  # cookie persists
    assert len(diff["added"]) == 0

    assert storage.delete_scan(id1, db_path=db) is True
    assert len(storage.list_scans(db_path=db)) == 1


def test_storage_stats_aggregates():
    db = os.path.join(tempfile.gettempdir(), "wvs_pytest_stats.db")
    if os.path.exists(db):
        os.remove(db)
    for sev in (Severity.HIGH, Severity.LOW):
        r = ScanResult(target="http://x", started_at="a", finished_at="b")
        r.add(Finding(type="X", severity=sev, endpoint="http://x", description="d"))
        storage.save_scan(r, db_path=db)
    st = storage.stats(db_path=db)
    assert st["total_scans"] == 2
    assert st["total_findings"] == 2
    assert st["severity_totals"]["high"] == 1 and st["severity_totals"]["low"] == 1
    assert len(st["trend"]) == 2


def test_get_many_preserves_order(mocker):
    from scanner.core.http_client import HttpClient
    c = HttpClient(workers=4)
    mocker.patch.object(c, "get", side_effect=lambda u, **k: u)
    urls = [f"http://x/{i}" for i in range(20)]
    assert c.get_many(urls) == urls
    c.close()


def test_crawler_skips_third_party_apps():
    from scanner.core.crawler import Crawler
    c = Crawler(client=None)
    assert c._is_skipped("http://x/phpmyadmin/index.php") is True
    assert c._is_skipped("http://x/dashboard/docs/use-sqlite.html") is True
    assert c._is_skipped("http://x/app/login.php") is False


def test_budgeted_map_respects_deadline():
    import time
    from scanner.core.concurrency import budgeted_map

    def slow(_):
        time.sleep(0.02)
        return 1

    results, skipped = budgeted_map(slow, list(range(60)), workers=4, deadline_s=0.05)
    assert skipped > 0                       # budget cut work short
    assert len(results) + skipped == 60      # accounting is exact
