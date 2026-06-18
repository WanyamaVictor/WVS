from __future__ import annotations

from scanner.core.models import Finding, Severity


class _Resp:
    def __init__(self, text="", status=200, headers=None, url="https://example.com/"):
        self.url = url
        self.status_code = status
        self.headers = headers or {}
        self.text = text
        self.ok = status < 400

    @property
    def elapsed(self):
        return type("E", (), {"total_seconds": lambda self: 0.12})()


def _make(text="", status=200, headers=None, url="https://example.com/"):
    return _Resp(text=text, status=status, headers=headers, url=url)


def test_headers_missing_when_no_security_headers(client, mocker):
    client.get = mocker.Mock(return_value=_make(headers={}))
    from scanner.scanners import headers as headers_scan
    out = headers_scan.scan(client, "https://example.com/")
    assert any(o.type == "Missing Security Header" for o in out)
    assert not any(o.type == "Weak Security Header" for o in out)
    assert not any(o.type == "Information Disclosure" for o in out)


def test_headers_detects_missing_and_weak(client, mocker):
    headers = {
        "strict-transport-security": "max-age=0",
        "x-powered-by": "Foo/1.0",
    }
    client.get = mocker.Mock(return_value=_make(headers=headers))
    from scanner.scanners import headers as headers_scan
    out = headers_scan.scan(client, "https://example.com/")
    types = {o.type for o in out}
    assert "Missing Security Header" in types
    assert "Information Disclosure" in types
    assert "Weak Security Header" in types
