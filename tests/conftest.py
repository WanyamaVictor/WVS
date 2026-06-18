from __future__ import annotations

import pytest


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


@pytest.fixture
def client():
    from scanner.core.http_client import HttpClient
    return HttpClient()
