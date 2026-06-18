from __future__ import annotations

from scanner.core.models import Finding, ScanResult, Severity


class TestSeverity:
    def test_scores(self):
        assert Severity.INFO.score == 0
        assert Severity.LOW.score == 2
        assert Severity.MEDIUM.score == 5
        assert Severity.HIGH.score == 8
        assert Severity.CRITICAL.score == 10

    def test_from_string(self):
        assert Severity("high") == Severity.HIGH
        assert Severity("info") == Severity.INFO


class TestFinding:
    def make_finding(self, **kwargs):
        defaults = dict(
            type="SQL Injection",
            severity=Severity.HIGH,
            endpoint="https://example.com/search",
            description="SQL error triggered.",
            payload="'",
            evidence="SQL syntax error",
            parameter="q",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_to_dict_serializes_severity(self):
        f = self.make_finding()
        d = f.to_dict()
        assert d["severity"] == "high"
        assert d["endpoint"] == "https://example.com/search"
        assert d["parameter"] == "q"
        assert d["payload"] == "'"


class TestScanResult:
    def test_risk_score_empty(self):
        r = ScanResult(target="https://t.com")
        assert r.risk_score == 0

    def test_risk_score_single_critical(self):
        r = ScanResult(target="https://t.com")
        r.add(Finding(type="X", severity=Severity.CRITICAL, endpoint="https://t.com", description="x"))
        assert r.risk_score == 100

    def test_risk_score_dominated_by_worst(self):
        r = ScanResult(target="https://t.com")
        for _ in range(10):
            r.add(Finding(type="X", severity=Severity.INFO, endpoint="https://t.com", description="x"))
        r.add(Finding(type="X", severity=Severity.HIGH, endpoint="https://t.com", description="x"))
        assert r.risk_score == 16

    def test_counts_by_severity(self):
        r = ScanResult(target="https://t.com")
        r.add(Finding(type="A", severity=Severity.LOW, endpoint="https://t.com", description="a"))
        r.add(Finding(type="B", severity=Severity.LOW, endpoint="https://t.com", description="b"))
        r.add(Finding(type="C", severity=Severity.MEDIUM, endpoint="https://t.com", description="c"))
        counts = r.counts_by_severity()
        assert counts["low"] == 2
        assert counts["medium"] == 1
        assert counts["critical"] == 0

    def test_to_dict_keys(self):
        r = ScanResult(target="https://t.com", pages_crawled=3)
        d = r.to_dict()
        assert d["target"] == "https://t.com"
        assert d["pages_crawled"] == 3
        assert "findings" in d
        assert "risk_score" in d
        assert "counts_by_severity" in d

    def test_extend(self):
        r = ScanResult(target="https://t.com")
        findings = [
            Finding(type="A", severity=Severity.LOW, endpoint="https://t.com/a", description="a"),
            Finding(type="B", severity=Severity.MEDIUM, endpoint="https://t.com/b", description="b"),
        ]
        r.extend(findings)
        assert len(r.findings) == 2
