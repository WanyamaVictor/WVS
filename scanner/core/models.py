"""Shared data structures used across the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Risk severity for a finding. String-valued so it serializes cleanly to JSON."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 2,
            Severity.MEDIUM: 5,
            Severity.HIGH: 8,
            Severity.CRITICAL: 10,
        }[self]


@dataclass
class Finding:
    """A single vulnerability or observation produced by a scanner module."""

    type: str            # e.g. "SQL Injection", "Reflected XSS", "Missing Header"
    severity: Severity
    endpoint: str        # the URL the issue was found at
    description: str
    payload: str = ""    # the payload/probe used, if any
    evidence: str = ""   # snippet of response that justifies the finding
    parameter: str = ""  # affected request parameter, if any

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    """Aggregate result of a full scan run."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    pages_crawled: int = 0
    started_at: str = ""
    finished_at: str = ""

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def risk_score(self) -> int:
        """0-100 aggregate risk based on the most severe findings."""
        if not self.findings:
            return 0
        # Weight by the worst findings rather than averaging, so a single
        # critical issue is not diluted by many info-level notes.
        scores = sorted((f.severity.score for f in self.findings), reverse=True)
        top = scores[:5]
        raw = sum(top) / (10 * len(top)) * 100
        return round(raw)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "pages_crawled": self.pages_crawled,
            "risk_score": self.risk_score,
            "counts_by_severity": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }
