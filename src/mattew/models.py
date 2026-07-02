"""Data models for crawled findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(Enum):
    ENDPOINT = "endpoint"
    JAVASCRIPT = "javascript"
    API_ROUTE = "api_route"
    PARAMETER = "parameter"
    SECRET = "secret"
    SUBDOMAIN = "subdomain"
    FILE = "file"
    COMMENT = "comment"
    FORM = "form"
    HEADER = "header"
    INFO = "info"
    TECH = "tech"
    WAF = "waf"


@dataclass
class Finding:
    type: FindingType
    url: str
    value: str
    source: str
    severity: Severity = Severity.INFO
    context: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "url": self.url,
            "value": self.value,
            "source": self.source,
            "severity": self.severity.value,
            "context": self.context,
            "metadata": self.metadata,
        }


@dataclass
class CrawlResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    urls_visited: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)
    tech_stack: list[dict] = field(default_factory=list)
    scan_time: float = 0.0

    def add(self, finding: Finding):
        self.findings.append(finding)

    def deduplicate(self):
        """Remove duplicate findings (same type + value + source)."""
        seen = set()
        unique = []
        for f in self.findings:
            # Use type + value + source as dedup key (ignore URL for header/secret checks)
            key = (f.type.value, f.value, f.source)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

    def summary(self) -> dict:
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for f in self.findings:
            by_type[f.type.value] = by_type.get(f.type.value, 0) + 1
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        return {
            "target": self.target,
            "total_findings": len(self.findings),
            "urls_visited": len(self.urls_visited),
            "by_type": by_type,
            "by_severity": by_severity,
            "errors": len(self.errors),
            "tech_stack": self.tech_stack,
            "scan_time": round(self.scan_time, 2),
        }

    def security_score(self) -> dict:
        """Calculate a 0-100 security score. Only counts actual security issues."""
        score = 100
        deductions = []
        # Only count medium+ findings as actual security issues
        for f in self.findings:
            if f.severity == Severity.CRITICAL:
                score -= 20
                deductions.append(f"-20: {f.value[:60]}")
            elif f.severity == Severity.HIGH:
                score -= 8
                deductions.append(f"-8: {f.value[:60]}")
            elif f.severity == Severity.MEDIUM:
                # Cap medium deductions - too many hidden params shouldn't tank score
                if len([d for d in deductions if d.startswith("-2:")]) < 5:
                    score -= 2
                    deductions.append(f"-2: {f.value[:60]}")
            # LOW and INFO don't count against score
        score = max(0, score)
        return {
            "score": score,
            "rating": (
                "A+" if score >= 95 else
                "A" if score >= 85 else
                "B" if score >= 70 else
                "C" if score >= 50 else
                "D" if score >= 30 else
                "F"
            ),
            "deductions": deductions[:20],
        }
