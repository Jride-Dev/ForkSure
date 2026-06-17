from __future__ import annotations

from .findings import SUPPORTED_SEVERITIES, SecurityFinding


SEVERITY_WEIGHTS = {
    "info": 0,
    "low": 10,
    "medium": 30,
    "high": 70,
    "critical": 100,
}


def calculate_security_score(findings: list[SecurityFinding]) -> dict:
    counts_by_severity = {severity: 0 for severity in SUPPORTED_SEVERITIES}

    score = 0
    for finding in findings:
        counts_by_severity[finding.severity] += 1
        score += SEVERITY_WEIGHTS[finding.severity]

    score = min(100, score)
    return {
        "score": score,
        "risk_level": _risk_level_for_score(score),
        "finding_count": len(findings),
        "counts_by_severity": counts_by_severity,
    }


def _risk_level_for_score(score: int) -> str:
    if score == 0:
        return "INFO"
    if score <= 24:
        return "LOW"
    if score <= 49:
        return "MEDIUM"
    if score <= 79:
        return "HIGH"
    return "CRITICAL"
