from codebloodhound.security.findings import SecurityFinding
from codebloodhound.security.scoring import calculate_security_score


def test_security_score_has_info_level_with_no_findings() -> None:
    score = calculate_security_score([])

    assert score["score"] == 0
    assert score["risk_level"] == "INFO"
    assert score["finding_count"] == 0
    assert score["counts_by_severity"] == {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }


def test_critical_finding_produces_critical_risk() -> None:
    finding = SecurityFinding(
        id="test-critical",
        category="test",
        severity="critical",
        title="Critical finding",
        description="A critical test finding.",
    )

    score = calculate_security_score([finding])

    assert score["score"] == 100
    assert score["risk_level"] == "CRITICAL"
    assert score["finding_count"] == 1
    assert score["counts_by_severity"]["critical"] == 1
