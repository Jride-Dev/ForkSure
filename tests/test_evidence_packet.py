from forksure.evidence_packet import EVIDENCE_DISCLAIMER, build_evidence_packet


def test_evidence_packet_builds_from_compare_result() -> None:
    packet = build_evidence_packet("Jride-Dev/ForkSure", "other/ForkSure", _compare_result())

    assert packet["source_repo"] == "Jride-Dev/ForkSure"
    assert packet["candidate_repo"] == "other/ForkSure"
    assert packet["overall_risk"] == "HIGH"
    assert packet["disclaimer"] == EVIDENCE_DISCLAIMER
    assert packet["risk_breakdown"]["name"]["risk_level"] == "HIGH"


def test_evidence_found_includes_name_readme_license_and_similarity_signals() -> None:
    packet = build_evidence_packet("Jride-Dev/ForkSure", "other/ForkSure", _compare_result())
    evidence = "\n".join(packet["evidence_found"])

    assert "repository name" in evidence
    assert "README attribution" in evidence
    assert "candidate license matches" in evidence
    assert "Code similarity scan completed" in evidence


def test_evidence_not_found_includes_no_code_similarity_when_score_is_zero() -> None:
    packet = build_evidence_packet("Jride-Dev/ForkSure", "other/ForkSure", _compare_result())
    evidence = "\n".join(packet["evidence_not_found"])

    assert "No exact file hash matches were found." in evidence
    assert "No meaningful code similarity was found." in evidence
    assert "License matches the source repository." in evidence


def test_recommendations_are_neutral_and_do_not_accuse() -> None:
    packet = build_evidence_packet("Jride-Dev/ForkSure", "other/ForkSure", _compare_result())
    recommendations = "\n".join(packet["manual_review_recommendations"]).casefold()

    assert "manual" in recommendations
    assert "should be added" in recommendations
    assert "stole" not in recommendations
    assert "thief" not in recommendations
    assert "malicious repository" not in recommendations


def _compare_result() -> dict:
    return {
        "source": {
            "full_name": "Jride-Dev/ForkSure",
            "html_url": "https://github.com/Jride-Dev/ForkSure",
            "fork": False,
        },
        "candidate": {
            "full_name": "other/ForkSure",
            "html_url": "https://github.com/other/ForkSure",
            "fork": False,
        },
        "name_similarity": {
            "score": 95,
            "risk_level": "HIGH",
            "reasons": ["Exact repository name match under a different owner."],
        },
        "readme_comparison": {
            "status": "missing-attribution",
            "severity": "high",
            "summary": "Candidate README does not mention obvious upstream attribution.",
        },
        "license_comparison": {
            "status": "same",
            "severity": "info",
            "summary": "Fork license matches source license MIT.",
        },
        "similarity": {
            "overall_similarity_score": 0,
            "exact_hash_match_count": 0,
            "shared_path_count": 2,
        },
        "candidate_security": {
            "score": 0,
            "risk_level": "INFO",
            "finding_count": 4,
        },
        "risk_breakdown": {
            "overall": {
                "risk_level": "HIGH",
                "summary": "Overall risk is HIGH due to Name / imposter, README attribution.",
                "reasons": [],
            },
            "name": {
                "risk_level": "HIGH",
                "summary": "Exact repository name match under a different owner.",
                "reasons": [],
            },
            "readme": {
                "risk_level": "HIGH",
                "summary": "README attribution is missing while name similarity is strong.",
                "reasons": [],
            },
            "license": {
                "risk_level": "INFO",
                "summary": "Fork license matches source license MIT.",
                "reasons": [],
            },
            "similarity": {
                "risk_level": "INFO",
                "summary": "No meaningful exact content/path similarity found.",
                "reasons": [],
            },
            "security": {
                "risk_level": "INFO",
                "summary": "Security audit score 0/100; only informational findings.",
                "reasons": [],
            },
        },
        "overall_risk": "HIGH",
    }
