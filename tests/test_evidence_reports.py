from forksure.reports import write_evidence_html_report


def test_evidence_html_report_is_created(tmp_path) -> None:
    output_path = tmp_path / "evidence.html"

    result = write_evidence_html_report(_packet(), output_path)

    assert result == output_path
    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")
    assert "ForkSure Evidence Packet" in html
    assert "Jride-Dev/ForkSure" in html
    assert "other/ForkSure" in html
    assert "Evidence Found" in html
    assert "Manual Review Recommendations" in html


def test_evidence_html_report_escapes_dynamic_text(tmp_path) -> None:
    output_path = tmp_path / "evidence.html"
    packet = _packet()
    packet["candidate_repo"] = "other/<script>alert(1)</script>"
    packet["evidence_found"] = ["Dangerous <script>alert(1)</script> text"]

    write_evidence_html_report(packet, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def _packet() -> dict:
    return {
        "source_repo": "Jride-Dev/ForkSure",
        "candidate_repo": "other/ForkSure",
        "source_url": "https://github.com/Jride-Dev/ForkSure",
        "candidate_url": "https://github.com/other/ForkSure",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "summary": "Manual review recommended.",
        "overall_risk": "HIGH",
        "risk_breakdown": {
            "name": {"risk_level": "HIGH", "summary": "Exact repository name match.", "reasons": []},
            "readme": {"risk_level": "HIGH", "summary": "Missing README attribution.", "reasons": []},
            "license": {"risk_level": "INFO", "summary": "License matches.", "reasons": []},
            "similarity": {"risk_level": "INFO", "summary": "No code similarity.", "reasons": []},
            "security": {"risk_level": "not scanned", "summary": "Security audit not requested.", "reasons": []},
        },
        "evidence_found": ["Exact or similar repository name evidence found."],
        "evidence_not_found": ["No exact file hash matches were found."],
        "manual_review_recommendations": ["Review the candidate repository manually."],
        "disclaimer": "ForkSure produces evidence for manual review.",
    }
