from forksure.reports import COMPARE_DISCLAIMER, write_compare_html_report


def test_compare_html_report_is_created(tmp_path) -> None:
    output_path = tmp_path / "compare.html"

    result = write_compare_html_report(_comparison(), output_path)

    assert result == output_path
    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")
    assert "ForkSure Repository Compare" in html
    assert COMPARE_DISCLAIMER in html
    assert "Jride-Dev/ForkSure" in html
    assert "other/ForkSure" in html
    assert "missing-attribution" in html


def test_compare_html_report_escapes_dynamic_text(tmp_path) -> None:
    output_path = tmp_path / "compare.html"
    comparison = _comparison()
    comparison["candidate"]["full_name"] = "other/<script>alert(1)</script>"
    comparison["candidate"]["description"] = "<script>alert(1)</script>"
    comparison["reasons"] = ["Reason has <script>alert(1)</script>"]

    write_compare_html_report(comparison, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def _comparison() -> dict:
    return {
        "source": {
            "full_name": "Jride-Dev/ForkSure",
            "html_url": "https://github.com/Jride-Dev/ForkSure",
            "description": "Repository provenance scanner.",
            "fork": False,
            "created_at": "2026-01-01",
            "pushed_at": "2026-01-02",
            "stargazers_count": 10,
            "default_branch": "main",
            "license_label": "MIT",
            "readme_status": "README.md",
        },
        "candidate": {
            "full_name": "other/ForkSure",
            "html_url": "https://github.com/other/ForkSure",
            "description": "Similar repository.",
            "fork": False,
            "created_at": "2026-01-03",
            "pushed_at": "2026-01-04",
            "stargazers_count": 1,
            "default_branch": "main",
            "license_label": "MIT",
            "readme_status": "README.md",
        },
        "name_similarity": {
            "score": 95,
            "risk_level": "HIGH",
            "reasons": ["Exact repository name match under a different owner."],
        },
        "license_comparison": {
            "status": "same",
            "severity": "info",
            "summary": "Fork license matches source license MIT.",
        },
        "readme_comparison": {
            "status": "missing-attribution",
            "severity": "high",
            "summary": "Candidate README does not mention obvious upstream attribution.",
        },
        "metadata_summary": {},
        "overall_risk": "HIGH",
        "reasons": ["Same or similar name with missing README attribution; manual review recommended."],
    }
