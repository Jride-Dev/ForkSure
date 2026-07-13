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
    assert "Risk Breakdown" in html
    assert "Code similarity" in html
    assert "not scanned" in html
    assert "Similarity Evidence" not in html


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


def test_compare_html_report_includes_similarity_section_when_present(tmp_path) -> None:
    output_path = tmp_path / "compare.html"
    comparison = _comparison()
    comparison["similarity"] = _similarity()

    write_compare_html_report(comparison, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "Similarity Evidence" in html
    assert "Overall score" in html
    assert "README.md" in html
    assert "Clone-based similarity evidence is for manual review" in html


def test_compare_html_report_includes_risk_breakdown(tmp_path) -> None:
    output_path = tmp_path / "compare.html"

    write_compare_html_report(_comparison(), output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "Risk Breakdown" in html
    assert "Name / imposter" in html
    assert "README attribution" in html
    assert "License" in html
    assert "Code similarity" in html
    assert "Security" in html


def test_compare_html_report_escapes_similarity_paths(tmp_path) -> None:
    output_path = tmp_path / "compare.html"
    comparison = _comparison()
    comparison["similarity"] = _similarity()
    comparison["similarity"]["top_matches"][0]["source_path"] = "docs/<script>.md"

    write_compare_html_report(comparison, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "<script>" not in html
    assert "docs/&lt;script&gt;.md" in html


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
        "risk_breakdown": {
            "overall": {
                "risk_level": "HIGH",
                "summary": "Overall risk is HIGH due to Name / imposter, README attribution.",
                "reasons": [
                    "Name / imposter: Exact repository name match under a different owner.",
                    "README attribution: README attribution is missing while name similarity is strong.",
                ],
            },
            "name": {
                "risk_level": "HIGH",
                "summary": "Exact repository name match under a different owner.",
                "reasons": ["Exact repository name match under a different owner."],
            },
            "readme": {
                "risk_level": "HIGH",
                "summary": "README attribution is missing while name similarity is strong.",
                "reasons": ["Candidate README does not mention obvious upstream attribution."],
            },
            "license": {
                "risk_level": "INFO",
                "summary": "Fork license matches source license MIT.",
                "reasons": ["Fork license matches source license MIT."],
            },
            "similarity": {
                "risk_level": "not scanned",
                "summary": "Code similarity was not requested.",
                "reasons": [],
            },
            "security": {
                "risk_level": "not scanned",
                "summary": "Security scanning is not part of repository compare yet.",
                "reasons": [],
            },
        },
        "overall_risk": "HIGH",
        "reasons": ["Same or similar name with missing README attribution; manual review recommended."],
    }


def _similarity() -> dict:
    return {
        "source_repo": "Jride-Dev/ForkSure",
        "candidate_repo": "other/ForkSure",
        "exact_file_matches": [
            {
                "source_path": "README.md",
                "candidate_path": "README.md",
                "sha256": "abc",
                "match_type": "same-path",
            }
        ],
        "matching_paths": [{"path": "README.md", "same_hash": True}],
        "source_file_count": 3,
        "candidate_file_count": 2,
        "shared_path_count": 1,
        "exact_hash_match_count": 1,
        "directory_similarity_score": 33,
        "exact_content_similarity_score": 33,
        "overall_similarity_score": 33,
        "top_matches": [
            {
                "source_path": "README.md",
                "candidate_path": "README.md",
                "sha256": "abc",
                "match_type": "same-path",
            }
        ],
        "ignored_paths_summary": {},
    }
