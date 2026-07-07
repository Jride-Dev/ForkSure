from codebloodhound.reports import IMPOSTER_DISCLAIMER, write_imposter_html_report


def test_imposter_html_report_file_is_created(tmp_path) -> None:
    output_path = tmp_path / "imposters.html"

    result = write_imposter_html_report("Jride-Dev/CodeBloodHound", [_candidate()], output_path)

    assert result == output_path
    assert output_path.exists()


def test_imposter_html_report_includes_target_repo_and_disclaimer(tmp_path) -> None:
    output_path = tmp_path / "imposters.html"

    write_imposter_html_report("Jride-Dev/CodeBloodHound", [_candidate()], output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "Jride-Dev/CodeBloodHound" in html
    assert IMPOSTER_DISCLAIMER in html


def test_imposter_html_report_includes_candidate_and_clickable_url(tmp_path) -> None:
    output_path = tmp_path / "imposters.html"

    write_imposter_html_report("Jride-Dev/CodeBloodHound", [_candidate()], output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "other/CodeBloodHound" in html
    assert '<article class="candidate-card">' in html
    assert '<a class="repo-link" href="https://github.com/other/CodeBloodHound">other/CodeBloodHound</a>' in html


def test_imposter_html_report_renders_reasons_as_list_items(tmp_path) -> None:
    output_path = tmp_path / "imposters.html"

    write_imposter_html_report("Jride-Dev/CodeBloodHound", [_candidate()], output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "possible-imposter" in html
    assert '<ul class="reason-list"><li>Manual review required.</li></ul>' in html
    assert IMPOSTER_DISCLAIMER in html


def test_imposter_html_report_includes_readme_excerpt_block(tmp_path) -> None:
    output_path = tmp_path / "imposters.html"

    write_imposter_html_report("Jride-Dev/CodeBloodHound", [_candidate()], output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "README Excerpt" in html
    assert '<div class="readme-excerpt">Mentions dependency scanning and provenance.</div>' in html


def test_imposter_html_report_includes_rare_string_evidence(tmp_path) -> None:
    output_path = tmp_path / "imposters.html"

    write_imposter_html_report("Jride-Dev/CodeBloodHound", [_candidate()], output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "Rare String Evidence" in html
    assert '<ul class="rare-list">' in html
    assert "CodeBloodHound correlates fork provenance with license drift evidence." in html
    assert "README.md" in html
    assert "Rare source phrase found in candidate repository." in html
    assert "https://github.com/other/CodeBloodHound/blob/main/README.md" in html


def test_imposter_html_report_escapes_dangerous_text(tmp_path) -> None:
    output_path = tmp_path / "imposters.html"
    candidate = _candidate()
    candidate.update(
        {
            "full_name": "other/<script>alert(1)</script>",
            "description": "<script>alert(1)</script>",
            "readme_text_excerpt": "README says <script>alert(1)</script>",
            "reasons": ["Reason has <script>alert(1)</script>"],
            "rare_string_matches": [
                {
                    "matched_string": "<script>alert(1)</script>",
                    "file_path": "docs/<script>.md",
                    "file_html_url": "https://github.com/other/repo/blob/main/docs/%3Cscript%3E.md",
                }
            ],
        }
    )

    write_imposter_html_report("Jride-Dev/CodeBloodHound", [candidate], output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_imposter_html_report_handles_no_candidates(tmp_path) -> None:
    output_path = tmp_path / "imposters.html"

    write_imposter_html_report("Jride-Dev/CodeBloodHound", [], output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "No imposter candidates found." in html
    assert '<article class="candidate-card">' not in html
    assert "<table>" not in html


def _candidate() -> dict:
    return {
        "risk_level": "HIGH",
        "classification": "possible-imposter",
        "score": 95,
        "full_name": "other/CodeBloodHound",
        "fork": False,
        "stargazers_count": 2,
        "created_at": "2026-01-01T00:00:00Z",
        "pushed_at": "2026-01-02T00:00:00Z",
        "license_key": "mit",
        "license_name": "MIT License",
        "description": "Supply chain scanner.",
        "readme_status": "found",
        "readme_text_excerpt": "Mentions dependency scanning and provenance.",
        "reasons": ["Manual review required."],
        "rare_string_matches": [
            {
                "matched_string": "CodeBloodHound correlates fork provenance with license drift evidence.",
                "file_path": "README.md",
                "file_html_url": "https://github.com/other/CodeBloodHound/blob/main/README.md",
                "reason": "Rare source phrase found in candidate repository.",
            }
        ],
        "html_url": "https://github.com/other/CodeBloodHound",
    }
