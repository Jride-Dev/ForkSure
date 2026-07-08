from rich.console import Console
from typer.testing import CliRunner

from forksure.cli import app


def test_cli_compare_command_renders_output(monkeypatch) -> None:
    monkeypatch.setattr("forksure.cli.compare_repositories", lambda source, candidate, github_client: _comparison())
    monkeypatch.setattr("forksure.cli.console", Console(width=180))
    runner = CliRunner()

    result = runner.invoke(app, ["compare", "Jride-Dev/ForkSure", "other/ForkSure"])

    assert result.exit_code == 0
    assert "Source repo" in result.output
    assert "Candidate repo" in result.output
    assert "Overall risk" in result.output
    assert "Repository Compare" in result.output
    assert "missing-attribution" in result.output


def test_cli_compare_accepts_similarity(monkeypatch) -> None:
    monkeypatch.setattr("forksure.cli.compare_repositories", lambda source, candidate, github_client: _comparison())
    monkeypatch.setattr("forksure.cli.scan_repository_similarity", lambda source, candidate: _similarity())
    monkeypatch.setattr("forksure.cli.console", Console(width=180))
    runner = CliRunner()

    result = runner.invoke(app, ["compare", "Jride-Dev/ForkSure", "other/ForkSure", "--similarity"])

    assert result.exit_code == 0
    assert "Similarity Evidence" in result.output
    assert "Overall similarity score" in result.output
    assert "README.md" in result.output


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
