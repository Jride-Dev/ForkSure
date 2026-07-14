from rich.console import Console
from typer.testing import CliRunner

from forksure.cli import app


def test_cli_compare_command_renders_output(monkeypatch) -> None:
    monkeypatch.setattr(
        "forksure.cli.compare_repositories",
        lambda source, candidate, github_client, include_security=False: _comparison(),
    )
    monkeypatch.setattr("forksure.cli.console", Console(width=180))
    runner = CliRunner()

    result = runner.invoke(app, ["compare", "Jride-Dev/ForkSure", "other/ForkSure"])

    assert result.exit_code == 0
    assert "Source repo" in result.output
    assert "Candidate repo" in result.output
    assert "Overall risk" in result.output
    assert "Repository Compare" in result.output
    assert "Risk Breakdown" in result.output
    assert "missing-attribution" in result.output


def test_cli_compare_accepts_similarity(monkeypatch) -> None:
    monkeypatch.setattr(
        "forksure.cli.compare_repositories",
        lambda source, candidate, github_client, include_security=False: _comparison(),
    )
    monkeypatch.setattr("forksure.cli.scan_repository_similarity", lambda source, candidate: _similarity())
    monkeypatch.setattr("forksure.cli.console", Console(width=180))
    runner = CliRunner()

    result = runner.invoke(app, ["compare", "Jride-Dev/ForkSure", "other/ForkSure", "--similarity"])

    assert result.exit_code == 0
    assert "Similarity Evidence" in result.output
    assert "Overall similarity score" in result.output
    assert "README.md" in result.output


def test_cli_compare_accepts_security(monkeypatch) -> None:
    seen: dict[str, bool] = {}

    def fake_compare(source, candidate, github_client, include_security=False):
        seen["include_security"] = include_security
        comparison = _comparison()
        comparison["source_security"] = _security_summary("Jride-Dev/ForkSure")
        comparison["candidate_security"] = _security_summary("other/ForkSure")
        comparison["risk_breakdown"]["security"] = {
            "risk_level": "INFO",
            "summary": "Security audit score 0/100; only informational findings.",
            "reasons": ["Security audit score 0/100; only informational findings."],
        }
        return comparison

    monkeypatch.setattr("forksure.cli.compare_repositories", fake_compare)
    monkeypatch.setattr("forksure.cli.console", Console(width=180))
    runner = CliRunner()

    result = runner.invoke(app, ["compare", "Jride-Dev/ForkSure", "other/ForkSure", "--security"])

    assert result.exit_code == 0
    assert seen["include_security"] is True
    assert "Security Audit" in result.output
    assert "Top Candidate Security Findings" in result.output


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


def _security_summary(repo: str) -> dict:
    return {
        "repo": repo,
        "local_path": ".forksure-cache/repos/repo",
        "score": 0,
        "risk_level": "INFO",
        "finding_count": 1,
        "counts_by_severity": {"info": 1, "low": 0, "medium": 0, "high": 0, "critical": 0},
        "top_findings": [
            {
                "id": "gitleaks-unavailable",
                "category": "secret",
                "severity": "info",
                "title": "Gitleaks unavailable",
                "description": "Install Gitleaks to enable secret scanning.",
                "file_path": None,
                "line": None,
                "source_tool": "gitleaks",
            }
        ],
        "unavailable_tool_info_findings": [],
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
