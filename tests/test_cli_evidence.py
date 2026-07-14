from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from forksure.cli import app


def test_cli_evidence_command_works_with_mocked_compare(monkeypatch) -> None:
    monkeypatch.setattr(
        "forksure.cli.compare_repositories",
        lambda source, candidate, github_client, include_security=False: _compare_result(),
    )
    monkeypatch.setattr("forksure.cli.console", Console(width=180))
    runner = CliRunner()

    result = runner.invoke(app, ["evidence", "Jride-Dev/ForkSure", "other/ForkSure"])

    assert result.exit_code == 0
    assert "ForkSure Evidence Packet" in result.output
    assert "Evidence found" in result.output
    assert "Evidence not found" in result.output
    assert "manual review" in result.output.lower()


def test_cli_evidence_similarity_and_open_use_mocks(monkeypatch, tmp_path) -> None:
    opened: list[str] = []
    seen: dict[str, bool] = {}
    output_path = tmp_path / "evidence.html"

    def fake_compare(source, candidate, github_client, include_security=False):
        seen["include_security"] = include_security
        return _compare_result()

    monkeypatch.setattr("forksure.cli.compare_repositories", fake_compare)
    monkeypatch.setattr("forksure.cli.scan_repository_similarity", lambda source, candidate: _similarity())
    monkeypatch.setattr("forksure.cli.webbrowser.open", lambda url: opened.append(url) or True)
    monkeypatch.setattr("forksure.cli.console", Console(width=180))
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "evidence",
            "Jride-Dev/ForkSure",
            "other/ForkSure",
            "--similarity",
            "--security",
            "--out",
            str(output_path),
            "--open",
        ],
    )

    assert result.exit_code == 0
    assert seen["include_security"] is True
    assert output_path.exists()
    assert opened
    assert "HTML report written to" in result.output


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
        "name_similarity": {"score": 95, "risk_level": "HIGH", "reasons": []},
        "readme_comparison": {"status": "missing-attribution", "severity": "high", "summary": "Missing attribution."},
        "license_comparison": {"status": "same", "severity": "info", "summary": "License matches."},
        "risk_breakdown": {
            "overall": {"risk_level": "HIGH", "summary": "Overall risk is HIGH.", "reasons": []},
            "name": {"risk_level": "HIGH", "summary": "Exact repository name match.", "reasons": []},
            "readme": {"risk_level": "HIGH", "summary": "Missing README attribution.", "reasons": []},
            "license": {"risk_level": "INFO", "summary": "License matches.", "reasons": []},
            "similarity": {"risk_level": "not scanned", "summary": "Code similarity was not requested.", "reasons": []},
            "security": {"risk_level": "not scanned", "summary": "Security audit not requested.", "reasons": []},
        },
        "overall_risk": "HIGH",
    }


def _similarity() -> dict:
    return {
        "source_repo": "Jride-Dev/ForkSure",
        "candidate_repo": "other/ForkSure",
        "exact_file_matches": [],
        "matching_paths": [],
        "source_file_count": 3,
        "candidate_file_count": 4,
        "shared_path_count": 0,
        "exact_hash_match_count": 0,
        "directory_similarity_score": 0,
        "exact_content_similarity_score": 0,
        "overall_similarity_score": 0,
        "top_matches": [],
        "ignored_paths_summary": {},
    }


def test_default_evidence_report_path_is_not_required(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "forksure.cli.compare_repositories",
        lambda source, candidate, github_client, include_security=False: _compare_result(),
    )
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(app, ["evidence", "Jride-Dev/ForkSure", "other/ForkSure", "--html"])

    assert result.exit_code == 0
    assert Path("reports/evidence-jride-dev-forksure-vs-other-forksure.html").exists()
