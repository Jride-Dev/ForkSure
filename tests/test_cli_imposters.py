from rich.console import Console
from typer.testing import CliRunner

from forksure.cli import app


def test_cli_imposters_command_renders_mocked_candidates(monkeypatch) -> None:
    monkeypatch.setattr(
        "forksure.cli.scan_imposters",
        lambda owner_repo, github_client: [
            {
                "risk_level": "HIGH",
                "classification": "possible-imposter",
                "score": 95,
                "full_name": "other/ForkSure",
                "fork": False,
                "stargazers_count": 2,
                "pushed_at": "2026-01-02T00:00:00Z",
                "reasons": ["Exact repository name match under a different owner."],
                "html_url": "https://github.com/other/ForkSure",
            }
        ],
    )
    monkeypatch.setattr("forksure.cli.console", Console(width=160))
    runner = CliRunner()

    result = runner.invoke(app, ["imposters", "Jride-Dev/ForkSure"])

    assert result.exit_code == 0
    assert "manual review" in result.output
    assert "other/ForkSure" in result.output
    assert "possible-imposter" in result.output
    assert "HIGH" in result.output
    assert "95" in result.output
    assert "URL" not in result.output
    assert "https://github.com/other/ForkSure" not in result.output
    assert "HTML report written" not in result.output


def test_cli_imposters_open_writes_and_opens_html_report(monkeypatch, tmp_path) -> None:
    opened_urls: list[str] = []
    output_path = tmp_path / "imposters.html"
    monkeypatch.setattr("forksure.cli.scan_imposters", lambda owner_repo, github_client: [])
    monkeypatch.setattr("forksure.cli.webbrowser.open", lambda url: opened_urls.append(url) or True)
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["imposters", "Jride-Dev/ForkSure", "--open", "--out", str(output_path)],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert "HTML report written to" in result.output
    assert opened_urls
    assert opened_urls[0].startswith("file:")


def test_cli_imposters_accepts_rare_strings(monkeypatch) -> None:
    monkeypatch.setattr("forksure.cli.scan_imposters", lambda owner_repo, github_client: [])
    monkeypatch.setattr(
        "forksure.cli.scan_rare_string_matches",
        lambda owner_repo, github_client, max_strings=5: [
            {
                "repository_full_name": "other/ForkSure",
                "repository_html_url": "https://github.com/other/ForkSure",
                "fork": False,
                "rare_string_matches": [
                    {
                        "matched_string": "ForkSure correlates fork provenance with license drift evidence.",
                        "file_path": "README.md",
                        "file_html_url": "https://github.com/other/ForkSure/blob/main/README.md",
                        "reason": "Rare source phrase found in candidate repository.",
                    }
                ],
                "reason": "Rare source phrase found in candidate repository.",
                "risk_level": "MEDIUM",
                "score": 60,
            }
        ],
    )
    monkeypatch.setattr("forksure.cli.console", Console(width=160))
    runner = CliRunner()

    result = runner.invoke(app, ["imposters", "Jride-Dev/ForkSure", "--rare-strings"])

    assert result.exit_code == 0
    assert "other/ForkSure" in result.output
    assert "Rare source phrase" in result.output
