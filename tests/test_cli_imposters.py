from rich.console import Console
from typer.testing import CliRunner

from codebloodhound.cli import app


def test_cli_imposters_command_renders_mocked_candidates(monkeypatch) -> None:
    monkeypatch.setattr(
        "codebloodhound.cli.scan_imposters",
        lambda owner_repo, github_client: [
            {
                "risk_level": "HIGH",
                "score": 95,
                "full_name": "other/CodeBloodHound",
                "fork": False,
                "stargazers_count": 2,
                "pushed_at": "2026-01-02T00:00:00Z",
                "reasons": ["Exact repository name match under a different owner."],
                "html_url": "https://github.com/other/CodeBloodHound",
            }
        ],
    )
    monkeypatch.setattr("codebloodhound.cli.console", Console(width=160))
    runner = CliRunner()

    result = runner.invoke(app, ["imposters", "Jride-Dev/CodeBloodHound"])

    assert result.exit_code == 0
    assert "manual review" in result.output
    assert "other/CodeBloodHound" in result.output
    assert "HIGH" in result.output
    assert "95" in result.output
