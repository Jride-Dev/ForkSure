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
    assert "HTML report written" not in result.output


def test_cli_imposters_open_writes_and_opens_html_report(monkeypatch, tmp_path) -> None:
    opened_urls: list[str] = []
    output_path = tmp_path / "imposters.html"
    monkeypatch.setattr("codebloodhound.cli.scan_imposters", lambda owner_repo, github_client: [])
    monkeypatch.setattr("codebloodhound.cli.webbrowser.open", lambda url: opened_urls.append(url) or True)
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["imposters", "Jride-Dev/CodeBloodHound", "--open", "--out", str(output_path)],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert "HTML report written to" in result.output
    assert opened_urls
    assert opened_urls[0].startswith("file:")
