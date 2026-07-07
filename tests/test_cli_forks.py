from datetime import UTC, datetime

from rich.console import Console
from typer.testing import CliRunner

from codebloodhound.cli import app
from codebloodhound.github_client import GitHubRepo
from codebloodhound.reports import render_forks


def test_forks_command_accepts_audit_license(monkeypatch) -> None:
    class FakeClient:
        def list_forks(self, owner_repo: str) -> list[GitHubRepo]:
            return []

        def get_repo_license(self, owner_repo: str) -> dict[str, bool | str | None]:
            return _license("mit", "MIT", "MIT License")

    monkeypatch.setattr("codebloodhound.cli.GitHubClient", FakeClient)
    monkeypatch.setattr("codebloodhound.cli.console", Console(width=160))
    runner = CliRunner()

    result = runner.invoke(app, ["forks", "Jride-Dev/CodeBloodHound", "--audit-license"])

    assert result.exit_code == 0
    assert "Source license" in result.output
    assert "MIT" in result.output
    assert "No forks found" in result.output


def test_forks_command_renders_license_status_with_mocked_client(monkeypatch) -> None:
    fork = _repo("fork/cbh")

    class FakeClient:
        def list_forks(self, owner_repo: str) -> list[GitHubRepo]:
            return [fork]

        def get_repo_license(self, owner_repo: str) -> dict[str, bool | str | None]:
            if owner_repo == "Jride-Dev/CodeBloodHound":
                return _license("mit", "MIT", "MIT License")
            return _license("bsd", "BSD", "BSD License")

    monkeypatch.setattr("codebloodhound.cli.GitHubClient", FakeClient)
    monkeypatch.setattr("codebloodhound.cli.console", Console(width=160))
    runner = CliRunner()

    result = runner.invoke(app, ["forks", "Jride-Dev/CodeBloodHound", "--audit-license"])

    assert result.exit_code == 0
    assert "fork/cbh" in result.output
    assert "BSD" in result.output
    assert "changed" in result.output
    assert "HIGH" in result.output


def test_forks_command_accepts_audit_readme(monkeypatch) -> None:
    class FakeClient:
        def list_forks(self, owner_repo: str) -> list[GitHubRepo]:
            return []

        def get_repo_readme(self, owner_repo: str) -> dict[str, bool | str | None]:
            return _readme("Source README")

    monkeypatch.setattr("codebloodhound.cli.GitHubClient", FakeClient)
    monkeypatch.setattr("codebloodhound.cli.console", Console(width=180))
    runner = CliRunner()

    result = runner.invoke(app, ["forks", "Jride-Dev/CodeBloodHound", "--audit-readme"])

    assert result.exit_code == 0
    assert "Source README" in result.output
    assert "README.md" in result.output
    assert "No forks found" in result.output


def test_forks_command_accepts_license_and_readme_audits(monkeypatch) -> None:
    fork = _repo("fork/cbh")

    class FakeClient:
        def list_forks(self, owner_repo: str) -> list[GitHubRepo]:
            return [fork]

        def get_repo_license(self, owner_repo: str) -> dict[str, bool | str | None]:
            return _license("mit", "MIT", "MIT License")

        def get_repo_readme(self, owner_repo: str) -> dict[str, bool | str | None]:
            if owner_repo == "Jride-Dev/CodeBloodHound":
                return _readme("Source README")
            return _readme("Fork credits Jride-Dev/CodeBloodHound.")

    monkeypatch.setattr("codebloodhound.cli.GitHubClient", FakeClient)
    monkeypatch.setattr("codebloodhound.cli.console", Console(width=180))
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["forks", "Jride-Dev/CodeBloodHound", "--audit-license", "--audit-readme"],
    )

    assert result.exit_code == 0
    assert "Source license" in result.output
    assert "Source README" in result.output
    assert "same" in result.output
    assert "preserved" in result.output


def test_render_forks_handles_readme_status_columns() -> None:
    fork = _repo("fork/cbh")
    console = Console(record=True, width=140)

    render_forks(
        [fork],
        console=console,
        source_readme=_readme("Source README"),
        readme_results={
            fork.full_name: {
                "readme": _readme("No attribution here."),
                "comparison": {
                    "status": "missing-attribution",
                    "severity": "high",
                    "summary": "Missing attribution.",
                },
            }
        },
    )

    output = console.export_text()

    assert "README Status" in output
    assert "README Risk" in output
    assert "missing-attribution" in output
    assert "HIGH" in output


def _repo(full_name: str) -> GitHubRepo:
    owner, name = full_name.split("/", 1)
    return GitHubRepo(
        id=1,
        name=name,
        full_name=full_name,
        owner={"login": owner, "html_url": f"https://github.com/{owner}"},
        html_url=f"https://github.com/{full_name}",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        pushed_at=datetime(2026, 1, 2, tzinfo=UTC),
        stargazers_count=3,
        default_branch="main",
    )


def _license(key: str, spdx_id: str, name: str) -> dict[str, bool | str | None]:
    return {
        "found": True,
        "key": key,
        "spdx_id": spdx_id,
        "name": name,
        "html_url": f"https://github.com/license/{key}",
        "error": None,
    }


def _readme(content: str) -> dict[str, bool | str | None]:
    return {
        "found": True,
        "name": "README.md",
        "path": "README.md",
        "html_url": "https://github.com/example/repo/blob/main/README.md",
        "download_url": "https://raw.githubusercontent.com/example/repo/main/README.md",
        "content_text": content,
        "error": None,
    }
