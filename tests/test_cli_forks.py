from datetime import UTC, datetime

from typer.testing import CliRunner

from codebloodhound.cli import app
from codebloodhound.github_client import GitHubRepo


def test_forks_command_accepts_audit_license(monkeypatch) -> None:
    class FakeClient:
        def list_forks(self, owner_repo: str) -> list[GitHubRepo]:
            return []

        def get_repo_license(self, owner_repo: str) -> dict[str, bool | str | None]:
            return _license("mit", "MIT", "MIT License")

    monkeypatch.setattr("codebloodhound.cli.GitHubClient", FakeClient)
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
    runner = CliRunner()

    result = runner.invoke(app, ["forks", "Jride-Dev/CodeBloodHound", "--audit-license"])

    assert result.exit_code == 0
    assert "fork/cbh" in result.output
    assert "BSD" in result.output
    assert "changed" in result.output
    assert "HIGH" in result.output


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
