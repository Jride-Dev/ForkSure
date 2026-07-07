import pytest

from codebloodhound.github_client import GitHubClient, GitHubNotFoundError, InvalidOwnerRepoError, parse_owner_repo


def test_parse_owner_repo_accepts_owner_and_repo() -> None:
    parsed = parse_owner_repo("openai/codex")

    assert parsed.owner == "openai"
    assert parsed.repo == "codex"
    assert parsed.slug == "openai/codex"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "openai",
        "openai/",
        "/codex",
        "openai/codex/extra",
        "https://github.com/openai/codex",
    ],
)
def test_parse_owner_repo_rejects_invalid_values(value: str) -> None:
    with pytest.raises(InvalidOwnerRepoError):
        parse_owner_repo(value)


def test_get_repo_license_404_becomes_not_found(monkeypatch) -> None:
    client = GitHubClient(token="")

    def raise_not_found(*args, **kwargs):
        raise GitHubNotFoundError("Repository license not found.")

    monkeypatch.setattr(client, "_request", raise_not_found)

    license_data = client.get_repo_license("openai/codex")

    assert license_data["found"] is False
    assert license_data["key"] is None
    assert license_data["spdx_id"] is None
    assert license_data["name"] is None
    assert license_data["html_url"] is None
    assert license_data["error"] is None
