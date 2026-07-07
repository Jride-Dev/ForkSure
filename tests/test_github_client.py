import base64

import pytest

from forksure.github_client import GitHubAPIError, GitHubClient, GitHubNotFoundError, InvalidOwnerRepoError, parse_owner_repo


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


def test_get_repo_readme_404_becomes_not_found(monkeypatch) -> None:
    client = GitHubClient(token="")

    def raise_not_found(*args, **kwargs):
        raise GitHubNotFoundError("Repository README not found.")

    monkeypatch.setattr(client, "_request", raise_not_found)

    readme_data = client.get_repo_readme("openai/codex")

    assert readme_data["found"] is False
    assert readme_data["name"] is None
    assert readme_data["path"] is None
    assert readme_data["html_url"] is None
    assert readme_data["download_url"] is None
    assert readme_data["content_text"] is None
    assert readme_data["error"] is None


def test_get_repo_readme_decodes_base64_content(monkeypatch) -> None:
    client = GitHubClient(token="")
    content = base64.b64encode(b"# Project\n\nUpstream: owner/repo\n").decode("ascii")

    def fake_request(*args, **kwargs):
        return {
            "name": "README.md",
            "path": "README.md",
            "html_url": "https://github.com/owner/repo/blob/main/README.md",
            "download_url": "https://raw.githubusercontent.com/owner/repo/main/README.md",
            "content": content,
        }

    monkeypatch.setattr(client, "_request", fake_request)

    readme_data = client.get_repo_readme("owner/repo")

    assert readme_data["found"] is True
    assert readme_data["name"] == "README.md"
    assert readme_data["path"] == "README.md"
    assert readme_data["content_text"] == "# Project\n\nUpstream: owner/repo\n"
    assert readme_data["error"] is None


def test_search_repositories_handles_api_error_gracefully(monkeypatch) -> None:
    client = GitHubClient(token="")

    def raise_api_error(*args, **kwargs):
        raise GitHubAPIError("Search failed.")

    monkeypatch.setattr(client, "_request", raise_api_error)

    assert client.search_repositories("ForkSure in:name") == []


def test_search_code_handles_api_error_gracefully(monkeypatch) -> None:
    client = GitHubClient(token="")

    def raise_api_error(*args, **kwargs):
        raise GitHubAPIError("Code search failed.")

    monkeypatch.setattr(client, "_request", raise_api_error)

    assert client.search_code('"rare phrase"') == []
