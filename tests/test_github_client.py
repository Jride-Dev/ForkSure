import pytest

from codebloodhound.github_client import InvalidOwnerRepoError, parse_owner_repo


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
