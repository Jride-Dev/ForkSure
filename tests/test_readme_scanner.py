from codebloodhound.readme_scanner import compare_readme_attribution


def test_readme_attribution_preserved_with_owner_repo() -> None:
    result = compare_readme_attribution(
        "Jride-Dev/CodeBloodHound",
        _readme("Source README"),
        _readme("This fork is based on Jride-Dev/CodeBloodHound."),
    )

    assert result["status"] == "preserved"
    assert result["severity"] == "info"


def test_readme_attribution_preserved_with_full_github_url() -> None:
    result = compare_readme_attribution(
        "Jride-Dev/CodeBloodHound",
        _readme("Source README"),
        _readme("Upstream: https://github.com/Jride-Dev/CodeBloodHound"),
    )

    assert result["status"] == "preserved"
    assert result["severity"] == "info"


def test_missing_fork_readme_is_medium() -> None:
    result = compare_readme_attribution(
        "Jride-Dev/CodeBloodHound",
        _readme("Source README"),
        _missing_readme(),
    )

    assert result["status"] == "missing-readme"
    assert result["severity"] == "medium"


def test_fork_readme_without_attribution_is_high() -> None:
    result = compare_readme_attribution(
        "Jride-Dev/CodeBloodHound",
        _readme("Source README"),
        _readme("A renamed project with no upstream credit."),
    )

    assert result["status"] == "missing-attribution"
    assert result["severity"] == "high"


def test_missing_source_readme_is_unknown_low() -> None:
    result = compare_readme_attribution(
        "Jride-Dev/CodeBloodHound",
        _missing_readme(),
        _readme("Fork README"),
    )

    assert result["status"] == "unknown"
    assert result["severity"] == "low"


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


def _missing_readme() -> dict[str, bool | str | None]:
    return {
        "found": False,
        "name": None,
        "path": None,
        "html_url": None,
        "download_url": None,
        "content_text": None,
        "error": None,
    }
