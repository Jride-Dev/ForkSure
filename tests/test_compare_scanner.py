from datetime import UTC, datetime
from typing import Any

from forksure.compare_scanner import compare_repositories
from forksure.github_client import GitHubRepo


def test_compare_repositories_returns_structured_result() -> None:
    client = FakeCompareClient()

    result = compare_repositories("Jride-Dev/ForkSure", "other/ForkSure", client)

    assert result["source"]["full_name"] == "Jride-Dev/ForkSure"
    assert result["candidate"]["full_name"] == "other/ForkSure"
    assert result["name_similarity"]["score"] >= 80
    assert result["license_comparison"]["status"] == "same"
    assert result["readme_comparison"]["status"] == "preserved"
    assert "metadata_summary" in result
    assert "reasons" in result


def test_changed_license_produces_high_risk() -> None:
    client = FakeCompareClient(candidate_license=_license("apache-2.0", "Apache-2.0", "Apache License 2.0"))

    result = compare_repositories("Jride-Dev/ForkSure", "other/ForkSure", client)

    assert result["license_comparison"]["status"] == "changed"
    assert result["overall_risk"] == "HIGH"


def test_missing_license_produces_medium_risk() -> None:
    client = FakeCompareClient(candidate_license=_missing_license())

    result = compare_repositories("Jride-Dev/ForkSure", "other/ForkSure", client)

    assert result["license_comparison"]["status"] == "missing"
    assert result["overall_risk"] == "MEDIUM"


def test_missing_readme_attribution_high_when_name_is_similar() -> None:
    client = FakeCompareClient(candidate_readme=_readme("Independent project without upstream mention."))

    result = compare_repositories("Jride-Dev/ForkSure", "other/ForkSure", client)

    assert result["readme_comparison"]["status"] == "missing-attribution"
    assert result["overall_risk"] == "HIGH"


def test_official_fork_lowers_risk() -> None:
    client = FakeCompareClient(candidate_repo=_repo("other/ForkSure", fork=True))

    result = compare_repositories("Jride-Dev/ForkSure", "other/ForkSure", client)

    assert result["candidate"]["fork"] is True
    assert result["overall_risk"] == "INFO"


class FakeCompareClient:
    def __init__(
        self,
        *,
        source_repo: GitHubRepo | None = None,
        candidate_repo: GitHubRepo | None = None,
        source_license: dict[str, Any] | None = None,
        candidate_license: dict[str, Any] | None = None,
        source_readme: dict[str, Any] | None = None,
        candidate_readme: dict[str, Any] | None = None,
    ) -> None:
        self.repos = {
            "Jride-Dev/ForkSure": source_repo or _repo("Jride-Dev/ForkSure"),
            "other/ForkSure": candidate_repo or _repo("other/ForkSure"),
        }
        self.licenses = {
            "Jride-Dev/ForkSure": source_license or _license("mit", "MIT", "MIT License"),
            "other/ForkSure": candidate_license or _license("mit", "MIT", "MIT License"),
        }
        self.readmes = {
            "Jride-Dev/ForkSure": source_readme or _readme("ForkSure source README."),
            "other/ForkSure": candidate_readme or _readme("Fork credits Jride-Dev/ForkSure."),
        }

    def get_repo(self, owner_repo: str) -> GitHubRepo:
        return self.repos[owner_repo]

    def get_repo_license(self, owner_repo: str) -> dict[str, Any]:
        return self.licenses[owner_repo]

    def get_repo_readme(self, owner_repo: str) -> dict[str, Any]:
        return self.readmes[owner_repo]


def _repo(full_name: str, *, fork: bool = False, description: str = "Repository provenance scanner.") -> GitHubRepo:
    owner, name = full_name.split("/", 1)
    return GitHubRepo(
        id=1,
        name=name,
        full_name=full_name,
        owner={"login": owner, "html_url": f"https://github.com/{owner}"},
        html_url=f"https://github.com/{full_name}",
        description=description,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        pushed_at=datetime(2026, 1, 2, tzinfo=UTC),
        stargazers_count=7,
        default_branch="main",
        fork=fork,
    )


def _license(key: str, spdx_id: str, name: str) -> dict[str, Any]:
    return {
        "found": True,
        "key": key,
        "spdx_id": spdx_id,
        "name": name,
        "html_url": f"https://github.com/license/{key}",
        "error": None,
    }


def _missing_license() -> dict[str, Any]:
    return {
        "found": False,
        "key": None,
        "spdx_id": None,
        "name": None,
        "html_url": None,
        "error": None,
    }


def _readme(content: str) -> dict[str, Any]:
    return {
        "found": True,
        "name": "README.md",
        "path": "README.md",
        "html_url": "https://github.com/example/repo/blob/main/README.md",
        "download_url": "https://raw.githubusercontent.com/example/repo/main/README.md",
        "content_text": content,
        "error": None,
    }
