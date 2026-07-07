from __future__ import annotations

from typing import Any

from codebloodhound.rare_string_scanner import (
    extract_rare_strings_from_text,
    merge_rare_string_matches,
    scan_rare_string_matches,
)


def test_rare_string_extraction_ignores_generic_markdown_badges_and_urls() -> None:
    text = """
# Installation
[![build](https://img.shields.io/badge/build-passing-green.svg)](https://example.com)
https://github.com/example/project
pip install example
CodeBloodHound correlates fork provenance with license drift evidence.
"""

    strings = extract_rare_strings_from_text(text)

    assert strings == ["CodeBloodHound correlates fork provenance with license drift evidence."]


def test_rare_string_extraction_is_deterministic_for_project_phrases() -> None:
    text = """
CodeBloodHound correlates fork provenance with license drift evidence.
Repository provenance checks highlight possible imposter packages for manual review.
The token is optional
"""

    first = extract_rare_strings_from_text(text)
    second = extract_rare_strings_from_text(text)

    assert first == second
    assert "CodeBloodHound correlates fork provenance with license drift evidence." in first
    assert "Repository provenance checks highlight possible imposter packages for manual review." in first


def test_rare_string_scan_excludes_source_repo_itself() -> None:
    client = FakeRareStringClient(
        [
            _code_result("Jride-Dev/CodeBloodHound"),
            _code_result("other/CodeBloodHound"),
        ]
    )

    matches = scan_rare_string_matches("Jride-Dev/CodeBloodHound", client, max_strings=1)

    assert [match["repository_full_name"] for match in matches] == ["other/CodeBloodHound"]


def test_rare_string_scan_deduplicates_repositories() -> None:
    client = FakeRareStringClient(
        [
            _code_result("other/CodeBloodHound", path="README.md"),
            _code_result("other/CodeBloodHound", path="docs/overview.md"),
        ]
    )

    matches = scan_rare_string_matches("Jride-Dev/CodeBloodHound", client, max_strings=1)

    assert len(matches) == 1
    assert matches[0]["repository_full_name"] == "other/CodeBloodHound"
    assert len(matches[0]["rare_string_matches"]) == 2


def test_rare_string_scan_assigns_high_for_multiple_non_fork_matches() -> None:
    client = FakeRareStringClient(
        [_code_result("other/CodeBloodHound")],
        readme_text="""
CodeBloodHound correlates fork provenance with license drift evidence.
Repository provenance checks highlight possible imposter packages for manual review.
""",
    )

    matches = scan_rare_string_matches("Jride-Dev/CodeBloodHound", client, max_strings=2)

    assert matches[0]["risk_level"] == "HIGH"
    assert matches[0]["score"] == 85


def test_merge_rare_string_matches_adds_rare_only_candidate() -> None:
    merged = merge_rare_string_matches(
        [],
        [
            {
                "repository_full_name": "other/CodeBloodHound",
                "repository_html_url": "https://github.com/other/CodeBloodHound",
                "fork": False,
                "rare_string_matches": [
                    {
                        "matched_string": "CodeBloodHound correlates fork provenance with license drift evidence.",
                        "file_path": "README.md",
                        "file_html_url": "https://github.com/other/CodeBloodHound/blob/main/README.md",
                        "reason": "Rare source phrase found in candidate repository.",
                    }
                ],
                "reason": "Rare source phrase found in candidate repository.",
                "risk_level": "MEDIUM",
                "score": 60,
            }
        ],
    )

    assert merged[0]["full_name"] == "other/CodeBloodHound"
    assert merged[0]["classification"] == "possible-imposter"
    assert merged[0]["rare_string_matches"]


class FakeRareStringClient:
    def __init__(self, results: list[dict[str, Any]], *, readme_text: str | None = None) -> None:
        self.results = results
        self.readme_text = readme_text or "CodeBloodHound correlates fork provenance with license drift evidence."

    def get_repo_readme(self, owner_repo: str) -> dict[str, Any]:
        return {
            "found": True,
            "name": "README.md",
            "path": "README.md",
            "html_url": f"https://github.com/{owner_repo}/blob/main/README.md",
            "download_url": f"https://raw.githubusercontent.com/{owner_repo}/main/README.md",
            "content_text": self.readme_text,
            "error": None,
        }

    def search_code(self, query: str, *, per_page: int = 10, max_pages: int = 1) -> list[dict[str, Any]]:
        return self.results


def _code_result(full_name: str, *, path: str = "README.md", fork: bool = False) -> dict[str, Any]:
    return {
        "name": path.rsplit("/", 1)[-1],
        "path": path,
        "html_url": f"https://github.com/{full_name}/blob/main/{path}",
        "repository_full_name": full_name,
        "repository_html_url": f"https://github.com/{full_name}",
        "repository_fork": fork,
        "repository_owner": full_name.split("/", 1)[0],
    }
