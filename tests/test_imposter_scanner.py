from __future__ import annotations

from typing import Any

from codebloodhound.imposter_scanner import (
    README_EXCERPT_LENGTH,
    classify_imposter_candidate,
    generate_name_variants,
    scan_imposters,
    score_name_similarity,
)


def test_name_variant_generation_is_deterministic() -> None:
    assert generate_name_variants("CodeBloodHound") == [
        "CodeBloodHound",
        "Code-BloodHound",
        "Code_BloodHound",
        "CodeBlood-Hound",
        "CodeBloodhound",
        "codebloodhound",
        "CodeBloodHoundPro",
        "CodeBloodHound-Scanner",
        "CodeBloodHound-Tool",
    ]


def test_exact_same_name_under_different_owner_scores_high() -> None:
    result = score_name_similarity("CodeBloodHound", "CodeBloodHound")

    assert result["risk_level"] == "HIGH"
    assert result["score"] >= 80


def test_punctuation_case_normalized_match_scores_high() -> None:
    result = score_name_similarity("CodeBloodHound", "code-blood-hound")

    assert result["risk_level"] == "HIGH"
    assert result["score"] >= 80


def test_contained_target_name_scores_medium() -> None:
    result = score_name_similarity("CodeBloodHound", "CodeBloodHoundPro")

    assert result["risk_level"] == "MEDIUM"


def test_weak_unrelated_name_scores_low_or_info() -> None:
    result = score_name_similarity("CodeBloodHound", "requests")

    assert result["risk_level"] in {"LOW", "INFO"}


def test_same_name_same_domain_candidate_classifies_as_possible_imposter() -> None:
    candidate = _repo(
        "other/CodeBloodHound",
        "CodeBloodHound",
        description="Supply chain SAST and secrets scanning for repository provenance.",
    )
    candidate["score"] = 95

    result = classify_imposter_candidate("Jride-Dev/CodeBloodHound", candidate)

    assert result["classification"] == "possible-imposter"
    assert result["risk_level"] == "HIGH"


def test_exact_name_unrelated_description_classifies_as_name_collision() -> None:
    candidate = _repo("other/CodeBloodHound", "CodeBloodHound", description="A tabletop campaign journal.")
    candidate["score"] = 95

    result = classify_imposter_candidate("Jride-Dev/CodeBloodHound", candidate)

    assert result["classification"] == "name-collision"
    assert result["risk_level"] == "LOW"


def test_official_fork_lowers_risk() -> None:
    candidate = _repo("other/CodeBloodHound", "CodeBloodHound", fork=True)
    candidate["score"] = 95

    result = classify_imposter_candidate("Jride-Dev/CodeBloodHound", candidate)

    assert result["classification"] == "official-fork"
    assert result["risk_level"] == "INFO"


def test_weak_fuzzy_candidate_remains_low_risk() -> None:
    candidate = _repo("other/BloodHound", "BloodHound")
    candidate["score"] = 35

    result = classify_imposter_candidate("Jride-Dev/CodeBloodHound", candidate)

    assert result["classification"] == "weak-similarity"
    assert result["risk_level"] == "LOW"


def test_scan_imposters_excludes_source_repo_itself() -> None:
    client = FakeSearchClient(
        [
            _repo("Jride-Dev/CodeBloodHound", "CodeBloodHound"),
            _repo("other/CodeBloodHound", "CodeBloodHound"),
        ]
    )

    candidates = scan_imposters("Jride-Dev/CodeBloodHound", client)

    assert [candidate["full_name"] for candidate in candidates] == ["other/CodeBloodHound"]


def test_scan_imposters_deduplicates_repeated_search_results() -> None:
    client = FakeSearchClient(
        [
            _repo("other/CodeBloodHound", "CodeBloodHound"),
            _repo("other/CodeBloodHound", "CodeBloodHound"),
        ]
    )

    candidates = scan_imposters("Jride-Dev/CodeBloodHound", client)

    assert len(candidates) == 1
    assert candidates[0]["full_name"] == "other/CodeBloodHound"
    assert candidates[0]["classification"] == "name-collision"
    assert candidates[0]["score"] >= 80


def test_scan_imposters_enriches_license_and_readme() -> None:
    client = FakeSearchClient([_repo("other/CodeBloodHound", "CodeBloodHound")], enrich=True)

    candidates = scan_imposters("Jride-Dev/CodeBloodHound", client)

    assert candidates[0]["license_key"] == "mit"
    assert candidates[0]["license_name"] == "MIT License"
    assert candidates[0]["readme_status"] == "found"
    assert "dependency scanning" in candidates[0]["readme_text_excerpt"]
    assert candidates[0]["readme_excerpt_truncated"] is False
    assert candidates[0]["readme_html_url"] == "https://github.com/other/CodeBloodHound/blob/main/README.md"


def test_scan_imposters_marks_long_readme_excerpt_as_truncated() -> None:
    readme_text = "First line\n" + ("A" * (README_EXCERPT_LENGTH + 100))
    client = FakeSearchClient([_repo("other/CodeBloodHound", "CodeBloodHound")], enrich=True, readme_text=readme_text)

    candidates = scan_imposters("Jride-Dev/CodeBloodHound", client)

    assert candidates[0]["readme_excerpt_truncated"] is True
    assert candidates[0]["readme_text_excerpt"].startswith("First line\n")
    assert len(candidates[0]["readme_text_excerpt"]) <= README_EXCERPT_LENGTH


class FakeSearchClient:
    def __init__(self, results: list[dict[str, Any]], *, enrich: bool = False, readme_text: str | None = None) -> None:
        self.results = results
        self.enrich = enrich
        self.readme_text = readme_text or "A dependency scanning and vulnerability provenance tool."

    def search_repositories(self, query: str, *, per_page: int = 20, max_pages: int = 1) -> list[dict[str, Any]]:
        return self.results

    def get_repo_license(self, owner_repo: str) -> dict[str, Any]:
        if not self.enrich:
            return {"found": False, "key": None, "name": None, "error": None}
        return {
            "found": True,
            "key": "mit",
            "spdx_id": "MIT",
            "name": "MIT License",
            "html_url": f"https://github.com/{owner_repo}/blob/main/LICENSE",
            "error": None,
        }

    def get_repo_readme(self, owner_repo: str) -> dict[str, Any]:
        if not self.enrich:
            return {
                "found": False,
                "name": None,
                "path": None,
                "html_url": None,
                "download_url": None,
                "content_text": None,
                "error": None,
            }
        return {
            "found": True,
            "name": "README.md",
            "path": "README.md",
            "html_url": f"https://github.com/{owner_repo}/blob/main/README.md",
            "download_url": f"https://raw.githubusercontent.com/{owner_repo}/main/README.md",
            "content_text": self.readme_text,
            "error": None,
        }


def _repo(full_name: str, name: str, *, fork: bool = False, description: str | None = None) -> dict[str, Any]:
    owner = full_name.split("/", 1)[0]
    return {
        "full_name": full_name,
        "name": name,
        "owner": owner,
        "html_url": f"https://github.com/{full_name}",
        "description": description,
        "fork": fork,
        "created_at": "2026-01-01T00:00:00Z",
        "pushed_at": "2026-01-02T00:00:00Z",
        "stargazers_count": 1,
        "default_branch": "main",
        "license_key": None,
        "license_name": None,
        "topics": [],
    }
