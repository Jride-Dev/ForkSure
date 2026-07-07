from __future__ import annotations

from typing import Any

from codebloodhound.imposter_scanner import generate_name_variants, scan_imposters, score_name_similarity


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
    assert candidates[0]["risk_level"] == "HIGH"


class FakeSearchClient:
    def __init__(self, results: list[dict[str, Any]]) -> None:
        self.results = results

    def search_repositories(self, query: str, *, per_page: int = 20, max_pages: int = 1) -> list[dict[str, Any]]:
        return self.results


def _repo(full_name: str, name: str, *, fork: bool = False) -> dict[str, Any]:
    owner = full_name.split("/", 1)[0]
    return {
        "full_name": full_name,
        "name": name,
        "owner": owner,
        "html_url": f"https://github.com/{full_name}",
        "description": None,
        "fork": fork,
        "created_at": "2026-01-01T00:00:00Z",
        "pushed_at": "2026-01-02T00:00:00Z",
        "stargazers_count": 1,
        "default_branch": "main",
    }
