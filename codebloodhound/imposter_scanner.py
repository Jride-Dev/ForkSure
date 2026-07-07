from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any

from .github_client import GitHubClient, parse_owner_repo


RISK_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def generate_name_variants(repo_name: str) -> list[str]:
    tokens = _split_name_tokens(repo_name)
    variants = [repo_name]

    if len(tokens) >= 2:
        variants.append(f"{tokens[0]}-{''.join(tokens[1:])}")
        variants.append(f"{tokens[0]}_{''.join(tokens[1:])}")
        variants.append(f"{''.join(tokens[:-1])}-{tokens[-1]}")
        variants.append(f"{''.join(tokens[:-1])}{tokens[-1].lower()}")

    variants.extend(
        [
            repo_name.lower(),
            f"{repo_name}Pro",
            f"{repo_name}-Scanner",
            f"{repo_name}-Tool",
        ]
    )

    return _dedupe_preserving_order(variants)


def score_name_similarity(target_name: str, candidate_name: str, *, fork: bool = False) -> dict[str, Any]:
    target_normalized = _normalize_name(target_name)
    candidate_normalized = _normalize_name(candidate_name)
    target_tokens = _normalized_tokens(target_name)
    candidate_tokens = _normalized_tokens(candidate_name)
    ratio = SequenceMatcher(None, target_normalized, candidate_normalized).ratio()
    score = 0
    reasons: list[str] = []

    if candidate_name == target_name:
        score = 95
        reasons.append("Exact repository name match under a different owner.")
    elif candidate_normalized == target_normalized:
        score = 90
        reasons.append("Repository name matches after case and punctuation normalization.")
    elif target_normalized and target_normalized in candidate_normalized:
        score = 70
        reasons.append("Candidate name contains the target repository name.")
    elif target_tokens and sorted(target_tokens) == sorted(candidate_tokens):
        score = 65
        reasons.append("Candidate name uses the target tokens rearranged or separated.")
    elif ratio >= 0.72:
        score = 35
        reasons.append("Candidate name has weak fuzzy similarity.")
    else:
        score = 5
        reasons.append("Candidate has little name similarity.")

    if fork and score < 90:
        score = max(0, score - 20)
        reasons.append("Candidate is marked as a fork by GitHub, lowering name-similarity risk.")

    return {
        "score": score,
        "risk_level": _risk_level(score),
        "reasons": reasons,
    }


def scan_imposters(owner_repo: str, github_client: GitHubClient) -> list[dict[str, Any]]:
    source = parse_owner_repo(owner_repo)
    source_full_name = source.slug.casefold()
    candidates_by_full_name: dict[str, dict[str, Any]] = {}

    for variant in generate_name_variants(source.repo):
        for item in github_client.search_repositories(f"{variant} in:name", per_page=20, max_pages=1):
            full_name = str(item.get("full_name") or "")
            if not full_name or full_name.casefold() == source_full_name:
                continue
            candidates_by_full_name.setdefault(full_name.casefold(), item)

    candidates: list[dict[str, Any]] = []
    for item in candidates_by_full_name.values():
        score = score_name_similarity(source.repo, str(item.get("name") or ""), fork=bool(item.get("fork")))
        candidates.append(
            {
                **item,
                "score": score["score"],
                "risk_level": score["risk_level"],
                "reasons": score["reasons"],
            }
        )

    return sorted(
        candidates,
        key=lambda candidate: (
            RISK_ORDER.get(str(candidate.get("risk_level")), 0),
            int(candidate.get("score") or 0),
            int(candidate.get("stargazers_count") or 0),
        ),
        reverse=True,
    )


def _split_name_tokens(value: str) -> list[str]:
    parts = re.split(r"[-_\s.]+", value)
    tokens: list[str] = []
    for part in parts:
        tokens.extend(re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", part))
    return tokens or [value]


def _normalized_tokens(value: str) -> list[str]:
    return [_normalize_name(token) for token in _split_name_tokens(value) if _normalize_name(token)]


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _risk_level(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped
