from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any

from .github_client import GitHubClient, parse_owner_repo


RISK_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
DOMAIN_TERMS = (
    "supply chain",
    "sast",
    "secrets",
    "dependency scanning",
    "vulnerability",
    "provenance",
    "code scanning",
)
README_EXCERPT_LENGTH = 360


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


def classify_imposter_candidate(target_owner_repo: str, candidate: dict) -> dict[str, Any]:
    source = parse_owner_repo(target_owner_repo)
    candidate_name = str(candidate.get("name") or str(candidate.get("full_name") or "").split("/")[-1])
    score = int(candidate.get("score") or 0)
    exact_name = candidate_name == source.repo
    normalized_match = _normalize_name(candidate_name) == _normalize_name(source.repo)
    same_domain_terms = _matched_domain_terms(candidate)
    reasons: list[str] = []

    if candidate.get("fork"):
        return {
            "classification": "official-fork",
            "risk_level": "INFO",
            "reasons": ["GitHub marks this candidate as a fork, lowering independent name-collision risk."],
        }

    if exact_name or normalized_match:
        reasons.append("Repository name matches the target name.")
        if same_domain_terms:
            reasons.append(f"Description, README, or topics include related security terms: {', '.join(same_domain_terms)}.")
            reasons.append("Manual review is required to determine whether the similarity is expected.")
            return {
                "classification": "possible-imposter",
                "risk_level": "HIGH",
                "reasons": reasons,
            }
        return {
            "classification": "name-collision",
            "risk_level": "LOW",
            "reasons": reasons + ["No same-domain scanner language was found in available metadata."],
        }

    if same_domain_terms:
        return {
            "classification": "same-domain-candidate",
            "risk_level": "MEDIUM",
            "reasons": [f"Metadata includes related security terms: {', '.join(same_domain_terms)}."],
        }

    if score < 50:
        return {
            "classification": "weak-similarity",
            "risk_level": "LOW",
            "reasons": ["Name similarity is weak; treat as a low-priority candidate."],
        }

    if score >= 50:
        return {
            "classification": "name-collision",
            "risk_level": "LOW",
            "reasons": ["Name similarity is present, but available metadata does not show same-domain scanner language."],
        }

    return {
        "classification": "unknown",
        "risk_level": "INFO",
        "reasons": ["Available metadata is not enough to classify this candidate."],
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
        enriched = _enrich_candidate(item, github_client)
        score = score_name_similarity(source.repo, str(enriched.get("name") or ""), fork=bool(enriched.get("fork")))
        enriched["score"] = score["score"]
        enriched["name_similarity_risk_level"] = score["risk_level"]
        enriched["name_similarity_reasons"] = score["reasons"]
        classification = classify_imposter_candidate(owner_repo, enriched)
        enriched["classification"] = classification["classification"]
        enriched["risk_level"] = classification["risk_level"]
        enriched["classification_reasons"] = classification["reasons"]
        enriched["reasons"] = _dedupe_preserving_order([*classification["reasons"], *score["reasons"]])
        candidates.append(enriched)

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


def _enrich_candidate(candidate: dict[str, Any], github_client: GitHubClient) -> dict[str, Any]:
    enriched = {
        "full_name": str(candidate.get("full_name") or ""),
        "name": str(candidate.get("name") or ""),
        "owner": str(candidate.get("owner") or ""),
        "html_url": str(candidate.get("html_url") or ""),
        "description": candidate.get("description"),
        "fork": bool(candidate.get("fork", False)),
        "created_at": candidate.get("created_at"),
        "pushed_at": candidate.get("pushed_at"),
        "stargazers_count": int(candidate.get("stargazers_count") or 0),
        "default_branch": str(candidate.get("default_branch") or ""),
        "license_key": candidate.get("license_key"),
        "license_name": candidate.get("license_name"),
        "topics": candidate.get("topics") if isinstance(candidate.get("topics"), list) else [],
        "readme_status": "unknown",
        "readme_text_excerpt": None,
    }
    full_name = enriched["full_name"]

    if full_name and hasattr(github_client, "get_repo_license") and not enriched["license_key"]:
        try:
            license_data = github_client.get_repo_license(full_name)
        except Exception:
            license_data = {"found": False, "error": "License lookup failed."}
        if license_data.get("found"):
            enriched["license_key"] = license_data.get("key")
            enriched["license_name"] = license_data.get("name")

    if full_name and hasattr(github_client, "get_repo_readme"):
        try:
            readme_data = github_client.get_repo_readme(full_name)
        except Exception:
            readme_data = {"found": False, "error": "README lookup failed."}
        if readme_data.get("found"):
            enriched["readme_status"] = "found"
            enriched["readme_text_excerpt"] = _excerpt(str(readme_data.get("content_text") or ""))
        elif readme_data.get("error"):
            enriched["readme_status"] = "unknown"
        else:
            enriched["readme_status"] = "missing"

    return enriched


def _matched_domain_terms(candidate: dict) -> list[str]:
    text_parts = [
        str(candidate.get("description") or ""),
        str(candidate.get("readme_text_excerpt") or ""),
        " ".join(str(topic) for topic in candidate.get("topics") or []),
    ]
    normalized_text = _normalize_domain_text(" ".join(text_parts))
    matches: list[str] = []
    for term in DOMAIN_TERMS:
        if _normalize_domain_text(term) in normalized_text:
            matches.append(term)
    return matches


def _excerpt(value: str) -> str | None:
    compact = " ".join(value.split())
    if not compact:
        return None
    if len(compact) <= README_EXCERPT_LENGTH:
        return compact
    return f"{compact[:README_EXCERPT_LENGTH].rstrip()}..."


def _normalize_domain_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


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
