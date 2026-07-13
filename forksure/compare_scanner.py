from __future__ import annotations

import re
from typing import Any, Mapping

from .github_client import GitHubClient, GitHubRepo
from .imposter_scanner import score_name_similarity
from .license_scanner import compare_licenses, format_license
from .readme_scanner import compare_readme_attribution


RISK_ORDER = {"not scanned": -1, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
RISK_LABELS = {
    "name": "Name / imposter",
    "readme": "README attribution",
    "license": "License",
    "similarity": "Code similarity",
    "security": "Security",
}


def compare_repositories(source_repo: str, candidate_repo: str, github_client: GitHubClient) -> dict[str, Any]:
    source_metadata = github_client.get_repo(source_repo)
    candidate_metadata = github_client.get_repo(candidate_repo)
    source_license = github_client.get_repo_license(source_repo)
    candidate_license = github_client.get_repo_license(candidate_repo)
    source_readme = github_client.get_repo_readme(source_repo)
    candidate_readme = github_client.get_repo_readme(candidate_repo)

    source = _repo_summary(source_metadata, license_data=source_license, readme_data=source_readme)
    candidate = _repo_summary(candidate_metadata, license_data=candidate_license, readme_data=candidate_readme)
    name_similarity = score_name_similarity(
        source_metadata.name,
        candidate_metadata.name,
        fork=candidate_metadata.fork,
    )
    license_comparison = compare_licenses(source_license, candidate_license)
    readme_comparison = compare_readme_attribution(source_repo, source_readme, candidate_readme)
    comparison = {
        "source": source,
        "candidate": candidate,
        "name_similarity": name_similarity,
        "license_comparison": license_comparison,
        "readme_comparison": readme_comparison,
        "metadata_summary": {
            "source_created_at": source["created_at"],
            "source_pushed_at": source["pushed_at"],
            "source_stars": source["stargazers_count"],
            "source_default_branch": source["default_branch"],
            "source_description": source["description"],
            "candidate_created_at": candidate["created_at"],
            "candidate_pushed_at": candidate["pushed_at"],
            "candidate_stars": candidate["stargazers_count"],
            "candidate_default_branch": candidate["default_branch"],
            "candidate_description": candidate["description"],
            "candidate_fork": candidate["fork"],
        },
    }
    return _with_risk_breakdown(comparison)


def add_similarity_to_comparison(comparison: Mapping[str, Any], similarity: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(comparison)
    result["similarity"] = dict(similarity)
    return _with_risk_breakdown(result)


def _repo_summary(
    repo: GitHubRepo,
    *,
    license_data: Mapping[str, Any],
    readme_data: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "name": repo.name,
        "full_name": repo.full_name,
        "html_url": str(repo.html_url),
        "description": _optional_text(getattr(repo, "description", None)),
        "fork": repo.fork,
        "created_at": _format_date(repo.created_at),
        "pushed_at": _format_date(repo.pushed_at),
        "stargazers_count": repo.stargazers_count,
        "default_branch": repo.default_branch,
        "license": dict(license_data),
        "license_label": format_license(license_data),
        "readme": dict(readme_data),
        "readme_status": _readme_status(readme_data),
    }


def _with_risk_breakdown(comparison: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(comparison)
    risk_breakdown = _build_risk_breakdown(result)
    result["risk_breakdown"] = risk_breakdown
    result["overall_risk"] = risk_breakdown["overall"]["risk_level"]
    result["reasons"] = risk_breakdown["overall"]["reasons"]
    return result


def _build_risk_breakdown(comparison: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    source = _mapping_or_empty(comparison.get("source"))
    candidate = _mapping_or_empty(comparison.get("candidate"))
    name_similarity = _mapping_or_empty(comparison.get("name_similarity"))
    license_comparison = _mapping_or_empty(comparison.get("license_comparison"))
    readme_comparison = _mapping_or_empty(comparison.get("readme_comparison"))
    similarity = comparison.get("similarity") if isinstance(comparison.get("similarity"), Mapping) else None

    breakdown = {
        "name": _name_risk(source, candidate, name_similarity),
        "readme": _readme_risk(candidate, name_similarity, readme_comparison),
        "license": _license_risk(license_comparison),
        "similarity": _similarity_risk(similarity),
        "security": _risk_item("not scanned", "Security scanning is not part of repository compare yet."),
    }
    breakdown["overall"] = _overall_from_breakdown(breakdown)
    return breakdown


def _name_risk(
    source: Mapping[str, Any],
    candidate: Mapping[str, Any],
    name_similarity: Mapping[str, Any],
) -> dict[str, Any]:
    score = int(name_similarity.get("score") or 0)
    is_fork = bool(candidate.get("fork"))
    source_name = _repo_name(source)
    candidate_name = _repo_name(candidate)
    source_owner = _repo_owner(source)
    candidate_owner = _repo_owner(candidate)
    source_normalized = _normalize_name(source_name)
    candidate_normalized = _normalize_name(candidate_name)
    similarity_reasons = _list_of_strings(name_similarity.get("reasons"))

    if is_fork:
        return _risk_item(
            "INFO",
            "Candidate is marked as a GitHub fork, lowering name/imposter risk.",
            ["GitHub marks the candidate repository as a fork."],
        )

    if source_name and candidate_name and source_name == candidate_name and source_owner != candidate_owner:
        return _risk_item(
            "HIGH",
            "Exact repository name match under a different owner.",
            similarity_reasons or ["Repository names match exactly while owners differ."],
        )

    if source_normalized and source_normalized == candidate_normalized and source_owner != candidate_owner:
        return _risk_item(
            "HIGH",
            "Repository names match after case and punctuation normalization.",
            similarity_reasons or ["Normalized repository names match while owners differ."],
        )

    if source_normalized and source_normalized in candidate_normalized and source_owner != candidate_owner:
        return _risk_item(
            "MEDIUM",
            "Candidate name contains the target repository name.",
            similarity_reasons or ["Candidate repository name contains the source repository name."],
        )

    if score >= 20:
        return _risk_item(
            "LOW",
            "Weak fuzzy name similarity found.",
            similarity_reasons or ["Repository names have weak fuzzy similarity."],
        )

    return _risk_item(
        "INFO",
        "No meaningful name similarity found.",
        similarity_reasons or ["Repository names do not show a meaningful match."],
    )


def _readme_risk(
    candidate: Mapping[str, Any],
    name_similarity: Mapping[str, Any],
    readme_comparison: Mapping[str, Any],
) -> dict[str, Any]:
    status = str(readme_comparison.get("status") or "unknown")
    summary = str(readme_comparison.get("summary") or "README attribution status is unknown.")
    score = int(name_similarity.get("score") or 0)
    strong_name_similarity = score >= 65

    if status == "preserved":
        return _risk_item("INFO", summary, [summary])

    if status == "missing-attribution":
        if strong_name_similarity and not candidate.get("fork"):
            return _risk_item(
                "HIGH",
                "README attribution is missing while name similarity is strong.",
                [summary],
            )
        return _risk_item(
            "MEDIUM",
            "README attribution is missing, but name similarity is weaker or the candidate is a fork.",
            [summary],
        )

    if status == "missing-readme":
        return _risk_item("MEDIUM", summary, [summary])

    if status == "unknown":
        return _risk_item("LOW", summary, [summary])

    return _risk_item("LOW", summary, [summary])


def _license_risk(license_comparison: Mapping[str, Any]) -> dict[str, Any]:
    status = str(license_comparison.get("status") or "unknown")
    summary = str(license_comparison.get("summary") or "License comparison status is unknown.")

    if status == "same":
        return _risk_item("INFO", summary, [summary])
    if status == "changed":
        return _risk_item("HIGH", summary, [summary])
    if status == "missing":
        return _risk_item("MEDIUM", summary, [summary])
    return _risk_item("LOW", summary, [summary])


def _similarity_risk(similarity: Mapping[str, Any] | None) -> dict[str, Any]:
    if similarity is None:
        return _risk_item("not scanned", "Code similarity was not requested.")

    score = int(similarity.get("overall_similarity_score") or 0)
    exact_matches = int(similarity.get("exact_hash_match_count") or 0)
    shared_paths = int(similarity.get("shared_path_count") or 0)
    summary = (
        f"Overall similarity score {score}; "
        f"{exact_matches} exact hash matches; {shared_paths} shared paths."
    )

    if score >= 75:
        return _risk_item("HIGH", summary, ["High clone-based path/hash similarity found."])
    if score >= 35:
        return _risk_item("MEDIUM", summary, ["Moderate clone-based path/hash similarity found."])
    if score > 0:
        return _risk_item("LOW", summary, ["Weak clone-based path/hash similarity found."])
    return _risk_item("INFO", "No meaningful exact content/path similarity found.", [summary])


def _overall_from_breakdown(breakdown: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    scored_items = {
        key: value
        for key, value in breakdown.items()
        if key != "overall" and RISK_ORDER.get(str(value.get("risk_level")), -1) >= 0
    }
    highest_risk = "INFO"
    for item in scored_items.values():
        risk = str(item.get("risk_level") or "INFO")
        if RISK_ORDER.get(risk, 0) > RISK_ORDER.get(highest_risk, 0):
            highest_risk = risk

    high_watermark = RISK_ORDER.get(highest_risk, 0)
    drivers = [
        key
        for key, item in scored_items.items()
        if RISK_ORDER.get(str(item.get("risk_level") or "INFO"), 0) == high_watermark
    ]

    if high_watermark > 0:
        labels = ", ".join(RISK_LABELS.get(key, key) for key in drivers)
        reasons = [
            f"{RISK_LABELS.get(key, key)}: {scored_items[key].get('summary')}"
            for key in drivers
        ]
        return _risk_item(highest_risk, f"Overall risk is {highest_risk} due to {labels}.", reasons)

    return _risk_item(
        "INFO",
        "No elevated metadata, license, README, or similarity risk signal was found.",
        ["Available scanned signals are informational or were not requested."],
    )


def _risk_item(risk_level: str, summary: str, reasons: list[str] | None = None) -> dict[str, Any]:
    return {
        "risk_level": risk_level,
        "summary": summary,
        "reasons": reasons or [],
    }


def _readme_status(readme_data: Mapping[str, Any]) -> str:
    if readme_data.get("error"):
        return "unknown"
    if not readme_data.get("found"):
        return "missing"
    return str(readme_data.get("path") or readme_data.get("name") or "found")


def _format_date(value: Any) -> str:
    if value is None:
        return "-"
    if hasattr(value, "date"):
        return value.date().isoformat()
    text = str(value)
    return text.split("T", 1)[0] if text else "-"


def _optional_text(value: Any) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    return text or "-"


def _mapping_or_empty(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    return {}


def _list_of_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item]


def _repo_name(repo: Mapping[str, Any]) -> str:
    name = str(repo.get("name") or "").strip()
    if name:
        return name
    full_name = str(repo.get("full_name") or "")
    return full_name.split("/", 1)[1] if "/" in full_name else full_name


def _repo_owner(repo: Mapping[str, Any]) -> str:
    full_name = str(repo.get("full_name") or "")
    return full_name.split("/", 1)[0].casefold() if "/" in full_name else ""


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())
