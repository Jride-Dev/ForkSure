from __future__ import annotations

from typing import Any, Mapping

from .github_client import GitHubClient, GitHubRepo
from .imposter_scanner import score_name_similarity
from .license_scanner import compare_licenses, format_license
from .readme_scanner import compare_readme_attribution


RISK_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


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
    overall_risk, reasons = _overall_risk(
        candidate,
        name_similarity,
        license_comparison,
        readme_comparison,
    )

    return {
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
        "overall_risk": overall_risk,
        "reasons": reasons,
    }


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


def _overall_risk(
    candidate: Mapping[str, Any],
    name_similarity: Mapping[str, Any],
    license_comparison: Mapping[str, str],
    readme_comparison: Mapping[str, str],
) -> tuple[str, list[str]]:
    score = int(name_similarity.get("score") or 0)
    similar_name = score >= 65
    weak_name = score < 50
    license_status = str(license_comparison.get("status") or "unknown")
    readme_status = str(readme_comparison.get("status") or "unknown")
    is_fork = bool(candidate.get("fork"))
    reasons: list[str] = []

    if is_fork:
        reasons.append("Candidate is marked as a GitHub fork, lowering provenance risk.")
        if license_status == "same" and readme_status == "preserved":
            reasons.append("License and README attribution look preserved for this fork.")
            return "INFO", reasons

    if license_status == "changed":
        reasons.append("License changed; manual review recommended for possible provenance concern.")
        return "HIGH", reasons

    if similar_name and readme_status == "missing-attribution":
        reasons.append("Same or similar name with missing README attribution; manual review recommended.")
        return "HIGH", reasons

    if license_status == "missing":
        reasons.append("Candidate license is missing while the source license is known.")
        return _lower_for_fork("MEDIUM", is_fork), reasons

    if readme_status == "missing-readme":
        reasons.append("Candidate README is missing while the source README exists.")
        return _lower_for_fork("MEDIUM", is_fork), reasons

    if similar_name:
        reasons.append("Same or similar repository name; metadata-only comparison needs manual review.")
        return _lower_for_fork("MEDIUM", is_fork), reasons

    if weak_name:
        reasons.append("Name similarity is weak and no obvious provenance issue was found.")
        return "LOW", reasons

    reasons.append("No high-confidence provenance concern was found in metadata-only comparison.")
    return _lower_for_fork("LOW", is_fork), reasons


def _lower_for_fork(risk: str, is_fork: bool) -> str:
    if not is_fork:
        return risk
    if risk == "HIGH":
        return "MEDIUM"
    if risk == "MEDIUM":
        return "LOW"
    if risk == "LOW":
        return "INFO"
    return risk


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
