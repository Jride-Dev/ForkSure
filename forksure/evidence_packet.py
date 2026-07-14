from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping


EVIDENCE_DISCLAIMER = (
    "ForkSure produces evidence for manual review. It does not determine ownership, "
    "intent, copyright infringement, or malicious behavior."
)


def build_evidence_packet(source_repo: str, candidate_repo: str, compare_result: dict) -> dict[str, Any]:
    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    source = _mapping_or_empty(compare_result.get("source"))
    candidate = _mapping_or_empty(compare_result.get("candidate"))
    risk_breakdown = _mapping_or_empty(compare_result.get("risk_breakdown"))
    overall_risk = str(compare_result.get("overall_risk") or _risk_level(risk_breakdown.get("overall")) or "INFO")
    evidence_found = _evidence_found(compare_result)
    evidence_not_found = _evidence_not_found(compare_result)

    return {
        "source_repo": source_repo,
        "candidate_repo": candidate_repo,
        "source_url": str(source.get("html_url") or _github_url(source_repo)),
        "candidate_url": str(candidate.get("html_url") or _github_url(candidate_repo)),
        "generated_at": generated_at,
        "summary": _summary(source_repo, candidate_repo, overall_risk, evidence_found, evidence_not_found),
        "overall_risk": overall_risk,
        "risk_breakdown": dict(risk_breakdown),
        "evidence_found": evidence_found,
        "evidence_not_found": evidence_not_found,
        "manual_review_recommendations": _recommendations(compare_result),
        "disclaimer": EVIDENCE_DISCLAIMER,
    }


def _evidence_found(compare_result: Mapping[str, Any]) -> list[str]:
    items: list[str] = []
    source = _mapping_or_empty(compare_result.get("source"))
    candidate = _mapping_or_empty(compare_result.get("candidate"))
    name_similarity = _mapping_or_empty(compare_result.get("name_similarity"))
    readme = _mapping_or_empty(compare_result.get("readme_comparison"))
    license_comparison = _mapping_or_empty(compare_result.get("license_comparison"))
    similarity = compare_result.get("similarity") if isinstance(compare_result.get("similarity"), Mapping) else None
    candidate_security = (
        compare_result.get("candidate_security") if isinstance(compare_result.get("candidate_security"), Mapping) else None
    )

    score = int(name_similarity.get("score") or 0)
    if score >= 65:
        items.append(f"Exact or similar repository name evidence found; name similarity score is {score}.")
    elif score >= 20:
        items.append(f"Weak repository name similarity evidence found; name similarity score is {score}.")

    readme_status = str(readme.get("status") or "unknown")
    if readme_status == "missing-attribution":
        items.append("README attribution evidence found: candidate README does not show obvious upstream attribution.")
    elif readme_status == "missing-readme":
        items.append("README evidence found: candidate README is missing while the source README is available.")

    license_status = str(license_comparison.get("status") or "unknown")
    if license_status == "changed":
        items.append("License evidence found: candidate license differs from the source license.")
    elif license_status == "missing":
        items.append("License evidence found: candidate license is missing while the source license is known.")
    elif license_status == "same":
        items.append("License evidence found: candidate license matches the source license.")

    if candidate.get("fork"):
        items.append("Candidate repository is marked as a GitHub fork.")

    if similarity is not None:
        similarity_score = int(similarity.get("overall_similarity_score") or 0)
        exact_matches = int(similarity.get("exact_hash_match_count") or 0)
        shared_paths = int(similarity.get("shared_path_count") or 0)
        items.append(
            f"Code similarity scan completed: score {similarity_score}/100, "
            f"{exact_matches} exact file matches, {shared_paths} shared paths."
        )
        if exact_matches:
            items.append(f"Exact file hash matches found: {exact_matches}.")

    if candidate_security is not None:
        security_score = int(candidate_security.get("score") or 0)
        security_risk = str(candidate_security.get("risk_level") or "INFO")
        finding_count = int(candidate_security.get("finding_count") or 0)
        if security_score > 0:
            items.append(
                f"Candidate security findings found: score {security_score}/100, "
                f"risk {security_risk}, {finding_count} findings."
            )

    if source.get("full_name") and candidate.get("full_name"):
        items.append(f"Metadata compared for {source.get('full_name')} and {candidate.get('full_name')}.")

    return _dedupe(items)


def _evidence_not_found(compare_result: Mapping[str, Any]) -> list[str]:
    items: list[str] = []
    candidate = _mapping_or_empty(compare_result.get("candidate"))
    readme = _mapping_or_empty(compare_result.get("readme_comparison"))
    license_comparison = _mapping_or_empty(compare_result.get("license_comparison"))
    similarity = compare_result.get("similarity") if isinstance(compare_result.get("similarity"), Mapping) else None
    candidate_security = (
        compare_result.get("candidate_security") if isinstance(compare_result.get("candidate_security"), Mapping) else None
    )

    if not candidate.get("fork"):
        items.append("Candidate repository is not marked as an official GitHub fork.")

    if str(license_comparison.get("status") or "unknown") == "same":
        items.append("License matches the source repository.")

    if str(readme.get("status") or "unknown") == "preserved":
        items.append("README upstream attribution appears preserved.")

    if similarity is None:
        items.append("Code similarity was not scanned.")
    else:
        similarity_score = int(similarity.get("overall_similarity_score") or 0)
        exact_matches = int(similarity.get("exact_hash_match_count") or 0)
        if exact_matches == 0:
            items.append("No exact file hash matches were found.")
        if similarity_score == 0:
            items.append("No meaningful code similarity was found.")

    if candidate_security is None:
        items.append("Security audit was not requested.")
    else:
        security_score = int(candidate_security.get("score") or 0)
        finding_count = int(candidate_security.get("finding_count") or 0)
        if security_score == 0 and finding_count:
            items.append("Security audit found only informational findings.")
        elif security_score == 0:
            items.append("Security audit found no elevated findings.")

    return _dedupe(items)


def _recommendations(compare_result: Mapping[str, Any]) -> list[str]:
    recommendations = [
        "Review the candidate repository manually.",
        "Check whether naming could confuse users.",
        "Check whether attribution should be added.",
        "Do not file abuse/copyright reports without confirming copied code, copied assets, malware, or deceptive impersonation.",
    ]
    license_status = str(_mapping_or_empty(compare_result.get("license_comparison")).get("status") or "unknown")
    if license_status in {"changed", "missing"}:
        recommendations.insert(3, "Review the license status before taking action.")
    return recommendations


def _summary(
    source_repo: str,
    candidate_repo: str,
    overall_risk: str,
    evidence_found: list[str],
    evidence_not_found: list[str],
) -> str:
    return (
        f"ForkSure generated a neutral evidence packet for {source_repo} and {candidate_repo}. "
        f"Overall risk is {overall_risk}. "
        f"Evidence found: {len(evidence_found)} item(s). Evidence not found/context: {len(evidence_not_found)} item(s). "
        "Manual review recommended."
    )


def _risk_level(value: object) -> str | None:
    if isinstance(value, Mapping):
        risk = value.get("risk_level")
        return str(risk) if risk else None
    return None


def _mapping_or_empty(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    return {}


def _github_url(owner_repo: str) -> str:
    return f"https://github.com/{owner_repo}"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value not in seen:
            deduped.append(value)
            seen.add(value)
    return deduped
