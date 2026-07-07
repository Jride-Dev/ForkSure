from __future__ import annotations

import re
from typing import Any

from .github_client import GitHubClient, parse_owner_repo


COMMON_HEADINGS = {
    "about",
    "api",
    "build",
    "configuration",
    "contributing",
    "development",
    "development setup",
    "features",
    "getting started",
    "installation",
    "license",
    "mvp",
    "overview",
    "quick start",
    "setup",
    "tests",
    "usage",
}
COMMON_COMMAND_PREFIXES = (
    "pip install",
    "python -m pip",
    "npm install",
    "npm run",
    "uv sync",
    "uv run",
    "git clone",
    "cd ",
    "docker build",
    "docker run",
)
COMMON_PHRASES = {
    "see license for details",
    "licensed under the mit license",
    "pull requests are welcome",
    "the token is optional",
}
TECHNICAL_TERMS = (
    "audit",
    "dependency",
    "fork",
    "github",
    "imposter",
    "license",
    "provenance",
    "repository",
    "scanner",
    "security",
    "supply",
    "vulnerability",
)


def extract_rare_strings_from_text(text: str, *, max_strings: int = 10) -> list[str]:
    candidates: list[tuple[int, int, str]] = []
    seen: set[str] = set()

    for index, raw_line in enumerate(text.splitlines()):
        phrase = _clean_line(raw_line)
        if not _is_candidate_phrase(phrase):
            continue
        key = phrase.casefold()
        if key in seen:
            continue
        seen.add(key)
        candidates.append((_score_phrase(phrase), index, phrase))

    candidates.sort(key=lambda item: (-item[0], item[1], item[2].casefold()))
    return [phrase for _, _, phrase in candidates[:max_strings]]


def extract_source_rare_strings(owner_repo: str, github_client: GitHubClient) -> list[str]:
    readme = github_client.get_repo_readme(owner_repo)
    if not readme.get("found"):
        return []
    return extract_rare_strings_from_text(str(readme.get("content_text") or ""))


def scan_rare_string_matches(
    owner_repo: str,
    github_client: GitHubClient,
    *,
    max_strings: int = 5,
) -> list[dict[str, Any]]:
    source = parse_owner_repo(owner_repo)
    source_full_name = source.slug.casefold()
    rare_strings = extract_source_rare_strings(owner_repo, github_client)[: max(0, max_strings)]
    matches_by_repo: dict[str, dict[str, Any]] = {}

    for rare_string in rare_strings:
        query = f'"{rare_string}"'
        for result in github_client.search_code(query, per_page=10, max_pages=1):
            full_name = str(result.get("repository_full_name") or "")
            if not full_name or full_name.casefold() == source_full_name:
                continue

            record = matches_by_repo.setdefault(
                full_name.casefold(),
                {
                    "repository_full_name": full_name,
                    "repository_html_url": result.get("repository_html_url") or "",
                    "fork": bool(result.get("repository_fork")),
                    "rare_string_matches": [],
                },
            )
            record["rare_string_matches"].append(
                {
                    "matched_string": rare_string,
                    "file_path": result.get("path") or "",
                    "file_html_url": result.get("html_url") or "",
                    "reason": "Rare source phrase found in candidate repository.",
                }
            )

    records = [_score_match_record(record) for record in matches_by_repo.values()]
    return sorted(records, key=lambda item: (item["score"], len(item["rare_string_matches"])), reverse=True)


def merge_rare_string_matches(candidates: list[dict[str, Any]], rare_matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_full_name = {str(candidate.get("full_name") or "").casefold(): candidate for candidate in candidates}

    for match in rare_matches:
        full_name = str(match.get("repository_full_name") or "")
        key = full_name.casefold()
        reason = str(match.get("reason") or "Rare source phrase found in candidate repository.")
        if key in by_full_name:
            candidate = by_full_name[key]
            candidate["rare_string_matches"] = match.get("rare_string_matches") or []
            candidate["rare_string_score"] = match.get("score")
            candidate["rare_string_risk_level"] = match.get("risk_level")
            candidate["reasons"] = _dedupe_preserving_order([*(candidate.get("reasons") or []), reason])
            if _risk_order(str(match.get("risk_level"))) > _risk_order(str(candidate.get("risk_level"))):
                candidate["risk_level"] = match.get("risk_level")
                candidate["classification"] = "possible-imposter"
            continue

        candidate = {
            "full_name": full_name,
            "name": full_name.split("/")[-1],
            "owner": full_name.split("/", 1)[0] if "/" in full_name else "",
            "html_url": match.get("repository_html_url") or "",
            "description": None,
            "fork": bool(match.get("fork")),
            "created_at": None,
            "pushed_at": None,
            "stargazers_count": 0,
            "default_branch": "",
            "license_key": None,
            "license_name": None,
            "topics": [],
            "readme_status": "unknown",
            "readme_text_excerpt": None,
            "readme_excerpt_truncated": False,
            "readme_html_url": None,
            "score": match.get("score") or 0,
            "risk_level": match.get("risk_level") or "MEDIUM",
            "classification": "official-fork" if match.get("fork") else "possible-imposter",
            "reasons": [reason],
            "rare_string_matches": match.get("rare_string_matches") or [],
            "rare_string_score": match.get("score"),
            "rare_string_risk_level": match.get("risk_level"),
        }
        by_full_name[key] = candidate
        candidates.append(candidate)

    return sorted(candidates, key=lambda item: (_risk_order(str(item.get("risk_level"))), int(item.get("score") or 0)), reverse=True)


def _clean_line(line: str) -> str:
    value = line.strip()
    value = re.sub(r"^[-*+]\s+", "", value)
    value = re.sub(r"^\d+\.\s+", "", value)
    value = value.strip("`*_ ")
    return " ".join(value.split())


def _is_candidate_phrase(phrase: str) -> bool:
    if not 18 <= len(phrase) <= 100:
        return False
    lower = phrase.casefold()
    if lower in COMMON_PHRASES or lower in COMMON_HEADINGS:
        return False
    if any(lower.startswith(prefix) for prefix in COMMON_COMMAND_PREFIXES):
        return False
    if phrase.startswith("#"):
        heading = phrase.lstrip("#").strip().casefold()
        if heading in COMMON_HEADINGS or len(heading.split()) <= 3:
            return False
    if "http://" in lower or "https://" in lower or "www." in lower:
        return False
    if "shields.io" in lower or "badge" in lower or phrase.startswith("[!["):
        return False
    if lower.count(" ") < 2 and not _has_mixed_case_token(phrase):
        return False
    return True


def _score_phrase(phrase: str) -> int:
    lower = phrase.casefold()
    score = len(phrase)
    if _has_mixed_case_token(phrase):
        score += 35
    if "-" in phrase:
        score += 20
    if any(term in lower for term in TECHNICAL_TERMS):
        score += 25
    if any(char.isdigit() for char in phrase):
        score += 8
    return score


def _has_mixed_case_token(value: str) -> bool:
    return any(any(char.islower() for char in token) and any(char.isupper() for char in token) for token in value.split())


def _score_match_record(record: dict[str, Any]) -> dict[str, Any]:
    match_count = len(record.get("rare_string_matches") or [])
    fork = bool(record.get("fork"))
    if fork:
        risk_level = "INFO"
        score = 20
    elif match_count >= 2:
        risk_level = "HIGH"
        score = 85
    else:
        risk_level = "MEDIUM"
        score = 60

    first_match = (record.get("rare_string_matches") or [{}])[0]
    return {
        **record,
        "matched_string": first_match.get("matched_string") or "",
        "file_path": first_match.get("file_path") or "",
        "file_html_url": first_match.get("file_html_url") or "",
        "reason": "Rare source phrase found in candidate repository.",
        "risk_level": risk_level,
        "score": score,
    }


def _risk_order(value: str) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(value, 0)


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped
