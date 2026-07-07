from __future__ import annotations

from typing import Any, Mapping

from .github_client import InvalidOwnerRepoError, parse_owner_repo


NEARBY_TEXT_WINDOW = 120


def compare_readme_attribution(
    source_repo: str,
    source_readme: Mapping[str, Any],
    fork_readme: Mapping[str, Any],
) -> dict[str, str]:
    if source_readme.get("error") or fork_readme.get("error"):
        return {
            "status": "unknown",
            "severity": "low",
            "summary": "README lookup failed; attribution could not be determined.",
        }

    if not source_readme.get("found"):
        return {
            "status": "unknown",
            "severity": "low",
            "summary": "Source README is unavailable; attribution could not be determined.",
        }

    if not fork_readme.get("found"):
        return {
            "status": "missing-readme",
            "severity": "medium",
            "summary": "Fork README is missing while the source README exists.",
        }

    content = str(fork_readme.get("content_text") or "").casefold()
    if not content:
        return {
            "status": "unknown",
            "severity": "low",
            "summary": "Fork README content is unavailable; attribution could not be determined.",
        }

    try:
        parsed = parse_owner_repo(source_repo)
    except InvalidOwnerRepoError:
        return {
            "status": "unknown",
            "severity": "low",
            "summary": "Source repository name is invalid; attribution could not be determined.",
        }

    owner = parsed.owner.casefold()
    repo = parsed.repo.casefold()
    shorthand = f"{owner}/{repo}"
    full_url = f"https://github.com/{owner}/{repo}"

    if full_url in content or shorthand in content or _contains_nearby(content, owner, repo):
        return {
            "status": "preserved",
            "severity": "info",
            "summary": "Fork README preserves obvious upstream attribution.",
        }

    return {
        "status": "missing-attribution",
        "severity": "high",
        "summary": f"Fork README does not mention obvious upstream attribution for {parsed.slug}.",
    }


def _contains_nearby(text: str, owner: str, repo: str) -> bool:
    owner_positions = _find_all(text, owner)
    repo_positions = _find_all(text, repo)
    return any(abs(owner_pos - repo_pos) <= NEARBY_TEXT_WINDOW for owner_pos in owner_positions for repo_pos in repo_positions)


def _find_all(text: str, token: str) -> list[int]:
    positions: list[int] = []
    start = 0
    while True:
        index = text.find(token, start)
        if index == -1:
            return positions
        positions.append(index)
        start = index + len(token)
