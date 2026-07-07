from __future__ import annotations

from .github_client import GitHubClient, GitHubRepo


def audit_forks(owner_repo: str, *, client: GitHubClient | None = None) -> list[GitHubRepo]:
    github = client or GitHubClient()
    return github.list_forks(owner_repo)
