from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from dotenv import load_dotenv
from pydantic import BaseModel, Field, HttpUrl


GITHUB_API_URL = "https://api.github.com"
OWNER_REPO_RE = re.compile(r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)$")


class GitHubAPIError(RuntimeError):
    """Base exception for GitHub API failures."""


class InvalidOwnerRepoError(ValueError):
    """Raised when an owner/repo argument is not valid."""


class GitHubNotFoundError(GitHubAPIError):
    """Raised when GitHub returns 404 for a requested repository."""


class GitHubRateLimitError(GitHubAPIError):
    """Raised when the GitHub API rate limit is exceeded."""


@dataclass(frozen=True)
class OwnerRepo:
    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


class GitHubOwner(BaseModel):
    login: str
    html_url: HttpUrl | None = None


class GitHubRepo(BaseModel):
    id: int
    name: str
    full_name: str
    owner: GitHubOwner
    html_url: HttpUrl
    created_at: datetime
    pushed_at: datetime | None = None
    stargazers_count: int = Field(default=0)
    default_branch: str
    fork: bool = False

    @property
    def stars(self) -> int:
        return self.stargazers_count


def parse_owner_repo(owner_repo: str) -> OwnerRepo:
    value = owner_repo.strip()
    match = OWNER_REPO_RE.fullmatch(value)
    if not match:
        raise InvalidOwnerRepoError("Expected repository in owner/repo format.")
    return OwnerRepo(owner=match.group("owner"), repo=match.group("repo"))


class GitHubClient:
    def __init__(
        self,
        *,
        token: str | None = None,
        base_url: str = GITHUB_API_URL,
        timeout: float = 20.0,
    ) -> None:
        load_dotenv()
        self.token = token if token is not None else os.getenv("GITHUB_TOKEN")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get_repo(self, owner_repo: str) -> GitHubRepo:
        parsed = parse_owner_repo(owner_repo)
        data = self._request("GET", f"/repos/{parsed.owner}/{parsed.repo}")
        return GitHubRepo.model_validate(data)

    def list_forks(self, owner_repo: str) -> list[GitHubRepo]:
        parsed = parse_owner_repo(owner_repo)
        forks: list[GitHubRepo] = []
        page = 1
        per_page = 100

        while True:
            data = self._request(
                "GET",
                f"/repos/{parsed.owner}/{parsed.repo}/forks",
                params={"per_page": per_page, "page": page},
            )
            if not isinstance(data, list):
                raise GitHubAPIError("Unexpected GitHub response while listing forks.")

            forks.extend(GitHubRepo.model_validate(item) for item in data)
            if len(data) < per_page:
                return forks
            page += 1

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "CodeBloodHound/0.1",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            with httpx.Client(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise GitHubAPIError(f"GitHub request failed: {exc}") from exc

        self._raise_for_status(response)
        return response.json()

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code < 400:
            return

        if response.status_code == 404:
            raise GitHubNotFoundError("Repository not found.")

        detail = _extract_error_message(response)
        is_rate_limited = (
            response.headers.get("x-ratelimit-remaining") == "0"
            or "rate limit" in detail.lower()
            or "secondary rate" in detail.lower()
        )
        if response.status_code in {403, 429} and is_rate_limited:
            reset_at = _format_rate_limit_reset(response.headers.get("x-ratelimit-reset"))
            message = "GitHub API rate limit exceeded."
            if reset_at:
                message = f"{message} Resets at {reset_at}."
            raise GitHubRateLimitError(message)

        raise GitHubAPIError(f"GitHub API error {response.status_code}: {detail}")


def get_repo(owner_repo: str) -> GitHubRepo:
    return GitHubClient().get_repo(owner_repo)


def list_forks(owner_repo: str) -> list[GitHubRepo]:
    return GitHubClient().list_forks(owner_repo)


def _extract_error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text.strip() or response.reason_phrase

    message = body.get("message") if isinstance(body, dict) else None
    return str(message or response.reason_phrase)


def _format_rate_limit_reset(value: str | None) -> str | None:
    if not value:
        return None
    try:
        reset = datetime.fromtimestamp(int(value), tz=timezone.utc)
    except ValueError:
        return None
    return reset.isoformat()
