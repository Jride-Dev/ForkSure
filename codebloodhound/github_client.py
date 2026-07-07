from __future__ import annotations

import base64
import binascii
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


def _license_data(
    *,
    found: bool,
    key: str | None = None,
    spdx_id: str | None = None,
    name: str | None = None,
    html_url: str | None = None,
    error: str | None = None,
) -> dict[str, bool | str | None]:
    return {
        "found": found,
        "key": key,
        "spdx_id": spdx_id,
        "name": name,
        "html_url": html_url,
        "error": error,
    }


def _readme_data(
    *,
    found: bool,
    name: str | None = None,
    path: str | None = None,
    html_url: str | None = None,
    download_url: str | None = None,
    content_text: str | None = None,
    error: str | None = None,
) -> dict[str, bool | str | None]:
    return {
        "found": found,
        "name": name,
        "path": path,
        "html_url": html_url,
        "download_url": download_url,
        "content_text": content_text,
        "error": error,
    }


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

    def get_repo_license(self, owner_repo: str) -> dict[str, bool | str | None]:
        parsed = parse_owner_repo(owner_repo)
        try:
            data = self._request("GET", f"/repos/{parsed.owner}/{parsed.repo}/license")
        except GitHubNotFoundError:
            return _license_data(found=False)
        except (GitHubRateLimitError, GitHubAPIError) as exc:
            return _license_data(found=False, error=str(exc))

        if not isinstance(data, dict):
            return _license_data(found=False, error="Unexpected GitHub license response.")

        license_info = data.get("license")
        if not isinstance(license_info, dict):
            return _license_data(found=False)

        return _license_data(
            found=True,
            key=_optional_string(license_info.get("key")),
            spdx_id=_optional_string(license_info.get("spdx_id")),
            name=_optional_string(license_info.get("name")),
            html_url=_optional_string(data.get("html_url")),
        )

    def get_repo_readme(self, owner_repo: str) -> dict[str, bool | str | None]:
        parsed = parse_owner_repo(owner_repo)
        try:
            data = self._request("GET", f"/repos/{parsed.owner}/{parsed.repo}/readme")
        except GitHubNotFoundError:
            return _readme_data(found=False)
        except (GitHubRateLimitError, GitHubAPIError) as exc:
            return _readme_data(found=False, error=str(exc))

        if not isinstance(data, dict):
            return _readme_data(found=False, error="Unexpected GitHub README response.")

        content = data.get("content")
        content_text = None
        error = None
        if isinstance(content, str):
            content_text, error = _decode_base64_text(content)

        return _readme_data(
            found=True,
            name=_optional_string(data.get("name")),
            path=_optional_string(data.get("path")),
            html_url=_optional_string(data.get("html_url")),
            download_url=_optional_string(data.get("download_url")),
            content_text=content_text,
            error=error,
        )

    def search_repositories(self, query: str, *, per_page: int = 20, max_pages: int = 1) -> list[dict[str, Any]]:
        repositories: list[dict[str, Any]] = []
        safe_per_page = max(1, min(per_page, 100))
        safe_max_pages = max(1, max_pages)

        for page in range(1, safe_max_pages + 1):
            try:
                data = self._request(
                    "GET",
                    "/search/repositories",
                    params={"q": query, "per_page": safe_per_page, "page": page},
                )
            except (GitHubRateLimitError, GitHubAPIError):
                return repositories

            if not isinstance(data, dict):
                return repositories

            items = data.get("items")
            if not isinstance(items, list):
                return repositories

            repositories.extend(_normalize_repository_item(item) for item in items if isinstance(item, dict))
            if len(items) < safe_per_page:
                return repositories

        return repositories

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


def get_repo_license(owner_repo: str) -> dict[str, bool | str | None]:
    return GitHubClient().get_repo_license(owner_repo)


def get_repo_readme(owner_repo: str) -> dict[str, bool | str | None]:
    return GitHubClient().get_repo_readme(owner_repo)


def search_repositories(query: str, *, per_page: int = 20, max_pages: int = 1) -> list[dict[str, Any]]:
    return GitHubClient().search_repositories(query, per_page=per_page, max_pages=max_pages)


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


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _decode_base64_text(value: str) -> tuple[str | None, str | None]:
    try:
        raw = base64.b64decode("".join(value.split()), validate=True)
        return raw.decode("utf-8", errors="replace"), None
    except (binascii.Error, ValueError) as exc:
        return None, f"Could not decode README content: {exc}"


def _normalize_repository_item(item: dict[str, Any]) -> dict[str, Any]:
    owner = item.get("owner")
    owner_login = owner.get("login") if isinstance(owner, dict) else None
    license_info = item.get("license")
    topics = item.get("topics")
    return {
        "full_name": _optional_string(item.get("full_name")) or "",
        "name": _optional_string(item.get("name")) or "",
        "owner": _optional_string(owner_login) or "",
        "html_url": _optional_string(item.get("html_url")) or "",
        "description": _optional_string(item.get("description")),
        "fork": bool(item.get("fork", False)),
        "created_at": _optional_string(item.get("created_at")),
        "pushed_at": _optional_string(item.get("pushed_at")),
        "stargazers_count": _optional_int(item.get("stargazers_count")),
        "default_branch": _optional_string(item.get("default_branch")) or "",
        "license_key": _optional_string(license_info.get("key")) if isinstance(license_info, dict) else None,
        "license_name": _optional_string(license_info.get("name")) if isinstance(license_info, dict) else None,
        "topics": [str(topic) for topic in topics] if isinstance(topics, list) else [],
    }


def _optional_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
