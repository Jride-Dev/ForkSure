from __future__ import annotations

import base64
import hashlib
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx


GITHUB_API_URL = "https://api.github.com"
GITHUB_OAUTH_URL = "https://github.com/login/oauth/access_token"
DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60


class GitHubAppAuthError(RuntimeError):
    """Raised when GitHub App authentication cannot be completed."""


@dataclass(frozen=True)
class GitHubAppConfig:
    client_id: str
    client_secret: str
    app_slug: str
    public_url: str

    @classmethod
    def from_env(cls) -> GitHubAppConfig | None:
        values = {
            "client_id": os.getenv("FORKSURE_GITHUB_APP_CLIENT_ID", "").strip(),
            "client_secret": os.getenv("FORKSURE_GITHUB_APP_CLIENT_SECRET", "").strip(),
            "app_slug": os.getenv("FORKSURE_GITHUB_APP_SLUG", "").strip(),
            "public_url": os.getenv("FORKSURE_PUBLIC_URL", "").strip().rstrip("/"),
        }
        if not all(values.values()):
            return None
        return cls(**values)

    @property
    def callback_url(self) -> str:
        return f"{self.public_url}/api/auth/github/callback"


@dataclass(frozen=True)
class GitHubUserSession:
    access_token: str
    login: str
    avatar_url: str | None
    installation_count: int
    expires_at: float


class InMemorySessionStore:
    """Short-lived server-side sessions; browser cookies contain only opaque IDs."""

    def __init__(self, *, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> None:
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, GitHubUserSession] = {}
        self._lock = threading.Lock()

    def create(
        self,
        *,
        access_token: str,
        login: str,
        avatar_url: str | None,
        installation_count: int,
        expires_in: int | None = None,
    ) -> tuple[str, GitHubUserSession]:
        ttl = self.ttl_seconds
        if expires_in is not None and expires_in > 0:
            ttl = min(ttl, expires_in)
        session = GitHubUserSession(
            access_token=access_token,
            login=login,
            avatar_url=avatar_url,
            installation_count=installation_count,
            expires_at=time.time() + ttl,
        )
        session_id = secrets.token_urlsafe(32)
        with self._lock:
            self._remove_expired_locked()
            self._sessions[session_id] = session
        return session_id, session

    def get(self, session_id: str | None) -> GitHubUserSession | None:
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.expires_at <= time.time():
                self._sessions.pop(session_id, None)
                return None
            return session

    def delete(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def _remove_expired_locked(self) -> None:
        now = time.time()
        expired = [session_id for session_id, session in self._sessions.items() if session.expires_at <= now]
        for session_id in expired:
            self._sessions.pop(session_id, None)


class GitHubAppAuthenticator:
    def __init__(self, config: GitHubAppConfig, *, timeout: float = 20.0) -> None:
        self.config = config
        self.timeout = timeout

    def installation_url(self) -> str:
        return f"https://github.com/apps/{self.config.app_slug}/installations/new"

    def authorization_url(self, state: str, code_challenge: str) -> str:
        query = urlencode(
            {
                "client_id": self.config.client_id,
                "redirect_uri": self.config.callback_url,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"https://github.com/login/oauth/authorize?{query}"

    def authenticate(self, code: str, code_verifier: str) -> dict[str, Any]:
        token_data = self._exchange_code(code, code_verifier)
        access_token = str(token_data.get("access_token") or "").strip()
        if not access_token:
            raise GitHubAppAuthError("GitHub did not return an access token.")

        headers = self._github_headers(access_token)
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                user_response = client.get(f"{GITHUB_API_URL}/user", headers=headers)
                installations_response = client.get(
                    f"{GITHUB_API_URL}/user/installations",
                    headers=headers,
                    params={"per_page": 100},
                )
        except httpx.HTTPError as exc:
            raise GitHubAppAuthError(f"GitHub user verification failed: {exc}") from exc

        user = self._json_response(user_response, "GitHub user verification")
        installations = self._json_response(installations_response, "GitHub installation verification")
        login = str(user.get("login") or "").strip()
        if not login:
            raise GitHubAppAuthError("GitHub did not return a user login.")

        return {
            "access_token": access_token,
            "login": login,
            "avatar_url": _optional_string(user.get("avatar_url")),
            "installation_count": int(installations.get("total_count") or 0),
            "expires_in": _optional_int(token_data.get("expires_in")),
        }

    def _exchange_code(self, code: str, code_verifier: str) -> dict[str, Any]:
        try:
            response = httpx.post(
                GITHUB_OAUTH_URL,
                headers={"Accept": "application/json", "User-Agent": "ForkSure"},
                data={
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "code": code,
                    "redirect_uri": self.config.callback_url,
                    "code_verifier": code_verifier,
                },
                timeout=self.timeout,
                follow_redirects=True,
            )
        except httpx.HTTPError as exc:
            raise GitHubAppAuthError(f"GitHub authorization failed: {exc}") from exc
        return self._json_response(response, "GitHub authorization")

    @staticmethod
    def _github_headers(access_token: str) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {access_token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ForkSure",
        }

    @staticmethod
    def _json_response(response: httpx.Response, action: str) -> dict[str, Any]:
        try:
            data = response.json()
        except ValueError as exc:
            raise GitHubAppAuthError(f"{action} returned an invalid response.") from exc
        if response.status_code >= 400:
            detail = data.get("error_description") or data.get("message") or data.get("error") or "request failed"
            raise GitHubAppAuthError(f"{action} failed: {detail}")
        if not isinstance(data, dict):
            raise GitHubAppAuthError(f"{action} returned an unexpected response.")
        return data


def new_oauth_state() -> str:
    return secrets.token_urlsafe(32)


def new_code_verifier() -> str:
    return secrets.token_urlsafe(64)


def code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None else None


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
