import time
from urllib.parse import parse_qs, urlparse

import httpx

from forksure.github_app_auth import (
    GitHubAppAuthenticator,
    GitHubAppConfig,
    InMemorySessionStore,
    code_challenge,
)


def test_authorization_url_uses_state_and_pkce() -> None:
    authenticator = GitHubAppAuthenticator(_config())

    url = authenticator.authorization_url("state-value", code_challenge("verifier-value"))
    query = parse_qs(urlparse(url).query)

    assert query["client_id"] == ["client-id"]
    assert query["state"] == ["state-value"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == ["https://forksure.example/api/auth/github/callback"]


def test_authenticate_verifies_user_and_installations(monkeypatch) -> None:
    exchanged: dict[str, str] = {}

    def fake_post(url, *, headers, data, timeout, follow_redirects):
        exchanged.update(data)
        return httpx.Response(200, json={"access_token": "user-token", "expires_in": 3600})

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url, **kwargs):
            if url.endswith("/user"):
                return httpx.Response(200, json={"login": "octocat", "avatar_url": "https://example/avatar.png"})
            return httpx.Response(200, json={"total_count": 2, "installations": []})

    monkeypatch.setattr("forksure.github_app_auth.httpx.post", fake_post)
    monkeypatch.setattr("forksure.github_app_auth.httpx.Client", FakeClient)

    result = GitHubAppAuthenticator(_config()).authenticate("oauth-code", "pkce-verifier")

    assert exchanged["code_verifier"] == "pkce-verifier"
    assert result == {
        "access_token": "user-token",
        "login": "octocat",
        "avatar_url": "https://example/avatar.png",
        "installation_count": 2,
        "expires_in": 3600,
    }


def test_session_store_uses_opaque_id_and_expires(monkeypatch) -> None:
    now = time.time()
    monkeypatch.setattr("forksure.github_app_auth.time.time", lambda: now)
    store = InMemorySessionStore(ttl_seconds=60)

    session_id, session = store.create(
        access_token="secret-token",
        login="octocat",
        avatar_url=None,
        installation_count=1,
    )

    assert "secret-token" not in session_id
    assert store.get(session_id) == session

    monkeypatch.setattr("forksure.github_app_auth.time.time", lambda: now + 61)
    assert store.get(session_id) is None


def _config() -> GitHubAppConfig:
    return GitHubAppConfig(
        client_id="client-id",
        client_secret="client-secret",
        app_slug="forksure-test",
        public_url="https://forksure.example",
    )
