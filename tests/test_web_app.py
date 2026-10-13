import asyncio
from pathlib import Path

import httpx
from typer.testing import CliRunner

from forksure.cli import app as cli_app
from forksure.web_app import OAUTH_STATE_COOKIE, OAUTH_VERIFIER_COOKIE, SESSION_COOKIE, SESSION_STORE, app


ROOT = Path(__file__).resolve().parents[1]


def request(method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        cookies = kwargs.pop("cookies", None)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            cookies=cookies,
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def test_web_ui_serves_review_console() -> None:
    response = request("GET", "/")

    assert response.status_code == 200
    assert "ForkSure Review Console" in response.text
    assert "Compare repositories" in response.text
    assert "Find close matches" in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_cloudflare_worker_is_proxy_only() -> None:
    worker = (ROOT / "deploy" / "cloudflare" / "worker.js").read_text(encoding="utf-8")

    assert "ForkSure API backend is not configured." in worker
    assert "GITHUB_TOKEN" not in worker
    assert "api.github.com" not in worker


def test_local_capabilities_include_full_scans() -> None:
    response = request("GET", "/api/capabilities")

    assert response.status_code == 200
    assert response.json() == {
        "hosted": False,
        "similarity": True,
        "security": True,
        "github_app_configured": False,
        "authenticated": False,
        "github_login": None,
        "private_repository_access": False,
    }


def test_hosted_capabilities_follow_environment(monkeypatch) -> None:
    monkeypatch.setenv("FORKSURE_HOSTED", "true")
    monkeypatch.setenv("FORKSURE_PROXY_TOKEN", "test-token")
    monkeypatch.setenv("FORKSURE_ENABLE_SIMILARITY", "false")

    response = request(
        "GET",
        "/api/capabilities",
        headers={"x-forksure-proxy-token": "test-token"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "hosted": True,
        "similarity": False,
        "security": True,
        "github_app_configured": False,
        "authenticated": False,
        "github_login": None,
        "private_repository_access": False,
    }


def test_hosted_api_rejects_requests_without_proxy_token(monkeypatch) -> None:
    monkeypatch.setenv("FORKSURE_HOSTED", "true")
    monkeypatch.setenv("FORKSURE_PROXY_TOKEN", "test-token")

    response = request("GET", "/api/capabilities")

    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized."}


def test_hosted_health_check_does_not_require_proxy_token(monkeypatch) -> None:
    monkeypatch.setenv("FORKSURE_HOSTED", "true")
    monkeypatch.setenv("FORKSURE_PROXY_TOKEN", "test-token")

    response = request("GET", "/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_compare_api_returns_existing_comparison(monkeypatch) -> None:
    expected = {
        "source": {"full_name": "owner/source"},
        "candidate": {"full_name": "other/source"},
        "overall_risk": "HIGH",
        "risk_breakdown": {},
    }
    seen: dict[str, object] = {}

    def fake_compare(source, candidate, github_client, include_security=False, **kwargs):
        seen.update(source=source, candidate=candidate, include_security=include_security)
        return expected

    monkeypatch.setattr("forksure.web_app.compare_repositories", fake_compare)
    response = request(
        "POST",
        "/api/compare",
        json={
            "source_repo": "owner/source",
            "candidate_repo": "other/source",
            "include_security": True,
        },
    )

    assert response.status_code == 200
    assert response.json() == expected
    assert seen == {"source": "owner/source", "candidate": "other/source", "include_security": True}


def test_compare_api_adds_similarity_when_requested(monkeypatch) -> None:
    monkeypatch.setattr(
        "forksure.web_app.compare_repositories",
        lambda source, candidate, github_client, include_security=False, **kwargs: {"overall_risk": "INFO"},
    )
    monkeypatch.setattr(
        "forksure.web_app.scan_repository_similarity",
        lambda source, candidate, **kwargs: {"overall_similarity_score": 42},
    )
    monkeypatch.setattr(
        "forksure.web_app.add_similarity_to_comparison",
        lambda comparison, similarity: {**comparison, "similarity": similarity},
    )

    response = request(
        "POST",
        "/api/compare",
        json={
            "source_repo": "owner/source",
            "candidate_repo": "other/source",
            "include_similarity": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["similarity"]["overall_similarity_score"] == 42


def test_matches_api_accepts_repository_name_without_owner(monkeypatch) -> None:
    seen: list[str] = []

    def fake_scan(owner_repo, github_client):
        seen.append(owner_repo)
        return [{"full_name": "someone/ForkSure", "risk_level": "LOW"}]

    monkeypatch.setattr("forksure.web_app.scan_imposters", fake_scan)
    response = request("POST", "/api/matches", json={"repository": "ForkSure"})

    assert response.status_code == 200
    assert seen == ["search/ForkSure"]
    assert response.json()["candidate_count"] == 1


def test_hosted_anonymous_request_does_not_inherit_server_github_token(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_compare(source, candidate, github_client, **kwargs):
        seen["token"] = github_client.token
        seen["allow_private"] = github_client.allow_private
        return {"overall_risk": "INFO"}

    monkeypatch.setenv("FORKSURE_HOSTED", "true")
    monkeypatch.setenv("FORKSURE_PROXY_TOKEN", "proxy-token")
    monkeypatch.setenv("GITHUB_TOKEN", "server-private-token")
    monkeypatch.setenv("FORKSURE_PUBLIC_GITHUB_TOKEN", "misconfigured-private-token")
    monkeypatch.setattr("forksure.web_app.compare_repositories", fake_compare)

    response = request(
        "POST",
        "/api/compare",
        headers={"x-forksure-proxy-token": "proxy-token"},
        json={"source_repo": "owner/source", "candidate_repo": "other/source"},
    )

    assert response.status_code == 200
    assert seen == {"token": "", "allow_private": False}


def test_proxy_configuration_fails_closed_when_hosted_flag_is_missing(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_compare(source, candidate, github_client, **kwargs):
        seen["token"] = github_client.token
        seen["allow_private"] = github_client.allow_private
        return {"overall_risk": "INFO"}

    monkeypatch.delenv("FORKSURE_HOSTED", raising=False)
    monkeypatch.setenv("FORKSURE_PROXY_TOKEN", "proxy-token")
    monkeypatch.setenv("GITHUB_TOKEN", "server-private-token")
    monkeypatch.setattr("forksure.web_app.compare_repositories", fake_compare)

    response = request(
        "POST",
        "/api/compare",
        headers={"x-forksure-proxy-token": "proxy-token"},
        json={"source_repo": "owner/source", "candidate_repo": "other/source"},
    )

    assert response.status_code == 200
    assert seen == {"token": "", "allow_private": False}


def test_hosted_anonymous_clone_does_not_receive_any_server_token(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_compare(source, candidate, github_client, **kwargs):
        seen["clone_token"] = kwargs["clone_token"]
        return {"overall_risk": "INFO"}

    monkeypatch.setenv("FORKSURE_HOSTED", "true")
    monkeypatch.setenv("FORKSURE_PROXY_TOKEN", "proxy-token")
    monkeypatch.setenv("GITHUB_TOKEN", "server-private-token")
    monkeypatch.setenv("FORKSURE_PUBLIC_GITHUB_TOKEN", "public-api-token")
    monkeypatch.setattr("forksure.web_app.compare_repositories", fake_compare)
    monkeypatch.setattr("forksure.web_app.scan_repository_similarity", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        "forksure.web_app.add_similarity_to_comparison",
        lambda comparison, similarity: {**comparison, "similarity": similarity},
    )

    response = request(
        "POST",
        "/api/compare",
        headers={"x-forksure-proxy-token": "proxy-token"},
        json={
            "source_repo": "owner/source",
            "candidate_repo": "other/source",
            "include_similarity": True,
        },
    )

    assert response.status_code == 200
    assert seen["clone_token"] == ""


def test_hosted_authenticated_request_uses_only_session_token(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_compare(source, candidate, github_client, **kwargs):
        seen["token"] = github_client.token
        seen["allow_private"] = github_client.allow_private
        return {"overall_risk": "INFO"}

    SESSION_STORE.clear()
    session_id, _ = SESSION_STORE.create(
        access_token="user-installation-token",
        login="octocat",
        avatar_url=None,
        installation_count=1,
    )
    monkeypatch.setenv("FORKSURE_HOSTED", "true")
    monkeypatch.setenv("FORKSURE_PROXY_TOKEN", "proxy-token")
    monkeypatch.setenv("GITHUB_TOKEN", "server-private-token")
    monkeypatch.setattr("forksure.web_app.compare_repositories", fake_compare)

    response = request(
        "POST",
        "/api/compare",
        headers={"x-forksure-proxy-token": "proxy-token"},
        cookies={SESSION_COOKIE: session_id},
        json={"source_repo": "owner/source", "candidate_repo": "other/source"},
    )

    assert response.status_code == 200
    assert seen == {"token": "user-installation-token", "allow_private": True}
    SESSION_STORE.clear()


def test_hosted_clone_work_uses_session_token_and_temporary_workspace(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_compare(source, candidate, github_client, **kwargs):
        seen["compare_token"] = kwargs["clone_token"]
        seen["compare_root"] = kwargs["clone_root"]
        return {"overall_risk": "INFO"}

    def fake_similarity(source, candidate, **kwargs):
        seen["similarity_token"] = kwargs["token"]
        seen["similarity_root"] = kwargs["cache_root"]
        return {"overall_similarity_score": 0}

    SESSION_STORE.clear()
    session_id, _ = SESSION_STORE.create(
        access_token="request-user-token",
        login="octocat",
        avatar_url=None,
        installation_count=1,
    )
    monkeypatch.setenv("FORKSURE_HOSTED", "true")
    monkeypatch.setenv("FORKSURE_PROXY_TOKEN", "proxy-token")
    monkeypatch.setattr("forksure.web_app.compare_repositories", fake_compare)
    monkeypatch.setattr("forksure.web_app.scan_repository_similarity", fake_similarity)
    monkeypatch.setattr(
        "forksure.web_app.add_similarity_to_comparison",
        lambda comparison, similarity: {**comparison, "similarity": similarity},
    )

    response = request(
        "POST",
        "/api/compare",
        headers={"x-forksure-proxy-token": "proxy-token"},
        cookies={SESSION_COOKIE: session_id},
        json={
            "source_repo": "owner/source",
            "candidate_repo": "other/source",
            "include_similarity": True,
        },
    )

    assert response.status_code == 200
    assert seen["compare_token"] == "request-user-token"
    assert seen["similarity_token"] == "request-user-token"
    assert seen["compare_root"] == seen["similarity_root"]
    assert not seen["compare_root"].exists()
    SESSION_STORE.clear()


def test_github_callback_rejects_state_mismatch(monkeypatch) -> None:
    _configure_github_app(monkeypatch)

    response = request(
        "GET",
        "/api/auth/github/callback?code=oauth-code&state=wrong",
        cookies={OAUTH_STATE_COOKIE: "expected", OAUTH_VERIFIER_COOKIE: "verifier"},
    )

    assert response.status_code == 400


def test_github_auth_start_sets_state_and_pkce_cookies(monkeypatch) -> None:
    _configure_github_app(monkeypatch)

    response = request("GET", "/api/auth/github/start")

    assert response.status_code == 303
    assert response.headers["location"].startswith("https://github.com/login/oauth/authorize?")
    assert response.cookies.get(OAUTH_STATE_COOKIE)
    assert response.cookies.get(OAUTH_VERIFIER_COOKIE)


def test_github_callback_creates_authenticated_session(monkeypatch) -> None:
    class FakeAuthenticator:
        def authenticate(self, code, verifier):
            assert (code, verifier) == ("oauth-code", "verifier")
            return {
                "access_token": "user-token",
                "login": "octocat",
                "avatar_url": None,
                "installation_count": 1,
                "expires_in": 3600,
            }

    SESSION_STORE.clear()
    monkeypatch.setattr("forksure.web_app._authenticator", lambda: FakeAuthenticator())
    callback = request(
        "GET",
        "/api/auth/github/callback?code=oauth-code&state=expected",
        cookies={OAUTH_STATE_COOKIE: "expected", OAUTH_VERIFIER_COOKIE: "verifier"},
    )

    assert callback.status_code == 303
    session_id = callback.cookies.get(SESSION_COOKIE)
    assert session_id

    status = request("GET", "/api/capabilities", cookies={SESSION_COOKIE: session_id})
    assert status.json()["authenticated"] is True
    assert status.json()["github_login"] == "octocat"
    assert status.json()["private_repository_access"] is True
    SESSION_STORE.clear()


def test_logout_invalidates_server_session() -> None:
    SESSION_STORE.clear()
    session_id, _ = SESSION_STORE.create(
        access_token="user-token",
        login="octocat",
        avatar_url=None,
        installation_count=1,
    )

    response = request("POST", "/api/auth/logout", cookies={SESSION_COOKIE: session_id})

    assert response.status_code == 200
    assert SESSION_STORE.get(session_id) is None


def test_ui_cli_command_starts_local_server(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(app_path, **kwargs):
        seen.update(app_path=app_path, **kwargs)

    monkeypatch.setattr("uvicorn.run", fake_run)
    result = CliRunner().invoke(cli_app, ["ui", "--no-open", "--port", "9001"])

    assert result.exit_code == 0
    assert "http://127.0.0.1:9001" in result.output
    assert seen == {
        "app_path": "forksure.web_app:app",
        "host": "127.0.0.1",
        "port": 9001,
        "log_level": "warning",
    }


def _configure_github_app(monkeypatch) -> None:
    monkeypatch.setenv("FORKSURE_GITHUB_APP_CLIENT_ID", "client-id")
    monkeypatch.setenv("FORKSURE_GITHUB_APP_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("FORKSURE_GITHUB_APP_SLUG", "forksure-test")
    monkeypatch.setenv("FORKSURE_PUBLIC_URL", "https://forksure.example")
