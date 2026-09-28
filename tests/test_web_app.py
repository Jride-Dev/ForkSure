import asyncio

import httpx
from typer.testing import CliRunner

from forksure.cli import app as cli_app
from forksure.web_app import app


def request(method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def test_web_ui_serves_review_console() -> None:
    response = request("GET", "/")

    assert response.status_code == 200
    assert "ForkSure Review Console" in response.text
    assert "Compare repositories" in response.text
    assert "Find close matches" in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_local_capabilities_include_full_scans() -> None:
    response = request("GET", "/api/capabilities")

    assert response.status_code == 200
    assert response.json() == {
        "hosted": False,
        "similarity": True,
        "security": True,
        "github_authenticated": False,
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
        "github_authenticated": False,
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

    def fake_compare(source, candidate, github_client, include_security=False):
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
        lambda source, candidate, github_client, include_security=False: {"overall_risk": "INFO"},
    )
    monkeypatch.setattr(
        "forksure.web_app.scan_repository_similarity",
        lambda source, candidate: {"overall_similarity_score": 42},
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
