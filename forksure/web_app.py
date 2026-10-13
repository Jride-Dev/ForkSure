from __future__ import annotations

import hmac
import os
import tempfile
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.requests import Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .compare_scanner import add_similarity_to_comparison, compare_repositories
from .github_client import (
    GitHubAPIError,
    GitHubClient,
    GitHubNotFoundError,
    GitHubPrivateRepositoryError,
    GitHubRateLimitError,
    InvalidOwnerRepoError,
)
from .github_app_auth import (
    GitHubAppAuthenticator,
    GitHubAppAuthError,
    GitHubAppConfig,
    InMemorySessionStore,
    code_challenge,
    new_code_verifier,
    new_oauth_state,
)
from .imposter_scanner import scan_imposters
from .similarity_scanner import SimilarityScanError, scan_repository_similarity


WEB_ROOT = Path(__file__).with_name("web")
SESSION_COOKIE = "forksure_session"
OAUTH_STATE_COOKIE = "forksure_oauth_state"
OAUTH_VERIFIER_COOKIE = "forksure_oauth_verifier"
OAUTH_COOKIE_MAX_AGE = 10 * 60
SESSION_STORE = InMemorySessionStore()


class CompareRequest(BaseModel):
    source_repo: str = Field(min_length=3, max_length=200)
    candidate_repo: str = Field(min_length=3, max_length=200)
    include_similarity: bool = False
    include_security: bool = False


class MatchRequest(BaseModel):
    repository: str = Field(min_length=1, max_length=200)


app = FastAPI(title="ForkSure", docs_url=None, redoc_url=None)
app.mount("/assets", StaticFiles(directory=WEB_ROOT / "assets"), name="assets")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    auth_error = _proxy_auth_error(request)
    response = auth_error if auth_error is not None else await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB_ROOT / "index.html")


@app.post("/api/compare")
def compare(payload: CompareRequest, request: Request) -> dict[str, Any]:
    if payload.include_similarity and not _capability_enabled("similarity"):
        raise HTTPException(status_code=403, detail="Similarity scanning is disabled on this deployment.")
    if payload.include_security and not _capability_enabled("security"):
        raise HTTPException(status_code=403, detail="Security scanning is disabled on this deployment.")
    try:
        github = _github_client_for_request(request)
        clone_token = _clone_token_for_request(request)
        workspace = tempfile.TemporaryDirectory(prefix="forksure-scan-") if (
            _hosted_mode()
            and (payload.include_similarity or payload.include_security)
        ) else nullcontext(None)
        with workspace as workspace_path:
            clone_root = Path(workspace_path) if workspace_path else None
            result = compare_repositories(
                payload.source_repo,
                payload.candidate_repo,
                github,
                include_security=payload.include_security,
                clone_token=clone_token,
                clone_root=clone_root,
            )
            if payload.include_similarity:
                result = add_similarity_to_comparison(
                    result,
                    scan_repository_similarity(
                        payload.source_repo,
                        payload.candidate_repo,
                        token=clone_token,
                        cache_root=clone_root,
                    ),
                )
        return result
    except Exception as exc:
        raise _http_error(exc) from exc


@app.post("/api/matches")
def matches(payload: MatchRequest, request: Request) -> dict[str, Any]:
    target = payload.repository.strip()
    owner_repo = target if "/" in target else f"search/{target}"
    try:
        candidates = scan_imposters(owner_repo, _github_client_for_request(request))
        return {"target": target, "candidate_count": len(candidates), "candidates": candidates}
    except Exception as exc:
        raise _http_error(exc) from exc


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/capabilities")
def capabilities(request: Request) -> dict[str, Any]:
    session = _request_session(request)
    return {
        "hosted": _hosted_mode(),
        "similarity": _capability_enabled("similarity"),
        "security": _capability_enabled("security"),
        "github_app_configured": GitHubAppConfig.from_env() is not None,
        "authenticated": session is not None,
        "github_login": session.login if session else None,
        "private_repository_access": bool(session and session.installation_count > 0),
    }


@app.get("/api/auth/github/connect")
def github_connect() -> RedirectResponse:
    authenticator = _authenticator()
    return RedirectResponse(authenticator.installation_url(), status_code=303)


@app.get("/api/auth/github/installed")
def github_installed() -> RedirectResponse:
    # Never trust GitHub's installation_id query parameter; OAuth verifies the user.
    return RedirectResponse("/api/auth/github/start", status_code=303)


@app.get("/api/auth/github/start")
def github_auth_start() -> RedirectResponse:
    authenticator = _authenticator()
    state = new_oauth_state()
    verifier = new_code_verifier()
    response = RedirectResponse(
        authenticator.authorization_url(state, code_challenge(verifier)),
        status_code=303,
    )
    cookie_options = _oauth_cookie_options()
    response.set_cookie(OAUTH_STATE_COOKIE, state, **cookie_options)
    response.set_cookie(OAUTH_VERIFIER_COOKIE, verifier, **cookie_options)
    return response


@app.get("/api/auth/github/callback")
def github_auth_callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
    expected_state = request.cookies.get(OAUTH_STATE_COOKIE, "")
    verifier = request.cookies.get(OAUTH_VERIFIER_COOKIE, "")
    if not code or not state or not expected_state or not verifier or not hmac.compare_digest(state, expected_state):
        raise HTTPException(status_code=400, detail="GitHub authorization could not be verified.")

    try:
        auth_data = _authenticator().authenticate(code, verifier)
    except GitHubAppAuthError as exc:
        raise HTTPException(status_code=502, detail="GitHub authorization could not be completed.") from exc

    session_id, _ = SESSION_STORE.create(**auth_data)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        max_age=SESSION_STORE.ttl_seconds,
        path="/",
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
    )
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth/github")
    response.delete_cookie(OAUTH_VERIFIER_COOKIE, path="/api/auth/github")
    return response


@app.post("/api/auth/logout")
def github_logout(request: Request) -> JSONResponse:
    SESSION_STORE.delete(request.cookies.get(SESSION_COOKIE))
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


def _proxy_auth_error(request: Request):
    if not request.url.path.startswith("/api/") or request.url.path == "/api/health":
        return None
    expected = os.getenv("FORKSURE_PROXY_TOKEN", "")
    if not expected:
        if _env_flag("FORKSURE_HOSTED", default=False):
            return _json_error(503, "ForkSure API authentication is not configured.")
        return None
    supplied = request.headers.get("x-forksure-proxy-token", "")
    if not hmac.compare_digest(supplied, expected):
        return _json_error(401, "Unauthorized.")
    return None


def _json_error(status_code: int, detail: str):
    return JSONResponse(status_code=status_code, content={"detail": detail})


def _authenticator() -> GitHubAppAuthenticator:
    config = GitHubAppConfig.from_env()
    if config is None:
        raise HTTPException(status_code=503, detail="GitHub App authentication is not configured.")
    return GitHubAppAuthenticator(config)


def _request_session(request: Request):
    return SESSION_STORE.get(request.cookies.get(SESSION_COOKIE))


def _github_client_for_request(request: Request) -> GitHubClient:
    session = _request_session(request)
    if session is not None and session.installation_count > 0:
        return GitHubClient(token=session.access_token, allow_private=True)
    if _hosted_mode():
        return GitHubClient(token="", allow_private=False)
    return GitHubClient()


def _clone_token_for_request(request: Request) -> str:
    session = _request_session(request)
    if session is not None and session.installation_count > 0:
        return session.access_token
    if _hosted_mode():
        return ""
    return os.getenv("GITHUB_TOKEN", "").strip()


def _oauth_cookie_options() -> dict[str, Any]:
    return {
        "max_age": OAUTH_COOKIE_MAX_AGE,
        "path": "/api/auth/github",
        "httponly": True,
        "secure": _cookie_secure(),
        "samesite": "lax",
    }


def _cookie_secure() -> bool:
    return _env_flag("FORKSURE_COOKIE_SECURE", default=_hosted_mode())


def _hosted_mode() -> bool:
    return _env_flag("FORKSURE_HOSTED", default=False) or bool(os.getenv("FORKSURE_PROXY_TOKEN", "").strip())


def _capability_enabled(name: str) -> bool:
    return _env_flag(f"FORKSURE_ENABLE_{name.upper()}", default=True)


def _env_flag(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, InvalidOwnerRepoError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, GitHubNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, GitHubPrivateRepositoryError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, GitHubRateLimitError):
        return HTTPException(status_code=429, detail="GitHub rate limit reached. Connect GitHub or try again later.")
    if isinstance(exc, SimilarityScanError):
        return HTTPException(status_code=502, detail=f"Similarity scan failed: {exc}")
    if isinstance(exc, GitHubAPIError):
        return HTTPException(status_code=502, detail=f"GitHub API error: {exc}")
    return HTTPException(status_code=500, detail="ForkSure could not complete the scan.")
