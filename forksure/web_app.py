from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.requests import Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .compare_scanner import add_similarity_to_comparison, compare_repositories
from .github_client import (
    GitHubAPIError,
    GitHubClient,
    GitHubNotFoundError,
    GitHubRateLimitError,
    InvalidOwnerRepoError,
)
from .imposter_scanner import scan_imposters
from .similarity_scanner import SimilarityScanError, scan_repository_similarity


WEB_ROOT = Path(__file__).with_name("web")


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
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB_ROOT / "index.html")


@app.post("/api/compare")
def compare(payload: CompareRequest) -> dict[str, Any]:
    try:
        result = compare_repositories(
            payload.source_repo,
            payload.candidate_repo,
            GitHubClient(),
            include_security=payload.include_security,
        )
        if payload.include_similarity:
            result = add_similarity_to_comparison(
                result,
                scan_repository_similarity(payload.source_repo, payload.candidate_repo),
            )
        return result
    except Exception as exc:
        raise _http_error(exc) from exc


@app.post("/api/matches")
def matches(payload: MatchRequest) -> dict[str, Any]:
    target = payload.repository.strip()
    owner_repo = target if "/" in target else f"search/{target}"
    try:
        candidates = scan_imposters(owner_repo, GitHubClient())
        return {"target": target, "candidate_count": len(candidates), "candidates": candidates}
    except Exception as exc:
        raise _http_error(exc) from exc


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, InvalidOwnerRepoError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, GitHubNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, GitHubRateLimitError):
        return HTTPException(status_code=429, detail="GitHub rate limit reached. Add GITHUB_TOKEN and try again.")
    if isinstance(exc, SimilarityScanError):
        return HTTPException(status_code=502, detail=f"Similarity scan failed: {exc}")
    if isinstance(exc, GitHubAPIError):
        return HTTPException(status_code=502, detail=f"GitHub API error: {exc}")
    return HTTPException(status_code=500, detail="ForkSure could not complete the scan.")
