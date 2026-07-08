from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .github_client import parse_owner_repo


CACHE_ROOT = Path(".forksure-cache") / "repos"
MAX_FILE_SIZE_BYTES = 1_000_000
TOP_MATCH_LIMIT = 20
IGNORED_SEGMENTS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".pytest-tmp",
    "tmp_pytest_run",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "htmlcov",
    ".mypy_cache",
    ".tox",
    ".forksure-cache",
    "reports",
    ".next",
    "out",
}
SOURCE_SUFFIXES = {
    ".bat",
    ".cfg",
    ".css",
    ".csv",
    ".dockerignore",
    ".editorconfig",
    ".env",
    ".gitignore",
    ".go",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".lock",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
SOURCE_FILENAMES = {
    "dockerfile",
    "makefile",
    "license",
    "notice",
    "readme",
    "requirements",
}


class SimilarityScanError(RuntimeError):
    """Raised when clone-based similarity scanning cannot complete."""


def scan_repository_similarity(source_repo: str, candidate_repo: str) -> dict[str, Any]:
    source_path = _ensure_repo_clone(source_repo)
    candidate_path = _ensure_repo_clone(candidate_repo)
    return _scan_repository_paths(source_repo, candidate_repo, source_path, candidate_path)


def _scan_repository_paths(
    source_repo: str,
    candidate_repo: str,
    source_path: Path,
    candidate_path: Path,
) -> dict[str, Any]:
    source_files, source_ignored = _collect_files(source_path)
    candidate_files, candidate_ignored = _collect_files(candidate_path)
    shared_paths = sorted(set(source_files) & set(candidate_files))
    matching_paths: list[dict[str, Any]] = []
    exact_matches: list[dict[str, str]] = []
    matched_source_paths: set[str] = set()
    seen_exact_pairs: set[tuple[str, str]] = set()

    for relative_path in shared_paths:
        source_info = source_files[relative_path]
        candidate_info = candidate_files[relative_path]
        same_hash = source_info["sha256"] == candidate_info["sha256"]
        matching_paths.append(
            {
                "path": relative_path,
                "same_hash": same_hash,
                "source_sha256": source_info["sha256"],
                "candidate_sha256": candidate_info["sha256"],
            }
        )
        if same_hash:
            _add_exact_match(
                exact_matches,
                seen_exact_pairs,
                matched_source_paths,
                relative_path,
                relative_path,
                source_info["sha256"],
                "same-path",
            )

    candidate_by_hash: dict[str, list[str]] = {}
    for path, info in candidate_files.items():
        candidate_by_hash.setdefault(str(info["sha256"]), []).append(path)

    for source_relative_path, source_info in source_files.items():
        for candidate_relative_path in candidate_by_hash.get(str(source_info["sha256"]), []):
            if source_relative_path == candidate_relative_path:
                continue
            _add_exact_match(
                exact_matches,
                seen_exact_pairs,
                matched_source_paths,
                source_relative_path,
                candidate_relative_path,
                str(source_info["sha256"]),
                "same-content-different-path",
            )

    denominator = max(len(source_files), len(candidate_files), 1)
    directory_score = round((len(shared_paths) / denominator) * 100)
    content_score = round((len(matched_source_paths) / denominator) * 100)
    overall_score = round((directory_score + content_score) / 2)

    exact_matches = sorted(exact_matches, key=lambda item: (item["match_type"], item["source_path"], item["candidate_path"]))
    return {
        "source_repo": source_repo,
        "candidate_repo": candidate_repo,
        "exact_file_matches": exact_matches,
        "matching_paths": matching_paths,
        "source_file_count": len(source_files),
        "candidate_file_count": len(candidate_files),
        "shared_path_count": len(shared_paths),
        "exact_hash_match_count": len(exact_matches),
        "directory_similarity_score": directory_score,
        "exact_content_similarity_score": content_score,
        "overall_similarity_score": overall_score,
        "top_matches": exact_matches[:TOP_MATCH_LIMIT],
        "ignored_paths_summary": _merge_ignored_summaries(source_ignored, candidate_ignored),
    }


def _ensure_repo_clone(owner_repo: str) -> Path:
    target = _cache_path_for_repo(owner_repo)
    cache_root = CACHE_ROOT.resolve()
    target_resolved = target.resolve()
    cache_root.mkdir(parents=True, exist_ok=True)

    if target.exists():
        if (target / ".git").exists() and _run_git(["git", "-C", str(target), "pull", "--ff-only"]):
            return target
        _remove_cached_repo(target_resolved, cache_root)

    repo_url = _repo_clone_url(owner_repo)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(target)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SimilarityScanError(f"Could not clone {owner_repo}: {exc}") from exc
    return target


def _run_git(command: list[str]) -> bool:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError:
        return False
    return result.returncode == 0


def _remove_cached_repo(target: Path, cache_root: Path) -> None:
    try:
        target.relative_to(cache_root)
    except ValueError as exc:
        raise SimilarityScanError(f"Refusing to remove path outside cache: {target}") from exc
    if target.is_dir():
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()


def _cache_path_for_repo(owner_repo: str) -> Path:
    parsed = parse_owner_repo(owner_repo)
    safe_name = _safe_repo_path_name(parsed.slug)
    return CACHE_ROOT / safe_name


def _repo_clone_url(owner_repo: str) -> str:
    parsed = parse_owner_repo(owner_repo)
    return f"https://github.com/{parsed.slug}.git"


def _safe_repo_path_name(value: str) -> str:
    safe = "".join(character.lower() if character.isalnum() else "-" for character in value).strip("-")
    while "--" in safe:
        safe = safe.replace("--", "-")
    return safe or "repository"


def _collect_files(root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    files: dict[str, dict[str, Any]] = {}
    ignored = {
        "ignored_directories": 0,
        "skipped_large_files": 0,
        "skipped_binary_files": 0,
        "skipped_non_source_files": 0,
    }

    for path in root.rglob("*"):
        if path.is_dir():
            continue
        relative_path = path.relative_to(root)
        if _should_skip_path(relative_path):
            ignored["ignored_directories"] += 1
            continue
        if not _is_source_like_file(path):
            ignored["skipped_non_source_files"] += 1
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_SIZE_BYTES:
            ignored["skipped_large_files"] += 1
            continue
        if _is_binary_file(path):
            ignored["skipped_binary_files"] += 1
            continue

        relative_key = relative_path.as_posix()
        files[relative_key] = {
            "sha256": _sha256_file(path),
            "size": size,
        }

    return files, ignored


def _should_skip_path(relative_path: Path) -> bool:
    for part in relative_path.parts:
        normalized = part.casefold()
        if normalized in IGNORED_SEGMENTS or "pycache" in normalized:
            return True
    return False


def _is_source_like_file(path: Path) -> bool:
    name = path.name.casefold()
    stem = path.stem.casefold()
    suffix = path.suffix.casefold()
    return suffix in SOURCE_SUFFIXES or name in SOURCE_FILENAMES or stem in SOURCE_FILENAMES


def _is_binary_file(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _add_exact_match(
    exact_matches: list[dict[str, str]],
    seen_exact_pairs: set[tuple[str, str]],
    matched_source_paths: set[str],
    source_path: str,
    candidate_path: str,
    sha256: str,
    match_type: str,
) -> None:
    key = (source_path, candidate_path)
    if key in seen_exact_pairs:
        return
    seen_exact_pairs.add(key)
    matched_source_paths.add(source_path)
    exact_matches.append(
        {
            "source_path": source_path,
            "candidate_path": candidate_path,
            "sha256": sha256,
            "match_type": match_type,
        }
    )


def _merge_ignored_summaries(source: dict[str, int], candidate: dict[str, int]) -> dict[str, int]:
    keys = sorted(set(source) | set(candidate))
    return {key: int(source.get(key, 0)) + int(candidate.get(key, 0)) for key in keys}
