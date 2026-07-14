from __future__ import annotations

from pathlib import Path


LOCAL_SCAN_IGNORED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "pycache",
    ".pytest_cache",
    ".pytest-tmp",
    "tmp_pytest_run",
    ".cbh-test-tmp",
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
}


def should_skip_path(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts

    return any(_is_ignored_segment(part) for part in parts)


def _is_ignored_segment(part: str) -> bool:
    normalized = part.casefold()
    return normalized in LOCAL_SCAN_IGNORED_DIR_NAMES or "pycache" in normalized
