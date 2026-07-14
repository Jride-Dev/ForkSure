from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from ..path_filters import should_skip_path
from .findings import SecurityFinding


PYTHON_LOCKFILES = {
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "requirements.lock",
    "requirements-dev.txt",
}
RENOVATE_CONFIGS = {
    "renovate.json",
    ".renovaterc",
    ".renovaterc.json",
    ".github/renovate.json",
}
DEPENDABOT_CONFIGS = {
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
}


def scan_dependencies(path: str | Path) -> list[SecurityFinding]:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    scan_root = root if root.is_dir() else root.parent
    files = set(_iter_dependency_files(root))
    findings: list[SecurityFinding] = []

    pyproject = _find_named_file(files, "pyproject.toml")
    python_lockfiles = {file_path for file_path in files if file_path.name in PYTHON_LOCKFILES}

    if pyproject is not None:
        uv_lock = _find_named_file(files, "uv.lock")
        if uv_lock is not None:
            findings.append(
                SecurityFinding(
                    id="deps-python-uv-lockfile-found",
                    category="dependencies",
                    severity="info",
                    title="Python uv lockfile found",
                    description="pyproject.toml has a committed uv.lock for resolved Python dependencies.",
                    file_path=_display_path(uv_lock, scan_root),
                    recommendation="Keep uv.lock committed and refresh it when dependencies change.",
                )
            )
        elif python_lockfiles:
            lockfile = sorted(python_lockfiles, key=lambda item: _display_path(item, scan_root))[0]
            findings.append(
                SecurityFinding(
                    id="deps-python-lockfile-found",
                    category="dependencies",
                    severity="info",
                    title="Python lockfile found",
                    description="A recognized Python dependency lock or requirements file is present.",
                    file_path=_display_path(lockfile, scan_root),
                    recommendation="Prefer uv.lock for pyproject.toml projects when using uv.",
                )
            )
        else:
            findings.append(
                SecurityFinding(
                    id="deps-python-missing-lockfile",
                    category="dependencies",
                    severity="medium",
                    title="Python project has no recognized lockfile",
                    description="pyproject.toml exists, but no recognized Python lockfile or requirements file was found.",
                    file_path=_display_path(pyproject, scan_root),
                    recommendation="Commit uv.lock, poetry.lock, Pipfile.lock, or a requirements lock/input file.",
                )
            )

    findings.extend(_dependency_bot_findings(files, scan_root))
    return findings


def _iter_dependency_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        scan_root = root.parent
        if not should_skip_path(root, scan_root) and _is_dependency_file(root, scan_root):
            yield root
        return

    for current_dir, dirnames, filenames in os.walk(root):
        current_path = Path(current_dir)
        if should_skip_path(current_path, root):
            dirnames[:] = []
            continue

        dirnames[:] = [
            dirname
            for dirname in dirnames
            if not should_skip_path(current_path / dirname, root)
        ]
        for filename in filenames:
            file_path = current_path / filename
            if not should_skip_path(file_path, root) and _is_dependency_file(file_path, root):
                yield file_path


def _is_dependency_file(path: Path, root: Path) -> bool:
    relative = _normalized_relative_path(path, root)
    return (
        path.name == "pyproject.toml"
        or path.name in PYTHON_LOCKFILES
        or relative in RENOVATE_CONFIGS
        or relative in DEPENDABOT_CONFIGS
    )


def _dependency_bot_findings(files: set[Path], root: Path) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for file_path in sorted(files, key=lambda item: _display_path(item, root)):
        relative = _normalized_relative_path(file_path, root)
        if relative in DEPENDABOT_CONFIGS:
            findings.append(
                SecurityFinding(
                    id="deps-dependabot-config-found",
                    category="dependencies",
                    severity="info",
                    title="Dependabot config found",
                    description="Dependabot dependency update configuration is present.",
                    file_path=_display_path(file_path, root),
                    recommendation="Keep dependency update automation enabled and reviewed.",
                )
            )
        elif relative in RENOVATE_CONFIGS:
            findings.append(
                SecurityFinding(
                    id="deps-renovate-config-found",
                    category="dependencies",
                    severity="info",
                    title="Renovate config found",
                    description="Renovate dependency update configuration is present.",
                    file_path=_display_path(file_path, root),
                    recommendation="Keep dependency update automation enabled and reviewed.",
                )
            )
    return findings


def _find_named_file(files: set[Path], name: str) -> Path | None:
    matches = [file_path for file_path in files if file_path.name == name]
    return sorted(matches, key=str)[0] if matches else None


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _normalized_relative_path(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path
    return relative.as_posix()
