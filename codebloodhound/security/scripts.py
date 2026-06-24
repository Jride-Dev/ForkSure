from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Pattern

from .findings import SecurityFinding


SCANNED_FILENAMES = {
    "package.json",
    "setup.py",
    "pyproject.toml",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
}
SCANNED_SUFFIXES = {".sh", ".ps1"}
IGNORED_DIR_NAMES = {
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
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "htmlcov",
    ".mypy_cache",
    ".tox",
}


@dataclass(frozen=True)
class ScriptRule:
    id: str
    category: str
    severity: str
    title: str
    description: str
    recommendation: str
    pattern: Pattern[str]


GENERIC_RULES = (
    ScriptRule(
        id="unsafe-script-curl-pipe-shell",
        category="unsafe-script",
        severity="high",
        title="curl output piped to shell",
        description="The script downloads remote content with curl and immediately executes it.",
        recommendation="Download to a file, verify integrity, and execute only trusted content.",
        pattern=re.compile(r"\bcurl\b[^|\n]*\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.IGNORECASE),
    ),
    ScriptRule(
        id="unsafe-script-wget-pipe-shell",
        category="unsafe-script",
        severity="high",
        title="wget output piped to shell",
        description="The script downloads remote content with wget and immediately executes it.",
        recommendation="Download to a file, verify integrity, and execute only trusted content.",
        pattern=re.compile(r"\bwget\b[^|\n]*\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.IGNORECASE),
    ),
    ScriptRule(
        id="unsafe-script-invoke-expression",
        category="unsafe-script",
        severity="high",
        title="PowerShell Invoke-Expression usage",
        description="Invoke-Expression can execute dynamically constructed or downloaded commands.",
        recommendation="Avoid Invoke-Expression and call explicit commands with validated arguments.",
        pattern=re.compile(r"\b(?:Invoke-Expression|IEX)\b", re.IGNORECASE),
    ),
    ScriptRule(
        id="unsafe-script-powershell-encoded-command",
        category="unsafe-script",
        severity="high",
        title="PowerShell EncodedCommand usage",
        description="Encoded PowerShell commands make script behavior harder to inspect.",
        recommendation="Use plain-text scripts or commands that can be reviewed directly.",
        pattern=re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b.*\s-(?:e|enc|encodedcommand)\b|\b-encodedcommand\b", re.IGNORECASE),
    ),
    ScriptRule(
        id="unsafe-script-child-process-exec",
        category="unsafe-script",
        severity="medium",
        title="child_process.exec usage",
        description="child_process.exec can run shell commands and may be risky with untrusted input.",
        recommendation="Prefer safer process APIs and avoid interpolating untrusted input.",
        pattern=re.compile(r"\bchild_process\.exec\s*\(", re.IGNORECASE),
    ),
    ScriptRule(
        id="unsafe-script-eval",
        category="unsafe-script",
        severity="medium",
        title="eval usage",
        description="eval executes dynamic code and can hide unsafe behavior.",
        recommendation="Replace eval with explicit parsing or dispatch logic.",
        pattern=re.compile(r"\beval\s*\(", re.IGNORECASE),
    ),
    ScriptRule(
        id="unsafe-script-base64-exec",
        category="unsafe-script",
        severity="high",
        title="base64 decode followed by execution",
        description="The script appears to decode base64 content and execute it.",
        recommendation="Avoid encoded executable payloads; keep executable code readable and reviewable.",
        pattern=re.compile(
            r"\bbase64\b[^|\n;]*(?:-d|--decode)[^|\n;]*(?:\|\s*(?:bash|sh|powershell|pwsh)\b|;\s*(?:bash|sh|powershell|pwsh|eval|exec)\b)",
            re.IGNORECASE,
        ),
    ),
)

PACKAGE_JSON_RULE = ScriptRule(
    id="unsafe-script-npm-postinstall",
    category="package-script",
    severity="medium",
    title="npm postinstall script",
    description="npm postinstall scripts run automatically during package installation.",
    recommendation="Review whether install-time execution is necessary and keep the command minimal.",
    pattern=re.compile(r"[\"']postinstall[\"']\s*:", re.IGNORECASE),
)

GITHUB_ACTION_RULE = ScriptRule(
    id="unsafe-script-unpinned-github-action",
    category="ci-workflow",
    severity="medium",
    title="GitHub Action pinned to main or master",
    description="A workflow action uses @main or @master instead of an immutable version.",
    recommendation="Pin GitHub Actions to a version tag or commit SHA.",
    pattern=re.compile(r"\buses:\s*[^#\s]+@(?:main|master)\b", re.IGNORECASE),
)


def scan_unsafe_scripts(path: str | Path) -> list[SecurityFinding]:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    scan_root = root if root.is_dir() else root.parent
    findings: list[SecurityFinding] = []
    for file_path in _iter_scannable_files(root):
        findings.extend(_scan_file(file_path, scan_root))
    return findings


def _iter_scannable_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if not should_skip_path(root, root.parent) and _is_scannable_file(root, root.parent):
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
            if not should_skip_path(file_path, root) and _is_scannable_file(file_path, root):
                yield file_path


def should_skip_path(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts

    if not parts and path.name:
        parts = (path.name,)

    return any(part.lower() in IGNORED_DIR_NAMES for part in parts)


def _is_scannable_file(path: Path, root: Path) -> bool:
    if path.name in SCANNED_FILENAMES or path.suffix in SCANNED_SUFFIXES:
        return True
    return path.suffix.lower() in {".yml", ".yaml"} and _is_github_workflow(path, root)


def _scan_file(path: Path, root: Path) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    rules = list(GENERIC_RULES)
    if path.name == "package.json":
        rules.append(PACKAGE_JSON_RULE)
    if _is_github_workflow(path, root):
        rules.append(GITHUB_ACTION_RULE)

    for line_number, line_text in enumerate(lines, start=1):
        for rule in rules:
            if rule.pattern.search(line_text):
                findings.append(_finding_from_rule(rule, path, root, line_number, line_text))

    return findings


def _finding_from_rule(rule: ScriptRule, path: Path, root: Path, line: int, evidence: str) -> SecurityFinding:
    return SecurityFinding(
        id=rule.id,
        category=rule.category,
        severity=rule.severity,
        title=rule.title,
        description=rule.description,
        file_path=_display_path(path, root),
        line=line,
        evidence=evidence.strip()[:240],
        recommendation=rule.recommendation,
    )


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _is_github_workflow(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts

    for index, part in enumerate(parts[:-1]):
        if part == ".github" and index + 1 < len(parts) and parts[index + 1] == "workflows":
            return True
    return False
