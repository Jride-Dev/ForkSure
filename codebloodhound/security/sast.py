from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .findings import SecurityFinding


SEMGREP_TIMEOUT_SECONDS = 180
DEFAULT_RULES = ["sql", "xss", "csrf"]
RULE_ALIASES = {
    "sql": "p/sql-injection",
    "xss": "p/xss",
    "csrf": "p/security-audit",
}
SEMGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def scan_sast(path: str | Path, rules: list[str] | None = None) -> list[SecurityFinding]:
    scan_path = Path(path)
    if not scan_path.exists():
        raise FileNotFoundError(f"Path does not exist: {scan_path}")

    semgrep = shutil.which("semgrep")
    if semgrep is None:
        return [_semgrep_unavailable_finding()]

    command = [semgrep, "--json"]
    for rule in _resolve_rules(rules):
        command.extend(["--config", rule])
    command.append(str(scan_path))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return [_semgrep_unavailable_finding()]
    except subprocess.SubprocessError as exc:
        return [
            SecurityFinding(
                id="sast-semgrep-error",
                category="sast",
                severity="medium",
                title="Semgrep scan failed",
                description=f"Semgrep could not complete the SAST scan: {exc}",
                recommendation="Run Semgrep manually for more detail, then retry the CodeBloodHound scan.",
                source_tool="semgrep",
            )
        ]

    if result.returncode != 0 and not result.stdout.strip():
        return [
            SecurityFinding(
                id="sast-semgrep-error",
                category="sast",
                severity="medium",
                title="Semgrep scan failed",
                description=(result.stderr.strip() or "Semgrep exited without JSON output."),
                recommendation="Run Semgrep manually for more detail, then retry the CodeBloodHound scan.",
                source_tool="semgrep",
            )
        ]

    return _parse_semgrep_json(result.stdout)


def _parse_semgrep_json(raw_json: str) -> list[SecurityFinding]:
    if not raw_json.strip():
        return []

    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError:
        return [
            SecurityFinding(
                id="sast-semgrep-malformed-json",
                category="sast",
                severity="medium",
                title="Malformed Semgrep JSON output",
                description="Semgrep returned output that CodeBloodHound could not parse as JSON.",
                recommendation="Run Semgrep manually and verify it can produce JSON output.",
                source_tool="semgrep",
            )
        ]

    results = parsed.get("results", []) if isinstance(parsed, dict) else []
    if not isinstance(results, list):
        return [
            SecurityFinding(
                id="sast-semgrep-malformed-json",
                category="sast",
                severity="medium",
                title="Unexpected Semgrep JSON shape",
                description="Semgrep JSON output did not contain a list of results.",
                recommendation="Run Semgrep manually and verify it can produce JSON output.",
                source_tool="semgrep",
            )
        ]

    findings: list[SecurityFinding] = []
    for result in results:
        if isinstance(result, dict):
            findings.append(_finding_from_semgrep_result(result))
    return findings


def _finding_from_semgrep_result(result: dict[str, Any]) -> SecurityFinding:
    extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
    check_id = str(result.get("check_id") or "unknown")
    message = str(extra.get("message") or result.get("message") or "Potential SAST finding detected.")
    semgrep_severity = str(extra.get("severity") or result.get("severity") or "").upper()

    return SecurityFinding(
        id=f"sast-{check_id}",
        category="sast",
        severity=SEMGREP_SEVERITY_MAP.get(semgrep_severity, "medium"),
        title=check_id if check_id != "unknown" else message,
        description=message,
        file_path=_optional_str(result.get("path")),
        line=_start_line(result),
        evidence=_redacted_snippet(extra.get("lines")),
        recommendation="Review the flagged code path and apply the framework-specific safe pattern.",
        source_tool="semgrep",
    )


def _resolve_rules(rules: list[str] | None) -> list[str]:
    selected = rules or DEFAULT_RULES
    resolved: list[str] = []
    for rule in selected:
        normalized = rule.strip()
        if normalized:
            resolved.append(RULE_ALIASES.get(normalized.lower(), normalized))
    return resolved or [RULE_ALIASES[rule] for rule in DEFAULT_RULES]


def _redacted_snippet(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    snippet = " ".join(value.strip().split())
    if len(snippet) <= 160:
        return snippet
    return f"{snippet[:157]}..."


def _semgrep_unavailable_finding() -> SecurityFinding:
    return SecurityFinding(
        id="sast-semgrep-unavailable",
        category="sast",
        severity="info",
        title="Semgrep unavailable",
        description="Semgrep was not found on PATH, so SAST scanning was skipped.",
        recommendation="Install Semgrep and ensure the semgrep executable is on PATH to enable SAST scanning.",
    )


def _start_line(result: dict[str, Any]) -> int | None:
    start = result.get("start")
    if isinstance(start, dict):
        return _optional_int(start.get("line"))
    return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
