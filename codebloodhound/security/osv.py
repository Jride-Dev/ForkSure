from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .findings import SecurityFinding


OSV_TIMEOUT_SECONDS = 180
OSV_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def scan_osv(path: str | Path) -> list[SecurityFinding]:
    scan_path = Path(path)
    if not scan_path.exists():
        raise FileNotFoundError(f"Path does not exist: {scan_path}")

    osv_scanner = shutil.which("osv-scanner")
    if osv_scanner is None:
        return [_osv_unavailable_finding()]

    command = [osv_scanner, "--format", "json", str(scan_path)]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=OSV_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return [_osv_unavailable_finding()]
    except subprocess.SubprocessError as exc:
        return [
            SecurityFinding(
                id="osv-scanner-error",
                category="dependency-vulnerability",
                severity="medium",
                title="OSV Scanner failed",
                description=f"OSV Scanner could not complete dependency vulnerability scanning: {exc}",
                recommendation="Run OSV Scanner manually for more detail, then retry the CodeBloodHound scan.",
                source_tool="osv-scanner",
            )
        ]

    if result.returncode != 0 and not result.stdout.strip():
        return [
            SecurityFinding(
                id="osv-scanner-error",
                category="dependency-vulnerability",
                severity="medium",
                title="OSV Scanner failed",
                description=(result.stderr.strip() or "OSV Scanner exited without JSON output."),
                recommendation="Run OSV Scanner manually for more detail, then retry the CodeBloodHound scan.",
                source_tool="osv-scanner",
            )
        ]

    return _parse_osv_json(result.stdout)


def _parse_osv_json(raw_json: str) -> list[SecurityFinding]:
    if not raw_json.strip():
        return []

    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError:
        return [
            SecurityFinding(
                id="osv-malformed-json",
                category="dependency-vulnerability",
                severity="medium",
                title="Malformed OSV Scanner JSON output",
                description="OSV Scanner returned output that CodeBloodHound could not parse as JSON.",
                recommendation="Run OSV Scanner manually and verify it can produce JSON output.",
                source_tool="osv-scanner",
            )
        ]

    findings: list[SecurityFinding] = []
    for package_record, vulnerability in _iter_vulnerability_records(parsed):
        findings.append(_finding_from_osv_record(package_record, vulnerability))
    return findings


def _iter_vulnerability_records(parsed: Any) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    roots = parsed if isinstance(parsed, list) else [parsed]
    for root in roots:
        if not isinstance(root, dict):
            continue

        for result in _as_list(root.get("results")):
            if not isinstance(result, dict):
                continue
            for package_record, vulnerability in _iter_result_records(result):
                yield package_record, vulnerability

        for package_record in _as_list(root.get("packages")):
            if not isinstance(package_record, dict):
                continue
            for vulnerability in _as_list(package_record.get("vulnerabilities")):
                if isinstance(vulnerability, dict):
                    yield package_record, vulnerability

        for vulnerability in _as_list(root.get("vulns")):
            if isinstance(vulnerability, dict):
                yield root, vulnerability

        for vulnerability in _as_list(root.get("vulnerabilities")):
            if isinstance(vulnerability, dict):
                yield root, vulnerability


def _iter_result_records(result: dict[str, Any]) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    source = result.get("source") if isinstance(result.get("source"), dict) else {}
    source_path = _optional_str(source.get("path") or result.get("path"))

    for package_record in _as_list(result.get("packages")):
        if not isinstance(package_record, dict):
            continue
        if source_path and "source_path" not in package_record:
            package_record = {**package_record, "source_path": source_path}
        for vulnerability in _as_list(package_record.get("vulnerabilities")):
            if isinstance(vulnerability, dict):
                yield package_record, vulnerability


def _finding_from_osv_record(package_record: dict[str, Any], vulnerability: dict[str, Any]) -> SecurityFinding:
    package = package_record.get("package") if isinstance(package_record.get("package"), dict) else {}
    package_name = _optional_str(package.get("name") or package_record.get("name") or package_record.get("package_name"))
    installed_version = _optional_str(
        package.get("version")
        or package_record.get("version")
        or package_record.get("installed_version")
        or package_record.get("installedVersion")
    )
    vuln_id = _optional_str(vulnerability.get("id") or _first_alias(vulnerability)) or "unknown"
    summary = _optional_str(vulnerability.get("summary") or vulnerability.get("details")) or "Dependency vulnerability detected."
    file_path = _optional_str(package_record.get("source_path") or package_record.get("path") or package_record.get("lockfile"))
    affected_range = _affected_range(vulnerability)
    fix_version = _fix_version(vulnerability)

    evidence_parts = [
        f"package={package_name or '-'}",
        f"version={installed_version or '-'}",
        f"vulnerability={vuln_id}",
    ]
    if affected_range:
        evidence_parts.append(f"affected={affected_range}")

    recommendation = "Upgrade the affected dependency to a non-vulnerable version."
    if fix_version:
        recommendation = f"Upgrade {package_name or 'the affected dependency'} to {fix_version} or later."

    title_package = f" in {package_name}" if package_name else ""
    return SecurityFinding(
        id=f"osv-{vuln_id}",
        category="dependency-vulnerability",
        severity=_severity_for_vulnerability(vulnerability),
        title=f"{vuln_id}{title_package}",
        description=summary,
        file_path=file_path,
        line=_optional_int(package_record.get("line")),
        evidence=" ".join(evidence_parts),
        recommendation=recommendation,
        source_tool="osv-scanner",
    )


def _severity_for_vulnerability(vulnerability: dict[str, Any]) -> str:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        severity = _optional_str(database_specific.get("severity"))
        mapped = OSV_SEVERITY_MAP.get((severity or "").upper())
        if mapped:
            return mapped

    for severity_record in _as_list(vulnerability.get("severity")):
        if isinstance(severity_record, dict):
            severity = _optional_str(severity_record.get("score") or severity_record.get("type"))
        else:
            severity = _optional_str(severity_record)
        mapped = OSV_SEVERITY_MAP.get((severity or "").upper())
        if mapped:
            return mapped

    direct = _optional_str(vulnerability.get("severity"))
    mapped = OSV_SEVERITY_MAP.get((direct or "").upper())
    return mapped or "medium"


def _affected_range(vulnerability: dict[str, Any]) -> str | None:
    ranges: list[str] = []
    for affected in _as_list(vulnerability.get("affected")):
        if not isinstance(affected, dict):
            continue
        for range_record in _as_list(affected.get("ranges")):
            if not isinstance(range_record, dict):
                continue
            events = []
            for event in _as_list(range_record.get("events")):
                if isinstance(event, dict):
                    events.extend(f"{key}:{value}" for key, value in event.items())
            if events:
                ranges.append(",".join(events))
    return ";".join(ranges) if ranges else None


def _fix_version(vulnerability: dict[str, Any]) -> str | None:
    for affected in _as_list(vulnerability.get("affected")):
        if not isinstance(affected, dict):
            continue
        database_specific = affected.get("database_specific")
        if isinstance(database_specific, dict):
            fixed = _optional_str(database_specific.get("fixed_version") or database_specific.get("fixed"))
            if fixed:
                return fixed

        for range_record in _as_list(affected.get("ranges")):
            if not isinstance(range_record, dict):
                continue
            for event in _as_list(range_record.get("events")):
                if isinstance(event, dict) and event.get("fixed"):
                    return str(event["fixed"])
    return None


def _osv_unavailable_finding() -> SecurityFinding:
    return SecurityFinding(
        id="osv-scanner-unavailable",
        category="dependency-vulnerability",
        severity="info",
        title="OSV Scanner unavailable",
        description="osv-scanner was not found on PATH, so dependency vulnerability scanning was skipped.",
        recommendation="Install OSV Scanner and ensure the osv-scanner executable is on PATH to enable dependency vulnerability scanning.",
    )


def _first_alias(vulnerability: dict[str, Any]) -> str | None:
    aliases = vulnerability.get("aliases")
    if isinstance(aliases, list) and aliases:
        return _optional_str(aliases[0])
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
