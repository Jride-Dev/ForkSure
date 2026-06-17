from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .findings import SecurityFinding


GITLEAKS_TIMEOUT_SECONDS = 120


def scan_secrets(path: str | Path) -> list[SecurityFinding]:
    scan_path = Path(path)
    if not scan_path.exists():
        raise FileNotFoundError(f"Path does not exist: {scan_path}")

    gitleaks = shutil.which("gitleaks")
    if gitleaks is None:
        return [_gitleaks_unavailable_finding()]

    command = [
        gitleaks,
        "detect",
        "--source",
        str(scan_path),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--exit-code",
        "0",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=GITLEAKS_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return [_gitleaks_unavailable_finding()]
    except subprocess.SubprocessError as exc:
        return [
            SecurityFinding(
                id="secrets-gitleaks-error",
                category="secrets",
                severity="medium",
                title="Gitleaks scan failed",
                description=f"Gitleaks could not complete the secret scan: {exc}",
                recommendation="Run Gitleaks manually for more detail, then retry the CodeBloodHound scan.",
            )
        ]

    if result.returncode != 0 and not result.stdout.strip():
        return [
            SecurityFinding(
                id="secrets-gitleaks-error",
                category="secrets",
                severity="medium",
                title="Gitleaks scan failed",
                description=(result.stderr.strip() or "Gitleaks exited without JSON output."),
                recommendation="Run Gitleaks manually for more detail, then retry the CodeBloodHound scan.",
                source_tool="gitleaks",
            )
        ]

    return _parse_gitleaks_json(result.stdout)


def _parse_gitleaks_json(raw_json: str) -> list[SecurityFinding]:
    if not raw_json.strip():
        return []

    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError:
        return [
            SecurityFinding(
                id="secrets-gitleaks-malformed-json",
                category="secrets",
                severity="medium",
                title="Malformed Gitleaks JSON output",
                description="Gitleaks returned output that CodeBloodHound could not parse as JSON.",
                recommendation="Run Gitleaks manually and verify it can produce JSON output.",
                source_tool="gitleaks",
            )
        ]

    if parsed is None:
        return []

    records = parsed.get("findings", []) if isinstance(parsed, dict) else parsed
    if not isinstance(records, list):
        return [
            SecurityFinding(
                id="secrets-gitleaks-malformed-json",
                category="secrets",
                severity="medium",
                title="Unexpected Gitleaks JSON shape",
                description="Gitleaks JSON output was not a list of findings.",
                recommendation="Run Gitleaks manually and verify it can produce JSON output.",
                source_tool="gitleaks",
            )
        ]

    findings: list[SecurityFinding] = []
    for record in records:
        if isinstance(record, dict):
            findings.append(_finding_from_gitleaks_record(record))
    return findings


def _finding_from_gitleaks_record(record: dict[str, Any]) -> SecurityFinding:
    rule_id = str(record.get("RuleID") or record.get("RuleId") or record.get("rule_id") or "unknown")
    description = str(record.get("Description") or record.get("description") or "Potential secret detected.")
    file_path = _optional_str(record.get("File") or record.get("file"))
    line = _optional_int(record.get("StartLine") or record.get("Line") or record.get("line"))
    severity = _severity_for_gitleaks_finding(rule_id, description)
    preview = _redacted_preview(record.get("Secret") or record.get("Match"))

    return SecurityFinding(
        id=f"secret-{rule_id}",
        category="secrets",
        severity=severity,
        title=f"Potential secret: {rule_id}",
        description=description,
        file_path=file_path,
        line=line,
        evidence=f"rule={rule_id} file={file_path or '-'} line={line or '-'} secret={preview}",
        recommendation="Rotate the secret if it is real, remove it from the repository, and rewrite exposed history if needed.",
        source_tool="gitleaks",
    )


def _severity_for_gitleaks_finding(rule_id: str, description: str) -> str:
    text = f"{rule_id} {description}".lower()

    critical_terms = (
        "private key",
        "private-key",
        "github token",
        "github-token",
        "github personal access token",
        "github pat",
        "github_pat",
        "ghp_",
        "cloud key",
        "cloud-key",
        "aws access key",
        "aws secret access key",
        "google cloud",
        "gcp key",
        "azure key",
        "database url",
        "database-url",
        "database_url",
        "postgres://",
        "mysql://",
        "service role key",
        "service-role-key",
        "service_role",
    )
    if any(term in text for term in critical_terms):
        return "critical"

    high_terms = (
        "api key",
        "api-key",
        "apikey",
        "oauth secret",
        "oauth-secret",
        "jwt secret",
        "jwt-secret",
        "webhook secret",
        "webhook-secret",
    )
    if any(term in text for term in high_terms):
        return "high"

    medium_terms = ("password", "credential", "credentials", "passwd")
    if any(term in text for term in medium_terms):
        return "medium"

    return "medium"


def _redacted_preview(value: Any) -> str:
    if not isinstance(value, str) or len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}...REDACTED...{value[-4:]}"


def _gitleaks_unavailable_finding() -> SecurityFinding:
    return SecurityFinding(
        id="secrets-gitleaks-unavailable",
        category="secrets",
        severity="info",
        title="Gitleaks unavailable",
        description="Gitleaks was not found on PATH, so secret scanning was skipped.",
        recommendation="Install Gitleaks and ensure the gitleaks executable is on PATH to enable secret scanning.",
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
