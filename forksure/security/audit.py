from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .dependencies import scan_dependencies
from .findings import SecurityFinding
from .osv import scan_osv
from .sast import scan_sast
from .secrets import scan_secrets
from .scripts import scan_unsafe_scripts
from .scoring import calculate_security_score


def run_security_audit(path: str | Path) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    findings.extend(scan_unsafe_scripts(path))
    findings.extend(scan_dependencies(path))
    findings.extend(scan_osv(path))
    findings.extend(scan_secrets(path))
    findings.extend(scan_sast(path))
    return findings


def build_security_audit_report(path: str | Path, findings: list[SecurityFinding]) -> dict:
    """Build the JSON-compatible summary for a local security audit."""
    return {
        "path": str(path),
        **calculate_security_score(findings),
        "findings": findings,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
